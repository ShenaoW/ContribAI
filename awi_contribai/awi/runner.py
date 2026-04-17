"""AWI issue submission runner.

Reads findings_open.csv, groups by repository, generates LLM-based
vulnerability disclosure issues, presents them for human review, and
submits approved issues to GitHub.

This module exposes ``run_awi_issue_submission()`` for use by the
``awi-contribai awi-submit`` CLI command defined in ``awi_contribai.cli.main``.
"""

from __future__ import annotations

import csv
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from awi_contribai.awi.issue_writer import AWIFinding, AWIIssueWriter
from awi_contribai.awi.review_gate import IssueReviewer

logger = logging.getLogger(__name__)
console = Console()

DEFAULT_FINDINGS = Path("outputs/argus-awi/findings_open.csv")
DEFAULT_SUBMITTED = Path("outputs/argus-awi/awi_issues_submitted.json")
DEFAULT_CONFIG = Path("config.yaml")


# ── CSV loading ────────────────────────────────────────────────────────────────


def load_findings(findings_path: Path) -> dict[str, list[AWIFinding]]:
    """Load findings CSV and group by repository slug.

    Returns a dict mapping repo slug → list of AWIFinding.
    """
    by_repo: dict[str, list[AWIFinding]] = defaultdict(list)

    with findings_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            finding = AWIFinding(
                repo=row["repo"],
                workflow=row["workflow"],
                workflow_url=row.get("workflow_url", ""),
                action=row.get("action", ""),
                taint_source=row["taint_source"],
                source_location=row.get("source_location", ""),
                sink_location=row.get("sink_location", ""),
                access_control=row.get("access_control", "open"),
            )
            by_repo[finding.repo].append(finding)

    logger.info(
        "Loaded %d findings across %d repos",
        sum(len(v) for v in by_repo.values()),
        len(by_repo),
    )
    return dict(by_repo)


# ── Submission log ─────────────────────────────────────────────────────────────


def load_submitted(submitted_path: Path) -> dict[str, dict]:
    """Load the submission log (repo → issue info)."""
    if submitted_path.exists():
        with submitted_path.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_submitted(submitted_path: Path, log: dict[str, dict]) -> None:
    """Persist the submission log."""
    submitted_path.parent.mkdir(parents=True, exist_ok=True)
    with submitted_path.open("w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)


# ── Config + provider init ─────────────────────────────────────────────────────


def build_llm_provider(config_path: Path):
    """Build an LLM provider from the ContribAI config file."""
    import yaml

    from awi_contribai.core.config import LLMConfig
    from awi_contribai.llm.provider import create_llm_provider

    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    llm_cfg = LLMConfig(**raw.get("llm", {}))
    return create_llm_provider(llm_cfg)


def build_github_client(config_path: Path):
    """Build a GitHub client from the ContribAI config file."""
    import yaml

    from awi_contribai.core.config import GitHubConfig
    from awi_contribai.github.client import GitHubClient

    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    gh_cfg = GitHubConfig(**raw.get("github", {}))
    return GitHubClient(gh_cfg.token, rate_limit_buffer=gh_cfg.rate_limit_buffer)


async def build_memory(config_path: Path):
    """Build and initialize a Memory instance from the ContribAI config file."""
    import yaml

    from awi_contribai.memory import Memory

    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    db_path = raw.get("storage", {}).get("db_path", "~/.contribai/memory.db")
    mem = Memory(db_path)
    await mem.init()
    return mem


# ── Workflow YAML fetcher ──────────────────────────────────────────────────────


async def fetch_workflow_yaml(github, repo: str, workflow_path: str) -> str | None:
    """Fetch the raw content of a workflow file from GitHub."""
    owner, name = repo.split("/", 1)
    try:
        content = await github.get_file_content(owner, name, workflow_path)
        return content
    except Exception as e:
        logger.warning("Could not fetch workflow YAML for %s/%s: %s", repo, workflow_path, e)
        return None


# ── Security disclosure policy check ──────────────────────────────────────────


async def check_security_policy(github, repo: str) -> dict:
    """Check whether the repo has a private disclosure channel.

    Returns a dict with:
        block            — True if public issue/PR disclosure should be avoided
        reasons          — list of human-readable reasons
        pvr_enabled      — GitHub Private Vulnerability Reporting is on
        has_security_md  — repo has a SECURITY.md / security policy file
        security_md_url  — URL of the security policy file (if any)
    """
    owner, name = repo.split("/", 1)
    result = {
        "block": False,
        "reasons": [],
        "pvr_enabled": False,
        "has_security_md": False,
        "security_md_url": None,
    }

    # 1. Private Vulnerability Reporting (on /repos/{o}/{r})
    # Note: security_and_analysis is only returned for authenticated users with
    # admin access, so this is a best-effort signal. It's usually None otherwise.
    try:
        repo_data = await github._get(f"/repos/{owner}/{name}")
        saa = repo_data.get("security_and_analysis") or {}
        pvr = saa.get("private_vulnerability_reporting") or {}
        if pvr.get("status") == "enabled":
            result["pvr_enabled"] = True
    except Exception as e:
        logger.debug("PVR check failed for %s: %s", repo, e)

    # 2. SECURITY.md — probe standard locations directly. The community-profile
    # API's `files.security_policy` is unreliable for repos that store the file
    # under .github/ or docs/.
    for candidate in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md",
                      "SECURITY", ".github/SECURITY"):
        try:
            await github.get_file_content(owner, name, candidate)
            result["has_security_md"] = True
            result["security_md_url"] = f"https://github.com/{repo}/blob/HEAD/{candidate}"
            break
        except Exception:
            continue

    if result["pvr_enabled"]:
        result["reasons"].append(
            "Private Vulnerability Reporting is enabled — use GitHub's PVR flow "
            f"(https://github.com/{repo}/security/advisories/new) instead of a public issue"
        )
    if result["has_security_md"]:
        result["reasons"].append(
            f"SECURITY.md exists at {result['security_md_url']} — "
            "follow its disclosure instructions"
        )

    result["block"] = result["pvr_enabled"] or result["has_security_md"]
    return result


# ── Core async runner ──────────────────────────────────────────────────────────


async def run_awi_issue_submission(
    findings_path: Path,
    config_path: Path,
    submitted_path: Path,
    *,
    dry_run: bool = False,
    auto_approve: bool = False,
    repo_filter: str | None = None,
    limit: int | None = None,
    fetch_yaml: bool = True,
    force: bool = False,
) -> None:
    """Main async logic for AWI issue submission.

    Called by the ``awi-contribai awi-submit`` command.
    """
    # Load findings
    all_findings = load_findings(findings_path)
    submitted_log = load_submitted(submitted_path)

    # Filter repos
    repos = list(all_findings.keys())
    if repo_filter:
        repos = [r for r in repos if r == repo_filter]
        if not repos:
            console.print(f"[red]No findings found for repo: {repo_filter}[/red]")
            return

    # Skip already submitted
    pending_repos = [r for r in repos if r not in submitted_log]
    if not pending_repos:
        console.print("[dim]All repos already have submitted issues. Nothing to do.[/dim]")
        return

    if limit:
        pending_repos = pending_repos[:limit]

    console.print(
        f"Processing [bold]{len(pending_repos)}[/bold] repos "
        f"([dim]{len(repos) - len(pending_repos)} already submitted, "
        f"{len(repos)} total[/dim])"
    )

    # Build clients
    llm = build_llm_provider(config_path)
    github = build_github_client(config_path)
    memory = await build_memory(config_path)

    writer = AWIIssueWriter(llm)
    reviewer = IssueReviewer(auto_approve=auto_approve)

    approved = 0
    rejected = 0
    skipped = 0
    errors = 0

    try:
        for i, repo in enumerate(pending_repos, 1):
            findings = all_findings[repo]
            console.print(
                f"\n[[bold cyan]{i}/{len(pending_repos)}[/bold cyan]] "
                f"[bold]{repo}[/bold] — {len(findings)} finding(s)"
            )

            # Security disclosure policy check
            policy = await check_security_policy(github, repo)
            if policy["block"] and not force:
                console.print(
                    "  [yellow]⚠  Private disclosure channel available:[/yellow]"
                )
                for r in policy["reasons"]:
                    console.print(f"    • {r}")
                console.print(
                    "  [yellow]Skipping public issue (use --force to override).[/yellow]"
                )
                submitted_log[repo] = {
                    "status": "skipped_private_channel",
                    "reasons": policy["reasons"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                save_submitted(submitted_path, submitted_log)
                skipped += 1
                continue

            # Optionally fetch workflow YAML for the first finding
            workflow_yaml = None
            if fetch_yaml and findings:
                workflow_yaml = await fetch_workflow_yaml(
                    github, repo, findings[0].workflow
                )

            # Generate issue via LLM
            console.print("  [dim]Generating issue via LLM...[/dim]")
            result = await writer.generate(repo, findings, workflow_yaml=workflow_yaml)
            if result is None:
                console.print(f"  [red]LLM generation failed for {repo}[/red]")
                errors += 1
                continue

            title, body = result

            # Human review
            actions = sorted({f.action for f in findings})
            taint_sources = sorted({f.taint_source for f in findings})
            workflow_urls = sorted({f.workflow_url for f in findings if f.workflow_url})

            decision = await reviewer.review(
                repo=repo,
                title=title,
                body=body,
                findings_count=len(findings),
                actions=actions,
                taint_sources=taint_sources,
                workflow_urls=workflow_urls,
            )

            if decision.skipped:
                skipped += 1
                continue

            if decision.rejected:
                rejected += 1
                submitted_log[repo] = {
                    "status": "rejected",
                    "title": title,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": decision.reason,
                }
                save_submitted(submitted_path, submitted_log)
                continue

            # Submit
            if dry_run:
                console.print(f"  [yellow][DRY RUN] Would submit: {title!r}[/yellow]")
                submitted_log[repo] = {
                    "status": "dry_run",
                    "title": title,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                save_submitted(submitted_path, submitted_log)
                approved += 1
                continue

            owner, name = repo.split("/", 1)
            try:
                console.print(f"  [dim]Submitting issue to {repo}...[/dim]")
                data = await github.create_issue(
                    owner, name, title=title, body=body, labels=["security"]
                )
            except Exception:
                try:
                    data = await github.create_issue(owner, name, title=title, body=body)
                except Exception as e:
                    console.print(f"  [red]Failed to submit issue: {e}[/red]")
                    errors += 1
                    continue

            issue_number = data["number"]
            issue_url = data["html_url"]
            console.print(f"  [green]Issue #{issue_number} created: {issue_url}[/green]")

            submitted_log[repo] = {
                "status": "submitted",
                "issue_number": issue_number,
                "issue_url": issue_url,
                "title": title,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "findings_count": len(findings),
                "actions": actions,
            }
            save_submitted(submitted_path, submitted_log)

            # Record to ContribAI memory DB for cross-tool status tracking
            try:
                await memory.record_issue(
                    repo=repo,
                    issue_number=issue_number,
                    issue_url=issue_url,
                    title=title,
                    issue_type="awi_disclosure",
                )
            except Exception as e:
                logger.warning("Could not record issue to memory DB: %s", e)

            approved += 1

    finally:
        await llm.close()
        await github.close()
        await memory.close()

    return approved, rejected, skipped, errors
