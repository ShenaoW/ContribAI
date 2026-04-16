"""AWI issue submission runner.

Reads findings_open.csv, groups by repository, generates LLM-based
vulnerability disclosure issues, presents them for human review, and
submits approved issues to GitHub.

Usage::

    python -m contribai.awi.runner \\
        --findings /path/to/findings_open.csv \\
        --config /path/to/config.yaml \\
        [--dry-run] [--auto-approve] [--repo owner/repo] [--limit N]
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

from contribai.awi.issue_writer import AWIFinding, AWIIssueWriter
from contribai.awi.review_gate import IssueReviewDecision, IssueReviewer

logger = logging.getLogger(__name__)

DEFAULT_FINDINGS = Path("/home/shenaow/ActionInjection/outputs/argus-awi/findings_open.csv")
DEFAULT_SUBMITTED = Path("/home/shenaow/ActionInjection/outputs/argus-awi/awi_issues_submitted.json")
DEFAULT_CONFIG = Path("/home/shenaow/ActionInjection/pr/ContribAI/config.yaml")


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

    logger.info("Loaded %d findings across %d repos", sum(len(v) for v in by_repo.values()), len(by_repo))
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

    from contribai.core.config import LLMConfig
    from contribai.llm.provider import create_llm_provider

    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    llm_cfg = LLMConfig(**raw.get("llm", {}))
    return create_llm_provider(llm_cfg)


def build_github_client(config_path: Path):
    """Build a GitHub client from the ContribAI config file."""
    import yaml

    from contribai.core.config import GitHubConfig
    from contribai.github.client import GitHubClient

    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    gh_cfg = GitHubConfig(**raw.get("github", {}))
    return GitHubClient(gh_cfg.token, rate_limit_buffer=gh_cfg.rate_limit_buffer)


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
) -> None:
    """Main async logic for AWI issue submission."""
    # Load findings
    all_findings = load_findings(findings_path)
    submitted_log = load_submitted(submitted_path)

    # Filter repos
    repos = list(all_findings.keys())
    if repo_filter:
        repos = [r for r in repos if r == repo_filter]
        if not repos:
            click.echo(f"[error] No findings found for repo: {repo_filter}", err=True)
            return

    # Skip already submitted
    pending_repos = [r for r in repos if r not in submitted_log]
    if not pending_repos:
        click.echo("All repos already have submitted issues. Nothing to do.")
        return

    if limit:
        pending_repos = pending_repos[:limit]

    click.echo(
        f"Processing {len(pending_repos)} repos "
        f"({len(repos) - len(pending_repos)} already submitted, "
        f"{len(repos)} total)"
    )

    # Build clients
    llm = build_llm_provider(config_path)
    github = build_github_client(config_path)

    writer = AWIIssueWriter(llm)
    reviewer = IssueReviewer(auto_approve=auto_approve)

    approved = 0
    rejected = 0
    skipped = 0
    errors = 0

    try:
        for i, repo in enumerate(pending_repos, 1):
            findings = all_findings[repo]
            click.echo(f"\n[{i}/{len(pending_repos)}] {repo} — {len(findings)} finding(s)")

            # Optionally fetch workflow YAML for the first finding
            workflow_yaml = None
            if fetch_yaml and findings:
                workflow_yaml = await fetch_workflow_yaml(
                    github, repo, findings[0].workflow
                )

            # Generate issue via LLM
            click.echo("  Generating issue via LLM...")
            result = await writer.generate(repo, findings, workflow_yaml=workflow_yaml)
            if result is None:
                click.echo(f"  [error] LLM generation failed for {repo}", err=True)
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
                click.echo(f"  [dry-run] Would submit issue: {title!r}")
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
                click.echo(f"  Submitting issue to {repo}...")
                data = await github.create_issue(
                    owner, name, title=title, body=body, labels=["security"]
                )
            except Exception:
                try:
                    data = await github.create_issue(owner, name, title=title, body=body)
                except Exception as e:
                    click.echo(f"  [error] Failed to submit issue: {e}", err=True)
                    errors += 1
                    continue

            issue_number = data["number"]
            issue_url = data["html_url"]
            click.echo(f"  Issue #{issue_number} created: {issue_url}")

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
            approved += 1

    finally:
        await llm.close()
        await github.close()

    # Summary
    click.echo("\n" + "=" * 60)
    click.echo(f"Submitted: {approved}  Rejected: {rejected}  Skipped: {skipped}  Errors: {errors}")
    click.echo(f"Submission log: {submitted_path}")


# ── Click CLI ──────────────────────────────────────────────────────────────────


@click.command("awi-submit")
@click.option(
    "--findings",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_FINDINGS,
    show_default=True,
    help="Path to findings_open.csv from ARGUS scan.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_CONFIG,
    show_default=True,
    help="Path to ContribAI config.yaml.",
)
@click.option(
    "--submitted",
    "submitted_path",
    type=click.Path(path_type=Path),
    default=DEFAULT_SUBMITTED,
    show_default=True,
    help="Path to submission log JSON (tracks already-submitted repos).",
)
@click.option("--dry-run", is_flag=True, help="Generate and review but do not actually submit.")
@click.option(
    "--auto-approve",
    is_flag=True,
    help="Skip human review and auto-approve all generated issues.",
)
@click.option(
    "--repo",
    "repo_filter",
    default=None,
    metavar="OWNER/REPO",
    help="Process only this specific repo.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    metavar="N",
    help="Process at most N repos.",
)
@click.option(
    "--no-fetch-yaml",
    "fetch_yaml",
    is_flag=True,
    default=True,
    help="Skip fetching workflow YAML (faster but less context for LLM).",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def cli(
    findings: Path,
    config_path: Path,
    submitted_path: Path,
    dry_run: bool,
    auto_approve: bool,
    repo_filter: Optional[str],
    limit: Optional[int],
    fetch_yaml: bool,
    verbose: bool,
) -> None:
    """Submit AWI vulnerability disclosure issues to affected GitHub repositories.

    Reads ARGUS scan results from findings_open.csv, generates professional
    vulnerability reports using an LLM, presents each report for human review,
    and submits approved reports as GitHub issues.

    Examples:

    \b
    # Dry run — preview without submitting
    python -m contribai.awi.runner --dry-run --limit 5

    \b
    # Interactive review, process one specific repo
    python -m contribai.awi.runner --repo owner/repo-name

    \b
    # Auto-approve all, submit up to 10 issues
    python -m contribai.awi.runner --auto-approve --limit 10
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    asyncio.run(
        run_awi_issue_submission(
            findings_path=findings,
            config_path=config_path,
            submitted_path=submitted_path,
            dry_run=dry_run,
            auto_approve=auto_approve,
            repo_filter=repo_filter,
            limit=limit,
            fetch_yaml=fetch_yaml,
        )
    )


if __name__ == "__main__":
    cli()
