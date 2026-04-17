"""Full AWI disclosure pipeline: issue + PR in one shot.

Orchestrates:
  1. LLM-generated disclosure issue → human review → submit to GitHub
  2. LLM-generated YAML fix patch → human review → submit PR linked to the issue
  3. Both recorded to ContribAI memory DB + JSON dedup logs

Exposed to the CLI as `awi-contribai awi-disclose`.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from awi_contribai.awi.issue_writer import AWIIssueWriter
from awi_contribai.awi.pr_writer import (
    DEFAULT_PR_LOG,
    _build_suggestion,
    _finding_description,
    _finding_title,
    _review_pr,
    find_residual_taint,
    load_pr_log,
    save_pr_log,
)
from awi_contribai.awi.review_gate import IssueReviewer
from awi_contribai.awi.runner import (
    build_github_client,
    build_llm_provider,
    build_memory,
    check_security_policy,
    fetch_workflow_yaml,
    load_findings,
    load_submitted,
    save_submitted,
)
from awi_contribai.core.config import ContributionConfig
from awi_contribai.core.models import ContributionType, Finding, RepoContext, Severity
from awi_contribai.generator.engine import ContributionGenerator
from awi_contribai.pr.manager import PRManager

logger = logging.getLogger(__name__)
console = Console()


async def run_awi_disclose(
    findings_path: Path,
    config_path: Path,
    submitted_path: Path,
    pr_log_path: Path,
    *,
    dry_run: bool = False,
    auto_approve: bool = False,
    repo_filter: str | None = None,
    limit: int | None = None,
    force: bool = False,
) -> tuple[int, int, int, int]:
    """One-shot: open disclosure issue, then open fix PR linked to it.

    Returns (full_success, issue_only, rejected, errors).
    """
    all_findings = load_findings(findings_path)
    issue_log = load_submitted(submitted_path)
    pr_log = load_pr_log(pr_log_path)

    # Eligible repos: have findings AND haven't already been through the full flow
    repos = list(all_findings.keys())
    if repo_filter:
        repos = [r for r in repos if r == repo_filter]
        if not repos:
            console.print(f"[red]No findings for repo: {repo_filter}[/red]")
            return 0, 0, 0, 1

    pending = [r for r in repos if r not in pr_log]  # PR log is the "done" marker
    if not pending:
        console.print("[dim]All eligible repos already completed full disclosure.[/dim]")
        return 0, 0, 0, 0

    if limit:
        pending = pending[:limit]

    console.print(
        f"Processing [bold]{len(pending)}[/bold] repos "
        f"([dim]{len(repos) - len(pending)} already done[/dim])"
    )

    llm = build_llm_provider(config_path)
    github = build_github_client(config_path)
    memory = await build_memory(config_path)

    issue_writer = AWIIssueWriter(llm)
    issue_reviewer = IssueReviewer(auto_approve=auto_approve)
    contrib_config = ContributionConfig()
    generator = ContributionGenerator(llm, contrib_config)
    pr_manager = PRManager(github)

    full_success = issue_only = rejected = errors = 0

    try:
        for repo_slug in pending:
            repo_findings = all_findings[repo_slug]
            owner, name = repo_slug.split("/", 1)

            console.print(
                f"\n[bold cyan]━━━ {repo_slug} ━━━[/bold cyan] "
                f"({len(repo_findings)} findings)"
            )

            # Security disclosure policy check
            policy = await check_security_policy(github, repo_slug)
            if policy["block"] and not force:
                console.print(
                    "\n[yellow]⚠  Private disclosure channel available:[/yellow]"
                )
                for r in policy["reasons"]:
                    console.print(f"  • {r}")
                console.print(
                    "[yellow]Skipping this repo (use --force to submit publicly anyway).[/yellow]"
                )
                skipped_flag = True
                issue_log[repo_slug] = {
                    "status": "skipped_private_channel",
                    "reasons": policy["reasons"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                save_submitted(submitted_path, issue_log)
                continue

            # ────────────────────────────────────────────────────────────
            # Step 1: Disclosure issue
            # ────────────────────────────────────────────────────────────
            console.print("\n[bold]1/2 Disclosure issue[/bold]")
            issue_number: int | None = None

            if repo_slug in issue_log and issue_log[repo_slug].get("issue_number"):
                # Reuse a previously opened issue (e.g. from a past awi-submit run)
                issue_number = issue_log[repo_slug]["issue_number"]
                console.print(
                    f"  [dim]Reusing existing issue #{issue_number}[/dim]"
                )
            else:
                # Generate new issue
                workflow_yaml_for_issue = await fetch_workflow_yaml(
                    github, repo_slug, repo_findings[0].workflow
                )
                console.print("  [dim]Generating issue via LLM...[/dim]")
                result = await issue_writer.generate(
                    repo_slug, repo_findings, workflow_yaml=workflow_yaml_for_issue
                )
                if result is None:
                    console.print("  [red]Issue generation failed[/red]")
                    errors += 1
                    continue
                title, body = result

                actions = sorted({f.action for f in repo_findings})
                taint_sources = sorted({f.taint_source for f in repo_findings})
                workflow_urls = sorted({f.workflow_url for f in repo_findings if f.workflow_url})

                decision = await issue_reviewer.review(
                    repo=repo_slug,
                    title=title,
                    body=body,
                    findings_count=len(repo_findings),
                    actions=actions,
                    taint_sources=taint_sources,
                    workflow_urls=workflow_urls,
                )

                if decision.skipped or decision.rejected:
                    console.print(
                        f"  [yellow]Issue {'skipped' if decision.skipped else 'rejected'}; "
                        f"skipping this repo entirely[/yellow]"
                    )
                    if decision.rejected:
                        rejected += 1
                    continue

                if dry_run:
                    console.print(f"  [yellow][DRY RUN] Would submit issue: {title!r}[/yellow]")
                    issue_number = -1  # placeholder so PR step can proceed with dry-run
                else:
                    try:
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
                    console.print(f"  [green]Issue #{issue_number}: {issue_url}[/green]")

                    issue_log[repo_slug] = {
                        "status": "submitted",
                        "issue_number": issue_number,
                        "issue_url": issue_url,
                        "title": title,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "findings_count": len(repo_findings),
                        "actions": actions,
                    }
                    save_submitted(submitted_path, issue_log)

                    try:
                        await memory.record_issue(
                            repo=repo_slug,
                            issue_number=issue_number,
                            issue_url=issue_url,
                            title=title,
                            issue_type="awi_disclosure",
                        )
                    except Exception as e:
                        logger.warning("Could not record issue to memory DB: %s", e)

            # ────────────────────────────────────────────────────────────
            # Step 2: Fix PR (per workflow)
            # ────────────────────────────────────────────────────────────
            console.print("\n[bold]2/2 Fix PR[/bold]")

            try:
                target_repo = await github.get_repo_details(owner, name)
            except Exception as e:
                console.print(f"  [red]Could not fetch repo: {e}[/red]")
                errors += 1
                issue_only += 1
                continue

            by_workflow: dict[str, list] = defaultdict(list)
            for f in repo_findings:
                by_workflow[f.workflow].append(f)

            any_pr_submitted = False

            for workflow_path, wf_findings in by_workflow.items():
                console.print(f"  [dim]{workflow_path}[/dim]")

                yaml_content = await fetch_workflow_yaml(github, repo_slug, workflow_path)
                if not yaml_content:
                    console.print("  [yellow]Could not fetch YAML, skipping workflow[/yellow]")
                    continue

                finding = Finding(
                    type=ContributionType.SECURITY_FIX,
                    severity=Severity.HIGH,
                    title=_finding_title(wf_findings),
                    description=_finding_description(repo_slug, wf_findings),
                    file_path=workflow_path,
                    suggestion=_build_suggestion(wf_findings),
                    confidence=0.95,
                )
                context = RepoContext(
                    repo=target_repo,
                    relevant_files={workflow_path: yaml_content},
                )

                console.print("  [dim]Generating YAML patch...[/dim]")
                try:
                    contribution = await generator.generate(finding, context)
                except Exception as e:
                    console.print(f"  [red]PR generation failed: {e}[/red]")
                    errors += 1
                    continue

                if not contribution:
                    console.print("  [yellow]Generator produced no changes[/yellow]")
                    continue

                # YAML validity check
                import yaml as _yaml
                yaml_ok = True
                for ch in contribution.changes:
                    try:
                        _yaml.safe_load(ch.new_content)
                    except Exception as e:
                        console.print(f"  [red]Patched YAML invalid: {e}[/red]")
                        yaml_ok = False
                        break
                if not yaml_ok:
                    continue

                residual_found = find_residual_taint(contribution.changes, wf_findings)
                if residual_found:
                    console.print(
                        f"  [red]Residual taint still present after patch: "
                        f"{', '.join(residual_found)}[/red]"
                    )
                    console.print(
                        "  [yellow]Skipping — generated patch did not remove the "
                        "vulnerable interpolation.[/yellow]"
                    )
                    continue

                patch_preview = "\n\n".join(
                    f"# {ch.path}\n{ch.new_content[:2000]}" for ch in contribution.changes
                )
                pr_decision = _review_pr(
                    repo_slug, finding, patch_preview, auto_approve=auto_approve
                )
                if pr_decision == "n":
                    console.print("  [red]PR rejected[/red]")
                    continue
                if pr_decision == "s":
                    console.print("  [yellow]PR skipped[/yellow]")
                    continue

                if dry_run:
                    console.print("  [yellow][DRY RUN] Would submit PR[/yellow]")
                    any_pr_submitted = True
                    continue

                try:
                    pr_result = await pr_manager.create_pr(
                        contribution,
                        target_repo,
                        closes_issue=issue_number if (issue_number and issue_number > 0) else None,
                    )
                    console.print(
                        f"  [green]✅ PR #{pr_result.pr_number}: {pr_result.pr_url}[/green]"
                    )

                    pr_log[repo_slug] = {
                        "pr_number": pr_result.pr_number,
                        "pr_url": pr_result.pr_url,
                        "workflow": workflow_path,
                        "issue_number": issue_number,
                        "submitted_at": datetime.now(timezone.utc).isoformat(),
                    }
                    save_pr_log(pr_log_path, pr_log)

                    try:
                        await memory.record_pr(
                            repo=repo_slug,
                            pr_number=pr_result.pr_number,
                            pr_url=pr_result.pr_url,
                            title=contribution.title,
                            pr_type="awi_fix",
                            branch=pr_result.branch_name,
                            fork=pr_result.fork_full_name,
                        )
                        if issue_number and issue_number > 0:
                            await memory.update_issue_status(
                                repo=repo_slug,
                                issue_number=issue_number,
                                status="open",
                                linked_pr_url=pr_result.pr_url,
                            )
                    except Exception as e:
                        logger.warning("Could not record PR to memory DB: %s", e)

                    any_pr_submitted = True
                except Exception as e:
                    console.print(f"  [red]PR creation failed: {e}[/red]")
                    errors += 1

            if any_pr_submitted:
                full_success += 1
            elif issue_number is not None:
                issue_only += 1

    finally:
        await llm.close()
        await github.close()
        await memory.close()

    console.print()
    console.print(
        Panel(
            f"✅ Full disclosure (issue + PR): [bold green]{full_success}[/bold green]\n"
            f"⚠️  Issue only (PR failed/skipped): [bold yellow]{issue_only}[/bold yellow]\n"
            f"❌ Rejected: [bold red]{rejected}[/bold red]"
            + (f"\n⚠️  Errors: [bold red]{errors}[/bold red]" if errors else ""),
            title="AWI Disclosure Complete" + (" (DRY RUN)" if dry_run else ""),
        )
    )

    return full_success, issue_only, rejected, errors
