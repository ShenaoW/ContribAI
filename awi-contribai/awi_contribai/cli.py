"""CLI for the standalone AWI ContribAI project."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel

from awi_contribai import __version__
from awi_contribai.core.config import load_config

console = Console()


def setup_logging(verbose: bool = False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
    )


def print_banner():
    console.print(f"[bold cyan]AWI ContribAI[/bold cyan] [dim]v{__version__}[/dim]")


@click.group()
@click.option("--config", "-c", type=click.Path(), default=None, help="Config YAML path.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
@click.pass_context
def cli(ctx, config, verbose):
    """AWI-only disclosure issue and fix PR automation."""
    ctx.ensure_object(dict)
    setup_logging(verbose)
    ctx.obj["config_path"] = config


def _load_checked_config(config_path: str | None):
    config = load_config(config_path)
    if not config.github.token:
        console.print("[red]GitHub token not configured. Set github.token or GITHUB_TOKEN.[/red]")
        sys.exit(1)
    if config.llm.provider != "ollama" and not config.llm.api_key and not config.llm.use_vertex:
        console.print("[red]LLM API key not configured for selected provider.[/red]")
        sys.exit(1)
    return config


@cli.command("disclose")
@click.option("--findings", type=click.Path(path_type=Path), default=None, help="ARGUS findings CSV.")
@click.option("--submitted", "submitted_path", type=click.Path(path_type=Path), default=None, help="Issue log JSON.")
@click.option("--pr-log", "pr_log_path", type=click.Path(path_type=Path), default=None, help="PR log JSON.")
@click.option("--dry-run", is_flag=True, help="Generate issue + patch without submitting.")
@click.option("--auto-approve", is_flag=True, help="Skip interactive review gates.")
@click.option("--repo", "repo_filter", default=None, metavar="OWNER/REPO", help="Process only this repo.")
@click.option("--limit", type=int, default=None, metavar="N", help="Process at most N repos.")
@click.option("--force", is_flag=True, help="Submit publicly even when SECURITY.md/PVR exists.")
@click.pass_context
def disclose(ctx, findings, submitted_path, pr_log_path, dry_run, auto_approve, repo_filter, limit, force):
    """Open AWI disclosure issue, then open linked fix PR."""
    from awi_contribai.awi.disclose import run_awi_disclose
    from awi_contribai.awi.pr_writer import DEFAULT_PR_LOG
    from awi_contribai.awi.runner import DEFAULT_FINDINGS, DEFAULT_SUBMITTED

    print_banner()
    config = _load_checked_config(ctx.obj["config_path"])
    findings_path = Path(findings) if findings else DEFAULT_FINDINGS
    sub_path = Path(submitted_path) if submitted_path else DEFAULT_SUBMITTED
    pr_path = Path(pr_log_path) if pr_log_path else DEFAULT_PR_LOG
    cfg_path = Path(ctx.obj["config_path"]) if ctx.obj["config_path"] else Path("config.yaml")
    if not findings_path.exists():
        console.print(f"[red]Findings file not found: {findings_path}[/red]")
        sys.exit(1)
    console.print(f"Mode: {'DRY RUN' if dry_run else 'LIVE'} | LLM: {config.llm.provider} ({config.llm.model})")
    asyncio.run(run_awi_disclose(findings_path, cfg_path, sub_path, pr_path, dry_run=dry_run, auto_approve=auto_approve, repo_filter=repo_filter, limit=limit, force=force))


@cli.command("submit")
@click.option("--findings", type=click.Path(path_type=Path), default=None, help="ARGUS findings CSV.")
@click.option("--submitted", "submitted_path", type=click.Path(path_type=Path), default=None, help="Issue log JSON.")
@click.option("--dry-run", is_flag=True, help="Generate issue without submitting.")
@click.option("--auto-approve", is_flag=True, help="Skip issue review.")
@click.option("--repo", "repo_filter", default=None, metavar="OWNER/REPO", help="Process only this repo.")
@click.option("--limit", type=int, default=None, metavar="N", help="Process at most N repos.")
@click.option("--fetch-yaml/--no-fetch-yaml", default=True, help="Fetch workflow YAML for richer issue text.")
@click.option("--force", is_flag=True, help="Submit publicly even when SECURITY.md/PVR exists.")
@click.pass_context
def submit(ctx, findings, submitted_path, dry_run, auto_approve, repo_filter, limit, fetch_yaml, force):
    """Only submit AWI disclosure issues."""
    from awi_contribai.awi.runner import DEFAULT_FINDINGS, DEFAULT_SUBMITTED, run_awi_issue_submission

    print_banner()
    _load_checked_config(ctx.obj["config_path"])
    findings_path = Path(findings) if findings else DEFAULT_FINDINGS
    sub_path = Path(submitted_path) if submitted_path else DEFAULT_SUBMITTED
    cfg_path = Path(ctx.obj["config_path"]) if ctx.obj["config_path"] else Path("config.yaml")
    result = asyncio.run(run_awi_issue_submission(findings_path, cfg_path, sub_path, dry_run=dry_run, auto_approve=auto_approve, repo_filter=repo_filter, limit=limit, fetch_yaml=fetch_yaml, force=force))
    if result:
        approved, rejected, skipped, errors = result
        console.print(Panel(f"Submitted: {approved}\nRejected: {rejected}\nSkipped: {skipped}\nErrors: {errors}", title="AWI Submit Complete"))


@cli.command("pr")
@click.option("--findings", type=click.Path(path_type=Path), default=None, help="ARGUS findings CSV.")
@click.option("--pr-log", "pr_log_path", type=click.Path(path_type=Path), default=None, help="PR log JSON.")
@click.option("--dry-run", is_flag=True, help="Generate patch without submitting.")
@click.option("--auto-approve", is_flag=True, help="Skip PR review.")
@click.option("--repo", "repo_filter", default=None, metavar="OWNER/REPO", help="Process only this repo.")
@click.option("--limit", type=int, default=None, metavar="N", help="Process at most N repos.")
@click.option("--issue", "issue_number", type=int, default=None, metavar="N", help="Issue number to close.")
@click.option("--force", is_flag=True, help="Submit PR even when SECURITY.md/PVR exists.")
@click.pass_context
def pr(ctx, findings, pr_log_path, dry_run, auto_approve, repo_filter, limit, issue_number, force):
    """Only submit AWI fix PRs."""
    from awi_contribai.awi.pr_writer import DEFAULT_PR_LOG, run_awi_pr_submission
    from awi_contribai.awi.runner import DEFAULT_FINDINGS

    print_banner()
    _load_checked_config(ctx.obj["config_path"])
    findings_path = Path(findings) if findings else DEFAULT_FINDINGS
    log_path = Path(pr_log_path) if pr_log_path else DEFAULT_PR_LOG
    cfg_path = Path(ctx.obj["config_path"]) if ctx.obj["config_path"] else Path("config.yaml")
    result = asyncio.run(run_awi_pr_submission(findings_path, cfg_path, log_path, dry_run=dry_run, auto_approve=auto_approve, repo_filter=repo_filter, limit=limit, issue_number=issue_number, force=force))
    if result:
        submitted, rejected, skipped, errors = result
        console.print(Panel(f"Submitted: {submitted}\nRejected: {rejected}\nSkipped: {skipped}\nErrors: {errors}", title="AWI PR Complete"))


@cli.command("status")
@click.option("--no-refresh", is_flag=True, help="Show cached statuses without GitHub refresh.")
@click.pass_context
def status(ctx, no_refresh):
    """Show tracked AWI issues and PRs."""
    from awi_contribai.awi.status import print_status

    print_banner()
    cfg_path = Path(ctx.obj["config_path"]) if ctx.obj["config_path"] else Path("config.yaml")
    asyncio.run(print_status(cfg_path, refresh=not no_refresh))


if __name__ == "__main__":
    cli()
