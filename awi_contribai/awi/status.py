"""AWI issue/PR status refresh & display.

Queries GitHub for the current state of every AWI-submitted issue/PR
tracked in the ContribAI memory DB, updates the stored status, and
prints a table summary.
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

from awi_contribai.awi.runner import build_github_client, build_memory

logger = logging.getLogger(__name__)
console = Console()


# GitHub PR states we care about. `merged` is derived from a separate flag
# on the /pulls response, not from `state`.
def _derive_pr_status(data: dict) -> str:
    if data.get("merged"):
        return "merged"
    if data.get("state") == "closed":
        return "closed"
    if data.get("draft"):
        return "draft"
    # Request-review activity
    if data.get("requested_reviewers"):
        return "review_requested"
    return "open"


def _derive_issue_status(data: dict) -> str:
    state = data.get("state", "open")
    if state == "closed":
        # closed_by reason in some API responses
        reason = data.get("state_reason") or ""
        if reason == "completed":
            return "closed_completed"
        return "closed"
    return state


async def refresh_all(config_path: Path) -> tuple[int, int]:
    """Refresh issue + PR statuses from GitHub. Returns (issues_refreshed, prs_refreshed)."""
    github = build_github_client(config_path)
    memory = await build_memory(config_path)
    issues_done = prs_done = 0

    try:
        # ── Issues ──
        issues = await memory.get_issues()
        for row in issues:
            repo = row["repo"]
            num = row["issue_number"]
            owner, name = repo.split("/", 1)
            try:
                data = await github._get(f"/repos/{owner}/{name}/issues/{num}")
            except Exception as e:
                logger.warning("Issue %s#%d fetch failed: %s", repo, num, e)
                continue
            new_status = _derive_issue_status(data)
            if new_status != row["status"]:
                await memory.update_issue_status(repo, num, new_status)
            issues_done += 1

        # ── PRs ──
        prs = await memory.get_prs()
        for row in prs:
            repo = row["repo"]
            num = row["pr_number"]
            owner, name = repo.split("/", 1)
            try:
                data = await github._get(f"/repos/{owner}/{name}/pulls/{num}")
            except Exception as e:
                logger.warning("PR %s#%d fetch failed: %s", repo, num, e)
                continue
            new_status = _derive_pr_status(data)
            if new_status != row["status"]:
                await memory.update_pr_status(repo, num, new_status)
            prs_done += 1

        return issues_done, prs_done
    finally:
        await github.close()
        await memory.close()


async def print_status(config_path: Path, *, refresh: bool = True) -> None:
    """Show all AWI issues & PRs with their current status."""
    if refresh:
        console.print("[dim]Refreshing statuses from GitHub...[/dim]")
        i_done, p_done = await refresh_all(config_path)
        console.print(f"[dim]Refreshed {i_done} issues, {p_done} PRs.[/dim]\n")

    memory = await build_memory(config_path)
    try:
        issues = await memory.get_issues(issue_type="awi_disclosure")
        prs = await memory.get_prs()
        # Filter PRs to AWI-submitted ones only
        awi_prs = [p for p in prs if p.get("type") == "awi_fix"]

        # ── Issues table ──
        i_table = Table(title=f"AWI Disclosure Issues ({len(issues)})")
        i_table.add_column("Repo", style="cyan")
        i_table.add_column("#", justify="right")
        i_table.add_column("Status")
        i_table.add_column("Linked PR", style="dim")
        i_table.add_column("Updated", style="dim")
        for r in issues:
            status_color = {
                "open": "green",
                "closed": "red",
                "closed_completed": "green",
            }.get(r["status"], "yellow")
            i_table.add_row(
                r["repo"],
                str(r["issue_number"]),
                f"[{status_color}]{r['status']}[/{status_color}]",
                r.get("linked_pr_url") or "—",
                r.get("updated_at", "")[:10],
            )
        console.print(i_table)

        # ── PRs table ──
        p_table = Table(title=f"AWI Fix PRs ({len(awi_prs)})")
        p_table.add_column("Repo", style="cyan")
        p_table.add_column("#", justify="right")
        p_table.add_column("Status")
        p_table.add_column("URL", style="dim")
        p_table.add_column("Updated", style="dim")
        for r in awi_prs:
            status_color = {
                "open": "green",
                "merged": "magenta",
                "closed": "red",
                "review_requested": "yellow",
                "draft": "dim",
            }.get(r["status"], "white")
            p_table.add_row(
                r["repo"],
                str(r["pr_number"]),
                f"[{status_color}]{r['status']}[/{status_color}]",
                r["pr_url"],
                r.get("updated_at", "")[:10],
            )
        console.print(p_table)
    finally:
        await memory.close()
