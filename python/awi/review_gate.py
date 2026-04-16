"""Human-in-the-loop review gate for AWI issue submission.

Displays the generated issue title and body in a Rich terminal UI
and prompts the user to approve, edit, reject, or skip before submission.
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)
console = Console()


class IssueReviewDecision:
    """Result of a human review decision for an issue."""

    APPROVE = "approve"
    REJECT = "reject"
    SKIP = "skip"

    def __init__(self, action: str, reason: str = ""):
        self.action = action
        self.reason = reason

    @property
    def approved(self) -> bool:
        return self.action == self.APPROVE

    @property
    def rejected(self) -> bool:
        return self.action == self.REJECT

    @property
    def skipped(self) -> bool:
        return self.action == self.SKIP

    def __repr__(self) -> str:
        return f"IssueReviewDecision(action={self.action!r}, reason={self.reason!r})"


class IssueReviewer:
    """Interactive review gate for AWI issue submission.

    Renders the issue title and Markdown body in the terminal, along with
    a summary of the underlying findings, then prompts for approval.

    Set ``auto_approve=True`` for non-interactive batch mode.
    """

    def __init__(self, *, auto_approve: bool = False):
        self._auto_approve = auto_approve

    async def review(
        self,
        repo: str,
        title: str,
        body: str,
        findings_count: int,
        actions: list[str],
        taint_sources: list[str],
        workflow_urls: list[str],
    ) -> IssueReviewDecision:
        """Present an issue for human review.

        Args:
            repo: GitHub repo slug (owner/repo).
            title: Generated issue title.
            body: Generated issue body (Markdown).
            findings_count: Number of AWI findings for this repo.
            actions: List of AI actions involved.
            taint_sources: List of taint sources (attacker-controlled inputs).
            workflow_urls: Links to affected workflow files.

        Returns:
            IssueReviewDecision with the user's choice.
        """
        if self._auto_approve:
            logger.info("[auto-approve] %s — %s", repo, title)
            return IssueReviewDecision(IssueReviewDecision.APPROVE, "auto")

        self._display_review(
            repo, title, body, findings_count, actions, taint_sources, workflow_urls
        )
        return self._prompt_decision()

    def _display_review(
        self,
        repo: str,
        title: str,
        body: str,
        findings_count: int,
        actions: list[str],
        taint_sources: list[str],
        workflow_urls: list[str],
    ) -> None:
        """Display the issue in Rich panels."""
        console.print()
        console.rule("[bold cyan]AWI Issue Review[/bold cyan]")
        console.print()

        # Summary table
        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("Key", style="bold cyan", min_width=16)
        info_table.add_column("Value")

        info_table.add_row("Repository", f"[bold]{repo}[/bold]")
        info_table.add_row("Findings", str(findings_count))
        info_table.add_row("Actions", ", ".join(actions))
        info_table.add_row("Taint sources", "\n".join(f"• {s}" for s in taint_sources))
        info_table.add_row(
            "Workflows",
            "\n".join(f"[link={u}]{u}[/link]" for u in workflow_urls[:3])
            + (f"\n... and {len(workflow_urls) - 3} more" if len(workflow_urls) > 3 else ""),
        )

        console.print(
            Panel(info_table, title="[bold]Vulnerability Summary", border_style="yellow")
        )

        # Issue title
        console.print(
            Panel(
                Text(title, style="bold white"),
                title="[bold]Issue Title",
                border_style="blue",
            )
        )

        # Issue body (rendered Markdown)
        try:
            md = Markdown(body)
            console.print(Panel(md, title="[bold]Issue Body (preview)", border_style="green"))
        except Exception:
            console.print(
                Panel(body[:3000] + ("..." if len(body) > 3000 else ""),
                      title="[bold]Issue Body",
                      border_style="green")
            )

        console.print()

    @staticmethod
    def _prompt_decision() -> IssueReviewDecision:
        """Prompt user for approval decision."""
        choices = Text()
        choices.append("[y]", style="bold green")
        choices.append("es — submit issue  ")
        choices.append("[n]", style="bold red")
        choices.append("o — reject  ")
        choices.append("[s]", style="bold yellow")
        choices.append("kip — skip for now")

        console.print(Panel(choices, title="[bold]Submit this issue?", border_style="cyan"))

        while True:
            try:
                response = console.input("[bold cyan]→ [/bold cyan]").strip().lower()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[yellow]Skipped (interrupted)[/yellow]")
                return IssueReviewDecision(IssueReviewDecision.SKIP, "interrupted")

            if response in ("y", "yes"):
                console.print("[green]Approved — submitting issue...[/green]")
                return IssueReviewDecision(IssueReviewDecision.APPROVE)
            if response in ("n", "no"):
                console.print("[red]Rejected — skipping this repo[/red]")
                return IssueReviewDecision(IssueReviewDecision.REJECT)
            if response in ("s", "skip"):
                console.print("[yellow]Skipped[/yellow]")
                return IssueReviewDecision(IssueReviewDecision.SKIP)

            console.print("[dim]Please enter y, n, or s[/dim]")
