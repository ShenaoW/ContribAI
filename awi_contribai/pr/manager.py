"""Fork, branch, commit, and PR creation for AWI fixes."""

from __future__ import annotations

import logging
import re

from awi_contribai.core.exceptions import PRCreationError
from awi_contribai.core.models import Contribution, ContributionType, PRResult, PRStatus, Repository
from awi_contribai.github.client import GitHubClient

logger = logging.getLogger(__name__)


class PRManager:
    def __init__(self, github: GitHubClient):
        self._github = github
        self._user: dict | None = None

    async def _get_user(self) -> dict:
        if self._user is None:
            self._user = await self._github.get_authenticated_user()
        return self._user

    def _build_signoff(self, user: dict) -> str | None:
        name = user.get("name") or user.get("login")
        email = user.get("email")
        if not email:
            email = f"{user.get('id', '')}+{user.get('login', '')}@users.noreply.github.com"
        return f"{name} <{email}>" if name else None

    async def create_pr(
        self,
        contribution: Contribution,
        target_repo: Repository,
        *,
        guidelines=None,
        closes_issue: int | None = None,
    ) -> PRResult:
        try:
            user = await self._get_user()
            username = user["login"]
            signoff = self._build_signoff(user)

            fork = await self._fork_if_needed(username, target_repo)
            branch = contribution.branch_name or self._branch_name(contribution)
            await self._github.create_branch(fork.owner, fork.name, branch, base=target_repo.default_branch)

            for change in contribution.changes:
                sha = None
                if not change.is_new_file:
                    try:
                        data = await self._github._get(
                            f"/repos/{fork.owner}/{fork.name}/contents/{change.path}",
                            params={"ref": branch},
                        )
                        sha = data.get("sha")
                    except Exception:
                        sha = None
                await self._github.create_or_update_file(
                    fork.owner,
                    fork.name,
                    change.path,
                    change.new_content,
                    contribution.commit_message,
                    branch,
                    sha=sha,
                    signoff=signoff,
                )

            body = self._pr_body(contribution, closes_issue=closes_issue)
            pr_data = await self._github.create_pull_request(
                target_repo.owner,
                target_repo.name,
                title=contribution.title,
                body=body,
                head=f"{fork.owner}:{branch}",
                base=target_repo.default_branch,
            )
            return PRResult(
                repo=target_repo,
                contribution=contribution,
                pr_number=pr_data["number"],
                pr_url=pr_data["html_url"],
                status=PRStatus.OPEN,
                branch_name=branch,
                fork_full_name=f"{fork.owner}/{fork.name}",
            )
        except Exception as exc:
            raise PRCreationError(f"Failed to create PR: {exc}") from exc

    async def _fork_if_needed(self, username: str, repo: Repository) -> Repository:
        try:
            existing = await self._github.get_repo_details(username, repo.name)
            if existing.owner == username:
                return existing
        except Exception:
            pass
        return await self._github.fork_repository(repo.owner, repo.name)

    def _branch_name(self, contribution: Contribution) -> str:
        prefix = "fix/security" if contribution.finding.type == ContributionType.SECURITY_FIX else "fix"
        slug = re.sub(r"[^a-z0-9]+", "-", contribution.finding.title.lower()).strip("-")[:48]
        return f"{prefix}-{slug or 'awi'}"

    def _pr_body(self, contribution: Contribution, *, closes_issue: int | None) -> str:
        files = "\n".join(f"- `{change.path}`" for change in contribution.changes)
        issue_line = f"\n\nCloses #{closes_issue}" if closes_issue else ""
        return f"""## Problem

{contribution.finding.description}

## Solution

{contribution.finding.suggestion or contribution.description}

## Changes

{files}

## Validation

- [ ] Workflow YAML remains valid
- [ ] Prompt no longer directly interpolates attacker-controlled event text
- [ ] Existing workflow behavior is preserved where possible{issue_line}
"""
