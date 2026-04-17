"""Small GitHub REST client for AWI disclosure and PR submission."""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from typing import Any

import httpx

from awi_contribai.core.exceptions import GitHubAPIError, RateLimitError
from awi_contribai.core.models import Repository

logger = logging.getLogger(__name__)
GITHUB_API = "https://api.github.com"


class GitHubClient:
    def __init__(self, token: str, rate_limit_buffer: int = 100):
        self.token = token
        self.rate_limit_buffer = rate_limit_buffer
        self._client = httpx.AsyncClient(
            base_url=GITHUB_API,
            timeout=60.0,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "awi-contribai",
            },
        )

    async def close(self):
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        response = await self._client.request(method, path, **kwargs)
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining is not None and int(remaining) < self.rate_limit_buffer:
            reset_at = response.headers.get("x-ratelimit-reset")
            raise RateLimitError(f"GitHub API rate limit buffer reached; reset={reset_at}")
        if response.status_code >= 400:
            raise GitHubAPIError(
                f"GitHub {method} {path} failed: {response.status_code} {response.text[:500]}",
                status_code=response.status_code,
            )
        if response.status_code == 204:
            return None
        return response.json()

    async def _get(self, path: str, **kwargs) -> Any:
        return await self._request("GET", path, **kwargs)

    async def _post(self, path: str, **kwargs) -> Any:
        return await self._request("POST", path, **kwargs)

    async def _put(self, path: str, **kwargs) -> Any:
        return await self._request("PUT", path, **kwargs)

    async def get_authenticated_user(self) -> dict:
        return await self._get("/user")

    async def get_repo_details(self, owner: str, repo: str) -> Repository:
        data = await self._get(f"/repos/{owner}/{repo}")
        owner_login = data.get("owner", {}).get("login", owner)
        return Repository(
            owner=owner_login,
            name=data["name"],
            full_name=data["full_name"],
            description=data.get("description"),
            language=data.get("language"),
            stars=data.get("stargazers_count", 0),
            forks=data.get("forks_count", 0),
            open_issues=data.get("open_issues_count", 0),
            topics=data.get("topics", []),
            default_branch=data.get("default_branch", "main"),
            html_url=data.get("html_url", ""),
            clone_url=data.get("clone_url", ""),
        )

    async def get_file_content(self, owner: str, repo: str, path: str, ref: str | None = None) -> str:
        params = {"ref": ref} if ref else None
        data = await self._get(f"/repos/{owner}/{repo}/contents/{path}", params=params)
        if isinstance(data, list):
            raise GitHubAPIError(f"Path is a directory: {path}")
        content = data.get("content", "")
        encoding = data.get("encoding")
        if encoding == "base64":
            return base64.b64decode(content).decode("utf-8")
        return content

    async def fork_repository(self, owner: str, repo: str) -> Repository:
        data = await self._post(f"/repos/{owner}/{repo}/forks")
        fork_owner = data.get("owner", {}).get("login", owner)
        return Repository(
            owner=fork_owner,
            name=data["name"],
            full_name=data["full_name"],
            default_branch=data.get("default_branch", "main"),
            html_url=data.get("html_url", ""),
            clone_url=data.get("clone_url", ""),
        )

    async def create_branch(self, owner: str, repo: str, branch: str, base: str | None = None) -> None:
        details = await self.get_repo_details(owner, repo)
        base_branch = base or details.default_branch
        ref = await self._get(f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
        sha = ref["object"]["sha"]
        try:
            await self._post(
                f"/repos/{owner}/{repo}/git/refs",
                json={"ref": f"refs/heads/{branch}", "sha": sha},
            )
        except GitHubAPIError as exc:
            if exc.status_code == 422:
                logger.info("Branch already exists: %s/%s:%s", owner, repo, branch)
                return
            raise

    async def create_or_update_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        *,
        sha: str | None = None,
        signoff: str | None = None,
    ) -> dict:
        if signoff and "Signed-off-by:" not in message:
            message = f"{message}\n\nSigned-off-by: {signoff}"
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        return await self._put(f"/repos/{owner}/{repo}/contents/{path}", json=payload)

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> dict:
        return await self._post(
            f"/repos/{owner}/{repo}/pulls",
            json={"title": title, "body": body, "head": head, "base": base},
        )

    async def create_issue(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict:
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels
        return await self._post(f"/repos/{owner}/{repo}/issues", json=payload)
