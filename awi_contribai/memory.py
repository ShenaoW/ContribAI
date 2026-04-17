"""SQLite status tracking for AWI issues and PRs."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS submitted_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    issue_url TEXT NOT NULL,
    title TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'awi_disclosure',
    status TEXT DEFAULT 'open',
    linked_pr_url TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT,
    UNIQUE(repo, issue_number)
);

CREATE TABLE IF NOT EXISTS submitted_prs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    pr_url TEXT NOT NULL,
    title TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'awi_fix',
    status TEXT DEFAULT 'open',
    branch TEXT,
    fork TEXT,
    created_at TEXT,
    updated_at TEXT,
    UNIQUE(repo, pr_number)
);
"""


class Memory:
    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path).expanduser()
        self._db: aiosqlite.Connection | None = None

    async def init(self):
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.executescript(SCHEMA)
        await self._db.commit()

    async def close(self):
        if self._db:
            await self._db.close()

    async def record_issue(self, repo: str, issue_number: int, issue_url: str, title: str, issue_type: str):
        now = datetime.now(UTC).isoformat()
        await self._db.execute(
            """INSERT OR REPLACE INTO submitted_issues
               (repo, issue_number, issue_url, title, type, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (repo, issue_number, issue_url, title, issue_type, now, now),
        )
        await self._db.commit()

    async def update_issue_status(
        self,
        repo: str,
        issue_number: int,
        status: str,
        linked_pr_url: str | None = None,
    ):
        now = datetime.now(UTC).isoformat()
        if linked_pr_url is None:
            await self._db.execute(
                "UPDATE submitted_issues SET status = ?, updated_at = ? WHERE repo = ? AND issue_number = ?",
                (status, now, repo, issue_number),
            )
        else:
            await self._db.execute(
                """UPDATE submitted_issues
                   SET status = ?, linked_pr_url = ?, updated_at = ?
                   WHERE repo = ? AND issue_number = ?""",
                (status, linked_pr_url, now, repo, issue_number),
            )
        await self._db.commit()

    async def get_issues(self, issue_type: str | None = None, limit: int = 100) -> list[dict]:
        if issue_type:
            cursor = await self._db.execute(
                "SELECT * FROM submitted_issues WHERE type = ? ORDER BY created_at DESC LIMIT ?",
                (issue_type, limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM submitted_issues ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def record_pr(
        self,
        repo: str,
        pr_number: int,
        pr_url: str,
        title: str,
        pr_type: str,
        branch: str = "",
        fork: str = "",
    ):
        now = datetime.now(UTC).isoformat()
        await self._db.execute(
            """INSERT OR REPLACE INTO submitted_prs
               (repo, pr_number, pr_url, title, type, branch, fork, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (repo, pr_number, pr_url, title, pr_type, branch, fork, now, now),
        )
        await self._db.commit()

    async def update_pr_status(self, repo: str, pr_number: int, status: str):
        await self._db.execute(
            "UPDATE submitted_prs SET status = ?, updated_at = ? WHERE repo = ? AND pr_number = ?",
            (status, datetime.now(UTC).isoformat(), repo, pr_number),
        )
        await self._db.commit()

    async def get_prs(self, limit: int = 100) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM submitted_prs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]
