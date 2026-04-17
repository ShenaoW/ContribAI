"""Minimal data models for the AWI-only workflow."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ContributionType(StrEnum):
    SECURITY_FIX = "security_fix"


class Severity(StrEnum):
    HIGH = "high"


class PRStatus(StrEnum):
    OPEN = "open"
    MERGED = "merged"
    CLOSED = "closed"
    REVIEW_REQUESTED = "review_requested"
    PENDING = "pending"


class Repository(BaseModel):
    owner: str
    name: str
    full_name: str
    description: str | None = None
    language: str | None = None
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    topics: list[str] = Field(default_factory=list)
    default_branch: str = "main"
    html_url: str = ""
    clone_url: str = ""

    @property
    def url(self) -> str:
        return f"https://github.com/{self.full_name}"


class FileNode(BaseModel):
    path: str
    type: str
    size: int = 0
    sha: str = ""


class Finding(BaseModel):
    type: ContributionType
    severity: Severity
    title: str
    description: str
    file_path: str
    suggestion: str | None = None
    confidence: float = 0.95


class FileChange(BaseModel):
    path: str
    original_content: str | None = None
    new_content: str
    is_new_file: bool = False
    is_deleted: bool = False


class Contribution(BaseModel):
    finding: Finding
    contribution_type: ContributionType
    title: str
    description: str
    changes: list[FileChange] = Field(default_factory=list)
    commit_message: str = ""
    tests_added: list[FileChange] = Field(default_factory=list)
    branch_name: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def total_files_changed(self) -> int:
        return len(self.changes) + len(self.tests_added)


class PRResult(BaseModel):
    repo: Repository
    contribution: Contribution
    pr_number: int
    pr_url: str
    status: PRStatus = PRStatus.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    branch_name: str = ""
    fork_full_name: str = ""


class RepoContext(BaseModel):
    repo: Repository
    file_tree: list[FileNode] = Field(default_factory=list)
    relevant_files: dict[str, str] = Field(default_factory=dict)
