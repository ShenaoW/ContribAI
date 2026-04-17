"""Configuration for the standalone AWI disclosure tool."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from awi_contribai.core.exceptions import ConfigError


class GitHubConfig(BaseModel):
    """GitHub API configuration."""

    token: str = ""
    rate_limit_buffer: int = 100

    @model_validator(mode="after")
    def resolve_token(self):
        if not self.token:
            self.token = os.environ.get("GITHUB_TOKEN", "")
        if not self.token:
            try:
                result = subprocess.run(
                    ["gh", "auth", "token"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0 and result.stdout.strip():
                    self.token = result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        return self


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: Literal["openai", "gemini", "anthropic", "ollama"] = "openai"
    model: str = "gpt-5.4"
    api_key: str = ""
    base_url: str | None = None
    temperature: float = 0.3
    max_tokens: int = 8192
    vertex_project: str = ""
    vertex_location: str = "global"

    @model_validator(mode="after")
    def resolve_api_key_and_defaults(self):
        if not self.api_key:
            env_map = {
                "openai": "OPENAI_API_KEY",
                "gemini": "GEMINI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
            }
            env_var = env_map.get(self.provider)
            if env_var:
                self.api_key = os.environ.get(env_var, "")
        if not self.vertex_project:
            self.vertex_project = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        return self

    @property
    def use_vertex(self) -> bool:
        return bool(self.vertex_project)


class StorageConfig(BaseModel):
    """Local state paths."""

    db_path: str = "~/.awi-contribai/memory.db"

    @property
    def resolved_db_path(self) -> Path:
        return Path(self.db_path).expanduser()


class ContributionConfig(BaseModel):
    """Patch generation settings."""

    commit_convention: Literal["conventional", "none"] = "conventional"
    pr_description_style: Literal["minimal", "detailed"] = "detailed"


class AWIConfig(BaseModel):
    """Root config for the AWI-only tool."""

    github: GitHubConfig = Field(default_factory=GitHubConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    contribution: ContributionConfig = Field(default_factory=ContributionConfig)


def load_config(path: str | Path | None = None) -> AWIConfig:
    """Load config from explicit path, ./config.yaml, or ~/.awi-contribai/config.yaml."""
    search_paths = [
        Path(path) if path else None,
        Path("config.yaml"),
        Path.home() / ".awi-contribai" / "config.yaml",
    ]
    for candidate in search_paths:
        if candidate and candidate.exists():
            try:
                raw = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
                return AWIConfig(**raw)
            except yaml.YAMLError as exc:
                raise ConfigError(f"Invalid YAML in {candidate}: {exc}") from exc
            except Exception as exc:
                raise ConfigError(f"Failed to load config from {candidate}: {exc}") from exc
    return AWIConfig()
