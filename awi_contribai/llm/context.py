"""Prompt context helpers for AWI patch generation."""

from __future__ import annotations

from awi_contribai.core.models import RepoContext


def build_repo_context_prompt(context: RepoContext, max_tokens: int = 4000) -> str:
    parts = [
        f"Repository: {context.repo.full_name}",
        f"Default branch: {context.repo.default_branch}",
    ]
    for path, content in context.relevant_files.items():
        max_chars = max_tokens * 4
        snippet = content[:max_chars]
        parts.append(f"\nFile: {path}\n```yaml\n{snippet}\n```")
    return "\n".join(parts)
