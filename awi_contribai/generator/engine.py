"""AWI-specific YAML patch generator."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from awi_contribai.core.config import ContributionConfig
from awi_contribai.core.models import Contribution, FileChange, Finding, RepoContext
from awi_contribai.llm.provider import LLMProvider

logger = logging.getLogger(__name__)


class ContributionGenerator:
    """Generate a focused workflow YAML patch for an AWI finding."""

    def __init__(self, llm: LLMProvider, config: ContributionConfig):
        self._llm = llm
        self._config = config

    async def generate(self, finding: Finding, context: RepoContext, *, guidelines=None) -> Contribution | None:
        prompt = self._build_prompt(finding, context)
        response = await self._llm.complete(prompt, system=self._system_prompt(), temperature=0.2)
        changes = self._parse_changes(response, context)
        if not changes:
            logger.warning("No valid YAML patch generated for %s", finding.file_path)
            return None
        return Contribution(
            finding=finding,
            contribution_type=finding.type,
            title=self._pr_title(finding),
            description=finding.description,
            changes=changes,
            commit_message=self._commit_message(finding),
            branch_name=self._branch_name(finding),
            generated_at=datetime.now(UTC),
        )

    def _system_prompt(self) -> str:
        return (
            "You are a security engineer fixing GitHub Actions workflow YAML. "
            "Return only valid JSON. Do not include markdown fences or commentary. "
            "Make the smallest safe change that fixes Agentic Workflow Injection."
        )

    def _build_prompt(self, finding: Finding, context: RepoContext) -> str:
        current = context.relevant_files.get(finding.file_path, "")
        return f"""
Fix this Agentic Workflow Injection vulnerability.

Repository: {context.repo.full_name}
File: {finding.file_path}
Title: {finding.title}
Description: {finding.description}
Required fix guidance:
{finding.suggestion or ''}

Current YAML:
```yaml
{current}
```

Return JSON in exactly this shape:
{{
  "changes": [
    {{
      "path": "{finding.file_path}",
      "new_content": "<complete patched YAML file>"
    }}
  ]
}}

Rules:
- Return the complete patched YAML file, not a diff.
- Preserve existing workflow behavior as much as possible.
- Add a trusted actor gate at the job level when missing.
- Remove direct prompt interpolation of attacker-controlled title/body/comment/ref fields.
- Use ID-based fetch instructions with gh CLI where the workflow still needs content.
- Do not replace content with placeholders like [REDACTED].
""".strip()

    def _parse_changes(self, response: str, context: RepoContext) -> list[FileChange]:
        raw = response.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("LLM returned non-JSON patch: %s", raw[:300])
            return []
        changes = []
        for item in data.get("changes", []):
            path = item.get("path")
            new_content = item.get("new_content")
            if not path or not new_content:
                continue
            changes.append(
                FileChange(
                    path=path,
                    original_content=context.relevant_files.get(path),
                    new_content=new_content.rstrip() + "\n",
                )
            )
        return changes

    def _pr_title(self, finding: Finding) -> str:
        return f"fix: prevent AWI in {finding.file_path.split('/')[-1]}"

    def _commit_message(self, finding: Finding) -> str:
        if self._config.commit_convention == "none":
            return f"Prevent AWI in {finding.file_path}"
        return f"fix(security): prevent AWI in {finding.file_path}"

    def _branch_name(self, finding: Finding) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")[:48]
        return f"fix/security-{slug or 'awi-workflow'}"
