"""LLM-based AWI vulnerability issue generator.

Generates responsible disclosure issues for GitHub Actions workflows
that are vulnerable to Agentic Workflow Injection (prompt injection)
attacks via attacker-controlled GitHub event data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contribai.llm.provider import LLMProvider

logger = logging.getLogger(__name__)


# ── Per-action fix guidance ────────────────────────────────────────────────────

FIX_GUIDANCE: dict[str, str] = {
    "anthropics/claude-code-action": """
**Fix approach for `anthropics/claude-code-action`:**
The action has a built-in access control parameter `allowed_tools` and, more importantly,
`allowed_non_write_users`. By default it restricts execution to users with write access.
However, if the workflow passes attacker-controlled data (issue title/body, comment body,
PR title/body, branch name) directly or indirectly into the `prompt` input without
sanitization, it remains vulnerable to prompt injection.

Recommended mitigations:
1. **Input sanitization**: Strip or escape special characters from event data before
   embedding in the `prompt` field. Avoid interpolating raw GitHub context variables
   directly.
2. **Scope limiting**: Set `allowed_tools` to the minimum necessary set of tools.
   Avoid enabling file-write or shell-exec tools unless strictly required.
3. **Access control**: Ensure `allowed_non_write_users` is not set to a value that
   permits untrusted users to trigger the workflow.
4. **Conditional guards**: Wrap the Claude step with a condition that validates the
   actor is trusted (e.g., `if: github.actor == github.repository_owner`).
""",

    "anthropic-ai/claude-code-action": """
**Fix approach for `anthropic-ai/claude-code-action`:**
Same as `anthropics/claude-code-action`. Ensure the `prompt` input does not directly
interpolate unvalidated GitHub event fields. Limit `allowed_tools` and restrict
triggering conditions to trusted actors.
""",

    "google-github-actions/run-gemini-cli": """
**Fix approach for `google-github-actions/run-gemini-cli`:**
This action has **no built-in access control**. Any user who can trigger the workflow
(e.g., by opening an issue, posting a comment, or creating a PR) can inject arbitrary
instructions into the Gemini CLI prompt.

Recommended mitigations:
1. **Actor allowlist**: Add a condition to restrict execution to trusted users:
   ```yaml
   if: github.actor == github.repository_owner ||
       contains(fromJSON('["trusted-bot"]'), github.actor)
   ```
2. **Input sanitization**: Do not interpolate `github.event.issue.body`,
   `github.event.comment.body`, or PR fields directly into the `prompt` parameter.
   Extract only structured data (e.g., issue number, label name) or pass via a
   sanitized summary step.
3. **Sandbox the action**: Run in a read-only environment where the Gemini CLI cannot
   write to the repository or call external APIs.
4. **Rate limiting**: Add concurrency controls to prevent abuse via rapid event creation.
""",

    "google-github-actions/gemini-cli-action": """
**Fix approach for `google-github-actions/gemini-cli-action`:**
Same as `run-gemini-cli`. This action also lacks built-in access control. Apply actor
allowlisting, avoid raw event data interpolation in prompts, and consider running in
a restricted sandbox environment.
""",

    "openai/codex-action": """
**Fix approach for `openai/codex-action`:**
The action supports an `allow-users` parameter that restricts who can trigger it.
However, if the workflow interpolates attacker-controlled event data (issue/PR
title, body, comment) into the prompt without validation, the access control is
insufficient.

Recommended mitigations:
1. **Set `allow-users`**: Explicitly configure `allow-users` with a list of trusted
   GitHub usernames or use organization membership checks.
2. **Input validation**: Never pass `github.event.issue.body` or similar fields
   directly into any prompt input. Use structured data extraction instead.
3. **Principle of least privilege**: Set `allow-write` to `false` if only read
   operations are needed.
""",
}

DEFAULT_FIX_GUIDANCE = """
**General fix guidance:**
1. **Never interpolate raw GitHub event data** (issue title/body, comment body, PR
   title/body, branch name) directly into AI agent prompt fields.
2. **Restrict who can trigger the workflow** using `if:` conditions based on
   `github.actor`, organization membership, or role checks.
3. **Apply the principle of least privilege**: limit the AI agent's capabilities
   (file access, API calls) to what is strictly necessary.
4. **Add input validation**: validate or sanitize external inputs before embedding
   them in prompts.
"""

# ── System prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security researcher specializing in responsible disclosure of AI security
vulnerabilities in CI/CD pipelines. You write clear, professional vulnerability
reports as GitHub issues.

Your reports:
- Are factual and non-alarmist
- Clearly explain the vulnerability class (prompt injection / agentic workflow injection)
- Show the specific vulnerable code path
- Provide actionable remediation steps
- Use standard GitHub Markdown formatting
- Are respectful and constructive in tone
- Do NOT include any boilerplate like "I hope this finds you well"
- Do NOT claim proof-of-concept exploits were run against the repository

Format your response as:
TITLE: <concise issue title, max 80 chars>
BODY:
<full markdown issue body>
"""

# ── Taint source → attack vector mapping ──────────────────────────────────────

TAINT_SOURCE_TRIGGERS: dict[str, str] = {
    "github.event.issue.title": "creating or editing an issue with a crafted title",
    "github.event.issue.body": "creating or editing an issue with a crafted body",
    "github.event.comment.body": "posting a crafted comment on an issue or PR",
    "github.event.pull_request.title": "opening a PR with a crafted title",
    "github.event.pull_request.body": "opening a PR with a crafted body",
    "github.event.pull_request.head.ref": "creating a branch with a crafted name",
    "github.event.pull_request.head.label": "creating a PR from a fork with a crafted label",
    "github.head_ref": "creating a branch with a crafted name",
    "github.event.review.body": "submitting a PR review with crafted content",
    "github.event.review_comment.body": "posting a crafted inline PR review comment",
    "github.event.discussion.body": "creating a discussion with crafted content",
    "github.event.discussion_comment.body": "posting a crafted discussion comment",
    "github.event.release.body": "publishing a release with crafted release notes",
    "github.event.release.name": "publishing a release with a crafted release name",
}


def _infer_trigger(taint_source: str) -> str:
    """Map a taint source to a human-readable attack vector description."""
    for key, desc in TAINT_SOURCE_TRIGGERS.items():
        if key in taint_source:
            return desc
    # Fallback: extract meaningful part from expression
    clean = re.sub(r"github\.event\.", "a crafted GitHub event field: ", taint_source)
    return clean


def _get_fix_guidance(action: str) -> str:
    """Return fix guidance for the given action name."""
    for key, guidance in FIX_GUIDANCE.items():
        if key in action:
            return guidance
    return DEFAULT_FIX_GUIDANCE


# ── Data structures ────────────────────────────────────────────────────────────


@dataclass
class AWIFinding:
    """A single AWI finding from the ARGUS scan output."""

    repo: str           # owner/repo
    workflow: str       # .github/workflows/foo.yml
    workflow_url: str   # GitHub permalink
    action: str         # e.g. anthropics/claude-code-action
    taint_source: str   # e.g. github.event.issue.body
    source_location: str
    sink_location: str
    access_control: str  # "open" or "restricted"


# ── Main class ─────────────────────────────────────────────────────────────────


class AWIIssueWriter:
    """Generate LLM-based AWI vulnerability issues for affected repositories.

    Usage::

        writer = AWIIssueWriter(llm_provider)
        title, body = await writer.generate("owner/repo", findings)
    """

    def __init__(self, llm: LLMProvider):
        self._llm = llm

    async def generate(
        self,
        repo: str,
        findings: list[AWIFinding],
        *,
        workflow_yaml: str | None = None,
    ) -> tuple[str, str] | None:
        """Generate an issue title and body for the given repository's findings.

        Args:
            repo: GitHub repo slug (owner/repo).
            findings: List of AWI findings for this repo.
            workflow_yaml: Optional raw workflow YAML content to include.

        Returns:
            (title, body) tuple, or None if generation failed.
        """
        prompt = self._build_prompt(repo, findings, workflow_yaml)
        try:
            raw = await self._llm.complete(prompt, system=SYSTEM_PROMPT, temperature=0.3)
        except Exception as e:
            logger.error("LLM generation failed for %s: %s", repo, e)
            return None

        return self._parse_response(raw, repo, findings)

    def _build_prompt(
        self,
        repo: str,
        findings: list[AWIFinding],
        workflow_yaml: str | None,
    ) -> str:
        """Build the LLM prompt for issue generation."""
        # Deduplicate actions and taint sources across findings
        actions = sorted({f.action for f in findings})
        taint_sources = sorted({f.taint_source for f in findings})
        workflows = sorted({f.workflow for f in findings})
        workflow_urls = sorted({f.workflow_url for f in findings})

        # Build attack vectors list
        attack_vectors = []
        for ts in taint_sources:
            trigger = _infer_trigger(ts)
            attack_vectors.append(f"- `{ts}` — via {trigger}")

        # Build per-finding table
        finding_rows = []
        for f in findings:
            finding_rows.append(
                f"| `{f.workflow}` | `{f.taint_source}` | {f.sink_location} |"
            )

        # Get fix guidance for the primary action
        primary_action = actions[0] if actions else "unknown"
        fix_guidance = _get_fix_guidance(primary_action)

        yaml_section = ""
        if workflow_yaml:
            # Truncate very long YAML
            if len(workflow_yaml) > 3000:
                yaml_section = (
                    f"\n\nHere is the relevant workflow YAML (truncated to 3000 chars):\n"
                    f"```yaml\n{workflow_yaml[:3000]}\n... (truncated)\n```"
                )
            else:
                yaml_section = (
                    f"\n\nHere is the workflow YAML:\n"
                    f"```yaml\n{workflow_yaml}\n```"
                )

        prompt = f"""\
Write a responsible disclosure GitHub issue for the repository `{repo}`.

## Vulnerability Summary

**Vulnerability class**: Agentic Workflow Injection (AWI) — a form of prompt injection
where attacker-controlled GitHub event data flows into AI agent prompts without
sanitization or access control validation.

**Affected repository**: {repo}
**Affected workflows**: {", ".join(f"`{w}`" for w in workflows)}
**Workflow links**: {", ".join(workflow_urls)}
**AI actions used**: {", ".join(f"`{a}`" for a in actions)}
**Number of vulnerable data flows**: {len(findings)}

## Taint Sources (attacker-controlled inputs)

{chr(10).join(attack_vectors)}

## Findings Detail

| Workflow | Taint Source | Sink Location |
|----------|-------------|---------------|
{chr(10).join(finding_rows)}

## Fix Guidance to Include

{fix_guidance}
{yaml_section}

## Instructions

Write a professional GitHub issue that:
1. Has a concise title (prefix with "Security: " or similar)
2. Explains what AWI/prompt injection is in 2-3 sentences (accessible to non-experts)
3. Shows the specific vulnerable workflow and taint source
4. Explains the impact: an attacker can control the AI agent's behavior by crafting
   an issue title/body, comment, PR, or branch name — potentially causing the agent
   to leak secrets, modify code maliciously, or exfiltrate data
5. Provides concrete remediation steps based on the fix guidance above
6. Ends with a note that this is a responsible disclosure with no active exploitation

The tone should be helpful and constructive, not threatening. This is a coordinated
vulnerability disclosure to help the maintainer improve their security posture.
"""
        return prompt

    @staticmethod
    def _parse_response(raw: str, repo: str, findings: list[AWIFinding]) -> tuple[str, str] | None:
        """Parse LLM response into (title, body) tuple."""
        raw = raw.strip()

        # Extract TITLE:
        title_match = re.search(r"^TITLE:\s*(.+)$", raw, re.MULTILINE)
        if not title_match:
            # Try to extract first non-empty line as title
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            if lines:
                title = lines[0].lstrip("#").strip()
                body = "\n".join(lines[1:]).strip()
                logger.warning("No TITLE: marker found for %s, using first line", repo)
            else:
                logger.error("Could not parse LLM response for %s", repo)
                return None
        else:
            title = title_match.group(1).strip()

            # Extract BODY:
            body_match = re.search(r"^BODY:\s*\n(.*)", raw, re.MULTILINE | re.DOTALL)
            if body_match:
                body = body_match.group(1).strip()
            else:
                # Everything after TITLE: line
                title_end = title_match.end()
                body = raw[title_end:].strip()
                if body.startswith("BODY:"):
                    body = body[5:].strip()

        # Validate
        if not title or not body:
            logger.error("Empty title or body for %s", repo)
            return None

        # Truncate title if too long
        if len(title) > 100:
            title = title[:97] + "..."

        return title, body
