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
    from awi_contribai.llm.provider import LLMProvider

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
You are a security researcher writing responsible disclosure reports for GitHub issues.
Write in a direct, technical style — no greetings, no preamble, no "I hope this finds you well".

Use exactly this structure (GitHub Markdown, ### headings):

### Summary
One paragraph. State the vulnerability class (Agentic Workflow Injection), which workflow
is affected, what attacker-controlled data flows into the prompt, and what the agent can do.

### Details
Explain the data flow precisely: which field (e.g. `github.event.issue.body`) is written
into the prompt, at which step, what permissions the job has. Quote the vulnerable YAML
snippet if available.

### PoC
Numbered steps. Step 1: open/post something (issue, comment, PR). Step 2: craft a body
that injects instructions. Step 3: what the agent does if it follows them. Be specific
about the injected payload.

### Impact
2-4 sentences on concrete attacker-achievable outcomes given the workflow's actual
permissions (token scopes, allowed tools, write access).

### Suggested Remediation
Bullet list of 3-5 specific, actionable fixes for this exact workflow and action.

### Reference
- https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents
- https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/

### Credit
Reported by Security PRIDE Research Group @security-pride

You MUST include the `### Credit` section verbatim as shown above. Do not
paraphrase it, do not omit it, do not move it to a different location. It
must be the LAST section of the issue body.

You MUST format your response EXACTLY as follows. The very first characters
of your response must be "TITLE:". Do NOT include any preamble, meta-commentary
("I'll draft the issue..."), acknowledgements, or reasoning before "TITLE:".
Do NOT wrap the response in markdown fences. Do NOT use "**Title**" or similar.

TITLE: <concise title, max 80 chars, plain text, start with "Security: ">
BODY:
<the full issue body using the structure above>

Example of the ONLY acceptable output format:

TITLE: Security: Agentic Workflow Injection in auto-label.yml via issue body
BODY:
### Summary
...
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
        # Deduplicate across findings
        actions = sorted({f.action for f in findings})
        taint_sources = sorted({f.taint_source for f in findings})
        workflows = sorted({f.workflow for f in findings})
        workflow_urls = sorted({f.workflow_url for f in findings})
        access_controls = sorted({f.access_control for f in findings})

        # Taint source list (just the expressions — no tool-internal metadata)
        taint_list = "\n".join(f"- `${{{{ {ts} }}}}`" for ts in taint_sources)

        # Workflow YAML section (include full content so LLM can read real line numbers)
        yaml_section = ""
        if workflow_yaml:
            yaml_trunc = workflow_yaml[:4000]
            yaml_section = (
                f"\n\n## Vulnerable workflow YAML\n\n"
                f"```yaml\n{yaml_trunc}\n"
                f"{'...(truncated)' if len(workflow_yaml) > 4000 else ''}\n```"
            )

        prompt = f"""\
Write a short, clean responsible-disclosure GitHub issue for `{repo}`.

## Context

- **Workflow file**: {", ".join(f"`{w}`" for w in workflows)}
- **Workflow URL**: {", ".join(workflow_urls)}
- **AI action**: {", ".join(f"`{a}`" for a in actions)}
- **Vulnerability class**: Prompt injection via attacker-controlled GitHub event data.
- **Attacker-controlled expressions interpolated into the AI prompt**:

{taint_list}
{yaml_section}

## Writing instructions

Write the issue as if you were a security researcher who just found this
on your own, by reading the workflow file. The reader (the repo maintainer)
does not know or care about the tool that found it.

- Read the workflow YAML above and describe the vulnerability IN YOUR OWN
  WORDS. Cite `filename:line_number` for the interpolation point (find the
  real line number yourself by reading the YAML).
- Describe the impact based on the job's `permissions:` and the AI action's
  capabilities as visible in the YAML.
- Write a concise, plausible PoC payload in the taint source type (e.g. a
  crafted PR title if the sink reads `pull_request.title`).
- Keep the remediation section short: 3-5 bullets. Point at the actor gate
  and the ID-based fetch pattern. Do NOT lecture on what prompt injection
  is in general.

## Tone rules

- No greetings, no "Hi maintainer", no "I hope this finds you well".
- No meta-commentary about how you wrote the issue.
- Do NOT mention any vulnerability-scanning tool, scanner name, or
  detection pipeline. Do NOT use jargon like "taint source", "sink",
  or "data flow" — those are internal terms, not reader-facing.
- Do NOT quote step-identifier strings like "🧐 Step Name | Job: foo |
  Step: bar (2th step)" — those are scanner artifacts. Refer to the
  step by its plain `name:` value in the YAML instead.
"""
        return prompt

    @staticmethod
    def _parse_response(raw: str, repo: str, findings: list[AWIFinding]) -> tuple[str, str] | None:
        """Parse LLM response into (title, body) tuple.

        Handles multiple formats the model may return:
          TITLE: <title>\\nBODY:\\n<body>       (canonical)
          Title: `<title>`\\n<body>             (markdown variant)
          **Title**\\n<title>\\n<body>           (bold header variant)
          # <title>\\n<body>                    (markdown heading)
        """
        raw = raw.strip()

        # Unified approach:
        #   1. Find the first title marker anywhere (`TITLE:`, `**Title**`, `Title:`)
        #      — discard any preamble before it.
        #   2. Find the first body marker after the title marker (`BODY:`,
        #      `**Body**`, `Body:`, or standalone `Body` line).
        #   3. Fall back to markdown heading, then first-line heuristics.

        title = None
        body = None

        # Step 1: find title marker. `**Title**` (bolded) can appear anywhere
        # (may be glued to LLM preamble text). Bare `TITLE:` / `Title:` must be
        # at line start so we don't false-match body prose.
        title_marker = re.search(
            r"(?:\*\*\s*Title\s*\*\*|^(?:TITLE|Title)\s*:)\s*",
            raw,
            re.MULTILINE,
        )
        if title_marker:
            after_title = raw[title_marker.end():]

            # Step 2: find body marker. `**Body**` anywhere, `BODY:`/`Body:`/
            # standalone `Body` only at line start.
            body_marker = re.search(
                r"(?:\*\*\s*Body\s*\*\*|^(?:BODY|Body)\s*:?\s*$)\s*",
                after_title,
                re.MULTILINE,
            )
            if body_marker:
                title_block = after_title[: body_marker.start()]
                body = after_title[body_marker.end():].strip()
            else:
                # No body marker — use first non-empty line as title, rest as body
                title_block = after_title
                body = ""

            # The title is the first non-empty line of title_block
            title_lines = [l.strip() for l in title_block.splitlines() if l.strip()]
            if title_lines:
                title = title_lines[0].strip("`*#").strip()
                # If no body marker found, body is everything else after the title line
                if not body:
                    # Find where the title line ends in title_block and grab the rest
                    title_end = title_block.find(title_lines[0]) + len(title_lines[0])
                    body = title_block[title_end:].strip()

        # Fallback: markdown heading `# <title>`
        if not title:
            heading = re.search(r"^#{1,3}\s+(.+)$", raw, re.MULTILINE)
            if heading:
                title = heading.group(1).strip()
                body = raw[heading.end():].strip()

        # Last resort: first non-empty line
        if not title:
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            if lines:
                title = lines[0].lstrip("#*`").strip()
                body = "\n".join(lines[1:]).strip()
                logger.warning("No TITLE marker found for %s, using first line", repo)
            else:
                logger.error("Could not parse LLM response for %s", repo)
                return None

        # Clean up title: strip markdown formatting and label prefixes
        title = re.sub(r"^\*{1,2}|^\*{1,2}$", "", title).strip()   # bold markers
        title = re.sub(r"^`|`$", "", title).strip()                  # backticks
        title = re.sub(r"^(Title|TITLE):\s*", "", title).strip()     # leftover label

        # Validate
        if not title or not body:
            logger.error("Empty title or body for %s", repo)
            return None

        # Truncate title if too long
        if len(title) > 100:
            title = title[:97] + "..."

        return title, body
