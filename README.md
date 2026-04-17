# AWI ContribAI

Standalone AWI-focused ContribAI for responsible disclosure of **Agentic Workflow
Injection (AWI)** vulnerabilities in GitHub Actions workflows.

This project is intentionally split from the original ContribAI agent. It keeps only the AWI
workflow:

1. Read ARGUS `findings_open.csv`
2. Generate a disclosure issue
3. Human-review or auto-approve the issue
4. Submit the issue to GitHub
5. Generate a minimal workflow YAML fix
6. Validate the patched YAML and residual taint
7. Submit a linked PR
8. Track issue/PR state locally in SQLite and JSON logs

## Install

Use a virtual environment:

```bash
cd awi-contribai
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[openai]'
```

Choose the extra that matches your LLM provider:

```bash
python -m pip install -e '.[openai]'
python -m pip install -e '.[gemini]'
python -m pip install -e '.[anthropic]'
python -m pip install -e '.[all]'
```

Verify the CLI:

```bash
awi-contribai --help
```

## Configure

Copy the example config:

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml`:

```yaml
github:
  token: "ghp_xxx"

llm:
  provider: "openai"
  model: "gpt-5.4"
  api_key: "sk_xxx"

storage:
  db_path: "~/.awi-contribai/memory.db"
```

You can also use environment variables:

```bash
export GITHUB_TOKEN="ghp_xxx"
export OPENAI_API_KEY="sk_xxx"
```

## Prepare ARGUS Findings

Default input path:

```text
outputs/argus-awi/findings_open.csv
```

Required columns:

```text
repo,workflow,workflow_url,action,taint_source,source_location,sink_location,access_control
```

Example row:

```csv
repo,workflow,workflow_url,action,taint_source,source_location,sink_location,access_control
owner/repo,.github/workflows/triage.yml,https://github.com/owner/repo/blob/main/.github/workflows/triage.yml,google-github-actions/run-gemini-cli,github.event.issue.body,issue.body,prompt,open
```

Use `--findings PATH` if the CSV lives elsewhere.

## Recommended Usage

### Dry-run one repo first

```bash
awi-contribai -c config.yaml disclose \
  --findings outputs/argus-awi/findings_open.csv \
  --repo owner/repo \
  --dry-run
```

This generates and previews both the issue and PR patch without writing to GitHub.

### Live full disclosure

```bash
awi-contribai -c config.yaml disclose --repo owner/repo
```

The interactive flow asks twice:

- approve/reject/skip the disclosure issue
- approve/reject/skip the fix PR

Choices:

- `y`: submit
- `n`: reject
- `s`: skip

### Batch safely

```bash
awi-contribai -c config.yaml disclose --limit 3 --dry-run
awi-contribai -c config.yaml disclose --limit 3
```

Use `--auto-approve` only after validating output quality:

```bash
awi-contribai -c config.yaml disclose --limit 3 --auto-approve
```

## Separate Commands

Only create disclosure issues:

```bash
awi-contribai -c config.yaml submit --repo owner/repo
awi-contribai -c config.yaml submit --repo owner/repo --no-fetch-yaml
```

Only create fix PRs:

```bash
awi-contribai -c config.yaml pr --repo owner/repo
awi-contribai -c config.yaml pr --repo owner/repo --issue 42
```

Check status:

```bash
awi-contribai -c config.yaml status
awi-contribai -c config.yaml status --no-refresh
```

## Useful Flags

| Flag | Commands | Description |
| --- | --- | --- |
| `--findings PATH` | `disclose`, `submit`, `pr` | ARGUS findings CSV |
| `--repo OWNER/REPO` | `disclose`, `submit`, `pr` | Process one repository |
| `--limit N` | `disclose`, `submit`, `pr` | Process at most N repos |
| `--dry-run` | `disclose`, `submit`, `pr` | Preview only; do not submit |
| `--auto-approve` | `disclose`, `submit`, `pr` | Skip interactive review |
| `--force` | `disclose`, `submit`, `pr` | Publicly submit even if SECURITY.md/PVR exists |
| `--no-fetch-yaml` | `submit` | Do not include workflow YAML in issue prompt |
| `--issue N` | `pr` | Add `Closes #N` to PR body |
| `--no-refresh` | `status` | Read local SQLite state only |

## Output Files

| Path | Purpose |
| --- | --- |
| `outputs/argus-awi/awi_issues_submitted.json` | Issue deduplication and audit log |
| `outputs/argus-awi/awi_prs_submitted.json` | PR deduplication and audit log |
| `~/.awi-contribai/memory.db` | SQLite status DB |
| `/tmp/awi_pr_debug/` | Full before/after YAML when `AWI_DEBUG=1` |

Re-running skips repos already present in the relevant JSON log. Remove a repo entry from the log
to retry it.

## Safety Notes

- The tool checks for GitHub Private Vulnerability Reporting and `SECURITY.md` before public issue/PR submission.
- Use `--force` only when you have confirmed public disclosure is appropriate.
- Always run `--dry-run` before a live batch.
- Review generated PoC, impact, and YAML patch before submitting security reports publicly.
