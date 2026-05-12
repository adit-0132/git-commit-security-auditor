# Multi-Tenant B2B Distribution Platform

- [Full System Architecture Diagram](https://adit-0132.github.io/git-commit-security-auditor/Task-2/architecture_flows.html)

- [AWS Infrastructure Diagram](https://adit-0132.github.io/git-commit-security-auditor/Task-2/aws_infrastructure.html)

---

# Git Commit Security Auditor

A CLI tool that scans GitHub repository commit history for hardcoded secrets, leaked credentials, and dangerous code patterns - with optional AI-powered explanations via Claude.

---

## Live Report Examples

| Report | HTML | JSON |
|--------|------|------|
| Github-Guardian-Portal - Standard Audit | [HTML](https://adit-0132.github.io/git-commit-security-auditor/outputs/html-outputs/audit_adit-0132_Github-Guardian-Portal_20260511_201312.html) | [JSON](https://adit-0132.github.io/git-commit-security-auditor/outputs/json-outputs/audit_adit-0132_Github-Guardian-Portal_20260511_201312.json) |
| Github-Guardian-Portal - AI Audit | [HTML](https://adit-0132.github.io/git-commit-security-auditor/outputs/html-outputs/AI_audit_adit-0132_Github-Guardian-Portal_20260511_201451.html) | [JSON](https://adit-0132.github.io/git-commit-security-auditor/outputs/json-outputs/audit_adit-0132_Github-Guardian-Portal_20260511_201451.json) |
| llm-context-router - Standard Audit | [HTML](https://adit-0132.github.io/git-commit-security-auditor/outputs/html-outputs/audit_adit-0132_llm-context-router_20260511_163713.html) | [JSON](https://adit-0132.github.io/git-commit-security-auditor/outputs/json-outputs/audit_adit-0132_llm-context-router_20260511_163713.json) |
| llm-context-router - AI Audit | [HTML](https://adit-0132.github.io/git-commit-security-auditor/outputs/html-outputs/AI_audit_adit-0132_llm-context-router_20260511_185107.html) | [JSON](https://adit-0132.github.io/git-commit-security-auditor/outputs/json-outputs/audit_adit-0132_llm-context-router_20260511_185107.json) |

---

## What It Does

- Fetches the last N commits from any public or private GitHub repository
- Scans each commit diff for secrets and dangerous patterns using 20 built-in rules
- Classifies findings by severity: **Critical**, **High**, **Medium**, **Low**
- Optionally calls the Claude API to generate a plain-English explanation for each finding
- Outputs structured **JSON** and/or **HTML** reports
- Exits with code `1` if any Critical or High findings are found (useful in CI pipelines)

---

## Detected Patterns

### Secrets (hardcoded credentials)

| Rule ID | Pattern |
|---------|---------|
| SEC001 | AWS Access Key ID (`AKIA...`) |
| SEC002 | AWS Secret Access Key |
| SEC003 | Generic API key / token assignment |
| SEC004 | GitHub Personal Access Token (`ghp_...`) |
| SEC005 | GitHub OAuth / App Token |
| SEC006 | Slack Token (`xox...`) |
| SEC007 | Stripe API Key |
| SEC008 | Hardcoded password in source |
| SEC009 | Private key header (`-----BEGIN ... PRIVATE KEY-----`) |
| SEC010 | Database connection string with credentials |
| SEC011 | Hardcoded JWT token |
| SEC012 | Anthropic API Key |
| SEC013 | OpenAI API Key |

### Dangerous Patterns

| Rule ID | Pattern |
|---------|---------|
| DAP001 | `eval()` call |
| DAP002 | `exec()` call |
| DAP003 | Raw SQL string concatenation |
| DAP004 | `subprocess` with `shell=True` |
| DAP005 | `os.system()` call |
| DAP006 | `pickle.loads()` / `pickle.load()` |
| DAP007 | `yaml.load()` without SafeLoader |
| DAP008 | Disabled SSL verification (`verify=False`) |
| DAP009 | Weak hash algorithm (MD5 / SHA1) |
| DAP010 | `DEBUG = True` in source |

---

## Requirements

- Python 3.11 or newer
- A GitHub Personal Access Token
- (Optional) An Anthropic API key for AI explanations

---

## Beginner Setup

### 1. Clone the repository

```bash
git clone https://github.com/adit-0132/git-commit-security-auditor.git
cd git-commit-security-auditor
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows
```

### 3. Install the package

```bash
pip install -e .
```

This installs the `git-audit` command on your PATH.

### 4. Set up API keys

Copy the example env file and fill in your credentials:

```bash
cp .env.example .env
```

Open `.env` and replace the placeholder values:

```env
# Required - create at https://github.com/settings/tokens
# Public repos: no scope needed. Private repos: enable the "repo" scope.
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Required for AI explanations (skip with --no-ai if you don't have one)
# Create at https://console.anthropic.com/
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Then load the file into your shell:

```bash
export $(grep -v '^#' .env | xargs)
```

Alternatively you can pass keys directly via CLI flags (see below).

---

## Usage

```
git-audit [OPTIONS] REPO_URL
```

`REPO_URL` can be a full URL or a short slug:

```bash
git-audit https://github.com/myorg/myapp
git-audit myorg/myapp
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--commits N` | `50` | Number of recent commits to scan (max 100) |
| `--output-dir PATH` | `.` | Directory for report files |
| `--format` | `all` | Output format: `all`, `json`, or `html` |
| `--min-severity` | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `--no-ai` | off | Skip AI explanations (no Anthropic key needed) |
| `--github-token TOKEN` | env | Override `GITHUB_TOKEN` env var |
| `--anthropic-key KEY` | env | Override `ANTHROPIC_API_KEY` env var |
| `-q, --quiet` | off | Suppress progress output |
| `-h, --help` | | Show help and exit |

### Examples

Scan the last 50 commits, generate both JSON and HTML reports:

```bash
git-audit myorg/myapp
```

Scan 100 commits, only show high and critical findings, skip AI:

```bash
git-audit myorg/myapp --commits 100 --min-severity high --no-ai
```

Write reports to a specific folder, JSON only:

```bash
git-audit myorg/myapp --output-dir ./reports --format json
```

Use in CI (exits with code 1 if critical/high findings found):

```bash
git-audit myorg/myapp --no-ai --min-severity high --quiet
```

---

## Output

Each run produces timestamped report files named:

```
audit_<owner>_<repo>_<YYYYMMDD_HHMMSS>.json
audit_<owner>_<repo>_<YYYYMMDD_HHMMSS>.html
```

### JSON report structure

```json
{
  "metadata": {
    "repo_full_name": "owner/repo",
    "scanned_at": "2026-05-11T20:13:12Z",
    "commits_scanned": 50,
    "commits_flagged": 2,
    "total_findings": 4,
    "scanner_version": "1.0.0"
  },
  "findings": [
    {
      "commit_sha": "abc123...",
      "author": "Jane Doe",
      "timestamp": "2026-05-10T14:22:00Z",
      "commit_message": "add config",
      "severity": "critical",
      "matches": [
        {
          "rule_id": "SEC001",
          "rule_name": "AWS Access Key ID",
          "severity": "critical",
          "category": "secret",
          "flagged_snippet": "+AWS_ACCESS_KEY=AKIA...",
          "file_path": "config/settings.py",
          "line_number": 42
        }
      ],
      "ai_explanation": "This commit exposed an AWS Access Key..."
    }
  ]
}
```

### HTML report

A self-contained HTML file with a summary dashboard, per-commit findings, flagged code snippets, and (when AI is enabled) plain-English explanations of each issue.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high findings |
| `1` | One or more critical or high findings detected |

---

## Running Tests

Install dev dependencies and run the test suite:

```bash
pip install -e ".[dev]"
pytest
```

---

## Project Structure

```
git-commit-security-auditor/
├── auditor/
│   ├── cli.py            # Entry point - Click command, orchestration
│   ├── detector.py       # Regex-based detection rules
│   ├── github_client.py  # GitHub REST API client
│   ├── ai_explainer.py   # Claude API integration
│   ├── config.py         # Configuration loading and validation
│   ├── models.py         # Pydantic data models
│   └── reporters/
│       ├── html_reporter.py
│       └── json_reporter.py
├── tests/
├── .env.example
└── pyproject.toml
```

---

## License

MIT
