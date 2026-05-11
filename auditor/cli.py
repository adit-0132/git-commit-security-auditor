from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from . import __version__
from .ai_explainer import AIExplainer, AIExplainerError
from .config import ConfigError, load_config
from .detector import Detector
from .github_client import GitHubAPIError, GitHubClient, RateLimitError
from .models import Finding, Report, ScanMetadata, Severity, SEVERITY_ORDER
from .reporters.html_reporter import write_html_report
from .reporters.json_reporter import write_json_report


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("repo_url")
@click.option(
    "--github-token",
    envvar="GITHUB_TOKEN",
    metavar="TOKEN",
    help="GitHub Personal Access Token (or set GITHUB_TOKEN env var).",
)
@click.option(
    "--anthropic-key",
    envvar="ANTHROPIC_API_KEY",
    metavar="KEY",
    help="Anthropic API key for AI explanations (or set ANTHROPIC_API_KEY env var).",
)
@click.option(
    "--commits",
    default=50,
    show_default=True,
    type=click.IntRange(1, 100),
    help="Number of recent commits to scan.",
)
@click.option(
    "--output-dir",
    default=".",
    show_default=True,
    type=click.Path(),
    help="Directory to write report files.",
)
@click.option(
    "--no-ai",
    is_flag=True,
    default=False,
    help="Skip AI explanations (faster; does not require ANTHROPIC_API_KEY).",
)
@click.option(
    "--min-severity",
    default="low",
    show_default=True,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Minimum severity level to include in reports.",
)
@click.option(
    "--format",
    "output_format",
    default="all",
    show_default=True,
    type=click.Choice(["all", "json", "html"], case_sensitive=False),
    help="Output format(s) to generate.",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output.")
@click.version_option(version=__version__, prog_name="git-audit")
def main(
    repo_url: str,
    github_token: str | None,
    anthropic_key: str | None,
    commits: int,
    output_dir: str,
    no_ai: bool,
    min_severity: str,
    output_format: str,
    quiet: bool,
) -> None:
    """Scan recent commits of a GitHub repository for security issues.

    REPO_URL can be a full URL (https://github.com/owner/repo)
    or a short slug (owner/repo).

    \b
    Examples:
      git-audit https://github.com/myorg/myapp
      git-audit myorg/myapp --commits 100 --no-ai
      git-audit myorg/myapp --min-severity high --format json
    """

    def log(msg: str, end: str = "\n") -> None:
        if not quiet:
            click.echo(msg, err=True, nl=(end == "\n"))

    # 1. Config
    try:
        config = load_config(
            github_token=github_token,
            anthropic_api_key=anthropic_key,
            commit_limit=commits,
            skip_ai=no_ai,
            output_dir=output_dir,
            min_severity=min_severity,
        )
    except ConfigError as exc:
        click.echo(f"Configuration error:\n{exc}", err=True)
        sys.exit(1)

    # 2. Parse repo URL
    gh = GitHubClient(config.github_token, timeout=config.timeout_github, max_retries=config.max_retries)
    try:
        owner, repo = gh.parse_repo_url(repo_url)
    except ValueError as exc:
        click.echo(f"Invalid repository URL: {exc}", err=True)
        sys.exit(1)

    # 3. Validate repo access
    try:
        repo_meta = gh.get_repo(owner, repo)
    except GitHubAPIError as exc:
        click.echo(f"GitHub error: {exc}", err=True)
        sys.exit(1)

    log(f"Scanning {repo_meta['full_name']} — last {config.commit_limit} commits")
    if config.skip_ai:
        log("  (AI explanations disabled)")

    # 4. Fetch commits and run detection
    detector = Detector()
    findings: list[Finding] = []
    scanned = 0
    min_sev_index = SEVERITY_ORDER.index(Severity(min_severity.lower()))

    try:
        for commit_summary in gh.iter_commits(owner, repo, limit=config.commit_limit):
            sha = commit_summary["sha"]
            scanned += 1
            log(f"  [{scanned:3d}/{config.commit_limit}] {sha[:8]}...", end="\n")

            try:
                commit_detail = gh.get_commit_diff(owner, repo, sha)
            except GitHubAPIError as exc:
                log(f"\n  Warning: skipping {sha[:8]} — {exc}")
                continue

            files = commit_detail.get("files", [])
            raw_matches = detector.scan_commit_files(files)

            # Filter by minimum severity
            filtered = [
                m for m in raw_matches
                if SEVERITY_ORDER.index(m.severity) <= min_sev_index
            ]
            if not filtered:
                continue

            commit_data = commit_summary["commit"]
            author_info = commit_data.get("author") or {}
            ts_str = author_info.get("date", "")
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            finding = Finding(
                commit_sha=sha,
                short_sha=sha[:8],
                author=author_info.get("name", "Unknown"),
                author_email=author_info.get("email", ""),
                timestamp=timestamp,
                commit_message=commit_data.get("message", "").split("\n")[0][:200],
                severity=Detector.worst_severity(filtered),
                matches=filtered,
                commit_url=f"https://github.com/{owner}/{repo}/commit/{sha}",
            )
            findings.append(finding)

    except RateLimitError as exc:
        log(f"\nRate limit hit after {scanned} commits: {exc}")
        log(f"Generating partial report with {len(findings)} finding(s) so far.")
    except KeyboardInterrupt:
        log(f"\nInterrupted after {scanned} commits. Generating partial report.")

    log(f"\nScanned {scanned} commit(s). Found {len(findings)} flagged commit(s).")

    # 5. Sort findings: critical first, then by timestamp descending
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), -f.timestamp.timestamp()))

    # 6. AI Explanations
    if not config.skip_ai and findings:
        log(f"Generating AI explanations for {len(findings)} finding(s)...")
        explainer = AIExplainer(config.anthropic_api_key, timeout=config.timeout_anthropic)

        # Check for auth failure early — surface it clearly rather than per-finding
        try:
            first = findings[0]
            first.ai_explanation = explainer.explain(first)
            log(f"  AI: 1/{len(findings)} complete", end="\r")
        except AIExplainerError as exc:
            msg = str(exc)
            if "Invalid ANTHROPIC_API_KEY" in msg:
                click.echo(f"\nAI error: {msg}", err=True)
                for f in findings:
                    f.ai_explanation = f"[AI explanation unavailable: {msg}]"
            else:
                findings[0].ai_explanation = f"[AI explanation unavailable: {msg}]"

        if not findings[0].ai_explanation or not findings[0].ai_explanation.startswith("["):
            for i, finding in enumerate(findings[1:], 2):
                try:
                    finding.ai_explanation = explainer.explain(finding)
                except AIExplainerError as exc:
                    finding.ai_explanation = f"[AI explanation unavailable: {exc}]"
                log(f"  AI: {i}/{len(findings)} complete", end="\r")

        log(f"\nAI explanations complete.")

    # 7. Build and write reports
    report = Report(
        metadata=ScanMetadata(
            repo_url=repo_url,
            repo_full_name=repo_meta["full_name"],
            scanned_at=datetime.now(timezone.utc),
            commits_scanned=scanned,
            commits_flagged=len(findings),
            total_findings=sum(len(f.matches) for f in findings),
            scanner_version=__version__,
        ),
        findings=findings,
    )

    out = Path(config.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = repo_meta["full_name"].replace("/", "_")
    base_name = f"audit_{safe_name}_{timestamp_tag}"

    written: list[str] = []

    if output_format in ("all", "json"):
        json_path = out / f"{base_name}.json"
        try:
            write_json_report(report, json_path)
            log(f"JSON report: {json_path}")
            written.append(str(json_path))
        except OSError as exc:
            click.echo(f"Failed to write JSON report: {exc}", err=True)

    if output_format in ("all", "html"):
        html_path = out / f"{base_name}.html"
        try:
            write_html_report(report, html_path)
            log(f"HTML report: {html_path}")
            written.append(str(html_path))
        except OSError as exc:
            click.echo(f"Failed to write HTML report: {exc}", err=True)

    # Print output file paths to stdout for pipeline use
    for path in written:
        click.echo(path)

    # 8. Exit code: 1 if any critical/high findings (CI integration)
    high_plus = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    sys.exit(1 if high_plus else 0)
