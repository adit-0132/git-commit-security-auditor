"""Tests for JSON and HTML reporters."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auditor.models import Finding, Report, RuleMatch, ScanMetadata, Severity
from auditor.reporters.html_reporter import write_html_report
from auditor.reporters.json_reporter import write_json_report


# Fixtures

@pytest.fixture
def sample_report() -> Report:
    ts = datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
    return Report(
        metadata=ScanMetadata(
            repo_url="https://github.com/test/repo",
            repo_full_name="test/repo",
            scanned_at=ts,
            commits_scanned=50,
            commits_flagged=2,
            total_findings=3,
            scanner_version="1.0.0",
        ),
        findings=[
            Finding(
                commit_sha="a" * 40,
                short_sha="aaaaaaaa",
                author="Alice Dev",
                author_email="alice@example.com",
                timestamp=ts,
                commit_message="add database config",
                severity=Severity.CRITICAL,
                matches=[
                    RuleMatch(
                        rule_id="SEC001",
                        rule_name="AWS Access Key ID",
                        severity=Severity.CRITICAL,
                        category="secret",
                        flagged_snippet="AWS_KEY = 'AKIAABCDEFGHIJ123456'",
                        line_number=42,
                        file_path="config/settings.py",
                    ),
                    RuleMatch(
                        rule_id="DAP001",
                        rule_name="eval() Call",
                        severity=Severity.HIGH,
                        category="dangerous_pattern",
                        flagged_snippet="result = eval(user_input)",
                        line_number=17,
                        file_path="utils/helpers.py",
                    ),
                ],
                ai_explanation="## AWS Access Key ID\n\nThis is risky because...\n\n## Summary\n\nHigh risk commit.",
                commit_url="https://github.com/test/repo/commit/" + "a" * 40,
            ),
            Finding(
                commit_sha="b" * 40,
                short_sha="bbbbbbbb",
                author="Bob Dev",
                author_email="bob@example.com",
                timestamp=ts,
                commit_message="disable ssl check",
                severity=Severity.MEDIUM,
                matches=[
                    RuleMatch(
                        rule_id="DAP008",
                        rule_name="Disabled SSL Verification",
                        severity=Severity.MEDIUM,
                        category="dangerous_pattern",
                        flagged_snippet="requests.get(url, verify=False)",
                        line_number=5,
                        file_path="api/client.py",
                    )
                ],
                ai_explanation=None,
                commit_url="https://github.com/test/repo/commit/" + "b" * 40,
            ),
        ],
    )


# JSON Reporter

class TestJSONReporter:
    def test_writes_valid_json(self, sample_report):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        write_json_report(sample_report, path)
        data = json.loads(path.read_text())
        assert isinstance(data, dict)

    def test_metadata_fields_present(self, sample_report):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        write_json_report(sample_report, path)
        data = json.loads(path.read_text())
        meta = data["metadata"]
        assert meta["repo_full_name"] == "test/repo"
        assert meta["commits_scanned"] == 50
        assert meta["commits_flagged"] == 2
        assert meta["total_findings"] == 3
        assert meta["scanner_version"] == "1.0.0"

    def test_findings_array(self, sample_report):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        write_json_report(sample_report, path)
        data = json.loads(path.read_text())
        assert len(data["findings"]) == 2

    def test_required_finding_fields(self, sample_report):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        write_json_report(sample_report, path)
        data = json.loads(path.read_text())
        finding = data["findings"][0]
        for field in ("commit_sha", "author", "timestamp", "severity", "matches", "commit_url"):
            assert field in finding, f"Missing field: {field}"

    def test_match_fields(self, sample_report):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        write_json_report(sample_report, path)
        data = json.loads(path.read_text())
        match = data["findings"][0]["matches"][0]
        assert match["rule_id"] == "SEC001"
        assert match["severity"] == "critical"
        assert match["flagged_snippet"] == "AWS_KEY = 'AKIAABCDEFGHIJ123456'"

    def test_ai_explanation_included(self, sample_report):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        write_json_report(sample_report, path)
        data = json.loads(path.read_text())
        assert data["findings"][0]["ai_explanation"] is not None
        assert data["findings"][1]["ai_explanation"] is None

    def test_timestamps_are_iso_strings(self, sample_report):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        write_json_report(sample_report, path)
        data = json.loads(path.read_text())
        ts = data["findings"][0]["timestamp"]
        assert isinstance(ts, str)
        assert "2024" in ts


# HTML Reporter

class TestHTMLReporter:
    def _render(self, sample_report) -> str:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = Path(f.name)
        write_html_report(sample_report, path)
        return path.read_text(encoding="utf-8")

    def test_writes_valid_html(self, sample_report):
        html = self._render(sample_report)
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_contains_repo_name(self, sample_report):
        html = self._render(sample_report)
        assert "test/repo" in html

    def test_contains_severity_badges(self, sample_report):
        html = self._render(sample_report)
        assert "badge-critical" in html
        assert "badge-medium" in html

    def test_contains_commit_sha(self, sample_report):
        html = self._render(sample_report)
        assert "aaaaaaaa" in html
        assert "bbbbbbbb" in html

    def test_contains_author_names(self, sample_report):
        html = self._render(sample_report)
        assert "Alice Dev" in html
        assert "Bob Dev" in html

    def test_contains_rule_ids(self, sample_report):
        html = self._render(sample_report)
        assert "SEC001" in html
        assert "DAP001" in html
        assert "DAP008" in html

    def test_contains_flagged_snippets(self, sample_report):
        html = self._render(sample_report)
        assert "AWS_KEY" in html
        assert "eval(user_input)" in html

    def test_ai_explanation_rendered(self, sample_report):
        html = self._render(sample_report)
        # AI explanation markdown should be rendered into HTML
        assert "ai-content" in html or "ai-explanation" in html

    def test_no_findings_shows_clean_message(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        empty_report = Report(
            metadata=ScanMetadata(
                repo_url="https://github.com/test/clean",
                repo_full_name="test/clean",
                scanned_at=ts,
                commits_scanned=10,
                commits_flagged=0,
                total_findings=0,
                scanner_version="1.0.0",
            ),
            findings=[],
        )
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = Path(f.name)
        write_html_report(empty_report, path)
        html = path.read_text(encoding="utf-8")
        assert "No security issues detected" in html

    def test_stats_counts_correct(self, sample_report):
        html = self._render(sample_report)
        # Commits scanned
        assert "50" in html
        # Commits flagged
        assert ">2<" in html or "2<" in html
