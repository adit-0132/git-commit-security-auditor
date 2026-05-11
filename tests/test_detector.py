"""Tests for the detection engine: true positives and false positive filters."""
from __future__ import annotations

import pytest

from auditor.detector import Detector, RULES
from auditor.models import Severity


@pytest.fixture
def detector() -> Detector:
    return Detector()


# Helpers

def make_patch(added_lines: list[str]) -> str:
    """Build a minimal unified diff patch with the given added lines."""
    header = "@@ -0,0 +1,{} @@\n".format(len(added_lines))
    return header + "\n".join(f"+{line}" for line in added_lines)


def scan(detector: Detector, lines: list[str], filename: str = "test.py") -> list:
    patch = make_patch(lines)
    return detector.scan_diff(patch, filename)


# True positives

class TestAWSAccessKeyID:
    def test_detects_real_key(self, detector):
        matches = scan(detector, ["AWS_KEY = 'AKIAABCDEFGHIJ123456'"])
        assert any(m.rule_id == "SEC001" for m in matches)

    def test_ignores_docs_example(self, detector):
        matches = scan(detector, ["example = 'AKIAIOSFODNN7EXAMPLE'"])
        assert not any(m.rule_id == "SEC001" for m in matches)

    def test_severity_is_critical(self, detector):
        matches = scan(detector, ["key = 'AKIAABCDEFGHIJ123456'"])
        aws = [m for m in matches if m.rule_id == "SEC001"]
        assert aws[0].severity == Severity.CRITICAL


class TestGitHubPAT:
    def test_detects_ghp_token(self, detector):
        token = "ghp_" + "A" * 36
        matches = scan(detector, [f"token = '{token}'"])
        assert any(m.rule_id == "SEC004" for m in matches)

    def test_detects_github_pat(self, detector):
        token = "github_pat_" + "A" * 82
        matches = scan(detector, [f"GITHUB_TOKEN = '{token}'"])
        assert any(m.rule_id == "SEC004" for m in matches)


class TestStripeKey:
    def test_detects_live_key(self, detector):
        matches = scan(detector, ["stripe_key = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWX'"])
        assert any(m.rule_id == "SEC007" for m in matches)

    def test_detects_test_key(self, detector):
        matches = scan(detector, ["stripe_pk = 'pk_test_ABCDEFGHIJKLMNOPQRSTUVWX'"])
        assert any(m.rule_id == "SEC007" for m in matches)


class TestHardcodedPassword:
    def test_detects_password_assignment(self, detector):
        matches = scan(detector, ['password = "hunter2abc"'])
        assert any(m.rule_id == "SEC008" for m in matches)

    def test_ignores_placeholder(self, detector):
        matches = scan(detector, ['password = "YOUR_PASSWORD"'])
        assert not any(m.rule_id == "SEC008" for m in matches)

    def test_ignores_getenv(self, detector):
        matches = scan(detector, ['password = os.getenv("DB_PASSWORD")'])
        assert not any(m.rule_id == "SEC008" for m in matches)


class TestPrivateKeyHeader:
    def test_detects_rsa_key(self, detector):
        matches = scan(detector, ["-----BEGIN RSA PRIVATE KEY-----"])
        assert any(m.rule_id == "SEC009" for m in matches)

    def test_detects_openssh_key(self, detector):
        matches = scan(detector, ["-----BEGIN OPENSSH PRIVATE KEY-----"])
        assert any(m.rule_id == "SEC009" for m in matches)


class TestDatabaseConnectionString:
    def test_detects_postgres_with_creds(self, detector):
        matches = scan(detector, ["db_url = 'postgres://admin:s3cr3t@db.example.com/prod'"])
        assert any(m.rule_id == "SEC010" for m in matches)

    def test_ignores_placeholder(self, detector):
        matches = scan(detector, ["db_url = 'postgres://user:password@localhost/db'"])
        assert not any(m.rule_id == "SEC010" for m in matches)


class TestAnthropicKey:
    def test_detects_anthropic_key(self, detector):
        key = "sk-ant-api03-" + "A" * 32
        matches = scan(detector, [f"api_key = '{key}'"])
        assert any(m.rule_id == "SEC012" for m in matches)


class TestOpenAIKey:
    def test_detects_openai_key(self, detector):
        key = "sk-" + "A" * 48
        matches = scan(detector, [f"OPENAI_KEY = '{key}'"])
        # Must NOT be caught as Anthropic (SEC012) when it's a plain sk- key
        sec013 = [m for m in matches if m.rule_id == "SEC013"]
        assert sec013, "Expected SEC013 to match an OpenAI-style key"

    def test_anthropic_key_not_double_flagged_as_openai(self, detector):
        key = "sk-ant-api03-" + "A" * 32
        matches = scan(detector, [f"key = '{key}'"])
        assert not any(m.rule_id == "SEC013" for m in matches), (
            "Anthropic key should be excluded from SEC013 by false-positive filter"
        )


class TestEvalCall:
    def test_detects_eval(self, detector):
        matches = scan(detector, ["result = eval(user_input)"])
        assert any(m.rule_id == "DAP001" for m in matches)
        assert [m for m in matches if m.rule_id == "DAP001"][0].severity == Severity.HIGH

    def test_detects_eval_with_spaces(self, detector):
        matches = scan(detector, ["x = eval  (expr)"])
        assert any(m.rule_id == "DAP001" for m in matches)


class TestExecCall:
    def test_detects_exec(self, detector):
        matches = scan(detector, ["exec(compile(source, '<string>', 'exec'))"])
        assert any(m.rule_id == "DAP002" for m in matches)


class TestSQLInjection:
    def test_detects_string_concat(self, detector):
        matches = scan(detector, ['query = "SELECT * FROM users WHERE id = " + user_id'])
        assert any(m.rule_id == "DAP003" for m in matches)

    def test_detects_format_string(self, detector):
        matches = scan(detector, ['sql = "DELETE FROM sessions WHERE token = %s" % token'])
        assert any(m.rule_id == "DAP003" for m in matches)


class TestSubprocessShell:
    def test_detects_shell_true(self, detector):
        matches = scan(detector, ['subprocess.run(cmd, shell=True)'])
        assert any(m.rule_id == "DAP004" for m in matches)


class TestPickle:
    def test_detects_pickle_loads(self, detector):
        matches = scan(detector, ["data = pickle.loads(raw_bytes)"])
        assert any(m.rule_id == "DAP006" for m in matches)

    def test_detects_pickle_load(self, detector):
        matches = scan(detector, ["obj = pickle.load(f)"])
        assert any(m.rule_id == "DAP006" for m in matches)


class TestSSLVerify:
    def test_detects_verify_false(self, detector):
        matches = scan(detector, ["resp = requests.get(url, verify=False)"])
        assert any(m.rule_id == "DAP008" for m in matches)


class TestDebugMode:
    def test_detects_debug_true(self, detector):
        matches = scan(detector, ["DEBUG = True"])
        assert any(m.rule_id == "DAP010" for m in matches)


# Patch scanning mechanics

class TestDiffScanning:
    def test_only_scans_added_lines(self, detector):
        """Lines starting with '-' (removed) must not be scanned."""
        patch = (
            "@@ -1,1 +1,1 @@\n"
            "-password = 'old_secret_value'\n"
            "+password = os.environ['PASSWORD']\n"
        )
        matches = detector.scan_diff(patch, "config.py")
        assert not any(m.rule_id == "SEC008" for m in matches)

    def test_skips_diff_header_lines(self, detector):
        patch = "@@ -0,0 +1,1 @@\n+eval(safe_expr)\n"
        matches = detector.scan_diff(patch, "safe.py")
        assert any(m.rule_id == "DAP001" for m in matches)

    def test_returns_correct_line_numbers(self, detector):
        patch = "@@ -0,0 +10,2 @@\n+ x = 1\n+password = 'secret123'\n"
        matches = detector.scan_diff(patch, "app.py")
        pw = [m for m in matches if m.rule_id == "SEC008"]
        assert pw[0].line_number == 11

    def test_snippet_truncated_to_200(self, detector):
        long_line = "password = '" + "x" * 300 + "'"
        matches = scan(detector, [long_line])
        for m in matches:
            assert len(m.flagged_snippet) <= 200


class TestFileSkipping:
    def test_skips_lock_files(self, detector):
        patch = make_patch(["password = 'secret'"])
        matches = detector.scan_diff(patch, "package-lock.json")
        # scan_diff itself doesn't skip files — scan_commit_files does
        files = [{"filename": "package-lock.json", "patch": patch}]
        matches = detector.scan_commit_files(files)
        assert matches == []

    def test_skips_vendor_directory(self, detector):
        patch = make_patch(["eval(x)"])
        files = [{"filename": "vendor/lib/code.py", "patch": patch}]
        matches = detector.scan_commit_files(files)
        assert matches == []

    def test_scans_normal_file(self, detector):
        patch = make_patch(["eval(user_input)"])
        files = [{"filename": "src/app.py", "patch": patch}]
        matches = detector.scan_commit_files(files)
        assert any(m.rule_id == "DAP001" for m in matches)

    def test_skips_binary_file_no_patch(self, detector):
        files = [{"filename": "image.png"}]  # no 'patch' key
        matches = detector.scan_commit_files(files)
        assert matches == []


class TestWorstSeverity:
    def test_critical_wins(self, detector):
        from auditor.models import RuleMatch
        matches = [
            RuleMatch(rule_id="X", rule_name="X", severity=Severity.HIGH, category="secret", flagged_snippet="x"),
            RuleMatch(rule_id="Y", rule_name="Y", severity=Severity.CRITICAL, category="secret", flagged_snippet="y"),
            RuleMatch(rule_id="Z", rule_name="Z", severity=Severity.LOW, category="secret", flagged_snippet="z"),
        ]
        assert Detector.worst_severity(matches) == Severity.CRITICAL

    def test_single_low(self, detector):
        from auditor.models import RuleMatch
        matches = [
            RuleMatch(rule_id="X", rule_name="X", severity=Severity.LOW, category="dangerous_pattern", flagged_snippet="x"),
        ]
        assert Detector.worst_severity(matches) == Severity.LOW
