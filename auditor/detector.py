from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .models import RuleMatch, Severity, SEVERITY_ORDER


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    category: str  # "secret" | "dangerous_pattern"
    false_positive_filter: Optional[re.Pattern] = None


RULES: list[DetectionRule] = [
    # Secrets
    DetectionRule(
        rule_id="SEC001",
        name="AWS Access Key ID",
        pattern=re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        severity=Severity.CRITICAL,
        category="secret",
        false_positive_filter=re.compile(r"AKIAIOSFODNN7EXAMPLE"),
    ),
    DetectionRule(
        rule_id="SEC002",
        name="AWS Secret Access Key",
        pattern=re.compile(
            r"(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws_secret)"
            r"\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        severity=Severity.CRITICAL,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC003",
        name="Generic API Key Assignment",
        pattern=re.compile(
            r'(?i)(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key)'
            r'\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'
        ),
        severity=Severity.HIGH,
        category="secret",
        false_positive_filter=re.compile(
            r'(?i)(your[-_]?api[-_]?key|example|placeholder|dummy|test_?key|fake|'
            r'<.*?>|\$\{.*?\}|os\.environ|getenv|YOUR_)'
        ),
    ),
    DetectionRule(
        rule_id="SEC004",
        name="GitHub Personal Access Token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        severity=Severity.CRITICAL,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC005",
        name="GitHub OAuth/App Token",
        pattern=re.compile(r"gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}"),
        severity=Severity.CRITICAL,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC006",
        name="Slack Token",
        pattern=re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,72}"),
        severity=Severity.HIGH,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC007",
        name="Stripe API Key",
        pattern=re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"),
        severity=Severity.CRITICAL,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC008",
        name="Hardcoded Password",
        pattern=re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'
        ),
        severity=Severity.HIGH,
        category="secret",
        false_positive_filter=re.compile(
            r"(?i)(your[-_]?password|password123|example|placeholder|changeme|"
            r"<.*?>|\$\{.*?\}|environ|getenv|input\(|getpass|PASSWORD_HERE)"
        ),
    ),
    DetectionRule(
        rule_id="SEC009",
        name="Private Key Header",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        severity=Severity.CRITICAL,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC010",
        name="Database Connection String with Credentials",
        pattern=re.compile(
            r"(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^:@\s]+:[^@\s]+@[^\s\"']+"
        ),
        severity=Severity.CRITICAL,
        category="secret",
        false_positive_filter=re.compile(
            r"(?i)(user:password|username:password|user:pass|<password>|\$\{)"
        ),
    ),
    DetectionRule(
        rule_id="SEC011",
        name="JWT Token (Hardcoded)",
        pattern=re.compile(
            r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
        ),
        severity=Severity.HIGH,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC012",
        name="Anthropic API Key",
        pattern=re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}"),
        severity=Severity.CRITICAL,
        category="secret",
    ),
    DetectionRule(
        rule_id="SEC013",
        name="OpenAI API Key",
        pattern=re.compile(r"sk-[A-Za-z0-9]{32,}(?:-[A-Za-z0-9]{20,})?"),
        severity=Severity.CRITICAL,
        category="secret",
        # Exclude Anthropic keys which also start with sk- (already caught by SEC012)
        false_positive_filter=re.compile(r"sk-ant-"),
    ),
    # Dangerous Patterns
    DetectionRule(
        rule_id="DAP001",
        name="eval() Call",
        pattern=re.compile(r"\beval\s*\("),
        severity=Severity.HIGH,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP002",
        name="exec() Call",
        pattern=re.compile(r"\bexec\s*\("),
        severity=Severity.HIGH,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP003",
        name="Raw SQL String Concatenation",
        pattern=re.compile(
            r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.{0,100}"
            r'(?:["\'\)]\s*\+\s*\w|\+\s*["\']|\+\s*\w+\s*\+|%\s*\w+|\.format\s*\(|f["\'].*\{)'
        ),
        severity=Severity.HIGH,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP004",
        name="subprocess with shell=True",
        pattern=re.compile(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True"),
        severity=Severity.HIGH,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP005",
        name="os.system() Call",
        pattern=re.compile(r"\bos\.system\s*\("),
        severity=Severity.MEDIUM,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP006",
        name="pickle.loads() / pickle.load()",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        severity=Severity.HIGH,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP007",
        name="yaml.load() without SafeLoader",
        pattern=re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.Safe)"),
        severity=Severity.MEDIUM,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP008",
        name="Disabled SSL Verification",
        pattern=re.compile(r"verify\s*=\s*False"),
        severity=Severity.MEDIUM,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP009",
        name="Weak Hash Algorithm (MD5/SHA1)",
        pattern=re.compile(r"(?i)(?:hashlib\.(?:md5|sha1)|MD5\(|SHA1\()"),
        severity=Severity.LOW,
        category="dangerous_pattern",
    ),
    DetectionRule(
        rule_id="DAP010",
        name="DEBUG Mode Enabled",
        pattern=re.compile(r"(?<![A-Za-z_])DEBUG\s*=\s*True"),
        severity=Severity.LOW,
        category="dangerous_pattern",
    ),
]

# Files to skip: lock files, minified assets, vendored code, build artifacts
_SKIP_SUFFIXES = (".lock", ".min.js", ".min.css", ".pb.go", ".pb2.py")
_SKIP_FRAGMENTS = ("vendor/", "node_modules/", "dist/", "build/", "package-lock.json", "yarn.lock")


class Detector:
    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = rules if rules is not None else RULES

    def scan_diff(self, patch: str, file_path: str) -> list[RuleMatch]:
        """Scan a unified diff patch, examining only added lines (+)."""
        matches: list[RuleMatch] = []
        current_new_line = 0

        for raw_line in patch.splitlines():
            if raw_line.startswith("@@"):
                m = re.search(r"\+(\d+)", raw_line)
                if m:
                    current_new_line = int(m.group(1)) - 1
                continue
            if raw_line.startswith("+++ "):
                continue
            if raw_line.startswith("+"):
                current_new_line += 1
                content = raw_line[1:]  # strip leading '+'
                for rule in self.rules:
                    if rule.pattern.search(content):
                        if rule.false_positive_filter and rule.false_positive_filter.search(content):
                            continue
                        matches.append(
                            RuleMatch(
                                rule_id=rule.rule_id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                category=rule.category,
                                flagged_snippet=content.strip()[:200],
                                line_number=current_new_line,
                                file_path=file_path,
                            )
                        )
            elif not raw_line.startswith("-"):
                current_new_line += 1

        return matches

    def scan_commit_files(self, files: list[dict]) -> list[RuleMatch]:
        """Scan all file patches from a GitHub commit API response."""
        all_matches: list[RuleMatch] = []
        for f in files:
            patch = f.get("patch", "")
            if not patch:
                continue
            filename = f.get("filename", "")
            if self._should_skip(filename):
                continue
            all_matches.extend(self.scan_diff(patch, filename))
        return all_matches

    @staticmethod
    def _should_skip(filename: str) -> bool:
        if any(filename.endswith(s) for s in _SKIP_SUFFIXES):
            return True
        return any(fragment in filename for fragment in _SKIP_FRAGMENTS)

    @staticmethod
    def worst_severity(matches: list[RuleMatch]) -> Severity:
        for s in SEVERITY_ORDER:
            if any(m.severity == s for m in matches):
                return s
        return Severity.LOW
