from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


class RuleMatch(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    category: str  # "secret" | "dangerous_pattern"
    flagged_snippet: str  # matched line, truncated to 200 chars
    line_number: Optional[int] = None
    file_path: Optional[str] = None


class Finding(BaseModel):
    commit_sha: str
    short_sha: str
    author: str
    author_email: str
    timestamp: datetime
    commit_message: str
    severity: Severity  # worst severity across all matches
    matches: list[RuleMatch] = Field(default_factory=list)
    ai_explanation: Optional[str] = None
    commit_url: str


class ScanMetadata(BaseModel):
    repo_url: str
    repo_full_name: str
    scanned_at: datetime
    commits_scanned: int
    commits_flagged: int
    total_findings: int
    scanner_version: str


class Report(BaseModel):
    metadata: ScanMetadata
    findings: list[Finding] = Field(default_factory=list)
