from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


class ConfigError(Exception):
    pass


@dataclass
class Config:
    github_token: str
    anthropic_api_key: str
    commit_limit: int = 50
    skip_ai: bool = False
    output_dir: str = "."
    min_severity: str = "low"
    timeout_github: int = 30
    timeout_anthropic: int = 60
    max_retries: int = 3


def load_config(
    github_token: Optional[str] = None,
    anthropic_api_key: Optional[str] = None,
    commit_limit: int = 50,
    skip_ai: bool = False,
    output_dir: str = ".",
    min_severity: str = "low",
) -> Config:
    """Load and validate configuration.

    Priority: CLI flag > environment variable > error (for required values).
    Collects all missing-value errors before raising so the user sees them all at once.
    """
    gh_token = github_token or os.environ.get("GITHUB_TOKEN", "")
    ai_key = anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    errors: list[str] = []
    if not gh_token:
        errors.append(
            "GITHUB_TOKEN not set. Use --github-token or export GITHUB_TOKEN=ghp_..."
        )
    if not ai_key and not skip_ai:
        errors.append(
            "ANTHROPIC_API_KEY not set. Use --anthropic-key, export ANTHROPIC_API_KEY=sk-ant-..., "
            "or pass --no-ai to skip AI explanations."
        )
    if errors:
        raise ConfigError("\n".join(errors))

    return Config(
        github_token=gh_token,
        anthropic_api_key=ai_key,
        commit_limit=commit_limit,
        skip_ai=skip_ai,
        output_dir=output_dir,
        min_severity=min_severity,
    )
