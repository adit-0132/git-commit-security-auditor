from __future__ import annotations

from typing import Callable, TYPE_CHECKING

import anthropic

if TYPE_CHECKING:
    from .models import Finding


class AIExplainerError(Exception):
    pass


_SYSTEM_PROMPT = """\
You are a security engineer reviewing a Git commit on behalf of a junior developer.
Your job is to explain what security issue was found, why it matters in plain language, \
and provide a concrete code fix.

Rules:
- Write for a developer with 1-2 years of experience
- Be specific: reference the actual code snippet, not a generic description
- For each issue, briefly describe the real-world attack scenario (1-2 sentences)
- Always provide a working code fix, not just general advice
- Be direct and constructive, not alarmist
- If multiple issues exist in one commit, address each one with a clear ## Issue N header
- End with a ## Summary section covering the overall risk level of this commit
- Format your response in Markdown with code blocks for fixes
"""


def _build_user_prompt(finding: Finding) -> str:
    issue_blocks: list[str] = []
    for i, match in enumerate(finding.matches, 1):
        location = f"File: {match.file_path or 'unknown'}"
        if match.line_number:
            location += f", line {match.line_number}"
        block = (
            f"Issue {i}: {match.rule_name} [{match.severity.value.upper()}]\n"
            f"{location}\n"
            f"Category: {match.category}\n"
            f"Flagged code:\n```\n{match.flagged_snippet}\n```"
        )
        issue_blocks.append(block)

    issues_text = "\n\n".join(issue_blocks)
    timestamp_str = finding.timestamp.strftime("%Y-%m-%d %H:%M UTC")

    return (
        f"Commit: {finding.short_sha} by {finding.author}\n"
        f"Committed at: {timestamp_str}\n"
        f"Commit message: {finding.commit_message[:200]}\n\n"
        f"The automated scanner found {len(finding.matches)} security issue(s) in this commit:\n\n"
        f"{issues_text}\n\n"
        "Please explain:\n"
        "1. What each issue is and why it is dangerous (with a real-world attack scenario)\n"
        "2. A concrete code fix for each issue\n"
        "3. A brief summary of the overall risk level of this commit\n\n"
        "Keep your explanation clear enough for a junior developer to act on immediately."
    )


class AIExplainer:
    MODEL = "claude-sonnet-4-6"
    MAX_TOKENS = 1024

    def __init__(self, api_key: str, timeout: int = 60) -> None:
        self.client = anthropic.Anthropic(api_key=api_key, timeout=timeout)

    def explain(self, finding: Finding) -> str:
        """Call Claude to generate a plain-English security explanation for a finding.

        Returns Markdown text. Raises AIExplainerError on unrecoverable failure.
        """
        try:
            response = self.client.messages.create(
                model=self.MODEL,
                max_tokens=self.MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": _build_user_prompt(finding)}],
            )
            return response.content[0].text
        except anthropic.RateLimitError as exc:
            raise AIExplainerError(
                f"Anthropic rate limit hit: {exc}. Try again later or use --no-ai."
            ) from exc
        except anthropic.AuthenticationError as exc:
            raise AIExplainerError(
                f"Invalid ANTHROPIC_API_KEY: {exc}. Check your key or use --no-ai."
            ) from exc
        except anthropic.APITimeoutError as exc:
            raise AIExplainerError(
                f"Anthropic API timed out: {exc}. Use --no-ai or increase timeout."
            ) from exc
        except anthropic.APIError as exc:
            raise AIExplainerError(f"Anthropic API error: {exc}") from exc

    def explain_batch(
        self,
        findings: list[Finding],
        on_progress: Callable[[int, int], None] | None = None,
    ) -> list[Finding]:
        """Annotate findings in-place with AI explanations.

        On per-finding failure, sets ai_explanation to a bracketed error string
        and continues — never aborts the whole batch.
        """
        for i, finding in enumerate(findings):
            try:
                finding.ai_explanation = self.explain(finding)
            except AIExplainerError as exc:
                finding.ai_explanation = f"[AI explanation unavailable: {exc}]"
            if on_progress:
                on_progress(i + 1, len(findings))
        return findings
