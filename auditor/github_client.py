from __future__ import annotations

import time
from typing import Iterator
from urllib.parse import urlparse

import requests


class GitHubAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class RateLimitError(GitHubAPIError):
    def __init__(self, retry_after: int) -> None:
        super().__init__(
            f"GitHub API rate limit exceeded. Retry after {retry_after}s.", 429
        )
        self.retry_after = retry_after


class GitHubClient:
    BASE_URL = "https://api.github.com"

    def __init__(self, token: str, timeout: int = 30, max_retries: int = 3) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        self.timeout = timeout
        self.max_retries = max_retries

    def parse_repo_url(self, url: str) -> tuple[str, str]:
        """Parse a GitHub URL or owner/repo slug into (owner, repo).

        Accepts:
          - https://github.com/owner/repo
          - https://github.com/owner/repo.git
          - owner/repo
        """
        cleaned = url.strip().rstrip("/").removesuffix(".git")
        if cleaned.startswith("http"):
            path = urlparse(cleaned).path.strip("/")
        else:
            path = cleaned
        parts = [p for p in path.split("/") if p]
        if len(parts) != 2:
            raise ValueError(
                f"Invalid GitHub repo URL or slug: {url!r}. "
                "Expected 'https://github.com/owner/repo' or 'owner/repo'."
            )
        return parts[0], parts[1]

    def get_repo(self, owner: str, repo: str) -> dict:
        """Fetch repository metadata. Raises GitHubAPIError if inaccessible."""
        return self._get(f"/repos/{owner}/{repo}")  # type: ignore[return-value]

    def iter_commits(self, owner: str, repo: str, limit: int = 50) -> Iterator[dict]:
        """Yield up to `limit` commit summary objects, handling pagination."""
        fetched = 0
        page = 1
        per_page = min(limit, 100)
        while fetched < limit:
            batch: list[dict] = self._get(  # type: ignore[assignment]
                f"/repos/{owner}/{repo}/commits",
                params={"per_page": per_page, "page": page},
            )
            if not batch:
                return
            for commit in batch:
                if fetched >= limit:
                    return
                yield commit
                fetched += 1
            if len(batch) < per_page:
                return  # no more pages
            page += 1

    def get_commit_diff(self, owner: str, repo: str, sha: str) -> dict:
        """Fetch full commit detail including per-file patches."""
        return self._get(f"/repos/{owner}/{repo}/commits/{sha}")  # type: ignore[return-value]

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        url = f"{self.BASE_URL}{path}"
        for attempt in range(self.max_retries):
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except requests.Timeout:
                raise GitHubAPIError(f"Request timed out: GET {path}")
            except requests.ConnectionError as exc:
                raise GitHubAPIError(f"Network error on GET {path}: {exc}")

            remaining = resp.headers.get("X-RateLimit-Remaining", "")

            if resp.status_code == 200:
                if remaining and int(remaining) < 10:
                    # Low rate limit warning — caller sees this via normal flow
                    pass
                return resp.json()

            if resp.status_code in (403, 429):
                if remaining == "0":
                    reset = resp.headers.get("X-RateLimit-Reset", "")
                    retry_after = max(int(reset) - int(time.time()), 1) if reset else 60
                    raise RateLimitError(retry_after)
                # 403 without rate limit = permission issue
                try:
                    message = resp.json().get("message", "")
                except Exception:
                    message = resp.text[:200]
                raise GitHubAPIError(
                    f"Access denied (HTTP 403): {message}. "
                    "Check that your token has the required permissions.",
                    403,
                )

            if resp.status_code == 404:
                raise GitHubAPIError(
                    f"Not found (HTTP 404): {path}. "
                    "Verify the repo URL and that your token can access it.",
                    404,
                )

            if resp.status_code == 422:
                try:
                    msg = resp.json().get("message", resp.text[:200])
                except Exception:
                    msg = resp.text[:200]
                raise GitHubAPIError(f"Unprocessable request: {msg}", 422)

            if resp.status_code >= 500:
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise GitHubAPIError(
                    f"GitHub server error (HTTP {resp.status_code}) after "
                    f"{self.max_retries} attempts.",
                    resp.status_code,
                )

            raise GitHubAPIError(
                f"Unexpected HTTP {resp.status_code}: {resp.text[:200]}",
                resp.status_code,
            )

        raise GitHubAPIError(f"All {self.max_retries} retries failed for GET {path}")
