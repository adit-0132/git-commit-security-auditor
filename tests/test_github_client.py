"""Tests for GitHubClient using mocked HTTP responses."""
from __future__ import annotations

import pytest
import responses as resp_mock

from auditor.github_client import GitHubAPIError, GitHubClient, RateLimitError


@pytest.fixture
def client() -> GitHubClient:
    return GitHubClient(token="test_token", timeout=5, max_retries=2)


# parse_repo_url

class TestParseRepoUrl:
    def test_full_https_url(self, client):
        assert client.parse_repo_url("https://github.com/owner/repo") == ("owner", "repo")

    def test_full_url_with_git_suffix(self, client):
        assert client.parse_repo_url("https://github.com/owner/repo.git") == ("owner", "repo")

    def test_full_url_trailing_slash(self, client):
        assert client.parse_repo_url("https://github.com/owner/repo/") == ("owner", "repo")

    def test_short_slug(self, client):
        assert client.parse_repo_url("owner/repo") == ("owner", "repo")

    def test_invalid_url_raises(self, client):
        with pytest.raises(ValueError, match="Invalid GitHub repo URL"):
            client.parse_repo_url("not-a-repo")

    def test_too_many_parts_raises(self, client):
        with pytest.raises(ValueError):
            client.parse_repo_url("owner/repo/extra")


# get_repo

class TestGetRepo:
    @resp_mock.activate
    def test_success(self, client):
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/repo",
            json={"full_name": "owner/repo", "id": 1},
            status=200,
        )
        result = client.get_repo("owner", "repo")
        assert result["full_name"] == "owner/repo"

    @resp_mock.activate
    def test_404_raises_not_found(self, client):
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/missing",
            json={"message": "Not Found"},
            status=404,
        )
        with pytest.raises(GitHubAPIError, match="Not found"):
            client.get_repo("owner", "missing")

    @resp_mock.activate
    def test_403_permission_raises(self, client):
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/private",
            json={"message": "Must have push access"},
            headers={"X-RateLimit-Remaining": "4999"},
            status=403,
        )
        with pytest.raises(GitHubAPIError, match="Access denied"):
            client.get_repo("owner", "private")

    @resp_mock.activate
    def test_rate_limit_raises(self, client):
        import time
        reset_ts = str(int(time.time()) + 3600)
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/repo",
            json={"message": "API rate limit exceeded"},
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": reset_ts,
            },
            status=403,
        )
        with pytest.raises(RateLimitError):
            client.get_repo("owner", "repo")


# iter_commits

def _make_commit(sha: str) -> dict:
    return {
        "sha": sha,
        "commit": {
            "author": {"name": "Test User", "email": "test@example.com", "date": "2024-01-01T00:00:00Z"},
            "message": "test commit",
        },
    }


class TestIterCommits:
    @resp_mock.activate
    def test_yields_up_to_limit(self, client):
        commits = [_make_commit(f"{i:040x}") for i in range(10)]
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/repo/commits",
            json=commits,
            status=200,
        )
        result = list(client.iter_commits("owner", "repo", limit=5))
        assert len(result) == 5

    @resp_mock.activate
    def test_pagination_stops_on_empty_page(self, client):
        page1 = [_make_commit(f"{i:040x}") for i in range(3)]
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/repo/commits",
            json=page1,
            status=200,
        )
        # Second page returns empty — pagination stops
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/repo/commits",
            json=[],
            status=200,
        )
        result = list(client.iter_commits("owner", "repo", limit=100))
        assert len(result) == 3

    @resp_mock.activate
    def test_yields_all_sha_values(self, client):
        commits = [_make_commit(f"abc{i:037x}") for i in range(3)]
        resp_mock.add(
            resp_mock.GET,
            "https://api.github.com/repos/owner/repo/commits",
            json=commits,
            status=200,
        )
        result = list(client.iter_commits("owner", "repo", limit=3))
        assert [r["sha"] for r in result] == [c["sha"] for c in commits]


# get_commit_diff

class TestGetCommitDiff:
    @resp_mock.activate
    def test_returns_files(self, client):
        sha = "a" * 40
        resp_mock.add(
            resp_mock.GET,
            f"https://api.github.com/repos/owner/repo/commits/{sha}",
            json={
                "sha": sha,
                "files": [
                    {"filename": "app.py", "patch": "+password = 'secret'", "status": "modified"},
                ],
            },
            status=200,
        )
        result = client.get_commit_diff("owner", "repo", sha)
        assert len(result["files"]) == 1
        assert result["files"][0]["filename"] == "app.py"

    @resp_mock.activate
    def test_server_error_retries_and_raises(self, client):
        sha = "b" * 40
        url = f"https://api.github.com/repos/owner/repo/commits/{sha}"
        # Two 500s (max_retries=2)
        resp_mock.add(resp_mock.GET, url, json={"message": "Internal Server Error"}, status=500)
        resp_mock.add(resp_mock.GET, url, json={"message": "Internal Server Error"}, status=500)
        with pytest.raises(GitHubAPIError, match="server error"):
            client.get_commit_diff("owner", "repo", sha)
