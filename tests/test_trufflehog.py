from src.dorker import Finding


def test_finding_source_defaults_to_dorker():
    f = Finding(
        id="abc",
        query="test",
        category="cloud_credentials",
        repo_full_name="org/repo",
        repo_url="https://github.com/org/repo",
        file_path=".env",
        file_url="https://github.com/org/repo/blob/main/.env",
        snippet="AWS_ACCESS_KEY_ID=[REDACTED]",
        repo_is_fork=False,
        repo_stars=0,
        repo_language=None,
        repo_created_at="",
        repo_pushed_at="",
    )
    assert f.source == "dorker"


def test_finding_source_can_be_set_to_trufflehog():
    f = Finding(
        id="abc",
        query="AWS",
        category="aws",
        repo_full_name="org/repo",
        repo_url="https://github.com/org/repo",
        file_path=".env",
        file_url="https://github.com/org/repo/blob/main/.env",
        snippet="",
        repo_is_fork=False,
        repo_stars=0,
        repo_language=None,
        repo_created_at="",
        repo_pushed_at="",
        source="trufflehog",
    )
    assert f.source == "trufflehog"
