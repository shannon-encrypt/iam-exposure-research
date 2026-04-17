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


import json
from unittest.mock import patch, MagicMock
from src.trufflehog import _run_trufflehog


def _mock_popen(stdout_lines: list[str]):
    """Helper: returns a mock Popen that yields stdout_lines."""
    mock_proc = MagicMock()
    mock_proc.stdout = iter(stdout_lines)
    mock_proc.wait.return_value = 0
    return MagicMock(return_value=mock_proc)


def test_run_trufflehog_parses_json_lines():
    lines = [
        json.dumps({"DetectorName": "AWS", "Verified": True}) + "\n",
        json.dumps({"DetectorName": "Okta", "Verified": False}) + "\n",
    ]
    with patch("src.trufflehog.subprocess.Popen", _mock_popen(lines)):
        result = _run_trufflehog(["github", "--org=test"])
    assert len(result) == 2
    assert result[0]["DetectorName"] == "AWS"
    assert result[1]["Verified"] is False


def test_run_trufflehog_skips_blank_lines():
    lines = [
        json.dumps({"DetectorName": "AWS", "Verified": True}) + "\n",
        "\n",
        "   \n",
    ]
    with patch("src.trufflehog.subprocess.Popen", _mock_popen(lines)):
        result = _run_trufflehog(["github", "--org=test"])
    assert len(result) == 1


def test_run_trufflehog_skips_non_json_lines():
    lines = [
        "time=2024-01-01 level=info msg=scanning\n",
        json.dumps({"DetectorName": "AWS", "Verified": True}) + "\n",
    ]
    with patch("src.trufflehog.subprocess.Popen", _mock_popen(lines)):
        result = _run_trufflehog(["github", "--org=test"])
    assert len(result) == 1


def test_run_trufflehog_raises_if_binary_missing():
    with patch("src.trufflehog.subprocess.Popen", side_effect=FileNotFoundError):
        try:
            _run_trufflehog(["github", "--org=test"])
            assert False, "should have raised RuntimeError"
        except RuntimeError as e:
            assert "trufflehog not found" in str(e)
            assert "https://github.com/trufflesecurity/trufflehog" in str(e)
