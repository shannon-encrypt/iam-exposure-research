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


from src.trufflehog import _to_finding


SAMPLE_TH_RESULT = {
    "SourceMetadata": {
        "Data": {
            "Github": {
                "repository": "https://github.com/org/repo",
                "file": "config/.env",
                "link": "https://github.com/org/repo/blob/abc123/config/.env",
                "commit": "abc123",
                "email": "dev@example.com",
                "timestamp": "2024-01-01 00:00:00 +0000",
            }
        }
    },
    "DetectorName": "AWS",
    "Verified": True,
}


def test_to_finding_maps_fields_correctly():
    f = _to_finding(SAMPLE_TH_RESULT)
    assert f.repo_full_name == "org/repo"
    assert f.repo_url == "https://github.com/org/repo"
    assert f.file_path == "config/.env"
    assert f.file_url == "https://github.com/org/repo/blob/abc123/config/.env"
    assert f.secret_types == ["AWS"]
    assert f.is_likely_real is True
    assert f.source == "trufflehog"
    assert f.category == "aws"


def test_to_finding_unverified_sets_is_likely_real_false():
    result = dict(SAMPLE_TH_RESULT)
    result["Verified"] = False
    f = _to_finding(result)
    assert f.is_likely_real is False


def test_to_finding_stable_id():
    f1 = _to_finding(SAMPLE_TH_RESULT)
    f2 = _to_finding(SAMPLE_TH_RESULT)
    assert f1.id == f2.id


def test_to_finding_id_differs_for_different_files():
    result2 = dict(SAMPLE_TH_RESULT)
    result2["SourceMetadata"] = {
        "Data": {
            "Github": {
                "repository": "https://github.com/org/repo",
                "file": "other/.env",
                "link": "https://github.com/org/repo/blob/abc123/other/.env",
            }
        }
    }
    f1 = _to_finding(SAMPLE_TH_RESULT)
    f2 = _to_finding(result2)
    assert f1.id != f2.id


def test_to_finding_missing_github_metadata_graceful():
    result = {"DetectorName": "Okta", "Verified": False, "SourceMetadata": {"Data": {}}}
    f = _to_finding(result)
    assert f.repo_full_name == ""
    assert f.file_path == ""
    assert f.source == "trufflehog"
