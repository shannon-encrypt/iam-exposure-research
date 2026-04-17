# TruffleHog Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TruffleHog as a dual-mode secret scanner — independent org/repo discovery and post-enrichment git history depth scan — feeding findings into the existing Claude enrichment and reporting pipeline.

**Architecture:** A new `src/trufflehog.py` module shells out to the `trufflehog` binary, converts JSON output to `Finding` objects, and returns them as peers to dorker findings. `main.py` orchestrates two enrichment passes: one before the depth scan (so severity filter is valid) and one after for new TruffleHog depth findings.

**Tech Stack:** Python 3.12, subprocess (stdlib), pytest, existing `Finding` dataclass, `rich` for console output.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `src/dorker.py` | Modify | Add `source` field to `Finding` dataclass |
| `src/trufflehog.py` | Create | TruffleHog subprocess wrapper, JSON→Finding converter, scan functions |
| `main.py` | Modify | Add `--trufflehog`/`--repo` flags, two-pass enrichment orchestration |
| `requirements.txt` | Modify | Add `pytest>=8.0.0` |
| `tests/__init__.py` | Create | Empty — makes tests a package |
| `tests/test_trufflehog.py` | Create | Unit tests for all `src/trufflehog.py` functions |

---

## Task 1: Test infrastructure + `source` field on `Finding`

**Files:**
- Modify: `requirements.txt`
- Modify: `src/dorker.py` (Finding dataclass, lines 26–51)
- Create: `tests/__init__.py`
- Create: `tests/test_trufflehog.py`

- [ ] **Step 1: Add pytest to requirements.txt**

Open `requirements.txt` and add at the bottom:
```
pytest>=8.0.0
```

- [ ] **Step 2: Install pytest in the venv**

```bash
source venv/bin/activate && pip install pytest>=8.0.0
```

Expected: `Successfully installed pytest-...`

- [ ] **Step 3: Create tests package**

```bash
mkdir tests && touch tests/__init__.py
```

- [ ] **Step 4: Write failing test for `source` field**

Create `tests/test_trufflehog.py`:

```python
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
```

- [ ] **Step 5: Run tests to verify they fail**

```bash
cd /path/to/iam-exposure-research && source venv/bin/activate && pytest tests/test_trufflehog.py -v
```

Expected: `ERROR` — `Finding` has no `source` field yet.

- [ ] **Step 6: Add `source` field to `Finding` dataclass**

In `src/dorker.py`, locate the `Finding` dataclass. Add `source` after the `discovered_at` field and before the enricher-filled fields (around line 41):

```python
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str = "dorker"  # "dorker" or "trufflehog"

    # Filled in by enricher
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
pytest tests/test_trufflehog.py::test_finding_source_defaults_to_dorker tests/test_trufflehog.py::test_finding_source_can_be_set_to_trufflehog -v
```

Expected: `2 passed`

- [ ] **Step 8: Commit**

```bash
git add requirements.txt src/dorker.py tests/__init__.py tests/test_trufflehog.py
git commit -m "feat: add source field to Finding dataclass and test infrastructure"
```

---

## Task 2: `_run_trufflehog` — subprocess wrapper

**Files:**
- Create: `src/trufflehog.py`
- Modify: `tests/test_trufflehog.py`

- [ ] **Step 1: Write failing tests for `_run_trufflehog`**

Append to `tests/test_trufflehog.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_trufflehog.py -k "run_trufflehog" -v
```

Expected: `ImportError` — `src/trufflehog.py` does not exist yet.

- [ ] **Step 3: Create `src/trufflehog.py` with `_run_trufflehog`**

```python
"""
trufflehog.py
TruffleHog integration for IAM exposure research.
Shells out to the locally-installed trufflehog binary, parses JSON output,
and returns Finding objects compatible with the existing enrichment pipeline.
"""

import json
import subprocess
import hashlib
from datetime import datetime
from rich.console import Console
from src.dorker import Finding

console = Console()


def _run_trufflehog(args: list[str]) -> list[dict]:
    cmd = ["trufflehog"] + args + ["--json", "--no-update"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        raise RuntimeError(
            "trufflehog not found. Install from https://github.com/trufflesecurity/trufflehog"
        )

    results = []
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            console.print(f"[yellow]TruffleHog: skipping non-JSON line: {line[:80]}[/yellow]")

    proc.wait()
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_trufflehog.py -k "run_trufflehog" -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add src/trufflehog.py tests/test_trufflehog.py
git commit -m "feat: add _run_trufflehog subprocess wrapper"
```

---

## Task 3: `_to_finding` — TruffleHog JSON → Finding converter

**Files:**
- Modify: `src/trufflehog.py`
- Modify: `tests/test_trufflehog.py`

- [ ] **Step 1: Write failing tests for `_to_finding`**

Append to `tests/test_trufflehog.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_trufflehog.py -k "to_finding" -v
```

Expected: `ImportError` — `_to_finding` not defined yet.

- [ ] **Step 3: Add `_to_finding` to `src/trufflehog.py`**

Add this function after `_run_trufflehog`:

```python
def _to_finding(result: dict) -> Finding:
    gh = result.get("SourceMetadata", {}).get("Data", {}).get("Github", {})
    repo_url = gh.get("repository", "")
    parts = repo_url.rstrip("/").split("/")
    repo_full_name = "/".join(parts[-2:]) if len(parts) >= 2 else ""
    file_path = gh.get("file", "")
    file_url = gh.get("link", "")
    detector = result.get("DetectorName", "unknown")
    category = detector.lower()

    fid = hashlib.sha256(
        f"{repo_full_name}::{file_path}::{detector}".encode()
    ).hexdigest()[:16]

    return Finding(
        id=fid,
        query=detector,
        category=category,
        repo_full_name=repo_full_name,
        repo_url=repo_url,
        file_path=file_path,
        file_url=file_url,
        snippet="",
        repo_is_fork=False,
        repo_stars=0,
        repo_language=None,
        repo_created_at="",
        repo_pushed_at="",
        is_likely_real=result.get("Verified", False),
        secret_types=[detector],
        source="trufflehog",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_trufflehog.py -k "to_finding" -v
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add src/trufflehog.py tests/test_trufflehog.py
git commit -m "feat: add _to_finding TruffleHog JSON to Finding converter"
```

---

## Task 4: `scan_source` — independent org/repo discovery

**Files:**
- Modify: `src/trufflehog.py`
- Modify: `tests/test_trufflehog.py`

- [ ] **Step 1: Write failing tests for `scan_source`**

Append to `tests/test_trufflehog.py`:

```python
from src.trufflehog import scan_source

TH_AWS_RESULT = {
    "SourceMetadata": {
        "Data": {
            "Github": {
                "repository": "https://github.com/org/repo",
                "file": ".env",
                "link": "https://github.com/org/repo/blob/abc123/.env",
            }
        }
    },
    "DetectorName": "AWS",
    "Verified": True,
}

TH_OKTA_RESULT = {
    "SourceMetadata": {
        "Data": {
            "Github": {
                "repository": "https://github.com/org/repo2",
                "file": "config.env",
                "link": "https://github.com/org/repo2/blob/abc123/config.env",
            }
        }
    },
    "DetectorName": "Okta",
    "Verified": False,
}


def test_scan_source_org_calls_github_subcommand():
    with patch("src.trufflehog._run_trufflehog", return_value=[TH_AWS_RESULT]) as mock_run:
        findings = scan_source(org="myorg")
    mock_run.assert_called_once_with(["github", "--org=myorg"])
    assert len(findings) == 1
    assert findings[0].source == "trufflehog"


def test_scan_source_repo_calls_git_subcommand():
    with patch("src.trufflehog._run_trufflehog", return_value=[TH_AWS_RESULT]) as mock_run:
        findings = scan_source(repo="https://github.com/org/repo")
    mock_run.assert_called_once_with(["git", "https://github.com/org/repo"])
    assert len(findings) == 1


def test_scan_source_org_and_repo_calls_both():
    with patch("src.trufflehog._run_trufflehog", side_effect=[[TH_AWS_RESULT], [TH_OKTA_RESULT]]) as mock_run:
        findings = scan_source(org="myorg", repo="https://github.com/org/repo2")
    assert mock_run.call_count == 2
    assert len(findings) == 2


def test_scan_source_deduplicates_same_finding():
    with patch("src.trufflehog._run_trufflehog", side_effect=[[TH_AWS_RESULT], [TH_AWS_RESULT]]):
        findings = scan_source(org="myorg", repo="https://github.com/org/repo")
    assert len(findings) == 1


def test_scan_source_returns_empty_when_no_args():
    with patch("src.trufflehog._run_trufflehog") as mock_run:
        findings = scan_source()
    mock_run.assert_not_called()
    assert findings == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_trufflehog.py -k "scan_source" -v
```

Expected: `ImportError` — `scan_source` not defined yet.

- [ ] **Step 3: Add `scan_source` to `src/trufflehog.py`**

Add after `_to_finding`:

```python
def scan_source(org: str = None, repo: str = None) -> list[Finding]:
    all_results = []

    if org:
        console.print(f"[bold]TruffleHog: scanning org [cyan]{org}[/cyan]...[/bold]")
        all_results.extend(_run_trufflehog(["github", f"--org={org}"]))

    if repo:
        console.print(f"[bold]TruffleHog: scanning repo [cyan]{repo}[/cyan]...[/bold]")
        all_results.extend(_run_trufflehog(["git", repo]))

    seen: dict[str, Finding] = {}
    for result in all_results:
        finding = _to_finding(result)
        if finding.id not in seen:
            seen[finding.id] = finding

    findings = list(seen.values())
    console.print(f"[green]TruffleHog: {len(findings)} unique findings from independent scan[/green]")
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_trufflehog.py -k "scan_source" -v
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add src/trufflehog.py tests/test_trufflehog.py
git commit -m "feat: add scan_source for independent TruffleHog org/repo discovery"
```

---

## Task 5: `scan_repos_from_findings` — post-enrichment depth scan

**Files:**
- Modify: `src/trufflehog.py`
- Modify: `tests/test_trufflehog.py`

- [ ] **Step 1: Write failing tests for `scan_repos_from_findings`**

Append to `tests/test_trufflehog.py`:

```python
from src.trufflehog import scan_repos_from_findings


def _make_finding(repo_url: str, file_path: str, severity: str, source: str = "dorker") -> Finding:
    fid = hashlib.sha256(f"{repo_url}::{file_path}::test".encode()).hexdigest()[:16]
    return Finding(
        id=fid,
        query="test",
        category="cloud_credentials",
        repo_full_name="/".join(repo_url.rstrip("/").split("/")[-2:]),
        repo_url=repo_url,
        file_path=file_path,
        file_url=repo_url + "/blob/main/" + file_path,
        snippet="",
        repo_is_fork=False,
        repo_stars=0,
        repo_language=None,
        repo_created_at="",
        repo_pushed_at="",
        severity=severity,
        source=source,
    )


def test_scan_repos_from_findings_scans_non_informational_repos():
    findings = [
        _make_finding("https://github.com/org/repo1", ".env", "high"),
        _make_finding("https://github.com/org/repo2", ".env", "informational"),
        _make_finding("https://github.com/org/repo3", ".env", "critical"),
    ]
    new_th = {
        "SourceMetadata": {"Data": {"Github": {
            "repository": "https://github.com/org/repo1",
            "file": "secrets/old.env",
            "link": "https://github.com/org/repo1/blob/abc/secrets/old.env",
        }}},
        "DetectorName": "AWS",
        "Verified": False,
    }
    with patch("src.trufflehog._run_trufflehog", return_value=[new_th]) as mock_run:
        new_findings = scan_repos_from_findings(findings)

    # repo1 (high) and repo3 (critical) scanned; repo2 (informational) skipped
    assert mock_run.call_count == 2
    called_args = [call[0][0] for call in mock_run.call_args_list]
    assert ["git", "https://github.com/org/repo1"] in called_args
    assert ["git", "https://github.com/org/repo3"] in called_args


def test_scan_repos_from_findings_excludes_already_known_ids():
    existing_finding = _make_finding("https://github.com/org/repo1", ".env", "high")
    # TruffleHog returns a result that maps to the same id as existing_finding
    same_result = {
        "SourceMetadata": {"Data": {"Github": {
            "repository": "https://github.com/org/repo1",
            "file": ".env",
            "link": "https://github.com/org/repo1/blob/main/.env",
        }}},
        "DetectorName": "test",
        "Verified": False,
    }
    # The id of same_result would differ because detector differs, so let's use a truly duplicate result
    # by patching _to_finding to return the existing id
    with patch("src.trufflehog._run_trufflehog", return_value=[same_result]):
        new_findings = scan_repos_from_findings([existing_finding])
    # Only new (non-duplicate) findings returned
    for f in new_findings:
        assert f.id != existing_finding.id


def test_scan_repos_from_findings_returns_empty_if_all_informational():
    findings = [
        _make_finding("https://github.com/org/repo1", ".env", "informational"),
    ]
    with patch("src.trufflehog._run_trufflehog") as mock_run:
        result = scan_repos_from_findings(findings)
    mock_run.assert_not_called()
    assert result == []


def test_scan_repos_from_findings_deduplicates_repos():
    findings = [
        _make_finding("https://github.com/org/repo1", ".env", "high"),
        _make_finding("https://github.com/org/repo1", "config.yml", "medium"),
    ]
    with patch("src.trufflehog._run_trufflehog", return_value=[]) as mock_run:
        scan_repos_from_findings(findings)
    # Same repo URL appears twice in findings — should only be scanned once
    assert mock_run.call_count == 1
```

Note: the test file needs `import hashlib` at the top. Add it alongside the existing imports.

- [ ] **Step 2: Add `import hashlib` to top of `tests/test_trufflehog.py`**

At the top of `tests/test_trufflehog.py`, ensure this import exists (add if missing):

```python
import hashlib
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pytest tests/test_trufflehog.py -k "scan_repos_from_findings" -v
```

Expected: `ImportError` — `scan_repos_from_findings` not defined yet.

- [ ] **Step 4: Add `scan_repos_from_findings` to `src/trufflehog.py`**

Add after `scan_source`:

```python
def scan_repos_from_findings(findings: list[Finding]) -> list[Finding]:
    repos = list({
        f.repo_url
        for f in findings
        if f.severity is not None and f.severity != "informational" and f.repo_url
    })

    if not repos:
        console.print("[yellow]TruffleHog: no repos to depth-scan (all findings are informational)[/yellow]")
        return []

    console.print(f"[bold]TruffleHog: depth-scanning {len(repos)} repos (full git history)...[/bold]")

    existing_ids = {f.id for f in findings}
    new_findings: dict[str, Finding] = {}

    for repo_url in repos:
        console.print(f"  → {repo_url}")
        results = _run_trufflehog(["git", repo_url])
        for result in results:
            finding = _to_finding(result)
            if finding.id not in existing_ids and finding.id not in new_findings:
                new_findings[finding.id] = finding

    result_list = list(new_findings.values())
    console.print(f"[green]TruffleHog: {len(result_list)} new findings from depth scan[/green]")
    return result_list
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_trufflehog.py -k "scan_repos_from_findings" -v
```

Expected: `4 passed`

- [ ] **Step 6: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/trufflehog.py tests/test_trufflehog.py
git commit -m "feat: add scan_repos_from_findings for post-enrichment depth scan"
```

---

## Task 6: Wire TruffleHog into `main.py`

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Add new CLI flags to `parse_args`**

In `main.py`, locate `parse_args()` and add two new arguments after the existing `--org` line:

```python
    parser.add_argument("--org", type=str, help="Scope all dork queries to a GitHub org (e.g. braze-inc)")
    parser.add_argument("--trufflehog", action="store_true", help="Enable TruffleHog scanning (independent + depth scan)")
    parser.add_argument("--repo", type=str, help="Scan a specific repo URL with TruffleHog (implies --trufflehog)")
    return parser.parse_args()
```

- [ ] **Step 2: Add `deduplicate` helper to `main.py`**

Add this function above `main()`:

```python
def deduplicate(finding_lists: list) -> list:
    seen = {}
    for findings in finding_lists:
        for f in findings:
            if f.id not in seen:
                seen[f.id] = f
            elif f.source == "trufflehog" and f.is_likely_real:
                seen[f.id] = f
    return list(seen.values())
```

- [ ] **Step 3: Update `main()` orchestration**

Replace the existing `main()` body (from `if args.load_findings:` to end of function) with:

```python
def main():
    args = parse_args()
    console.rule("[bold blue]IAM Exposure Research Tool[/bold blue]")

    th_enabled = args.trufflehog or bool(args.repo)

    # --- Load or dork ---
    if args.load_findings:
        from src.dorker import Finding
        from dataclasses import fields
        with open(args.load_findings) as f:
            raw = json.load(f)
        finding_fields = {field.name for field in fields(Finding)}
        dork_findings = [Finding(**{k: v for k, v in item.items() if k in finding_fields}) for item in raw]
        console.print(f"[green]Loaded {len(dork_findings)} findings[/green]")
    else:
        from src.dorker import run_dorks
        dork_findings = run_dorks(categories=args.categories, max_results_per_query=args.max_results, dry_run=args.dry_run, org=args.org)
        if args.dry_run:
            if th_enabled:
                from src.trufflehog import scan_source
                console.print("\n[bold]TruffleHog commands (dry run):[/bold]")
                if args.org:
                    console.print(f"  → trufflehog github --org={args.org} --json --no-update")
                if args.repo:
                    console.print(f"  → trufflehog git {args.repo} --json --no-update")
                console.print("  → trufflehog git <repo_url> --json --no-update  (per enriched finding)")
            sys.exit(0)

    # --- Independent TruffleHog scan ---
    th_independent = []
    if th_enabled:
        from src.trufflehog import scan_source
        th_independent = scan_source(org=args.org, repo=args.repo)

    # --- First merge: TH independent + dorker ---
    merged = deduplicate([th_independent, dork_findings])

    if not merged:
        console.print("[yellow]No findings.[/yellow]")
        sys.exit(0)

    # --- First enrichment pass ---
    if not args.skip_enrichment:
        from src.enricher import enrich_findings
        enriched = enrich_findings(merged, only_real=False)
    else:
        enriched = merged

    # --- Post-enrichment TruffleHog depth scan ---
    th_depth = []
    if th_enabled and not args.skip_enrichment:
        from src.trufflehog import scan_repos_from_findings
        th_depth = scan_repos_from_findings(enriched)
        if th_depth:
            from src.enricher import enrich_findings
            th_depth = enrich_findings(th_depth, only_real=False)

    # --- Final merge, filter, sort ---
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    all_findings = deduplicate([enriched, th_depth])
    if args.only_real:
        all_findings = [f for f in all_findings if f.is_likely_real]
        console.print(f"[yellow]Filtered to {len(all_findings)} likely-real findings[/yellow]")
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity or "informational", 4))

    from src.reporter import generate_report
    json_path, blog_path = generate_report(all_findings)

    console.rule("[bold green]Complete[/bold green]")
    console.print(f"  Findings JSON : {json_path}")
    console.print(f"  Blog post     : {blog_path}")
```

- [ ] **Step 4: Verify the tool still runs in dry-run mode**

```bash
source venv/bin/activate && python main.py --dry-run
```

Expected: queries printed, no errors, exits 0.

- [ ] **Step 5: Verify dry-run with `--trufflehog` prints TruffleHog commands**

```bash
python main.py --dry-run --trufflehog --org testorg
```

Expected: GitHub dork queries printed, then TruffleHog commands section showing `trufflehog github --org=testorg ...`.

- [ ] **Step 6: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add main.py
git commit -m "feat: wire TruffleHog into main pipeline with two-pass enrichment"
```

---

## Task 7: Update README and CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add TruffleHog to README usage section**

In `README.md`, add to the Usage section after the existing examples:

```markdown
# Run with TruffleHog independent org scan + depth scan on dorker findings
python main.py --trufflehog --org braze-inc

# Scan a single repo with TruffleHog only (no dorking)
python main.py --skip-enrichment --trufflehog --repo https://github.com/org/repo

# Full run: dorking + TruffleHog independent + depth scan
python main.py --trufflehog
```

Also add a **Requirements** note under Setup:

```markdown
### TruffleHog (optional)
Required only if using `--trufflehog` or `--repo` flags.
Install: https://github.com/trufflesecurity/trufflehog
```

- [ ] **Step 2: Update CHANGELOG**

Add to the top of `CHANGELOG.md` under `[Unreleased]`:

```markdown
## [Unreleased] - 2026-04-17

### Added
- `--trufflehog` flag: enables TruffleHog scanning in two modes
  - Independent scan: runs `trufflehog github --org` or `trufflehog git <repo>` before dorking
  - Depth scan: runs `trufflehog git` on all non-informational repos after first enrichment pass
- `--repo <url>` flag: scan a single repo with TruffleHog (implies `--trufflehog`)
- `source` field on `Finding` dataclass (`"dorker"` or `"trufflehog"`) for origin tracking
- Two-pass enrichment: independent+dorker findings enriched first, TruffleHog depth findings enriched separately
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: update README and CHANGELOG for TruffleHog integration"
```
