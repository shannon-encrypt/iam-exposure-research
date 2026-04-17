"""
trufflehog.py
TruffleHog integration for IAM exposure research.
Shells out to the locally-installed trufflehog binary, parses JSON output,
and returns Finding objects compatible with the existing enrichment pipeline.
"""

import json
import subprocess
import hashlib
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

    assert proc.stdout is not None
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


def scan_source(org: str | None = None, repo: str | None = None) -> list[Finding]:
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
