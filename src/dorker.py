"""
dorker.py
GitHub search module for IAM exposure research.
Executes dork queries via GitHub Search API, normalizes results,
and returns structured findings for AI enrichment.
"""

import os
import time
import yaml
import hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from github import Github, GithubException, RateLimitExceededException
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv

load_dotenv()
console = Console()


@dataclass
class Finding:
    """A single raw finding from a GitHub dork query."""
    id: str                          # SHA256 of repo+path+query for dedup
    query: str                       # The dork query that found this
    category: str                    # Category from dorks.yaml
    repo_full_name: str              # e.g. "org/repo"
    repo_url: str
    file_path: str
    file_url: str
    snippet: str                     # First 500 chars of file content (redacted later)
    repo_is_fork: bool
    repo_stars: int
    repo_language: Optional[str]
    repo_created_at: str
    repo_pushed_at: str
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Filled in by enricher
    severity: Optional[str] = None
    idp_fingerprint: Optional[str] = None
    secret_types: list = field(default_factory=list)
    mitre_ttps: list = field(default_factory=list)
    remediation: Optional[str] = None
    analyst_notes: Optional[str] = None
    is_likely_real: Optional[bool] = None


def load_dorks(dorks_path: str = None) -> dict:
    """Load dork queries from YAML file."""
    if dorks_path is None:
        dorks_path = Path(__file__).parent.parent / "queries" / "dorks.yaml"
    with open(dorks_path) as f:
        return yaml.safe_load(f)["categories"]


def make_finding_id(repo_full_name: str, file_path: str, query: str) -> str:
    """Stable dedup key for a finding."""
    raw = f"{repo_full_name}::{file_path}::{query}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def redact_snippet(content: str) -> str:
    """
    Capture enough context to classify without storing actual secret values.
    Replaces anything that looks like a credential value with [REDACTED].
    """
    import re
    # Redact values after common key patterns
    patterns = [
        r'((?:secret|key|token|password|passwd|pwd|credential|auth)\s*[=:]\s*["\']?)([A-Za-z0-9+/=_\-\.]{8,})',
        r'(AKIA[A-Z0-9]{16})',           # AWS access key format
        r'(sk-[A-Za-z0-9]{32,})',        # OpenAI-style keys
        r'(eyJ[A-Za-z0-9_\-\.]+)',       # JWTs
    ]
    redacted = content[:800]
    for pat in patterns:
        redacted = re.sub(pat, lambda m: m.group(1) + '[REDACTED]' if len(m.groups()) > 1 else '[REDACTED]', redacted, flags=re.IGNORECASE)
    return redacted[:500]


def run_dorks(
    categories: list[str] = None,
    max_results_per_query: int = 10,
    dry_run: bool = False,
    org: str = None,
) -> list[Finding]:
    """
    Execute GitHub dork queries and return normalized Finding objects.

    Args:
        categories: List of category names to run. None = all categories.
        max_results_per_query: Cap results per query to stay within rate limits.
        dry_run: If True, print queries without executing.

    Returns:
        List of deduplicated Finding objects.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN not set in environment.")

    dorks = load_dorks()
    g = Github(token)

    if categories:
        dorks = {k: v for k, v in dorks.items() if k in categories}

    org_prefix = f"org:{org} " if org else ""

    findings: dict[str, Finding] = {}  # keyed by finding id for dedup
    total_queries = sum(len(v["queries"]) for v in dorks.values())

    console.print(f"\n[bold]IAM Exposure Research — GitHub Dorking[/bold]")
    if org:
        console.print(f"Org scope: [bold cyan]{org}[/bold cyan]")
    console.print(f"Categories: {list(dorks.keys())}")
    console.print(f"Total queries: {total_queries}")
    console.print(f"Max results/query: {max_results_per_query}\n")

    if dry_run:
        for cat, meta in dorks.items():
            console.print(f"[cyan]{cat}[/cyan]: {meta['description']}")
            for q in meta["queries"]:
                console.print(f"  → {org_prefix}{q}")
        return []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Searching...", total=total_queries)

        for category, meta in dorks.items():
            for query in meta["queries"]:
                scoped_query = f"{org_prefix}{query}"
                progress.update(task, description=f"[cyan]{category}[/cyan]: {scoped_query[:60]}...")

                try:
                    results = g.search_code(scoped_query)
                    count = 0

                    for item in results:
                        if count >= max_results_per_query:
                            break

                        repo = item.repository
                        fid = make_finding_id(repo.full_name, item.path, query)

                        if fid in findings:
                            count += 1
                            continue

                        try:
                            content = item.decoded_content.decode("utf-8", errors="replace")
                        except Exception:
                            content = "[could not decode content]"

                        finding = Finding(
                            id=fid,
                            query=query,
                            category=category,
                            repo_full_name=repo.full_name,
                            repo_url=repo.html_url,
                            file_path=item.path,
                            file_url=item.html_url,
                            snippet=redact_snippet(content),
                            repo_is_fork=repo.fork,
                            repo_stars=repo.stargazers_count,
                            repo_language=repo.language,
                            repo_created_at=repo.created_at.isoformat() if repo.created_at else "",
                            repo_pushed_at=repo.pushed_at.isoformat() if repo.pushed_at else "",
                        )
                        findings[fid] = finding
                        count += 1

                    # GitHub Search API: 30 requests/min authenticated
                    time.sleep(2.5)

                except RateLimitExceededException:
                    console.print("\n[yellow]Rate limit hit — sleeping 60s...[/yellow]")
                    time.sleep(60)
                except GithubException as e:
                    console.print(f"\n[red]GitHub error on query '{query}': {e}[/red]")
                    time.sleep(3)

                progress.advance(task)

    result_list = list(findings.values())
    console.print(f"\n[green]✓ Found {len(result_list)} unique findings across {total_queries} queries[/green]")
    return result_list
