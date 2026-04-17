#!/usr/bin/env python3
"""
main.py - IAM Exposure Research Tool CLI entrypoint.

Usage:
  python main.py --dry-run
  python main.py --categories cloud_credentials okta_saml_sso
  python main.py --max-results 5
  python main.py --only-real
  python main.py
"""

import argparse
import json
import sys
from rich.console import Console
from dotenv import load_dotenv

load_dotenv()
console = Console()


def parse_args():
    parser = argparse.ArgumentParser(description="IAM Exposure Research — GitHub dorking + Claude AI enrichment")
    parser.add_argument("--categories", nargs="+", help="Categories to run (default: all)")
    parser.add_argument("--max-results", type=int, default=10, help="Max results per query (default: 10)")
    parser.add_argument("--dry-run", action="store_true", help="Print queries without executing")
    parser.add_argument("--only-real", action="store_true", help="Only include likely-active credentials")
    parser.add_argument("--skip-enrichment", action="store_true", help="Skip Claude API enrichment")
    parser.add_argument("--load-findings", type=str, help="Load existing findings.json")
    parser.add_argument("--org", type=str, help="Scope all dork queries to a GitHub org (e.g. braze-inc)")
    parser.add_argument("--trufflehog", action="store_true", help="Enable TruffleHog scanning (independent + depth scan)")
    parser.add_argument("--repo", type=str, help="Scan a specific repo URL with TruffleHog (implies --trufflehog)")
    return parser.parse_args()


def deduplicate(finding_lists: list) -> list:
    seen = {}
    for findings in finding_lists:
        for f in findings:
            if f.id not in seen:
                seen[f.id] = f
            else:
                existing = seen[f.id]
                if f.source == "trufflehog" and f.is_likely_real and not existing.is_likely_real:
                    seen[f.id] = f
    return list(seen.values())


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


if __name__ == "__main__":
    main()
