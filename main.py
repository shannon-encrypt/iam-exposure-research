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
    return parser.parse_args()


def main():
    args = parse_args()
    console.rule("[bold blue]IAM Exposure Research Tool[/bold blue]")

    if args.load_findings:
        from src.dorker import Finding
        from dataclasses import fields
        with open(args.load_findings) as f:
            raw = json.load(f)
        finding_fields = {field.name for field in fields(Finding)}
        findings = [Finding(**{k: v for k, v in item.items() if k in finding_fields}) for item in raw]
        console.print(f"[green]Loaded {len(findings)} findings[/green]")
    else:
        from src.dorker import run_dorks
        findings = run_dorks(categories=args.categories, max_results_per_query=args.max_results, dry_run=args.dry_run, org=args.org)
        if args.dry_run:
            sys.exit(0)

    if not findings:
        console.print("[yellow]No findings.[/yellow]")
        sys.exit(0)

    if not args.skip_enrichment:
        from src.enricher import enrich_findings
        findings = enrich_findings(findings, only_real=args.only_real)

    from src.reporter import generate_report
    json_path, blog_path = generate_report(findings)

    console.rule("[bold green]Complete[/bold green]")
    console.print(f"  Findings JSON : {json_path}")
    console.print(f"  Blog post     : {blog_path}")


if __name__ == "__main__":
    main()
