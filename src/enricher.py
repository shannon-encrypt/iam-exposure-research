"""
enricher.py
AI enrichment layer using Claude API.
Takes raw Finding objects and populates severity, IdP fingerprint,
MITRE TTPs, remediation, and likelihood scoring.
"""

import os
import json
import time
from anthropic import Anthropic
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv
from src.dorker import Finding

load_dotenv()
console = Console()

client = Anthropic()

SYSTEM_PROMPT = """You are a senior cloud security researcher specializing in IAM and identity exposure analysis.
You analyze GitHub code snippets that may contain exposed credentials, secrets, or misconfigured identity provider settings.

Your job is to classify each finding with precision and honesty. Many findings will be test data, examples, or already-rotated credentials — say so when that's likely.

Always respond with valid JSON only. No preamble, no markdown fences."""

CLASSIFICATION_PROMPT = """Analyze this GitHub finding and return a JSON object with the following fields:

Finding details:
- Category: {category}
- Query that found it: {query}
- Repository: {repo_full_name} (stars: {stars}, fork: {is_fork}, language: {language})
- File path: {file_path}
- Snippet (values redacted):
{snippet}

Return JSON with exactly these fields:
{{
  "severity": "critical|high|medium|low|informational",
  "is_likely_real": true|false,
  "confidence": "high|medium|low",
  "secret_types": ["list of secret/credential types detected, e.g. AWS_ACCESS_KEY, OKTA_API_TOKEN, SAML_METADATA"],
  "idp_fingerprint": "primary identity provider if detectable, e.g. Okta, Microsoft Entra, AWS IAM, GCP, generic",
  "mitre_ttps": ["relevant ATT&CK technique IDs, e.g. T1552.001, T1078"],
  "attack_scenario": "1-2 sentence description of how this could be exploited",
  "remediation": "Concrete remediation steps, 2-3 sentences",
  "analyst_notes": "Notes on why this might be a false positive, test data, or otherwise low risk. Be specific."
}}

Severity guidance:
- critical: Active, likely-real credential for a cloud/IdP root or admin account
- high: Active credential with significant access scope (IAM, SSO, cloud service account)
- medium: Credential of unknown validity, limited scope, or partial exposure
- low: Likely rotated, example, or test credential
- informational: Config exposure with no direct secret material"""


def enrich_finding(finding: Finding, max_retries: int = 3) -> Finding:
    """Send a single finding to Claude API for enrichment."""
    prompt = CLASSIFICATION_PROMPT.format(
        category=finding.category,
        query=finding.query,
        repo_full_name=finding.repo_full_name,
        stars=finding.repo_stars,
        is_fork=finding.repo_is_fork,
        language=finding.repo_language or "unknown",
        file_path=finding.file_path,
        snippet=finding.snippet or "[no content]",
    )

    for attempt in range(max_retries):
        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            raw = response.content[0].text.strip()
            # Strip markdown fences if model adds them despite instructions
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            data = json.loads(raw)

            finding.severity = data.get("severity", "informational")
            finding.is_likely_real = data.get("is_likely_real", False)
            finding.secret_types = data.get("secret_types", [])
            finding.idp_fingerprint = data.get("idp_fingerprint", "unknown")
            finding.mitre_ttps = data.get("mitre_ttps", [])
            finding.remediation = data.get("remediation", "")
            finding.analyst_notes = data.get("analyst_notes", "")

            # Attach attack scenario to notes if present
            if data.get("attack_scenario"):
                finding.analyst_notes = f"Attack scenario: {data['attack_scenario']}\n\n{finding.analyst_notes}"

            return finding

        except json.JSONDecodeError as e:
            console.print(f"[yellow]JSON parse error on attempt {attempt+1}: {e}[/yellow]")
            time.sleep(2)
        except Exception as e:
            console.print(f"[red]Enrichment error on attempt {attempt+1}: {e}[/red]")
            time.sleep(5)

    # If all retries fail, mark as unclassified
    finding.severity = "informational"
    finding.analyst_notes = "Enrichment failed after retries."
    return finding


def enrich_findings(
    findings: list[Finding],
    only_real: bool = False,
    delay_seconds: float = 0.5,
) -> list[Finding]:
    """
    Enrich a list of findings with AI classification.

    Args:
        findings: Raw Finding objects from dorker.
        only_real: If True, only return findings where is_likely_real=True.
        delay_seconds: Pause between API calls to avoid rate limits.

    Returns:
        Enriched Finding objects sorted by severity.
    """
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

    console.print(f"\n[bold]Enriching {len(findings)} findings via Claude API...[/bold]\n")
    enriched = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Classifying...", total=len(findings))

        for i, finding in enumerate(findings):
            progress.update(task, description=f"[purple]{i+1}/{len(findings)}[/purple] {finding.repo_full_name}/{finding.file_path[:40]}")
            enriched_finding = enrich_finding(finding)
            enriched.append(enriched_finding)
            time.sleep(delay_seconds)
            progress.advance(task)

    if only_real:
        enriched = [f for f in enriched if f.is_likely_real]
        console.print(f"[yellow]Filtered to {len(enriched)} likely-real findings[/yellow]")

    enriched.sort(key=lambda f: SEVERITY_ORDER.get(f.severity or "informational", 4))

    # Summary stats
    from collections import Counter
    sev_counts = Counter(f.severity for f in enriched)
    console.print("\n[bold]Enrichment complete — severity breakdown:[/bold]")
    for sev in ["critical", "high", "medium", "low", "informational"]:
        count = sev_counts.get(sev, 0)
        if count:
            color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green", "informational": "white"}.get(sev, "white")
            console.print(f"  [{color}]{sev.upper():15}[/{color}] {count}")

    return enriched
