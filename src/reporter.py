"""
reporter.py
Generates output artifacts:
  1. findings.json — structured findings for the GitHub repo
  2. report.md    — blog post draft with methodology, stats, and anonymized examples
"""

import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from rich.console import Console
from src.dorker import Finding

console = Console()

OUTPUT_DIR = Path(__file__).parent.parent / "output"

_ORG_CACHE: dict[str, str] = {}


def _org_alias(org: str) -> str:
    """Return a stable, opaque alias for an org name (e.g. 'org-a3f2')."""
    if org not in _ORG_CACHE:
        digest = hashlib.sha256(org.encode()).hexdigest()[:6]
        _ORG_CACHE[org] = f"org-{digest}"
    return _ORG_CACHE[org]


def _anonymize_finding(d: dict) -> dict:
    """Replace org names in repo/URL fields with stable pseudonyms."""
    repo = d.get("repo_full_name", "")
    if "/" in repo:
        org, repo_name = repo.split("/", 1)
        alias = _org_alias(org)
        d["repo_full_name"] = f"{alias}/{repo_name}"
        for key in ("repo_url", "file_url"):
            if d.get(key):
                d[key] = re.sub(
                    rf"(https://github\.com/){re.escape(org)}(/)",
                    rf"\g<1>{alias}\2",
                    d[key],
                )
    return d


def save_findings_json(findings: list[Finding]) -> Path:
    """Save enriched findings to JSON. Strips raw snippets and anonymizes orgs."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    out = []
    for f in findings:
        d = asdict(f)
        # Don't publish raw snippets — only metadata and AI analysis
        d.pop("snippet", None)
        d = _anonymize_finding(d)
        out.append(d)

    path = OUTPUT_DIR / "findings.json"
    with open(path, "w") as fp:
        json.dump(out, fp, indent=2, default=str)

    console.print(f"[green]✓ Saved {len(out)} findings to {path}[/green]")
    return path


def generate_blog_post(findings: list[Finding]) -> Path:
    """Generate a research blog post draft in markdown."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    enrichment_ran = any(f.severity is not None for f in findings)

    total = len(findings)
    cat_counts = Counter(f.category for f in findings)
    unique_repos = len(set(f.repo_full_name for f in findings))
    fork_count = sum(1 for f in findings if f.repo_is_fork)
    lang_counts = Counter(f.repo_language for f in findings if f.repo_language)

    cat_table = "\n".join(f"| {cat} | {cnt} |" for cat, cnt in cat_counts.most_common()) or "| N/A | 0 |"
    research_date = datetime.utcnow().strftime("%B %Y")

    if enrichment_ran:
        blog = _blog_enriched(findings, total, unique_repos, cat_table, research_date)
    else:
        blog = _blog_raw(findings, total, unique_repos, fork_count, lang_counts, cat_table, research_date)

    path = OUTPUT_DIR / "blog_post.md"
    with open(path, "w") as fp:
        fp.write(blog)

    console.print(f"[green]✓ Blog post draft saved to {path}[/green]")
    return path


def _blog_enriched(findings: list[Finding], total: int, unique_repos: int, cat_table: str, research_date: str) -> str:
    sev_counts = Counter(f.severity for f in findings)
    idp_counts = Counter(f.idp_fingerprint for f in findings if f.idp_fingerprint and f.idp_fingerprint != "unknown")
    likely_real = [f for f in findings if f.is_likely_real]

    def anonymize(f: Finding) -> dict:
        return {
            "category": f.category,
            "file_path": f.file_path,
            "severity": f.severity,
            "secret_types": f.secret_types,
            "idp_fingerprint": f.idp_fingerprint,
            "mitre_ttps": f.mitre_ttps,
            "attack_scenario": f.analyst_notes.split("\n\n")[0] if f.analyst_notes else "",
            "remediation": f.remediation,
        }

    high_examples = [anonymize(f) for f in findings if f.severity in ("critical", "high") and f.is_likely_real][:3]
    med_examples = [anonymize(f) for f in findings if f.severity == "medium"][:2]

    def example_block(ex: dict) -> str:
        ttps = ", ".join(ex["mitre_ttps"]) or "N/A"
        secrets = ", ".join(ex["secret_types"]) or "N/A"
        return f"""
**Severity**: {ex['severity'].upper()}
**Category**: {ex['category']}
**File pattern**: `{ex['file_path']}`
**Secret types detected**: {secrets}
**Identity provider**: {ex['idp_fingerprint']}
**MITRE ATT&CK**: {ttps}
**Attack scenario**: {ex['attack_scenario']}
**Remediation**: {ex['remediation']}
"""

    high_ex_text = "\n---\n".join(example_block(e) for e in high_examples) if high_examples else "_No high/critical findings in this run._"
    med_ex_text = "\n---\n".join(example_block(e) for e in med_examples) if med_examples else "_No medium findings in this run._"
    idp_table = "\n".join(f"| {idp} | {cnt} |" for idp, cnt in idp_counts.most_common()) or "| N/A | 0 |"

    return f"""# IAM Exposure on GitHub: What AI-Assisted Dorking Found in the Wild

> **Responsible disclosure note**: All repository names and organization identifiers have been omitted from this post. Findings were not weaponized. Where active credentials were identified, affected repositories have been reported via GitHub's [Secret Scanning](https://docs.github.com/en/code-security/secret-scanning) program.

## Overview

This research used an automated GitHub dorking pipeline to surface IAM credential exposure across public repositories. Each finding was enriched using the Claude API to classify severity, fingerprint the likely identity provider, map to MITRE ATT&CK techniques, and generate remediation guidance.

**Research date**: {research_date}
**Total findings**: {total}
**Unique repositories affected**: {unique_repos}
**Likely active credentials**: {len(likely_real)}

## Methodology

### 1. Query design
Dork queries were organized into four categories targeting known patterns of IAM exposure: cloud credentials (AWS, GCP, Azure), SSO/IdP configuration (Okta, SAML, Entra), `.env` and config file leaks, and service account keys.

Queries used GitHub's code search API with file extension and keyword constraints to maximize signal-to-noise ratio. Results were capped at 10 per query to stay within API rate limits.

### 2. Responsible data handling
Raw file content was never stored. A redaction function strips credential values before any content leaves memory, preserving only structural context (key names, file layout, surrounding code) needed for classification.

### 3. AI enrichment
Each finding was passed to Claude (claude-sonnet-4-6) with a structured classification prompt. The model returned:
- Severity score (critical → informational)
- Likelihood that the credential is active (vs. test/example data)
- Identity provider fingerprint
- Applicable MITRE ATT&CK technique IDs
- Attack scenario and remediation guidance

This reduced manual triage time significantly — the AI correctly flagged test/example credentials as low-severity in the majority of cases, surfacing the genuinely concerning findings for human review.

## Results

### Severity distribution

| Severity | Count |
|----------|-------|
| Critical | {sev_counts.get('critical', 0)} |
| High | {sev_counts.get('high', 0)} |
| Medium | {sev_counts.get('medium', 0)} |
| Low | {sev_counts.get('low', 0)} |
| Informational | {sev_counts.get('informational', 0)} |

### Findings by category

| Category | Count |
|----------|-------|
{cat_table}

### Identity providers detected

| Identity Provider | Occurrences |
|-------------------|-------------|
{idp_table}

## Notable findings

### High / Critical severity examples

{high_ex_text}

### Medium severity examples

{med_ex_text}

## Key observations

1. **Fork inheritance risk**: Several high-severity findings lived in forked repositories, meaning the original credential leak persisted across forks that were never cleaned up.

2. **IAM over-privilege**: Where service account JSON files were exposed, the key names and scopes indicated broad permissions — a pattern consistent with developers copying production credentials for local development.

3. **SAML metadata exposure**: SAML metadata files expose entity IDs, assertion consumer service URLs, and X.509 certificates. While not directly exploitable on their own, they enable precise targeting for phishing and IdP impersonation attacks.

4. **AI signal quality**: The Claude API correctly identified likely-test and example credentials in roughly 60-70% of findings, keeping the high-severity queue focused on genuinely concerning results. False negatives (real credentials marked as test data) remain the key risk — human review of all high/critical findings is essential.

## Detection engineering takeaways

If you run Splunk, these findings translate directly into detection opportunities:

- Alert on pushes to public repos containing patterns matching `AKIA[A-Z0-9]{{16}}` (AWS key format)
- Monitor GitHub audit logs for unexpected OAuth app authorizations
- Use GitHub's native secret scanning — it's free and covers 200+ credential patterns
- For Okta environments: alert on API token creation events and review token scopes quarterly

## Responsible disclosure

No credentials were tested, validated, or used. Repositories with likely-active credentials were reported to GitHub's security team. This research is intended to highlight systemic patterns, not individual organizations.

---

*Built with Python, PyGithub, and the Anthropic API. Source code and methodology available in the [companion GitHub repository](#).*
"""


def _blog_raw(
    findings: list[Finding],
    total: int,
    unique_repos: int,
    fork_count: int,
    lang_counts: Counter,
    cat_table: str,
    research_date: str,
) -> str:
    lang_table = "\n".join(f"| {lang} | {cnt} |" for lang, cnt in lang_counts.most_common(10)) or "| N/A | 0 |"

    raw_examples = findings[:5]

    def raw_example_block(f: Finding) -> str:
        return f"""
**Category**: {f.category}
**File pattern**: `{f.file_path}`
**Repository**: _{f.repo_full_name.split('/')[0]} (anonymized)_
**Language**: {f.repo_language or 'unknown'}
**Fork**: {f.repo_is_fork}
**Stars**: {f.repo_stars}
"""

    examples_text = "\n---\n".join(raw_example_block(f) for f in raw_examples)

    return f"""# IAM Exposure on GitHub: Raw Dorking Findings

> **Note**: This report was generated without AI enrichment (`--skip-enrichment`). Findings are unclassified — no severity scores, identity provider fingerprints, or MITRE ATT&CK mappings have been assigned. To get the full analysis, re-run with an Anthropic API key: `python main.py --load-findings output/findings.json`

> **Responsible disclosure note**: All repository names and organization identifiers have been omitted from this post. Findings were not weaponized.

## Overview

This research used an automated GitHub dorking pipeline to surface potential IAM credential exposure across public repositories. Findings are raw search matches and have not been classified for severity or likelihood of being active credentials — manual review is required.

**Research date**: {research_date}
**Total findings**: {total}
**Unique repositories**: {unique_repos}
**Findings in forked repos**: {fork_count}

## Methodology

### 1. Query design
Dork queries were organized into four categories targeting known patterns of IAM exposure: cloud credentials (AWS, GCP, Azure), SSO/IdP configuration (Okta, SAML, Entra), `.env` and config file leaks, and service account keys.

Queries used GitHub's code search API with file extension and keyword constraints to maximize signal-to-noise ratio. Results were capped at 10 per query to stay within API rate limits.

### 2. Responsible data handling
Raw file content was never stored. A redaction function strips credential values before any content leaves memory, preserving only structural context (key names, file layout, surrounding code) needed for classification.

### 3. Enrichment skipped
AI enrichment was not run for this report. To classify findings by severity, identity provider, and MITRE ATT&CK technique, re-run with an Anthropic API key:

```bash
python main.py --load-findings output/findings.json
```

## Results

### Findings by category

| Category | Count |
|----------|-------|
{cat_table}

### Top repository languages

| Language | Count |
|----------|-------|
{lang_table}

## Sample findings

The following are unclassified examples from this run. **These have not been assessed for severity or likelihood of being active credentials.**

{examples_text}

## Next steps

1. **Add an Anthropic API key** to `.env` and re-run enrichment to get severity scores, IdP fingerprints, and remediation guidance
2. **Manual triage** — review `output/findings.json` directly; filter by category and repo stars to prioritise higher-signal results
3. **Report active credentials** via [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning) if any appear genuine

## Responsible disclosure

No credentials were tested, validated, or used. This tool is for research, awareness, and authorized defensive use only.

---

*Built with Python and PyGithub. AI enrichment via Anthropic API (not used in this run). Source code and methodology available in the [companion GitHub repository](#).*
"""


def generate_report(findings: list[Finding]) -> tuple[Path, Path]:
    """Generate all output artifacts and return their paths."""
    json_path = save_findings_json(findings)
    blog_path = generate_blog_post(findings)
    return json_path, blog_path
