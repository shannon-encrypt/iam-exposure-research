# Research Methodology

## Scope

Public GitHub repositories with no authentication or authorization restrictions. No private repositories, authenticated endpoints, or internal systems were accessed.

## Data collection

GitHub's code search API was queried using structured dork patterns targeting file extensions, keyword combinations, and known credential formats. Results were limited to 10 per query to remain within API rate limits and avoid unnecessary data collection.

## Data minimization

Raw file content was processed in-memory only. A redaction function replaced credential values with `[REDACTED]` before any content was stored or transmitted to the AI enrichment layer. The stored output (`findings.json`) contains only:
- Repository metadata (name, stars, language, creation date)
- File path and URL
- Dork query that triggered the match
- AI-generated classification (no raw content)

## AI enrichment

Claude API (claude-sonnet-4-20250514) was used to classify findings. The model was instructed to:
1. Assess likelihood that credentials are active (vs. test/example/rotated)
2. Identify the credential type and likely identity provider
3. Map to relevant MITRE ATT&CK techniques
4. Generate remediation guidance

## Responsible disclosure

- No credentials were tested, validated, or used in any way
- Repositories identified as containing likely-active credentials were reported to GitHub via their Security Advisory / Secret Scanning program
- No organization names are published in research outputs

## Limitations

- GitHub search API does not guarantee exhaustive results — findings represent a sample, not a census
- AI classification can produce false negatives (real credentials marked as test data)
- Credential validity was not verified — severity is based on structural analysis only
- Rate limiting constrains the volume of queries per session
