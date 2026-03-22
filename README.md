# IAM Exposure Research Tool

AI-assisted GitHub dorking pipeline for surfacing IAM credential and identity provider exposure in public repositories.

## What it does

1. **Dorking** — Executes categorized GitHub search queries targeting exposed cloud credentials, SSO configs, SAML metadata, and `.env` leaks
2. **AI enrichment** — Passes each finding (with values redacted) to Claude API for severity scoring, IdP fingerprinting, MITRE ATT&CK mapping, and remediation generation
3. **Reporting** — Outputs `findings.json` and a `blog_post.md` research write-up

## Setup

```bash
git clone <this-repo>
cd iam-exposure-research
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Fill in GITHUB_TOKEN and ANTHROPIC_API_KEY
```

### GitHub token requirements
- Fine-grained personal access token
- Scopes needed: `public_repo` (read-only), no write permissions required

## Usage

```bash
# Preview all queries without executing
python main.py --dry-run

# Run specific categories only
python main.py --categories cloud_credentials okta_saml_sso

# Full run, only surface likely-real credentials
python main.py --only-real

# Full run, all categories
python main.py

# Re-enrich existing findings without re-running dorks
python main.py --load-findings output/findings.json
```

## Dork categories

| Category | Description |
|----------|-------------|
| `cloud_credentials` | AWS keys, GCP service account JSON, Azure client secrets |
| `okta_saml_sso` | Okta API tokens, SAML metadata, SSWS tokens |
| `entra_azure_ad` | Microsoft Entra / Azure AD credentials |
| `generic_secrets` | .env files, config.yml, npmrc, dockercfg |

## Responsible use

- No credentials are stored, tested, or validated
- Raw file content is redacted before AI processing
- Findings with likely-active credentials should be reported via [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- This tool is for research and awareness, not exploitation

## Output

- `output/findings.json` — Structured findings with AI analysis (no raw secrets)
- `output/blog_post.md` — Research write-up draft with anonymized examples

## Methodology

See `docs/methodology.md` for full research methodology and responsible disclosure approach.
