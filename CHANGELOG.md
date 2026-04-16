# Changelog

## [Unreleased] - 2026-04-16

### Added
- `--org` CLI flag to scope all dork queries to a specific GitHub org (e.g. `--org example-org`)
- Org prefix (`org:<name>`) is prepended to all queries at runtime and shown in dry-run output

### Changed
- AWS dork queries now exclude `os.environ` and `os.getenv` references to reduce false positives
- `.npmrc` dork updated to exclude placeholder token patterns (`${NPM_TOKEN}`, `NPM_TOKEN`)

## [0.1.0] - Initial Release

### Added
- GitHub code search dorking across four categories: `cloud_credentials`, `okta_saml_sso`, `entra_azure_ad`, `generic_secrets`
- Claude API enrichment for findings
- `--dry-run`, `--categories`, `--max-results`, `--only-real`, `--skip-enrichment`, `--load-findings` CLI flags
- Rich terminal output with progress spinner and findings table
