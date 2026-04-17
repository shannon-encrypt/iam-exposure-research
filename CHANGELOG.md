# Changelog

## [Unreleased] - 2026-04-17

### Added
- `--trufflehog` flag: enables TruffleHog scanning in two modes
  - Independent scan: runs `trufflehog github --org` or `trufflehog git <repo>` before dorking
  - Depth scan: runs `trufflehog git` on all non-informational repos after first enrichment pass
- `--repo <url>` flag: scan a single repo with TruffleHog (implies `--trufflehog`)
- `source` field on `Finding` dataclass (`"dorker"` or `"trufflehog"`) for origin tracking
- Two-pass enrichment: independent+dorker findings enriched first, TruffleHog depth findings enriched separately

### Changed
- AWS dork queries now exclude `os.environ` and `os.getenv` references to reduce false positives
- `.npmrc` dork updated to exclude placeholder token patterns (`${NPM_TOKEN}`, `NPM_TOKEN`)

## [0.1.0] - Initial Release

### Added
- GitHub code search dorking across four categories: `cloud_credentials`, `okta_saml_sso`, `entra_azure_ad`, `generic_secrets`
- Claude API enrichment for findings
- `--dry-run`, `--categories`, `--max-results`, `--only-real`, `--skip-enrichment`, `--load-findings` CLI flags
- Rich terminal output with progress spinner and findings table
