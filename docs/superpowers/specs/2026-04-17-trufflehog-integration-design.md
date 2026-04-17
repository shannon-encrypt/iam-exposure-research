# TruffleHog Integration Design

**Date**: 2026-04-17  
**Status**: Approved

## Overview

Add TruffleHog secret scanning as a complementary discovery layer alongside the existing GitHub dorking pipeline. TruffleHog runs in two modes: as an independent source (scanning a GitHub org or specific repo directly) and as a depth scanner (scanning full git history of repos already discovered by the dorker). All TruffleHog findings flow into the existing Claude enrichment and reporting pipeline unchanged.

## Architecture

```
main.py
  ├── trufflehog.scan_source(org, repo)            ← independent mode (runs first)
  ├── dorker.run_dorks(...)                         ← existing, unchanged
  ├── deduplicate([th_independent, dork_findings])
  ├── enricher.enrich_findings(...)                 ← first enrichment pass
  ├── trufflehog.scan_repos_from_findings()        ← depth scan on enriched results (severity filter now valid)
  ├── enricher.enrich_findings(new_th_findings)    ← second enrichment pass (TH depth only)
  └── final merge + sort by severity
```

The depth scan runs **after** the first enrichment pass so that the severity filter (`low/medium/high/critical`) has valid values to filter on. New findings from the depth scan get their own enrichment pass before the final merge.

TruffleHog is invoked via subprocess, shelling out to a locally-installed `trufflehog` binary with `--json --no-update`. Output is streamed line by line and each line parsed as a JSON object.

## New Module: `src/trufflehog.py`

### Functions

**`_run_trufflehog(args: list[str]) -> list[dict]`**  
Private subprocess wrapper. Runs `trufflehog <args> --json --no-update`, streams stdout line by line, parses each line as JSON. Raises `RuntimeError` with install instructions if the binary is not found (`FileNotFoundError`). Returns a list of raw TruffleHog result dicts.

**`_to_finding(result: dict, category: str) -> Finding`**  
Converts a single TruffleHog JSON result to a `Finding` dataclass. Field mappings:

| TruffleHog field | Finding field |
|---|---|
| `DetectorName` | `secret_types` (wrapped in list) |
| `Verified` | `is_likely_real` |
| `SourceMetadata.Data.Github.repository` | `repo_url`, `repo_full_name` |
| `SourceMetadata.Data.Github.file` | `file_path` |
| `SourceMetadata.Data.Github.link` | `file_url` |
| `DetectorName` (lowercased) | `category` |

Sets `source="trufflehog"`. Repo metadata fields (`repo_stars`, `repo_language`, etc.) are left as defaults — they are not available in TruffleHog output.

**`scan_source(org: str = None, repo: str = None) -> list[Finding]`**  
Independent discovery mode. Runs one of:
- `trufflehog github --org=<org> --json --no-update` if `org` is provided
- `trufflehog git <repo> --json --no-update` if `repo` is provided
- Both if both are provided

Returns deduplicated `Finding` objects keyed on `repo + file_path + detector`.

**`scan_repos_from_findings(findings: list[Finding]) -> list[Finding]`**  
Depth scan mode. Collects unique `repo_url` values from findings where `severity` is not `None` and not `"informational"` (i.e. low/medium/high/critical). For each repo, runs `trufflehog git <repo_url> --json --no-update` to scan full git history. Deduplicates on `repo + file_path + detector`. Returns new `Finding` objects not already present in the input list.

## `Finding` Dataclass Change

Add one field:

```python
source: str = "dorker"  # "dorker" or "trufflehog"
```

This allows the reporter to break down findings by origin in the blog post and JSON output.

## `main.py` Changes

### New CLI flags

```
--trufflehog          Enable TruffleHog scanning (both independent and depth scan modes)
--repo <url>          Scan a specific repo URL with TruffleHog (implies --trufflehog)
```

### Updated orchestration

```python
th_independent: list[Finding] = []
th_depth: list[Finding] = []

# 1. Independent TruffleHog scan (before dorking)
if args.trufflehog or args.repo:
    th_independent = scan_source(org=args.org, repo=args.repo)

# 2. Dorking (existing, unchanged)
dork_findings = run_dorks(categories=args.categories, ...)

# 3. First merge: TH independent + dorker
merged = deduplicate([th_independent, dork_findings])

# 4. First enrichment pass (existing, unchanged)
enriched = enrich_findings(merged, only_real=False)

# 5. Post-enrichment depth scan (severity filter is now valid)
if args.trufflehog or args.repo:
    th_depth = scan_repos_from_findings(enriched)
    if th_depth:
        th_depth = enrich_findings(th_depth, only_real=False)

# 6. Final merge, apply only_real filter, sort by severity
all_findings = deduplicate([enriched, th_depth])
if args.only_real:
    all_findings = [f for f in all_findings if f.is_likely_real]
all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity or "informational", 4))
```

### Deduplication logic

All findings are keyed by `finding.id` (SHA256 of `repo + file_path + query/detector`). When the same file is found by both dorker and TruffleHog, the TruffleHog version wins if `is_likely_real=True`; otherwise the dorker version is kept. This preserves the richer repo metadata that dorker collects.

## Edge Cases

| Scenario | Behavior |
|---|---|
| `trufflehog` binary not installed | `RuntimeError` with message: "trufflehog not found. Install from https://github.com/trufflesecurity/trufflehog" |
| `--dry-run --trufflehog` | Prints TruffleHog commands that would run without executing, matching dorker dry-run style |
| `--load-findings --trufflehog` | Depth scan still runs on loaded findings — useful for re-scanning previously discovered repos |
| Repo with no secrets in history | Zero findings returned, no error |
| TruffleHog JSON parse error on a line | Line is skipped with a console warning; scan continues |
| `--repo` without `--org` | Single repo independent scan only; dorker still runs across all categories |

## Out of Scope

- Parallel repo scanning (sequential only for now)
- TruffleHog filesystem or S3 source types
- Suppressing already-known findings across runs (delta run feature — separate spec)
- Prompt caching and parallel enrichment improvements (separate spec)
