"""
trufflehog.py
TruffleHog integration for IAM exposure research.
Shells out to the locally-installed trufflehog binary, parses JSON output,
and returns Finding objects compatible with the existing enrichment pipeline.
"""

import json
import subprocess
import hashlib
from rich.console import Console
from src.dorker import Finding

console = Console()


def _run_trufflehog(args: list[str]) -> list[dict]:
    cmd = ["trufflehog"] + args + ["--json", "--no-update"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        raise RuntimeError(
            "trufflehog not found. Install from https://github.com/trufflesecurity/trufflehog"
        )

    assert proc.stdout is not None
    results = []
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            console.print(f"[yellow]TruffleHog: skipping non-JSON line: {line[:80]}[/yellow]")

    proc.wait()
    return results
