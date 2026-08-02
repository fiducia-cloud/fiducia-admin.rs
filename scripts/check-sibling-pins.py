#!/usr/bin/env python3
"""Fail when CI and container builds compile different sibling contracts."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / "dependency-pins.json").read_text(encoding="utf-8"))

HEX_SHA = re.compile(r"^[0-9a-f]{40}$")

for repository, sha in PINS.items():
    if not isinstance(sha, str) or not HEX_SHA.fullmatch(sha):
        raise SystemExit(f"{repository}: dependency-pins.json must contain a full lowercase commit SHA")

interfaces = PINS["fiducia-interfaces"]
sync = PINS["fiducia-sync"]

contracts = {
    ".github/workflows/ci.yml": [
        rf"repository:\s*fiducia-cloud/fiducia-interfaces\s+ref:\s*{interfaces}\b",
        rf"repository:\s*fiducia-cloud/fiducia-sync\s+ref:\s*{sync}\b",
    ],
    ".github/workflows/docker.yml": [
        rf"INTERFACES_REF={interfaces}\b",
        rf"SYNC_REF={sync}\b",
    ],
    "Dockerfile": [
        rf"ARG INTERFACES_REF={interfaces}\b",
        rf"ARG SYNC_REF={sync}\b",
    ],
}

failures: list[str] = []
for relative_path, patterns in contracts.items():
    text = (ROOT / relative_path).read_text(encoding="utf-8")
    for pattern in patterns:
        if re.search(pattern, text, flags=re.MULTILINE) is None:
            failures.append(f"{relative_path}: missing synchronized pin matching {pattern}")

if failures:
    raise SystemExit("sibling dependency pin drift:\n- " + "\n- ".join(failures))

print(
    "sibling dependency pins synchronized: "
    f"fiducia-interfaces={interfaces}, fiducia-sync={sync}"
)
