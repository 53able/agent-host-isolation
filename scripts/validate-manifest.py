#!/usr/bin/env python3
"""Validate an agent-host-isolation manifest."""

import json
import sys
from pathlib import Path

from manifest_v2 import validate_v2


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/validate-manifest.py path/to/isolation-manifest.json", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"ERROR: Manifest not found: {path}. Copy assets/isolation-manifest.template.json and fill it in.", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: Manifest is not valid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}", file=sys.stderr)
        return 2

    if data.get("manifest_version") != 2:
        print("Manifest validation FAILED:\n- manifest_version 2 is required; v1 manifests are no longer executable and must be migrated.", file=sys.stderr)
        return 1
    errors = validate_v2(data)
    if errors:
        print("Manifest validation FAILED:", file=sys.stderr)
        for item in errors:
            print(f"- {item}", file=sys.stderr)
        return 1
    print(f"Manifest validation PASSED: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
