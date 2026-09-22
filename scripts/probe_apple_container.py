#!/usr/bin/env python3
"""Collect non-mutating host evidence for an Apple Container manifest."""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from apple_container_compiler import canonical_hash
from manifest_v2 import validate_v2

REQUIRED_CREATE_OPTIONS = {
    "--read-only", "--cap-drop", "--cpus", "--memory", "--ulimit", "--label",
    "--mount", "--network", "--env",
}


def _run(argv: list[str]) -> tuple[int, str]:
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    return result.returncode, (result.stdout + result.stderr).strip()


def _version(value: str) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+){1,2}", value)
    return tuple(int(part) for part in match.group().split(".")) if match else ()


def probe(manifest: dict) -> dict:
    errors = validate_v2(manifest)
    if errors:
        raise ValueError("invalid manifest: " + "; ".join(errors))
    runtime = manifest["runtime"]
    evidence = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "task_id": manifest["task"]["id"],
        "manifest_hash": canonical_hash(manifest),
        "workspace_hash": canonical_hash(manifest["workspace"]),
        "architecture": platform.machine(),
        "verification_status": "unverified",
        "blocked_reasons": [],
    }

    code, macos = _run(["sw_vers", "-productVersion"])
    evidence["macos_version"] = macos if code == 0 else None
    if code != 0 or _version(macos) < _version(runtime["minimum_macos_version"]):
        evidence["blocked_reasons"].append("minimum macOS version is not satisfied")

    code, system_version = _run(["container", "system", "version"])
    evidence["container_system_version"] = system_version if code == 0 else None
    if code != 0 or _version(system_version) < _version(runtime["minimum_version"]):
        evidence["blocked_reasons"].append("minimum Apple Container version is not satisfied")

    code, help_text = _run(["container", "create", "--help"])
    missing_options = sorted(option for option in REQUIRED_CREATE_OPTIONS if option not in help_text)
    evidence["missing_required_create_options"] = missing_options
    if code != 0 or missing_options:
        evidence["blocked_reasons"].append("required Apple Container create options are unavailable")

    code, service_status = _run(["container", "system", "status"])
    evidence["service_status"] = service_status
    if code != 0 or "not running" in service_status.lower():
        evidence["blocked_reasons"].append("Apple Container services are not running")

    code, properties = _run(["container", "system", "property", "list"])
    evidence["system_properties"] = properties if code == 0 else None
    if code != 0:
        evidence["blocked_reasons"].append("kernel image and system properties could not be recorded")

    evidence["readiness"] = "blocked" if evidence["blocked_reasons"] else "ready for adversarial tests"
    return evidence


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/probe_apple_container.py path/to/isolation-manifest.json", file=sys.stderr)
        return 2
    try:
        manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        evidence = probe(manifest)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence["readiness"] != "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
