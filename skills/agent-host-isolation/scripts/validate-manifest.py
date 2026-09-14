#!/usr/bin/env python3
"""Validate a minimal agent-host-isolation manifest."""
import json
import sys
from pathlib import Path

REQUIRED = {"task_id", "profile", "execution_host", "input_mounts", "scratch", "network", "credentials", "host_integration", "control_sockets", "resource_limits", "result_gate", "supply_chain"}
LIMITS = {"cpu", "memory_bytes", "processes", "disk_bytes", "log_bytes", "vm_count", "wall_time_seconds"}

def error(errors, message):
    errors.append(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/validate-manifest.py path/to/isolation-manifest.json", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        print(f"ERROR: Manifest not found: {path}. Copy assets/isolation-manifest.template.json and fill it in.", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: Manifest is not valid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}", file=sys.stderr)
        return 2

    errors = []
    missing = REQUIRED - data.keys()
    if missing:
        error(errors, "Missing required keys: " + ", ".join(sorted(missing)))
    if data.get("execution_host") not in {"restricted-interpreter", "guest-vm"}:
        error(errors, "execution_host must be 'restricted-interpreter' or 'guest-vm'.")
    if data.get("profile") == "guest-build" and data.get("execution_host") != "guest-vm":
        error(errors, "guest-build requires execution_host 'guest-vm' because arbitrary binary execution needs a VM boundary.")
    for mount in data.get("input_mounts", []):
        if mount.get("read_only") is not True:
            error(errors, f"Writable host mount detected at target {mount.get('target', '<unknown>')}. Use a read-only input snapshot and guest-local scratch.")
    scratch = data.get("scratch", {})
    if scratch.get("guest_local") is not True or not isinstance(scratch.get("max_bytes"), int) or scratch.get("max_bytes", 0) <= 0:
        error(errors, "scratch must be guest_local: true with a positive integer max_bytes.")
    network = data.get("network", {})
    if network.get("default") != "deny":
        error(errors, "network.default must be 'deny'. Add narrowly scoped entries to network.allow when required.")
    if data.get("host_integration") is not False:
        error(errors, "host_integration must be false in the standard profile.")
    if data.get("control_sockets"):
        error(errors, "control_sockets must be empty. Do not pass Docker/container, SSH-agent, or other host control sockets to the execution host.")
    credentials = data.get("credentials", {})
    if credentials.get("mode") != "none" and not credentials.get("task_scoped_broker"):
        error(errors, "Credentials require task_scoped_broker: true; do not expose direct long-lived credentials to the execution host.")
    limits = data.get("resource_limits", {})
    missing_limits = LIMITS - limits.keys()
    if missing_limits:
        error(errors, "Missing resource limits: " + ", ".join(sorted(missing_limits)))
    for key in LIMITS - missing_limits:
        if key != "cpu" and (not isinstance(limits[key], int) or limits[key] <= 0):
            error(errors, f"resource_limits.{key} must be a positive integer.")
    gate = data.get("result_gate", {})
    if gate.get("required") is not True:
        error(errors, "result_gate.required must be true. Keep external writes and credential-bound operations outside the guest.")
    supply = data.get("supply_chain", {})
    if not supply.get("image_digest") or str(supply.get("image_digest")).startswith("replace-with"):
        error(errors, "supply_chain.image_digest must name an immutable image digest.")

    if errors:
        print("Manifest validation FAILED:", file=sys.stderr)
        for item in errors:
            print(f"- {item}", file=sys.stderr)
        return 1
    print(f"Manifest validation PASSED: {path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
