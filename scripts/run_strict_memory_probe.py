#!/usr/bin/env python3
"""Probe Apple Container memory enforcement without promoting isolation status."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from apple_container_compiler import canonical_hash, compile_command, require_resource_ownership
from manifest_v2 import validate_v2
from run_apple_container_smoke import build_manifest, cleanup, run, SNAPSHOT


def create_tracked_volume(manifest: dict, action: str, volume_key: str, volumes: list[str]) -> None:
    volumes.append(manifest["runtime"][volume_key]["volume"])
    run(compile_command(manifest, action))


def cleanup_volumes(manifest: dict, volumes: list[str]) -> list[str]:
    errors: list[str] = []
    for volume in volumes:
        inspected = run(["container", "volume", "inspect", volume], check=False)
        if inspected.returncode != 0:
            if "volume not found" not in inspected.stderr:
                errors.append(f"volume inspect failed: {volume}")
            continue
        try:
            labels = json.loads(inspected.stdout)[0]["configuration"]["labels"]
            require_resource_ownership(manifest, labels)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            errors.append(f"volume ownership check failed: {volume}: {exc}")
            continue
        if run(["container", "volume", "delete", volume], check=False).returncode != 0:
            errors.append(f"volume delete failed: {volume}")
    return errors


def execute() -> dict:
    worktree_status = run(["git", "status", "--short"], timeout=10).stdout.splitlines()
    if worktree_status:
        raise RuntimeError("strict-memory probe requires a clean worktree")
    task_id = f"ahi-memory-{uuid.uuid4().hex[:8]}"
    manifest = build_manifest(task_id)
    probe_script = Path(__file__).resolve()
    manifest["workspace"]["lockfile"] = {
        "path": "scripts/run_strict_memory_probe.py",
        "sha256": hashlib.sha256(probe_script.read_bytes()).hexdigest(),
    }
    manifest["task"].update({
        "attempt_id": "attempt-1",
        "strict_memory": True,
        "goal": "measure OS-enforced memory exhaustion and cleanup",
        "command": ["sh", "-ec", "trap 'cat /sys/fs/cgroup/memory.events > /output/memory-events.txt' EXIT; cat /sys/fs/cgroup/memory.max > /output/cgroup-limit.txt; awk 'BEGIN { x=\"x\"; for (i=0;i<30;i++) x=x x; print length(x) }'; echo unexpected-success > /output/after-allocation.txt"],
    })
    manifest["resources"]["memory_bytes"]["limit"] = 268435456
    errors = validate_v2(manifest)
    if errors:
        raise ValueError("invalid probe manifest: " + "; ".join(errors))
    snapshot = Path(manifest["workspace"]["snapshot"]["source"])
    evidence = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "task_id": task_id,
        "manifest": manifest,
        "manifest_hash": canonical_hash(manifest),
        "worktree_status_before": worktree_status,
        "host": {
            "macos": platform.mac_ver()[0],
            "architecture": platform.machine(),
            "container_version": run(["container", "system", "version"]).stdout.strip(),
            "system_properties": run(["container", "system", "property", "list"]).stdout.strip(),
        },
        "checks": {name: "unverified" for name in (
            "memory", "watchdog", "cleanup", "artifact_result_gate",
            "process", "disk", "log", "wall_time", "full_agent_path",
        )},
        "verification_status": "unverified",
    }
    volumes: list[str] = []
    created = False
    try:
        if snapshot.exists() or snapshot.is_symlink():
            raise RuntimeError("probe snapshot path already exists")
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.mkdir()
        for file in SNAPSHOT.iterdir():
            if not file.is_file() or file.is_symlink():
                raise RuntimeError("probe input must contain regular files only")
            (snapshot / file.name).write_bytes(file.read_bytes())
        for action, volume_key in (("create-scratch-volume", "scratch"), ("create-output-volume", "output")):
            create_tracked_volume(manifest, action, volume_key, volumes)
        created = True
        run(compile_command(manifest, "create-probe"))
        inspected = json.loads(run(compile_command(manifest, "inspect")).stdout)[0]
        labels = inspected["configuration"]["labels"]
        evidence["configured_memory_bytes"] = inspected["configuration"]["resources"]["memoryInBytes"]
        start_argv = compile_command(manifest, "start", observed_labels=labels)
        start_argv.insert(2, "--attach")
        started = run(start_argv, timeout=20, check=False)
        evidence["start_argv"] = start_argv
        evidence["start_returncode"] = started.returncode
        evidence["start_stdout"] = started.stdout.strip()
        evidence["start_stderr"] = started.stderr.strip()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            inspected = json.loads(run(compile_command(manifest, "inspect")).stdout)[0]
            if inspected.get("status", {}).get("state") != "running":
                break
            time.sleep(0.2)
        else:
            evidence["checks"]["watchdog"] = "blocked"
            raise TimeoutError("container remained running after probe deadline")
        evidence["final_status"] = inspected.get("status")
        evidence["logs"] = run(compile_command(manifest, "logs", observed_labels=labels), check=False).stdout
        pinned_image = f"{manifest['workspace']['image']['reference']}@{manifest['workspace']['image']['digest']}"
        read_argv = [
            "container", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--mount", f"type=volume,source={manifest['runtime']['output']['volume']},target=/output,readonly",
            pinned_image, "sh", "-c", "cat /output/cgroup-limit.txt; cat /output/memory-events.txt; test ! -e /output/after-allocation.txt",
        ]
        observed = run(read_argv, timeout=30, check=False)
        evidence["artifact_read_argv"] = read_argv
        evidence["artifact_read_returncode"] = observed.returncode
        observed_lines = observed.stdout.splitlines()
        evidence["cgroup_memory_max"] = observed_lines[0] if observed_lines else None
        evidence["cgroup_memory_events"] = "\n".join(observed_lines[1:])
        evidence["artifact_read_stderr"] = observed.stderr.strip()
        evidence["checks"]["memory"] = (
            "passed" if evidence["configured_memory_bytes"] == 268435456
            and evidence["cgroup_memory_max"] == "268435456"
            and started.returncode == 137
            and any(line.startswith("oom_kill ") and int(line.split()[1]) > 0 for line in observed_lines[1:])
            and observed.returncode == 0
            else "unverified"
        )
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, TimeoutError, KeyError) as exc:
        evidence["blocked_reason"] = str(exc)
        evidence["verification_status"] = "blocked"
    finally:
        try:
            evidence["cleanup_errors"] = cleanup(manifest, created, []) + cleanup_volumes(manifest, volumes)
            missing_container = run(["container", "inspect", task_id], check=False)
            evidence["container_absent"] = missing_container.returncode != 0 and "container not found" in missing_container.stderr
            evidence["volumes_absent"] = {}
            for volume in volumes:
                missing_volume = run(["container", "volume", "inspect", volume], check=False)
                evidence["volumes_absent"][volume] = missing_volume.returncode != 0 and "volume not found" in missing_volume.stderr
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, TimeoutError) as exc:
            evidence["cleanup_errors"] = [str(exc)]
            evidence["container_absent"] = False
            evidence["volumes_absent"] = {}
        if snapshot.exists() and not snapshot.is_symlink():
            for file in snapshot.iterdir():
                file.unlink()
            snapshot.rmdir()
        evidence["checks"]["cleanup"] = (
            "passed" if not evidence["cleanup_errors"] and evidence["container_absent"]
            and len(evidence["volumes_absent"]) == 2 and all(evidence["volumes_absent"].values())
            else "blocked"
        )
        if evidence["checks"]["cleanup"] == "blocked":
            evidence["verification_status"] = "blocked"
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = execute()
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, TimeoutError, KeyError) as exc:
        evidence = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "verification_status": "blocked",
            "blocked_reason": str(exc),
            "checks": {"memory": "unverified", "cleanup": "unverified"},
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.output)
    print(json.dumps({"evidence": str(args.output), "checks": evidence["checks"]}, sort_keys=True))
    return 0 if evidence["checks"]["memory"] == evidence["checks"]["cleanup"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
