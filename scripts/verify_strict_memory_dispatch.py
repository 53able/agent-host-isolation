#!/usr/bin/env python3
"""Exercise the guest-build command path and record auto-dispatch prerequisites."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from guest_build_runner import run_guest_build
from run_apple_container_smoke import SNAPSHOT, build_manifest, run


CASES = {
    "full_agent_path": (["sh", "-c", "printf passed > /output/result.txt"], 10, 1_048_576, ["/output/result.txt"]),
    "wall_time": (["sh", "-c", "sleep 10"], 2, 1_048_576, []),
    "log": (["sh", "-c", "yes x"], 5, 32_768, []),
    "disk": (["sh", "-c", "if dd if=/dev/zero of=/scratch/big bs=1M count=40; then echo disk-limit-bypassed; exit 3; else echo disk-limit-denied; fi"], 5, 1_048_576, []),
    "process": (["sh", "-c", "n=0; for i in $(seq 1 40); do sleep 2 & kill -0 $! && n=$((n+1)); done; echo spawned:$n; if [ $n -lt 40 ]; then echo process-limit-denied; exit 0; else echo process-limit-bypassed; exit 3; fi"], 5, 1_048_576, []),
    "artifact_result_gate": (["sh", "-c", "ln -s /workspace/allowed.txt /output/result.txt"], 5, 1_048_576, ["/output/result.txt"]),
}


def execute(memory_evidence: Path) -> dict:
    status_before = run(["git", "status", "--short"], timeout=10).stdout.splitlines()
    record = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": run(["git", "rev-parse", "HEAD"], timeout=10).stdout.strip(),
        "worktree_status_before": status_before,
        "runner_sha256": hashlib.sha256((Path(__file__).parent / "guest_build_runner.py").read_bytes()).hexdigest(),
        "host": {
            "macos": platform.mac_ver()[0],
            "architecture": platform.machine(),
            "container_version": run(["container", "system", "version"], timeout=10).stdout.strip(),
        },
        "checks": {key: "unverified" for key in (
            *CASES, "memory", "cleanup", "watchdog", "open_files", "cpu", "vm_count",
            "mount", "credential", "network", "command_path", "supply_chain", "side_effect", "resource",
        )},
        "cases": {},
    }
    memory = json.loads(memory_evidence.read_text())
    record["memory_evidence_sha256"] = hashlib.sha256(memory_evidence.read_bytes()).hexdigest()
    memory_ok = (
        memory.get("worktree_status_before") == []
        and memory.get("manifest", {}).get("workspace", {}).get("repository", {}).get("commit") == record["source_commit"]
        and memory.get("host", {}).get("macos") == record["host"]["macos"]
        and memory.get("host", {}).get("architecture") == record["host"]["architecture"]
        and memory.get("host", {}).get("container_version") == record["host"]["container_version"]
        and memory.get("checks", {}).get("memory") == "passed"
        and memory.get("checks", {}).get("cleanup") == "passed"
    )
    record["checks"]["memory"] = "passed" if memory_ok else "blocked"
    for case, (command, wall_seconds, log_bytes, artifacts) in CASES.items():
        task_id = f"ahi-verify-{case.replace('_', '-')[:8]}-{uuid.uuid4().hex[:7]}"
        manifest = build_manifest(task_id)
        manifest["task"].update(strict_memory=True, command=command, expected_artifacts=artifacts)
        manifest["resources"]["wall_time_seconds"]["limit"] = wall_seconds
        manifest["resources"]["log_bytes"]["limit"] = log_bytes
        if case == "full_agent_path":
            record["tested_profile"] = {
                "image": manifest["workspace"]["image"],
                "resources": manifest["resources"],
            }
        snapshot = Path(manifest["workspace"]["snapshot"]["source"])
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SNAPSHOT, snapshot)
        try:
            with tempfile.TemporaryDirectory(prefix="ahi-verify-import-") as temporary:
                destination = Path(temporary) / "imported"
                outcome = run_guest_build(manifest, destination)
                artifact_ok = case == "full_agent_path" and (destination / "result.txt").is_file() and (destination / "result.txt").read_bytes() == b"passed"
        finally:
            shutil.rmtree(snapshot)
        record["cases"][case] = {"manifest_hash": outcome["manifest_hash"], "outcome": outcome}
        clean = not outcome["cleanup_errors"] and outcome.get("container_absent") and len(outcome.get("volumes_absent", {})) == 2 and all(outcome["volumes_absent"].values())
        if not clean:
            record["checks"]["cleanup"] = "blocked"
        if case == "full_agent_path":
            passed = outcome["status"] == "passed" and artifact_ok
        elif case in {"wall_time", "log"}:
            expected = "host wall-time limit exceeded" if case == "wall_time" else "host output limit exceeded"
            passed = outcome.get("watchdog_violation") == expected and outcome["status"] == "blocked"
        elif case == "artifact_result_gate":
            passed = outcome["status"] == "blocked" and "non-regular file" in outcome.get("error", "")
        elif case == "disk":
            passed = outcome["status"] == "passed" and "disk-limit-denied" in outcome.get("stdout", "") and "No space left" in outcome.get("stderr", "")
        else:
            passed = outcome["status"] == "passed" and "process-limit-denied" in outcome.get("stdout", "") and "process-limit-bypassed" not in outcome.get("stdout", "")
        record["checks"][case] = "passed" if passed and clean else "blocked"
    if record["checks"]["cleanup"] != "blocked":
        record["checks"]["cleanup"] = "passed"
    record["checks"]["watchdog"] = "passed" if record["checks"]["wall_time"] == record["checks"]["log"] == "passed" else "blocked"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--memory-evidence", type=Path, required=True)
    args = parser.parse_args()
    record = execute(args.memory_evidence)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, args.output)
    print(json.dumps({"checks": record["checks"], "evidence": str(args.output)}, sort_keys=True))
    return 0 if all(value == "passed" for value in record["checks"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
