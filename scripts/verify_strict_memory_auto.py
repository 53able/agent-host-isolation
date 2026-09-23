#!/usr/bin/env python3
"""Verify one controller-issued strict-memory event through automatic artifact import."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from run_apple_container_smoke import build_manifest, run
from strict_memory_dispatch import IMPORT_ROOT, dispatch

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_CONTENT = b"allowed snapshot content\n"
ISSUE_EVENT = """
import { createInspectRuntime, blockInspectForStrictMemory } from './scripts/just_bash_runtime.mjs';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const { manifest, snapshotFiles } = JSON.parse(input);
const runtime = createInspectRuntime({ manifest, snapshotFiles });
const event = await blockInspectForStrictMemory({ runtime });
process.stdout.write(JSON.stringify(event));
"""


def execute() -> dict:
    status_before = run(["git", "status", "--short"], timeout=10).stdout.splitlines()
    if status_before:
        raise RuntimeError("automatic-path verification requires a clean worktree")
    commit = run(["git", "rev-parse", "HEAD"], timeout=10).stdout.strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], timeout=10).stdout.strip()
    task_id = f"ahi-auto-{uuid.uuid4().hex[:8]}"
    source = json.loads((ROOT / "validation" / "just-bash" / "manifest.json").read_text())
    source["task"].update(id=task_id, attempt_id=f"attempt-{uuid.uuid4().hex[:8]}",
                          goal="verify controller-issued strict-memory automatic dispatch")
    source["workspace"]["repository"].update(commit=commit, tree_hash=tree)
    issued = subprocess.run(["node", "--input-type=module", "-e", ISSUE_EVENT], cwd=ROOT,
                            input=json.dumps({"manifest": source, "snapshotFiles": {"allowed.txt": SNAPSHOT_CONTENT.decode()}}),
                            capture_output=True, text=True, timeout=15, check=True)
    event = json.loads(issued.stdout)
    target = build_manifest(task_id)
    target["task"].update(attempt_id=f"attempt-{uuid.uuid4().hex[:8]}", goal=source["task"]["goal"],
                          strict_memory=True, command=["sh", "-c", "cat /workspace/allowed.txt > /output/result.txt"],
                          expected_artifacts=["/output/result.txt"])
    target["workspace"]["repository"] = source["workspace"]["repository"]
    target["resources"]["disk_bytes"]["enforced_by"] = "apple-container-tmpfs"
    target["resources"]["wall_time_seconds"]["limit"] = 10
    with tempfile.TemporaryDirectory(prefix="ahi-auto-source-") as temporary:
        source_dir = Path(temporary)
        (source_dir / "allowed.txt").write_bytes(SNAPSHOT_CONTENT)
        outcome = dispatch(source, event, target, source_dir)
    destination = IMPORT_ROOT / task_id / target["task"]["attempt_id"]
    artifact = destination / "result.txt"
    imported = artifact.is_file() and artifact.read_bytes() == SNAPSHOT_CONTENT
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": commit,
        "worktree_status_before": status_before,
        "source_attempt_id": source["task"]["attempt_id"],
        "target_attempt_id": target["task"]["attempt_id"],
        "task_id": task_id,
        "controller_event": {"event": event["event"], "missing_capability": event["missing_capability"],
                             "outcome": event["outcome"], "source": event["source"]},
        "dispatch_status": outcome["status"],
        "automatic": outcome["automatic"],
        "verification_checks": outcome.get("verification_checks"),
        "guest_result": outcome.get("guest_result"),
        "blocked_reasons": outcome.get("blocked_reasons"),
        "artifact_imported": imported,
        "artifact_sha256": "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest() if imported else None,
        "artifact_destination": str(destination),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        record = execute()
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        record = {"captured_at": datetime.now(timezone.utc).isoformat(), "dispatch_status": "blocked",
                  "automatic": False, "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, args.output)
    print(json.dumps({"dispatch_status": record["dispatch_status"], "automatic": record["automatic"],
                      "artifact_imported": record.get("artifact_imported"), "output": str(args.output)}, sort_keys=True))
    return 0 if record["dispatch_status"] == "passed" and record["automatic"] and record.get("artifact_imported") else 1


if __name__ == "__main__":
    raise SystemExit(main())
