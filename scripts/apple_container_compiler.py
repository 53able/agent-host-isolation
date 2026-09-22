#!/usr/bin/env python3
"""Compile a validated manifest into allowlisted Apple Container argv arrays."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from manifest_v2 import validate_v2


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def compile_command(manifest: dict[str, Any], action: str) -> list[str]:
    errors = validate_v2(manifest)
    if errors:
        raise ValueError("invalid manifest: " + "; ".join(errors))

    task = manifest["task"]
    task_id = task["id"]
    if action == "start":
        return ["container", "start", task_id]
    if action == "stop":
        return ["container", "stop", "--time", str(task["lifecycle"]["stop_timeout_seconds"]), task_id]
    if action == "delete":
        return ["container", "delete", task_id]
    if action == "inspect":
        return ["container", "inspect", task_id]
    if action == "logs":
        return ["container", "logs", task_id]
    if action == "boot-logs":
        return ["container", "logs", "--boot", task_id]
    if action == "stats":
        return ["container", "stats", "--format", "json", "--no-stream", task_id]
    if action == "create-scratch-volume":
        return _volume_create(manifest, "scratch")
    if action == "create-output-volume":
        return _volume_create(manifest, "output")
    if action not in {"create", "run"}:
        raise ValueError(f"unsupported action: {action}")

    workspace = manifest["workspace"]
    runtime = manifest["runtime"]
    resources = manifest["resources"]
    manifest_hash = canonical_hash(manifest)
    workspace_hash = canonical_hash(workspace)
    argv = [
        "container", action,
        "--name", task_id,
        "--read-only",
        "--cap-drop", "ALL",
        "--cpus", str(resources["cpu"]["limit"]),
        "--memory", str(resources["memory_bytes"]["limit"]),
        "--ulimit", f"nproc={resources['processes']['limit']}:{resources['processes']['limit']}",
        "--ulimit", f"nofile={resources['open_files']['limit']}:{resources['open_files']['limit']}",
        "--label", f"org.agent-host-isolation.task-id={task_id}",
        "--label", f"org.agent-host-isolation.manifest-hash={manifest_hash}",
        "--label", f"org.agent-host-isolation.workspace-hash={workspace_hash}",
        "--mount", _mount("bind", workspace["snapshot"]["source"], workspace["snapshot"]["target"], readonly=True),
        "--mount", _mount("volume", runtime["scratch"]["volume"], runtime["scratch"]["target"]),
        "--mount", _mount("volume", runtime["output"]["volume"], runtime["output"]["target"]),
        "--network", manifest["gateway"]["task_network"],
    ]
    for key in sorted(runtime["environment"]):
        argv.extend(["--env", f"{key}={runtime['environment'][key]}"])
    image = workspace["image"]
    argv.append(f"{image['reference'].split('@', 1)[0]}@{image['digest']}")
    argv.extend(task["command"])
    return argv


def _mount(kind: str, source: str, target: str, readonly: bool = False) -> str:
    parts = [f"type={kind}", f"source={source}", f"target={target}"]
    if readonly:
        parts.append("readonly")
    return ",".join(parts)


def _volume_create(manifest: dict[str, Any], name: str) -> list[str]:
    volume = manifest["runtime"][name]["volume"]
    size = manifest["resources"]["disk_bytes"]["limit"]
    if name == "output":
        size = min(size, manifest["resultGate"]["artifact_import"]["max_bytes"])
    return [
        "container", "volume", "create", "-s", str(size),
        "--label", f"org.agent-host-isolation.task-id={manifest['task']['id']}", volume,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("action", choices=(
        "create-scratch-volume", "create-output-volume", "create", "run", "start",
        "stop", "delete", "inspect", "logs", "boot-logs", "stats",
    ))
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        argv = compile_command(manifest, args.action)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
