#!/usr/bin/env python3
"""Compile a validated manifest into allowlisted Apple Container argv arrays."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from manifest_v2 import SNAPSHOT_ROOT, validate_v2


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def expected_labels(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        "org.agent-host-isolation.task-id": manifest["task"]["id"],
        "org.agent-host-isolation.manifest-hash": canonical_hash(manifest),
        "org.agent-host-isolation.workspace-hash": canonical_hash(manifest["workspace"]),
    }


def require_resource_ownership(manifest: dict[str, Any], observed_labels: dict[str, Any] | None) -> None:
    if not isinstance(observed_labels, dict):
        raise ValueError("resource ownership labels are required before operating on an existing resource")
    for key, expected in expected_labels(manifest).items():
        if observed_labels.get(key) != expected:
            raise ValueError(f"resource ownership mismatch for label {key}")


def require_network_attestation(manifest: dict[str, Any], attestation: dict[str, Any] | None) -> None:
    grants = manifest["gateway"]["grants"]
    if not grants:
        return
    gateway = manifest["gateway"]["egress_gateway"]
    expected = {
        "task_id": manifest["task"]["id"],
        "manifest_hash": canonical_hash(manifest),
        "network": manifest["gateway"]["task_network"],
        "gateway_id": gateway["id"],
        "policy_hash": gateway["policy_hash"],
        "default": "deny",
    }
    if not isinstance(attestation, dict) or any(attestation.get(key) != value for key, value in expected.items()):
        raise ValueError("a matching host-issued default-deny gateway attestation is required")


def require_snapshot_source(manifest: dict[str, Any]) -> None:
    source = Path(manifest["workspace"]["snapshot"]["source"])
    trusted_root = Path(SNAPSHOT_ROOT)
    try:
        resolved_root = trusted_root.resolve(strict=True)
        resolved_source = source.resolve(strict=True)
        resolved_source.relative_to(resolved_root)
    except (FileNotFoundError, ValueError) as exc:
        raise ValueError("snapshot source must exist beneath the trusted snapshot root") from exc
    if not resolved_source.is_dir():
        raise ValueError("snapshot source must be a directory")
    current = source
    while current != trusted_root:
        if current.is_symlink():
            raise ValueError("snapshot source path must not contain symlinks")
        current = current.parent
    for root, directories, files in os.walk(resolved_source, followlinks=False):
        root_path = Path(root)
        for name in directories + files:
            candidate = root_path / name
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ValueError("snapshot contents must not contain symlinks")
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError("snapshot contents must contain only directories and regular files")


def compile_command(
    manifest: dict[str, Any],
    action: str,
    *,
    observed_labels: dict[str, Any] | None = None,
    network_attestation: dict[str, Any] | None = None,
) -> list[str]:
    errors = validate_v2(manifest)
    if errors:
        raise ValueError("invalid manifest: " + "; ".join(errors))

    task = manifest["task"]
    task_id = task["id"]
    existing_resource_actions = {"start", "stop", "delete", "logs", "boot-logs", "stats"}
    if action in existing_resource_actions:
        require_resource_ownership(manifest, observed_labels)
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

    require_snapshot_source(manifest)
    require_network_attestation(manifest, network_attestation)

    workspace = manifest["workspace"]
    runtime = manifest["runtime"]
    resources = manifest["resources"]
    labels = expected_labels(manifest)
    argv = [
        "container", action,
        "--name", task_id,
        "--read-only",
        "--cap-drop", "ALL",
        "--cpus", str(resources["cpu"]["limit"]),
        "--memory", str(resources["memory_bytes"]["limit"]),
        "--ulimit", f"nproc={resources['processes']['limit']}:{resources['processes']['limit']}",
        "--ulimit", f"nofile={resources['open_files']['limit']}:{resources['open_files']['limit']}",
        "--label", f"org.agent-host-isolation.task-id={labels['org.agent-host-isolation.task-id']}",
        "--label", f"org.agent-host-isolation.manifest-hash={labels['org.agent-host-isolation.manifest-hash']}",
        "--label", f"org.agent-host-isolation.workspace-hash={labels['org.agent-host-isolation.workspace-hash']}",
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
    argv = ["container", "volume", "create", "-s", str(size)]
    for key, value in expected_labels(manifest).items():
        argv.extend(["--label", f"{key}={value}"])
    argv.append(volume)
    return argv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("action", choices=(
        "create-scratch-volume", "create-output-volume", "create", "run", "start",
        "stop", "delete", "inspect", "logs", "boot-logs", "stats",
    ))
    parser.add_argument("--resource-labels", type=Path)
    parser.add_argument("--network-attestation", type=Path)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        labels = json.loads(args.resource_labels.read_text(encoding="utf-8")) if args.resource_labels else None
        attestation = json.loads(args.network_attestation.read_text(encoding="utf-8")) if args.network_attestation else None
        argv = compile_command(
            manifest,
            args.action,
            observed_labels=labels,
            network_attestation=attestation,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
