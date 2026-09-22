#!/usr/bin/env python3
"""Run a bounded Apple Container denial smoke test and emit JSON evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apple_container_compiler import canonical_hash, compile_command

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "assets" / "isolation-manifest.template.json"
SNAPSHOT = ROOT / "validation" / "apple-container" / "input"
IMAGE = "docker.io/library/alpine:3.22"
EXPECTED_MARKERS = {
    "rootfs-denied", "workspace-write-denied", "host-home-hidden",
    "ssh-agent-hidden", "control-socket-hidden", "network-loopback-only",
    "internet-egress-denied", "host-gateway-denied", "capabilities-dropped",
    "artifact-written", "ahi-smoke-pass",
}


def run(argv: list[str], *, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {argv[:3]}: {result.stderr.strip()}")
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def image_digest() -> str:
    inspected = json.loads(run(["container", "image", "inspect", IMAGE]).stdout)
    return inspected[0]["configuration"]["descriptor"]["digest"]


def build_manifest(task_id: str) -> dict[str, Any]:
    manifest = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    commit = run(["git", "rev-parse", "HEAD"], timeout=10).stdout.strip()
    tree_hash = run(["git", "rev-parse", "HEAD^{tree}"], timeout=10).stdout.strip()
    manifest["task"].update({
        "id": task_id,
        "goal": "verify Apple Container denial controls on the recorded host",
        "command": ["sh", "-c", probe_script()],
        "expected_artifacts": ["/output/result.txt"],
        "lifecycle": {"stop_timeout_seconds": 2, "checkpoint": "disabled"},
    })
    manifest["workspace"]["repository"].update({
        "url": "https://github.com/53able/agent-host-isolation.git",
        "commit": commit,
        "tree_hash": tree_hash,
    })
    manifest["workspace"]["snapshot"].update({
        "id": f"{task_id}-input",
        "source": f"/var/tmp/agent-host-isolation/snapshots/{task_id}-input",
    })
    manifest["workspace"]["image"] = {"reference": IMAGE, "digest": image_digest()}
    manifest["workspace"]["toolchain"] = {
        "python": platform.python_version(),
        "apple-container": run(["container", "--version"], timeout=10).stdout.strip(),
    }
    manifest["workspace"]["lockfile"] = {
        "path": "scripts/run_apple_container_smoke.py",
        "sha256": sha256_file(Path(__file__).resolve()),
    }
    manifest["workspace"]["skills"] = [{"id": "agent-host-isolation", "version": commit}]
    manifest["gateway"].update({"task_network": "none", "grants": []})
    manifest["model"].update({"provider": "none", "id": "none"})
    manifest["runtime"]["scratch"]["volume"] = f"{task_id}-scratch"
    manifest["runtime"]["output"]["volume"] = f"{task_id}-output"
    manifest["resources"].update({
        "cpu": {"limit": 1, "enforced_by": "apple-container", "on_exceed": "throttle"},
        "memory_bytes": {"limit": 268435456, "enforced_by": "apple-container", "on_exceed": "terminate"},
        "disk_bytes": {"limit": 16777216, "enforced_by": "apple-container-volume", "on_exceed": "block"},
        "processes": {"limit": 32, "enforced_by": "guest-ulimit", "on_exceed": "block"},
        "open_files": {"limit": 64, "enforced_by": "guest-ulimit", "on_exceed": "block"},
        "log_bytes": {"limit": 1048576, "enforced_by": "host-watchdog", "on_exceed": "terminate"},
        "vm_count": {"limit": 1, "enforced_by": "host-scheduler", "on_exceed": "block"},
        "wall_time_seconds": {"limit": 20, "enforced_by": "host-watchdog", "on_exceed": "terminate"},
    })
    manifest["resultGate"].update({
        "artifact_import": {
            "source": "/output", "max_bytes": 1048576,
            "reject_symlinks": True, "reject_path_traversal": True,
        },
        "audit_record": f"evidence/{task_id}.json",
    })
    return manifest


def probe_script() -> str:
    return r'''set -u
failed=0
if touch /rootfs-write-probe 2>/dev/null; then echo rootfs-writable; failed=1; else echo rootfs-denied; fi
if touch /workspace/write-probe 2>/dev/null; then echo workspace-writable; failed=1; else echo workspace-write-denied; fi
if [ -e /Users ]; then echo host-home-visible; failed=1; else echo host-home-hidden; fi
if [ -n "${SSH_AUTH_SOCK:-}" ] || [ -S /run/host-services/ssh-auth.sock ]; then echo ssh-agent-visible; failed=1; else echo ssh-agent-hidden; fi
if [ -S /var/run/docker.sock ] || [ -S /run/containerd/containerd.sock ]; then echo control-socket-visible; failed=1; else echo control-socket-hidden; fi
interfaces="$(ls /sys/class/net | tr '\n' ' ')"
if [ "$interfaces" = "lo " ]; then echo network-loopback-only; else echo "unexpected-interfaces:$interfaces"; failed=1; fi
if wget -T 2 -qO- http://1.1.1.1 >/dev/null 2>&1; then echo internet-egress-reachable; failed=1; else echo internet-egress-denied; fi
if wget -T 2 -qO- http://192.168.64.1 >/dev/null 2>&1; then echo host-gateway-reachable; failed=1; else echo host-gateway-denied; fi
cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
if [ "$cap_eff" = "0000000000000000" ]; then echo capabilities-dropped; else echo "capabilities-present:$cap_eff"; failed=1; fi
printf 'nofile=%s\n' "$(ulimit -n)"
printf 'nproc=%s\n' "$(ulimit -u)"
printf 'artifact-ok\n' > /output/result.txt && echo artifact-written
if [ "$failed" -eq 0 ]; then echo ahi-smoke-pass; fi
sleep 3
exit "$failed"'''


def wait_until_stopped(task_id: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        inspected = json.loads(run(["container", "inspect", task_id], timeout=10).stdout)[0]
        last = inspected
        if inspected.get("status", {}).get("state") != "running":
            return inspected
        time.sleep(0.25)
    raise TimeoutError(f"container {task_id} did not stop within {timeout} seconds")


def cleanup(manifest: dict[str, Any], container_created: bool, volumes: list[str]) -> list[str]:
    errors: list[str] = []
    task_id = manifest["task"]["id"]
    if container_created:
        inspect = run(["container", "inspect", task_id], timeout=10, check=False)
        if inspect.returncode == 0:
            try:
                labels = json.loads(inspect.stdout)[0]["configuration"]["labels"]
                stop = run(compile_command(manifest, "stop", observed_labels=labels), timeout=10, check=False)
                if stop.returncode not in {0, 1}:
                    errors.append("container stop failed")
                delete = run(compile_command(manifest, "delete", observed_labels=labels), timeout=10, check=False)
                if delete.returncode != 0:
                    errors.append("container delete failed")
            except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"container ownership check failed: {exc}")
    for volume in volumes:
        deleted = run(["container", "volume", "delete", volume], timeout=10, check=False)
        if deleted.returncode != 0:
            errors.append(f"volume delete failed: {volume}")
    return errors


def execute() -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:8]
    task_id = f"ahi-smoke-{suffix}"
    manifest = build_manifest(task_id)
    staged_snapshot = Path(manifest["workspace"]["snapshot"]["source"])
    created_volumes: list[str] = []
    container_created = False
    evidence: dict[str, Any] = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "task_id": task_id,
        "repository_commit": run(["git", "rev-parse", "HEAD"], timeout=10).stdout.strip(),
        "worktree_status_before": run(["git", "status", "--short"], timeout=10).stdout.splitlines(),
        "manifest": manifest,
        "manifest_hash": canonical_hash(manifest),
        "commands": {},
        "cleanup_errors": [],
        "status": "failed",
    }
    try:
        if staged_snapshot.exists() or staged_snapshot.is_symlink():
            raise RuntimeError(f"refusing to reuse snapshot path: {staged_snapshot}")
        staged_snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SNAPSHOT, staged_snapshot, symlinks=False)
        status = run(["container", "system", "status"], timeout=10)
        properties = run(["container", "system", "property", "list"], timeout=10)
        evidence["host"] = {
            "macos": run(["sw_vers", "-productVersion"], timeout=10).stdout.strip(),
            "architecture": platform.machine(),
            "container_version": run(["container", "system", "version"], timeout=10).stdout.strip(),
            "service_status": status.stdout.strip(),
            "system_properties": properties.stdout.strip(),
        }
        for action in ("create-scratch-volume", "create-output-volume", "create"):
            argv = compile_command(manifest, action)
            evidence["commands"][action] = argv
            run(argv, timeout=30)
            if action.endswith("volume"):
                created_volumes.append(manifest["runtime"]["scratch" if "scratch" in action else "output"]["volume"])
            elif action == "create":
                container_created = True
        ownership_inspect = json.loads(run(compile_command(manifest, "inspect"), timeout=10).stdout)[0]
        labels = ownership_inspect["configuration"]["labels"]
        start_argv = compile_command(manifest, "start", observed_labels=labels)
        evidence["commands"]["start"] = start_argv
        run(start_argv, timeout=10)
        evidence["stats"] = json.loads(run(compile_command(manifest, "stats", observed_labels=labels), timeout=10).stdout)
        running_inspect = json.loads(run(compile_command(manifest, "inspect"), timeout=10).stdout)[0]
        evidence["running_inspect"] = running_inspect
        evidence["final_inspect"] = wait_until_stopped(task_id, 15)
        logs = run(compile_command(manifest, "logs", observed_labels=labels), timeout=10).stdout
        evidence["logs"] = logs
        pinned_image = (
            f"{manifest['workspace']['image']['reference'].split('@', 1)[0]}"
            f"@{manifest['workspace']['image']['digest']}"
        )
        reader = [
            "container", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--mount", f"type=volume,source={manifest['runtime']['output']['volume']},target=/output,readonly",
            pinned_image, "cat", "/output/result.txt",
        ]
        evidence["commands"]["artifact-read"] = reader
        evidence["artifact"] = run(reader, timeout=30).stdout.strip()
        validate_evidence(evidence)
        evidence["status"] = "passed"
    finally:
        evidence["cleanup_errors"] = cleanup(manifest, container_created, created_volumes)
        if staged_snapshot.exists() and not staged_snapshot.is_symlink():
            shutil.rmtree(staged_snapshot)
        if evidence["cleanup_errors"]:
            evidence["status"] = "cleanup-failed"
    return evidence


def validate_evidence(evidence: dict[str, Any]) -> None:
    logs = evidence["logs"]
    missing = sorted(marker for marker in EXPECTED_MARKERS if marker not in logs)
    if missing:
        raise RuntimeError("missing denial markers: " + ", ".join(missing))
    if "nofile=64" not in logs or "nproc=32" not in logs:
        raise RuntimeError("guest ulimits do not match the manifest")
    if evidence["artifact"] != "artifact-ok":
        raise RuntimeError("output artifact could not be read back")
    config = evidence["running_inspect"]["configuration"]
    if config.get("readOnly") is not True or config.get("capDrop") != ["ALL"]:
        raise RuntimeError("runtime read-only/capability controls do not match")
    if config.get("ssh") or config.get("virtualization") or config.get("publishedSockets") or config.get("publishedPorts"):
        raise RuntimeError("forbidden runtime integration was present")
    if config.get("networks"):
        raise RuntimeError("networkless task unexpectedly received an interface")
    if config.get("resources", {}).get("cpus") != 1 or config.get("resources", {}).get("memoryInBytes") != 268435456:
        raise RuntimeError("runtime resource controls do not match")
    expected_digest = evidence["manifest"]["workspace"]["image"]["digest"]
    if config.get("image", {}).get("descriptor", {}).get("digest") != expected_digest:
        raise RuntimeError("runtime image digest does not match the manifest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = execute()
    except (OSError, subprocess.SubprocessError, RuntimeError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.output)
    print(json.dumps({
        "status": evidence["status"],
        "evidence": str(args.output),
        "manifest_hash": evidence["manifest_hash"],
        "cleanup_errors": evidence["cleanup_errors"],
    }, sort_keys=True))
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
