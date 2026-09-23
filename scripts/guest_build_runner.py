#!/usr/bin/env python3
"""Run one networkless guest-build command with host limits and a result gate."""

from __future__ import annotations

import argparse
import io
import json
import os
import selectors
import signal
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from apple_container_compiler import canonical_hash, compile_command, expected_labels, require_resource_ownership
from import_artifacts import import_artifacts
from manifest_v2 import validate_v2
from run_apple_container_smoke import cleanup, run
from run_strict_memory_probe import cleanup_volumes

MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_WALL_SECONDS = 30
MAX_ARTIFACT_FILES = 1024


class CleanupError(RuntimeError):
    pass


def bounded_process(argv: list[str], *, seconds: int, max_bytes: int) -> dict[str, Any]:
    """Capture bounded CLI output and kill its process group on a host limit."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    output = bytearray()
    errors = bytearray()
    deadline = time.monotonic() + seconds
    violation = None
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            if time.monotonic() >= deadline:
                violation = "host wall-time limit exceeded"
                break
            for key, _ in selector.select(timeout=min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                remaining = max_bytes - len(output) - len(errors)
                key.data.extend(chunk[:max(0, remaining)])
                if len(chunk) > remaining:
                    violation = "host output limit exceeded"
                    break
            if violation:
                break
    if violation:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        returncode = process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        returncode = process.wait(timeout=3)
    process.stdout.close()
    process.stderr.close()
    return {"returncode": returncode, "stdout": bytes(output), "stderr": bytes(errors), "violation": violation}


def extract_output(archive: bytes, manifest: dict[str, Any], staging: Path) -> None:
    limit = manifest["resultGate"]["artifact_import"]["max_bytes"]
    total = 0
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            parts = path.parts
            if path.is_absolute() or ".." in parts or "\x00" in member.name:
                raise ValueError("artifact archive path is unsafe")
            parts = tuple(part for part in parts if part != ".")
            if not parts:
                continue
            relative = PurePosixPath(*parts)
            if str(relative) in seen:
                raise ValueError("artifact archive contains duplicate paths")
            seen.add(str(relative))
            if len(seen) > MAX_ARTIFACT_FILES or len(str(relative)) > 4096:
                raise ValueError("artifact archive exceeds entry limits")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("artifact archive contains a non-regular file")
            total += member.size
            if total > limit:
                raise ValueError("artifact archive exceeds the result-gate byte limit")
            destination = staging.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise ValueError("artifact archive file has no contents")
            with destination.open("xb") as target:
                while chunk := source.read(65536):
                    target.write(chunk)


def _inspect_labels(name: str, manifest: dict[str, Any]) -> dict[str, Any] | None:
    inspected = run(["container", "inspect", name], timeout=10, check=False)
    if inspected.returncode != 0:
        if "container not found" in inspected.stderr:
            return None
        raise RuntimeError(f"container inspect failed: {name}")
    labels = json.loads(inspected.stdout)[0]["configuration"]["labels"]
    require_resource_ownership(manifest, labels)
    return labels


def _reader_output(manifest: dict[str, Any]) -> bytes:
    reader = f"ahi-reader-{uuid.uuid4().hex[:12]}"
    image = manifest["workspace"]["image"]
    pinned_image = f"{image['reference']}@{image['digest']}"
    argv = ["container", "run", "--rm", "--name", reader, "--network", "none",
            "--read-only", "--cap-drop", "ALL"]
    for key, value in expected_labels(manifest).items():
        argv.extend(["--label", f"{key}={value}"])
    argv.extend(["--mount", f"type=volume,source={manifest['runtime']['output']['volume']},target=/output,readonly",
                 pinned_image, "tar", "-C", "/output", "-cf", "-", "."])
    limit = manifest["resultGate"]["artifact_import"]["max_bytes"]
    try:
        result = bounded_process(argv, seconds=min(30, manifest["resources"]["wall_time_seconds"]["limit"]),
                                 max_bytes=limit + 1_048_576)
        if result["violation"] or result["returncode"] != 0:
            raise RuntimeError(f"artifact reader failed: {result['violation'] or result['stderr'][:200]!r}")
        return result["stdout"]
    finally:
        try:
            labels = _inspect_labels(reader, manifest)
            if labels is not None:
                run(["container", "stop", "--time", "2", reader], timeout=10, check=False)
                run(["container", "delete", reader], timeout=10, check=False)
                if _inspect_labels(reader, manifest) is not None:
                    raise CleanupError("artifact reader cleanup failed")
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, KeyError, IndexError) as exc:
            raise CleanupError(f"artifact reader cleanup failed: {exc}") from exc


def run_guest_build(manifest: dict[str, Any], destination: Path) -> dict[str, Any]:
    errors = validate_v2(manifest)
    if errors:
        raise ValueError("invalid guest-build manifest: " + "; ".join(errors))
    if manifest["task"]["profile"] != "guest-build" or manifest["runtime"]["kind"] != "apple-container":
        raise ValueError("guest-build on apple-container is required")
    if manifest["gateway"]["grants"] or manifest["gateway"]["task_network"] != "none":
        raise ValueError("networked tasks require a separate reviewed controller")
    if manifest["gateway"]["credential_broker"] is not None or manifest["model"]["credential_broker_ref"] is not None:
        raise ValueError("credential brokers require a separate reviewed controller")
    if manifest["resultGate"]["artifact_import"]["max_bytes"] > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact import exceeds the host ceiling")
    if manifest["resources"]["log_bytes"]["limit"] > MAX_LOG_BYTES:
        raise ValueError("log budget exceeds the host ceiling")
    if manifest["resources"]["wall_time_seconds"]["limit"] > MAX_WALL_SECONDS:
        raise ValueError("wall-time budget exceeds the host ceiling")
    if destination.exists() or destination.is_symlink():
        raise ValueError("artifact destination already exists")
    task_id = manifest["task"]["id"]
    volumes: list[str] = []
    created = False
    record: dict[str, Any] = {"task_id": task_id, "manifest_hash": canonical_hash(manifest),
                              "status": "blocked", "cleanup_errors": [], "artifact_records": []}
    archive: bytes | None = None
    try:
        for action, key in (("create-scratch-volume", "scratch"), ("create-output-volume", "output")):
            volumes.append(manifest["runtime"][key]["volume"])
            run(compile_command(manifest, action), timeout=30)
        created = True
        run(compile_command(manifest, "create"), timeout=30)
        labels = _inspect_labels(task_id, manifest)
        if labels is None:
            raise RuntimeError("created container was not found")
        command = compile_command(manifest, "start-attached", observed_labels=labels)
        result = bounded_process(command, seconds=manifest["resources"]["wall_time_seconds"]["limit"],
                                 max_bytes=manifest["resources"]["log_bytes"]["limit"])
        record["exit_code"] = result["returncode"]
        record["watchdog_violation"] = result["violation"]
        record["stdout"] = result["stdout"].decode("utf-8", errors="replace")
        record["stderr"] = result["stderr"].decode("utf-8", errors="replace")
        if result["violation"] or result["returncode"] != 0:
            raise RuntimeError(result["violation"] or f"guest exited {result['returncode']}")
        inspected = run(["container", "inspect", task_id], timeout=10)
        configuration = json.loads(inspected.stdout)[0]
        require_resource_ownership(manifest, configuration["configuration"]["labels"])
        if configuration["status"]["state"] != "stopped":
            raise RuntimeError("guest completion state is unconfirmed")
        archive = _reader_output(manifest)
    except CleanupError as exc:
        record["cleanup_errors"].append(str(exc))
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, KeyError, IndexError, tarfile.TarError) as exc:
        record["error"] = str(exc)
    finally:
        try:
            record["cleanup_errors"].extend(cleanup(manifest, created, []))
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, KeyError, IndexError) as exc:
            record["cleanup_errors"].append(str(exc))
        try:
            record["cleanup_errors"].extend(cleanup_volumes(manifest, volumes))
            record["container_absent"] = _inspect_labels(task_id, manifest) is None
            record["volumes_absent"] = {}
            for volume in volumes:
                result = run(["container", "volume", "inspect", volume], timeout=10, check=False)
                record["volumes_absent"][volume] = result.returncode != 0 and "volume not found" in result.stderr
            if not record["container_absent"] or not all(record["volumes_absent"].values()):
                record["cleanup_errors"].append("task resources remain after cleanup")
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, KeyError, IndexError) as exc:
            record["cleanup_errors"].append(str(exc))
        if record["cleanup_errors"]:
            record["status"] = "cleanup-failed"
    if archive is not None and not record["cleanup_errors"]:
        try:
            with tempfile.TemporaryDirectory(prefix="ahi-guest-output-") as temporary:
                staging = Path(temporary)
                extract_output(archive, manifest, staging)
                record["artifact_records"] = import_artifacts(manifest, staging, destination)
            record["status"] = "passed"
        except (OSError, ValueError, tarfile.TarError) as exc:
            record["error"] = str(exc)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    record = run_guest_build(json.loads(args.manifest.read_text()), args.destination)
    print(json.dumps(record, sort_keys=True))
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
