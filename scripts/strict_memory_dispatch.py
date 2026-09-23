#!/usr/bin/env python3
"""Fail-closed strict-memory escalation through a freshly verified guest runner."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

from guest_build_runner import run_guest_build
from just_bash_contract import build_escalation_request
from run_strict_memory_probe import execute as probe_memory
from verify_strict_memory_dispatch import execute as verify_dispatch

REQUIRED_CHECKS = {
    "memory", "process", "disk", "log", "wall_time", "watchdog",
    "cleanup", "artifact_result_gate", "full_agent_path", "quiescence", "open_files", "cpu", "vm_count",
    "mount", "credential", "network", "command_path", "supply_chain", "side_effect", "resource",
}
IMPORT_ROOT = Path("/var/tmp/agent-host-isolation/imports")
ROOT = Path(__file__).resolve().parents[1]


def verify_host_event(event: dict[str, Any]) -> None:
    source = event.get("source", {})
    task_id = source.get("task_id")
    attempt_id = source.get("attempt_id")
    if not isinstance(task_id, str) or not isinstance(attempt_id, str):
        raise ValueError("strict-memory event lacks a source attempt")
    git_dir = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.strip()
    claim_key = hashlib.sha256((task_id + "\0" + attempt_id).encode()).hexdigest()
    claim = (ROOT / git_dir).resolve() / "agent-host-isolation" / "just-bash-attempts-v1" / claim_key
    metadata = claim.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("source attempt claim is not private and owned")
    event_path = claim / "strict-memory-event.json"
    event_metadata = event_path.lstat()
    if not stat.S_ISREG(event_metadata.st_mode) or event_metadata.st_uid != os.getuid() or event_metadata.st_mode & 0o077:
        raise ValueError("strict-memory event record is not private and owned")
    if json.loads(event_path.read_text()) != event:
        raise ValueError("strict-memory event differs from the host-issued record")
    if (claim / "manifest-hash").read_text().strip() != source.get("manifest_hash"):
        raise ValueError("source claim manifest hash differs from the event")


@contextmanager
def claim_dispatch_attempt(target: dict[str, Any], registry_root: Path | None = None):
    attempt = target["task"].get("attempt_id")
    if not attempt:
        raise ValueError("automatic target requires an attempt ID")
    if registry_root is None:
        git_dir = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=ROOT, capture_output=True,
                                 text=True, check=True).stdout.strip()
        root = (ROOT / git_dir).resolve() / "agent-host-isolation" / "apple-dispatch-attempts-v1"
    else:
        root = registry_root
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("dispatch attempt registry must be a private owned directory")
    attempt_key = hashlib.sha256((target["task"]["id"] + "\0" + attempt).encode()).hexdigest()
    descriptor = os.open(root / "vm-slot.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        lock_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != os.getuid() or lock_metadata.st_mode & 0o077:
            raise ValueError("VM slot lock must be a private owned file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("the automatic-dispatch VM slot is occupied") from exc
        try:
            (root / attempt_key).mkdir(mode=0o700)
        except FileExistsError as exc:
            raise ValueError("automatic target attempt was already claimed") from exc
        yield root / attempt_key
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def trusted_destination(target: dict[str, Any]) -> Path:
    IMPORT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = IMPORT_ROOT.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("artifact import root must be a private owned directory")
    task_root = IMPORT_ROOT / target["task"]["id"]
    task_root.mkdir(mode=0o700, exist_ok=True)
    metadata = task_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("task import root must be a private owned directory")
    return task_root / target["task"]["attempt_id"]


def eligibility_errors(verification: dict[str, Any], target: dict[str, Any]) -> list[str]:
    errors = []
    if verification.get("worktree_status_before") != []:
        errors.append("verification did not start from a clean worktree")
    checks = verification.get("checks", {})
    if not REQUIRED_CHECKS.issubset(checks):
        errors.append("verification checks are incomplete")
    for name in sorted(REQUIRED_CHECKS):
        if checks.get(name) != "passed":
            errors.append(f"{name} is not verified")
    profile = verification.get("tested_profile", {})
    if profile.get("image") != target["workspace"]["image"]:
        errors.append("target image differs from the verified image")
    if profile.get("resources") != target["resources"]:
        errors.append("target resources differ from the verified profile")
    runner_digest = hashlib.sha256((Path(__file__).parent / "guest_build_runner.py").read_bytes()).hexdigest()
    if verification.get("runner_sha256") != runner_digest:
        errors.append("guest runner differs from the verified implementation")
    return errors


def stage_source_snapshot(source: dict[str, Any], source_dir: Path, target: dict[str, Any]) -> Path:
    """Copy only source-manifest bytes into the new target's controller-owned snapshot."""
    if source_dir.is_symlink() or not source_dir.is_dir():
        raise ValueError("source snapshot must be a real directory")
    entries = source["workspace"]["snapshot"]["paths"]
    aggregate = "sha256:" + hashlib.sha256(json.dumps(entries, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    if aggregate != source["workspace"]["snapshot"]["hash"]:
        raise ValueError("source snapshot aggregate hash differs from the manifest")
    if any(item.get("type") != "regular" for item in entries):
        raise ValueError("automatic dispatch requires a file-only source snapshot")
    expected = {item["path"] for item in entries}
    actual = set()
    for item in source_dir.rglob("*"):
        if item.is_symlink():
            raise ValueError("source snapshot contains a symlink")
        if item.is_file():
            actual.add(item.relative_to(source_dir).as_posix())
        elif not item.is_dir():
            raise ValueError("source snapshot contains a special file")
    if actual != expected:
        raise ValueError("source snapshot files differ from the manifest")
    destination = Path(target["workspace"]["snapshot"]["source"])
    if destination.exists() or destination.is_symlink():
        raise ValueError("target snapshot already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)
    try:
        for item in entries:
            relative = PurePosixPath(item["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("source snapshot path is unsafe")
            candidate = source_dir.joinpath(*relative.parts)
            descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("source snapshot entry is not a regular file")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    data = handle.read(item["size_bytes"] + 1)
            finally:
                os.close(descriptor)
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            if len(data) != item["size_bytes"] or digest != item["hash"]:
                raise ValueError("source snapshot bytes differ from the manifest")
            output = destination.joinpath(*relative.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        return destination
    except Exception:
        shutil.rmtree(destination)
        raise


def dispatch(source: dict[str, Any], event: dict[str, Any], target: dict[str, Any],
             source_dir: Path) -> dict[str, Any]:
    request = build_escalation_request(source, event, target, "audit/strict-memory-dispatch.json")
    if request["missing_capability"] != "strict-memory":
        raise ValueError("automatic dispatch accepts only strict-memory InspectBlocked")
    verify_host_event(event)
    if target["task"]["goal"] != source["task"]["goal"]:
        raise ValueError("automatic target must retain the source task goal")
    if target["workspace"]["repository"] != source["workspace"]["repository"]:
        raise ValueError("automatic target must retain the source repository identity")
    with claim_dispatch_attempt(target) as audit_dir:
        try:
            record = _dispatch_claimed(source, request, target, source_dir)
        except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
            record = {"request": request, "status": "blocked", "automatic": False,
                      "blocked_reasons": [str(exc)]}
        temporary = audit_dir / "audit.tmp"
        temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        temporary.chmod(0o600)
        os.replace(temporary, audit_dir / "audit.json")
        return record


def _dispatch_claimed(source: dict[str, Any], request: dict[str, Any], target: dict[str, Any],
                      source_dir: Path) -> dict[str, Any]:
    record: dict[str, Any] = {"request": request, "status": "blocked", "automatic": False}
    try:
        with tempfile.TemporaryDirectory(prefix="ahi-memory-check-") as temporary:
            evidence_path = Path(temporary) / "memory.json"
            memory = probe_memory()
            evidence_path.write_text(json.dumps(memory))
            verification = verify_dispatch(evidence_path)
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        record["blocked_reasons"] = [f"live verification failed: {exc}"]
        return record
    record["memory_evidence"] = memory
    record["verification"] = verification
    record["verification_checks"] = verification["checks"]
    errors = eligibility_errors(verification, target)
    if errors:
        record["blocked_reasons"] = errors
        return record
    snapshot = stage_source_snapshot(source, source_dir, target)
    try:
        result = run_guest_build(target, trusted_destination(target))
    finally:
        shutil.rmtree(snapshot)
    record["guest_result"] = result
    record["automatic"] = True
    record["status"] = "passed" if result["status"] == "passed" else "blocked"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_manifest", type=Path)
    parser.add_argument("blocked_event", type=Path)
    parser.add_argument("target_manifest", type=Path)
    parser.add_argument("source_snapshot", type=Path)
    args = parser.parse_args()
    try:
        record = dispatch(json.loads(args.source_manifest.read_text()), json.loads(args.blocked_event.read_text()),
                          json.loads(args.target_manifest.read_text()), args.source_snapshot)
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        record = {"status": "blocked", "automatic": False, "blocked_reasons": [str(exc)]}
    print(json.dumps(record, sort_keys=True))
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
