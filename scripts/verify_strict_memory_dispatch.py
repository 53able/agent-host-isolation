#!/usr/bin/env python3
"""Exercise the guest-build command path and record auto-dispatch prerequisites."""

from __future__ import annotations

import argparse
import copy
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
    "full_agent_path": (["sh", "-c", "id; printf passed > /output/result.txt"], 10, 1_048_576, ["/output/result.txt"]),
    "wall_time": (["sh", "-c", "sleep 10"], 2, 1_048_576, []),
    "log": (["sh", "-c", "yes x"], 5, 32_768, []),
    "disk": (["sh", "-c", "if dd if=/dev/zero of=/scratch/big bs=1M count=40; then echo disk-limit-bypassed; exit 3; else echo disk-limit-denied; fi"], 5, 1_048_576, []),
    "output_disk": (["sh", "-c", "if dd if=/dev/zero of=/output/big bs=1M count=4; then echo output-limit-bypassed; exit 3; else rm -f /output/big; echo output-limit-denied; fi"], 5, 1_048_576, []),
    "shm_disk": (["sh", "-c", "if dd if=/dev/zero of=/dev/shm/big bs=1M count=4; then echo shm-limit-bypassed; exit 3; else echo shm-limit-denied; fi"], 5, 1_048_576, []),
    "process": (["sh", "-c", "ulimit -u; n=0; for i in $(seq 1 40); do sleep 2 & kill -0 $! && n=$((n+1)); done; echo spawned:$n; if [ $n -lt 40 ]; then echo process-limit-denied; exit 0; else echo process-limit-bypassed; exit 3; fi"], 5, 1_048_576, []),
    "open_files": (["sh", "-c", "ulimit -Sn; ulimit -Hn; awk 'BEGIN {for (i=1;i<=100;i++) print \"x\" > (\"/scratch/f\" i)}'"], 5, 1_048_576, []),
    "cpu": (["sh", "-c", "cat /sys/fs/cgroup/cpu.max; if echo max > /sys/fs/cgroup/cpu.max; then echo cpu-limit-bypassed; exit 3; else echo cpu-limit-denied; fi"], 5, 1_048_576, []),
    "mount": (["sh", "-c", "if test -e /Users; then echo mount-bypassed; exit 3; fi; if printf x > /workspace/allowed.txt; then echo mount-bypassed; exit 3; fi; if printf x > /rootfs-escape; then echo rootfs-bypassed; exit 3; fi; ln -s /Users /scratch/host; test ! -e /scratch/host && echo mount-denied"], 5, 1_048_576, []),
    "credential": (["sh", "-c", "if env | cut -d= -f1 | grep -Eq '^(AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|GITHUB_TOKEN|SSH_AUTH_SOCK)$'; then echo credential-bypassed; exit 3; fi; for p in /root/.aws/credentials /root/.git-credentials /run/host-services/ssh-auth.sock /var/run/docker.sock /run/containerd/containerd.sock; do if test -r \"$p\"; then echo credential-bypassed; exit 3; fi; done; echo credential-denied"], 5, 1_048_576, []),
    "network": (["sh", "-c", "test \"$(ls /sys/class/net)\" = lo || exit 3; for url in http://1.1.1.1:80 http://192.168.64.1:80 http://169.254.169.254:80 http://127.0.0.1:2375; do if wget -T 1 -qO- \"$url\" >/dev/null 2>&1; then echo network-bypassed; exit 3; fi; done; echo network-denied"], 10, 1_048_576, []),
    "command_injection": (["--mount", "type=bind,source=/Users,target=/host"], 5, 1_048_576, []),
    "side_effect": (["sh", "-c", "if printf tampered > /workspace/allowed.txt; then echo host-write-bypassed; exit 3; fi; if wget -T 1 --post-data=payload -qO- http://1.1.1.1:80 >/dev/null 2>&1; then echo post-bypassed; exit 3; fi; printf accepted > /output/result.txt; echo side-effect-denied"], 5, 1_048_576, ["/output/result.txt"]),
    "artifact_symlink": (["sh", "-c", "ln -s /workspace/allowed.txt /output/result.txt"], 5, 1_048_576, ["/output/result.txt"]),
    "artifact_unexpected": (["sh", "-c", "printf unexpected > /output/extra.txt"], 5, 1_048_576, []),
    "artifact_oversize": (["sh", "-c", "head -c 1048576 /dev/zero > /output/result.txt; printf x >> /output/result.txt"], 5, 1_048_576, ["/output/result.txt"]),
    "artifact_partial": (["sh", "-c", "printf partial > /output/result.txt; exit 7"], 5, 1_048_576, ["/output/result.txt"]),
    "quiescence": (["sh", "-c", "printf partial > /output/result.txt; sleep 20 >/dev/null 2>&1 &"], 5, 1_048_576, ["/output/result.txt"]),
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
            *CASES, "artifact_result_gate", "memory", "cleanup", "watchdog", "vm_count",
            "mount", "credential", "network", "command_path", "supply_chain", "side_effect", "resource",
        )},
        "cases": {},
        "host_checks": {},
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
    record["checks"]["vm_count"] = "passed" if verify_vm_slot() else "blocked"
    for case, (command, wall_seconds, log_bytes, artifacts) in CASES.items():
        task_id = f"ahi-verify-{case.replace('_', '-')[:8]}-{uuid.uuid4().hex[:7]}"
        manifest = build_manifest(task_id)
        manifest["task"].update(strict_memory=True, command=command, expected_artifacts=artifacts)
        manifest["resources"]["disk_bytes"]["enforced_by"] = "apple-container-tmpfs"
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
                side_effect_ok = case == "side_effect" and (destination / "result.txt").is_file() and (destination / "result.txt").read_bytes() == b"accepted"
                imported_exists = destination.exists()
                snapshot_unchanged = (snapshot / "allowed.txt").read_bytes() == (SNAPSHOT / "allowed.txt").read_bytes()
        finally:
            shutil.rmtree(snapshot)
        record["cases"][case] = {"manifest_hash": outcome["manifest_hash"], "outcome": outcome}
        clean = not outcome["cleanup_errors"] and outcome.get("container_absent") and outcome.get("volumes_absent") == {}
        if not clean:
            record["checks"]["cleanup"] = "blocked"
        if case == "full_agent_path":
            passed = outcome["status"] == "passed" and artifact_ok and "uid=1000" in outcome.get("stdout", "")
        elif case in {"wall_time", "log"}:
            expected = "host wall-time limit exceeded" if case == "wall_time" else "host output limit exceeded"
            passed = outcome.get("watchdog_violation") == expected and outcome["status"] == "blocked"
        elif case == "artifact_symlink":
            passed = outcome["status"] == "blocked" and "non-regular file" in outcome.get("error", "")
        elif case == "artifact_unexpected":
            passed = outcome["status"] == "blocked" and "unexpected artifact" in outcome.get("error", "")
        elif case == "artifact_oversize":
            passed = outcome["status"] == "blocked" and "byte limit" in outcome.get("error", "")
        elif case == "artifact_partial":
            passed = outcome["status"] == "blocked" and outcome.get("exit_code") == 7 and not imported_exists
        elif case == "quiescence":
            passed = outcome["status"] == "blocked" and "task processes remain" in outcome.get("error", "") and not imported_exists
        elif case in {"disk", "output_disk", "shm_disk"}:
            marker = {"disk": "disk-limit-denied", "output_disk": "output-limit-denied", "shm_disk": "shm-limit-denied"}[case]
            passed = outcome["status"] == "passed" and marker in outcome.get("stdout", "") and "No space left" in outcome.get("stderr", "")
        elif case == "open_files":
            passed = (outcome["status"] == "blocked" and outcome.get("stdout", "").startswith("64\n64\n")
                      and "No file descriptors available" in outcome.get("stderr", ""))
        elif case == "cpu":
            first = outcome.get("stdout", "").splitlines()[0:1]
            parts = first[0].split() if first else []
            quota_ok = len(parts) == 2 and all(part.isdigit() for part in parts) and 0 < int(parts[0]) <= int(parts[1])
            passed = (outcome["status"] == "passed" and quota_ok
                      and "cpu-limit-denied" in outcome.get("stdout", "")
                      and "cpu-limit-bypassed" not in outcome.get("stdout", ""))
        elif case in {"mount", "credential", "network"}:
            passed = (outcome["status"] == "passed" and f"{case}-denied" in outcome.get("stdout", "")
                      and f"{case}-bypassed" not in outcome.get("stdout", "") and snapshot_unchanged)
        elif case == "command_injection":
            passed = (outcome["status"] == "blocked" and outcome.get("exit_code") != 0
                      and "illegal option" in outcome.get("stderr", "") and not imported_exists)
        elif case == "side_effect":
            passed = (outcome["status"] == "passed" and side_effect_ok and snapshot_unchanged
                      and "side-effect-denied" in outcome.get("stdout", "") and "bypassed" not in outcome.get("stdout", ""))
        else:
            passed = (outcome["status"] == "blocked" and outcome.get("stdout", "").startswith("32\n")
                      and "Resource temporarily unavailable" in outcome.get("stderr", "")
                      and "process-limit-bypassed" not in outcome.get("stdout", ""))
        record["checks"][case] = "passed" if passed and clean else "blocked"
    record["checks"]["disk"] = (
        "passed" if record["checks"]["disk"] == record["checks"]["output_disk"] == record["checks"]["shm_disk"] == "passed" else "blocked"
    )
    if record["checks"]["cleanup"] != "blocked":
        record["checks"]["cleanup"] = "passed"
    record["checks"]["watchdog"] = "passed" if record["checks"]["wall_time"] == record["checks"]["log"] == "passed" else "blocked"
    record["checks"]["artifact_result_gate"] = (
        "passed" if all(record["checks"][key] == "passed" for key in
                        ("artifact_symlink", "artifact_unexpected", "artifact_oversize", "artifact_partial"))
        else "blocked"
    )
    preflight = verify_policy_preflight()
    record["host_checks"].update(preflight)
    for category in ("mount", "credential", "network", "side_effect"):
        if not preflight[category]:
            record["checks"][category] = "blocked"
    record["checks"]["supply_chain"] = "passed" if verify_supply_chain(record) else "blocked"
    record["checks"]["command_path"] = (
        "passed" if record["checks"]["command_injection"] == record["checks"]["full_agent_path"] == "passed" else "blocked"
    )
    record["checks"]["resource"] = (
        "passed" if all(record["checks"][key] == "passed" for key in (
            "memory", "process", "disk", "log", "wall_time", "watchdog", "open_files", "cpu", "vm_count", "cleanup"))
        else "blocked"
    )
    return record


def verify_policy_preflight() -> dict[str, bool]:
    base = build_manifest(f"ahi-verify-policy-{uuid.uuid4().hex[:7]}")
    base["task"]["strict_memory"] = True
    base["resources"]["disk_bytes"]["enforced_by"] = "apple-container-tmpfs"
    checks: dict[str, bool] = {}
    mutations = {
        "mount": (lambda manifest: manifest["workspace"]["snapshot"].update(source="/tmp/untrusted"), "trusted snapshot path"),
        "credential": (lambda manifest: manifest["runtime"].update(environment={"AWS_SECRET_ACCESS_KEY": "denied-canary"}), "empty explicit environment"),
        "network": (lambda manifest: manifest["gateway"].update(task_network=f"{manifest['task']['id']}-network"), "must be 'none'"),
        "side_effect": (lambda manifest: manifest["resultGate"].update(allowed_side_effects=["push"]), "allowed_side_effects"),
    }
    with tempfile.TemporaryDirectory(prefix="ahi-verify-policy-") as temporary:
        for name, (mutate, expected) in mutations.items():
            manifest = copy.deepcopy(base)
            mutate(manifest)
            try:
                run_guest_build(manifest, Path(temporary) / name)
                rejected = False
            except ValueError as exc:
                rejected = expected in str(exc)
            inspected = run(["container", "inspect", manifest["task"]["id"]], timeout=10, check=False)
            checks[name] = rejected and inspected.returncode != 0 and "container not found" in inspected.stderr
    return checks


def verify_supply_chain(record: dict) -> bool:
    from strict_memory_dispatch import REQUIRED_CHECKS, eligibility_errors, stage_source_snapshot

    profile = record.get("tested_profile", {})
    target = {"workspace": {"image": profile.get("image")}, "resources": profile.get("resources")}
    verification = {
        "worktree_status_before": [],
        "checks": {key: "passed" for key in REQUIRED_CHECKS},
        "tested_profile": profile,
        "runner_sha256": record["runner_sha256"],
    }
    if eligibility_errors(verification, target):
        return False
    changed = copy.deepcopy(target)
    changed["workspace"]["image"]["digest"] = "sha256:" + "0" * 64
    if "target image differs from the verified image" not in eligibility_errors(verification, changed):
        return False
    with tempfile.TemporaryDirectory(prefix="ahi-verify-snapshot-") as temporary:
        root = Path(temporary)
        source_dir = root / "source"
        source_dir.mkdir()
        (source_dir / "allowed.txt").write_bytes(b"allowed")
        entries = [{"path": "allowed.txt", "type": "regular", "size_bytes": 7,
                    "hash": "sha256:" + hashlib.sha256(b"allowed").hexdigest()}]
        source = {"workspace": {"snapshot": {"paths": entries,
                   "hash": "sha256:" + hashlib.sha256(json.dumps(entries, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()}}}
        staged = stage_source_snapshot(source, source_dir, {"workspace": {"snapshot": {"source": str(root / "staged")}}})
        if (staged / "allowed.txt").read_bytes() != b"allowed":
            return False
        (source_dir / "allowed.txt").write_bytes(b"tampered")
        try:
            stage_source_snapshot(source, source_dir, {"workspace": {"snapshot": {"source": str(root / "rejected")}}})
        except ValueError as exc:
            return "source snapshot bytes differ" in str(exc) and not (root / "rejected").exists()
    return False


def verify_vm_slot() -> bool:
    from strict_memory_dispatch import claim_dispatch_attempt

    with tempfile.TemporaryDirectory(prefix="ahi-verify-vm-slot-") as temporary:
        registry = Path(temporary) / "registry"
        first = {"task": {"id": "verify-vm-first", "attempt_id": "attempt-1"}}
        second = {"task": {"id": "verify-vm-second", "attempt_id": "attempt-1"}}
        try:
            with claim_dispatch_attempt(first, registry):
                try:
                    with claim_dispatch_attempt(second, registry):
                        return False
                except ValueError as exc:
                    if "VM slot is occupied" not in str(exc):
                        return False
            with claim_dispatch_attempt(second, registry):
                return True
        except (OSError, ValueError, subprocess.SubprocessError):
            return False


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
