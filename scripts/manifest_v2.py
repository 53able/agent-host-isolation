#!/usr/bin/env python3
"""Validation primitives for the declarative Apple Container manifest."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from just_bash_manifest import validate_just_bash_v2

TOP_LEVEL_KEYS = {
    "manifest_version", "task", "workspace", "gateway", "model", "runtime",
    "resources", "resultGate",
}
RESOURCE_ENFORCERS = {
    "cpu": {"apple-container"},
    "memory_bytes": {"apple-container"},
    "disk_bytes": {"apple-container-volume"},
    "processes": {"guest-ulimit"},
    "open_files": {"guest-ulimit"},
    "log_bytes": {"host-watchdog"},
    "vm_count": {"host-scheduler"},
    "wall_time_seconds": {"host-watchdog"},
}
PLACEHOLDER = re.compile(r"(?:replace-with|placeholder|example\.invalid)", re.I)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_ID = re.compile(r"^[0-9a-f]{40,64}$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SNAPSHOT_ROOT = PurePosixPath("/var/tmp/agent-host-isolation/snapshots")
PROTECTED_GUEST_PATHS = tuple(PurePosixPath(path) for path in (
    "/", "/bin", "/dev", "/etc", "/proc", "/run", "/sbin", "/sys", "/usr",
))


def _mapping(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object.")
        return {}
    return value


def _required(obj: dict[str, Any], names: set[str], path: str, errors: list[str]) -> None:
    missing = names - obj.keys()
    if missing:
        errors.append(f"{path} missing required keys: {', '.join(sorted(missing))}.")


def _no_unknown(obj: dict[str, Any], names: set[str], path: str, errors: list[str]) -> None:
    unknown = obj.keys() - names
    if unknown:
        errors.append(f"{path} contains unknown keys: {', '.join(sorted(unknown))}.")


def _positive(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _absolute_guest_path(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("/")
        and ".." not in PurePosixPath(value).parts
        and "," not in value
        and "\x00" not in value
    )


def _paths_overlap(left: PurePosixPath, right: PurePosixPath) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _safe_mount_target(value: Any) -> bool:
    if not _absolute_guest_path(value):
        return False
    target = PurePosixPath(value)
    return not any(
        target == protected or (protected != PurePosixPath("/") and target.is_relative_to(protected))
        for protected in PROTECTED_GUEST_PATHS
    )


def validate_v2(data: Any) -> list[str]:
    if isinstance(data, dict) and isinstance(data.get("runtime"), dict) and data["runtime"].get("kind") == "just-bash":
        return validate_just_bash_v2(data)
    errors: list[str] = []
    root = _mapping(data, "manifest", errors)
    _required(root, TOP_LEVEL_KEYS, "manifest", errors)
    _no_unknown(root, TOP_LEVEL_KEYS, "manifest", errors)
    if root.get("manifest_version") != 2:
        errors.append("manifest_version must be 2.")

    _validate_task(root.get("task"), errors)
    _validate_workspace(root.get("workspace"), errors)
    _validate_gateway(root.get("gateway"), errors)
    _validate_model(root.get("model"), errors)
    _validate_runtime(root.get("runtime"), errors)
    _validate_resources(root.get("resources"), errors)
    _validate_result_gate(root.get("resultGate"), errors)
    _validate_references(root, errors)
    return errors


def _validate_task(value: Any, errors: list[str]) -> None:
    task = _mapping(value, "task", errors)
    required_keys = {"id", "goal", "profile", "strict_memory", "command", "expected_artifacts", "lifecycle"}
    allowed_keys = required_keys | {"attempt_id"}
    _required(task, required_keys, "task", errors)
    _no_unknown(task, allowed_keys, "task", errors)
    task_id = task.get("id")
    if not isinstance(task_id, str) or not SAFE_ID.fullmatch(task_id) or PLACEHOLDER.search(task_id):
        errors.append("task.id must be a non-placeholder lowercase task identifier.")
    attempt_id = task.get("attempt_id")
    if attempt_id is not None and (not isinstance(attempt_id, str) or not SAFE_ID.fullmatch(attempt_id) or PLACEHOLDER.search(attempt_id)):
        errors.append("task.attempt_id must be a concrete lowercase identifier when present.")
    if not isinstance(task.get("goal"), str) or not task.get("goal") or PLACEHOLDER.search(task.get("goal", "")):
        errors.append("task.goal must be concrete and non-empty.")
    if task.get("profile") not in {"guest-build", "elevated-release"}:
        errors.append("task.profile must be 'guest-build' or 'elevated-release' for apple-container.")
    if type(task.get("strict_memory")) is not bool:
        errors.append("task.strict_memory must be a boolean.")
    command = task.get("command")
    if not isinstance(command, list) or not command or any(not isinstance(x, str) or not x for x in command):
        errors.append("task.command must be a non-empty argv array of non-empty strings.")
    artifacts = task.get("expected_artifacts")
    if not isinstance(artifacts, list) or any(not _absolute_guest_path(x) for x in artifacts):
        errors.append("task.expected_artifacts must contain absolute guest paths without '..'.")
    lifecycle = _mapping(task.get("lifecycle"), "task.lifecycle", errors)
    keys = {"stop_timeout_seconds", "checkpoint"}
    _required(lifecycle, keys, "task.lifecycle", errors)
    _no_unknown(lifecycle, keys, "task.lifecycle", errors)
    if not isinstance(lifecycle.get("stop_timeout_seconds"), int) or lifecycle.get("stop_timeout_seconds", 0) <= 0:
        errors.append("task.lifecycle.stop_timeout_seconds must be a positive integer.")
    if lifecycle.get("checkpoint") not in {"disabled", "application-level"}:
        errors.append("task.lifecycle.checkpoint must be 'disabled' or 'application-level'.")


def _validate_workspace(value: Any, errors: list[str]) -> None:
    workspace = _mapping(value, "workspace", errors)
    keys = {"repository", "snapshot", "image", "toolchain", "lockfile", "mcps", "skills"}
    _required(workspace, keys, "workspace", errors)
    _no_unknown(workspace, keys, "workspace", errors)

    repository = _mapping(workspace.get("repository"), "workspace.repository", errors)
    keys = {"url", "commit", "tree_hash"}
    _required(repository, keys, "workspace.repository", errors)
    _no_unknown(repository, keys, "workspace.repository", errors)
    if not isinstance(repository.get("url"), str) or not repository.get("url") or PLACEHOLDER.search(repository.get("url", "")):
        errors.append("workspace.repository.url must be a concrete repository URL.")
    for name in ("commit", "tree_hash"):
        item = repository.get(name)
        if not isinstance(item, str) or not HEX_ID.fullmatch(item):
            errors.append(f"workspace.repository.{name} must be a full 40-64 character lowercase hex identity.")

    snapshot = _mapping(workspace.get("snapshot"), "workspace.snapshot", errors)
    keys = {"id", "source", "target", "read_only"}
    _required(snapshot, keys, "workspace.snapshot", errors)
    _no_unknown(snapshot, keys, "workspace.snapshot", errors)
    if not isinstance(snapshot.get("id"), str) or not SAFE_ID.fullmatch(snapshot.get("id", "")) or PLACEHOLDER.search(snapshot.get("id", "")):
        errors.append("workspace.snapshot.id must be a concrete logical snapshot identifier.")
    expected_source = SNAPSHOT_ROOT / str(snapshot.get("id", ""))
    if (
        not isinstance(snapshot.get("source"), str)
        or PurePosixPath(snapshot.get("source", "/")) != expected_source
        or "," in snapshot.get("source", "")
        or "\x00" in snapshot.get("source", "")
        or PLACEHOLDER.search(snapshot.get("source", ""))
    ):
        errors.append(
            "workspace.snapshot.source must equal the trusted snapshot path "
            f"{expected_source} derived from workspace.snapshot.id."
        )
    if not _safe_mount_target(snapshot.get("target")):
        errors.append("workspace.snapshot.target must be a non-protected absolute guest path without '..'.")
    if snapshot.get("read_only") is not True:
        errors.append("workspace.snapshot must be read_only: true; writable host mounts are forbidden.")

    image = _mapping(workspace.get("image"), "workspace.image", errors)
    keys = {"reference", "digest"}
    _required(image, keys, "workspace.image", errors)
    _no_unknown(image, keys, "workspace.image", errors)
    if (
        not isinstance(image.get("reference"), str)
        or not image.get("reference")
        or image.get("reference", "").startswith("-")
        or "@" in image.get("reference", "")
        or any(character.isspace() for character in image.get("reference", ""))
        or PLACEHOLDER.search(image.get("reference", ""))
    ):
        errors.append("workspace.image.reference must name a concrete OCI image.")
    if not isinstance(image.get("digest"), str) or not SHA256.fullmatch(image.get("digest", "")):
        errors.append("workspace.image.digest must be an immutable sha256 digest; mutable tags alone are rejected.")
    if not isinstance(workspace.get("toolchain"), dict):
        errors.append("workspace.toolchain must be an object of pinned tool identities.")
    elif any(
        not isinstance(name, str) or not name or not isinstance(version, str) or not version or PLACEHOLDER.search(version)
        for name, version in workspace["toolchain"].items()
    ):
        errors.append("workspace.toolchain entries must have concrete string names and pinned string versions.")
    lockfile = _mapping(workspace.get("lockfile"), "workspace.lockfile", errors)
    _required(lockfile, {"path", "sha256"}, "workspace.lockfile", errors)
    _no_unknown(lockfile, {"path", "sha256"}, "workspace.lockfile", errors)
    if not isinstance(lockfile.get("path"), str) or not lockfile.get("path") or PLACEHOLDER.search(lockfile.get("path", "")):
        errors.append("workspace.lockfile.path must be concrete and non-empty.")
    digest = lockfile.get("sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch("sha256:" + digest.removeprefix("sha256:")):
        errors.append("workspace.lockfile.sha256 must be a 64-character sha256 value.")
    for collection in ("mcps", "skills"):
        identities = workspace.get(collection)
        if not isinstance(identities, list):
            errors.append(f"workspace.{collection} must be an array of logical identities.")
            continue
        for index, identity in enumerate(identities):
            if not isinstance(identity, dict) or set(identity) != {"id", "version"}:
                errors.append(f"workspace.{collection}[{index}] must contain only id and version.")
                continue
            if any(not isinstance(identity.get(k), str) or not identity.get(k) or PLACEHOLDER.search(identity.get(k, "")) for k in ("id", "version")):
                errors.append(f"workspace.{collection}[{index}] must contain concrete id and version strings.")


def _validate_gateway(value: Any, errors: list[str]) -> None:
    gateway = _mapping(value, "gateway", errors)
    keys = {"default", "task_network", "ingress_ports", "grants", "credential_broker", "egress_gateway"}
    _required(gateway, keys, "gateway", errors)
    _no_unknown(gateway, keys, "gateway", errors)
    if gateway.get("default") != "deny":
        errors.append("gateway.default must be 'deny'.")
    network = gateway.get("task_network")
    if not isinstance(network, str) or not SAFE_ID.fullmatch(network) or PLACEHOLDER.search(network):
        errors.append("gateway.task_network must be 'none' or name a concrete task-dedicated network enforced by a gateway.")
    if gateway.get("ingress_ports") != []:
        errors.append("gateway.ingress_ports must be empty in the standard profile.")
    broker = gateway.get("credential_broker")
    if broker is not None and (not isinstance(broker, str) or not broker):
        errors.append("gateway.credential_broker must be null or a non-empty broker reference.")

    egress_gateway = gateway.get("egress_gateway")
    if egress_gateway is not None:
        egress_gateway = _mapping(egress_gateway, "gateway.egress_gateway", errors)
        gateway_keys = {"id", "policy_hash"}
        _required(egress_gateway, gateway_keys, "gateway.egress_gateway", errors)
        _no_unknown(egress_gateway, gateway_keys, "gateway.egress_gateway", errors)
        if not isinstance(egress_gateway.get("id"), str) or not SAFE_ID.fullmatch(egress_gateway.get("id", "")):
            errors.append("gateway.egress_gateway.id must be a concrete safe identifier.")
        if not isinstance(egress_gateway.get("policy_hash"), str) or not SHA256.fullmatch(egress_gateway.get("policy_hash", "")):
            errors.append("gateway.egress_gateway.policy_hash must be an immutable sha256 digest.")

    grants = gateway.get("grants")
    keys = {"destination", "scope", "protocol", "port", "method", "purpose", "expiry", "max_bytes", "audit_record"}
    if not isinstance(grants, list):
        errors.append("gateway.grants must be an array.")
        return
    if grants and network == "none":
        errors.append("gateway.task_network cannot be 'none' when egress grants are declared.")
    if not grants and network != "none":
        errors.append("gateway.task_network must be 'none' when no egress grants are declared.")
    if grants and not isinstance(egress_gateway, dict):
        errors.append("gateway.egress_gateway is required when egress grants are declared.")
    if not grants and egress_gateway is not None:
        errors.append("gateway.egress_gateway must be null when no egress grants are declared.")
    audit_records: set[str] = set()
    for index, raw_grant in enumerate(grants):
        path = f"gateway.grants[{index}]"
        grant = _mapping(raw_grant, path, errors)
        _required(grant, keys, path, errors)
        _no_unknown(grant, keys, path, errors)
        destination = grant.get("destination")
        if not isinstance(destination, str) or not destination or "*" in destination or PLACEHOLDER.search(destination):
            errors.append(f"{path}.destination must be concrete and cannot contain wildcards.")
        if not isinstance(grant.get("scope"), str) or not grant.get("scope"):
            errors.append(f"{path}.scope must be non-empty.")
        if grant.get("protocol") not in {"http", "https", "tcp", "udp"}:
            errors.append(f"{path}.protocol is invalid.")
        if not isinstance(grant.get("port"), int) or not 1 <= grant.get("port", 0) <= 65535:
            errors.append(f"{path}.port must be between 1 and 65535.")
        method = grant.get("method")
        if not isinstance(method, str) or not method or method != method.upper():
            errors.append(f"{path}.method must be an explicit uppercase method or operation.")
        for name in ("purpose", "audit_record"):
            if not isinstance(grant.get(name), str) or not grant.get(name) or PLACEHOLDER.search(grant.get(name, "")):
                errors.append(f"{path}.{name} must be concrete and non-empty.")
        audit_record = grant.get("audit_record")
        if isinstance(audit_record, str):
            if audit_record in audit_records:
                errors.append(f"{path}.audit_record must uniquely identify one grant budget.")
            audit_records.add(audit_record)
        try:
            expiry = datetime.fromisoformat(str(grant.get("expiry", "")).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError
        except ValueError:
            errors.append(f"{path}.expiry must be an ISO-8601 timestamp with timezone.")
        if not isinstance(grant.get("max_bytes"), int) or grant.get("max_bytes", 0) <= 0:
            errors.append(f"{path}.max_bytes must be a positive integer.")


def _validate_model(value: Any, errors: list[str]) -> None:
    model = _mapping(value, "model", errors)
    keys = {"provider", "id", "credential_broker_ref"}
    _required(model, keys, "model", errors)
    _no_unknown(model, keys, "model", errors)
    for name in ("provider", "id"):
        if not isinstance(model.get(name), str) or not model.get(name) or PLACEHOLDER.search(model.get(name, "")):
            errors.append(f"model.{name} must be a concrete identity.")
    broker_ref = model.get("credential_broker_ref")
    if broker_ref is not None and (not isinstance(broker_ref, str) or not broker_ref):
        errors.append("model.credential_broker_ref must be null or a non-empty broker reference; secrets must not be embedded.")


def _validate_runtime(value: Any, errors: list[str]) -> None:
    runtime = _mapping(value, "runtime", errors)
    keys = {"kind", "minimum_version", "minimum_macos_version", "rootfs_read_only", "drop_capabilities", "ssh_forwarding", "socket_publishing", "nested_virtualization", "environment", "scratch", "output"}
    _required(runtime, keys, "runtime", errors)
    _no_unknown(runtime, keys, "runtime", errors)
    if runtime.get("kind") != "apple-container":
        errors.append("runtime.kind must be 'apple-container'.")
    for name in ("minimum_version", "minimum_macos_version"):
        if not isinstance(runtime.get(name), str) or not re.fullmatch(r"\d+(?:\.\d+){1,2}", runtime.get(name, "")):
            errors.append(f"runtime.{name} must be a pinned numeric version.")
    if runtime.get("rootfs_read_only") is not True:
        errors.append("runtime.rootfs_read_only must be true.")
    if runtime.get("drop_capabilities") != ["ALL"]:
        errors.append("runtime.drop_capabilities must be exactly ['ALL']; capability additions are forbidden.")
    for name in ("ssh_forwarding", "socket_publishing", "nested_virtualization"):
        if runtime.get(name) is not False:
            errors.append(f"runtime.{name} must be false in the standard profile.")
    environment = runtime.get("environment")
    if not isinstance(environment, dict):
        errors.append("runtime.environment must be an object of explicit KEY=value entries.")
    else:
        for key, item in environment.items():
            if not ENV_NAME.fullmatch(key) or not isinstance(item, str):
                errors.append("runtime.environment only accepts valid names with explicit string values; host inheritance is forbidden.")
    for name in ("scratch", "output"):
        volume = _mapping(runtime.get(name), f"runtime.{name}", errors)
        _required(volume, {"volume", "target"}, f"runtime.{name}", errors)
        _no_unknown(volume, {"volume", "target"}, f"runtime.{name}", errors)
        if not isinstance(volume.get("volume"), str) or not SAFE_ID.fullmatch(volume.get("volume", "")) or PLACEHOLDER.search(volume.get("volume", "")):
            errors.append(f"runtime.{name}.volume must be a concrete named volume, not a host path.")
        if not _safe_mount_target(volume.get("target")):
            errors.append(f"runtime.{name}.target must be a non-protected absolute guest path without '..'.")


def _validate_resources(value: Any, errors: list[str]) -> None:
    resources = _mapping(value, "resources", errors)
    _required(resources, set(RESOURCE_ENFORCERS), "resources", errors)
    _no_unknown(resources, set(RESOURCE_ENFORCERS), "resources", errors)
    for name, allowed_enforcers in RESOURCE_ENFORCERS.items():
        policy = _mapping(resources.get(name), f"resources.{name}", errors)
        keys = {"limit", "enforced_by", "on_exceed"}
        _required(policy, keys, f"resources.{name}", errors)
        _no_unknown(policy, keys, f"resources.{name}", errors)
        limit = policy.get("limit")
        if name == "cpu":
            valid_limit = _positive(limit)
        else:
            valid_limit = isinstance(limit, int) and not isinstance(limit, bool) and limit > 0
        if not valid_limit:
            errors.append(f"resources.{name}.limit must be a positive {'number' if name == 'cpu' else 'integer'}.")
        if policy.get("enforced_by") not in allowed_enforcers:
            errors.append(f"resources.{name}.enforced_by must be one of {sorted(allowed_enforcers)}; unsupported enforcement cannot be ignored.")
        if policy.get("on_exceed") not in {"block", "throttle", "terminate"}:
            errors.append(f"resources.{name}.on_exceed must be block, throttle, or terminate.")


def _validate_result_gate(value: Any, errors: list[str]) -> None:
    gate = _mapping(value, "resultGate", errors)
    keys = {"required", "artifact_import", "allowed_side_effects", "audit_record"}
    _required(gate, keys, "resultGate", errors)
    _no_unknown(gate, keys, "resultGate", errors)
    if gate.get("required") is not True:
        errors.append("resultGate.required must be true.")
    artifact_import = _mapping(gate.get("artifact_import"), "resultGate.artifact_import", errors)
    keys = {"source", "max_bytes", "reject_symlinks", "reject_path_traversal"}
    _required(artifact_import, keys, "resultGate.artifact_import", errors)
    _no_unknown(artifact_import, keys, "resultGate.artifact_import", errors)
    if not _absolute_guest_path(artifact_import.get("source")):
        errors.append("resultGate.artifact_import.source must be an absolute guest path without '..'.")
    if not isinstance(artifact_import.get("max_bytes"), int) or artifact_import.get("max_bytes", 0) <= 0:
        errors.append("resultGate.artifact_import.max_bytes must be a positive integer.")
    for name in ("reject_symlinks", "reject_path_traversal"):
        if artifact_import.get(name) is not True:
            errors.append(f"resultGate.artifact_import.{name} must be true.")
    if gate.get("allowed_side_effects") != []:
        errors.append("resultGate.allowed_side_effects must be empty in the standard profile.")
    audit = gate.get("audit_record")
    if not isinstance(audit, str) or not audit or PLACEHOLDER.search(audit):
        errors.append("resultGate.audit_record must be a concrete location.")


def _validate_references(root: dict[str, Any], errors: list[str]) -> None:
    runtime = root.get("runtime")
    task = root.get("task")
    gate = root.get("resultGate")
    gateway = root.get("gateway")
    model = root.get("model")
    resources = root.get("resources")
    workspace = root.get("workspace")
    if not all(isinstance(item, dict) for item in (runtime, task, gate, gateway, model, resources, workspace)):
        return
    snapshot = workspace.get("snapshot")
    scratch = runtime.get("scratch")
    output = runtime.get("output")
    artifact_import = gate.get("artifact_import")
    if isinstance(output, dict) and isinstance(artifact_import, dict):
        output_target = output.get("target")
        if artifact_import.get("source") != output_target:
            errors.append("resultGate.artifact_import.source must equal runtime.output.target.")
        if isinstance(output_target, str) and output_target.startswith("/"):
            base = PurePosixPath(output_target)
            for artifact in task.get("expected_artifacts", []):
                if isinstance(artifact, str) and artifact.startswith("/") and not PurePosixPath(artifact).is_relative_to(base):
                    errors.append("task.expected_artifacts must remain within runtime.output.target.")
                    break
    mounts = (("workspace.snapshot", snapshot), ("runtime.scratch", scratch), ("runtime.output", output))
    valid_mounts = [(name, value) for name, value in mounts if isinstance(value, dict)]
    for index, (left_name, left) in enumerate(valid_mounts):
        left_target = left.get("target")
        if not _absolute_guest_path(left_target):
            continue
        for right_name, right in valid_mounts[index + 1:]:
            right_target = right.get("target")
            if _absolute_guest_path(right_target) and _paths_overlap(PurePosixPath(left_target), PurePosixPath(right_target)):
                errors.append(f"{left_name}.target and {right_name}.target must not overlap.")
    if isinstance(scratch, dict) and isinstance(output, dict):
        if scratch.get("volume") == output.get("volume"):
            errors.append("runtime.scratch.volume and runtime.output.volume must be distinct.")
    task_id = task.get("id")
    if isinstance(task_id, str):
        for name, volume in (("scratch", scratch), ("output", output)):
            if isinstance(volume, dict) and isinstance(volume.get("volume"), str):
                if not volume["volume"].startswith(task_id + "-"):
                    errors.append(f"runtime.{name}.volume must be task-scoped with prefix '{task_id}-'.")
        grants = gateway.get("grants")
        if isinstance(grants, list) and grants:
            expected_network = f"{task_id}-network"
            if gateway.get("task_network") != expected_network:
                errors.append(f"gateway.task_network must equal the task-dedicated name '{expected_network}'.")
    model_broker = model.get("credential_broker_ref")
    gateway_broker = gateway.get("credential_broker")
    if model_broker is not None and model_broker != gateway_broker:
        errors.append("model.credential_broker_ref must resolve to gateway.credential_broker.")
    disk = resources.get("disk_bytes")
    if isinstance(disk, dict) and isinstance(artifact_import, dict):
        disk_limit = disk.get("limit")
        import_limit = artifact_import.get("max_bytes")
        if isinstance(disk_limit, int) and isinstance(import_limit, int) and import_limit > disk_limit:
            errors.append("resultGate.artifact_import.max_bytes cannot exceed resources.disk_bytes.limit.")
