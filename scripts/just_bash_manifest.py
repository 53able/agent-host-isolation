#!/usr/bin/env python3
"""Fail-closed validation for the JustBash extension to Manifest v2."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

TOP_LEVEL_KEYS = {"manifest_version", "task", "workspace", "gateway", "model", "runtime", "resources", "resultGate", "verification"}
TASK_KEYS = {"id", "attempt_id", "goal", "profile", "command", "command_classes", "expected_artifacts", "lifecycle"}
RUNTIME_KEYS = {
    "kind", "package_version", "node_version", "agent_host_isolation_version", "profile_variant",
    "execution_limit_profile", "javascript", "python", "custom_commands",
    "tool_invocation", "inherit_host_environment", "filesystem", "limits",
    "host_watchdog", "unsupported_command", "host_shell_fallback", "audit_events", "escalation",
}
LIMIT_MAXIMA = {
    "max_call_depth": 100,
    "max_command_count": 20_000,
    "max_source_bytes": 8_388_608,
    "max_filesystem_bytes": 268_435_456,
    "max_output_bytes": 33_554_432,
    "max_archive_bytes": 268_435_456,
    "max_database_bytes": 134_217_728,
    "max_execution_time_ms": 30_000,
    "max_extension_cleanup_time_ms": 1_000,
}
HOST_WATCHDOG_MAXIMA = {"max_rss_bytes": 2_147_483_648, "wall_time_ms": 120_000, "poll_interval_ms": 1_000}
ALLOWED_COMMAND_CLASSES = {"read", "search", "text-processing", "structured-data", "hash", "deterministic-transform"}
INSPECT_COMMAND_POLICY_V1 = {
    "cat": ("read", 1), "ls": ("read", 0), "head": ("read", 1), "tail": ("read", 1),
    "rg": ("search", 2), "grep": ("search", 2),
    "wc": ("text-processing", 1), "sort": ("text-processing", 1), "uniq": ("text-processing", 1),
    "jq": ("structured-data", 2), "sha256sum": ("hash", 1), "md5sum": ("hash", 1),
    "printf": ("deterministic-transform", 1), "echo": ("deterministic-transform", 0),
}


def _safe_inspect_argv(command: list[str]) -> bool:
    if not command or any(not isinstance(arg, str) for arg in command):
        return False
    policy = INSPECT_COMMAND_POLICY_V1.get(command[0])
    if policy is None:
        return False
    args = command[1:]
    if command[0] == "jq" and args and args[0] == "-r":
        args = args[1:]
    return len(args) >= policy[1] and all(not arg.startswith("-") for arg in args)
REQUIRED_AUDIT_EVENTS = {"runtime_identity", "command", "stdout_stderr", "filesystem_diff", "artifact", "failure", "limit_violation", "result_gate", "cleanup"}
REQUIRED_TESTS = {"mount", "credential", "network", "command_path", "resource", "supply_chain", "side_effect"}
PLACEHOLDER = re.compile(r"(?:replace-with|placeholder|example\.invalid)", re.I)
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_ID = re.compile(r"^[0-9a-f]{40,64}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


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


def _pinned_version(value: Any) -> bool:
    return isinstance(value, str) and VERSION.fullmatch(value) is not None


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.startswith("~") or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _absolute_guest_path(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("/") and "\x00" not in value and ".." not in PurePosixPath(value).parts


def _concrete(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and PLACEHOLDER.search(value) is None


def canonical_manifest_hash(data: dict[str, Any]) -> str:
    """Hash the executable contract, excluding its post-execution verification record."""
    payload = {key: value for key, value in data.items() if key != "verification"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_just_bash_v2(data: Any) -> list[str]:
    errors: list[str] = []
    root = _mapping(data, "manifest", errors)
    _required(root, TOP_LEVEL_KEYS, "manifest", errors)
    _no_unknown(root, TOP_LEVEL_KEYS, "manifest", errors)
    if root.get("manifest_version") != 2:
        errors.append("manifest_version must be 2.")

    _validate_task(root.get("task"), errors)
    snapshot_total = _validate_workspace(root.get("workspace"), errors)
    runtime_value = root.get("runtime") if isinstance(root.get("runtime"), dict) else {}
    task_value = root.get("task") if isinstance(root.get("task"), dict) else {}
    _validate_gateway(root.get("gateway"), runtime_value.get("profile_variant"), task_value.get("id"), errors)
    _validate_model(root.get("model"), errors)
    limits = _validate_runtime(root.get("runtime"), errors)
    _validate_resources(root.get("resources"), limits, runtime_value.get("host_watchdog"), errors)
    _validate_result_gate(root.get("resultGate"), limits, errors)
    _validate_verification(root, errors)
    _validate_references(root, snapshot_total, limits, errors)
    return errors


def _validate_task(value: Any, errors: list[str]) -> None:
    task = _mapping(value, "task", errors)
    _required(task, TASK_KEYS, "task", errors)
    _no_unknown(task, TASK_KEYS, "task", errors)
    for name in ("id", "attempt_id"):
        item = task.get(name)
        if not isinstance(item, str) or not SAFE_ID.fullmatch(item) or PLACEHOLDER.search(item):
            errors.append(f"task.{name} must be a concrete lowercase identifier.")
    if not _concrete(task.get("goal")):
        errors.append("task.goal must be concrete and non-empty.")
    if task.get("profile") != "inspect":
        errors.append("runtime.kind 'just-bash' requires task.profile 'inspect'; guest-build and elevated-release are rejected.")
    command = task.get("command")
    if not isinstance(command, list) or not command or any(not isinstance(item, str) or not item or "\x00" in item for item in command):
        errors.append("task.command must be a non-empty argv array of non-empty strings.")
    classes = task.get("command_classes")
    if (
        not isinstance(classes, list)
        or not classes
        or any(not isinstance(item, str) or item not in ALLOWED_COMMAND_CLASSES for item in classes)
        or len(classes) != len(set(classes))
    ):
        errors.append("task.command_classes must be a unique non-empty subset of standard inspect command classes.")
    if isinstance(command, list) and command and isinstance(command[0], str):
        policy = INSPECT_COMMAND_POLICY_V1.get(command[0])
        if policy is None or not isinstance(classes, list) or policy[0] not in classes or not _safe_inspect_argv(command):
            errors.append("task.command must be a versioned standard inspect command with its class declared in task.command_classes.")
    artifacts = task.get("expected_artifacts")
    if not isinstance(artifacts, list) or any(not _absolute_guest_path(item) for item in artifacts):
        errors.append("task.expected_artifacts must contain absolute virtual-filesystem paths without '..'.")
    lifecycle = _mapping(task.get("lifecycle"), "task.lifecycle", errors)
    keys = {"stop_timeout_seconds", "checkpoint"}
    _required(lifecycle, keys, "task.lifecycle", errors)
    _no_unknown(lifecycle, keys, "task.lifecycle", errors)
    if type(lifecycle.get("stop_timeout_seconds")) is not int or not 0 < lifecycle.get("stop_timeout_seconds", 0) <= 30:
        errors.append("task.lifecycle.stop_timeout_seconds must be an integer from 1 through 30.")
    if lifecycle.get("checkpoint") not in {"disabled", "application-level"}:
        errors.append("task.lifecycle.checkpoint must be disabled or application-level; process checkpoints are unsupported.")


def _validate_workspace(value: Any, errors: list[str]) -> int:
    workspace = _mapping(value, "workspace", errors)
    keys = {"repository", "snapshot", "image", "toolchain", "lockfile", "mcps", "skills"}
    _required(workspace, keys, "workspace", errors)
    _no_unknown(workspace, keys, "workspace", errors)
    repository = _mapping(workspace.get("repository"), "workspace.repository", errors)
    _required(repository, {"url", "commit", "tree_hash"}, "workspace.repository", errors)
    _no_unknown(repository, {"url", "commit", "tree_hash"}, "workspace.repository", errors)
    if not _concrete(repository.get("url")):
        errors.append("workspace.repository.url must be concrete.")
    for name in ("commit", "tree_hash"):
        if not isinstance(repository.get(name), str) or not HEX_ID.fullmatch(repository.get(name, "")):
            errors.append(f"workspace.repository.{name} must be a full lowercase hex identity.")

    snapshot = _mapping(workspace.get("snapshot"), "workspace.snapshot", errors)
    snapshot_keys = {"id", "target", "read_only", "hash", "paths"}
    _required(snapshot, snapshot_keys, "workspace.snapshot", errors)
    _no_unknown(snapshot, snapshot_keys, "workspace.snapshot", errors)
    if not isinstance(snapshot.get("id"), str) or not SAFE_ID.fullmatch(snapshot.get("id", "")) or PLACEHOLDER.search(snapshot.get("id", "")):
        errors.append("workspace.snapshot.id must be concrete.")
    if snapshot.get("target") != "/workspace":
        errors.append("workspace.snapshot.target must be /workspace.")
    if snapshot.get("read_only") is not True:
        errors.append("workspace.snapshot.read_only must be true.")
    if not isinstance(snapshot.get("hash"), str) or not SHA256.fullmatch(snapshot.get("hash", "")):
        errors.append("workspace.snapshot.hash must be an exact sha256 digest.")
    paths = snapshot.get("paths")
    total = 0
    seen: set[str] = set()
    if not isinstance(paths, list) or not paths:
        errors.append("workspace.snapshot.paths must be a non-empty array.")
    else:
        for index, raw in enumerate(paths):
            path = f"workspace.snapshot.paths[{index}]"
            entry = _mapping(raw, path, errors)
            entry_keys = {"path", "type", "size_bytes", "hash"}
            _required(entry, entry_keys, path, errors)
            _no_unknown(entry, entry_keys, path, errors)
            name = entry.get("path")
            if not _safe_relative_path(name):
                errors.append(f"{path}.path must remain inside the minimum snapshot.")
            elif name in seen:
                errors.append(f"{path}.path duplicates another snapshot entry.")
            else:
                seen.add(name)
            if entry.get("type") != "regular":
                errors.append(f"{path}.type must be regular in a file-only snapshot; it forbids symlinks, directories, devices, sockets, FIFOs, and other special files.")
            size = entry.get("size_bytes")
            if type(size) is not int or size < 0:
                errors.append(f"{path}.size_bytes must be a non-negative integer.")
            else:
                total += size
            if not isinstance(entry.get("hash"), str) or not SHA256.fullmatch(entry.get("hash", "")):
                errors.append(f"{path}.hash must be an exact sha256 digest.")
    if workspace.get("image") is not None:
        errors.append("workspace.image must be null for the in-process JustBash runtime.")
    toolchain = _mapping(workspace.get("toolchain"), "workspace.toolchain", errors)
    required_tools = {"node", "just-bash", "agent-host-isolation"}
    _required(toolchain, required_tools, "workspace.toolchain", errors)
    _no_unknown(toolchain, required_tools, "workspace.toolchain", errors)
    for name in required_tools:
        if not _pinned_version(toolchain.get(name)):
            errors.append(f"workspace.toolchain.{name} must be an exact pinned semantic version.")
    lockfile = _mapping(workspace.get("lockfile"), "workspace.lockfile", errors)
    _required(lockfile, {"path", "sha256"}, "workspace.lockfile", errors)
    _no_unknown(lockfile, {"path", "sha256"}, "workspace.lockfile", errors)
    if not _safe_relative_path(lockfile.get("path")):
        errors.append("workspace.lockfile.path must be a relative snapshot path.")
    digest = str(lockfile.get("sha256", ""))
    if not SHA256.fullmatch("sha256:" + digest.removeprefix("sha256:")):
        errors.append("workspace.lockfile.sha256 must be an exact sha256 digest.")
    for collection in ("mcps", "skills"):
        identities = workspace.get(collection)
        if not isinstance(identities, list):
            errors.append(f"workspace.{collection} must be an array.")
            continue
        for index, identity in enumerate(identities):
            if not isinstance(identity, dict) or set(identity) != {"id", "version"} or any(not _concrete(identity.get(key)) for key in ("id", "version")):
                errors.append(f"workspace.{collection}[{index}] must contain only concrete id and version strings.")
    return total


def _validate_gateway(value: Any, profile_variant: Any, task_id: Any, errors: list[str]) -> None:
    gateway = _mapping(value, "gateway", errors)
    keys = {"default", "task_network", "ingress_ports", "grants", "credential_broker"}
    _required(gateway, keys, "gateway", errors)
    _no_unknown(gateway, keys, "gateway", errors)
    if gateway.get("default") != "deny":
        errors.append("gateway.default must be deny.")
    grants = gateway.get("grants")
    if profile_variant == "standard":
        if gateway.get("task_network") is not None or grants != []:
            errors.append("standard JustBash inspect must not configure network or grants; use a separately reviewed derived profile.")
    elif profile_variant == "network-derived":
        network = gateway.get("task_network")
        if not isinstance(task_id, str) or network != f"{task_id}-network" or not SAFE_ID.fullmatch(network):
            errors.append("gateway.task_network must be bound to task.id as '<task.id>-network'.")
        if not isinstance(grants, list) or not grants:
            errors.append("network-derived JustBash requires at least one scoped gateway grant.")
        else:
            for index, grant in enumerate(grants):
                _validate_network_grant(grant, index, task_id, errors)
    if gateway.get("ingress_ports") != []:
        errors.append("gateway.ingress_ports must be empty.")
    if gateway.get("credential_broker") is not None:
        errors.append("gateway.credential_broker must be null.")


def _validate_network_grant(value: Any, index: int, task_id: Any, errors: list[str]) -> None:
    path = f"gateway.grants[{index}]"
    grant = _mapping(value, path, errors)
    keys = {"task_id", "origin", "port", "path_prefix", "methods", "scope", "purpose", "expiry", "max_bytes", "audit_record", "redirect_policy"}
    _required(grant, keys, path, errors)
    _no_unknown(grant, keys, path, errors)
    if grant.get("task_id") != task_id:
        errors.append(f"{path}.task_id must match task.id.")
    origin = grant.get("origin")
    parsed = None
    hostname = None
    parsed_port = None
    try:
        parsed = urlsplit(origin) if isinstance(origin, str) else None
        hostname = parsed.hostname if parsed else None
        parsed_port = parsed.port if parsed else None
    except ValueError:
        parsed = None
        hostname = None
        parsed_port = None
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False
    else:
        is_ip_literal = False
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or is_ip_literal
    ):
        errors.append(f"{path}.origin must be an exact non-IP HTTP(S) origin.")
    port = grant.get("port")
    effective_port = parsed_port if parsed_port is not None else (443 if parsed and parsed.scheme == "https" else 80)
    if type(port) is not int or not 1 <= port <= 65535 or port != effective_port:
        errors.append(f"{path}.port must exactly match the origin port.")
    prefix = grant.get("path_prefix")
    if (
        not isinstance(prefix, str)
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]*", prefix)
        or "//" in prefix
        or any(segment in {".", ".."} for segment in prefix.split("/"))
        or (prefix != "/" and not prefix.endswith("/"))
    ):
        errors.append(f"{path}.path_prefix must be a canonical absolute URL path prefix without traversal or encoded separators, query, or fragment.")
    methods = grant.get("methods")
    if not isinstance(methods, list) or not methods or any(not isinstance(method, str) or method not in {"GET", "HEAD"} for method in methods):
        errors.append(f"{path}.methods must contain only GET or HEAD for inspect.")
    for name in ("scope", "purpose"):
        if not _concrete(grant.get(name)):
            errors.append(f"{path}.{name} must be concrete and non-empty.")
    if not _safe_relative_path(grant.get("audit_record")) or PLACEHOLDER.search(str(grant.get("audit_record"))):
        errors.append(f"{path}.audit_record must be a concrete relative path.")
    try:
        expiry = datetime.fromisoformat(str(grant.get("expiry", "")).replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError
    except ValueError:
        errors.append(f"{path}.expiry must be a future ISO-8601 timestamp with timezone.")
    if type(grant.get("max_bytes")) is not int or grant.get("max_bytes", 0) <= 0:
        errors.append(f"{path}.max_bytes must be a positive integer.")
    if grant.get("redirect_policy") != "revalidate-exact-origin":
        errors.append(f"{path}.redirect_policy must revalidate the exact origin on every redirect.")


def _validate_model(value: Any, errors: list[str]) -> None:
    model = _mapping(value, "model", errors)
    keys = {"provider", "id", "credential_broker_ref"}
    _required(model, keys, "model", errors)
    _no_unknown(model, keys, "model", errors)
    if model.get("provider") != "none" or model.get("id") != "none" or model.get("credential_broker_ref") is not None:
        errors.append("standard JustBash inspect must not receive model or credential capability.")


def _validate_runtime(value: Any, errors: list[str]) -> dict[str, int]:
    runtime = _mapping(value, "runtime", errors)
    _required(runtime, RUNTIME_KEYS, "runtime", errors)
    _no_unknown(runtime, RUNTIME_KEYS, "runtime", errors)
    if runtime.get("kind") != "just-bash":
        errors.append("runtime.kind must be just-bash.")
    if runtime.get("profile_variant") not in {"standard", "network-derived"}:
        errors.append("runtime.profile_variant must be standard or network-derived.")
    elif runtime.get("profile_variant") == "network-derived":
        errors.append("network-derived JustBash is unavailable until a request-time enforcing gateway adapter is installed.")
    for name in ("package_version", "node_version", "agent_host_isolation_version"):
        if not _pinned_version(runtime.get(name)):
            errors.append(f"runtime.{name} must be an exact pinned semantic version.")
    node = runtime.get("node_version")
    if _pinned_version(node) and tuple(int(item) for item in node.split("-", 1)[0].split(".")[:2]) < (20, 19):
        errors.append("runtime.node_version must be at least 20.19.0 for JustBash.")
    if runtime.get("execution_limit_profile") != "hardened":
        errors.append("runtime.execution_limit_profile must be hardened.")
    for name in ("javascript", "python", "tool_invocation", "inherit_host_environment"):
        if runtime.get(name) is not False:
            errors.append(f"runtime.{name} must be false in standard inspect.")
    if runtime.get("custom_commands") != []:
        errors.append("runtime.custom_commands must be empty in standard inspect.")
    filesystem = _mapping(runtime.get("filesystem"), "runtime.filesystem", errors)
    fs_keys = {"implementation", "host_root", "writes"}
    _required(filesystem, fs_keys, "runtime.filesystem", errors)
    _no_unknown(filesystem, fs_keys, "runtime.filesystem", errors)
    if filesystem.get("implementation") not in {"in-memory", "overlay"}:
        errors.append("runtime.filesystem.implementation must be in-memory or overlay.")
    if filesystem.get("host_root") != "input-snapshot-only" or filesystem.get("writes") != "task-local-overlay":
        errors.append("runtime.filesystem must expose only the input snapshot and task-local overlay writes.")
    raw_limits = _mapping(runtime.get("limits"), "runtime.limits", errors)
    _required(raw_limits, set(LIMIT_MAXIMA), "runtime.limits", errors)
    _no_unknown(raw_limits, set(LIMIT_MAXIMA), "runtime.limits", errors)
    limits: dict[str, int] = {}
    for name, maximum in LIMIT_MAXIMA.items():
        limit = raw_limits.get(name)
        if type(limit) is not int or not 0 < limit <= maximum:
            errors.append(f"runtime.limits.{name} must be a positive integer no greater than {maximum}.")
        else:
            limits[name] = limit
    watchdog = _mapping(runtime.get("host_watchdog"), "runtime.host_watchdog", errors)
    _required(watchdog, set(HOST_WATCHDOG_MAXIMA), "runtime.host_watchdog", errors)
    _no_unknown(watchdog, set(HOST_WATCHDOG_MAXIMA), "runtime.host_watchdog", errors)
    for name, maximum in HOST_WATCHDOG_MAXIMA.items():
        value = watchdog.get(name)
        if type(value) is not int or not 0 < value <= maximum:
            errors.append(f"runtime.host_watchdog.{name} must be a positive integer no greater than {maximum}.")
    if type(watchdog.get("wall_time_ms")) is int and watchdog["wall_time_ms"] <= limits.get("max_execution_time_ms", 0):
        errors.append("runtime.host_watchdog.wall_time_ms must exceed the per-command execution limit.")
    if runtime.get("unsupported_command") != "InspectBlocked":
        errors.append("runtime.unsupported_command must be InspectBlocked.")
    if runtime.get("host_shell_fallback") is not False:
        errors.append("runtime.host_shell_fallback must be false.")
    events = runtime.get("audit_events")
    if not isinstance(events, list) or any(not isinstance(event, str) for event in events) or not REQUIRED_AUDIT_EVENTS.issubset(events):
        errors.append("runtime.audit_events is missing required runtime, command, output, result, or cleanup evidence.")
    escalation = _mapping(runtime.get("escalation"), "runtime.escalation", errors)
    esc_keys = {"target_profile", "runtime_kind", "require_new_manifest", "require_new_attempt", "automatic"}
    _required(escalation, esc_keys, "runtime.escalation", errors)
    _no_unknown(escalation, esc_keys, "runtime.escalation", errors)
    expected = {"target_profile": "guest-build", "runtime_kind": "apple-container", "require_new_manifest": True, "require_new_attempt": True, "automatic": False}
    for name, expected_value in expected.items():
        if escalation.get(name) != expected_value:
            errors.append(f"runtime.escalation.{name} must be {expected_value!r}.")
    return limits


def _validate_resources(value: Any, limits: dict[str, int], watchdog_value: Any, errors: list[str]) -> None:
    resources = _mapping(value, "resources", errors)
    host_keys = {"sampled_worker_rss_bytes", "host_wall_time_ms"}
    _required(resources, set(LIMIT_MAXIMA) | host_keys, "resources", errors)
    _no_unknown(resources, set(LIMIT_MAXIMA) | host_keys, "resources", errors)
    for name in LIMIT_MAXIMA:
        policy = _mapping(resources.get(name), f"resources.{name}", errors)
        keys = {"limit", "enforced_by", "on_exceed"}
        _required(policy, keys, f"resources.{name}", errors)
        _no_unknown(policy, keys, f"resources.{name}", errors)
        if policy.get("limit") != limits.get(name):
            errors.append(f"resources.{name}.limit must equal runtime.limits.{name}.")
        if policy.get("enforced_by") != "just-bash":
            errors.append(f"resources.{name}.enforced_by must be just-bash.")
        if policy.get("on_exceed") not in {"block", "terminate"}:
            errors.append(f"resources.{name}.on_exceed must be block or terminate.")
    watchdog = watchdog_value if isinstance(watchdog_value, dict) else {}
    for name, source in (("sampled_worker_rss_bytes", "max_rss_bytes"), ("host_wall_time_ms", "wall_time_ms")):
        policy = _mapping(resources.get(name), f"resources.{name}", errors)
        _required(policy, {"limit", "enforced_by", "on_exceed"}, f"resources.{name}", errors)
        _no_unknown(policy, {"limit", "enforced_by", "on_exceed"}, f"resources.{name}", errors)
        if policy.get("limit") != watchdog.get(source):
            errors.append(f"resources.{name}.limit must equal runtime.host_watchdog.{source}.")
        if policy.get("enforced_by") != "host-watchdog" or policy.get("on_exceed") != "terminate":
            errors.append(f"resources.{name} must be terminated by host-watchdog.")


def _validate_result_gate(value: Any, limits: dict[str, int], errors: list[str]) -> None:
    gate = _mapping(value, "resultGate", errors)
    keys = {"required", "filesystem_diff", "artifact_import", "allowed_side_effects", "audit_record"}
    _required(gate, keys, "resultGate", errors)
    _no_unknown(gate, keys, "resultGate", errors)
    if gate.get("required") is not True or gate.get("filesystem_diff") is not True:
        errors.append("resultGate must require artifact and filesystem-diff inspection.")
    artifact = _mapping(gate.get("artifact_import"), "resultGate.artifact_import", errors)
    artifact_keys = {"source", "max_bytes", "reject_symlinks", "reject_path_traversal"}
    _required(artifact, artifact_keys, "resultGate.artifact_import", errors)
    _no_unknown(artifact, artifact_keys, "resultGate.artifact_import", errors)
    if artifact.get("source") != "/scratch/export":
        errors.append("resultGate.artifact_import.source must be the task-local /scratch/export subtree.")
    max_bytes = artifact.get("max_bytes")
    if type(max_bytes) is not int or max_bytes <= 0 or max_bytes > limits.get("max_output_bytes", 0):
        errors.append("resultGate.artifact_import.max_bytes cannot exceed runtime.limits.max_output_bytes.")
    for name in ("reject_symlinks", "reject_path_traversal"):
        if artifact.get(name) is not True:
            errors.append(f"resultGate.artifact_import.{name} must be true.")
    if gate.get("allowed_side_effects") != []:
        errors.append("resultGate.allowed_side_effects must be empty.")
    audit = gate.get("audit_record")
    if not _safe_relative_path(audit) or PLACEHOLDER.search(str(audit)):
        errors.append("resultGate.audit_record must be a concrete relative path without traversal.")


def _validate_verification(root: dict[str, Any], errors: list[str]) -> None:
    verification = _mapping(root.get("verification"), "verification", errors)
    keys = {"status", "adversarial_evidence"}
    _required(verification, keys, "verification", errors)
    _no_unknown(verification, keys, "verification", errors)
    status = verification.get("status")
    evidence = verification.get("adversarial_evidence")
    if status not in {"unverified", "blocked", "verified-for-tested-configuration"}:
        errors.append("verification.status is invalid.")
    if not isinstance(evidence, list):
        errors.append("verification.adversarial_evidence must be an array.")
        return
    if status != "verified-for-tested-configuration":
        return
    if len(evidence) != 1 or not isinstance(evidence[0], dict):
        errors.append("verified-for-tested-configuration requires one structured evidence record.")
        return
    record = evidence[0]
    record_keys = {"host_os", "host_version", "embedding", "package_version", "node_version", "agent_host_isolation_version", "manifest_hash", "input_snapshot_hash", "tests", "cleanup_passed"}
    _required(record, record_keys, "verification.adversarial_evidence[0]", errors)
    _no_unknown(record, record_keys, "verification.adversarial_evidence[0]", errors)
    for name in ("host_os", "host_version", "embedding"):
        if not _concrete(record.get(name)):
            errors.append(f"verification.adversarial_evidence[0].{name} must be concrete.")
    runtime = root.get("runtime") if isinstance(root.get("runtime"), dict) else {}
    for name in ("package_version", "node_version", "agent_host_isolation_version"):
        if record.get(name) != runtime.get(name):
            errors.append(f"verification evidence {name} must match runtime.{name}.")
    if record.get("manifest_hash") != canonical_manifest_hash(root):
        errors.append("verification evidence manifest_hash must match the canonical executable manifest hash.")
    workspace = root.get("workspace") if isinstance(root.get("workspace"), dict) else {}
    snapshot = workspace.get("snapshot") if isinstance(workspace.get("snapshot"), dict) else {}
    if record.get("input_snapshot_hash") != snapshot.get("hash"):
        errors.append("verification evidence input_snapshot_hash must match workspace.snapshot.hash.")
    required_tests = set(REQUIRED_TESTS)
    if runtime.get("profile_variant") == "network-derived":
        required_tests.update({"network_redirect", "network_ip_literal", "network_alternate_port"})
    tests = _mapping(record.get("tests"), "verification.adversarial_evidence[0].tests", errors)
    _required(tests, required_tests, "verification.adversarial_evidence[0].tests", errors)
    _no_unknown(tests, required_tests, "verification.adversarial_evidence[0].tests", errors)
    if any(tests.get(name) is not True for name in required_tests):
        errors.append("all required adversarial test classes must pass before verification.")
    if record.get("cleanup_passed") is not True:
        errors.append("verification evidence cleanup_passed must be true.")


def _validate_references(root: dict[str, Any], snapshot_total: int, limits: dict[str, int], errors: list[str]) -> None:
    if snapshot_total > limits.get("max_filesystem_bytes", 0):
        errors.append("workspace.snapshot total size cannot exceed runtime.limits.max_filesystem_bytes.")
    runtime = root.get("runtime") if isinstance(root.get("runtime"), dict) else {}
    workspace = root.get("workspace") if isinstance(root.get("workspace"), dict) else {}
    toolchain = workspace.get("toolchain") if isinstance(workspace.get("toolchain"), dict) else {}
    pairs = (("node", "node_version"), ("just-bash", "package_version"), ("agent-host-isolation", "agent_host_isolation_version"))
    for tool_name, runtime_name in pairs:
        if toolchain.get(tool_name) != runtime.get(runtime_name):
            errors.append(f"workspace.toolchain.{tool_name} must match runtime.{runtime_name}.")
    task = root.get("task") if isinstance(root.get("task"), dict) else {}
    gate = root.get("resultGate") if isinstance(root.get("resultGate"), dict) else {}
    artifact = gate.get("artifact_import", {}) if isinstance(gate, dict) else {}
    source = artifact.get("source") if isinstance(artifact, dict) else None
    if isinstance(source, str) and source.startswith("/"):
        base = PurePosixPath(source)
        expected_artifacts = task.get("expected_artifacts")
        if not isinstance(expected_artifacts, list):
            return
        for item in expected_artifacts:
            if isinstance(item, str) and item.startswith("/") and not PurePosixPath(item).is_relative_to(base):
                errors.append("task.expected_artifacts must remain within resultGate.artifact_import.source.")
                break
