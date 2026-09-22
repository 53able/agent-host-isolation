#!/usr/bin/env python3
"""Task state and evidence contracts for isolated Apple Container execution."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

TERMINAL_STATES = {"Succeeded", "Failed", "Cancelled", "CleanupFailed"}
TRANSITIONS = {
    "Pending": {"Prepared", "Failed", "Cancelled"},
    "Prepared": {"Running", "Failed", "Cancelled", "CleanupFailed"},
    "Running": {"Waiting", "Stopping", "Succeeded", "Failed", "Cancelled"},
    "Waiting": {"Running", "Stopping", "Failed", "Cancelled"},
    "Stopping": {"Stopped", "Failed", "CleanupFailed"},
    "Stopped": {"Resuming", "Cancelled", "CleanupFailed"},
    "Resuming": {"Running", "Failed", "Cancelled"},
}
EVENT_TYPES = {
    "container.inspect", "container.logs", "container.boot_logs", "container.stats",
    "apple.system_log", "gateway.grant", "gateway.deny", "broker.decision",
    "watchdog.timeout", "cleanup.result", "checkpoint.saved", "checkpoint.restored",
    "task.transition",
}
HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def require_transition(current: str, target: str) -> None:
    if current in TERMINAL_STATES or target not in TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid task transition: {current} -> {target}")


def validate_checkpoint(checkpoint: dict[str, Any], *, task_id: str, manifest_hash: str, workspace_hash: str) -> list[str]:
    errors: list[str] = []
    expected = {
        "contract": "application-level",
        "task_id": task_id,
        "manifest_hash": manifest_hash,
        "workspace_hash": workspace_hash,
    }
    for key, value in expected.items():
        if checkpoint.get(key) != value:
            errors.append(f"checkpoint.{key} does not match the active task contract.")
    if not HASH.fullmatch(str(checkpoint.get("state_hash", ""))):
        errors.append("checkpoint.state_hash must be an immutable sha256 digest.")
    if checkpoint.get("contains_direct_credentials") is not False:
        errors.append("checkpoint containing directly inherited credentials cannot be resumed.")
    if checkpoint.get("leases_revalidated") is not True:
        errors.append("resume requires credential and network leases to be revalidated and reissued.")
    return errors


def validate_event(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"event_version", "type", "timestamp", "task_id", "manifest_hash", "workspace_hash", "source", "payload"}
    missing = required - event.keys()
    if missing:
        errors.append("event missing required keys: " + ", ".join(sorted(missing)))
    if event.get("event_version") != 1:
        errors.append("event.event_version must be 1.")
    if event.get("type") not in EVENT_TYPES:
        errors.append("event.type is not recognized.")
    if not isinstance(event.get("task_id"), str) or not event.get("task_id"):
        errors.append("event.task_id must be non-empty.")
    for key in ("manifest_hash", "workspace_hash"):
        if not HASH.fullmatch(str(event.get(key, ""))):
            errors.append(f"event.{key} must be a sha256 digest.")
    try:
        timestamp = datetime.fromisoformat(str(event.get("timestamp", "")).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
    except ValueError:
        errors.append("event.timestamp must be an ISO-8601 timestamp with timezone.")
    if not isinstance(event.get("source"), str) or not event.get("source"):
        errors.append("event.source must be non-empty.")
    if not isinstance(event.get("payload"), dict):
        errors.append("event.payload must be an object.")
    return errors


def verification_status(required_results: dict[str, str]) -> str:
    """Return the only honest aggregate status for the seven adversarial classes."""
    expected = {"mount", "credential", "network", "command-path", "resource", "supply-chain", "side-effect"}
    if set(required_results) != expected:
        return "unverified"
    if any(value == "blocked" for value in required_results.values()):
        return "blocked"
    if all(value == "passed" for value in required_results.values()):
        return "verified for tested configuration"
    return "unverified"
