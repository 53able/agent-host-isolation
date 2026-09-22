#!/usr/bin/env python3
"""Create an auditable InspectBlocked escalation request without widening a task."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from just_bash_manifest import canonical_manifest_hash, validate_just_bash_v2
from manifest_v2 import SAFE_ID, validate_v2


def _manifest_hash(manifest: dict[str, Any]) -> str:
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _safe_audit_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.startswith("~") or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def build_escalation_request(
    source_manifest: dict[str, Any],
    blocked_event: dict[str, Any],
    target_manifest: dict[str, Any],
    audit_record: str,
) -> dict[str, Any]:
    source_errors = validate_just_bash_v2(source_manifest)
    if source_errors:
        raise ValueError("source manifest is invalid: " + "; ".join(source_errors))
    target_errors = validate_v2(target_manifest)
    if target_errors:
        raise ValueError("target manifest is invalid: " + "; ".join(target_errors))
    if target_manifest["task"].get("id") != source_manifest["task"]["id"]:
        raise ValueError("target manifest must retain the same task.id")
    if not isinstance(blocked_event, dict) or any(
        blocked_event.get(key) != expected for key, expected in (
            ("event", "InspectBlocked"), ("outcome", "blocked"), ("exit_code", 127),
            ("host_shell_fallback", False),
        )
    ) or blocked_event.get("escalation") != {"automatic": False, "requested": False}:
        raise ValueError("a fail-closed InspectBlocked event is required")
    missing_capability = blocked_event.get("missing_capability")
    if not isinstance(missing_capability, str) or not missing_capability.strip():
        raise ValueError("InspectBlocked missing_capability must be non-empty")
    source_hash = canonical_manifest_hash(source_manifest)
    expected_source = {
        "task_id": source_manifest["task"]["id"],
        "attempt_id": source_manifest["task"]["attempt_id"],
        "manifest_hash": source_hash,
    }
    if blocked_event.get("source") != expected_source:
        raise ValueError("InspectBlocked source identity must match the source manifest")
    source_attempt = source_manifest["task"]["attempt_id"]
    target_attempt = target_manifest["task"].get("attempt_id")
    if not isinstance(target_attempt, str) or not SAFE_ID.fullmatch(target_attempt) or target_attempt == source_attempt:
        raise ValueError("target manifest must identify a new valid attempt")
    if target_manifest["task"].get("profile") != "guest-build" or target_manifest["runtime"].get("kind") != "apple-container":
        raise ValueError("target manifest must select guest-build on apple-container")
    target_hash = _manifest_hash(target_manifest)
    if target_hash == source_hash:
        raise ValueError("target manifest must be distinct from the source manifest")
    if not _safe_audit_path(audit_record):
        raise ValueError("audit_record must be a safe relative path")
    return {
        "event": "InspectBlocked",
        "task_id": source_manifest["task"]["id"],
        "source_attempt_id": source_attempt,
        "source_manifest_hash": source_hash,
        "blocked_event_hash": _manifest_hash(blocked_event),
        "missing_capability": missing_capability,
        "target_profile": "guest-build",
        "target_runtime_kind": "apple-container",
        "target_attempt_id": target_attempt,
        "target_manifest_hash": target_hash,
        "automatic": False,
        "audit_record": audit_record,
    }


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "Usage: python3 scripts/just_bash_contract.py SOURCE_MANIFEST BLOCKED_EVENT_JSON TARGET_MANIFEST AUDIT_RECORD",
            file=sys.stderr,
        )
        return 2
    try:
        source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        blocked_event = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        target = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
        request = build_escalation_request(source, blocked_event, target, sys.argv[4])
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(request, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
