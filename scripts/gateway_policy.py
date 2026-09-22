#!/usr/bin/env python3
"""Pure policy adapter for task-scoped gateway and broker decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any

from manifest_v2 import validate_v2


class InMemoryUsageLedger:
    """Atomic test/local ledger. Production gateways must supply a durable equivalent."""

    def __init__(self) -> None:
        self._used: dict[tuple[str, str], int] = {}
        self._lock = Lock()

    def consume(self, task_id: str, grant_id: str, amount: int, limit: int) -> tuple[bool, int]:
        key = (task_id, grant_id)
        with self._lock:
            used = self._used.get(key, 0)
            if amount > limit - used:
                return False, used
            used += amount
            self._used[key] = used
            return True, used


def decide(
    manifest: dict[str, Any],
    request: dict[str, Any],
    *,
    ledger: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Match a request to one exact manifest grant; default deny on every mismatch."""
    now = now or datetime.now(timezone.utc)
    task_id = manifest.get("task", {}).get("id") if isinstance(manifest, dict) else None
    errors = validate_v2(manifest)
    if errors:
        return _deny(task_id, "manifest validation failed")
    if request.get("task_id") != task_id:
        return _deny(task_id, "task_id mismatch")
    required = {"destination", "scope", "protocol", "port", "method", "bytes"}
    if required - request.keys():
        return _deny(task_id, "request is missing bounded grant fields")
    if not isinstance(request.get("bytes"), int) or isinstance(request.get("bytes"), bool) or request["bytes"] < 0:
        return _deny(task_id, "request byte count is invalid")

    for grant in manifest.get("gateway", {}).get("grants", []):
        if any(request.get(key) != grant.get(key) for key in ("destination", "scope", "protocol", "port", "method")):
            continue
        try:
            expiry = datetime.fromisoformat(grant["expiry"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError):
            return _deny(task_id, "grant expiry is invalid")
        if now >= expiry:
            return _deny(task_id, "grant is expired", grant.get("audit_record"))
        if ledger is None or not callable(getattr(ledger, "consume", None)):
            return _deny(task_id, "a cumulative grant usage ledger is required", grant.get("audit_record"))
        allowed, used = ledger.consume(task_id, grant["audit_record"], request["bytes"], grant["max_bytes"])
        if not allowed:
            return _deny(task_id, "grant byte limit exceeded", grant.get("audit_record"))
        return {
            "allowed": True,
            "task_id": task_id,
            "reason": "matched exact active grant",
            "audit_record": grant["audit_record"],
            "purpose": grant["purpose"],
            "expiry": grant["expiry"],
            "bytes_used": used,
            "bytes_remaining": grant["max_bytes"] - used,
        }
    return _deny(task_id, "no exact active grant matched")


def _deny(task_id: Any, reason: str, audit_record: str | None = None) -> dict[str, Any]:
    return {
        "allowed": False,
        "task_id": task_id,
        "reason": reason,
        "audit_record": audit_record,
    }
