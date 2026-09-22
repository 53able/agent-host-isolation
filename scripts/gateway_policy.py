#!/usr/bin/env python3
"""Pure policy adapter for task-scoped gateway and broker decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def decide(manifest: dict[str, Any], request: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Match a request to one exact manifest grant; default deny on every mismatch."""
    now = now or datetime.now(timezone.utc)
    task_id = manifest.get("task", {}).get("id")
    if request.get("task_id") != task_id:
        return _deny(task_id, "task_id mismatch")
    required = {"destination", "scope", "protocol", "port", "method", "bytes"}
    if required - request.keys():
        return _deny(task_id, "request is missing bounded grant fields")
    if not isinstance(request.get("bytes"), int) or request["bytes"] < 0:
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
        if request["bytes"] > grant.get("max_bytes", -1):
            return _deny(task_id, "grant byte limit exceeded", grant.get("audit_record"))
        return {
            "allowed": True,
            "task_id": task_id,
            "reason": "matched exact active grant",
            "audit_record": grant["audit_record"],
            "purpose": grant["purpose"],
            "expiry": grant["expiry"],
        }
    return _deny(task_id, "no exact active grant matched")


def _deny(task_id: Any, reason: str, audit_record: str | None = None) -> dict[str, Any]:
    return {
        "allowed": False,
        "task_id": task_id,
        "reason": reason,
        "audit_record": audit_record,
    }
