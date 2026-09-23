#!/usr/bin/env python3
"""One-shot boundary from broker bytes to a standard, networkless inspect input."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

from inspect_fetch_store import FetchAuditStore, FetchStoreError
from just_bash_manifest import canonical_manifest_hash, validate_just_bash_v2


class SnapshotGateDenied(ValueError):
    """The broker result cannot be imported into a standard inspect attempt."""


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class InspectSnapshotGate:
    """Validate and atomically consume one broker result before runtime construction."""

    def __init__(self, store: FetchAuditStore | str):
        self._store = store if isinstance(store, FetchAuditStore) else FetchAuditStore(store)

    def _deny(self, source_manifest: dict[str, Any], reason: str) -> None:
        task = source_manifest.get("task", {}) if isinstance(source_manifest, dict) else {}
        if isinstance(task.get("id"), str) and isinstance(task.get("attempt_id"), str):
            try:
                self._store.record(task_id=task["id"], attempt_id=task["attempt_id"],
                                   manifest_hash=canonical_manifest_hash(source_manifest),
                                   decision="result_gate", reason=reason,
                                   payload={"result_gate": "denied", "cleanup_outcome": "rejected"})
            except FetchStoreError:
                pass
        raise SnapshotGateDenied(reason)

    def import_snapshot(self, source_manifest: dict[str, Any], source_record: dict[str, Any],
                        body: bytes | bytearray | memoryview,
                        target_manifest: dict[str, Any]) -> dict[str, Any]:
        """Return only content-checked ``snapshotFiles`` and approved standard manifest."""
        try:
            content = bytes(body)
        except Exception as exc:
            self._deny(source_manifest, "broker body is not bytes")
            raise AssertionError from exc
        try:
            source_hash = canonical_manifest_hash(source_manifest)
            task = source_manifest["task"]
            target = deepcopy(target_manifest)
            if source_record.get("event_id") is None:
                raise SnapshotGateDenied("broker record has no durable event_id")
            if source_record.get("manifest_hash") != source_hash:
                raise SnapshotGateDenied("broker record manifest hash mismatch")
            if source_record.get("task_id") != task["id"] or source_record.get("attempt_id") != task["attempt_id"]:
                raise SnapshotGateDenied("broker record task or attempt mismatch")
            if source_record.get("result_gate") != "pending" or source_record.get("verification") != "unverified":
                raise SnapshotGateDenied("broker result is not pending and unverified")
            digest = _sha256(content)
            if source_record.get("size_bytes") != len(content) or source_record.get("sha256") != digest:
                raise SnapshotGateDenied("broker body identity mismatch")
            grant = next((item for item in source_manifest.get("gateway", {}).get("grants", [])
                          if item.get("audit_record") == source_record.get("audit_record")
                          and item.get("task_id") == task["id"] and item.get("attempt_id") == task["attempt_id"]), None)
            if grant is None or len(content) > grant["max_bytes"]:
                raise SnapshotGateDenied("broker body exceeds the bound grant budget")
            target_task = target.get("task", {})
            if target_task.get("id") != task["id"] or target_task.get("attempt_id") == task["attempt_id"]:
                raise SnapshotGateDenied("target must reuse task id with a new attempt")
            runtime = target.get("runtime", {})
            gateway = target.get("gateway", {})
            if runtime.get("profile_variant") != "standard" or gateway.get("task_network") is not None or gateway.get("grants") != []:
                raise SnapshotGateDenied("target must be a standard networkless manifest")
            paths = target["workspace"]["snapshot"]["paths"]
            if len(paths) != 1 or paths[0].get("type") != "regular":
                raise SnapshotGateDenied("target must declare exactly one regular snapshot file")
            entry = paths[0]
            if not isinstance(entry.get("path"), str) or not entry["path"]:
                raise SnapshotGateDenied("target snapshot path is invalid")
            entry["size_bytes"] = len(content)
            entry["hash"] = digest
            target["workspace"]["snapshot"]["hash"] = _sha256(json.dumps(paths, separators=(",", ":"), ensure_ascii=False).encode())
            # Imported evidence has not undergone the exact-runtime adversarial suite.
            target["verification"] = {"status": "unverified", "adversarial_evidence": []}
            errors = validate_just_bash_v2(target)
            if errors:
                raise SnapshotGateDenied("target manifest is invalid: " + "; ".join(errors))
            target_hash = canonical_manifest_hash(target)
            self._store.consume_result(source_event_id=source_record["event_id"], task_id=task["id"],
                                       source_attempt_id=task["attempt_id"], source_manifest_hash=source_hash,
                                       target_attempt_id=target_task["attempt_id"], target_manifest_hash=target_hash,
                                       body_hash=digest, size_bytes=len(content), source_record=source_record)
            return {"manifest": target, "snapshotFiles": {entry["path"]: content},
                    "manifest_hash": target_hash, "source_event_id": source_record["event_id"],
                    "approved": True}
        except (KeyError, TypeError, SnapshotGateDenied, FetchStoreError) as exc:
            self._deny(source_manifest, str(exc))
            raise AssertionError from exc


def import_fetch_snapshot(source_manifest: dict[str, Any], source_record: dict[str, Any],
                          body: bytes | bytearray | memoryview, target_manifest: dict[str, Any],
                          *, store: FetchAuditStore | str) -> dict[str, Any]:
    return InspectSnapshotGate(store).import_snapshot(source_manifest, source_record, body, target_manifest)


def _main() -> int:
    import base64
    import sys

    try:
        request = json.load(sys.stdin)
        result = import_fetch_snapshot(
            request["source_manifest"], request["source_record"],
            base64.b64decode(request["body_base64"], validate=True), request["target_manifest"],
            store=request["audit_store"],
        )
        result["snapshotFiles"] = {path: base64.b64encode(value).decode("ascii")
                                   for path, value in result["snapshotFiles"].items()}
        # Preserve manifest object key order: the Node runtime hashes the exact
        # JSON.stringify ordering of snapshot entries.
        json.dump(result, sys.stdout)
        return 0
    except (SnapshotGateDenied, KeyError, TypeError, ValueError) as exc:
        json.dump({"error": str(exc)}, sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
