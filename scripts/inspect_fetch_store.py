#!/usr/bin/env python3
"""Durable, host-private state for the inspect fetch broker.

The store is deliberately small: grant state and append-only audit events live
in SQLite, and all state transitions use ``BEGIN IMMEDIATE`` so a restart or a
concurrent caller cannot reset a byte budget or re-arm a revoked grant.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FetchStoreError(RuntimeError):
    """The broker must fail closed when durable state cannot be written."""


def _private_db_path(path: str | os.PathLike[str]) -> Path:
    db = Path(path).expanduser()
    if db.name in {"", ".", ".."} or db.is_absolute() is False:
        raise FetchStoreError("audit database path must be absolute")
    parent = db.parent
    if not parent.exists():
        raise FetchStoreError("audit database parent must already exist")
    parent_stat = os.lstat(parent)
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise FetchStoreError("audit database parent must be a directory, not a symlink")
    if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise FetchStoreError("audit database parent must be private and owned by the current user")
    if db.exists():
        db_stat = os.lstat(db)
        if stat.S_ISLNK(db_stat.st_mode) or not stat.S_ISREG(db_stat.st_mode):
            raise FetchStoreError("audit database must be a regular file, not a symlink")
        if db_stat.st_uid != os.getuid():
            raise FetchStoreError("audit database must be owned by the current user")
        os.chmod(db, 0o600)
    return db


class FetchAuditStore:
    """SQLite-backed grant ledger and append-only audit sink."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = _private_db_path(path)
        try:
            self._db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            self._db.execute("PRAGMA busy_timeout=5000")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            os.chmod(self.path, 0o600)
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS grants (
                    task_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    audit_record TEXT NOT NULL UNIQUE,
                    manifest_hash TEXT NOT NULL,
                    expiry TEXT NOT NULL,
                    max_bytes INTEGER NOT NULL CHECK(max_bytes > 0),
                    used_bytes INTEGER NOT NULL DEFAULT 0 CHECK(used_bytes >= 0),
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
                    PRIMARY KEY(task_id, attempt_id, audit_record)
                );
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    task_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    audit_record TEXT,
                    manifest_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    bytes INTEGER NOT NULL DEFAULT 0 CHECK(bytes >= 0),
                    payload TEXT NOT NULL CHECK(json_valid(payload) = 1),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CHECK(decision IN ('request', 'allowed', 'redirect', 'denied', 'budget', 'usage', 'revoked', 'result_gate'))
                );
                CREATE TABLE IF NOT EXISTS result_imports (
                    source_event_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    source_attempt_id TEXT NOT NULL,
                    source_manifest_hash TEXT NOT NULL,
                    target_attempt_id TEXT NOT NULL,
                    target_manifest_hash TEXT NOT NULL UNIQUE,
                    body_hash TEXT NOT NULL,
                    bytes INTEGER NOT NULL CHECK(bytes >= 0),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TRIGGER IF NOT EXISTS events_no_update
                BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS events_no_delete
                BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
                """
            )
        except (OSError, sqlite3.Error) as exc:
            raise FetchStoreError(f"cannot initialize audit store: {exc}") from exc

    def register_manifest(self, manifest: dict[str, Any], manifest_hash: str) -> None:
        task = manifest["task"]
        grants = manifest.get("gateway", {}).get("grants", [])
        try:
            self._db.execute("BEGIN IMMEDIATE")
            for grant in grants:
                row = self._db.execute(
                    "SELECT task_id, attempt_id, manifest_hash, expiry, max_bytes FROM grants WHERE audit_record = ?",
                    (grant["audit_record"],),
                ).fetchone()
                if row is not None and tuple(row) != (grant["task_id"], grant["attempt_id"], manifest_hash, grant["expiry"], grant["max_bytes"]):
                    raise FetchStoreError("audit_record is already bound to another grant")
                self._db.execute(
                    "INSERT OR IGNORE INTO grants(task_id, attempt_id, audit_record, manifest_hash, expiry, max_bytes) VALUES (?, ?, ?, ?, ?, ?)",
                    (grant["task_id"], grant["attempt_id"], grant["audit_record"], manifest_hash, grant["expiry"], grant["max_bytes"]),
                )
            self._db.commit()
        except FetchStoreError:
            self._db.rollback()
            raise
        except sqlite3.Error as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot register grant: {exc}") from exc

    def _event(self, *, task_id: str, attempt_id: str, manifest_hash: str, decision: str,
               audit_record: str | None = None, reason: str | None = None,
               bytes_count: int = 0, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        event = {
            **(payload or {}),
            "event_id": uuid.uuid4().hex,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "audit_record": audit_record,
            "manifest_hash": manifest_hash,
            "decision": decision,
            "reason": reason,
            "bytes": bytes_count,
        }
        self._db.execute(
            "INSERT INTO events(event_id, task_id, attempt_id, audit_record, manifest_hash, decision, reason, bytes, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event["event_id"], task_id, attempt_id, audit_record, manifest_hash, decision, reason, bytes_count, json.dumps(event, sort_keys=True)),
        )
        return event

    def record(self, *, task_id: str, attempt_id: str, manifest_hash: str, decision: str,
               audit_record: str | None = None, reason: str | None = None,
               bytes_count: int = 0, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if decision not in {"redirect", "denied", "budget", "usage"}:
            raise FetchStoreError("authorization decisions require a transactional store method")
        try:
            self._db.execute("BEGIN IMMEDIATE")
            event = self._event(task_id=task_id, attempt_id=attempt_id, manifest_hash=manifest_hash,
                                decision=decision, audit_record=audit_record, reason=reason,
                                bytes_count=bytes_count, payload=payload)
            self._db.commit()
            return event
        except sqlite3.Error as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot append audit event: {exc}") from exc

    @staticmethod
    def _check_grant_row(row: tuple[Any, ...] | None) -> None:
        if row is None:
            raise FetchStoreError("grant is not registered for this manifest")
        expiry, revoked = row
        if revoked:
            raise FetchStoreError("grant revoked")
        try:
            expires_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise FetchStoreError("grant expiry is invalid") from exc
        if expires_at.tzinfo is None or datetime.now(timezone.utc) >= expires_at:
            raise FetchStoreError("grant expired")

    def begin_request(self, grant: dict[str, Any], manifest_hash: str,
                      payload: dict[str, Any]) -> dict[str, Any]:
        """Order a request after DNS against concurrent durable revocation."""
        try:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT expiry, revoked FROM grants WHERE task_id=? AND attempt_id=? AND audit_record=? AND manifest_hash=?",
                (grant["task_id"], grant["attempt_id"], grant["audit_record"], manifest_hash),
            ).fetchone()
            self._check_grant_row(row)
            event = self._event(task_id=grant["task_id"], attempt_id=grant["attempt_id"],
                                manifest_hash=manifest_hash, decision="request",
                                audit_record=grant["audit_record"], payload=payload)
            self._db.commit()
            return event
        except FetchStoreError:
            self._db.rollback()
            raise
        except sqlite3.Error as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot begin request: {exc}") from exc

    def record_result_denied(self, *, task_id: str, attempt_id: str,
                             manifest_hash: str, reason: str) -> dict[str, Any]:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            event = self._event(task_id=task_id, attempt_id=attempt_id,
                                manifest_hash=manifest_hash, decision="result_gate", reason=reason,
                                payload={"result_gate": "denied", "cleanup_outcome": "rejected"})
            self._db.commit()
            return event
        except sqlite3.Error as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot record result gate denial: {exc}") from exc

    def consume(self, grant: dict[str, Any], manifest_hash: str, amount: int,
                payload: dict[str, Any] | None = None) -> int:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT used_bytes, max_bytes, expiry, revoked FROM grants WHERE task_id=? AND attempt_id=? AND audit_record=? AND manifest_hash=?",
                (grant["task_id"], grant["attempt_id"], grant["audit_record"], manifest_hash),
            ).fetchone()
            if row is None:
                raise FetchStoreError("grant is not registered for this manifest")
            used, maximum, expiry, revoked = row
            self._check_grant_row((expiry, revoked))
            if amount > maximum - used:
                self._event(task_id=grant["task_id"], attempt_id=grant["attempt_id"], manifest_hash=manifest_hash,
                            decision="budget", audit_record=grant["audit_record"],
                            reason="grant byte budget exceeded", bytes_count=amount,
                            payload={**(payload or {}), "cleanup_outcome": "revoke_required"})
                self._db.commit()
                raise FetchStoreError("grant byte budget exceeded")
            new_used = used + amount
            self._db.execute("UPDATE grants SET used_bytes=? WHERE task_id=? AND attempt_id=? AND audit_record=?",
                             (new_used, grant["task_id"], grant["attempt_id"], grant["audit_record"]))
            self._event(task_id=grant["task_id"], attempt_id=grant["attempt_id"], manifest_hash=manifest_hash,
                        decision="usage", audit_record=grant["audit_record"], bytes_count=amount,
                        payload={"used_bytes": new_used, "max_bytes": maximum})
            self._db.commit()
            return new_used
        except FetchStoreError:
            self._db.rollback()
            raise
        except sqlite3.Error as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot consume grant budget: {exc}") from exc

    def ensure_active(self, grant: dict[str, Any], manifest_hash: str) -> None:
        try:
            row = self._db.execute(
                "SELECT expiry, revoked FROM grants WHERE task_id=? AND attempt_id=? AND audit_record=? AND manifest_hash=?",
                (grant["task_id"], grant["attempt_id"], grant["audit_record"], manifest_hash),
            ).fetchone()
            self._check_grant_row(row)
        except sqlite3.Error as exc:
            raise FetchStoreError(f"cannot read grant state: {exc}") from exc

    def record_allowed(self, grant: dict[str, Any], manifest_hash: str,
                       *, bytes_count: int = 0,
                       payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Append an allowed result only while its durable grant is active.

        The grant check and event insert share one write transaction, so a
        concurrent revoke cannot leave an allowed event after revocation.
        """
        try:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT expiry, revoked FROM grants WHERE task_id=? AND attempt_id=? AND audit_record=? AND manifest_hash=?",
                (grant["task_id"], grant["attempt_id"], grant["audit_record"], manifest_hash),
            ).fetchone()
            self._check_grant_row(row)
            event = self._event(task_id=grant["task_id"], attempt_id=grant["attempt_id"],
                                manifest_hash=manifest_hash, decision="allowed",
                                audit_record=grant["audit_record"], bytes_count=bytes_count,
                                payload=payload)
            self._db.commit()
            return event
        except FetchStoreError:
            self._db.rollback()
            raise
        except sqlite3.Error as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot append allowed audit event: {exc}") from exc

    def revoke(self, *, task_id: str, attempt_id: str, manifest_hash: str, reason: str,
               audit_record: str | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("UPDATE grants SET revoked=1 WHERE task_id=? AND attempt_id=? AND manifest_hash=?",
                             (task_id, attempt_id, manifest_hash))
            event = self._event(task_id=task_id, attempt_id=attempt_id, manifest_hash=manifest_hash,
                                decision="revoked", audit_record=audit_record, reason=reason,
                                payload={**(payload or {}), "cleanup_outcome": "revoked", "revocation_outcome": "grant_revoked"})
            self._db.commit()
            return event
        except sqlite3.Error as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot revoke grant: {exc}") from exc

    def events(self, *, task_id: str | None = None, attempt_id: str | None = None,
               audit_record: str | None = None) -> list[dict[str, Any]]:
        try:
            clauses = []
            values: list[str] = []
            for name, value in (("task_id", task_id), ("attempt_id", attempt_id), ("audit_record", audit_record)):
                if value is not None:
                    clauses.append(f"{name} = ?")
                    values.append(value)
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            rows = self._db.execute(f"SELECT payload FROM events{where} ORDER BY sequence", values).fetchall()
            return [json.loads(row[0]) for row in rows]
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise FetchStoreError(f"cannot read audit events: {exc}") from exc

    def consume_result(self, *, source_event_id: str, task_id: str, source_attempt_id: str,
                       source_manifest_hash: str, target_attempt_id: str,
                       target_manifest_hash: str, body_hash: str, size_bytes: int,
                       source_record: dict[str, Any] | None = None) -> dict[str, Any]:
        """Atomically consume one pending allowed event and bind its target manifest."""
        try:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT payload FROM events WHERE event_id=? AND task_id=? AND attempt_id=? AND manifest_hash=? AND decision='allowed'",
                (source_event_id, task_id, source_attempt_id, source_manifest_hash),
            ).fetchone()
            if row is None:
                raise FetchStoreError("source event is not an allowed event for this attempt")
            source = json.loads(row[0])
            if source.get("result_gate") != "pending":
                raise FetchStoreError("source event is not pending")
            grant_row = self._db.execute(
                "SELECT expiry, revoked FROM grants WHERE task_id=? AND attempt_id=? AND audit_record=? AND manifest_hash=?",
                (task_id, source_attempt_id, source.get("audit_record"), source_manifest_hash),
            ).fetchone()
            self._check_grant_row(grant_row)
            for key, expected in (("task_id", task_id), ("attempt_id", source_attempt_id),
                                  ("manifest_hash", source_manifest_hash), ("size_bytes", size_bytes),
                                  ("sha256", body_hash)):
                if source.get(key) != expected:
                    raise FetchStoreError(f"source event {key} mismatch")
            if source_record is not None:
                for key in ("audit_record", "purpose", "url", "method", "redirect_hops"):
                    if source_record.get(key) != source.get(key):
                        raise FetchStoreError(f"source event {key} mismatch")
            existing = self._db.execute(
                "SELECT source_event_id FROM result_imports WHERE source_event_id=? OR target_manifest_hash=?",
                (source_event_id, target_manifest_hash),
            ).fetchone()
            if existing is not None:
                raise FetchStoreError("source event or target manifest was already consumed")
            self._db.execute(
                "INSERT INTO result_imports(source_event_id, task_id, source_attempt_id, source_manifest_hash, target_attempt_id, target_manifest_hash, body_hash, bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (source_event_id, task_id, source_attempt_id, source_manifest_hash, target_attempt_id,
                 target_manifest_hash, body_hash, size_bytes),
            )
            event = self._event(task_id=task_id, attempt_id=target_attempt_id,
                                manifest_hash=target_manifest_hash, decision="result_gate",
                                audit_record=source.get("audit_record"), bytes_count=size_bytes,
                                payload={"source_event_id": source_event_id, "source_manifest_hash": source_manifest_hash,
                                         "target_manifest_hash": target_manifest_hash, "result_gate": "approved"})
            self._db.commit()
            return event
        except FetchStoreError:
            self._db.rollback()
            raise
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            self._db.rollback()
            raise FetchStoreError(f"cannot consume result gate event: {exc}") from exc

    def close(self) -> None:
        self._db.close()
