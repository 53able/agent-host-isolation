#!/usr/bin/env python3
"""Host-only, read-only fetch broker for a future network-derived inspect flow.

The broker returns bytes for a new, separately validated standard inspect snapshot.
It never exposes a network handle to JustBash or makes a derived manifest executable.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from copy import deepcopy
from datetime import datetime, timezone
from threading import Event, Lock
from typing import Any
from urllib.parse import urljoin, urlsplit

from inspect_fetch_store import FetchAuditStore, FetchStoreError
from inspect_fetch_resolver import DNSResolutionError, HostDNSResolver
from just_bash_manifest import canonical_manifest_hash, validate_just_bash_v2

_UNAVAILABLE = "network-derived JustBash is unavailable until a request-time enforcing gateway adapter is installed."
_REDIRECTS = {301, 302, 303, 307, 308}


class FetchDenied(ValueError):
    pass


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, port: int, timeout: float):
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class InspectFetchBroker:
    """One attempt's grant state. All request hops are checked before connecting."""

    def __init__(self, manifest: dict[str, Any], *, timeout: float = 5.0, cancel: Event | None = None,
                 audit_store: FetchAuditStore | str | None = None, audit_store_path: str | None = None,
                 dns_timeout: float = 2.0, resolver: HostDNSResolver | None = None):
        errors = [error for error in validate_just_bash_v2(manifest) if error != _UNAVAILABLE]
        if errors or manifest.get("runtime", {}).get("profile_variant") != "network-derived":
            raise FetchDenied("invalid network-derived broker contract: " + "; ".join(errors))
        if not 0 < timeout <= 30:
            raise ValueError("timeout must be between 0 and 30 seconds")
        self._manifest = deepcopy(manifest)
        self._manifest_hash = canonical_manifest_hash(self._manifest)
        self._timeout = timeout
        self._cancel = cancel or Event()
        self._resolver = resolver or HostDNSResolver(timeout=dns_timeout)
        self._lock = Lock()
        self._revoked = False
        if audit_store is not None and audit_store_path is not None:
            raise ValueError("provide only one audit store")
        try:
            self._store = audit_store if isinstance(audit_store, FetchAuditStore) else FetchAuditStore(audit_store_path or audit_store)
            self._store.register_manifest(self._manifest, self._manifest_hash)
        except FetchStoreError as exc:
            raise FetchDenied(f"audit persistence unavailable: {exc}") from exc

    @property
    def audit(self) -> list[dict[str, Any]]:
        return self._store.events(task_id=self._manifest["task"]["id"], attempt_id=self._manifest["task"]["attempt_id"])

    def revoke(self, reason: str = "cancelled", *, grant: dict[str, Any] | None = None,
               context: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._revoked = True
            try:
                self._store.revoke(task_id=self._manifest["task"]["id"], attempt_id=self._manifest["task"]["attempt_id"],
                                   manifest_hash=self._manifest_hash, reason=reason,
                                   audit_record=grant["audit_record"] if grant else None, payload=context)
            except FetchStoreError as exc:
                raise FetchDenied(f"audit persistence unavailable: {exc}") from exc

    def _check_active(self, grant: dict[str, Any], deadline: float) -> None:
        if self._cancel.is_set():
            raise FetchDenied("cancelled")
        if time.monotonic() >= deadline:
            raise FetchDenied("timeout")
        with self._lock:
            if self._revoked:
                raise FetchDenied("grant revoked")
        expiry = datetime.fromisoformat(grant["expiry"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) >= expiry:
            raise FetchDenied("grant expired")

    def _check_active_locked(self, grant: dict[str, Any], deadline: float) -> None:
        """Final response check; caller holds ``self._lock``."""
        if self._cancel.is_set():
            raise FetchDenied("cancelled")
        if time.monotonic() >= deadline:
            raise FetchDenied("timeout")
        if self._revoked:
            raise FetchDenied("grant revoked")
        expiry = datetime.fromisoformat(grant["expiry"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) >= expiry:
            raise FetchDenied("grant expired")

    def _authorize(self, url: str, method: str, scope: str, purpose: str, deadline: float) -> tuple[dict[str, Any], str, str, int]:
        try:
            parsed = urlsplit(url)
            port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        except (TypeError, ValueError) as exc:
            raise FetchDenied("invalid URL") from exc
        # HTTPS only. Deny URL ambiguity, embedded credentials, IP literals, query,
        # fragments, escaped path separators, and noncanonical dot segments.
        if parsed.scheme != "https" or not parsed.hostname or not 1 <= port <= 65535 or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise FetchDenied("URL is outside the read-only HTTPS policy")
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise FetchDenied("IP literal denied")
        path = parsed.path or "/"
        if not re.fullmatch(r"/[A-Za-z0-9._~/-]*", path) or "//" in path or any(part in {".", ".."} for part in path.split("/")):
            raise FetchDenied("noncanonical path denied")
        origin = f"https://{parsed.hostname}:{port}"
        for grant in self._manifest["gateway"]["grants"]:
            if (
                grant["task_id"] == self._manifest["task"]["id"]
                and grant["attempt_id"] == self._manifest["task"]["attempt_id"]
                and grant["origin"] == origin
                and grant["port"] == port
                and method in grant["methods"]
                and grant["scope"] == scope
                and grant["purpose"] == purpose
                and path.startswith(grant["path_prefix"])
            ):
                self._check_active(grant, deadline)
                try:
                    self._store.ensure_active(grant, self._manifest_hash)
                except FetchStoreError as exc:
                    raise FetchDenied(str(exc)) from exc
                return grant, parsed.hostname, path, port
        raise FetchDenied("no exact active grant matched")

    def _consume(self, grant: dict[str, Any], amount: int, context: dict[str, Any] | None = None) -> None:
        with self._lock:
            if self._revoked:
                raise FetchDenied("grant revoked")
        try:
            self._store.consume(grant, self._manifest_hash, amount, payload=context)
        except FetchStoreError as exc:
            raise FetchDenied(str(exc)) from exc

    @staticmethod
    def _request_context(url: str, method: str, scope: str, purpose: str) -> dict[str, Any]:
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
            port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
            origin = f"{parsed.scheme}://{hostname}:{port}" if hostname else None
            path = parsed.path or "/"
        except (TypeError, ValueError):
            origin, port, path = None, None, None
        return {"origin": origin, "port": port, "path": path, "method": method, "scope": scope, "purpose": purpose}

    def _record(self, decision: str, *, reason: str | None = None, grant: dict[str, Any] | None = None,
                payload: dict[str, Any] | None = None, bytes_count: int = 0) -> dict[str, Any]:
        try:
            return self._store.record(task_id=self._manifest["task"]["id"], attempt_id=self._manifest["task"]["attempt_id"],
                               manifest_hash=self._manifest_hash, decision=decision,
                               audit_record=grant["audit_record"] if grant else None, reason=reason,
                               bytes_count=bytes_count, payload=payload)
        except FetchStoreError as exc:
            raise FetchDenied(f"audit persistence unavailable: {exc}") from exc

    def _set_remaining_socket_timeout(self, connection: _PinnedHTTPSConnection, grant: dict[str, Any], deadline: float) -> None:
        self._check_active(grant, deadline)
        if connection.sock is None:
            raise FetchDenied("connection has no active socket")
        connection.sock.settimeout(max(0.001, deadline - time.monotonic()))

    def fetch(self, url: str, *, method: str, scope: str, purpose: str, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, Any]]:
        deadline = time.monotonic() + self._timeout
        current = url
        grant = None
        try:
            if headers:
                raise FetchDenied("caller headers and credential overrides denied")
            if method not in {"GET", "HEAD"}:
                raise FetchDenied("method denied")
            for hop in range(6):
                request_context = self._request_context(current, method, scope, purpose)
                grant, hostname, path, port = self._authorize(current, method, scope, purpose, deadline)
                # Resolve each hop and pin the verified address for TLS. No proxy or
                # system URL opener is used. Every address must be globally routable.
                try:
                    addresses = self._resolver.resolve(hostname, port, deadline=deadline, cancel=self._cancel)
                except DNSResolutionError as exc:
                    raise FetchDenied(str(exc)) from exc
                if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
                    raise FetchDenied("DNS resolved to a nonpublic address")
                connection = _PinnedHTTPSConnection(hostname, sorted(addresses)[0], port, max(0.1, deadline - time.monotonic()))
                try:
                    self._check_active(grant, deadline)
                    connection.request(method, path, headers={"Accept": "*/*"})
                    self._set_remaining_socket_timeout(connection, grant, deadline)
                    response = connection.getresponse()
                    if response.status in _REDIRECTS:
                        location = response.getheader("Location")
                        if not location:
                            raise FetchDenied("redirect without Location")
                        current = urljoin(current, location)
                        self._record("redirect", grant=grant, payload={**self._request_context(current, method, scope, purpose),
                                                                        "hop": hop, "url": current,
                                                                        "cleanup_outcome": "in_progress"})
                        continue
                    if response.status < 200 or response.status >= 300:
                        raise FetchDenied(f"HTTP status {response.status}")
                    chunks = []
                    while True:
                        self._set_remaining_socket_timeout(connection, grant, deadline)
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        self._consume(grant, len(chunk), request_context)
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    # Recheck cancellation, deadline, and durable grant state
                    # after the final read, atomically with the allowed event.
                    with self._lock:
                        self._check_active_locked(grant, deadline)
                        try:
                            audit_event = self._store.record_allowed(
                                grant, self._manifest_hash, bytes_count=len(body),
                                payload={**request_context, "url": current,
                                         "task_id": grant["task_id"], "attempt_id": grant["attempt_id"],
                                         "audit_record": grant["audit_record"], "purpose": purpose,
                                         "manifest_hash": self._manifest_hash, "method": method,
                                         "redirect_hops": hop, "size_bytes": len(body),
                                         "sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
                                         "result_gate": "pending", "verification": "unverified",
                                         "cleanup_outcome": "not_required"})
                        except FetchStoreError as exc:
                            raise FetchDenied(str(exc)) from exc
                    record = {
                        "task_id": grant["task_id"], "attempt_id": grant["attempt_id"],
                        "audit_record": grant["audit_record"], "purpose": purpose,
                        "manifest_hash": self._manifest_hash,
                        "url": current, "method": method, "redirect_hops": hop,
                        "size_bytes": len(body), "sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
                        "result_gate": "pending", "verification": "unverified",
                    }
                    record["event_id"] = audit_event["event_id"]
                    return body, record
                finally:
                    connection.close()
            raise FetchDenied("redirect hop limit exceeded")
        except BaseException as exc:
            reason = str(exc) if isinstance(exc, FetchDenied) else type(exc).__name__
            self._record("denied", reason=reason, grant=grant,
                         payload={**self._request_context(current, method, scope, purpose),
                                  "url": current, "cleanup_outcome": "revoke_required"})
            self.revoke(reason, grant=grant, context=self._request_context(current, method, scope, purpose))
            if isinstance(exc, FetchDenied):
                raise
            raise FetchDenied(reason) from exc
