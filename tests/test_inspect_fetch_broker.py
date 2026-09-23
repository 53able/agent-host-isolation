import hashlib
import json
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from inspect_fetch_broker import FetchDenied, InspectFetchBroker
from inspect_fetch_resolver import HostDNSResolver
from inspect_fetch_store import FetchAuditStore


def manifest():
    value = json.loads((ROOT / "assets" / "just-bash-inspect-manifest.template.json").read_text())
    value["task"].update(id="inspect-task", attempt_id="attempt-1", goal="inspect fetched public metadata", command=["cat", "data.json"])
    value["workspace"]["repository"].update(url="https://github.com/53able/agent-host-isolation.git", commit="b" * 40, tree_hash="c" * 40)
    value["workspace"]["snapshot"].update(id="snapshot-inspect", hash="sha256:" + "a" * 64)
    value["workspace"]["snapshot"]["paths"][0]["hash"] = "sha256:" + "a" * 64
    versions = {"node": "22.18.0", "just-bash": "3.4.2", "agent-host-isolation": "0.1.0"}
    value["workspace"]["toolchain"] = versions
    value["workspace"]["lockfile"]["sha256"] = "sha256:" + "d" * 64
    value["workspace"]["skills"] = [{"id": "agent-host-isolation", "version": "0.1.0"}]
    value["runtime"].update(profile_variant="network-derived", package_version="3.4.2", node_version="22.18.0", agent_host_isolation_version="0.1.0")
    value["gateway"].update(task_network="inspect-task-network", grants=[{
        "task_id": "inspect-task", "attempt_id": "attempt-1", "origin": "https://api.example.com:443",
        "port": 443, "path_prefix": "/v1/data/", "methods": ["GET", "HEAD"],
        "scope": "public metadata", "purpose": "bounded inspection input",
        "expiry": "2099-01-01T00:00:00Z", "max_bytes": 8,
        "audit_record": "audit/network.json", "redirect_policy": "revalidate-exact-origin",
    }])
    value["resultGate"]["audit_record"] = "audit/inspect.json"
    return value


class Response:
    def __init__(self, status=200, body=b"data", location=None, on_read=None):
        self.status = status
        self.body = body
        self.location = location
        self.on_read = on_read

    def getheader(self, name):
        return self.location if name == "Location" else None

    def read(self, _size):
        result, self.body = self.body, b""
        if self.on_read:
            self.on_read()
        return result


class Connection:
    responses = []
    requests = []

    def __init__(self, host, address, port, timeout):
        self.host, self.address, self.port = host, address, port
        self.sock = self
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def request(self, method, path, headers):
        self.requests.append((self.host, self.address, self.port, method, path, headers))

    def getresponse(self):
        return self.responses.pop(0)

    def close(self):
        pass


def public_dns(*_args, **_kwargs):
    return [(None, None, None, None, ("8.8.8.8", 443))]


def private_dns(*_args, **_kwargs):
    return [(None, None, None, None, ("127.0.0.1", 443))]


def failing_dns(*_args, **_kwargs):
    raise socket.gaierror("resolver down")


def blocking_dns(*_args, **_kwargs):
    time.sleep(10)
    return []


class BrokerTests(unittest.TestCase):
    def setUp(self):
        Connection.responses = []
        Connection.requests = []
        self.transport = patch("inspect_fetch_broker._PinnedHTTPSConnection", Connection)
        self.resolver = patch("inspect_fetch_broker.HostDNSResolver",
                             side_effect=lambda **_kwargs: HostDNSResolver(resolve_fn=public_dns))
        self.resolver.start()
        self.transport.start()
        self.addCleanup(self.resolver.stop)
        self.addCleanup(self.transport.stop)

    def fetch(self, broker, url="https://api.example.com/v1/data/item", **kwargs):
        return broker.fetch(url, method="GET", scope="public metadata", purpose="bounded inspection input", **kwargs)

    def test_allowed_snapshot_bytes_have_identity_and_pending_gate(self):
        Connection.responses = [Response(body=b"data")]
        broker = InspectFetchBroker(manifest())
        body, record = self.fetch(broker)
        self.assertEqual(body, b"data")
        self.assertEqual(record["sha256"], "sha256:" + hashlib.sha256(body).hexdigest())
        self.assertEqual(record["result_gate"], "pending")
        self.assertEqual(record["verification"], "unverified")
        self.assertEqual(Connection.requests[0][:5], ("api.example.com", "8.8.8.8", 443, "GET", "/v1/data/item"))
        self.assertEqual(Connection.requests[0][5], {"Accept": "*/*"})

    def test_final_read_rechecks_cancellation_before_allowed_event(self):
        cancelled = Event()
        Connection.responses = [Response(body=b"data", on_read=cancelled.set)]
        broker = InspectFetchBroker(manifest(), cancel=cancelled)
        with self.assertRaisesRegex(FetchDenied, "cancelled"):
            self.fetch(broker)
        self.assertFalse(any(event["decision"] == "allowed" for event in broker.audit))

    def test_final_read_rechecks_grant_revocation_before_allowed_event(self):
        broker = None

        def revoke_after_read():
            broker.revoke("response read cancellation")

        Connection.responses = [Response(body=b"data", on_read=revoke_after_read)]
        broker = InspectFetchBroker(manifest())
        with self.assertRaisesRegex(FetchDenied, "grant revoked"):
            self.fetch(broker)
        self.assertFalse(any(event["decision"] == "allowed" for event in broker.audit))

    def test_final_read_rechecks_deadline_before_allowed_event(self):
        Connection.responses = [Response(body=b"data", on_read=lambda: time.sleep(0.01))]
        broker = InspectFetchBroker(manifest(), timeout=0.001)
        with self.assertRaisesRegex(FetchDenied, "timeout"):
            self.fetch(broker)
        self.assertFalse(any(event["decision"] == "allowed" for event in broker.audit))

    def test_redirect_rechecks_each_hop_and_denies_origin_path_and_port(self):
        for location in ("https://other.example.com/v1/data/item", "/admin", "https://api.example.com:8443/v1/data/item", "https://127.0.0.1/v1/data/item"):
            with self.subTest(location=location):
                Connection.requests = []
                Connection.responses = [Response(302, location=location)]
                broker = InspectFetchBroker(manifest())
                with self.assertRaises(FetchDenied):
                    self.fetch(broker)
                self.assertEqual(len(Connection.requests), 1)
                self.assertEqual(broker.audit[-1]["decision"], "revoked")

    def test_allowed_redirect_rechecks_and_returns_final_bytes(self):
        Connection.responses = [Response(302, location="/v1/data/next"), Response(body=b"done")]
        broker = InspectFetchBroker(manifest())
        body, record = self.fetch(broker)
        self.assertEqual(body, b"done")
        self.assertEqual(record["redirect_hops"], 1)
        self.assertEqual(len(Connection.requests), 2)
        self.assertEqual(Connection.requests[1][4], "/v1/data/next")

    def test_request_policy_denials_revoke_attempt(self):
        cases = [
            ("https://api.example.com/admin", {}),
            ("https://api.example.com/v1/data/%2e%2e/admin", {}),
            ("https://api.example.com/v1/data/..\\admin", {}),
            ("https://127.0.0.1/v1/data/item", {}),
            ("https://api.example.com:8443/v1/data/item", {}),
            ("https://api.example.com:0/v1/data/item", {}),
            ("https://api.example.com:000/v1/data/item", {}),
            ("https://api.example.com/v1/data/item", {"headers": {"Authorization": "Bearer attacker"}}),
        ]
        for url, extra in cases:
            with self.subTest(url=url, extra=extra):
                broker = InspectFetchBroker(manifest())
                with self.assertRaises(FetchDenied):
                    self.fetch(broker, url, **extra)
                self.assertFalse(Connection.requests)
                with self.assertRaises(FetchDenied):
                    self.fetch(broker)

    def test_budget_is_cumulative_and_overflow_revokes(self):
        Connection.responses = [Response(body=b"12345"), Response(body=b"6789")]
        broker = InspectFetchBroker(manifest())
        self.fetch(broker)
        with self.assertRaisesRegex(FetchDenied, "byte budget"):
            self.fetch(broker)
        self.assertTrue(any(item.get("reason") == "grant byte budget exceeded" for item in broker.audit))

    def test_private_dns_and_cancel_are_denied(self):
        broker = InspectFetchBroker(manifest())
        broker = InspectFetchBroker(manifest(), resolver=HostDNSResolver(resolve_fn=private_dns))
        with self.assertRaisesRegex(FetchDenied, "nonpublic"):
            self.fetch(broker)
        cancelled = Event()
        cancelled.set()
        broker = InspectFetchBroker(manifest(), cancel=cancelled)
        with self.assertRaisesRegex(FetchDenied, "cancelled"):
            self.fetch(broker)

    def test_dns_timeout_records_durable_denial_and_revoke_before_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "audit.sqlite3"
            broker = InspectFetchBroker(
                manifest(), audit_store_path=str(db), dns_timeout=0.05,
                resolver=HostDNSResolver(timeout=0.05, resolve_fn=blocking_dns),
            )
            with self.assertRaisesRegex(FetchDenied, "DNS timeout"):
                self.fetch(broker)
            self.assertFalse(Connection.requests)
            events = FetchAuditStore(str(db)).events(task_id="inspect-task", attempt_id="attempt-1")
            self.assertTrue(any(event["decision"] == "denied" and event["reason"] == "DNS timeout" for event in events))
            self.assertTrue(any(event["decision"] == "revoked" and event["cleanup_outcome"] == "revoked" for event in events))

    def test_method_expiry_and_timeout_are_checked_at_request_time(self):
        broker = InspectFetchBroker(manifest())
        with self.assertRaisesRegex(FetchDenied, "method denied"):
            broker.fetch("https://api.example.com/v1/data/item", method="POST", scope="public metadata", purpose="bounded inspection input")
        self.assertFalse(Connection.requests)
        broker = InspectFetchBroker(manifest())
        broker._manifest["gateway"]["grants"][0]["expiry"] = "2000-01-01T00:00:00Z"
        with self.assertRaisesRegex(FetchDenied, "expired"):
            self.fetch(broker)
        broker = InspectFetchBroker(manifest())
        with patch("inspect_fetch_broker.time.monotonic", side_effect=[0.0, 100.0]):
            with self.assertRaisesRegex(FetchDenied, "timeout"):
                self.fetch(broker)
        self.assertFalse(Connection.requests)

    def test_slow_response_exceeds_total_deadline(self):
        class SlowResponse(Response):
            def read(self, _size):
                time.sleep(0.02)
                return b"x"

        Connection.responses = [SlowResponse()]
        broker = InspectFetchBroker(manifest(), timeout=0.01)
        with self.assertRaisesRegex(FetchDenied, "timeout"):
            self.fetch(broker)
        self.assertEqual(broker.audit[-1]["decision"], "revoked")

    def test_invalid_or_standard_manifest_cannot_construct_broker(self):
        value = manifest()
        value["gateway"]["grants"][0]["attempt_id"] = "other-attempt"
        with self.assertRaisesRegex(FetchDenied, "attempt_id"):
            InspectFetchBroker(value)
        value = manifest()
        value["runtime"]["profile_variant"] = "standard"
        with self.assertRaises(FetchDenied):
            InspectFetchBroker(value)

    def test_budget_and_revoke_survive_broker_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "audit.sqlite3"
            Connection.responses = [Response(body=b"12345")]
            first = InspectFetchBroker(manifest(), audit_store_path=str(db))
            self.fetch(first)
            Connection.responses = [Response(body=b"6789")]
            restarted = InspectFetchBroker(manifest(), audit_store_path=str(db))
            with self.assertRaisesRegex(FetchDenied, "byte budget"):
                self.fetch(restarted)
            self.assertTrue(any(event["decision"] == "budget" for event in restarted.audit))

            restarted.revoke("operator cancellation")
            Connection.requests = []
            with self.assertRaisesRegex(FetchDenied, "grant revoked"):
                self.fetch(InspectFetchBroker(manifest(), audit_store_path=str(db)))
            self.assertFalse(Connection.requests)
            events = restarted.audit
            self.assertTrue(any(event["decision"] == "revoked" and event["reason"] == "operator cancellation" for event in events))
            self.assertTrue(all(event["task_id"] == "inspect-task" and event["attempt_id"] == "attempt-1" for event in events))

    def test_duplicate_grant_audit_record_is_rejected(self):
        value = manifest()
        duplicate = dict(value["gateway"]["grants"][0])
        duplicate["path_prefix"] = "/v1/other/"
        value["gateway"]["grants"].append(duplicate)
        from just_bash_manifest import validate_just_bash_v2
        self.assertTrue(any("audit_record must uniquely identify" in error for error in validate_just_bash_v2(value)))

    def test_denials_reopen_with_normalized_identity_and_cleanup_evidence(self):
        cases = [
            ("path", lambda broker: self.fetch(broker, "https://api.example.com/admin"), "no exact"),
            ("method", lambda broker: broker.fetch("https://api.example.com/v1/data/item", method="POST", scope="public metadata", purpose="bounded inspection input"), "method"),
            ("expiry", lambda broker: self.fetch(broker), "expired"),
            ("timeout", lambda broker: self.fetch(broker), "timeout"),
            ("cancel", lambda broker: self.fetch(broker), "cancelled"),
            ("dns", lambda broker: self.fetch(broker), "gaierror"),
        ]
        for name, action, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                db = Path(directory) / "audit.sqlite3"
                cancelled = Event() if name == "cancel" else None
                broker = InspectFetchBroker(manifest(), audit_store_path=str(db), cancel=cancelled)
                if name == "expiry":
                    broker._manifest["gateway"]["grants"][0]["expiry"] = "2000-01-01T00:00:00Z"
                if name == "timeout":
                    clock = patch("inspect_fetch_broker.time.monotonic", side_effect=[0.0, 100.0])
                    clock.start()
                elif name == "cancel":
                    cancelled.set()
                elif name == "dns":
                    broker._resolver = HostDNSResolver(resolve_fn=failing_dns)
                try:
                    with self.assertRaises(FetchDenied):
                        action(broker)
                finally:
                    if name == "timeout":
                        clock.stop()
                reopened = FetchAuditStore(str(db))
                events = reopened.events(task_id="inspect-task", attempt_id="attempt-1")
                denied = [event for event in events if event["decision"] == "denied"][-1]
                self.assertIn(expected, denied["reason"])
                self.assertEqual(denied["task_id"], "inspect-task")
                self.assertEqual(denied["attempt_id"], "attempt-1")
                self.assertEqual(denied["origin"], "https://api.example.com:443")
                self.assertEqual(denied["port"], 443)
                self.assertEqual(denied["path"], "/admin" if name == "path" else "/v1/data/item")
                self.assertEqual(denied["method"], "POST" if name == "method" else "GET")
                self.assertEqual(denied["scope"], "public metadata")
                self.assertEqual(denied["purpose"], "bounded inspection input")
                self.assertEqual(denied["cleanup_outcome"], "revoke_required")
                self.assertTrue(any(event["decision"] == "revoked" and event["cleanup_outcome"] == "revoked" for event in events))

    def test_redirect_audit_preserves_each_hop_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "audit.sqlite3"
            Connection.responses = [Response(302, location="https://other.example.com/v1/data/item")]
            broker = InspectFetchBroker(manifest(), audit_store_path=str(db))
            with self.assertRaises(FetchDenied):
                self.fetch(broker)
            events = FetchAuditStore(str(db)).events(task_id="inspect-task", attempt_id="attempt-1")
            redirect = [event for event in events if event["decision"] == "redirect"][-1]
            denied = [event for event in events if event["decision"] == "denied"][-1]
            self.assertEqual(redirect["origin"], "https://other.example.com:443")
            self.assertEqual(redirect["path"], "/v1/data/item")
            self.assertEqual(denied["origin"], "https://other.example.com:443")

    def test_reopen_rejects_cross_attempt_audit_record_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "audit.sqlite3"
            first = InspectFetchBroker(manifest(), audit_store_path=str(db))
            with self.assertRaises(FetchDenied):
                self.fetch(first, "https://api.example.com/admin")
            changed = manifest()
            changed["task"]["attempt_id"] = "attempt-2"
            changed["gateway"]["grants"][0]["attempt_id"] = "attempt-2"
            with self.assertRaisesRegex(FetchDenied, "audit_record"):
                InspectFetchBroker(changed, audit_store_path=str(db))
            events = FetchAuditStore(str(db)).events(task_id="inspect-task", attempt_id="attempt-1")
            self.assertTrue(any(event["decision"] == "denied" and event["cleanup_outcome"] == "revoke_required" for event in events))

    def test_reopened_network_denials_keep_identity_and_cleanup(self):
        cases = [
            ("ip", "https://127.0.0.1/v1/data/item", None, "IP literal denied", "https://127.0.0.1:443"),
            ("port", "https://api.example.com:8443/v1/data/item", None, "no exact active grant matched", "https://api.example.com:8443"),
            ("redirect", "https://api.example.com/v1/data/item", "/v1/data/item", "no exact active grant matched", "https://other.example.com:443"),
        ]
        for name, url, location, reason, origin in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                db = Path(directory) / "audit.sqlite3"
                if location:
                    Connection.responses = [Response(302, location="https://other.example.com" + location)]
                broker = InspectFetchBroker(manifest(), audit_store_path=str(db))
                with self.assertRaisesRegex(FetchDenied, reason):
                    self.fetch(broker, url)
                events = FetchAuditStore(str(db)).events(task_id="inspect-task", attempt_id="attempt-1")
                denied = [event for event in events if event["decision"] == "denied"][-1]
                self.assertEqual(denied["origin"], origin)
                self.assertEqual(denied["port"], 443 if name == "ip" else (8443 if name == "port" else 443))
                self.assertEqual(denied["path"], "/v1/data/item")
                self.assertEqual(denied["method"], "GET")
                self.assertEqual(denied["cleanup_outcome"], "revoke_required")
                self.assertTrue(any(event["decision"] == "revoked" and event["cleanup_outcome"] == "revoked" and event["origin"] == origin for event in events))

    def test_reopened_budget_denial_keeps_identity_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "audit.sqlite3"
            Connection.responses = [Response(body=b"12345")]
            self.fetch(InspectFetchBroker(manifest(), audit_store_path=str(db)))
            Connection.responses = [Response(body=b"6789")]
            with self.assertRaisesRegex(FetchDenied, "byte budget"):
                self.fetch(InspectFetchBroker(manifest(), audit_store_path=str(db)))
            events = FetchAuditStore(str(db)).events(task_id="inspect-task", attempt_id="attempt-1")
            budget = [event for event in events if event["decision"] == "budget"][-1]
            self.assertEqual(budget["origin"], "https://api.example.com:443")
            self.assertEqual(budget["path"], "/v1/data/item")
            self.assertEqual(budget["method"], "GET")
            self.assertEqual(budget["cleanup_outcome"], "revoke_required")
            self.assertTrue(any(event["decision"] == "revoked" and event["cleanup_outcome"] == "revoked" for event in events))

    def test_audit_events_are_append_only(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "audit.sqlite3"
            broker = InspectFetchBroker(manifest(), audit_store_path=str(db))
            with self.assertRaises(FetchDenied):
                self.fetch(broker, "https://api.example.com/admin")
            store = FetchAuditStore(str(db))
            with self.assertRaisesRegex(Exception, "append-only"):
                store._db.execute("DELETE FROM events")
            with self.assertRaisesRegex(Exception, "append-only"):
                store._db.execute("UPDATE events SET reason='tampered'")


if __name__ == "__main__":
    unittest.main()
