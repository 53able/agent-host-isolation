import hashlib
import json
import sys
import time
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from inspect_fetch_broker import FetchDenied, InspectFetchBroker


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
    def __init__(self, status=200, body=b"data", location=None):
        self.status = status
        self.body = body
        self.location = location

    def getheader(self, name):
        return self.location if name == "Location" else None

    def read(self, _size):
        result, self.body = self.body, b""
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


class BrokerTests(unittest.TestCase):
    def setUp(self):
        Connection.responses = []
        Connection.requests = []
        self.dns = patch("inspect_fetch_broker.socket.getaddrinfo", side_effect=public_dns)
        self.transport = patch("inspect_fetch_broker._PinnedHTTPSConnection", Connection)
        self.dns.start()
        self.transport.start()
        self.addCleanup(self.dns.stop)
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
        with patch("inspect_fetch_broker.socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 443))]):
            with self.assertRaisesRegex(FetchDenied, "nonpublic"):
                self.fetch(broker)
        cancelled = Event()
        cancelled.set()
        broker = InspectFetchBroker(manifest(), cancel=cancelled)
        with self.assertRaisesRegex(FetchDenied, "cancelled"):
            self.fetch(broker)

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


if __name__ == "__main__":
    unittest.main()
