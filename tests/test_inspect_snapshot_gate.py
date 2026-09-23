import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from inspect_fetch_store import FetchAuditStore, FetchStoreError
from inspect_snapshot_gate import InspectSnapshotGate, SnapshotGateDenied
from just_bash_manifest import canonical_manifest_hash, validate_just_bash_v2
from test_inspect_fetch_broker import Connection, Response, manifest as source_manifest


class SnapshotGateTests(unittest.TestCase):
    def target(self):
        value = json.loads((ROOT / "assets" / "just-bash-inspect-manifest.template.json").read_text())
        value["task"].update(id="inspect-task", attempt_id="attempt-2", goal="inspect imported metadata", command=["cat", "data.json"])
        value["workspace"]["repository"].update(url="https://github.com/53able/agent-host-isolation.git", commit="b" * 40, tree_hash="c" * 40)
        value["workspace"]["snapshot"].update(id="snapshot-imported")
        value["workspace"]["snapshot"]["paths"] = [{"path": "data.json", "type": "regular", "size_bytes": 0, "hash": "sha256:" + "0" * 64}]
        versions = {"node": "22.18.0", "just-bash": "3.4.2", "agent-host-isolation": "0.2.0"}
        value["workspace"]["toolchain"] = versions
        value["workspace"]["lockfile"]["sha256"] = "sha256:" + "d" * 64
        value["workspace"]["skills"] = [{"id": "agent-host-isolation", "version": "0.2.0"}]
        value["runtime"].update(package_version="3.4.2", node_version="22.18.0", agent_host_isolation_version="0.2.0")
        value["resultGate"]["audit_record"] = "audit/import.json"
        return value

    def setup_result(self):
        source = source_manifest()
        body = b"data"
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        store = FetchAuditStore(str(Path(self.directory.name) / "audit.sqlite3"))
        source_hash = canonical_manifest_hash(source)
        store.register_manifest(source, source_hash)
        grant = source["gateway"]["grants"][0]
        event = store.record_allowed(
            grant, source_hash, bytes_count=len(body),
            payload={"purpose": "bounded inspection input", "url": "https://api.example.com/v1/data/item",
                     "method": "GET", "redirect_hops": 0, "size_bytes": len(body), "sha256": digest,
                     "result_gate": "pending", "verification": "unverified"})
        return source, body, store, {**event, "size_bytes": len(body), "sha256": digest,
                                    "result_gate": "pending", "verification": "unverified"}

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_import_returns_one_checked_file_and_consumes_event(self):
        source, body, store, record = self.setup_result()
        result = InspectSnapshotGate(store).import_snapshot(source, record, body, self.target())
        self.assertTrue(result["approved"])
        self.assertEqual(result["snapshotFiles"], {"data.json": body})
        self.assertEqual(validate_just_bash_v2(result["manifest"]), [])
        self.assertTrue(any(e.get("result_gate") == "approved" for e in store.events(task_id="inspect-task", attempt_id="attempt-2")))

    def test_revoked_source_grant_cannot_pass_result_gate(self):
        source, body, store, record = self.setup_result()
        store.revoke(task_id="inspect-task", attempt_id="attempt-1",
                     manifest_hash=canonical_manifest_hash(source), reason="task cancelled",
                     audit_record="audit/network.json")
        with self.assertRaisesRegex(SnapshotGateDenied, "revoked"):
            InspectSnapshotGate(store).import_snapshot(source, record, body, self.target())
        self.assertFalse(any(event.get("result_gate") == "approved"
                             for event in store.events(task_id="inspect-task", attempt_id="attempt-2")))

    def test_expired_source_grant_cannot_pass_result_gate(self):
        source, body, store, record = self.setup_result()
        store._db.execute(
            "UPDATE grants SET expiry = ? WHERE task_id = ? AND attempt_id = ? AND audit_record = ?",
            ("2000-01-01T00:00:00Z", "inspect-task", "attempt-1", "audit/network.json"),
        )
        with self.assertRaisesRegex(SnapshotGateDenied, "expired"):
            InspectSnapshotGate(store).import_snapshot(source, record, body, self.target())

    def test_cancelled_broker_result_cannot_pass_result_gate(self):
        source, body, store, record = self.setup_result()
        from inspect_fetch_broker import InspectFetchBroker

        broker = InspectFetchBroker(source, audit_store=store)
        broker.cancel()
        with self.assertRaisesRegex(SnapshotGateDenied, "revoked"):
            InspectSnapshotGate(store).import_snapshot(source, record, body, self.target())

    def test_external_cancel_token_revokes_after_fetch_result(self):
        source = source_manifest()
        store = FetchAuditStore(str(Path(self.directory.name) / "cancel.sqlite3"))
        from inspect_fetch_broker import DurableCancellation, InspectFetchBroker

        class PublicResolver:
            def resolve(self, *_args, **_kwargs):
                return {"8.8.8.8"}

        token = DurableCancellation()
        Connection.responses = [Response(body=b"data")]
        with patch("inspect_fetch_broker._PinnedHTTPSConnection", Connection):
            broker = InspectFetchBroker(source, audit_store=store, cancel=token, resolver=PublicResolver())
            body, record = broker.fetch("https://api.example.com/v1/data/item", method="GET",
                                        scope="public metadata", purpose="bounded inspection input")
        token.set()
        with self.assertRaisesRegex(SnapshotGateDenied, "revoked"):
            InspectSnapshotGate(store).import_snapshot(source, record, body, self.target())

    def test_generic_record_cannot_create_allowed_event(self):
        source = source_manifest()
        source_hash = canonical_manifest_hash(source)
        store = FetchAuditStore(str(Path(self.directory.name) / "generic.sqlite3"))
        store.register_manifest(source, source_hash)
        with self.assertRaises(FetchStoreError):
            store.record(task_id="inspect-task", attempt_id="attempt-1", manifest_hash=source_hash,
                         decision="allowed", audit_record="audit/network.json")

    def test_replay_and_mutations_are_denied(self):
        source, body, store, record = self.setup_result()
        gate = InspectSnapshotGate(store)
        gate.import_snapshot(source, record, body, self.target())
        with self.assertRaisesRegex(SnapshotGateDenied, "consumed"):
            gate.import_snapshot(source, record, body, self.target())

    def test_record_body_and_target_mutations_are_denied(self):
        for mutation in ("record", "audit_record", "purpose", "url", "method", "body", "target"):
            with self.subTest(mutation=mutation):
                source, body, store, record = self.setup_result()
                target = self.target()
                if mutation == "record":
                    record["manifest_hash"] = "sha256:" + "f" * 64
                elif mutation in {"audit_record", "purpose", "url", "method"}:
                    record[mutation] = "forged"
                elif mutation == "body":
                    body = b"tampered"
                else:
                    target["gateway"]["grants"] = [{"bad": True}]
                with self.assertRaises(SnapshotGateDenied):
                    InspectSnapshotGate(store).import_snapshot(source, record, body, target)


if __name__ == "__main__":
    unittest.main()
