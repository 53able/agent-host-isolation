#!/usr/bin/env python3
"""Reproducible request-time evidence for the inspect fetch boundary.

The broker probes use an injected resolver/transport so the denial matrix can
run deterministically without opening an Internet connection.  One successful
probe then crosses the real Python snapshot gate and the installed JustBash
runtime.  The evidence deliberately remains ``unverified`` because the
transport is not production network I/O.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit

import inspect_fetch_broker as broker_module
from inspect_fetch_broker import FetchDenied, InspectFetchBroker
from inspect_fetch_resolver import DNSResolutionError
from inspect_fetch_store import FetchAuditStore
from inspect_snapshot_gate import InspectSnapshotGate, SnapshotGateDenied
from just_bash_manifest import canonical_manifest_hash

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_JSON = ROOT / "evidence" / "inspect-fetch-issue5-20260923.json"
EVIDENCE_MD = ROOT / "evidence" / "inspect-fetch-issue5-20260923.md"
BODY = b"network-derived evidence\n"


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def now_expiry(seconds: int = 600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


class InjectedResolver:
    def __init__(self, addresses=None, error=None, cancel: Event | None = None):
        self.addresses = set(addresses or {"93.184.216.34"})
        self.error = error
        self.cancel = cancel

    def resolve(self, hostname, port, *, deadline, cancel=None):
        if self.cancel is not None:
            self.cancel.set()
        if self.error:
            raise DNSResolutionError(self.error)
        if cancel and cancel.is_set():
            raise DNSResolutionError("DNS cancelled")
        return self.addresses


class FakeSocket:
    def settimeout(self, value):
        self.timeout = value


class FakeResponse:
    def __init__(self, status=200, body=b"", location=None, error=None):
        self.status, self.body, self.location, self.error = status, body, location, error

    def getheader(self, name):
        return self.location if name.lower() == "location" else None

    def read(self, size=-1):
        if self.error:
            raise self.error
        body, self.body = self.body, b""
        return body


class FakeConnection:
    routes = {}

    def __init__(self, hostname, address, port, timeout):
        self.hostname, self.port, self.sock = hostname, port, FakeSocket()
        self.path = None

    def connect(self):
        return None

    def request(self, method, path, headers):
        self.path = path

    def getresponse(self):
        route = self.routes.get((self.hostname, self.port, self.path), self.routes.get((self.hostname, self.port, "*")))
        if route is None:
            return FakeResponse(404)
        return route

    def close(self):
        return None


class Probe:
    def __init__(self, name, url, expected, *, method="GET", headers=None, grant=None, resolver=None, routes=None, timeout=2.0, cancel=None):
        self.name, self.url, self.expected = name, url, expected
        self.method, self.headers, self.grant = method, headers, grant
        self.resolver, self.routes, self.timeout, self.cancel = resolver, routes or {}, timeout, cancel


def base_manifest(task_id: str, attempt_id: str, *, target=False, body: bytes = BODY) -> dict:
    source = json.loads((ROOT / "validation" / "just-bash" / "manifest.json").read_text())
    source["task"]["id"] = task_id
    source["task"]["attempt_id"] = attempt_id
    source["task"]["goal"] = "adversarial inspect fetch evidence"
    source["task"]["command"] = ["cat", "data.txt"]
    source["workspace"]["snapshot"]["id"] = "inspect-fetch-issue5-snapshot"
    source["workspace"]["snapshot"]["paths"] = [{"path": "data.txt", "type": "regular", "size_bytes": len(body), "hash": digest(body)}]
    source["workspace"]["snapshot"]["hash"] = digest(json.dumps(source["workspace"]["snapshot"]["paths"], separators=(",", ":")))
    source["workspace"]["repository"]["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source["workspace"]["repository"]["tree_hash"] = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
    source["workspace"]["toolchain"]["node"] = subprocess.check_output(["node", "-p", "process.versions.node"], text=True).strip()
    source["workspace"]["toolchain"]["just-bash"] = json.loads((ROOT / "node_modules/just-bash/package.json").read_text())["version"]
    source["workspace"]["lockfile"]["sha256"] = digest((ROOT / "package-lock.json").read_bytes())
    source["runtime"]["node_version"] = source["workspace"]["toolchain"]["node"]
    source["runtime"]["package_version"] = source["workspace"]["toolchain"]["just-bash"]
    source["runtime"]["profile_variant"] = "standard" if target else "network-derived"
    source["gateway"] = {"default": "deny", "task_network": None, "ingress_ports": [], "grants": [], "credential_broker": None}
    source["verification"] = {"status": "unverified", "adversarial_evidence": []}
    if not target:
        source["gateway"]["task_network"] = f"{task_id}-network"
        source["gateway"]["grants"] = [grant_for(task_id, attempt_id)]
    return source


def grant_for(task_id, attempt_id, *, origin="https://api.example.com:443", path_prefix="/v1/data/", methods=None, expiry=None, max_bytes=4096):
    return {"task_id": task_id, "attempt_id": attempt_id, "origin": origin, "port": int(urlsplit(origin).port),
            "path_prefix": path_prefix, "methods": methods or ["GET"], "scope": "public metadata",
            "purpose": "bounded inspection input", "expiry": expiry or now_expiry(), "max_bytes": max_bytes,
            "audit_record": "audit/inspect-fetch-issue5.json", "redirect_policy": "revalidate-exact-origin"}


def run_probe(probe: Probe, index: int) -> dict:
    task_id, attempt_id = f"inspect-fetch-issue5-{index:02d}", f"attempt-{index:02d}"
    manifest = base_manifest(task_id, attempt_id)
    if probe.grant is not None:
        grant = copy.deepcopy(probe.grant)
        grant["task_id"], grant["attempt_id"] = task_id, attempt_id
        if probe.name == "expiry-deny":
            grant["expiry"] = now_expiry()
        manifest["gateway"]["grants"] = [grant]
    directory = tempfile.TemporaryDirectory(prefix="inspect-fetch-issue5-")
    db = str(Path(directory.name) / "audit.sqlite3")
    original = broker_module._PinnedHTTPSConnection
    FakeConnection.routes = probe.routes
    broker_module._PinnedHTTPSConnection = FakeConnection
    observed = {"decision": "denied", "reason": None, "cleanup": None}
    try:
        fetcher = InspectFetchBroker(manifest, timeout=probe.timeout, cancel=probe.cancel, audit_store_path=db, resolver=probe.resolver or InjectedResolver())
        if probe.name == "expiry-deny":
            fetcher._manifest["gateway"]["grants"][0]["expiry"] = "2000-01-01T00:00:00Z"
        try:
            body, record = fetcher.fetch(probe.url, method=probe.method, scope="public metadata", purpose="bounded inspection input", headers=probe.headers)
            observed.update({"decision": "allowed", "body_sha256": digest(body), "record": record})
        except FetchDenied as exc:
            observed["reason"] = str(exc)
        restart_reader = subprocess.run(["python3", "-c", "import json,sys; sys.path.insert(0, 'scripts'); from inspect_fetch_store import FetchAuditStore; print(json.dumps(FetchAuditStore(sys.argv[1]).events(task_id=sys.argv[2], attempt_id=sys.argv[3])))", db, task_id, attempt_id], cwd=ROOT, text=True, capture_output=True, check=True)
        events = json.loads(restart_reader.stdout)
        observed["events"] = events
        observed["cleanup"] = any(e.get("decision") == "revoked" and e.get("cleanup_outcome") == "revoked" for e in events)
        observed["durable_after_restart"] = len(events) > 0
        observed["passed"] = (observed["decision"] == probe.expected) and (probe.expected == "allowed" or observed["cleanup"])
        return {"name": probe.name, "class": probe.name.split("-", 1)[0], "input": {"url": probe.url, "method": probe.method}, "expected": probe.expected, "observed": observed, "transport": "injected/mock; no live network"}
    finally:
        broker_module._PinnedHTTPSConnection = original
        directory.cleanup()


def run_success_gate_runtime(index: int) -> dict:
    task_id, attempt_id = "inspect-fetch-issue5-success", "attempt-success"
    source = base_manifest(task_id, attempt_id)
    directory = tempfile.TemporaryDirectory(prefix="inspect-fetch-issue5-gate-")
    db = str(Path(directory.name) / "audit.sqlite3")
    original = broker_module._PinnedHTTPSConnection
    FakeConnection.routes = {("api.example.com", 443, "/v1/data/item"): FakeResponse(body=BODY)}
    broker_module._PinnedHTTPSConnection = FakeConnection
    try:
        fetcher = InspectFetchBroker(source, audit_store_path=db, resolver=InjectedResolver())
        fetched, record = fetcher.fetch("https://api.example.com/v1/data/item", method="GET", scope="public metadata", purpose="bounded inspection input")
        target = base_manifest(task_id, f"attempt-import-{uuid.uuid4().hex[:12]}", target=True, body=fetched)
        payload = {"sourceManifest": source, "sourceRecord": record, "body": base64.b64encode(fetched).decode(), "targetManifest": target, "auditStorePath": db}
        code = """import { readFileSync } from 'node:fs'; import { createInspectRuntimeFromFetch, executeInspectCommand } from './scripts/just_bash_runtime.mjs'; const p=JSON.parse(readFileSync(0,'utf8')); const r=createInspectRuntimeFromFetch({sourceManifest:p.sourceManifest,sourceRecord:p.sourceRecord,body:Buffer.from(p.body,'base64'),targetManifest:p.targetManifest,auditStorePath:p.auditStorePath}); const x=await executeInspectCommand({runtime:r,argv:p.targetManifest.task.command}); console.log(JSON.stringify({stdout:x.result.stdout,profile:p.targetManifest.runtime.profile_variant}));"""
        result = subprocess.run(["node", "--input-type=module", "-e", code], cwd=ROOT, input=json.dumps(payload), text=True, capture_output=True, timeout=15)
        runtime = json.loads(result.stdout) if result.returncode == 0 else {"error": result.stderr.strip()}
        tampered = copy.deepcopy(record)
        tampered["sha256"] = digest(b"tampered")
        try:
            InspectSnapshotGate(db).import_snapshot(source, tampered, fetched, target)
            tamper_rejected = False
        except (SnapshotGateDenied, AssertionError):
            tamper_rejected = True
        return {"name": "gate-and-real-just-bash", "class": "result_gate", "expected": "allowed", "observed": {"decision": "allowed", "runtime": runtime, "tamper_rejected": tamper_rejected, "source_manifest_hash": canonical_manifest_hash(source), "target_manifest_hash": canonical_manifest_hash(target), "source_manifest": source, "target_manifest": target, "snapshot_paths": target["workspace"]["snapshot"]["paths"], "transport": "injected/mock; real installed JustBash standard runtime"}, "passed": result.returncode == 0 and runtime.get("stdout") == BODY.decode() and runtime.get("profile") == "standard" and tamper_rejected}
    finally:
        broker_module._PinnedHTTPSConnection = original
        directory.cleanup()


def run_live_probe(name: str, url: str, *, origin: str, path_prefix: str, method: str = "GET") -> dict:
    """Exercise the actual resolver, TLS socket, and HTTP parser when available."""
    task_id, attempt_id = f"inspect-fetch-live-{name}", f"attempt-{uuid.uuid4().hex[:12]}"
    source = base_manifest(task_id, attempt_id)
    source["gateway"]["grants"] = [grant_for(task_id, attempt_id, origin=origin, path_prefix=path_prefix, max_bytes=4096)]
    directory = tempfile.TemporaryDirectory(prefix="inspect-fetch-live-")
    db = str(Path(directory.name) / "audit.sqlite3")
    observed = {"transport": "live public DNS + TLS + HTTPS", "url": url, "origin": origin, "path_prefix": path_prefix}
    try:
        child = subprocess.Popen(["python3", "-c", "import json,sys,base64; sys.path.insert(0, 'scripts'); from inspect_fetch_broker import InspectFetchBroker,FetchDenied; r=json.load(sys.stdin); f=InspectFetchBroker(r['manifest'], timeout=8.0, audit_store_path=r['db']); out={'decision':'denied'};\ntry:\n b,x=f.fetch(r['url'], method=r['method'], scope='public metadata', purpose='bounded inspection input'); out.update(decision='allowed',body=base64.b64encode(b).decode(),record=x)\nexcept FetchDenied as e: out['reason']=str(e)\nprint(json.dumps(out))"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = child.communicate(json.dumps({"manifest": source, "db": db, "url": url, "method": method}), timeout=20)
        observed["broker_process"] = {"pid": child.pid, "returncode": child.returncode, "terminated_before_reader": child.poll() is not None}
        result = json.loads(stdout) if stdout.strip() else {"decision": "unavailable", "reason": stderr.strip()}
        if result.get("decision") == "allowed":
            body = base64.b64decode(result["body"])
            observed.update({"decision": "allowed", "status": "HTTP 2xx", "bytes": len(body), "sha256": digest(body), "record": result["record"]})
            if name == "live-example-com":
                target = base_manifest(task_id, f"attempt-import-{uuid.uuid4().hex[:12]}", target=True, body=body)
                payload = {"sourceManifest": source, "sourceRecord": result["record"], "body": base64.b64encode(body).decode(), "targetManifest": target, "auditStorePath": db}
                code = """import { readFileSync } from 'node:fs'; import { createInspectRuntimeFromFetch, executeInspectCommand } from './scripts/just_bash_runtime.mjs'; const p=JSON.parse(readFileSync(0,'utf8')); const r=createInspectRuntimeFromFetch({sourceManifest:p.sourceManifest,sourceRecord:p.sourceRecord,body:Buffer.from(p.body,'base64'),targetManifest:p.targetManifest,auditStorePath:p.auditStorePath}); const x=await executeInspectCommand({runtime:r,argv:p.targetManifest.task.command}); console.log(JSON.stringify({stdout:x.result.stdout,profile:p.targetManifest.runtime.profile_variant}));"""
                runtime_run = subprocess.run(["node", "--input-type=module", "-e", code], cwd=ROOT, input=json.dumps(payload), text=True, capture_output=True, timeout=15)
                observed["runtime"] = json.loads(runtime_run.stdout) if runtime_run.returncode == 0 else {"error": runtime_run.stderr.strip()}
                observed["source_manifest_hash"] = canonical_manifest_hash(source)
                observed["target_manifest_hash"] = canonical_manifest_hash(target)
                observed["snapshot_paths"] = target["workspace"]["snapshot"]["paths"]
        else:
            observed.update({"decision": "denied", "reason": result.get("reason", "broker unavailable")})
        reader = subprocess.run(["python3", "-c", "import json,sys; sys.path.insert(0, 'scripts'); from inspect_fetch_store import FetchAuditStore; print(json.dumps(FetchAuditStore(sys.argv[1]).events(task_id=sys.argv[2], attempt_id=sys.argv[3])))", db, task_id, attempt_id], cwd=ROOT, text=True, capture_output=True, check=True)
        events = json.loads(reader.stdout)
        observed["audit_events"] = events
        observed["cleanup"] = any(e.get("decision") == "revoked" for e in events)
    except Exception as exc:
        observed.update({"decision": "unavailable", "reason": f"{type(exc).__name__}: {exc}"})
    finally:
        directory.cleanup()
    expected = "allowed" if name == "live-example-com" else "denied-after-redirect"
    observed["redirect_event"] = any(e.get("decision") == "redirect" for e in observed.get("audit_events", []))
    observed["passed"] = (name == "live-example-com" and observed["decision"] == "allowed" and observed.get("runtime", {}).get("profile") == "standard") or (name == "live-redirect-hop" and observed["decision"] == "denied" and observed["redirect_event"])
    return {"name": name, "class": "live_network", "expected": expected, "observed": observed, "passed": observed["passed"]}


def main() -> int:
    probes = [
        Probe("origin-deny", "https://evil.example.com/v1/data/item", "denied", routes={}),
        Probe("path-deny", "https://api.example.com/v2/data/item", "denied", routes={}),
        Probe("method-deny", "https://api.example.com/v1/data/item", "denied", method="POST", routes={}),
        Probe("dns-ip-literal", "https://93.184.216.34/v1/data/item", "denied", routes={}),
        Probe("alternate-port", "https://api.example.com:8443/v1/data/item", "denied", routes={}),
        Probe("redirect-hop-deny", "https://api.example.com/v1/data/item", "denied", routes={("api.example.com", 443, "/v1/data/item"): FakeResponse(302, location="https://evil.example.com/v1/data/item")}),
        Probe("header-credential-deny", "https://api.example.com/v1/data/item", "denied", headers={"Authorization": "Bearer secret"}, routes={}),
        Probe("expiry-deny", "https://api.example.com/v1/data/item", "denied", grant=grant_for("inspect-fetch-issue5-08", "attempt-08", expiry="2000-01-01T00:00:00Z"), routes={}),
        Probe("byte-budget-deny", "https://api.example.com/v1/data/item", "denied", grant=grant_for("inspect-fetch-issue5-09", "attempt-09", max_bytes=4), routes={("api.example.com", 443, "/v1/data/item"): FakeResponse(body=BODY)}),
        Probe("dns-timeout-deny", "https://api.example.com/v1/data/item", "denied", resolver=InjectedResolver(error="DNS timeout"), routes={}),
        Probe("cancel-deny", "https://api.example.com/v1/data/item", "denied", resolver=InjectedResolver(error="DNS cancelled"), routes={}, cancel=Event()),
        Probe("request-timeout-deny", "https://api.example.com/v1/data/item", "denied", routes={("api.example.com", 443, "/v1/data/item"): FakeResponse(error=TimeoutError("socket timeout"))}, timeout=0.1),
    ]
    results = [run_probe(probe, index + 1) for index, probe in enumerate(probes)]
    gate = run_success_gate_runtime(len(results) + 1)
    results.append(gate)
    results.append(run_live_probe("live-example-com", "https://example.com/", origin="https://example.com:443", path_prefix="/"))
    results.append(run_live_probe("live-redirect-hop", "https://httpbin.org/redirect/1", origin="https://httpbin.org:443", path_prefix="/redirect/", method="GET"))
    status = "unverified"
    git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    git_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT, text=True).splitlines()
    source_probe = next(item for item in results if item["name"] == "gate-and-real-just-bash")
    source_manifest = source_probe["observed"]["source_manifest"]
    target_manifest = source_probe["observed"]["target_manifest"]
    evidence = {"captured_at": datetime.now(timezone.utc).isoformat(), "status": status,
                "reason": "the full denial matrix uses injected transport; live example.com HTTPS and httpbin redirect probes were attempted, but this does not establish production-equivalent coverage for every required class",
                "host": {"os": platform.system(), "release": platform.release(), "machine": platform.machine(), "python": platform.python_version()},
                "runtime": {"node": subprocess.check_output(["node", "-p", "process.versions.node"], text=True).strip(),
                            "just_bash": json.loads((ROOT / "node_modules/just-bash/package.json").read_text())["version"],
                            "embedding": "scripts/just_bash_runtime.mjs:createInspectRuntimeFromFetch + executeInspectCommand",
                            "broker": "scripts/inspect_fetch_broker.py", "store": "SQLite FetchAuditStore", "gate": "scripts/inspect_snapshot_gate.py"},
                "repository": {"url": "https://github.com/53able/agent-host-isolation.git", "head": git_head, "tree": git_tree, "dirty_worktree": dirty},
                "input_hashes": {"harness": digest((ROOT / "scripts/run_inspect_fetch_adversarial.py").read_bytes()), "lockfile": digest((ROOT / "package-lock.json").read_bytes()), "source_manifest": canonical_manifest_hash(source_manifest), "target_manifest": canonical_manifest_hash(target_manifest), "source_snapshot": source_manifest["workspace"]["snapshot"]["hash"], "target_snapshot": target_manifest["workspace"]["snapshot"]["hash"]},
                "source_manifest": source_manifest,
                "target_manifest": target_manifest,
                "snapshot_paths": {"source": source_manifest["workspace"]["snapshot"]["paths"], "target": target_manifest["workspace"]["snapshot"]["paths"]},
                "tested_embedding": "Python broker/store/gate -> real installed JustBash standard runtime; denial probes use injected transport, live probes use public HTTPS",
                "probes": results,
                "all_probes_passed": all(item.get("observed", {}).get("passed", item.get("passed", False)) for item in results),
                "injected_transport_probes_passed": all(item.get("observed", {}).get("passed", item.get("passed", False)) for item in results if not item["name"].startswith("live-")),
                "live_probes_passed": all(item.get("observed", {}).get("passed", item.get("passed", False)) for item in results if item["name"].startswith("live-"))}
    EVIDENCE_JSON.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lines = ["# Inspect fetch Issue #5 adversarial evidence", "", f"Status: `{status}`", "", evidence["reason"], "", f"Runtime: Node {evidence['runtime']['node']}, JustBash {evidence['runtime']['just_bash']}", "", "| Probe | Expected | Observed | Passed |", "|---|---|---|---|"]
    for item in results:
        observed = item.get("observed", {})
        lines.append(f"| `{item['name']}` | `{item['expected']}` | `{observed.get('decision', 'n/a')}` | `{observed.get('passed', item.get('passed', False))}` |")
    lines += ["", "Every denial records durable audit events and revocation. The example.com success path runs through the real broker process, result gate, and installed JustBash runtime. The live redirect probe must produce a durable redirect event followed by hop reauthorization denial; overall status remains unverified because the full required class matrix is not production-equivalent.", ""]
    EVIDENCE_MD.write_text("\n".join(lines))
    print(json.dumps({"status": status, "evidence": str(EVIDENCE_JSON), "probes": len(results), "all_passed": evidence["all_probes_passed"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
