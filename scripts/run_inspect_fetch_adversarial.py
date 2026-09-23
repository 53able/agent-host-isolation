#!/usr/bin/env python3
"""Request-time evidence for the inspect fetch boundary.

The legacy deterministic probes use injected transport. The live matrix runs
the broker's real resolver and HTTPS path, then a successful fetch crosses the
snapshot gate and installed JustBash runtime. Verification is scoped to the
captured host, runtime, manifests, and committed execution inputs.
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
from threading import Timer
from urllib.parse import urlsplit

import inspect_fetch_broker as broker_module
from inspect_fetch_broker import DurableCancellation, FetchDenied, InspectFetchBroker
from inspect_fetch_resolver import DNSResolutionError
from inspect_fetch_store import FetchAuditStore
from inspect_snapshot_gate import InspectSnapshotGate, SnapshotGateDenied
from just_bash_manifest import canonical_manifest_hash

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_JSON = ROOT / "evidence" / "inspect-fetch-issue5-20260923.json"
EVIDENCE_MD = ROOT / "evidence" / "inspect-fetch-issue5-20260923.md"
BODY = b"network-derived evidence\n"
REQUIRED_LIVE_PROBES = frozenset({
    "live-example-com", "live-redirect-hop", "live-origin-deny",
    "live-path-deny", "live-method-deny", "live-ip-literal-deny",
    "live-alternate-port-deny", "live-header-deny", "live-expiry-deny",
    "live-byte-budget", "live-dns-timeout", "live-request-timeout",
    "live-cancel",
})
REQUIRED_VERIFICATION_PROBES = REQUIRED_LIVE_PROBES | {"gate-and-real-just-bash"}


def verification_status(results: list[dict], execution_input_dirty: list[str]) -> str:
    """Verify only a complete, passing live matrix against committed inputs."""
    required = [item for item in results if item.get("name") in REQUIRED_VERIFICATION_PROBES]
    names = [item.get("name") for item in required]
    complete = len(names) == len(REQUIRED_VERIFICATION_PROBES) and set(names) == REQUIRED_VERIFICATION_PROBES
    def passed(item: dict) -> bool:
        decisions = [value for value in (item.get("passed"), item.get("observed", {}).get("passed"))
                     if value is not None]
        return bool(decisions) and all(value is True for value in decisions)
    all_passed = bool(results) and all(passed(item) for item in results)
    return "verified-for-tested-configuration" if complete and all_passed and not execution_input_dirty else "unverified"


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def now_expiry(seconds: int = 600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


class InjectedResolver:
    def __init__(self, addresses=None, error=None, cancel: DurableCancellation | None = None):
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


def run_live_probe(name: str, url: str, *, origin: str, path_prefix: str, method: str = "GET",
                   expected_reason: str | None = None) -> dict:
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
        observed["broker_process_ok"] = child.returncode == 0
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
        observed["allowed_event"] = any(e.get("decision") == "allowed" for e in events)
        observed["result_import"] = any(e.get("decision") == "result_gate" for e in events)
        observed["result_import"] = observed["result_import"] or any(e.get("decision") == "result_gate" for e in _read_all_events(db))
        observed["grant_revoked"] = any(e.get("decision") == "revoked" and e.get("revocation_outcome") == "grant_revoked" for e in events)
    except Exception as exc:
        observed.update({"decision": "unavailable", "reason": f"{type(exc).__name__}: {exc}"})
    finally:
        directory.cleanup()
    expected = "allowed" if name == "live-example-com" else "denied-after-redirect"
    observed["redirect_event"] = any(e.get("decision") == "redirect" for e in observed.get("audit_events", []))
    decisions = [event.get("decision") for event in observed.get("audit_events", [])]
    observed["redirect_sequence"] = decisions[:4] if name == "live-redirect-hop" else []
    redirect_ok = (name == "live-redirect-hop" and observed["decision"] == "denied" and
                   observed.get("reason") == expected_reason and observed.get("redirect_sequence") == ["request", "redirect", "denied", "revoked"] and
                   not observed.get("allowed_event") and not observed.get("result_import") and observed.get("grant_revoked"))
    success_ok = (name == "live-example-com" and observed["decision"] == "allowed" and
                  observed.get("runtime", {}).get("profile") == "standard" and observed.get("runtime", {}).get("stdout") == body.decode() and
                  observed.get("result_import")) if "body" in locals() else False
    observed["passed"] = observed.get("broker_process_ok", False) and (success_ok or redirect_ok)
    return {"name": name, "class": "live_network", "expected": expected, "observed": observed, "passed": observed["passed"]}


def _read_events_after_process(db: str, task_id: str, attempt_id: str) -> list[dict]:
    """Reopen the audit DB in a separate process before the temp directory closes."""
    reader = subprocess.run(
        ["python3", "-c", "import json,sys; sys.path.insert(0, 'scripts'); from inspect_fetch_store import FetchAuditStore; print(json.dumps(FetchAuditStore(sys.argv[1]).events(task_id=sys.argv[2], attempt_id=sys.argv[3])))", db, task_id, attempt_id],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    return json.loads(reader.stdout)


def _read_all_events(db: str) -> list[dict]:
    reader = subprocess.run(
        ["python3", "-c", "import json,sys; sys.path.insert(0, 'scripts'); from inspect_fetch_store import FetchAuditStore; print(json.dumps(FetchAuditStore(sys.argv[1]).events()))", db],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    return json.loads(reader.stdout)


def _live_events(observed: dict, db: str, task_id: str, attempt_id: str) -> None:
    events = _read_events_after_process(db, task_id, attempt_id)
    observed["audit_events"] = events
    observed["allowed_event"] = any(e.get("decision") == "allowed" for e in events)
    observed["result_import"] = any(e.get("decision") == "result_gate" for e in events)
    observed["grant_revoked"] = any(e.get("decision") == "revoked" and e.get("revocation_outcome") == "grant_revoked" for e in events)


def run_live_preconnect_probe(name: str, url: str, *, expected_reason: str, method: str = "GET",
                              headers: dict[str, str] | None = None, expiry: str | None = None,
                              delay: float = 0.0) -> dict:
    """Run policy denials through the real broker before DNS or socket setup."""
    task_id, attempt_id = f"inspect-fetch-live-{name}", f"attempt-{uuid.uuid4().hex[:12]}"
    source = base_manifest(task_id, attempt_id)
    if expiry is not None:
        source["gateway"]["grants"][0]["expiry"] = expiry
    directory = tempfile.TemporaryDirectory(prefix="inspect-fetch-live-preconnect-")
    db = str(Path(directory.name) / "audit.sqlite3")
    observed = {"transport": "real broker; pre-connect policy path", "url": url, "stage": "pre_connect_policy",
                "network_attempt": "none_by_decision_chronology", "decision": "unavailable"}
    try:
        child_code = """import json,sys,time
import multiprocessing
trace={'calls':{},'returns':{}}
def profiler(frame,event,arg):
 mod=frame.f_globals.get('__name__',''); name=frame.f_code.co_name; self_obj=frame.f_locals.get('self')
 if event not in ('call','return'): return profiler
 cls=type(self_obj).__name__ if self_obj is not None else ''
 key=None
 if mod == 'inspect_fetch_resolver' and name == 'resolve': key='dns.resolve'
 elif mod == 'inspect_fetch_broker' and cls == '_PinnedHTTPSConnection' and name == '__init__': key='tls.connection_init'
 elif mod == 'inspect_fetch_broker' and cls == '_PinnedHTTPSConnection' and name == 'connect': key='tls.connect'
 elif mod == 'http.client' and name == 'getresponse': key='http.getresponse'
 elif mod == 'http.client' and name == 'read': key='http.read'
 if key:
  bucket=trace['calls'] if event == 'call' else trace['returns']
  bucket[key]=bucket.get(key,0)+1
 return profiler
sys.setprofile(profiler)
sys.path.insert(0, 'scripts')
from inspect_fetch_broker import InspectFetchBroker,FetchDenied
r=json.load(sys.stdin)
f=InspectFetchBroker(r['manifest'], timeout=3.0, audit_store_path=r['db'])
out={'decision':'denied'}
try:
 if r.get('delay'): time.sleep(r['delay'])
 f.fetch(r['url'], method=r['method'], scope='public metadata', purpose='bounded inspection input', headers=r.get('headers'))
 out['decision']='allowed'
except FetchDenied as e:
 out['reason']=str(e)
finally:
 sys.setprofile(None)
 out['trace']=trace
 out['active_children_after_fetch']=len(multiprocessing.active_children())
print(json.dumps(out))"""
        child = subprocess.run(
            ["python3", "-c", child_code], cwd=ROOT,
            input=json.dumps({"manifest": source, "db": db, "url": url, "method": method, "headers": headers, "delay": delay}),
            text=True, capture_output=True, timeout=12,
        )
        result = json.loads(child.stdout) if child.stdout.strip() else {"decision": "unavailable", "reason": child.stderr.strip()}
        observed.update(result)
        observed["trace"] = result.get("trace", {})
        observed["active_children_after_fetch"] = result.get("active_children_after_fetch")
        observed["trace_calls_zero"] = not any(result.get("trace", {}).get("calls", {}).values())
        observed["trace_returns_zero"] = not any(result.get("trace", {}).get("returns", {}).values())
        _live_events(observed, db, task_id, attempt_id)
        observed["broker_process"] = {"returncode": child.returncode, "exited_before_audit_reader": True}
        observed["denied_event"] = any(e.get("decision") == "denied" for e in observed["audit_events"])
        observed["passed"] = (child.returncode == 0 and result.get("decision") == "denied" and
                               result.get("reason") == expected_reason and observed["denied_event"] and observed["trace_calls_zero"] and observed["trace_returns_zero"] and
                               result.get("active_children_after_fetch") == 0 and
                               not observed["allowed_event"] and not observed["result_import"] and observed["grant_revoked"])
    except Exception as exc:
        observed.update({"decision": "unavailable", "reason": f"{type(exc).__name__}: {exc}"})
    finally:
        directory.cleanup()
    return {"name": name, "class": "live_preconnect_policy", "expected": "denied", "observed": observed, "passed": observed.get("passed", False)}


def run_live_denial_probe(name: str, url: str, *, origin: str, path_prefix: str, expected_reason: str,
                          max_bytes: int = 4096,
                          timeout: float = 8.0, dns_timeout: float = 2.0, cancel_after: float | None = None) -> dict:
    """Run a real DNS/TLS/HTTPS request whose result must be denied and revoked."""
    task_id, attempt_id = f"inspect-fetch-live-{name}", f"attempt-{uuid.uuid4().hex[:12]}"
    source = base_manifest(task_id, attempt_id)
    source["gateway"]["grants"] = [grant_for(task_id, attempt_id, origin=origin, path_prefix=path_prefix, max_bytes=max_bytes)]
    directory = tempfile.TemporaryDirectory(prefix="inspect-fetch-live-denial-")
    db = str(Path(directory.name) / "audit.sqlite3")
    observed = {"transport": "live broker network path", "url": url, "origin": origin, "path_prefix": path_prefix,
                "stage": "unknown", "network_attempt": "unknown", "decision": "unavailable", "cancel_phase": "unknown"}
    try:
        child_code = """import json,sys,multiprocessing
from threading import Timer
trace={'calls':{},'returns':{}}
def profiler(frame,event,arg):
 mod=frame.f_globals.get('__name__',''); name=frame.f_code.co_name; self_obj=frame.f_locals.get('self')
 if event not in ('call','return'): return profiler
 cls=type(self_obj).__name__ if self_obj is not None else ''
 key=None
 if mod == 'inspect_fetch_resolver' and name == 'resolve': key='dns.resolve'
 elif mod == 'inspect_fetch_broker' and cls == '_PinnedHTTPSConnection' and name == '__init__': key='tls.connection_init'
 elif mod == 'inspect_fetch_broker' and cls == '_PinnedHTTPSConnection' and name == 'connect': key='tls.connect'
 elif mod == 'http.client' and name == 'getresponse': key='http.getresponse'
 elif mod == 'http.client' and name == 'read': key='http.read'
 if key:
  bucket=trace['calls'] if event == 'call' else trace['returns']
  bucket[key]=bucket.get(key,0)+1
 return profiler
sys.setprofile(profiler)
sys.path.insert(0, 'scripts')
from inspect_fetch_broker import InspectFetchBroker,FetchDenied,DurableCancellation
r=json.load(sys.stdin); cancel=DurableCancellation(); timer=None
if r.get('cancel_after') is not None:
 timer=Timer(r['cancel_after'], cancel.set); timer.start()
f=InspectFetchBroker(r['manifest'], timeout=r['timeout'], dns_timeout=r['dns_timeout'], cancel=cancel, audit_store_path=r['db'])
out={'decision':'denied'}
try:
 b,x=f.fetch(r['url'], method='GET', scope='public metadata', purpose='bounded inspection input')
 out.update(decision='allowed',bytes=len(b),record=x)
except FetchDenied as e:
 out['reason']=str(e)
finally:
 if timer is not None:
  timer.cancel(); out['cancel_fired']=cancel.is_set()
 sys.setprofile(None)
 out['trace']=trace
 out['active_children_after_fetch']=len(multiprocessing.active_children())
print(json.dumps(out))"""
        child = subprocess.run(
            ["python3", "-c", child_code], cwd=ROOT,
            input=json.dumps({"manifest": source, "db": db, "url": url, "timeout": timeout, "dns_timeout": dns_timeout, "cancel_after": cancel_after}),
            text=True, capture_output=True, timeout=max(15, int(timeout + 8)),
        )
        result = json.loads(child.stdout) if child.stdout.strip() else {"decision": "unavailable", "reason": child.stderr.strip()}
        observed.update(result)
        observed["trace"] = result.get("trace", {})
        calls = result.get("trace", {}).get("calls", {})
        observed["traced_phase"] = ("http" if calls.get("http.read", 0) else "http_headers" if calls.get("http.getresponse", 0) else "tls" if calls.get("tls.connect", 0) else "dns" if calls.get("dns.resolve", 0) else "unknown")
        observed["stage"] = observed["traced_phase"]
        observed["network_attempt"] = {"http": "live DNS + TLS + HTTPS response", "http_headers": "live DNS + TLS + HTTP response headers", "tls": "live DNS + TLS connection attempt", "dns": "live DNS resolution"}.get(observed["traced_phase"], "unknown")
        observed["transport"] = observed["network_attempt"]
        observed["active_children_after_fetch"] = result.get("active_children_after_fetch")
        _live_events(observed, db, task_id, attempt_id)
        observed["broker_process"] = {"returncode": child.returncode, "exited_before_audit_reader": True}
        observed["denied_event"] = any(e.get("decision") == "denied" for e in observed["audit_events"])
        observed["budget_event"] = next((e for e in observed["audit_events"] if e.get("decision") == "budget"), None)
        if observed["budget_event"] is not None:
            observed["body_bytes_observed"] = observed["budget_event"].get("bytes")
            observed["max_bytes"] = max_bytes
        reason_ok = result.get("reason") == expected_reason
        budget_ok = (expected_reason == "grant byte budget exceeded" and observed["budget_event"] is not None and
                     observed.get("body_bytes_observed", 0) > max_bytes)
        cancel_ok = expected_reason != "cancelled" or result.get("cancel_fired") is True
        reaping_ok = expected_reason not in {"DNS timeout", "cancelled"} or result.get("active_children_after_fetch") == 0
        expected_phase = {"grant byte budget exceeded": "http", "timeout": "http_headers"}.get(expected_reason)
        phase_ok = (observed["traced_phase"] == expected_phase if expected_phase is not None else
                    observed["traced_phase"] != "unknown" if expected_reason == "cancelled" else True)
        observed["passed"] = (child.returncode == 0 and result.get("decision") == "denied" and reason_ok and
                               observed["denied_event"] and not observed["allowed_event"] and not observed["result_import"] and
                               observed["grant_revoked"] and (budget_ok if expected_reason == "grant byte budget exceeded" else True) and cancel_ok and reaping_ok and phase_ok)
    except Exception as exc:
        observed.update({"decision": "unavailable", "reason": f"{type(exc).__name__}: {exc}"})
    finally:
        directory.cleanup()
    return {"name": name, "class": "live_network_denial", "expected": "denied", "observed": observed, "passed": observed.get("passed", False)}


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
        Probe("cancel-deny", "https://api.example.com/v1/data/item", "denied", resolver=InjectedResolver(error="DNS cancelled"), routes={}, cancel=DurableCancellation()),
        Probe("request-timeout-deny", "https://api.example.com/v1/data/item", "denied", routes={("api.example.com", 443, "/v1/data/item"): FakeResponse(error=TimeoutError("socket timeout"))}, timeout=0.1),
    ]
    results = [run_probe(probe, index + 1) for index, probe in enumerate(probes)]
    gate = run_success_gate_runtime(len(results) + 1)
    results.append(gate)
    results.append(run_live_probe("live-example-com", "https://example.com/", origin="https://example.com:443", path_prefix="/"))
    results.append(run_live_probe("live-redirect-hop", "https://httpbin.org/redirect/1", origin="https://httpbin.org:443", path_prefix="/redirect/", method="GET", expected_reason="no exact active grant matched"))
    # These policy denials use the real broker and stop before resolver/socket setup.
    results.extend([
        run_live_preconnect_probe("live-origin-deny", "https://evil.example.com/v1/data/item", expected_reason="no exact active grant matched"),
        run_live_preconnect_probe("live-path-deny", "https://api.example.com/v2/data/item", expected_reason="no exact active grant matched"),
        run_live_preconnect_probe("live-method-deny", "https://api.example.com/v1/data/item", expected_reason="method denied", method="POST"),
        run_live_preconnect_probe("live-ip-literal-deny", "https://93.184.216.34/v1/data/item", expected_reason="IP literal denied"),
        run_live_preconnect_probe("live-alternate-port-deny", "https://api.example.com:8443/v1/data/item", expected_reason="no exact active grant matched"),
        run_live_preconnect_probe("live-header-deny", "https://api.example.com/v1/data/item", expected_reason="caller headers and credential overrides denied", headers={"Authorization": "Bearer secret"}),
        run_live_preconnect_probe("live-expiry-deny", "https://api.example.com/v1/data/item", expected_reason="grant expired", expiry=now_expiry(1), delay=1.2),
    ])
    # These cases exercise real public DNS, TLS, HTTP response handling, and the
    # durable denial/revocation path.  A cancellation phase is intentionally
    # reported as unknown because the broker has no phase callback.
    results.extend([
        run_live_denial_probe("live-byte-budget", "https://httpbin.org/bytes/32", origin="https://httpbin.org:443", path_prefix="/bytes/", expected_reason="grant byte budget exceeded", max_bytes=4),
        run_live_denial_probe("live-dns-timeout", "https://example.com/", origin="https://example.com:443", path_prefix="/", expected_reason="DNS timeout", dns_timeout=0.001),
        run_live_denial_probe("live-request-timeout", "https://httpbin.org/delay/3", origin="https://httpbin.org:443", path_prefix="/delay/", expected_reason="timeout", timeout=0.75),
        run_live_denial_probe("live-cancel", "https://httpbin.org/delay/3", origin="https://httpbin.org:443", path_prefix="/delay/", expected_reason="cancelled", timeout=6.0, cancel_after=0.25),
    ])
    git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    git_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT, text=True).splitlines()
    execution_input_dirty = subprocess.check_output([
        "git", "status", "--porcelain=v1", "--untracked-files=all", "--", ".",
        ":(exclude)evidence/inspect-fetch-issue5-20260923.json",
        ":(exclude)evidence/inspect-fetch-issue5-20260923.md",
    ], cwd=ROOT, text=True).splitlines()
    status = verification_status(results, execution_input_dirty)
    source_probe = next(item for item in results if item["name"] == "gate-and-real-just-bash")
    source_manifest = source_probe["observed"]["source_manifest"]
    target_manifest = source_probe["observed"]["target_manifest"]
    reason = ("all required broker and runtime probes passed with committed execution inputs"
              if status == "verified-for-tested-configuration" else
              "required probes failed or execution inputs were uncommitted; verification remains unverified")
    evidence = {"captured_at": datetime.now(timezone.utc).isoformat(), "status": status,
                "reason": reason,
                "host": {"os": platform.system(), "release": platform.release(), "machine": platform.machine(), "python": platform.python_version()},
                "runtime": {"node": subprocess.check_output(["node", "-p", "process.versions.node"], text=True).strip(),
                            "just_bash": json.loads((ROOT / "node_modules/just-bash/package.json").read_text())["version"],
                            "embedding": "scripts/just_bash_runtime.mjs:createInspectRuntimeFromFetch + executeInspectCommand",
                            "broker": "scripts/inspect_fetch_broker.py", "store": "SQLite FetchAuditStore", "gate": "scripts/inspect_snapshot_gate.py"},
                "repository": {"url": "https://github.com/53able/agent-host-isolation.git", "head": git_head, "tree": git_tree,
                               "dirty_worktree": dirty, "execution_input_dirty_worktree": execution_input_dirty},
                "input_hashes": {"harness": digest((ROOT / "scripts/run_inspect_fetch_adversarial.py").read_bytes()), "lockfile": digest((ROOT / "package-lock.json").read_bytes()), "source_manifest": canonical_manifest_hash(source_manifest), "target_manifest": canonical_manifest_hash(target_manifest), "source_snapshot": source_manifest["workspace"]["snapshot"]["hash"], "target_snapshot": target_manifest["workspace"]["snapshot"]["hash"]},
                "source_manifest": source_manifest,
                "target_manifest": target_manifest,
                "snapshot_paths": {"source": source_manifest["workspace"]["snapshot"]["paths"], "target": target_manifest["workspace"]["snapshot"]["paths"]},
                "tested_embedding": "Python broker/store/gate -> real installed JustBash standard runtime; legacy deterministic probes use injected transport, new pre-connect and network denial probes use the real broker with public HTTPS",
                "probes": results,
                "all_probes_passed": all(item.get("observed", {}).get("passed", item.get("passed", False)) for item in results),
                "injected_transport_probes_passed": all(item.get("observed", {}).get("passed", item.get("passed", False)) for item in results if not item["name"].startswith("live-")),
                "live_probes_passed": all(item.get("observed", {}).get("passed", item.get("passed", False)) for item in results if item["name"].startswith("live-")),
                "real_preconnect_probes_passed": all(item.get("passed", False) for item in results if item.get("class") == "live_preconnect_policy"),
                "real_network_denial_probes_passed": all(item.get("passed", False) for item in results if item.get("class") == "live_network_denial")}
    EVIDENCE_JSON.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lines = ["# Inspect fetch Issue #5 adversarial evidence", "", f"Status: `{status}`", "", evidence["reason"], "", f"Runtime: Node {evidence['runtime']['node']}, JustBash {evidence['runtime']['just_bash']}", "", "| Probe | Expected | Observed | Passed |", "|---|---|---|---|"]
    for item in results:
        observed = item.get("observed", {})
        lines.append(f"| `{item['name']}` | `{item['expected']}` | `{observed.get('decision', 'n/a')}` | `{observed.get('passed', item.get('passed', False))}` |")
    lines += ["", "The deterministic legacy matrix uses injected transport. The live matrix uses the real broker, resolver, and HTTPS connection where policy permits one. Pre-connect denials have zero traced resolver/socket calls; denied results have no allowed/result-gate event and a durable revocation after broker exit. The successful fetch crosses the one-shot gate into installed standard JustBash. Verification applies only to the captured runtime, host, manifests, snapshots, and committed execution inputs; a failed or incomplete rerun returns to `unverified`.", ""]
    EVIDENCE_MD.write_text("\n".join(lines))
    print(json.dumps({"status": status, "evidence": str(EVIDENCE_JSON), "probes": len(results), "all_passed": evidence["all_probes_passed"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
