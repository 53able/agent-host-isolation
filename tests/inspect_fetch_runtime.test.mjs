import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createInspectRuntimeFromFetch, executeInspectCommand } from "../scripts/just_bash_runtime.mjs";

const root = new URL("../", import.meta.url);
const digest = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;

test("fetch result gate imports bytes and executes them in standard JustBash", async () => {
  const source = JSON.parse(readFileSync(new URL("../assets/just-bash-inspect-manifest.template.json", import.meta.url), "utf8"));
  const body = Buffer.from("fetched content\n");
  source.task.id = `inspect-${randomUUID()}`;
  source.task.attempt_id = `attempt-${randomUUID()}`;
  source.task.command = ["cat", "data.json"];
  source.task.goal = "inspect fetched content";
  source.workspace.snapshot.paths = [{ path: "data.json", type: "regular", size_bytes: body.length, hash: digest(body) }];
  source.workspace.snapshot.hash = digest(JSON.stringify(source.workspace.snapshot.paths));
  source.workspace.repository.commit = "b".repeat(40);
  source.workspace.repository.tree_hash = "c".repeat(40);
  source.workspace.toolchain = { node: process.versions.node, "just-bash": "3.4.2", "agent-host-isolation": "0.1.0" };
  source.runtime.package_version = "3.4.2";
  source.runtime.node_version = process.versions.node;
  source.runtime.agent_host_isolation_version = "0.1.0";
  source.runtime.profile_variant = "network-derived";
  source.gateway.task_network = `${source.task.id}-network`;
  source.gateway.grants = [{ task_id: source.task.id, attempt_id: source.task.attempt_id, origin: "https://api.example.com:443", port: 443,
    path_prefix: "/v1/data/", methods: ["GET"], scope: "public metadata", purpose: "bounded inspection input",
    expiry: "2099-01-01T00:00:00Z", max_bytes: 4096, audit_record: "audit/network.json", redirect_policy: "revalidate-exact-origin" }];
  source.resultGate.audit_record = "audit/inspect.json";
  source.verification = { status: "unverified", adversarial_evidence: [] };

  const target = JSON.parse(readFileSync(new URL("../validation/just-bash/manifest.json", import.meta.url), "utf8"));
  target.task.id = source.task.id;
  target.task.attempt_id = `attempt-${randomUUID()}`;
  target.task.command = ["cat", "data.json"];
  target.task.goal = "inspect imported fetched content";
  target.workspace.snapshot.paths = [{ path: "data.json", type: "regular", size_bytes: 0, hash: digest("") }];
  target.workspace.snapshot.hash = digest(JSON.stringify(target.workspace.snapshot.paths));
  target.workspace.snapshot.id = `snapshot-${randomUUID()}`;
  target.verification = { status: "unverified", adversarial_evidence: [] };

  const directory = mkdtempSync(join(tmpdir(), "inspect-fetch-runtime-"));
  const db = join(directory, "audit.sqlite3");
  const setup = spawnSync("python3", ["-c", `import json,sys
sys.path.insert(0, 'scripts')
from inspect_fetch_store import FetchAuditStore
from just_bash_manifest import canonical_manifest_hash
r=json.load(sys.stdin); s=r['source']; b=bytes.fromhex(r['body_hex']); store=FetchAuditStore(r['db']); source_hash=canonical_manifest_hash(s); store.register_manifest(s, source_hash)
e=store.record(task_id=s['task']['id'], attempt_id=s['task']['attempt_id'], manifest_hash=source_hash, decision='allowed', audit_record='audit/network.json', bytes_count=len(b), payload={'purpose':'bounded inspection input','url':'https://api.example.com/v1/data/item','method':'GET','redirect_hops':0,'size_bytes':len(b),'sha256':r['body_hash'],'result_gate':'pending','verification':'unverified'})
print(json.dumps(e))`], { input: JSON.stringify({ source, body_hex: body.toString("hex"), body_hash: digest(body), db }), encoding: "utf8", cwd: root.pathname });
  assert.equal(setup.status, 0, setup.stderr);
  const event = JSON.parse(setup.stdout);
  const record = { ...event, task_id: source.task.id, attempt_id: source.task.attempt_id, manifest_hash: event.manifest_hash,
    audit_record: "audit/network.json", purpose: "bounded inspection input", url: "https://api.example.com/v1/data/item", method: "GET",
    redirect_hops: 0, size_bytes: body.length, sha256: digest(body), result_gate: "pending", verification: "unverified" };
  try {
    const runtime = createInspectRuntimeFromFetch({ sourceManifest: source, sourceRecord: record, body, targetManifest: target, auditStorePath: db });
    const result = await executeInspectCommand({ runtime, argv: target.task.command });
    assert.equal(result.result.stdout, "fetched content\n");
    assert.equal(result.source.task_id, target.task.id);
    assert.equal(source.runtime.profile_variant, "network-derived");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
