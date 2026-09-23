import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { Bash, defineCommand } from "just-bash";
import {
  blockInspectForStrictMemory,
  canonicalManifestHash,
  createInspectRuntime,
  executeInspectCommand,
  inspectRuntimeFilesystemSnapshot,
  INSPECT_BLOCKED_EVENT,
} from "../scripts/just_bash_runtime.mjs";

const baseline = JSON.parse(readFileSync(new URL("../validation/just-bash/manifest.json", import.meta.url), "utf8"));
const digest = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;

function fixture(argv = ["rg", "allowed", "/workspace"], snapshotFiles = { "allowed.txt": "allowed snapshot content\n" }) {
  const manifest = structuredClone(baseline);
  manifest.task.id = `inspect-${randomUUID()}`;
  manifest.task.attempt_id = `attempt-${randomUUID()}`;
  manifest.task.command = argv;
  manifest.task.strict_memory = false;
  manifest.task.command_classes = [...new Set([...manifest.task.command_classes, "deterministic-transform"])];
  manifest.verification = { status: "unverified", adversarial_evidence: [] };
  const paths = Object.entries(snapshotFiles).map(([path, value]) => ({
    path, type: "regular", size_bytes: Buffer.byteLength(value), hash: digest(value),
  }));
  manifest.workspace.snapshot.paths = paths;
  manifest.workspace.snapshot.hash = digest(JSON.stringify(paths));
  return { manifest, runtime: createInspectRuntime({ manifest, snapshotFiles }) };
}

test("blocks an undeclared native command before execution with source identity", async () => {
  const { manifest, runtime } = fixture();
  const event = await executeInspectCommand({ runtime, argv: ["node", "--version"] });
  assert.equal(event.event, INSPECT_BLOCKED_EVENT);
  assert.equal(event.outcome, "blocked");
  assert.equal(event.exit_code, 127);
  assert.deepEqual(event.source, {
    task_id: manifest.task.id,
    attempt_id: manifest.task.attempt_id,
    manifest_hash: canonicalManifestHash(manifest),
  });
  assert.equal(event.missing_capability, "undeclared-command");
  assert.equal(event.host_shell_fallback, false);
  assert.deepEqual(event.escalation, { automatic: false, requested: false });
  await assert.rejects(executeInspectCommand({ runtime, argv: manifest.task.command }), /terminal \(blocked\)/);
  await assert.rejects(executeInspectCommand({ runtime, argv: ["node", "--version"] }), /terminal \(blocked\)/);
  assert.throws(() => createInspectRuntime({ manifest, snapshotFiles: { "allowed.txt": "allowed snapshot content\n" } }), /already claimed/);
  const moduleUrl = new URL("../scripts/just_bash_runtime.mjs", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { createInspectRuntime } from ${JSON.stringify(moduleUrl)};
    let input = "";
    for await (const chunk of process.stdin) input += chunk;
    createInspectRuntime(JSON.parse(input));
  `], {
    input: JSON.stringify({ manifest, snapshotFiles: { "allowed.txt": "allowed snapshot content\n" } }),
    encoding: "utf8",
  });
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /already claimed/);
});

test("host controller blocks strict memory before dispatch with a terminal event", async () => {
  const { manifest, runtime } = fixture();
  const event = await blockInspectForStrictMemory({ runtime });
  assert.equal(event.event, "InspectBlocked");
  assert.equal(event.missing_capability, "strict-memory");
  assert.deepEqual(event.source, {
    task_id: manifest.task.id,
    attempt_id: manifest.task.attempt_id,
    manifest_hash: canonicalManifestHash(manifest),
  });
  assert.equal(event.exit_code, 127);
  assert.equal(event.result.stdout, "");
  assert.equal(event.host_shell_fallback, false);
  assert.deepEqual(event.escalation, { automatic: false, requested: false });
  await assert.rejects(executeInspectCommand({ runtime, argv: manifest.task.command }), /terminal \(blocked\)/);
  await assert.rejects(blockInspectForStrictMemory({ runtime }), /terminal \(blocked\)/);
  await assert.rejects(blockInspectForStrictMemory({ runtime: {} }), /trusted inspect runtime/);
});

test("host controller aborts an in-flight inspect attempt before issuing strict-memory event", async () => {
  const { manifest, runtime } = fixture(["cat", "allowed.txt"]);
  const execution = executeInspectCommand({ runtime, argv: manifest.task.command });
  const event = await blockInspectForStrictMemory({ runtime });
  assert.equal(event.missing_capability, "strict-memory");
  assert.equal(event.outcome, "blocked");
  assert.deepEqual(await execution, event);
  await assert.rejects(executeInspectCommand({ runtime, argv: manifest.task.command }), /terminal \(blocked\)/);
});

test("controller-issued strict-memory event creates a manual request for a new guest attempt", async () => {
  const { manifest, runtime } = fixture();
  const event = await blockInspectForStrictMemory({ runtime });
  const target = JSON.parse(readFileSync(new URL("../assets/isolation-manifest.template.json", import.meta.url), "utf8"));
  target.task.id = manifest.task.id;
  target.task.attempt_id = `attempt-${randomUUID()}`;
  target.task.goal = "run the task with an OS memory limit";
  target.task.command = ["sh", "-c", "true"];
  target.task.strict_memory = true;
  target.workspace.repository = { url: "https://github.com/53able/agent-host-isolation.git", commit: "a".repeat(40), tree_hash: "b".repeat(40) };
  target.workspace.snapshot = { id: `snapshot-${manifest.task.id}`, source: `/var/tmp/agent-host-isolation/snapshots/snapshot-${manifest.task.id}`, target: "/workspace", read_only: true };
  target.workspace.image = { reference: "ghcr.io/example/agent-build:1.0", digest: digest("image") };
  target.workspace.toolchain = { node: process.versions.node };
  target.workspace.lockfile = { path: "package-lock.json", sha256: digest("lockfile") };
  target.workspace.skills = [{ id: "agent-host-isolation", version: "v0.2.0" }];
  target.model = { provider: "none", id: "none", credential_broker_ref: null };
  target.runtime.scratch.volume = `${manifest.task.id}-scratch`;
  target.runtime.output.volume = `${manifest.task.id}-output`;
  target.resultGate.audit_record = "audit/strict-memory.json";
  const generated = spawnSync("python3", ["-c", `
import json,sys
sys.path.insert(0,"scripts")
from just_bash_contract import build_escalation_request
from strict_memory_dispatch import verify_host_event
data=json.load(sys.stdin)
verify_host_event(data["event"])
print(json.dumps(build_escalation_request(data["source"],data["event"],data["target"],"audit/strict-memory.json")))
`], { input: JSON.stringify({ source: manifest, event, target }), encoding: "utf8" });
  assert.equal(generated.status, 0, generated.stderr);
  const request = JSON.parse(generated.stdout);
  assert.equal(request.missing_capability, "strict-memory");
  assert.equal(request.strict_memory, true);
  assert.equal(request.automatic, false);
  assert.equal(request.source_attempt_id, manifest.task.attempt_id);
  assert.equal(request.target_attempt_id, target.task.attempt_id);
});

test("command-not-found cannot be relabeled as strict memory by the caller", async () => {
  const { manifest, runtime } = fixture();
  await assert.rejects(executeInspectCommand({
    runtime, argv: manifest.task.command, missingCapability: "strict-memory",
  }), /host controller stop path/);
  const result = await executeInspectCommand({ runtime, argv: manifest.task.command });
  assert.equal(result.outcome, "completed");
  await assert.rejects(blockInspectForStrictMemory({ runtime }), /terminal \(completed\)/);
});

test("rejects arbitrary executors and host-backed replacement commands", async () => {
  await assert.rejects(executeInspectCommand({
    runtime: { exec: async () => ({ exitCode: 0, stdout: "forged", stderr: "" }) },
    argv: ["printf", "safe"],
  }), /trusted inspect runtime/);
  let hostCallbackRan = false;
  const bash = new Bash({ customCommands: [defineCommand("printf", async () => {
    hostCallbackRan = true;
    return { exitCode: 0, stdout: "forged", stderr: "" };
  })] });
  await assert.rejects(executeInspectCommand({ runtime: bash, argv: ["printf", "safe"] }), /trusted inspect runtime/);
  assert.equal(hostCallbackRan, false);
  const { runtime } = fixture();
  const blocked = await executeInspectCommand({ runtime, argv: ["node", "--version"] });
  assert.equal(blocked.host_shell_fallback, false);
  assert.equal(blocked.escalation.requested, false);
});

test("preserves successful and non-blocked JustBash results", async () => {
  const { runtime } = fixture(["rg", "missing", "/workspace/no-file"]);
  const event = await executeInspectCommand({ runtime, argv: ["rg", "missing", "/workspace/no-file"] });
  assert.equal(event.event, "command");
  assert.equal(event.outcome, "failed");
  assert.notEqual(event.exit_code, 0);
  assert.equal(event.host_shell_fallback, false);
  assert.equal("escalation" in event, false);
  await assert.rejects(executeInspectCommand({ runtime, argv: ["rg", "missing", "/workspace/no-file"] }), /terminal \(failed\)/);
});

test("rejects invalid manifests and mismatched snapshots before construction", () => {
  const { manifest } = fixture();
  assert.throws(() => createInspectRuntime({
    manifest: { ...manifest, runtime: { ...manifest.runtime, host_shell_fallback: true } },
    snapshotFiles: { "allowed.txt": "allowed snapshot content\n" },
  }), /invalid inspect manifest/);
  assert.throws(() => createInspectRuntime({ manifest, snapshotFiles: { "allowed.txt": "tampered" } }), /identity mismatch/);
  assert.throws(() => createInspectRuntime({ manifest, snapshotFiles: { "allowed.txt": "allowed snapshot content\n", "extra.txt": "secret" } }), /exactly the declared/);
  assert.throws(() => createInspectRuntime({ manifest, snapshotFiles: {} }), /exactly the declared/);
  const directoryManifest = structuredClone(manifest);
  directoryManifest.workspace.snapshot.paths = [{ path: "src", type: "directory", size_bytes: 0, hash: digest("src") }];
  directoryManifest.workspace.snapshot.hash = digest(JSON.stringify(directoryManifest.workspace.snapshot.paths));
  assert.throws(() => createInspectRuntime({ manifest: directoryManifest, snapshotFiles: {} }), /file-only snapshot/);
});

test("rejects a declared runtime identity that differs from the installed package", () => {
  const { manifest } = fixture();
  manifest.runtime.package_version = "99.99.99";
  manifest.workspace.toolchain["just-bash"] = "99.99.99";
  assert.throws(() => createInspectRuntime({
    manifest, snapshotFiles: { "allowed.txt": "allowed snapshot content\n" },
  }), /inspect runtime identity mismatch: JustBash package version/);
});

test("binds immutable manifest identity and exact argv to the runtime handle", async () => {
  const { manifest, runtime } = fixture();
  const hash = canonicalManifestHash(manifest);
  manifest.task.command = ["printf", "widened"];
  const blocked = await executeInspectCommand({ runtime, argv: manifest.task.command });
  assert.equal(blocked.event, "InspectBlocked");
  assert.equal(blocked.source.manifest_hash, hash);
  await assert.rejects(executeInspectCommand({ runtime, argv: ["rg", "allowed", "/workspace"] }), /terminal \(blocked\)/);
  const nextManifest = structuredClone(manifest);
  nextManifest.task.attempt_id = `attempt-${randomUUID()}`;
  nextManifest.task.command = ["rg", "allowed", "/workspace"];
  const nextRuntime = createInspectRuntime({ manifest: nextManifest, snapshotFiles: { "allowed.txt": "allowed snapshot content\n" } });
  const declared = await executeInspectCommand({ runtime: nextRuntime, argv: nextManifest.task.command });
  assert.equal(declared.exit_code, 0);
  assert.equal(declared.source.attempt_id, nextManifest.task.attempt_id);
  assert.notEqual(declared.source.manifest_hash, hash);
  await assert.rejects(executeInspectCommand({ runtime: nextRuntime, argv: nextManifest.task.command }), /terminal \(completed\)/);
});

test("copies snapshot bytes before constructing the private filesystem", async () => {
  const bytes = Buffer.from("allowed snapshot content\n");
  const { runtime } = fixture(["cat", "allowed.txt"], { "allowed.txt": bytes });
  bytes.fill(0x78);
  const event = await executeInspectCommand({ runtime, argv: ["cat", "allowed.txt"] });
  assert.equal(event.result.stdout, "allowed snapshot content\n");
});

test("does not dispatch through a replaced Bash prototype method", async () => {
  const { runtime } = fixture();
  const original = Bash.prototype.exec;
  let replacementRan = false;
  try {
    Bash.prototype.exec = async () => {
      replacementRan = true;
      return { exitCode: 0, stdout: "forged", stderr: "" };
    };
    const event = await executeInspectCommand({ runtime, argv: ["rg", "allowed", "/workspace"] });
    assert.equal(event.exit_code, 0);
    assert.notEqual(event.result.stdout, "forged");
    assert.equal(replacementRan, false);
  } finally {
    Bash.prototype.exec = original;
  }
});

test("quoting prevents shell injection and undeclared execution", async () => {
  for (const injected of [
    "touched > /scratch/touched; missing-command",
    "don't > /scratch/touched; missing-command",
  ]) {
    const argv = ["printf", injected];
    const { runtime } = fixture(argv);
    const event = await executeInspectCommand({ runtime, argv });
    assert.equal(event.exit_code, 0);
    assert.match(event.result.stdout, /\/scratch\/touched; missing-command/);
    assert.equal("/scratch/touched" in await inspectRuntimeFilesystemSnapshot(runtime), false);
  }
  const { runtime } = fixture(["printf", "safe"]);
  const blocked = await executeInspectCommand({ runtime, argv: ["mkdir", "-p", "/workspace/undeclared"] });
  assert.equal(blocked.event, "InspectBlocked");
  assert.equal("/workspace/undeclared" in await inspectRuntimeFilesystemSnapshot(runtime), false);
});

test("rejects nested command execution before touching the virtual filesystem", async () => {
  const { runtime } = fixture();
  const dangerous = ["find", "/workspace", "-exec", "rm", "-f", "{}", ";"];
  const event = await executeInspectCommand({ runtime, argv: dangerous });
  assert.equal(event.event, "InspectBlocked");
  const next = fixture();
  const preBlocked = await executeInspectCommand({ runtime: next.runtime, argv: ["rg", "--pre", "python3", "/workspace"] });
  assert.equal(preBlocked.event, "InspectBlocked");
  assert.ok("/workspace/allowed.txt" in await inspectRuntimeFilesystemSnapshot(runtime));
});

test("hardened defaults support representative inspect commands", async () => {
  const files = { "data.json": '{"value":"marker"}\n' };
  for (const argv of [
    ["rg", "marker", "data.json"], ["jq", "-r", ".value", "data.json"],
    ["sha256sum", "data.json"], ["sort", "data.json"], ["printf", "checked"],
  ]) {
    const { runtime } = fixture(argv, files);
    const event = await executeInspectCommand({ runtime, argv });
    assert.equal(event.exit_code, 0, `${argv.join(" ")}: ${event.result.stderr}`);
    assert.equal(event.outcome, "completed");
  }
});
