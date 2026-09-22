import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

import { Bash } from "just-bash";
import {
  canonicalManifestHash,
  executeInspectCommand,
  INSPECT_BLOCKED_EVENT,
} from "../scripts/just_bash_runtime.mjs";

const manifest = {
  task: { id: "inspect-task", attempt_id: "attempt-1", command: ["rg", "marker", "/workspace"] },
  runtime: { kind: "just-bash", host_shell_fallback: false },
  verification: { status: "unverified", adversarial_evidence: [] },
};

test("blocks an undeclared native command before execution with source identity", async () => {
  const bash = new Bash();

  const event = await executeInspectCommand({
    bash,
    argv: ["node", "--version"],
    manifest,
  });

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
});

test("rejects an arbitrary executor and never requests fallback", async () => {
  await assert.rejects(executeInspectCommand({
    bash: { exec: async () => ({ exitCode: 127, stdout: "", stderr: "command not found" }) },
    argv: ["node", "--version"],
    manifest,
  }), /JustBash instance/);
  const bash = new Bash();
  const event = await executeInspectCommand({
    bash,
    argv: ["node", "--version"],
    manifest,
  });

  assert.equal(event.host_shell_fallback, false);
  assert.equal(event.escalation.requested, false);
});

test("preserves successful and non-blocked JustBash results", async () => {
  const bash = new Bash();
  const declared = { ...manifest, task: { ...manifest.task, command: ["rg", "missing", "/workspace/no-file"] } };
  const event = await executeInspectCommand({
    bash,
    argv: declared.task.command,
    manifest: declared,
  });

  assert.equal(event.event, "command");
  assert.equal(event.outcome, "failed");
  assert.notEqual(event.exit_code, 0);
  assert.equal(event.host_shell_fallback, false);
  assert.equal("escalation" in event, false);
});

test("derives source identity from the manifest before execution", async () => {
  const bash = new Bash();
  await assert.rejects(
    executeInspectCommand({
      bash,
      argv: ["rg", "marker", "/workspace"],
      manifest: { ...manifest, task: { id: "inspect-task" } },
    }),
    /manifest\.task\.attempt_id/,
  );
  await assert.rejects(executeInspectCommand({
    bash,
    argv: ["rg", "marker", "/workspace"],
    manifest: { ...manifest, runtime: { kind: "just-bash", host_shell_fallback: true } },
  }), /fallback disabled/);
});

test("rejects a replaced executor on a real JustBash instance", async () => {
  const bash = new Bash();
  bash.exec = async () => ({ exitCode: 127, stdout: "", stderr: "explicit exit 127" });
  await assert.rejects(
    executeInspectCommand({ bash, argv: manifest.task.command, manifest }),
    /must not be replaced/,
  );
});

test("exact argv binding and quoting prevent shell injection and undeclared execution", async () => {
  const bash = new Bash();
  for (const injected of [
    ["printf", "touched > /scratch/touched; missing-command"],
    ["printf", "don't > /scratch/touched; missing-command"],
  ]) {
    const declared = { ...manifest, task: { ...manifest.task, command: injected } };
    const event = await executeInspectCommand({ bash, argv: injected, manifest: declared });
    assert.equal(event.exit_code, 0);
    assert.match(event.result.stdout, /\/scratch\/touched; missing-command/);
  }
  assert.equal(await bash.fs.exists("/scratch/touched"), false);
  const declared = { ...manifest, task: { ...manifest.task, command: ["printf", "safe"] } };
  const blocked = await executeInspectCommand({ bash, argv: ["mkdir", "-p", "/workspace/undeclared"], manifest: declared });
  assert.equal(blocked.event, "InspectBlocked");
  assert.equal(await bash.fs.exists("/workspace/undeclared"), false);
});

test("template hardened defaults support representative inspect commands", async () => {
  const manifest = JSON.parse(readFileSync(new URL("../assets/just-bash-inspect-manifest.template.json", import.meta.url), "utf8"));
  manifest.task.id = "inspect-task";
  const limits = manifest.runtime.limits;
  const bash = new Bash({
    files: { "/workspace/data.json": '{"value":"marker"}\n' },
    cwd: "/workspace",
    executionLimitProfile: "hardened",
    executionLimits: {
      maxCallDepth: limits.max_call_depth,
      maxCommandCount: limits.max_command_count,
      maxSourceBytes: limits.max_source_bytes,
      maxFileSystemBytes: limits.max_filesystem_bytes,
      maxOutputSize: limits.max_output_bytes,
      maxArchiveBytes: limits.max_archive_bytes,
      maxDatabaseBytes: limits.max_database_bytes,
      maxExecutionTimeMs: limits.max_execution_time_ms,
      maxExtensionCleanupTimeMs: limits.max_extension_cleanup_time_ms,
    },
  });
  for (const argv of [["rg", "marker", "data.json"], ["jq", "-r", ".value", "data.json"], ["sha256sum", "data.json"], ["sed", "s/marker/checked/", "data.json"], ["printf", "checked"]]) {
    manifest.task.command = argv;
    const event = await executeInspectCommand({ bash, argv, manifest });
    assert.equal(event.exit_code, 0, `${argv.join(" ")}: ${event.result.stderr}`);
    assert.equal(event.outcome, "completed");
  }
});
