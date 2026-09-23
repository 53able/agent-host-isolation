#!/usr/bin/env node

/**
 * The host-side boundary for one JustBash command execution.
 *
 * This adapter accepts only a module-owned inspect runtime, never an arbitrary executor.
 * A simple unsupported command with exit code 127 is converted into an InspectBlocked event;
 * there is no host-shell fallback and no automatic escalation here.
 */

export const INSPECT_BLOCKED_EVENT = "InspectBlocked";
export const INSPECT_BLOCKED_EXIT_CODE = 127;

import { Bash } from "just-bash";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const VALIDATOR = fileURLToPath(new URL("./validate-manifest.py", import.meta.url));
const trustedRuntimes = new WeakMap();
const BASH_EXEC = Bash.prototype.exec;
export const AGENT_HOST_ISOLATION_VERSION = "0.1.0";

const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const INSPECT_COMMAND_MIN_ARGS_V1 = {
  cat: 1, ls: 0, head: 1, tail: 1, rg: 2, grep: 2,
  wc: 1, sort: 1, uniq: 1, jq: 2, sha256sum: 1, md5sum: 1,
  printf: 1, echo: 0,
};

function validArgv(value) {
  return Array.isArray(value) && value.length > 0 &&
    value.every((part) => typeof part === "string" && part.length > 0 && !part.includes("\0"));
}

function allowedInspectArgv(argv) {
  if (!Object.hasOwn(INSPECT_COMMAND_MIN_ARGS_V1, argv[0])) return false;
  const minimum = INSPECT_COMMAND_MIN_ARGS_V1[argv[0]];
  let args = argv.slice(1);
  if (argv[0] === "jq" && args[0] === "-r") args = args.slice(1);
  return args.length >= minimum && args.every((part) => !part.startsWith("-"));
}

function shellQuote(value) {
  return `'${value.split("'").join("'\"'\"'")}'`;
}

function requireNonEmptyString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function canonicalManifestHash(manifest) {
  const { verification: _verification, ...executable } = manifest;
  return `sha256:${createHash("sha256").update(stableJson(executable)).digest("hex")}`;
}

function sourceIdentity(manifest) {
  if (!manifest || typeof manifest !== "object" || manifest.runtime?.kind !== "just-bash" || manifest.runtime?.host_shell_fallback !== false) {
    throw new TypeError("validated JustBash manifest with host shell fallback disabled is required");
  }
  const taskId = requireNonEmptyString(manifest.task?.id, "manifest.task.id");
  const attemptId = requireNonEmptyString(manifest.task?.attempt_id, "manifest.task.attempt_id");
  if (!SAFE_ID.test(taskId) || !SAFE_ID.test(attemptId)) {
    throw new TypeError("manifest task identity must use safe identifiers");
  }
  return {
    task_id: taskId,
    attempt_id: attemptId,
    manifest_hash: canonicalManifestHash(manifest),
  };
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function executionLimits(limits) {
  return {
    maxCallDepth: limits.max_call_depth,
    maxCommandCount: limits.max_command_count,
    maxSourceBytes: limits.max_source_bytes,
    maxFileSystemBytes: limits.max_filesystem_bytes,
    maxOutputSize: limits.max_output_bytes,
    maxArchiveBytes: limits.max_archive_bytes,
    maxDatabaseBytes: limits.max_database_bytes,
    maxExecutionTimeMs: limits.max_execution_time_ms,
    maxExtensionCleanupTimeMs: limits.max_extension_cleanup_time_ms,
  };
}

function assertRuntimeIdentity(manifest) {
  const installed = JSON.parse(readFileSync(new URL("../node_modules/just-bash/package.json", import.meta.url), "utf8"));
  const lockfile = readFileSync(new URL("../package-lock.json", import.meta.url));
  const locked = JSON.parse(lockfile).packages?.["node_modules/just-bash"];
  const problems = [];
  if (manifest.workspace.lockfile.path !== "package-lock.json" || manifest.workspace.lockfile.sha256 !== sha256(lockfile)) problems.push("lockfile hash");
  if (!locked?.integrity?.startsWith("sha512-") || locked.version !== installed.version) problems.push("installed package lock identity");
  if (manifest.runtime.package_version !== installed.version || manifest.workspace.toolchain["just-bash"] !== installed.version) problems.push("JustBash package version");
  if (manifest.runtime.node_version !== process.versions.node || manifest.workspace.toolchain.node !== process.versions.node) problems.push("Node.js version");
  if (manifest.runtime.agent_host_isolation_version !== AGENT_HOST_ISOLATION_VERSION || manifest.workspace.toolchain["agent-host-isolation"] !== AGENT_HOST_ISOLATION_VERSION) problems.push("agent-host-isolation version");
  if (problems.length) throw new TypeError(`inspect runtime identity mismatch: ${problems.join(", ")}`);
}

function claimAttempt(identity) {
  const gitDir = spawnSync("git", ["rev-parse", "--git-common-dir"], {
    cwd: ROOT, encoding: "utf8", timeout: 5_000,
  });
  if (gitDir.error || gitDir.status !== 0 || !gitDir.stdout.trim()) {
    throw new TypeError("durable repository attempt registry is unavailable");
  }
  const claimRoot = join(resolve(ROOT, gitDir.stdout.trim()), "agent-host-isolation", "just-bash-attempts-v1");
  mkdirSync(claimRoot, { recursive: true, mode: 0o700 });
  const root = lstatSync(claimRoot);
  if (!root.isDirectory() || root.isSymbolicLink() || root.uid !== process.getuid() || (root.mode & 0o077) !== 0) {
    throw new TypeError("host attempt registry must be a private owned directory");
  }
  const claim = join(claimRoot, sha256(`${identity.task_id}\0${identity.attempt_id}`).slice(7));
  try {
    mkdirSync(claim, { mode: 0o700 });
  } catch (error) {
    if (error.code === "EEXIST") throw new TypeError("Task attempt was already claimed; create a new attempt");
    throw error;
  }
  writeFileSync(join(claim, "manifest-hash"), `${identity.manifest_hash}\n`, { flag: "wx", mode: 0o600 });
  return claim;
}

/** Validate and privately construct the standard, networkless inspect runtime. */
export function createInspectRuntime({ manifest, snapshotFiles }) {
  const boundManifest = structuredClone(manifest);
  const validation = spawnSync("python3", [VALIDATOR, "-"], {
    cwd: ROOT,
    input: JSON.stringify(boundManifest),
    encoding: "utf8",
    timeout: 5_000,
  });
  if (validation.error || validation.status !== 0) {
    throw new TypeError(`invalid inspect manifest: ${validation.error?.message ?? validation.stderr.trim()}`);
  }
  assertRuntimeIdentity(boundManifest);
  const identity = sourceIdentity(boundManifest);
  if (!snapshotFiles || typeof snapshotFiles !== "object" || Array.isArray(snapshotFiles)) {
    throw new TypeError("snapshotFiles must map declared relative paths to content");
  }
  const paths = boundManifest.workspace.snapshot.paths;
  if (sha256(JSON.stringify(paths)) !== boundManifest.workspace.snapshot.hash) {
    throw new TypeError("input snapshot aggregate hash mismatch");
  }
  if (paths.some((entry) => entry.type !== "regular")) {
    throw new TypeError("standard inspect requires file-only snapshot entries; expand directories before construction");
  }
  const regularPaths = paths.filter((entry) => entry.type === "regular");
  if (Object.keys(snapshotFiles).length !== regularPaths.length) {
    throw new TypeError("snapshotFiles must contain exactly the declared regular files");
  }
  const files = {};
  for (const entry of regularPaths) {
    if (!Object.hasOwn(snapshotFiles, entry.path)) throw new TypeError(`missing snapshot file: ${entry.path}`);
    const value = snapshotFiles[entry.path];
    if (typeof value !== "string" && !(value instanceof Uint8Array)) {
      throw new TypeError(`snapshot file must be bytes or text: ${entry.path}`);
    }
    const content = Buffer.from(value);
    if (content.length !== entry.size_bytes || sha256(content) !== entry.hash) {
      throw new TypeError(`snapshot file identity mismatch: ${entry.path}`);
    }
    files[`/workspace/${entry.path}`] = content;
  }
  const claim = claimAttempt(identity);
  const bash = new Bash({
    files,
    cwd: "/workspace",
    env: { HOME: "/home/user", PATH: "/bin:/usr/bin" },
    commands: Object.keys(INSPECT_COMMAND_MIN_ARGS_V1),
    executionLimitProfile: "hardened",
    executionLimits: executionLimits(boundManifest.runtime.limits),
    python: false,
    javascript: false,
    customCommands: [],
    defenseInDepth: { enabled: "auto", auditMode: false },
  });
  const runtime = Object.freeze(Object.create(null));
  trustedRuntimes.set(runtime, { bash, manifest: boundManifest, identity, claim, phase: "ready", abortController: new AbortController() });
  return runtime;
}

/** Read-only virtual-filesystem evidence without exposing the Bash instance. */
export async function inspectRuntimeFilesystemSnapshot(runtime) {
  const state = trustedRuntimes.get(runtime);
  if (!state) throw new TypeError("trusted inspect runtime is required");
  const snapshot = {};
  for (const path of [...state.bash.fs.getAllPaths()].sort()) {
    const stat = await state.bash.fs.lstat(path);
    if (stat.isSymbolicLink) snapshot[path] = { type: "symlink", target: await state.bash.fs.readlink(path) };
    else if (stat.isDirectory) snapshot[path] = { type: "directory" };
    else {
      const content = await state.bash.fs.readFileBuffer(path);
      snapshot[path] = { type: "regular", bytes: content.byteLength, sha256: sha256(content) };
    }
  }
  return snapshot;
}

/** Host controller only: stop this attempt when inspection reveals a strict memory requirement. */
export async function blockInspectForStrictMemory({ runtime }) {
  const state = trustedRuntimes.get(runtime);
  if (!state) throw new TypeError("trusted inspect runtime is required");
  if (state.phase !== "ready" && state.phase !== "executing") {
    throw new TypeError(`inspect runtime attempt is terminal (${state.phase})`);
  }
  const command = state.command ?? state.manifest.task.command.map(shellQuote).join(" ");
  const event = {
    event: INSPECT_BLOCKED_EVENT,
    outcome: "blocked",
    command,
    exit_code: INSPECT_BLOCKED_EXIT_CODE,
    source: state.identity,
    missing_capability: "strict-memory",
    host_shell_fallback: false,
    escalation: { automatic: false, requested: false },
    result: { exitCode: INSPECT_BLOCKED_EXIT_CODE, stdout: "", stderr: "strict memory requirement discovered by host controller" },
  };
  state.strictMemoryEvent = event;
  state.phase = "blocked";
  const settled = state.execution ? state.execution.then(() => {}, () => {}) : Promise.resolve();
  state.blockPromise = settled.then(() => {
    writeFileSync(join(state.claim, "strict-memory-event.json"), JSON.stringify(event), { flag: "wx", mode: 0o600 });
    return event;
  });
  state.abortController.abort();
  return state.blockPromise;
}

/**
 * Execute the declared command once through a privately owned JustBash instance.
 *
 * `runtime` must be created by createInspectRuntime. Only the exact declared argv is executed;
 * each argument is shell-quoted so arguments cannot become shell operators.
 * The returned record is suitable for the command audit stream.  Consumers
 * must submit a separate escalation request after validating a new target
 * manifest; this function never widens the current attempt.
 */
export async function executeInspectCommand({
  runtime,
  argv,
  missingCapability = "unsupported-command",
  signal,
}) {
  const state = trustedRuntimes.get(runtime);
  if (!state) throw new TypeError("trusted inspect runtime is required");
  if (state.phase !== "ready") throw new TypeError(`inspect runtime attempt is terminal (${state.phase})`);
  const { bash, manifest, identity } = state;
  requireNonEmptyString(missingCapability, "missingCapability");
  if (missingCapability === "strict-memory") {
    throw new TypeError("strict-memory requires the host controller stop path");
  }
  if (!validArgv(argv) || !validArgv(manifest.task?.command)) {
    throw new TypeError("requested and manifest task.command must be non-empty argv arrays");
  }
  const command = argv.map(shellQuote).join(" ");
  if (
    !allowedInspectArgv(manifest.task.command) ||
    argv.length !== manifest.task.command.length ||
    argv.some((part, index) => part !== manifest.task.command[index])
  ) {
    state.phase = "blocked";
    return {
      event: INSPECT_BLOCKED_EVENT,
      outcome: "blocked",
      command,
      exit_code: INSPECT_BLOCKED_EXIT_CODE,
      source: identity,
      missing_capability: "undeclared-command",
      host_shell_fallback: false,
      escalation: { automatic: false, requested: false },
      result: { exitCode: INSPECT_BLOCKED_EXIT_CODE, stdout: "", stderr: "requested argv is not declared for this inspect attempt" },
    };
  }

  state.phase = "executing";
  state.command = command;
  let result;
  try {
    const executionSignal = signal ? AbortSignal.any([signal, state.abortController.signal]) : state.abortController.signal;
    state.execution = Reflect.apply(BASH_EXEC, bash, [command, { signal: executionSignal }]);
    result = await state.execution;
  } catch (error) {
    if (state.strictMemoryEvent) return state.blockPromise;
    state.phase = "failed";
    throw error;
  }
  if (state.strictMemoryEvent) return state.blockPromise;
  if (
    !result || typeof result !== "object" ||
    !Number.isInteger(result.exitCode) ||
    typeof result.stdout !== "string" ||
    typeof result.stderr !== "string"
  ) {
    state.phase = "failed";
    throw new TypeError("JustBash executor must return a typed result object");
  }

  const exitCode = result.exitCode;
  state.phase = exitCode === 0 ? "completed" : "failed";
  if (exitCode === INSPECT_BLOCKED_EXIT_CODE && /command not found/i.test(result.stderr)) {
    state.phase = "blocked";
    return {
      event: INSPECT_BLOCKED_EVENT,
      outcome: "blocked",
      command,
      exit_code: exitCode,
      source: identity,
      missing_capability: missingCapability,
      host_shell_fallback: false,
      escalation: { automatic: false, requested: false },
      result,
    };
  }

  return {
    event: "command",
    outcome: exitCode === 0 ? "completed" : "failed",
    command,
    exit_code: exitCode,
    source: identity,
    host_shell_fallback: false,
    result,
  };
}
