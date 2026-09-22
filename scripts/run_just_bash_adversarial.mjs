#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { arch, platform, release, tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { Bash, DefenseInDepthBox } from "just-bash";
import { invalidateVerification } from "./invalidate_just_bash_verification.mjs";
import { canonicalManifestHash, executeInspectCommand } from "./just_bash_runtime.mjs";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const INPUT = join(ROOT, "validation", "just-bash", "input", "allowed.txt");
const MANIFEST_PATH = join(ROOT, "validation", "just-bash", "manifest.json");
const EVIDENCE_JSON = join(ROOT, "evidence", "just-bash-adversarial-20260923.json");
const EVIDENCE_MD = join(ROOT, "evidence", "just-bash-adversarial-20260923.md");
const PACKAGE_VERSION = "3.4.2";
const AGENT_HOST_ISOLATION_VERSION = "0.1.0";
const TEST_CLASSES = [
  "mount",
  "credential",
  "network",
  "command_path",
  "resource",
  "supply_chain",
  "side_effect",
];

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function runHost(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    timeout: options.timeout ?? 10_000,
    env: options.env ?? process.env,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr.trim()}`,
    );
  }
  return result.stdout.trim();
}

function assertCleanExecutionInputs() {
  const dirty = runHost("git", [
    "status", "--porcelain=v1", "--untracked-files=all", "--", ".",
    ":(exclude)evidence/just-bash-adversarial-20260923.json",
    ":(exclude)evidence/just-bash-adversarial-20260923.md",
    ":(exclude)validation/just-bash/manifest.json",
  ]);
  if (dirty) {
    throw new Error(`verification requires committed execution inputs; dirty paths:\n${dirty}`);
  }
}

function packageMetadata() {
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8"));
  const installed = JSON.parse(
    readFileSync(join(ROOT, "node_modules", "just-bash", "package.json"), "utf8"),
  );
  const locked = lock.packages?.["node_modules/just-bash"];
  if (!locked?.version || !locked.integrity) {
    throw new Error("package-lock.json does not pin just-bash with integrity metadata");
  }
  return { installed, locked };
}

function hostIdentity() {
  if (platform() === "darwin") {
    return {
      os: "macOS",
      version: runHost("sw_vers", ["-productVersion"]),
      build: runHost("sw_vers", ["-buildVersion"]),
      kernel_release: release(),
      architecture: arch(),
    };
  }
  return {
    os: platform(),
    version: release(),
    build: null,
    kernel_release: release(),
    architecture: arch(),
  };
}

function snapshotRecord() {
  const content = readFileSync(INPUT);
  const paths = [
    {
      path: basename(INPUT),
      type: "regular",
      size_bytes: content.length,
      hash: sha256(content),
    },
  ];
  return {
    content,
    paths,
    hash: sha256(JSON.stringify(paths)),
  };
}

function buildManifest() {
  const snapshot = snapshotRecord();
  const nodeVersion = process.versions.node;
  const limits = {
    max_call_depth: 8,
    max_command_count: 32,
    max_source_bytes: 4096,
    max_filesystem_bytes: 131072,
    max_output_bytes: 4096,
    max_archive_bytes: 32768,
    max_database_bytes: 32768,
    max_execution_time_ms: 1000,
    max_extension_cleanup_time_ms: 25,
  };
  const resource = (name, onExceed) => ({
    limit: limits[name],
    enforced_by: "just-bash",
    on_exceed: onExceed,
  });
  return {
    manifest_version: 2,
    task: {
      id: "just-bash-adversarial-20260923",
      attempt_id: "attempt-1",
      goal: "verify the standard JustBash inspect embedding with denial-oriented adversarial probes",
      profile: "inspect",
      command: ["rg", "allowed", "/workspace"],
      command_classes: ["read", "search", "text-processing", "structured-data", "hash"],
      expected_artifacts: ["/scratch/export/result.txt"],
      lifecycle: { stop_timeout_seconds: 5, checkpoint: "application-level" },
    },
    workspace: {
      repository: {
        url: "https://github.com/53able/agent-host-isolation.git",
        commit: runHost("git", ["rev-parse", "HEAD"]),
        tree_hash: runHost("git", ["rev-parse", "HEAD^{tree}"]),
      },
      snapshot: {
        id: "just-bash-adversarial-input",
        target: "/workspace",
        read_only: true,
        hash: snapshot.hash,
        paths: snapshot.paths,
      },
      image: null,
      toolchain: {
        node: nodeVersion,
        "just-bash": PACKAGE_VERSION,
        "agent-host-isolation": AGENT_HOST_ISOLATION_VERSION,
      },
      lockfile: {
        path: "package-lock.json",
        sha256: sha256(readFileSync(join(ROOT, "package-lock.json"))),
      },
      mcps: [],
      skills: [{ id: "agent-host-isolation", version: AGENT_HOST_ISOLATION_VERSION }],
    },
    gateway: {
      default: "deny",
      task_network: null,
      ingress_ports: [],
      grants: [],
      credential_broker: null,
    },
    model: { provider: "none", id: "none", credential_broker_ref: null },
    runtime: {
      kind: "just-bash",
      package_version: PACKAGE_VERSION,
      node_version: nodeVersion,
      agent_host_isolation_version: AGENT_HOST_ISOLATION_VERSION,
      profile_variant: "standard",
      execution_limit_profile: "hardened",
      javascript: false,
      python: false,
      custom_commands: [],
      tool_invocation: false,
      inherit_host_environment: false,
      filesystem: {
        implementation: "in-memory",
        host_root: "input-snapshot-only",
        writes: "task-local-overlay",
      },
      limits,
      unsupported_command: "InspectBlocked",
      host_shell_fallback: false,
      audit_events: [
        "runtime_identity",
        "command",
        "stdout_stderr",
        "filesystem_diff",
        "artifact",
        "failure",
        "limit_violation",
        "result_gate",
        "cleanup",
      ],
      escalation: {
        target_profile: "guest-build",
        runtime_kind: "apple-container",
        require_new_manifest: true,
        require_new_attempt: true,
        automatic: false,
      },
    },
    resources: {
      max_call_depth: resource("max_call_depth", "terminate"),
      max_command_count: resource("max_command_count", "terminate"),
      max_source_bytes: resource("max_source_bytes", "block"),
      max_filesystem_bytes: resource("max_filesystem_bytes", "block"),
      max_output_bytes: resource("max_output_bytes", "terminate"),
      max_archive_bytes: resource("max_archive_bytes", "block"),
      max_database_bytes: resource("max_database_bytes", "block"),
      max_execution_time_ms: resource("max_execution_time_ms", "terminate"),
      max_extension_cleanup_time_ms: resource("max_extension_cleanup_time_ms", "terminate"),
    },
    resultGate: {
      required: true,
      filesystem_diff: true,
      artifact_import: {
        source: "/scratch/export",
        max_bytes: 4096,
        reject_symlinks: true,
        reject_path_traversal: true,
      },
      allowed_side_effects: [],
      audit_record: relative(ROOT, EVIDENCE_JSON),
    },
    verification: { status: "unverified", adversarial_evidence: [] },
  };
}

function validateManifestFile() {
  runHost("python3", ["scripts/validate-manifest.py", relative(ROOT, MANIFEST_PATH)]);
}

function assertRuntimeIdentity(manifest) {
  const { installed, locked } = packageMetadata();
  const expectedLockHash = sha256(readFileSync(join(ROOT, manifest.workspace.lockfile.path)));
  const problems = [];
  if (installed.version !== manifest.runtime.package_version) problems.push("installed package version");
  if (locked.version !== manifest.runtime.package_version) problems.push("locked package version");
  if (manifest.workspace.toolchain["just-bash"] !== manifest.runtime.package_version) problems.push("toolchain package version");
  if (manifest.runtime.node_version !== process.versions.node) problems.push("Node.js version");
  if (manifest.workspace.toolchain.node !== process.versions.node) problems.push("toolchain Node.js version");
  if (manifest.workspace.lockfile.sha256 !== expectedLockHash) problems.push("lockfile hash");
  if (!locked.integrity.startsWith("sha512-")) problems.push("package integrity");
  if (snapshotRecord().hash !== manifest.workspace.snapshot.hash) problems.push("snapshot hash");
  if (problems.length) throw new Error(`runtime identity mismatch: ${problems.join(", ")}`);
}

function executionLimits(manifest) {
  const limits = manifest.runtime.limits;
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

function makeBash(manifest, extraFiles = {}) {
  assertRuntimeIdentity(manifest);
  const content = readFileSync(INPUT, "utf8");
  return new Bash({
    files: { "/workspace/allowed.txt": content, ...extraFiles },
    cwd: "/workspace",
    env: { HOME: "/home/user", PATH: "/bin:/usr/bin" },
    executionLimitProfile: "hardened",
    executionLimits: executionLimits(manifest),
    python: false,
    javascript: false,
    customCommands: [],
    defenseInDepth: { enabled: "auto", auditMode: false },
  });
}

function tarArchive(name, content) {
  const body = Buffer.from(content);
  const header = Buffer.alloc(512);
  const field = (offset, length, value) => Buffer.from(value).copy(header, offset, 0, length);
  const octal = (value, length) => `${value.toString(8).padStart(length - 1, "0")}\0`;
  field(0, 100, name);
  field(100, 8, octal(0o644, 8));
  field(108, 8, octal(0, 8));
  field(116, 8, octal(0, 8));
  field(124, 12, octal(body.length, 12));
  field(136, 12, octal(0, 12));
  header.fill(0x20, 148, 156);
  header[156] = "0".charCodeAt(0);
  field(257, 6, "ustar\0");
  field(263, 2, "00");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  field(148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  const padding = Buffer.alloc((512 - (body.length % 512)) % 512);
  return Buffer.concat([header, body, padding, Buffer.alloc(1024)]);
}

function summarizeResult(result) {
  const summarize = (value) => ({
    preview: value.slice(0, 512),
    bytes: Buffer.byteLength(value),
    sha256: sha256(value),
  });
  return {
    exit_code: result.exitCode,
    stdout: summarize(result.stdout ?? ""),
    stderr: summarize(result.stderr ?? ""),
  };
}

function limitViolation(stderr) {
  for (const [pattern, name] of [
    [/maximum recursion depth/, "max_call_depth"],
    [/too many commands/, "max_command_count"],
    [/script input size limit/, "max_source_bytes"],
    [/filesystem byte limit/, "max_filesystem_bytes"],
    [/(?:output size|format width) limit/, "max_output_bytes"],
    [/archive.*(?:limit|large)/i, "max_archive_bytes"],
    [/database.*limit/i, "max_database_bytes"],
    [/execution deadline/, "max_execution_time_ms"],
    [/execution aborted/, "cancellation"],
  ]) {
    if (pattern.test(stderr)) return name;
  }
  return null;
}

async function filesystemSnapshot(bash) {
  if (typeof bash.fs.getAllPaths !== "function") {
    throw new Error("filesystem diff audit unavailable: fs.getAllPaths is not exposed");
  }
  const snapshot = {};
  for (const path of [...bash.fs.getAllPaths()].sort()) {
    const stat = await bash.fs.lstat(path);
    if (stat.isSymbolicLink) {
      snapshot[path] = { type: "symlink", target: await bash.fs.readlink(path) };
    } else if (stat.isDirectory) {
      snapshot[path] = { type: "directory" };
    } else {
      const content = await bash.fs.readFileBuffer(path);
      snapshot[path] = { type: "regular", bytes: content.byteLength, sha256: sha256(content) };
    }
  }
  return snapshot;
}

function filesystemDiff(before, after) {
  if (!before || !after) return null;
  const beforePaths = new Set(Object.keys(before));
  const afterPaths = new Set(Object.keys(after));
  return {
    created: [...afterPaths].filter((path) => !beforePaths.has(path)).sort(),
    deleted: [...beforePaths].filter((path) => !afterPaths.has(path)).sort(),
    modified: [...afterPaths]
      .filter((path) => beforePaths.has(path) && stableJson(before[path]) !== stableJson(after[path]))
      .sort(),
  };
}

async function evaluateArtifact(bash, candidate, resultGate) {
  const started = process.hrtime.bigint();
  const decision = (value) => ({
    duration_ms: Number(process.hrtime.bigint() - started) / 1_000_000,
    limit_violation: null,
    filesystem_diff: { created: [], deleted: [], modified: [] },
    ...value,
  });
  const source = resultGate.artifact_import.source;
  if (candidate.split("/").includes("..") || !candidate.startsWith(`${source}/`)) {
    return decision({ candidate, accepted: false, reason: "path-outside-export-root" });
  }
  let stat;
  try {
    stat = await bash.fs.lstat(candidate);
  } catch {
    return decision({ candidate, accepted: false, reason: "missing" });
  }
  if (stat.isSymbolicLink) return decision({ candidate, accepted: false, reason: "symlink" });
  if (!stat.isFile) return decision({ candidate, accepted: false, reason: "not-regular-file" });
  const content = await bash.fs.readFileBuffer(candidate);
  if (content.byteLength > resultGate.artifact_import.max_bytes) {
    return decision({ candidate, accepted: false, reason: "size-limit", bytes: content.byteLength });
  }
  return decision({
    candidate,
    accepted: true,
    reason: "accepted",
    bytes: content.byteLength,
    sha256: sha256(content),
    host_import_performed: false,
  });
}

async function executeTests(manifest, hostSentinel) {
  const probes = [];
  const classPass = Object.fromEntries(TEST_CLASSES.map((name) => [name, true]));
  const record = (testClass, name, command, expected, observed, passed) => {
    const normalized = {
      duration_ms: observed?.duration_ms ?? null,
      limit_violation: observed?.limit_violation ?? null,
      filesystem_diff: observed?.filesystem_diff ?? null,
      ...observed,
    };
    probes.push({ test_class: testClass, name, command, expected, observed: normalized, passed });
    classPass[testClass] &&= passed;
  };
  const execProbe = async (testClass, name, bash, command, expected, oracle, options) => {
    let result;
    const before = await filesystemSnapshot(bash);
    const started = process.hrtime.bigint();
    try {
      const execution = await executeInspectCommand({
        bash,
        command,
        manifest,
        options,
      });
      result = execution.result;
      const passed = Boolean(await oracle(result));
      const after = await filesystemSnapshot(bash);
      record(testClass, name, command, expected, {
        event: execution.event,
        ...summarizeResult(result),
        duration_ms: Number(process.hrtime.bigint() - started) / 1_000_000,
        limit_violation: limitViolation(result.stderr ?? ""),
        filesystem_diff: filesystemDiff(before, after),
      }, passed);
      return result;
    } catch (error) {
      const after = await filesystemSnapshot(bash).catch(() => null);
      record(testClass, name, command, expected, {
        thrown: error.message,
        duration_ms: Number(process.hrtime.bigint() - started) / 1_000_000,
        limit_violation: limitViolation(error.message),
        filesystem_diff: filesystemDiff(before, after),
      }, false);
      return null;
    }
  };

  const traversal = tarArchive("../escaped.txt", "archive escape\n");
  const oversized = tarArchive("large.txt", Buffer.alloc(40_000, 0x61));
  const bash = makeBash(manifest, {
    "/workspace/traversal.tar": traversal,
    "/workspace/oversized.tar": oversized,
  });

  // Filesystem-diff evidence is a required result-gate input. Do not run any
  // probe when the embedding cannot provide a complete virtual-filesystem
  // snapshot; otherwise a missing audit would be recorded as a successful
  // run with a null diff.
  try {
    await filesystemSnapshot(bash);
  } catch (error) {
    record(
      "side_effect",
      "filesystem-diff-audit-availability",
      "inspect virtual filesystem before adversarial probes",
      "missing filesystem snapshot capability leaves verification unverified",
      {
        thrown: error.message,
        filesystem_diff: null,
        audit_available: false,
      },
      false,
    );
    return {
      probes,
      classPass,
      resultGate: {
        accepted: false,
        reason: "filesystem-diff-audit-unavailable",
      },
      defense: DefenseInDepthBox.getInstance().getStatus(),
    };
  }

  await execProbe("mount", "snapshot-read", bash, "cat /workspace/allowed.txt", "declared snapshot is readable", (r) => r.exitCode === 0 && r.stdout === "allowed snapshot content\n");
  await execProbe("mount", "absolute-host-read", bash, `cat ${hostSentinel}`, "absolute host path is absent", (r) => r.exitCode !== 0 && !r.stdout.includes("host-secret"));
  await execProbe("mount", "parent-traversal", bash, `cat /workspace/../..${hostSentinel}`, "parent traversal cannot reach the host", (r) => r.exitCode !== 0 && !r.stdout.includes("host-secret"));
  await execProbe("mount", "symlink-escape", bash, `ln -s ${hostSentinel} /workspace/leak && cat /workspace/leak`, "symlink resolves only in the virtual filesystem", (r) => r.exitCode !== 0 && !r.stdout.includes("host-secret"));
  await execProbe("mount", "archive-traversal", bash, "tar -xf /workspace/traversal.tar -C /workspace", "archive traversal is rejected without partial extraction", async (r) => r.exitCode !== 0 && !(await bash.fs.exists("/escaped.txt")) && !(await bash.fs.exists("/workspace/escaped.txt")));

  await execProbe("credential", "host-environment", bash, "env", "host secret and inherited credential variables are absent", (r) => r.exitCode === 0 && !r.stdout.includes("JB_HOST_SECRET") && !r.stdout.includes("SSH_AUTH_SOCK") && !r.stdout.includes("AWS_") && !r.stdout.includes("GITHUB_TOKEN"));
  await execProbe("credential", "credential-files", bash, "cat ~/.aws/credentials ~/.git-credentials ~/.config/gh/hosts.yml /run/host-services/ssh-auth.sock", "standard credential paths and SSH agent socket are absent", (r) => r.exitCode !== 0 && r.stdout === "");
  await execProbe("credential", "git-helper", bash, "git credential fill", "Git credential helper is unavailable", (r) => r.exitCode === 127);

  for (const [name, target] of [
    ["internet", "https://example.com"],
    ["lan", "http://192.168.1.1"],
    ["host-gateway", "http://host.docker.internal"],
    ["loopback", "http://127.0.0.1:8080"],
    ["metadata", "http://169.254.169.254/latest/meta-data"],
    ["ip-literal", "http://1.1.1.1"],
    ["alternate-port", "https://example.com:444"],
  ]) {
    await execProbe("network", name, bash, `curl ${target}`, "undeclared network path is unavailable", (r) => r.exitCode === 127 && r.stderr.includes("command not found"));
  }
  await execProbe("network", "redirect", bash, "wget https://httpbingo.org/redirect-to?url=https://example.com", "redirect path is unavailable", (r) => r.exitCode === 127);
  await execProbe("network", "control-socket", bash, "cat /var/run/docker.sock /run/containerd/containerd.sock", "runtime control sockets are absent", (r) => r.exitCode !== 0 && r.stdout === "");

  await execProbe("command_path", "name-path", bash, "cat allowed.txt", "command-name path reads only the VFS", (r) => r.exitCode === 0 && r.stdout === "allowed snapshot content\n");
  await execProbe("command_path", "absolute-command-path", bash, "/bin/cat allowed.txt", "absolute command path has the same VFS policy", (r) => r.exitCode === 0 && r.stdout === "allowed snapshot content\n");
  for (const command of ["node --version", "python3 -c pass", "js-exec -c 1", "custom-command", "mcp call", "vi allowed.txt", "ssh localhost"]) {
    await execProbe("command_path", `blocked-${command.split(" ")[0]}`, bash, command, "optional/native/tool path is unavailable", (r) => r.exitCode === 127);
  }

  await execProbe("resource", "call-depth", makeBash(manifest), "f(){ f; }; f", "max_call_depth terminates recursion", (r) => r.exitCode === 126 && r.stderr.includes("maximum recursion depth"));
  await execProbe("resource", "command-count", makeBash(manifest), "for i in {1..64}; do true; done", "max_command_count terminates execution", (r) => r.exitCode === 126 && r.stderr.includes("too many commands"));
  await execProbe("resource", "source-bytes", makeBash(manifest), `#${"x".repeat(5000)}`, "max_source_bytes rejects input before parsing", (r) => r.exitCode === 126 && r.stderr.includes("script input size limit"));
  const filesystemProbeStarted = process.hrtime.bigint();
  try {
    makeBash(manifest, { "/workspace/too-large.bin": Buffer.alloc(manifest.runtime.limits.max_filesystem_bytes + 1) });
    record("resource", "filesystem-bytes", "construct VFS with oversized snapshot", "max_filesystem_bytes rejects allocation", { thrown: null }, false);
  } catch (error) {
    record("resource", "filesystem-bytes", "construct VFS with oversized snapshot", "max_filesystem_bytes rejects allocation", {
      thrown: error.message,
      duration_ms: Number(process.hrtime.bigint() - filesystemProbeStarted) / 1_000_000,
      limit_violation: "max_filesystem_bytes",
      filesystem_diff: { created: [], deleted: [], modified: [] },
    }, /filesystem|storage|bytes|limit/i.test(error.message));
  }
  await execProbe("resource", "output-bytes", makeBash(manifest), "printf '%05000d' 0", "max_output_bytes terminates output", (r) => r.exitCode === 126 && /(?:output size|format width) limit/.test(r.stderr));
  await execProbe("resource", "archive-bytes", bash, "mkdir -p /workspace/archive-out && tar -xf /workspace/oversized.tar -C /workspace/archive-out", "max_archive_bytes rejects expansion", (r) => r.exitCode !== 0 && /archive|limit|size/i.test(r.stderr));
  await execProbe("resource", "database-bytes", makeBash(manifest), "sqlite3 /workspace/limit.db \"CREATE TABLE t(x); INSERT INTO t VALUES(zeroblob(40000));\"", "max_database_bytes rejects oversized database", (r) => r.exitCode !== 0 && /database|limit|size/i.test(r.stderr));
  await execProbe("resource", "execution-time", makeBash(manifest), "sleep 2", "max_execution_time_ms terminates execution", (r) => r.exitCode === 124 && /deadline|time/i.test(r.stderr));
  {
    const cancellationBash = makeBash(manifest);
    const before = await filesystemSnapshot(cancellationBash);
    const controller = new AbortController();
    const started = Date.now();
    setTimeout(() => controller.abort(), 10);
    const cancelled = await cancellationBash.exec("sleep 2", { signal: controller.signal });
    const followup = await cancellationBash.exec("printf revoked");
    record(
      "resource",
      "cancellation-revocation",
      "abort sleep; then execute a fresh bounded command",
      "abort completes promptly and no in-flight authority survives",
      {
        duration_ms: Date.now() - started,
        limit_violation: limitViolation(cancelled.stderr ?? ""),
        filesystem_diff: filesystemDiff(before, await filesystemSnapshot(cancellationBash)),
        cancelled: summarizeResult(cancelled),
        followup: summarizeResult(followup),
      },
      cancelled.exitCode !== 0 && followup.exitCode === 0 && followup.stdout === "revoked" && Date.now() - started < 500,
    );
  }

  {
    const started = process.hrtime.bigint();
    const altered = structuredClone(manifest);
    altered.runtime.package_version = "3.4.1";
    altered.workspace.toolchain["just-bash"] = "3.4.1";
    let rejected = false;
    try { assertRuntimeIdentity(altered); } catch { rejected = true; }
    record("supply_chain", "package-version", "start with just-bash@3.4.1 identity", "mismatched package identity is rejected before execution", { rejected, duration_ms: Number(process.hrtime.bigint() - started) / 1_000_000, filesystem_diff: { created: [], deleted: [], modified: [] } }, rejected);
  }
  {
    const started = process.hrtime.bigint();
    const altered = structuredClone(manifest);
    altered.workspace.lockfile.sha256 = `sha256:${"0".repeat(64)}`;
    let rejected = false;
    try { assertRuntimeIdentity(altered); } catch { rejected = true; }
    record("supply_chain", "lockfile-hash", "start with altered lockfile hash", "mismatched lockfile is rejected before execution", { rejected, duration_ms: Number(process.hrtime.bigint() - started) / 1_000_000, filesystem_diff: { created: [], deleted: [], modified: [] } }, rejected);
  }
  {
    const started = process.hrtime.bigint();
    const altered = structuredClone(manifest);
    altered.workspace.snapshot.hash = `sha256:${"0".repeat(64)}`;
    let rejected = false;
    try { assertRuntimeIdentity(altered); } catch { rejected = true; }
    record("supply_chain", "snapshot-hash", "start with altered snapshot hash", "mismatched snapshot is rejected before execution", { rejected, duration_ms: Number(process.hrtime.bigint() - started) / 1_000_000, filesystem_diff: { created: [], deleted: [], modified: [] } }, rejected);
  }

  await execProbe("side_effect", "push", bash, "git push origin HEAD", "push is unavailable without a broker grant", (r) => r.exitCode === 127);
  await execProbe("side_effect", "deploy", bash, "kubectl apply -f deploy.yml", "deploy is unavailable without a broker grant", (r) => r.exitCode === 127);
  await execProbe("side_effect", "external-post", bash, "curl -X POST https://example.com", "external write is unavailable without a broker grant", (r) => r.exitCode === 127);
  await execProbe("side_effect", "expired-grant", bash, "broker-write --grant expired --destination other", "expired or mismatched broker grant has no command path", (r) => r.exitCode === 127);
  await execProbe("side_effect", "host-write", bash, `printf compromised > ${hostSentinel}`, "absolute write remains in VFS and cannot alter host", () => readFileSync(hostSentinel, "utf8").startsWith("host-secret:"));
  await execProbe("side_effect", "snapshot-overlay", bash, "printf changed > /workspace/allowed.txt", "snapshot writes remain in overlay", () => readFileSync(INPUT, "utf8") === "allowed snapshot content\n");
  await execProbe("side_effect", "artifact-export", bash, "mkdir -p /scratch/export && printf verified > /scratch/export/result.txt", "artifact remains in VFS pending result gate", async (r) => r.exitCode === 0 && (await bash.fs.readFile("/scratch/export/result.txt")) === "verified");

  const artifactPath = "/scratch/export/result.txt";
  await bash.fs.symlink("/workspace/allowed.txt", "/scratch/export/link");
  await bash.fs.writeFile("/scratch/outside.txt", "outside");
  await bash.fs.writeFile("/scratch/export/oversized.bin", Buffer.alloc(manifest.resultGate.artifact_import.max_bytes + 1));
  const resultGate = await evaluateArtifact(bash, artifactPath, manifest.resultGate);
  record("side_effect", "result-gate", "inspect /scratch/export/result.txt", "only bounded regular-file artifact is accepted", resultGate, resultGate.accepted);

  for (const [name, candidate, expectedReason] of [
    ["result-gate-symlink", "/scratch/export/link", "symlink"],
    ["result-gate-traversal", "/scratch/export/../outside.txt", "path-outside-export-root"],
    ["result-gate-oversize", "/scratch/export/oversized.bin", "size-limit"],
  ]) {
    const decision = await evaluateArtifact(bash, candidate, manifest.resultGate);
    record("side_effect", name, `result gate inspect ${candidate}`, `result gate rejects ${expectedReason}`, decision, !decision.accepted && decision.reason === expectedReason);
  }

  return { probes, classPass, resultGate, defense: DefenseInDepthBox.getInstance().getStatus() };
}

function markdownEvidence(evidence) {
  const rows = TEST_CLASSES.map((name) => {
    const count = evidence.probes.filter((probe) => probe.test_class === name).length;
    return `| ${name} | ${count} | ${evidence.tests[name] ? "pass" : "fail"} |`;
  }).join("\n");
  return `# JustBash adversarial verification\n\n` +
    `- Overall status: \`${evidence.status}\`\n` +
    `- Captured at: \`${evidence.captured_at}\`\n` +
    `- Host: \`${evidence.host.os} ${evidence.host.version} (${evidence.host.architecture})\`\n` +
    `- JustBash: \`${evidence.runtime.package_version}\`\n` +
    `- Node.js: \`${evidence.runtime.node_version}\`\n` +
    `- Manifest SHA-256: \`${evidence.manifest_hash}\`\n` +
    `- Snapshot SHA-256: \`${evidence.input_snapshot_hash}\`\n\n` +
    `## Test classes\n\n| Class | Probes | Status |\n|---|---:|---|\n${rows}\n\n` +
    `All probe commands, bounded output previews, hashes, cleanup results, runtime capability status, and result-gate decision are recorded in \`${relative(ROOT, EVIDENCE_JSON)}\`.\n\n` +
    `JustBash is an in-process restricted interpreter, not a VM or OS isolation boundary. This result applies only to the exact recorded host, package, Node.js, manifest, snapshot, lockfile, and embedding.\n`;
}

async function main() {
  mkdirSync(join(ROOT, "validation", "just-bash"), { recursive: true });
  mkdirSync(join(ROOT, "evidence"), { recursive: true });
  invalidateVerification();
  if (process.env.npm_lifecycle_event !== "test:just-bash-adversarial") {
    throw new Error("run through 'npm run test:just-bash-adversarial' so the clean-install pretest executes");
  }
  assertCleanExecutionInputs();
  const manifest = buildManifest();
  writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
  validateManifestFile();
  assertRuntimeIdentity(manifest);

  const secret = randomBytes(24).toString("hex");
  const sentinel = join(tmpdir(), `ahi-just-bash-host-sentinel-${process.pid}`);
  const previousSecret = process.env.JB_HOST_SECRET;
  process.env.JB_HOST_SECRET = secret;
  writeFileSync(sentinel, `host-secret:${secret}\n`, { mode: 0o600 });

  let testResult;
  let cleanupPassed = false;
  let cleanupError = null;
  try {
    testResult = await executeTests(manifest, sentinel);
  } finally {
    try {
      rmSync(sentinel);
      cleanupPassed = true;
    } catch (error) {
      cleanupError = error.message;
    }
    if (previousSecret === undefined) delete process.env.JB_HOST_SECRET;
    else process.env.JB_HOST_SECRET = previousSecret;
  }

  const allPassed = cleanupPassed && TEST_CLASSES.every((name) => testResult.classPass[name]);
  const host = hostIdentity();
  const evidenceRecord = {
    host_os: host.os,
    host_version: host.version,
    embedding: "scripts/run_just_bash_adversarial.mjs:Bash+InMemoryFs",
    package_version: manifest.runtime.package_version,
    node_version: manifest.runtime.node_version,
    agent_host_isolation_version: manifest.runtime.agent_host_isolation_version,
    manifest_hash: canonicalManifestHash(manifest),
    input_snapshot_hash: manifest.workspace.snapshot.hash,
    tests: testResult.classPass,
    cleanup_passed: cleanupPassed,
  };
  if (allPassed) {
    manifest.verification = {
      status: "verified-for-tested-configuration",
      adversarial_evidence: [evidenceRecord],
    };
  }
  writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
  validateManifestFile();

  const evidence = {
    captured_at: new Date().toISOString(),
    status: allPassed ? "verified-for-tested-configuration" : "unverified",
    task_id: manifest.task.id,
    attempt_id: manifest.task.attempt_id,
    host: { ...host, home_directory_exposed_to_guest: false },
    runtime: {
      kind: "just-bash",
      package_version: manifest.runtime.package_version,
      package_integrity: packageMetadata().locked.integrity,
      installation: "npm ci --ignore-scripts via pretest:just-bash-adversarial",
      node_version: manifest.runtime.node_version,
      agent_host_isolation_version: manifest.runtime.agent_host_isolation_version,
      embedding: evidenceRecord.embedding,
      defense_in_depth: testResult.defense,
    },
    repository: manifest.workspace.repository,
    lockfile_hash: manifest.workspace.lockfile.sha256,
    manifest_path: relative(ROOT, MANIFEST_PATH),
    manifest_hash: evidenceRecord.manifest_hash,
    input_snapshot_hash: evidenceRecord.input_snapshot_hash,
    tests: testResult.classPass,
    probes: testResult.probes,
    result_gate: testResult.resultGate,
    cleanup: {
      runtime_instance_released: true,
      virtual_filesystem_released: true,
      host_sentinel_removed: cleanupPassed,
      host_environment_restored: true,
      temporary_credentials_revoked: true,
      temporary_network_grants_removed: true,
      extension_authority_revoked_after_cancellation: testResult.probes.find((probe) => probe.name === "cancellation-revocation")?.passed === true,
      error: cleanupError,
    },
  };
  writeFileSync(EVIDENCE_JSON, `${JSON.stringify(evidence, null, 2)}\n`);
  writeFileSync(EVIDENCE_MD, markdownEvidence(evidence));
  console.log(JSON.stringify({ status: evidence.status, tests: evidence.tests, evidence: relative(ROOT, EVIDENCE_JSON) }, null, 2));
  if (!allPassed) process.exitCode = 1;
}

await main();
