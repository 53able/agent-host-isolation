#!/usr/bin/env node

/** Host-side best-effort RSS and wall-time watchdog for the JustBash worker. */

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { invalidateVerification } from "./invalidate_just_bash_verification.mjs";
import { canonicalManifestHash } from "./just_bash_runtime.mjs";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const MANIFEST_PATH = join(ROOT, "validation/just-bash/manifest.json");
const EVIDENCE_JSON = join(ROOT, "evidence/just-bash-adversarial-20260923.json");
const EVIDENCE_MD = join(ROOT, "evidence/just-bash-adversarial-20260923.md");
export const HOST_WATCHDOG = Object.freeze({
  max_rss_bytes: 536_870_912,
  wall_time_ms: 30_000,
  poll_interval_ms: 50,
});

function readRssBytes(pid) {
  const result = spawnSync("ps", ["-o", "rss=", "-p", String(pid)], {
    encoding: "utf8", timeout: 1_000,
  });
  if (result.error || result.status !== 0) throw new Error("host RSS measurement unavailable");
  const kib = Number(result.stdout.trim());
  if (!Number.isSafeInteger(kib) || kib < 0) throw new Error("host RSS measurement invalid");
  return kib * 1024;
}

/** Runs a trusted Node argv without a shell. It is not an OS hard memory limit. */
export async function runNodeWithWatchdog(args, limits, options = {}) {
  if (!["darwin", "linux"].includes(process.platform)) throw new Error("host watchdog is unsupported on this platform");
  if (!Array.isArray(args) || args.length === 0 || args.some((arg) => typeof arg !== "string")) {
    throw new TypeError("trusted Node argv is required");
  }
  for (const name of ["max_rss_bytes", "wall_time_ms", "poll_interval_ms"]) {
    if (!Number.isSafeInteger(limits?.[name]) || limits[name] <= 0) throw new TypeError(`invalid watchdog ${name}`);
  }
  const child = spawn(process.execPath, args, {
    cwd: options.cwd ?? ROOT,
    env: options.env ?? process.env,
    stdio: options.stdio ?? "inherit",
    detached: true,
    shell: false,
  });
  const started = Date.now();
  let violation = null;
  let peakRssBytes = 0;
  const killGroup = (reason) => {
    if (violation || child.exitCode !== null || child.signalCode !== null) return;
    violation = reason;
    try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
  };
  const poll = setInterval(() => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    if (Date.now() - started > limits.wall_time_ms) {
      killGroup("host wall-time limit exceeded");
      return;
    }
    try {
      const rss = readRssBytes(child.pid);
      peakRssBytes = Math.max(peakRssBytes, rss);
      if (rss > limits.max_rss_bytes) killGroup("host RSS limit exceeded");
    } catch (error) {
      if (child.exitCode === null && child.signalCode === null) killGroup(error.message);
    }
  }, limits.poll_interval_ms);
  const onSignal = () => killGroup("host watchdog interrupted");
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  const outcome = await new Promise((done) => {
    child.once("error", (error) => done({ code: null, signal: null, error: error.message }));
    child.once("close", (code, signal) => done({ code, signal, error: null }));
  });
  clearInterval(poll);
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
  return {
    ok: !violation && !outcome.error && outcome.code === 0,
    reason: violation ?? outcome.error ?? (outcome.code === 0 ? null : `worker exited ${outcome.code ?? outcome.signal}`),
    exit_code: outcome.code,
    signal: outcome.signal,
    peak_rss_bytes: peakRssBytes,
    duration_ms: Date.now() - started,
  };
}

async function main() {
  const started = Date.now();
  const sentinelDir = mkdtempSync(join(tmpdir(), "ahi-just-bash-watchdog-"));
  let result;
  try {
    result = await runNodeWithWatchdog(["scripts/run_just_bash_adversarial.mjs"], HOST_WATCHDOG, {
      env: { ...process.env, AHI_WATCHDOG_CHILD: "1", AHI_HOST_SENTINEL_PATH: join(sentinelDir, "sentinel") },
    });
  } finally {
    rmSync(sentinelDir, { recursive: true, force: true });
  }
  const observed = {
    configured: HOST_WATCHDOG,
    peak_worker_rss_bytes: result.peak_rss_bytes,
    duration_ms: result.duration_ms,
    limit_violation: result.reason,
    worker_exit_code: result.exit_code,
    worker_signal: result.signal,
    sentinel_removed: true,
  };
  if (!result.ok) {
    let identity = {};
    try {
      if (statSync(MANIFEST_PATH).mtimeMs >= started) {
        const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
        identity = {
          task_id: manifest.task.id,
          attempt_id: manifest.task.attempt_id,
          manifest_hash: canonicalManifestHash(manifest),
          input_snapshot_hash: manifest.workspace.snapshot.hash,
        };
      }
    } catch { /* A worker stopped before manifest creation has no executable identity. */ }
    let workerEvidence = {};
    try {
      if (statSync(EVIDENCE_JSON).mtimeMs >= started) {
        workerEvidence = JSON.parse(readFileSync(EVIDENCE_JSON, "utf8"));
      }
    } catch { /* The worker may have stopped before recording probes. */ }
    invalidateVerification(result.reason, { ...workerEvidence, ...identity, host_watchdog: observed });
    process.stderr.write(`JustBash host watchdog: ${result.reason}\n`);
    process.exitCode = 1;
  } else {
    const evidence = JSON.parse(readFileSync(EVIDENCE_JSON, "utf8"));
    evidence.host_watchdog = { ...observed, limit_violation: null };
    writeFileSync(EVIDENCE_JSON, `${JSON.stringify(evidence, null, 2)}\n`);
    const markdown = readFileSync(EVIDENCE_MD, "utf8");
    writeFileSync(EVIDENCE_MD, `${markdown}\nHost watchdog: peak sampled worker RSS ${result.peak_rss_bytes} bytes; wall time ${result.duration_ms} ms; configured limits ${HOST_WATCHDOG.max_rss_bytes} bytes / ${HOST_WATCHDOG.wall_time_ms} ms.\n`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
