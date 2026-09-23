import assert from "node:assert/strict";
import test from "node:test";

import { runNodeWithWatchdog } from "../scripts/just_bash_watchdog.mjs";

const supported = ["darwin", "linux"].includes(process.platform);
const limits = { max_rss_bytes: 512 * 1024 * 1024, wall_time_ms: 2_000, poll_interval_ms: 10 };

test("host watchdog allows a bounded worker", { skip: !supported }, async () => {
  const result = await runNodeWithWatchdog(["-e", "setTimeout(() => process.exit(0), 100)"], limits, { stdio: "ignore" });
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.exit_code, 0);
  assert.ok(result.peak_rss_bytes > 0);
});

test("host watchdog terminates a worker exceeding wall time", { skip: !supported }, async () => {
  const result = await runNodeWithWatchdog(["-e", "setInterval(() => {}, 1000)"], {
    ...limits, wall_time_ms: 100,
  }, { stdio: "ignore" });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "host wall-time limit exceeded");
  assert.equal(result.signal, "SIGKILL");
});

test("host watchdog terminates a worker exceeding RSS", { skip: !supported }, async () => {
  const result = await runNodeWithWatchdog(["-e", "setInterval(() => {}, 1000)"], {
    ...limits, max_rss_bytes: 1024 * 1024,
  }, { stdio: "ignore" });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "host RSS limit exceeded");
  assert.ok(result.peak_rss_bytes > 1024 * 1024);
  assert.equal(result.signal, "SIGKILL");
});

test("host watchdog rejects invalid limits before spawning", async () => {
  await assert.rejects(
    runNodeWithWatchdog(["-e", "process.exit(0)"], { ...limits, poll_interval_ms: 0 }),
    /invalid watchdog poll_interval_ms/,
  );
});
