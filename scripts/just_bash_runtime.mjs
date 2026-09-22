#!/usr/bin/env node

/**
 * The host-side boundary for one JustBash command execution.
 *
 * This adapter accepts a JustBash instance, never an arbitrary executor.
 * A simple unsupported command with exit code 127 is converted into an InspectBlocked event;
 * there is no host-shell fallback and no automatic escalation here.
 */

export const INSPECT_BLOCKED_EVENT = "InspectBlocked";
export const INSPECT_BLOCKED_EXIT_CODE = 127;

import { Bash } from "just-bash";
import { createHash } from "node:crypto";

const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const ATOMIC_COMMAND = /^[A-Za-z][A-Za-z0-9._/-]*(?: [A-Za-z0-9._:/?=-]+)*$/;

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

/**
 * Execute exactly one command in an existing JustBash instance.
 *
 * `bash` must be a JustBash instance. A compound command can have side effects
 * before its final exit 127, so only an atomic command-not-found is classified
 * as InspectBlocked.
 * The returned record is suitable for the command audit stream.  Consumers
 * must submit a separate escalation request after validating a new target
 * manifest; this function never widens the current attempt.
 */
export async function executeInspectCommand({
  bash,
  command,
  manifest,
  missingCapability = "unsupported-command",
  options,
}) {
  if (!(bash instanceof Bash)) throw new TypeError("bash must be a JustBash instance");
  requireNonEmptyString(command, "command");
  const identity = sourceIdentity(manifest);
  requireNonEmptyString(missingCapability, "missingCapability");

  const result = await bash.exec(command, options);
  if (
    !result || typeof result !== "object" ||
    !Number.isInteger(result.exitCode) ||
    typeof result.stdout !== "string" ||
    typeof result.stderr !== "string"
  ) {
    throw new TypeError("JustBash executor must return a typed result object");
  }

  const exitCode = result.exitCode;
  if (exitCode === INSPECT_BLOCKED_EXIT_CODE && ATOMIC_COMMAND.test(command) && /command not found/i.test(result.stderr)) {
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
