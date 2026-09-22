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

/**
 * Execute exactly one command in an existing JustBash instance.
 *
 * `bash` must be a JustBash instance. Only the exact declared argv is executed;
 * each argument is shell-quoted so arguments cannot become shell operators.
 * The returned record is suitable for the command audit stream.  Consumers
 * must submit a separate escalation request after validating a new target
 * manifest; this function never widens the current attempt.
 */
export async function executeInspectCommand({
  bash,
  argv,
  manifest,
  missingCapability = "unsupported-command",
  options,
}) {
  if (!(bash instanceof Bash)) throw new TypeError("bash must be a JustBash instance");
  if (bash.exec !== Bash.prototype.exec) throw new TypeError("JustBash exec method must not be replaced");
  const identity = sourceIdentity(manifest);
  requireNonEmptyString(missingCapability, "missingCapability");
  if (!validArgv(argv) || !validArgv(manifest.task?.command)) {
    throw new TypeError("requested and manifest task.command must be non-empty argv arrays");
  }
  const command = argv.map(shellQuote).join(" ");
  if (
    !allowedInspectArgv(manifest.task.command) ||
    argv.length !== manifest.task.command.length ||
    argv.some((part, index) => part !== manifest.task.command[index])
  ) {
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
  if (exitCode === INSPECT_BLOCKED_EXIT_CODE && /command not found/i.test(result.stderr)) {
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
