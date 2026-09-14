# Capability classification and execution profiles

**Language:** English | [日本語](../ja-JP/mechanisms/01-capability-profiles.md)

## Purpose

Select an execution environment from the capabilities a task actually requires, rather than running every task in the same general-purpose shell.

## Mechanism

The workflow first separates task requirements into inputs, commands, outputs, network access, credentials, side effects, and resource limits. It then selects one of three profiles.

| Profile | Execution requirement | Boundary |
|---|---|---|
| `inspect` | Search, parse, format, or perform deterministic transformations | Restricted or in-memory filesystem; no network, credentials, or side effects |
| `guest-build` | Install dependencies, build, test, generate code, or run arbitrary binaries | Short-lived guest VM with read-only input and guest-local scratch |
| `elevated-release` | Perform one explicit external write after build evidence exists | `guest-build` restrictions plus a task-scoped host-side broker |

## Decision rule

Use `inspect` only when the task does not require arbitrary native execution. Use `guest-build` as soon as a package manager, compiler, test runner, generated program, or unknown binary must run. Use `elevated-release` only for a named release operation, never for exploration.

## Failure behavior

If the selected profile cannot perform the task, do not replace the boundary with a broader host shell. Record the missing capability, add the narrowest enforceable grant, validate the manifest again, and rerun the task.
