# Adversarial verification and status recording

**Language:** English | [日本語](../ja-JP/mechanisms/06-adversarial-verification.md)

## Purpose

Test whether forbidden capabilities are denied, rather than treating successful task execution as proof of isolation.

## Mechanism

Run seven test classes against the exact host, guest runtime, and task manifest.

| Test class | Denial being tested |
|---|---|
| Mount | Access to unmounted paths, parent directories, and escaping symlinks |
| Credential | Access to environment secrets, credential files, agents, helpers, and metadata services |
| Network | Access to undeclared Internet, LAN, gateway, host-service, and control endpoints |
| Command path | Policy bypass through editors, file APIs, MCP, extensions, or host bridges |
| Resource | Work beyond configured process, memory, disk, log, and time limits |
| Supply chain | Execution with an image or tool identity different from the pinned value |
| Side effect | Push, deploy, or external write without a valid bounded broker grant |

## Evidence record

Record the host version, runtime version, manifest hash, command or procedure, expected denial, observed result, and cleanup result. These fields define the configuration to which the conclusion applies.

## Status rule

Use `verified for tested configuration` only after every required test passes. Mark unrun, unsupported, ambiguous, or failed checks as `blocked` or `unverified`. Do not transfer the result automatically to another host, runtime version, manifest, or tool path.
