# Agent Host Isolation

A reusable Agent Skill for designing and verifying capability-based execution boundaries around AI agents.

**Language:** English | [日本語](docs/ja-JP/README.md)

[![CI](https://github.com/53able/agent-host-isolation/actions/workflows/ci.yml/badge.svg)](https://github.com/53able/agent-host-isolation/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why this skill exists

Prompts and approval dialogs can guide an agent, but they are not host-security boundaries. If an agent receives an unrestricted shell, writable host mounts, credentials, control sockets, and network access, a careful instruction cannot reliably remove those capabilities.

This skill moves the decision into the execution environment:

```text
untrusted input
  → define required capabilities
  → select inspect or guest-build
  → validate a default-deny task manifest
  → execute in a restricted host
  → inspect untrusted artifacts at a host-side result gate
  → run denial-oriented adversarial tests
```

The objective is not “absolute safety.” It is to make unauthorized access to named protected assets denyable and testable without relying on the model's judgment.

## Adoption benefits

Each benefit is documented as an operational story with its situation, risk, workflow change, practical value, and remaining limit.

1. [Run an unfamiliar repository without exposing the whole host](docs/benefits/01-unfamiliar-repository.md)
2. [Keep credentials outside ordinary execution](docs/benefits/02-credential-separation.md)
3. [Add network access only when the task needs it](docs/benefits/03-network-control.md)
4. [Separate artifact generation from permanent host changes](docs/benefits/04-artifact-import.md)
5. [Stop resource-heavy work before it becomes a host incident](docs/benefits/05-resource-limits.md)
6. [Replace “the build passed” with evidence that the boundary held](docs/benefits/06-boundary-evidence.md)

## Install

Install the skill with the Vercel Skills CLI:

```bash
npx skills add 53able/agent-host-isolation --skill agent-host-isolation
```

To inspect the available skill before installation:

```bash
npx skills add 53able/agent-host-isolation --list
```

## Quick start

### 1. Classify the task

Choose the smallest sufficient profile:

| Profile | Use for | Default boundary |
|---|---|---|
| `inspect` | Search, parsing, formatting, deterministic transformations | Restricted or in-memory filesystem; no network, credentials, or side effects |
| `guest-build` | Install, build, test, code generation, arbitrary binaries | Short-lived guest VM; read-only input; guest-local scratch; default-deny network |
| `elevated-release` | One explicit release operation after verified build evidence | `guest-build` restrictions plus a task-scoped host-side broker |

A restricted interpreter such as JustBash can reduce capabilities for inspection tasks. It is not a VM boundary and must not replace a guest VM for arbitrary native execution.

### 2. Create a task manifest

Copy the bundled template:

```bash
cp assets/isolation-manifest.template.json isolation-manifest.json
```

Define the exact input snapshot, network policy, credential mode, resource limits, immutable image identity, result gate, and audit record. Keep unspecified capabilities denied.

### 3. Validate before execution

```bash
python3 scripts/validate-manifest.py isolation-manifest.json
```

The validator rejects common unsafe configurations, including writable input mounts, unrestricted networking, host integration, control sockets, direct credentials without a scoped broker, missing resource limits, and mutable image identities.

### 4. Execute and import through a result gate

Run arbitrary binaries only inside the selected guest VM. Export patches, logs, and generated files to guest output storage. Before importing them, inspect paths, symlinks, file types, sizes, hashes, and the destination repository.

Keep Git push, deployment, publishing, external writes, and credential-bound operations outside the guest. A host-side broker should validate the task, destination, scope, expiry, and audit record before performing an elevated operation.

### 5. Test denial, not only success

Copy `assets/isolation-verification.template.md` and record the seven test classes:

1. Mount
2. Credential
3. Network
4. Command path
5. Resource
6. Supply chain
7. Side effect

Use `verified for tested configuration` only after every required test passes on the named host, runtime version, and manifest. Mark unrun or unsupported checks as `blocked` or `unverified`.

## Repository structure

```text
SKILL.md
assets/
references/
scripts/
docs/
  benefits/
    01-...md through 06-...md
  ja-JP/
    README.md
    benefits/
      01-...md through 06-...md
tests/
.github/workflows/
```

## Important limitations

- This repository provides a procedure and deterministic manifest checks; it does not create a VM or host firewall by itself.
- A VM does not neutralize capabilities explicitly passed through mounts, sockets, credentials, networking, or host integration.
- Restricted interpreters reduce available commands but are not equivalent to guest-VM isolation.
- Runtime-specific flags and host reachability must be tested on the target operating system and runtime version.
- A successful build is not evidence that protected paths and endpoints were denied.

## License

[MIT](LICENSE) © 2026 53able
