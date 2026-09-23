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

## How the isolation mechanism works

The mechanism is divided into seven boundaries. Each document explains the control, its decision rule, and its failure behavior.

1. [Capability classification and execution profiles](docs/mechanisms/01-capability-profiles.md)
2. [Read-only input and guest-local scratch](docs/mechanisms/02-input-and-scratch.md)
3. [Default-deny network and credential handling](docs/mechanisms/03-network-and-credentials.md)
4. [Result gate and host-side broker](docs/mechanisms/04-result-gate-and-broker.md)
5. [Resource limits, watchdogs, and cleanup](docs/mechanisms/05-resource-governance.md)
6. [Adversarial verification and status recording](docs/mechanisms/06-adversarial-verification.md)
7. [JustBash inspect runtime contract](docs/mechanisms/07-just-bash-inspect-runtime.md)

## Install

Install the skill with the Vercel Skills CLI:

```bash
npx skills add 53able/agent-host-isolation
```

## Versions

Releases use Git tags. To install a fixed version:

```bash
npx skills add '53able/agent-host-isolation#v0.1.0'
```

A project installation records the source and selected Git ref in `skills-lock.json`. Commit that file when the project must reproduce the same skill version.

To update the project installation explicitly:

```bash
npx skills update agent-host-isolation -p
```

See [CHANGELOG.md](CHANGELOG.md) for release changes.

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

Copy the template for the selected runtime. For a guest build:

```bash
cp assets/isolation-manifest.template.json isolation-manifest.json
```

Manifest v2 separates `task`, `workspace`, `gateway`, `model`, `runtime`, `resources`, and `resultGate`. Define the exact input snapshot, network policy, credential references, resource enforcement owners, immutable image identity, result gate, and audit record. Keep unspecified capabilities denied. Legacy v1 manifests are rejected rather than silently translated into an executable configuration.

For a JustBash inspect task, use Manifest v2:

```bash
cp assets/just-bash-inspect-manifest.template.json isolation-manifest.json
```

The JustBash template uses the same top-level Manifest v2 resources and specializes `runtime.kind`, the minimum snapshot, interpreter limits, and `InspectBlocked` escalation policy.

Set `task.strict_memory` explicitly. Standard JustBash `inspect` accepts only `false`: its sampled worker RSS watchdog is not an OS hard limit. A strict-memory `InspectBlocked` event can generate a new, nonautomatic Apple Container `guest-build` request with a new manifest and attempt. [The bounded memory probe](evidence/strict-memory-probe-20260923.md) confirms one OS OOM limit and cleanup on the recorded host; automatic strict-memory dispatch remains disabled while the other resource and full-path checks are unverified.

### 3. Validate before execution

```bash
python3 scripts/validate-manifest.py isolation-manifest.json
```

The validator rejects legacy v1 manifests and validates both Apple Container and JustBash through the shared Manifest v2 contract. For standard JustBash it rejects incompatible profiles, unpinned versions, unsafe snapshots, optional capabilities, network grants, unknown runtime fields, unbounded limits, host-shell fallback, and incomplete escalation identities. `network-derived` grant fields are schema-checked but the profile is not executable until a request-time gateway adapter enforces exact origin, path, method, expiry, byte budget, and every redirect hop.

### 4. Compile Apple Container argv

Generate one allowlisted operation at a time:

```bash
python3 scripts/apple_container_compiler.py isolation-manifest.json create
python3 scripts/apple_container_compiler.py isolation-manifest.json start --resource-labels observed-labels.json
python3 scripts/apple_container_compiler.py isolation-manifest.json stats --resource-labels observed-labels.json
python3 scripts/apple_container_compiler.py isolation-manifest.json stop --resource-labels observed-labels.json
python3 scripts/apple_container_compiler.py isolation-manifest.json delete --resource-labels observed-labels.json
```

The compiler emits a JSON argv array, not a shell command. It always pins the image digest and emits the task, manifest, and workspace hashes as labels. It has no arbitrary-extra-argument input, so options such as `--ssh`, `--publish-socket`, `--virtualization`, `--cap-add`, undeclared mounts, ports, networks, and inherited host environment variables cannot pass through. Input snapshots must be controller-staged beneath `/var/tmp/agent-host-isolation/snapshots/<snapshot-id>`; arbitrary host paths are rejected.

Apple Container network attachment is not a destination allowlist. Networkless tasks must use `none`. A task with grants requires a task-dedicated network, an explicit external default-deny gateway identity, and a matching host-issued attestation before `create` or `run` argv can be generated. Existing-container actions also require matching task, manifest, and workspace labels. See [the Apple Container runtime contract](references/apple-container-runtime.md).

Collect non-mutating host readiness evidence before execution:

```bash
python3 scripts/probe_apple_container.py isolation-manifest.json
```

The probe never reports `verified`; it only reports whether the recorded host is ready for adversarial tests or why it is blocked.

With Apple Container services running, execute the bounded local denial smoke test and retain its JSON evidence:

```bash
python3 scripts/run_apple_container_smoke.py \
  --output evidence/apple-container-smoke-YYYYMMDD.json
```

### 5. Execute and import through a result gate

Run arbitrary binaries only inside the selected guest VM. Export patches, logs, and generated files to guest output storage. Before importing them, inspect paths, symlinks, file types, cumulative sizes, hashes, and the destination repository. `scripts/import_artifacts.py` implements the regular-file-only host import gate and refuses unexpected files or an existing destination.

Keep Git push, deployment, publishing, external writes, and credential-bound operations outside the guest. A host-side broker should validate the task, destination, scope, expiry, and audit record before performing an elevated operation.

### 6. Test denial, not only success

Copy `assets/isolation-verification.template.md` and record the seven test classes:

1. Mount
2. Credential
3. Network
4. Command path
5. Resource
6. Supply chain
7. Side effect

Use `verified for tested configuration` only after every required test passes on the named host, runtime version, and manifest. Mark unrun or unsupported checks as `blocked` or `unverified`.

The recorded JustBash test run is in [`evidence/just-bash-adversarial-20260923.md`](evidence/just-bash-adversarial-20260923.md). Reproduce it with `npm ci --ignore-scripts && npm run test:just-bash-adversarial`; the runner keeps the manifest `unverified` unless every required class and cleanup check passes.

## Repository structure

```text
SKILL.md
assets/
references/
scripts/
docs/
  mechanisms/
    01-...md through 07-...md
  ja-JP/
    README.md
    mechanisms/
      01-...md through 07-...md
tests/
.github/workflows/
```

## Important limitations

- This repository provides a procedure and deterministic manifest checks; it does not create a VM or host firewall by itself.
- Validator or compiler success does not make a configuration `verified`; only the seven adversarial test classes on the recorded host/runtime can do that.
- A VM does not neutralize capabilities explicitly passed through mounts, sockets, credentials, networking, or host integration.
- Restricted interpreters reduce available commands but are not equivalent to guest-VM isolation.
- Runtime-specific flags and host reachability must be tested on the target operating system and runtime version.
- A successful build is not evidence that protected paths and endpoints were denied.

## License

[MIT](LICENSE) © 2026 53able
