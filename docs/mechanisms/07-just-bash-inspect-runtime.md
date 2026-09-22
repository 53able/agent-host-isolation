# JustBash inspect runtime

**Language:** English | [日本語](../ja-JP/mechanisms/07-just-bash-inspect-runtime.md)

## Boundary

`runtime.kind: just-bash` is an `inspect`-only, in-process interpreter. It is useful for bounded search, text processing, structured-data parsing, hashing, and deterministic transformations. It is not a VM or OS security boundary and must not run package managers, compilers, test runners, native binaries, generated programs, or workloads that require a VM boundary.

Use `assets/just-bash-inspect-manifest.template.json` for this runtime. Manifest v2 separates task identity, the minimum input snapshot, Gateway grants, runtime capabilities, result-gate policy, audit events, and verification status. The validator rejects unknown v2 fields rather than silently enabling a capability.

## Standard capabilities

The standard profile exposes only the declared snapshot to an in-memory filesystem or an overlay rooted at the already-created snapshot. Writes remain in a task-local virtual overlay. The repository root, parent workspace, home directory, host environment, child processes, native binaries, control sockets, and credentials are not exposed.

Network, JavaScript, Python, custom commands, and tool invocation are disabled. The standard validator rejects every network attachment and grant. The separately declared `network-derived` variant binds a task network and each grant to task ID, exact non-IP origin and port, path prefix, methods, scope, purpose, expiry, byte limit, redirect revalidation, and audit record. Its verified evidence additionally requires redirect, IP-literal, and alternate-port denial tests. Full Internet access is never valid. Other optional capabilities require separately specified and reviewed derived profiles; they never mutate a running standard attempt.

The manifest pins the JustBash package, Node.js, agent-host-isolation, and input snapshot identities. It selects `execution_limit_profile: hardened` and fixes call depth, command count, source, filesystem, output, archive, database, wall-clock, and extension-cleanup limits. A limit violation fails the attempt; partial output is not a successful artifact.

## Snapshot and result flow

The host constructs the snapshot before starting JustBash. Every entry records a relative path, regular-file or directory type, size, and hash. Absolute paths, parent traversal, home-relative paths, symlinks, devices, sockets, and FIFOs are rejected. Archive extraction must remain inside the virtual filesystem and within the archive expansion limit.

Filesystem changes and exported artifacts are untrusted output. The result gate validates paths, symlinks, types, sizes, hashes, and destinations before any host import. The runtime never writes directly to the host repository.

## Failure and escalation

An unsupported command or missing capability produces `InspectBlocked`. It never falls back to a host shell and never widens the current attempt. If native execution is required, create a new `guest-build` manifest, a new manifest hash, and a new Task attempt for the Apple Container runtime; validate both the new manifest and its result gate before execution. Escalation is a request, not automatic authorization.

After the target manifest validates, create the audit event with `scripts/just_bash_contract.py`. The generator rejects a reused attempt ID, a reused or malformed target manifest hash, an invalid source manifest, or a missing capability. It records source and target identities without executing either runtime.

One Task session owns one JustBash instance. Filesystem and explicit Task state may be exported between calls, but shell environment, functions, working directory, process memory, and an in-flight command are not checkpoints. Resume requires matching manifest, runtime-version, and input-snapshot hashes.

## Evidence

Events associate task and attempt IDs, manifest and snapshot hashes, runtime versions, normalized command metadata, exit code, duration, limit violations, bounded stdout/stderr hashes, filesystem diff, artifacts, result-gate decision, and cleanup outcome. AST command collection is audit assistance, not the sole security enforcement mechanism.

Keep verification status `unverified` or `blocked` until adversarial tests run against the exact package, Node.js, host, manifest, snapshot, and embedding configuration. `verified-for-tested-configuration` requires a structured record whose canonical executable-manifest hash, snapshot hash, runtime versions, seven test classes, and cleanup result all match. A validator pass establishes contract consistency; it does not prove escape resistance.
