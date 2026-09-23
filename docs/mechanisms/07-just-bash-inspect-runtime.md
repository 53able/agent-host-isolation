# JustBash inspect runtime

**Language:** English | [日本語](../ja-JP/mechanisms/07-just-bash-inspect-runtime.md)

## Boundary

`runtime.kind: just-bash` is an `inspect`-only, in-process interpreter. It is useful for bounded search, text processing, structured-data parsing, hashing, and deterministic transformations. It is not a VM or OS security boundary and must not run package managers, compilers, test runners, native binaries, generated programs, or workloads that require a VM boundary.

Use `assets/just-bash-inspect-manifest.template.json` for this runtime. Manifest v2 separates task identity, the minimum input snapshot, Gateway grants, runtime capabilities, result-gate policy, audit events, and verification status. The validator rejects unknown v2 fields rather than silently enabling a capability.

## Standard capabilities

The standard profile exposes only the declared snapshot to an in-memory filesystem or an overlay rooted at the already-created snapshot. Writes remain in a task-local virtual overlay. The repository root, parent workspace, home directory, host environment, child processes, native binaries, control sockets, and credentials are not exposed. The versioned command preflight allows a small set of inspection commands with positional arguments; option-led subcommands are denied. In particular, `find`, `awk`, and `sed` are not in the standard allowlist because their argument languages can delegate execution or perform additional writes.

Network, JavaScript, Python, custom commands, and tool invocation are disabled. The standard validator rejects every network attachment and grant. `network-derived` is currently rejected, including when its grant declaration is well formed: no request-time gateway adapter enforces exact origin, path, method, expiry, byte limits, and redirect-hop revalidation for JustBash. The pinned npm package does not expose the secure fetch factory through its root entry point, so this implementation does not rely on private internals or a pre-request-only check to enable network access. Declaring a grant does not enable network access. Full Internet access is never valid. Other optional capabilities require separately specified and reviewed derived profiles; they never mutate a running standard attempt.

The manifest pins the JustBash package, Node.js, agent-host-isolation, and input snapshot identities. It selects `execution_limit_profile: hardened` and fixes call depth, command count, source, filesystem, output, archive, database, wall-clock, and extension-cleanup limits. The template starts with the bounds used by the adversarial harness (8 calls deep, 32 commands, 4 KiB source/output, 128 KiB filesystem, 32 KiB archive/database, 1 s execution, 25 ms cleanup). Validator maxima are ceilings, not recommended defaults. The adversarial harness also runs in a separate Node worker under a host watchdog: 512 MiB worker RSS, 30 s total wall time, and 50 ms polling. These host limits are cross-referenced in Manifest v2 resources and a violation kills the worker process group, invalidating verification. RSS polling is best-effort, not an OS hard memory limit: short allocation spikes and memory held by other processes are outside its guarantee. Workloads requiring a strict host memory boundary need an OS-enforced worker/container limit. A limit violation fails the attempt; partial output is not a successful artifact.

Polling and RSS measurement can also delay wall-time enforcement; a strict deadline needs an OS-enforced worker/container limit.

`task.strict_memory` is required and must be `false` for standard `inspect`. A Task requiring an OS-enforced memory ceiling must not enter the JustBash runtime, even if its requested bytes are below the sampled RSS threshold. If the trusted host controller discovers that requirement before dispatch or while the command is running, it calls `blockInspectForStrictMemory({ runtime })` on its private runtime handle. The adapter terminates the attempt and returns `InspectBlocked` with `missing_capability: "strict-memory"`.

## Snapshot and result flow

The host constructs the snapshot before starting JustBash. Every entry records a relative regular-file path, size, and hash. Absolute paths, parent traversal, home-relative paths, symlinks, directories, devices, sockets, and FIFOs are rejected as entries. Archive extraction must remain inside the virtual filesystem and within the archive expansion limit.

The standard inspect factory requires a file-only snapshot manifest: expand selected directories into regular-file entries before construction. It checks every file's bytes and the aggregate path record against the manifest, then copies the bytes into the private in-memory filesystem.

Filesystem changes and exported artifacts are untrusted output. The result gate validates paths, symlinks, types, sizes, hashes, and destinations before any host import. The runtime never writes directly to the host repository.

## Failure and escalation

The host-side `scripts/just_bash_runtime.mjs` adapter accepts only an opaque handle created from a validated Manifest v2 and content-checked input snapshot by `createInspectRuntime`; caller-created JustBash instances cannot enter this path. The factory fixes networkless built-in commands, an in-memory filesystem, no optional language/tool/custom-command capability, and hardened limits. The adapter executes the declared argv at most once, shell-quoting each argument; undeclared argv becomes `InspectBlocked` before execution. A declared atomic JustBash command-not-found exit (127) also becomes `InspectBlocked`. Arbitrary shell strings and compound commands are not accepted. It never falls back to a host shell or widens the current attempt. If native execution is required, create a new `guest-build` manifest with the **same Task ID**, a new manifest hash, and a new Task attempt for the Apple Container runtime; validate both the new manifest and its result gate before execution. Escalation is a request, not automatic authorization.

The host controller keeps the runtime handle private and makes the strict-memory decision from trusted Task policy, not agent text or a caller-supplied `missingCapability`. It may call `blockInspectForStrictMemory` only while the attempt is ready or executing. The adapter marks the attempt blocked, aborts an in-flight JustBash command, and waits for that command to settle before returning the event. The pending `executeInspectCommand` call returns the same blocked event, never a successful result; subsequent execution and repeated block calls are rejected. Partial output is not eligible for result-gate import. If an in-flight command does not settle after abort, the host worker watchdog must terminate it; no strict-memory event is issued from an unconfirmed stop. A requirement discovered after the attempt is terminal needs a new Task attempt.

After the target manifest validates, pass the recorded `InspectBlocked` JSON event to `scripts/just_bash_contract.py` with the source and target manifests. The generator requires the event's source Task/attempt/manifest hash and missing capability, rejects a reused attempt ID or different Task ID, and records the blocked-event hash with both manifest identities. It does not execute either runtime.

For `strict-memory`, the new Apple Container `guest-build` manifest must set `task.strict_memory: true`. A generated request alone remains `automatic: false`. If the controller preconfigures a validated target through `createInspectRuntime`, `blockInspectForStrictMemory` dispatches a separate attempt after the inspect attempt stops. The dispatcher reruns memory exhaustion, cleanup, watchdog, artifact/result gate, the full `task.command` path, and the other required checks on the target host/runtime before execution. A manual probe result for one limit does not authorize automatic dispatch.

One standard inspect attempt owns one private JustBash instance and executes one declared command. Filesystem and explicit Task state may be exported for a new validated attempt, but shell environment, functions, working directory, process memory, and an in-flight command are not checkpoints. Resume requires matching manifest, runtime-version, and input-snapshot hashes.

The host atomically claims each Task/attempt identity once in a private registry under the repository's Git common directory. Claims are retained to prevent same-repository replay, including after a process restart. A retry must use a new attempt ID; a fresh handle with the old ID is rejected.

Claim records are not automatically pruned. They are small but grow with attempts; archival or pruning must be a deliberate host-control-plane operation after the Task is retired, and must not permit reuse of an old attempt ID.

## Evidence

Events associate task and attempt IDs, manifest and snapshot hashes, runtime versions, normalized command metadata, exit code, duration, limit violations, bounded stdout/stderr hashes, filesystem diff, artifacts, result-gate decision, and cleanup outcome. AST command collection is audit assistance, not the sole security enforcement mechanism.

Keep verification status `unverified` or `blocked` until adversarial tests run against the exact package, Node.js, host, manifest, snapshot, and embedding configuration. The runner refuses a verified result if execution inputs differ from the committed tree (excluding its generated manifest and evidence outputs). `verified-for-tested-configuration` requires a structured record whose canonical executable-manifest hash, snapshot hash, runtime versions, seven test classes, and cleanup result all match. A validator pass establishes contract consistency; it does not prove escape resistance.
