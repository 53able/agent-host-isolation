# Apple Container runtime contract

This contract applies to Manifest v2 documents whose `runtime.kind` is `apple-container`.

## Trust boundary

Apple Container supplies a lightweight VM per container. That VM boundary does not revoke capabilities explicitly passed through host mounts, SSH forwarding, published sockets, nested virtualization, environment inheritance, published ports, or networking. The standard profile rejects those capabilities and requires:

- an immutable OCI digest;
- a read-only root filesystem and input snapshot;
- named, size-limited scratch and output volumes;
- all Linux capabilities dropped;
- explicit CPU, memory, process, open-file, disk, log, VM-count, and wall-time enforcement owners;
- a task-dedicated network connected to an external default-deny gateway.

`--network` only selects an attachment. It is not evidence of destination-, method-, or scope-level egress enforcement. A manifest with no grants still needs the gateway to deny all egress. If the host cannot provide that gateway, execution is blocked or unverified.

## Command compilation

`scripts/apple_container_compiler.py` accepts only a manifest path and a fixed action. It returns a JSON argv array for volume creation, create/run, start/stop/delete, inspect, logs, boot logs, or one-shot JSON stats. It never accepts passthrough CLI options.

Create/run always generates `--read-only`, `--cap-drop ALL`, explicit resource limits, the declared mounts, explicit environment values, the task network, and these labels:

- `org.agent-host-isolation.task-id`
- `org.agent-host-isolation.manifest-hash`
- `org.agent-host-isolation.workspace-hash`

The caller must execute the array directly. Joining it into a string and evaluating it through a shell violates this contract.

## Lifecycle

The allowed state transitions are implemented in `scripts/task_lifecycle.py`. `stop` followed by `start` restarts the container process while retaining its filesystems; it is not a memory checkpoint.

Application-level resume is a separate `Stopped -> Resuming -> Running` path. The checkpoint must bind the task ID, manifest hash, workspace hash, and state hash. Checkpoints containing directly inherited credentials are rejected. Credential and network leases must be checked and reissued before entering `Running`.

## Evidence and verification

Inspect, stdio logs, boot logs, JSON stats, Apple system logs, gateway decisions, broker decisions, watchdog timeouts, checkpoints, transitions, and cleanup results normalize into events containing the task ID, manifest hash, and workspace hash.

Compiler or validator success is static evidence only. The status remains `unverified` until all seven adversarial classes pass on the recorded macOS, Apple Container CLI, and kernel image. Unsupported tests are `blocked`; they never become verified by inference.

Run `python3 scripts/probe_apple_container.py isolation-manifest.json` before execution. The probe records host and CLI versions, required option availability, service status, and system properties without starting services or containers. A successful probe means only `ready for adversarial tests`; it deliberately leaves verification status `unverified`.
