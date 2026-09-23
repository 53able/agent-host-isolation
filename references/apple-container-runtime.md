# Apple Container runtime contract

This contract applies to Manifest v2 documents whose `runtime.kind` is `apple-container`.

## Trust boundary

Apple Container supplies a lightweight VM per container. That VM boundary does not revoke capabilities explicitly passed through host mounts, SSH forwarding, published sockets, nested virtualization, environment inheritance, published ports, or networking. The standard profile rejects those capabilities and requires:

- an immutable OCI digest;
- a read-only root filesystem and controller-staged input snapshot beneath `/var/tmp/agent-host-isolation/snapshots`;
- guest-local scratch and output storage with declared limits (named volumes for the standard path; fixed-size tmpfs for supervised strict-memory dispatch); enforcement must be tested on the selected path;
- all Linux capabilities dropped;
- explicit CPU, memory, process, open-file, disk, log, VM-count, and wall-time enforcement owners;
- no network for tasks without grants; a task-dedicated network connected to an externally attested default-deny gateway for tasks with grants.

`--network` only selects an attachment. It is not evidence of destination-, method-, or scope-level egress enforcement. A manifest without grants must use `task_network: "none"`, which Apple Container materializes without a network interface. A manifest with grants must name `<task-id>-network`, identify the external gateway and immutable policy hash, and provide a host-issued attestation binding the task, manifest hash, network, gateway, policy, and default-deny mode. Missing or mismatched attestation blocks compilation.

## Command compilation

`scripts/apple_container_compiler.py` accepts a manifest path and a fixed action, plus optional ownership-label and network-attestation JSON paths where required. It returns a JSON argv array for volume creation, create/run, start/stop/delete, inspect, logs, boot logs, or one-shot JSON stats. It never accepts passthrough CLI options.

Create/run always generates `--read-only`, `--cap-drop ALL`, explicit resource limits, the declared mounts, explicit environment values, the task network, and these labels:

- `org.agent-host-isolation.task-id`
- `org.agent-host-isolation.manifest-hash`
- `org.agent-host-isolation.workspace-hash`

The caller must execute the array directly. Joining it into a string and evaluating it through a shell violates this contract.

Before compiling create/run, the compiler resolves the snapshot path and rejects missing directories, symlinks, or paths escaping the controller-owned snapshot root. Before compiling start/stop/delete/logs/stats, the caller supplies labels observed from `container inspect`; all three ownership labels must match. Named volumes carry the same labels.

Gateway decisions require an atomic cumulative usage ledger. `max_bytes` is a grant-wide budget, not a per-request limit. The included in-memory ledger is for local tests only; a production gateway must provide a durable transactional equivalent.

## Lifecycle

The allowed state transitions are implemented in `scripts/task_lifecycle.py`. `stop` followed by `start` restarts the container process while retaining its filesystems; it is not a memory checkpoint.

Application-level resume is a separate `Stopped -> Resuming -> Running` path. The checkpoint must bind the task ID, manifest hash, workspace hash, and state hash. Checkpoints containing directly inherited credentials are rejected. Credential and network leases must be checked and reissued before entering `Running`.

Guest output remains untrusted. `scripts/import_artifacts.py` rejects symlinks, special files, undeclared paths, cumulative size overruns, content changes during import, and pre-existing destination files while recording a SHA-256 digest for every imported file.

## Evidence and verification

Inspect, stdio logs, boot logs, JSON stats, Apple system logs, gateway decisions, broker decisions, watchdog timeouts, checkpoints, transitions, and cleanup results normalize into events containing the task ID, manifest hash, and workspace hash.

Compiler or validator success is static evidence only. The status remains `unverified` until all seven adversarial classes pass on the recorded macOS, Apple Container CLI, and kernel image. Unsupported tests are `blocked`; they never become verified by inference.

`task.strict_memory` explicitly distinguishes workloads requiring an OS-enforced ceiling. The Apple Container compiler emits `--memory`, but that flag alone does not prove enforcement. `scripts/run_strict_memory_probe.py` records the guest cgroup limit, OOM kill count, exit status, and resource cleanup for one bounded workload. The earlier named-volume/root path failed process and disk limit probes on Apple Container 1.2.2 and is rejected for ordinary strict-memory tasks. The supervised tmpfs/non-root path has separate live evidence covering those limits, watchdogs, artifact/result gate, and the declared `task.command` path. The dispatcher reruns the required checks before each target attempt; a memory probe alone never authorizes dispatch. See the [strict-memory dispatch gate](../docs/mechanisms/08-strict-memory-dispatch.md) and its linked evidence. Verification applies only to the recorded host, runtime, image, and resource profile.

Run `python3 scripts/probe_apple_container.py isolation-manifest.json` before execution. The probe records host and CLI versions, required option availability, service status, and system properties without starting services or containers. A successful probe means only `ready for adversarial tests`; it deliberately leaves verification status `unverified`.

After starting Apple Container services with explicit operator authorization, run the bounded denial smoke test:

```bash
python3 scripts/run_apple_container_smoke.py \
  --output evidence/apple-container-smoke-YYYYMMDD.json
```

The smoke test uses a networkless, read-only Alpine container compiled from Manifest v2. It checks mount, credential/socket, network, command-path, capability, resource, supply-chain identity, artifact, observability, and cleanup controls. It creates uniquely named containers and volumes and deletes only those resources.
