---
name: agent-host-isolation
description: Designs and verifies capability-based execution boundaries for AI agents by selecting isolated hosts, mounts, network access, credentials, resource limits, and result-import gates. Use when designing or auditing agent execution isolation, sandbox policies, guest VM workflows, or host-side brokers. Don't use for prompt-only safety reviews, unrestricted host automation, or claims of verified isolation without local adversarial tests.
---

# Agent Host Isolation

## Procedure

**Step 1: Define the protection boundary.**
1. Identify the task, expected commands, required inputs, expected outputs, and every intended side effect.
2. Treat model output, web content, repository content, dependencies, and generated artifacts as untrusted input.
3. Read `references/boundary-model.md` and classify every protected asset and capability.
4. Do not use a prompt, approval dialog, or tool description as the sole protection boundary. Record it only as a supplementary control.
5. Copy `assets/isolation-manifest.template.json` to a task-specific manifest. Deny every unspecified capability.

**Step 2: Select the execution host.**
1. Use an in-memory or restricted interpreter only for deterministic inspection, search, formatting, and other operations that require no arbitrary native binary execution.
2. Use a short-lived guest VM for dependency installation, builds, tests, generated code, or arbitrary binary execution.
3. Do not treat an interpreter, a container label, or a human approval hook as equivalent to a guest-VM boundary.
4. Keep the control plane on the host only when it must retain interactive authentication or policy authority. Keep the execution plane in the selected restricted host.
5. Read `references/execution-profiles.md` before selecting a profile other than `inspect` or `guest-build`.

**Step 3: Materialize minimum capabilities.**
1. Create a read-only input snapshot containing only the repository paths required by the task. Do not mount a parent workspace or home directory.
2. Create guest-local scratch storage with a size limit. Do not use a writable host bind mount as scratch storage.
3. Disable host integration, control sockets, SSH-agent forwarding, credential helpers, and inherited secret environment variables.
4. Deny network access by default. If the task requires network access, specify every allowed destination, protocol, port, method, and purpose in the manifest.
5. Define CPU, memory, process, disk, log-volume, VM-count, and wall-time limits. Assign a host-side watchdog and cleanup action.
6. Route external writes, credential use, publishing, deployment, and patch application through a host-side result gate. Bind every elevation to a task, destination, scope, expiry, and audit record.
7. Run `python3 scripts/validate-manifest.py path/to/isolation-manifest.json` before starting the execution host. Correct every reported error; do not waive an error by modifying validator output.

**Step 4: Execute and import results.**
1. Run the workload only in the selected execution host.
2. Export artifacts into the designated guest output directory. Do not grant a writable host repository solely to collect output.
3. Treat exported artifacts as untrusted. Check paths, symlinks, file types, sizes, hashes, and the destination repository before import.
4. Present diffs and side-effect requests to the result gate. Keep Git push, deploy, POST, DELETE, and credential-bound requests unavailable to the guest.
5. Destroy the guest, scratch storage, short-lived credentials, and temporary network grants after the task completes or times out.

**Step 5: Verify the boundary locally.**
1. Copy `assets/isolation-verification.template.md` to the task evidence location.
2. Run the seven test classes in `references/adversarial-test-plan.md`: mount, credential, network, command-path, resource, supply-chain, and side-effect.
3. Capture the exact host version, guest runtime version, manifest hash, commands, observed output, and cleanup result for every test.
4. Mark the boundary `verified for tested configuration` only when every required test passes on the target host and runtime version.
5. Mark unrun, unsupported, or ambiguous tests as `blocked` or `unverified`. Do not infer pass status from vendor documentation or a successful normal build.

## Error handling

- If `scripts/validate-manifest.py` reports a writable host mount, replace it with a read-only input snapshot and guest-local scratch storage.
- If the validator reports a secret, socket, host integration, or unrestricted network grant, remove it or narrow it to a task-scoped broker capability; then rerun validation.
- If a task cannot run without a capability absent from the manifest, stop execution, add the capability with a bounded scope, and rerun validation.
- If an adversarial test reaches a protected asset or unintended endpoint, stop the profile rollout, preserve evidence, revoke temporary grants, and treat the profile as failed.
- If the guest runtime cannot provide the requested enforcement, select a stronger execution host or record the task as blocked. Do not substitute a stricter prompt for missing enforcement.
