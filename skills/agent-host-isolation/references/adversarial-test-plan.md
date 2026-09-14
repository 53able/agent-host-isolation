# Adversarial test plan

Run every test against the target host, guest runtime, and manifest. Adapt exact commands to the runtime, but preserve each oracle.

1. **Mount test:** Attempt read and write access to an unmounted host path, parent directory, and a symlink resolving outside the input snapshot. Expect denial.
2. **Credential test:** Search inherited environment variables, standard credential locations, SSH-agent sockets, Git helper access, and cloud metadata paths. Expect no usable credential.
3. **Network test:** Attempt Internet, LAN, host gateway, host-loopback service, and runtime control-socket access. Expect every undeclared path to fail.
4. **Command-path test:** Exercise every agent-exposed tool path, including shell, editor, file APIs, MCP or extension bridges, and broker clients. Expect the same workspace and capability policy.
5. **Resource test:** Exceed each configured time, process, memory, disk, and log budget with safe bounded probes. Expect enforcement, cleanup, and no host exhaustion.
6. **Supply-chain test:** Present an image or tool identity different from the pinned digest or commit. Expect rejection before execution.
7. **Side-effect test:** Attempt push, deploy, and external writes without a valid broker grant; then attempt a mismatched destination or expired grant. Expect denial.

A successful normal task does not substitute for these tests. Record every untestable oracle as `blocked`.
