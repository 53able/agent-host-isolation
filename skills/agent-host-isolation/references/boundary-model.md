# Boundary model

Classify capabilities before execution. Grant a capability only when the manifest names its scope and enforcement point.

| Capability | Examples | Standard disposition |
|---|---|---|
| Host filesystem | Home directory, parent workspace, credential stores | Deny |
| Task inputs | Explicit source snapshot | Read-only only |
| Guest filesystem | Scratch and output directory | Guest-local and size-limited |
| Process execution | Compiler, package manager, arbitrary binary | Guest VM for arbitrary binaries |
| Network | Package registry, API endpoint | Deny by default; allow narrowly |
| Credentials | SSH agent, cloud token, Git helper | Deny; use a task-scoped broker |
| Runtime control | Docker socket, container daemon, host bridge | Deny |
| External side effect | Push, publish, deploy, POST, DELETE | Result gate only |
| Resources | CPU, memory, disk, time, logs, VM count | Explicit quota and watchdog |

Separate the **control plane** from the **execution plane**. The control plane may retain interactive authentication and policy authority, but it must not implicitly relay broad host capabilities into the execution plane. The result gate is an enforcement point that validates a bounded request, not a generic approval prompt.
