# Execution profiles

## `inspect`

Use for text search, parsing, formatting, and deterministic transformations without arbitrary native execution.

- Filesystem: in-memory or restricted read-only view
- Network: off
- Credentials and host bridges: off
- Side effects: none

## `guest-build`

Use for package installation, builds, tests, code generation, and arbitrary binaries.

- Host: short-lived guest VM
- Inputs: minimum read-only snapshot
- Scratch and output: guest-local and quota-limited
- Network: deny unless the manifest contains a required allowlist
- Credentials, control sockets, and host integration: off
- External writes: result gate only

## `elevated-release`

Use only after `guest-build` evidence exists and an explicit release operation is required.

- Retain the `guest-build` restrictions.
- Use a host-side broker for the single named destination and action.
- Issue a short-lived, scoped credential after the result gate validates the request.
- Record the destination, request body or diff, expiry, actor, and outcome.

Do not use `elevated-release` for exploratory execution or for a task that has not passed the isolation tests applicable to its execution host.
