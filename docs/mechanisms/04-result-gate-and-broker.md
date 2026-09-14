# Result gate and host-side broker

**Language:** English | [日本語](../ja-JP/mechanisms/04-result-gate-and-broker.md)

## Purpose

Separate untrusted artifact generation from permanent host changes and authenticated external side effects.

## Result-gate mechanism

The guest exports patches, archives, logs, and generated files to a designated output location. The host treats every exported artifact as untrusted and checks:

- destination repository and path
- path traversal and symlink resolution
- file type and size
- hash and source identity
- requested diff or operation

Only the inspected result is imported into the host repository.

## Broker mechanism

Git push, deployment, publishing, POST, DELETE, signing, and other credential-bound operations remain outside the guest. A host-side broker accepts a structured request and verifies its task, destination, scope, expiry, and audit record before performing one permitted operation.

## Failure behavior

Reject artifacts that do not match the expected destination or limits. Reject broker requests that are expired, address a different destination, request a broader action, or lack the required evidence.
