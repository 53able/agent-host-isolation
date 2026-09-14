# Default-deny network and credential handling

**Language:** English | [日本語](../ja-JP/mechanisms/03-network-and-credentials.md)

## Purpose

Prevent ordinary agent execution from inheriting ambient access to external services, internal networks, and authenticated systems.

## Network mechanism

Begin with network access denied. When the task requires a connection, add an explicit grant to the manifest. Describe the destination, protocol, port, method, and purpose. Treat access to the Internet, LAN, host gateway, host services, and runtime control endpoints as separate paths to test.

## Credential mechanism

Do not pass SSH-agent sockets, cloud tokens, Git credential helpers, signing keys, or inherited secret environment variables into the guest. When an authenticated side effect is required, send a bounded request to a host-side broker instead of exposing the credential.

## Decision rule

A capability is granted because a named task step requires it, not because a tool commonly expects it. Remove the grant when that step is no longer part of the task.

## Failure behavior

A denied connection or missing credential is evidence of an unmet capability requirement. Stop, identify the exact operation, and either keep the task blocked or add a narrower grant. Do not respond by enabling unrestricted egress or forwarding a long-lived credential.
