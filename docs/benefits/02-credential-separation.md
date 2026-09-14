# Keep credentials outside ordinary execution

**Language:** English | [日本語](../ja-JP/benefits/02-credential-separation.md)

## Situation

A build runs on a machine that also stores SSH keys, cloud tokens, Git credentials, or signing authority.

## Risk without an execution boundary

Convenient environment inheritance and socket forwarding can give the task the operator's long-lived authority. A compromised dependency or injected command may then authenticate to systems unrelated to the build.

## How the skill changes the workflow

Deny credentials in ordinary guest execution. When an operation truly requires authentication, send a bounded request to a host-side broker. Bind the request to one task, destination, scope, expiry, and audit record.

## Adoption benefit

Routine builds and tests no longer inherit long-lived credentials. Elevated authority is separated from exploratory execution and limited to a named operation.

## What this does not prove

A broker must enforce its request schema and scope. Moving credentials outside the guest does not help if the broker accepts arbitrary destinations or actions.
