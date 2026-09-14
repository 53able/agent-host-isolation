# Add network access only when the task needs it

**Language:** English | [日本語](../ja-JP/benefits/03-network-control.md)

## Situation

A package installation or API-backed test may need to contact a registry or service.

## Risk without an execution boundary

Unrestricted egress creates an unreviewed route to external services, the local network, and host-facing endpoints. It can also hide which dependency or test introduced the requirement.

## How the skill changes the workflow

Start with network access denied. If execution fails because a connection is required, add the specific destination, protocol, port, method, and purpose to the task manifest. Remove the grant when the task no longer needs it.

## Adoption benefit

Network capability becomes visible and reviewable instead of being an ambient property of the machine. Failures reveal the capability the task actually requires.

## What this does not prove

An allowlist must be tested against redirects, DNS behavior, host gateways, and local services on the target runtime. A configuration label alone does not establish network isolation.
