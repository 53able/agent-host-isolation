# Run an unfamiliar repository without exposing the whole host

**Language:** English | [日本語](../ja-JP/benefits/01-unfamiliar-repository.md)

## Situation

An AI agent needs to install dependencies and run tests in a repository that has not yet been trusted.

## Risk without an execution boundary

Running the task directly on the host exposes every path and service available to that process. Unexpected repository content or generated commands can therefore affect more than the task requires.

## How the skill changes the workflow

Use the `guest-build` profile. Give the guest a read-only task snapshot and guest-local scratch space. Keep the host home directory, parent workspace, credentials, and control sockets outside the guest.

## Adoption benefit

The task receives enough capability to build and test without inheriting the whole host environment. If execution behaves unexpectedly, the impact boundary is smaller and explicit.

## What this does not prove

A guest VM is not sufficient by itself. Writable mounts, forwarded sockets, credentials, and unrestricted networking still expand the guest's authority and must remain controlled by the task manifest.
