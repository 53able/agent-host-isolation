# Stop resource-heavy work before it becomes a host incident

**Language:** English | [日本語](../ja-JP/benefits/05-resource-limits.md)

## Situation

A build, test, or generated command begins consuming processes, memory, disk space, logs, or wall time.

## Risk without an execution boundary

The task can exhaust host resources without reading a protected file or using a credential. Waiting for the agent to notice its own runaway workload is not a reliable stop condition.

## How the skill changes the workflow

Define CPU, memory, process, disk, log-volume, VM-count, and wall-time limits before execution. Assign a host-side watchdog and cleanup action for completion, failure, and timeout.

## Adoption benefit

Resource failure has a predefined bound and recovery path. Operators can reason about the maximum task footprint before running it.

## What this does not prove

A configured value must be exercised on the target runtime. Limits that are unsupported, unenforced, or missing from cleanup behavior remain unverified.
