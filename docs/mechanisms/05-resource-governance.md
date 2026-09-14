# Resource limits, watchdogs, and cleanup

**Language:** English | [日本語](../ja-JP/mechanisms/05-resource-governance.md)

## Purpose

Bound workloads that consume host capacity without crossing a filesystem, credential, or network boundary.

## Mechanism

The task manifest defines limits for:

- CPU
- memory
- process count
- disk usage
- log volume
- concurrent VM count
- wall time

A host-side watchdog observes the workload and enforces the stop condition. Cleanup removes the guest, scratch storage, temporary network grants, and short-lived credentials after completion, failure, or timeout.

## Separation of responsibilities

The guest runtime enforces the resource controls it supports. The host scheduler controls fleet-wide concerns such as VM count, accumulated logs, timeout handling, and cleanup. Do not assume one runtime flag covers all of these limits.

## Failure behavior

If a limit is exceeded, terminate the workload, preserve bounded diagnostic evidence, and run cleanup. If the target runtime cannot enforce a required limit, record that control as `blocked` or select a stronger execution host.
