# Read-only input and guest-local scratch

**Language:** English | [日本語](../ja-JP/mechanisms/02-input-and-scratch.md)

## Purpose

Let the guest read the files required by the task without giving it direct write access to the host repository or unrelated host paths.

## Mechanism

Create a task snapshot containing only the required repository paths and mount it read-only. Keep the host home directory and parent workspace outside the guest. Place dependency caches, build output, temporary files, and intermediate state in size-limited guest-local scratch storage.

```text
host repository
  → minimal read-only snapshot
  → guest execution
  → guest-local scratch and output
```

The input snapshot and scratch storage have different roles. The snapshot is the immutable source material. Scratch is disposable working state owned by the guest.

## Import boundary

Do not make the host repository writable merely to collect output. Export intended artifacts from guest storage and pass them to the result gate for inspection.

## Failure behavior

If a build attempts to modify the read-only input, redirect the required temporary path to guest scratch. If the task truly requires a source change, export that change as an artifact instead of changing the host repository in place.
