# Supervised strict-memory path (2026-09-23)

Raw evidence: [`strict-memory-dispatch-tmpfs-20260923.json`](strict-memory-dispatch-tmpfs-20260923.json), SHA-256 `279591c8f3f8202754cb3a8ee1d0ac4c87b2c518432aca7ac3259e40e151f0d3`. The run began with a clean worktree at commit `376d6507051a3bc3f25890469132b230d1902453` on macOS 26.7 / Apple Container 1.2.2.

The supervised runner executed `task.command` as UID 1000 and imported its expected output through the result gate. It enforced the 32-process limit. Attempts to exceed the allocated scratch, output, and `/dev/shm` tmpfs capacities failed with `No space left on device`; their allocations sum to the 16 MiB disk budget. The memory probe, wall and log watchdogs, artifact rejection, live-child rejection, and cleanup also passed. No task container or named volume remained.

Automatic dispatch remains **blocked**. CPU, open-file, and VM-count limits and the seven adversarial classes are still unverified through this exact path. The dispatcher requires all checks to pass before starting an automatic target attempt. The earlier named-volume/root failure is preserved in [`strict-memory-dispatch-20260923.md`](strict-memory-dispatch-20260923.md).
