# Strict-memory dispatch verification (2026-09-23)

The tested full path is `task.command` in Apple Container followed by the result gate. Raw evidence: [`strict-memory-dispatch-20260923.json`](strict-memory-dispatch-20260923.json), SHA-256 `7ab416747a213d52a6d9f885e39a061cae4d5a6436241c8b1dc1db6c6956fbea`. The run began with a clean worktree at commit `be554d3aec73e534ed1c3f148a175d05611c525e` on macOS 26.7 / Apple Container 1.2.2.

The memory probe, command and result-gate path, wall and log watchdogs, artifact rejection (symlink, unexpected, oversized, and output from a failed task), and cleanup passed. Every test container and its two volumes were absent after cleanup.

Automatic dispatch remains **blocked**. A task wrote 40 MiB to scratch despite the requested 16 MiB limit. A root task spawned 40 processes despite `nproc=32`. Both tests exited with `disk-limit-bypassed` or `process-limit-bypassed`. CPU, open-file, and VM-count limits and the seven adversarial classes remain unverified. The dispatcher requires all checks to pass and therefore cannot execute the target task on this evidence.
