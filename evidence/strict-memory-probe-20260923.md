# Strict-memory Apple Container probe

- Captured: 2026-09-23 01:21:35 UTC
- Host: macOS 26.7, arm64
- Apple Container: CLI and API server 1.2.2, commit `0190097d06df0b9065f4c2d2c7873c649d81d493`
- Task: `ahi-memory-31d6fb8e`
- Source commit: `7631eb38607ea7fa2edd1621b4f2911de3a98bd9` (clean worktree before probe)
- Manifest hash: `sha256:3131a1ac79588d6d062bf057b42cad3229602770b4cb2704a82c92f4cd7e6b61`
- [Raw evidence](strict-memory-probe-20260923.json) SHA-256: `916393432b54da7d280fb976207ba8709951a8d31ba523e9cdef005a8d05e530`

The guest reported `/sys/fs/cgroup/memory.max = 268435456`, matching the compiled `--memory` setting. A bounded allocation above that value exited 137. `memory.events` reported `oom 1` and `oom_kill 1`; the expected post-allocation artifact was absent. The test container and both named volumes were absent after cleanup. Apple Container rejected an earlier 64 MiB probe because this CLI requires at least 200 MiB; the final probe uses 256 MiB.

| Check | Status | Scope |
| --- | --- | --- |
| OS memory ceiling | passed | One Alpine process and one 256 MiB limit on this host/runtime |
| Container/volume cleanup | passed | Probe task resources only |
| Watchdog | unverified | No watchdog timeout was triggered |
| Artifact/result gate | unverified | Output volume was read for evidence, not imported through a full agent result gate |
| Process, disk, log, wall time | unverified | No exhaustion tests were run |
| Full agent path | unverified | Probe command, not an agent workload |

Overall strict-memory dispatch remains **unverified and disabled**. This probe does not supersede the broader Apple Container work in issue #1 or establish verification of all resource limits.

Reproduce with `python3 scripts/run_strict_memory_probe.py --output evidence/strict-memory-probe-YYYYMMDD.json` after starting Apple Container services. The runner uses a pinned image digest, records the full manifest and host properties, and deletes only its UUID-suffixed resources.
