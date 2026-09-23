# Strict-memory Apple Container probe

- Captured: 2026-09-23 00:59:44 UTC
- Host: macOS 26.7, arm64
- Apple Container: CLI and API server 1.2.2, commit `0190097d06df0b9065f4c2d2c7873c649d81d493`
- Task: `ahi-memory-2c45e952`
- Manifest hash: `sha256:6d75bd845fa92ca808c32e0a06999bed761bc681337f5d3a4527844a98bdc315`
- [Raw evidence](strict-memory-probe-20260923.json) SHA-256: `2b5d8ac3fe0eb48038ba90134f46b8aad75642291f27c00e2c7255f316784682`

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
