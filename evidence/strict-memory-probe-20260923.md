# Strict-memory Apple Container probe

- Captured: 2026-09-23 01:28:05 UTC
- Host: macOS 26.7, arm64
- Apple Container: CLI and API server 1.2.2, commit `0190097d06df0b9065f4c2d2c7873c649d81d493`
- Task: `ahi-memory-bf88bb00`
- Source commit: `84e9d8febde52bf2c8e17033ea0f8dd83663b046` (clean worktree before probe)
- Manifest hash: `sha256:f4b7b7cacf5234359a842b2d1c584921be4aaae725c629915701e4f7efcd628a`
- [Raw evidence](strict-memory-probe-20260923.json) SHA-256: `2cc3741a0a41e181e431b2ae7f10524cf6cfc45cc8e11171e89ac52967f20639`

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
