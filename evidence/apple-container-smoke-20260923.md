# Apple Container denial smoke evidence

## Status

- Smoke result: `passed`
- Overall isolation verification: `unverified`
- Task ID: `ahi-smoke-49ae71ed`
- Captured: `2026-09-22T19:15:48.670979+00:00`
- Repository commit under test: `de5b1e8ab708455aa4de638cfc3581e3bc06b13d`
- Worktree before execution: clean
- Manifest SHA-256: `sha256:6cff99ec124218d65fc2346c63884d8dfda6afe26d6cb2464dfa6942b6c50230`
- Raw evidence SHA-256: `ff606eb0ac8813d9f9e972dbc455ca627b03c3de3387ab77130607215eb3d15c`

The smoke test passed every oracle below. The overall status remains `unverified` because this bounded run did not exhaust every resource limit or every agent-exposed command path required by the full adversarial plan.

## Host and runtime

| Item | Observed value |
|---|---|
| macOS | `26.7` |
| Architecture | `arm64` |
| Apple Container CLI | `1.2.2`, commit `0190097d06df0b9065f4c2d2c7873c649d81d493` |
| API server | running, version `1.2.2` |
| Kernel | `opt/kata/share/kata-containers/vmlinux-6.18.15-186` |
| Kernel digest | `sha256:f63d54507d1f18635d94475077e4c2330de4d8e05cedf25f7c38f063b0e66a91` |
| VM init image | `ghcr.io/apple/containerization/vminit:0.40.1` |
| Test image | `docker.io/library/alpine:3.22` |
| Test image digest | `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce` |

## Observed denials and bounds

| Class | Oracle | Observation |
|---|---|---|
| Mount | Root filesystem write fails | `rootfs-denied` |
| Mount | Read-only input snapshot write fails | `workspace-write-denied` |
| Mount | Host home hierarchy is absent | `host-home-hidden` |
| Credential | SSH agent is absent | `ssh-agent-hidden` |
| Command path | Docker/container control sockets are absent | `control-socket-hidden` |
| Network | Only loopback interface exists | `network-loopback-only` |
| Network | Internet endpoint is unreachable | `internet-egress-denied` |
| Side effect | Host gateway is unreachable | `host-gateway-denied` |
| Capability | Effective capability mask is zero | `capabilities-dropped` |
| Resource | Open-file limit | `nofile=64` |
| Resource | Process limit | `nproc=32` |
| Resource | CPU / memory configuration | 1 CPU / 268435456 bytes |
| Resource | Runtime stats | 2 processes, 4096000 bytes used, 0 network RX/TX |
| Supply chain | Runtime image digest equals manifest digest | matched |
| Result gate | Guest output volume write and readonly import | `artifact-ok` |
| Cleanup | Test container and both named volumes absent afterward | passed |

## Reproduction

```bash
container system start --enable-kernel-install --timeout 120
python3 scripts/run_apple_container_smoke.py \
  --output evidence/apple-container-smoke-YYYYMMDD.json
```

The runner creates UUID-suffixed resources and deletes only the container and volumes it created. Full commands, manifest, inspect output, stats, logs, system properties, artifact contents, and cleanup result are retained in [apple-container-smoke-20260923.json](apple-container-smoke-20260923.json).

## Remaining full-verification work

- Exhaust CPU, memory, disk, log, process, VM-count, and wall-time limits independently.
- Exercise every agent-exposed MCP, Skill, editor, and broker path.
- Test a real task-dedicated gateway network with active, expired, mismatched, and over-budget grants.
- Run path traversal, symlink, special-file, and oversize artifact-import adversarial cases.
