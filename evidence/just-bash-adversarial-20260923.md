# JustBash adversarial verification

- Overall status: `verified-for-tested-configuration`
- Captured at: `2026-09-22T22:53:57.537Z`
- Host: `macOS 26.7 (arm64)`
- JustBash: `3.4.2`
- Node.js: `24.13.1`
- Manifest SHA-256: `sha256:875cb092d32acabde193335dce9b74e2a31a7dd4af234ddd873efd7466e09649`
- Snapshot SHA-256: `sha256:844f3e4cea5dcb8868cd5e203e2d237a03fd637ce8e2e87700f3734a5e82475a`

## Test classes

| Class | Probes | Status |
|---|---:|---|
| mount | 5 | pass |
| credential | 3 | pass |
| network | 9 | pass |
| command_path | 10 | pass |
| resource | 9 | pass |
| supply_chain | 3 | pass |
| side_effect | 11 | pass |

All probe commands, bounded output previews, hashes, cleanup results, runtime capability status, and result-gate decision are recorded in `evidence/just-bash-adversarial-20260923.json`.

JustBash is an in-process restricted interpreter, not a VM or OS isolation boundary. This result applies only to the exact recorded host, package, Node.js, manifest, snapshot, lockfile, and embedding.
