# Changelog

## v0.2.0 - 2026-09-23

### Breaking changes

- Legacy v1 manifests are rejected. Recreate them from the Manifest v2 templates and validate them before execution.

### Added

- Add Manifest v2 resources for task, workspace, gateway, model, Apple Container runtime, resources, and result gate.
- Add strict Manifest v2 validation, allowlisted Apple Container argv compilation, gateway grant decisions, lifecycle/checkpoint contracts, normalized event validation, and non-mutating host readiness probing.
- Add a fail-closed JustBash `inspect` runtime extension to the shared Manifest v2 contract.
- Document the JustBash boundary, lifecycle, observability, adversarial tests, and `InspectBlocked` behavior in English and Japanese.
- Add a bounded, cleanup-aware Apple Container denial smoke test with JSON evidence output.
- Add a pinned JustBash embedding that runs all seven adversarial test classes and emits hash-bound verification evidence.
- Add a host-side HTTPS fetch broker with durable grant audit records, bounded DNS resolution, per-hop redirect checks, and a result-gated bridge into a new networkless JustBash snapshot.
- Add a controller-triggered strict-memory dispatch path that rechecks the target Apple Container profile before running the declared command and importing artifacts.
- Record live broker, strict-memory, supervised resource, and automatic dispatch verification for their tested host and runtime configurations.

### Changed

- Decouple the logical skill identity from its physical installation directory in tests and deployment guidance.
- Validate pinned runtime identities, minimum snapshots, optional capabilities, scoped network grants, hardened resource limits, result-gate evidence, and Apple Container escalation requests.
- Keep direct `network-derived` JustBash execution disabled; use the one-shot host broker and a new standard `inspect` attempt for approved fetched bytes.
- Reject the named-volume/root path for ordinary strict-memory tasks after process and disk limits failed on the tested host; use the supervised tmpfs/non-root path.

## v0.1.0 - 2026-09-15

### Initial release

- Define capability-based execution boundaries for AI-agent workloads.
- Provide `inspect`, `guest-build`, and `elevated-release` execution profiles.
- Include a default-deny task-manifest template and validator.
- Document read-only inputs, guest-local scratch, network and credential controls, result gates, host-side brokers, resource governance, and adversarial verification.
- Provide English and Japanese documentation.
