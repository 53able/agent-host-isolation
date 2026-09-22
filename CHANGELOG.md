# Changelog

## Unreleased

### Added

- Add Manifest v2 resources for task, workspace, gateway, model, Apple Container runtime, resources, and result gate.
- Add strict Manifest v2 validation, allowlisted Apple Container argv compilation, gateway grant decisions, lifecycle/checkpoint contracts, normalized event validation, and non-mutating host readiness probing.
- Add a fail-closed JustBash `inspect` runtime extension to the shared Manifest v2 contract.
- Document the JustBash boundary, lifecycle, observability, adversarial tests, and `InspectBlocked` behavior in English and Japanese.

### Changed

- Reject legacy v1 manifests instead of treating them as executable configurations.
- Decouple the logical skill identity from its physical installation directory in tests and deployment guidance.
- Validate pinned runtime identities, minimum snapshots, optional capabilities, scoped network grants, hardened resource limits, result-gate evidence, and Apple Container escalation requests.

## v0.1.0 - 2026-09-15

### Initial release

- Define capability-based execution boundaries for AI-agent workloads.
- Provide `inspect`, `guest-build`, and `elevated-release` execution profiles.
- Include a default-deny task-manifest template and validator.
- Document read-only inputs, guest-local scratch, network and credential controls, result gates, host-side brokers, resource governance, and adversarial verification.
- Provide English and Japanese documentation.
