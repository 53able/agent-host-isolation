# Changelog

## Unreleased

### Added

- Add Manifest v2 resources for task, workspace, gateway, model, Apple Container runtime, resources, and result gate.
- Add strict Manifest v2 validation, allowlisted Apple Container argv compilation, gateway grant decisions, lifecycle/checkpoint contracts, normalized event validation, and non-mutating host readiness probing.
- Add a bounded, cleanup-aware Apple Container denial smoke test with JSON evidence output.

### Changed

- Reject legacy v1 manifests instead of treating them as executable configurations.
- Decouple the logical skill identity from its physical installation directory in tests and deployment guidance.

## v0.1.0 - 2026-09-15

### Initial release

- Define capability-based execution boundaries for AI-agent workloads.
- Provide `inspect`, `guest-build`, and `elevated-release` execution profiles.
- Include a default-deny task-manifest template and validator.
- Document read-only inputs, guest-local scratch, network and credential controls, result gates, host-side brokers, resource governance, and adversarial verification.
- Provide English and Japanese documentation.
