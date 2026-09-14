# Replace “the build passed” with evidence that the boundary held

**Language:** English | [日本語](../ja-JP/benefits/06-boundary-evidence.md)

## Situation

A build completes successfully inside the selected execution environment.

## Risk without adversarial verification

Success shows that the expected path worked. It does not show that forbidden paths, credentials, networks, command bridges, or side effects were inaccessible.

## How the skill changes the workflow

Run the seven denial-oriented test classes: mount, credential, network, command path, resource, supply chain, and side effect. Record the host version, runtime version, manifest hash, commands, observations, and cleanup result.

## Adoption benefit

The isolation claim becomes bounded evidence rather than a general impression. Reviewers can see exactly which configuration was tested and which checks remain missing.

## What this does not prove

Evidence does not transfer automatically to another operating system, runtime version, manifest, or tool path. Mark missing and unsupported checks as `blocked` or `unverified`.
