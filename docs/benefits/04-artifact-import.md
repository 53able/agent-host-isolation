# Separate artifact generation from permanent host changes

**Language:** English | [日本語](../ja-JP/benefits/04-artifact-import.md)

## Situation

An AI agent produces patches, archives, logs, and generated files that need to return to a host repository.

## Risk without an execution boundary

A writable repository mount combines generation with persistence. Path traversal, symlink handling, or a mistaken destination can modify host files before anyone inspects the result.

## How the skill changes the workflow

Export artifacts to guest output storage. Treat them as untrusted input. A host-side result gate checks paths, symlinks, file types, sizes, hashes, and the destination before importing the intended result.

## Adoption benefit

The host change becomes a separate and observable operation. Generated content can be reviewed or rejected without giving the guest direct write access to the repository.

## What this does not prove

Artifact inspection must cover the actual import mechanism. Checking a displayed diff is insufficient if another archive extractor or file bridge can bypass the same policy.
