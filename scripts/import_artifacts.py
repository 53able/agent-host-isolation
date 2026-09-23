#!/usr/bin/env python3
"""Inspect and import untrusted guest artifacts through a host-side result gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from manifest_v2 import validate_v2


def _expected_relative_paths(manifest: dict[str, Any]) -> list[PurePosixPath]:
    output = PurePosixPath(manifest["runtime"]["output"]["target"])
    return [PurePosixPath(path).relative_to(output) for path in manifest["task"]["expected_artifacts"]]


def inspect_artifacts(manifest: dict[str, Any], source: Path) -> list[dict[str, Any]]:
    errors = validate_v2(manifest)
    if errors:
        raise ValueError("invalid manifest: " + "; ".join(errors))
    if source.is_symlink() or not source.is_dir():
        raise ValueError("artifact source must be a real directory, not a symlink")

    source = source.resolve(strict=True)
    expected = _expected_relative_paths(manifest)
    for relative in expected:
        candidate = source / relative
        if not candidate.exists() and not candidate.is_symlink():
            raise ValueError(f"expected artifact is missing: {relative}")

    records: list[dict[str, Any]] = []
    total = 0
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in directories:
            candidate = root_path / name
            if candidate.is_symlink():
                raise ValueError(f"artifact symlink is forbidden: {candidate.relative_to(source)}")
        for name in files:
            candidate = root_path / name
            relative = PurePosixPath(candidate.relative_to(source).as_posix())
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"artifact symlink is forbidden: {relative}")
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"artifact must be a regular file: {relative}")
            if not any(relative == item or relative.is_relative_to(item) for item in expected):
                raise ValueError(f"unexpected artifact is forbidden: {relative}")
            total += metadata.st_size
            if total > manifest["resultGate"]["artifact_import"]["max_bytes"]:
                raise ValueError("artifact import exceeds the cumulative byte limit")
            digest = hashlib.sha256()
            descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError(f"artifact changed during inspection: {relative}")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
            finally:
                os.close(descriptor)
            records.append({"path": relative.as_posix(), "size": metadata.st_size, "sha256": digest.hexdigest()})
    return sorted(records, key=lambda item: item["path"])


def import_artifacts(manifest: dict[str, Any], source: Path, destination: Path) -> list[dict[str, Any]]:
    records = inspect_artifacts(manifest, source)
    if destination.exists() or destination.is_symlink():
        raise ValueError("artifact destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    source = source.resolve(strict=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    copied_total = 0
    try:
        for record in records:
            relative = Path(record["path"])
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source_file = source / relative
            descriptor = os.open(source_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise ValueError(f"artifact is no longer a regular file: {relative}")
                digest = hashlib.sha256()
                with os.fdopen(descriptor, "rb", closefd=False) as input_file, target.open("xb") as output_file:
                    for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                        copied_total += len(chunk)
                        if copied_total > manifest["resultGate"]["artifact_import"]["max_bytes"]:
                            raise ValueError("artifact import exceeds the cumulative byte limit during copy")
                        digest.update(chunk)
                        output_file.write(chunk)
                if target.stat().st_size != record["size"] or digest.hexdigest() != record["sha256"]:
                    raise ValueError(f"artifact changed during import: {relative}")
            finally:
                os.close(descriptor)
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("source", type=Path, help="host-mounted read-only guest output directory")
    parser.add_argument("destination", type=Path, help="trusted host import directory")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        records = import_artifacts(manifest, args.source, args.destination)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"imported": records}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
