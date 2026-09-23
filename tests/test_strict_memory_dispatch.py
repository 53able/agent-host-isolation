import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import strict_memory_dispatch as dispatch_module  # noqa: E402

REQUIRED_CHECKS = dispatch_module.REQUIRED_CHECKS
eligibility_errors = dispatch_module.eligibility_errors
stage_source_snapshot = dispatch_module.stage_source_snapshot


class StrictMemoryDispatchTests(unittest.TestCase):
    def test_blocked_verification_never_stages_or_runs_target(self):
        target = {"workspace": {"image": {"digest": "sha256:abc"}}, "resources": {"memory_bytes": 256}}
        verification = {"worktree_status_before": [], "checks": {key: "passed" for key in REQUIRED_CHECKS}}
        verification["checks"]["process"] = "blocked"
        with patch.object(dispatch_module, "probe_memory", return_value={}), \
             patch.object(dispatch_module, "verify_dispatch", return_value=verification), \
             patch.object(dispatch_module, "stage_source_snapshot") as staged, \
             patch.object(dispatch_module, "run_guest_build") as runner:
            record = dispatch_module._dispatch_claimed({}, {"task_id": "test"}, target, Path("/missing"))
        self.assertEqual(record["status"], "blocked")
        self.assertFalse(record["automatic"])
        self.assertIn("process is not verified", record["blocked_reasons"])
        staged.assert_not_called()
        runner.assert_not_called()

    def test_requires_every_resource_and_full_path_check(self):
        target = {"workspace": {"image": {"digest": "sha256:abc"}}, "resources": {"memory_bytes": 256}}
        digest = hashlib.sha256((ROOT / "scripts" / "guest_build_runner.py").read_bytes()).hexdigest()
        verification = {
            "worktree_status_before": [], "checks": {key: "passed" for key in REQUIRED_CHECKS},
            "tested_profile": {"image": target["workspace"]["image"], "resources": target["resources"]},
            "runner_sha256": digest,
        }
        self.assertEqual(eligibility_errors(verification, target), [])
        verification["checks"]["process"] = "blocked"
        self.assertIn("process is not verified", eligibility_errors(verification, target))
        verification["checks"]["process"] = "passed"
        verification["worktree_status_before"] = [" M scripts/guest_build_runner.py"]
        self.assertIn("verification did not start from a clean worktree", eligibility_errors(verification, target))

    def test_stages_only_exact_source_snapshot_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = root / "source"
            source_dir.mkdir()
            (source_dir / "allowed.txt").write_bytes(b"allowed")
            source = {"workspace": {"snapshot": {"paths": [{
                "path": "allowed.txt", "type": "regular", "size_bytes": 7,
                "hash": "sha256:" + hashlib.sha256(b"allowed").hexdigest(),
            }]}}}
            entries = source["workspace"]["snapshot"]["paths"]
            source["workspace"]["snapshot"]["hash"] = "sha256:" + hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()
            target = {"workspace": {"snapshot": {"source": str(root / "target")}}}
            staged = stage_source_snapshot(source, source_dir, target)
            self.assertEqual((staged / "allowed.txt").read_bytes(), b"allowed")
            (source_dir / "extra.txt").write_bytes(b"extra")
            target["workspace"]["snapshot"]["source"] = str(root / "other")
            with self.assertRaisesRegex(ValueError, "differ from the manifest"):
                stage_source_snapshot(source, source_dir, target)
            self.assertFalse((root / "other").exists())


if __name__ == "__main__":
    unittest.main()
