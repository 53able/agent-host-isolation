import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_inspect_fetch_adversarial import REQUIRED_VERIFICATION_PROBES, verification_status


class FetchEvidenceStatusTests(unittest.TestCase):
    def test_only_complete_passing_committed_matrix_can_be_verified(self):
        results = [{"name": name, "passed": True} for name in REQUIRED_VERIFICATION_PROBES]
        self.assertEqual(verification_status(results, []), "verified-for-tested-configuration")
        self.assertEqual(verification_status(results, [" M scripts/inspect_fetch_broker.py"]), "unverified")
        self.assertEqual(verification_status(results[:-1], []), "unverified")
        self.assertEqual(verification_status(results + [results[0]], []), "unverified")
        failed = [{**item, "passed": False} if item["name"] == "live-redirect-hop" else item for item in results]
        self.assertEqual(verification_status(failed, []), "unverified")
        inconsistent = [{**item, "observed": {"passed": False}} if item["name"] == "live-cancel" else item
                        for item in results]
        self.assertEqual(verification_status(inconsistent, []), "unverified")


if __name__ == "__main__":
    unittest.main()
