import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from guest_build_runner import bounded_process, extract_output  # noqa: E402


def archive_member(name, content=b"data", *, kind=tarfile.REGTYPE):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.size = len(content) if kind == tarfile.REGTYPE else 0
        tar.addfile(info, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


class GuestBuildRunnerTests(unittest.TestCase):
    def test_host_wall_and_output_watchdog(self):
        normal = bounded_process([sys.executable, "-c", "print('ok')"], seconds=2, max_bytes=100)
        self.assertEqual(normal["returncode"], 0)
        self.assertEqual(normal["stdout"], b"ok\n")
        self.assertIsNone(normal["violation"])
        wall = bounded_process([sys.executable, "-c", "import time; time.sleep(3)"], seconds=1, max_bytes=100)
        self.assertEqual(wall["violation"], "host wall-time limit exceeded")
        noisy = bounded_process([sys.executable, "-c", "print('x' * 10000)"], seconds=2, max_bytes=100)
        self.assertEqual(noisy["violation"], "host output limit exceeded")

    def test_tar_extraction_rejects_traversal_symlink_and_size_overrun(self):
        manifest = {"resultGate": {"artifact_import": {"max_bytes": 4}}}
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary)
            for name, kind, content in (("../escape", tarfile.REGTYPE, b"x"),
                                        ("link", tarfile.SYMTYPE, b""),
                                        ("large", tarfile.REGTYPE, b"12345")):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        extract_output(archive_member(name, content, kind=kind), manifest, staging)
            extract_output(archive_member("./result.txt", b"good"), manifest, staging)
            self.assertEqual((staging / "result.txt").read_bytes(), b"good")


if __name__ == "__main__":
    unittest.main()
