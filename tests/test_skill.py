import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT
SKILL_FILE = ROOT / "SKILL.md"
VALIDATOR = ROOT / "scripts" / "validate-manifest.py"
TEMPLATE = ROOT / "assets" / "isolation-manifest.template.json"


class SkillStructureTests(unittest.TestCase):
    def test_frontmatter_metadata(self):
        text = SKILL_FILE.read_text(encoding="utf-8")
        match = re.match(r"^---\nname: ([^\n]+)\ndescription: ([^\n]+)\n---\n", text)
        self.assertIsNotNone(match, "SKILL.md must start with name and description frontmatter")
        name, description = match.groups()
        self.assertEqual(name, SKILL_DIR.name)
        self.assertRegex(name, r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
        self.assertLessEqual(len(description), 1024)
        self.assertIn("Use when", description)
        self.assertIn("Don't use for", description)
        self.assertLess(len(text.splitlines()), 500)

    def test_referenced_skill_files_exist(self):
        text = SKILL_FILE.read_text(encoding="utf-8")
        paths = re.findall(r"`((?:assets|references|scripts)/[^` ]+)`", text)
        self.assertTrue(paths)
        for relative in paths:
            if "path/to/" in relative:
                continue
            self.assertTrue((SKILL_DIR / relative).exists(), relative)


class ManifestValidatorTests(unittest.TestCase):
    def run_validator(self, manifest):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            return subprocess.run(
                ["python3", str(VALIDATOR), str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def valid_manifest(self):
        manifest = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        manifest["task_id"] = "test-task"
        manifest["resource_limits"]["cpu"] = "1"
        manifest["result_gate"]["audit_record"] = "audit/test-task.json"
        manifest["supply_chain"]["image_digest"] = "sha256:" + "0" * 64
        manifest["supply_chain"]["tool_commit"] = "na"
        return manifest

    def test_accepts_bounded_manifest(self):
        result = self.run_validator(self.valid_manifest())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASSED", result.stdout)

    def test_rejects_writable_host_mount(self):
        manifest = self.valid_manifest()
        manifest["input_mounts"][0]["read_only"] = False
        result = self.run_validator(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Writable host mount", result.stderr)

    def test_rejects_control_socket(self):
        manifest = self.valid_manifest()
        manifest["control_sockets"] = ["/var/run/docker.sock"]
        result = self.run_validator(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("control_sockets must be empty", result.stderr)


if __name__ == "__main__":
    unittest.main()
