import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_FILE = ROOT / "SKILL.md"
VALIDATOR = ROOT / "scripts" / "validate-manifest.py"
TEMPLATE = ROOT / "assets" / "isolation-manifest.template.json"
sys.path.insert(0, str(ROOT / "scripts"))


def load_script(name):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compiler = load_script("apple_container_compiler")
gateway_policy = load_script("gateway_policy")
lifecycle = load_script("task_lifecycle")


def valid_manifest():
    manifest = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    manifest["task"].update(id="test-task", goal="run the bounded test suite", command=["python3", "-m", "unittest"])
    manifest["workspace"]["repository"].update(
        url="https://github.com/53able/agent-host-isolation.git", commit="a" * 40, tree_hash="b" * 40,
    )
    manifest["workspace"]["snapshot"].update(id="snapshot-test-task", source="/var/tmp/agent-inputs/test-task")
    manifest["workspace"]["image"].update(
        reference="ghcr.io/example/agent-build:1.0", digest="sha256:" + "c" * 64,
    )
    manifest["workspace"]["toolchain"] = {"python": "3.12.7"}
    manifest["workspace"]["lockfile"] = {"path": "requirements.lock", "sha256": "d" * 64}
    manifest["workspace"]["skills"] = [{"id": "agent-host-isolation", "version": "v0.2.0"}]
    manifest["gateway"]["task_network"] = "ahi-test-task"
    manifest["model"].update(provider="openai", id="gpt-test")
    manifest["runtime"]["scratch"]["volume"] = "ahi-test-task-scratch"
    manifest["runtime"]["output"]["volume"] = "ahi-test-task-output"
    manifest["resultGate"]["audit_record"] = "audit/test-task.json"
    return manifest


class SkillStructureTests(unittest.TestCase):
    def test_frontmatter_metadata_uses_logical_skill_id(self):
        text = SKILL_FILE.read_text(encoding="utf-8")
        match = re.match(r"^---\nname: ([^\n]+)\ndescription: ([^\n]+)\n---\n", text)
        self.assertIsNotNone(match, "SKILL.md must start with name and description frontmatter")
        name, description = match.groups()
        self.assertEqual(name, "agent-host-isolation")
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
            if "path/to/" not in relative:
                self.assertTrue((ROOT / relative).exists(), relative)


class ManifestValidatorTests(unittest.TestCase):
    def run_validator(self, manifest):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            return subprocess.run(
                ["python3", str(VALIDATOR), str(path)], capture_output=True, text=True, check=False,
            )

    def assert_rejected(self, mutate, message):
        manifest = valid_manifest()
        mutate(manifest)
        result = self.run_validator(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_accepts_bounded_v2_manifest(self):
        result = self.run_validator(valid_manifest())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASSED", result.stdout)

    def test_rejects_legacy_manifest(self):
        result = self.run_validator({"task_id": "legacy"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v1 manifests are no longer executable", result.stderr)

    def test_rejects_unknown_fields(self):
        self.assert_rejected(lambda m: m.update({"extra_args": ["--ssh"]}), "unknown keys: extra_args")

    def test_rejects_placeholder_task_and_audit_ids(self):
        self.assert_rejected(lambda m: m["task"].update(id="replace-with-id"), "task.id")
        self.assert_rejected(lambda m: m["resultGate"].update(audit_record="placeholder"), "audit_record")

    def test_rejects_writable_host_mount(self):
        self.assert_rejected(lambda m: m["workspace"]["snapshot"].update(read_only=False), "writable host mounts")

    def test_rejects_mount_option_injection(self):
        self.assert_rejected(
            lambda m: m["workspace"]["snapshot"].update(source="/safe,readonly=false"),
            "snapshot.source",
        )

    def test_rejects_mutable_image_without_digest(self):
        self.assert_rejected(lambda m: m["workspace"]["image"].update(digest="latest"), "immutable sha256 digest")

    def test_rejects_option_shaped_image_reference(self):
        self.assert_rejected(lambda m: m["workspace"]["image"].update(reference="--ssh"), "image.reference")

    def test_rejects_dangerous_apple_container_capabilities(self):
        for key in ("ssh_forwarding", "socket_publishing", "nested_virtualization"):
            with self.subTest(key=key):
                self.assert_rejected(lambda m, key=key: m["runtime"].update({key: True}), f"runtime.{key} must be false")
        self.assert_rejected(lambda m: m["runtime"].update(drop_capabilities=[]), "drop_capabilities")

    def test_rejects_implicit_host_environment_inheritance(self):
        self.assert_rejected(lambda m: m["runtime"].update(environment={"TOKEN": None}), "host inheritance is forbidden")

    def test_validates_complete_network_grants(self):
        grant = {
            "destination": "api.example.com", "scope": "/v1/responses", "protocol": "https",
            "port": 443, "method": "POST", "purpose": "model inference",
            "expiry": "2030-01-01T00:00:00Z", "max_bytes": 1048576,
            "audit_record": "audit/grant-1.json",
        }
        manifest = valid_manifest()
        manifest["gateway"]["grants"] = [grant]
        self.assertEqual(self.run_validator(manifest).returncode, 0)
        for key in grant:
            with self.subTest(key=key):
                self.assert_rejected(
                    lambda m, key=key: m["gateway"].update(grants=[{k: v for k, v in grant.items() if k != key}]),
                    "gateway.grants[0]",
                )

    def test_rejects_wrong_resource_enforcement_owner(self):
        self.assert_rejected(
            lambda m: m["resources"]["wall_time_seconds"].update(enforced_by="apple-container"),
            "unsupported enforcement cannot be ignored",
        )

    def test_rejects_cross_resource_reference_mismatches(self):
        self.assert_rejected(
            lambda m: m["resultGate"]["artifact_import"].update(source="/scratch"),
            "must equal runtime.output.target",
        )
        self.assert_rejected(
            lambda m: m["task"].update(expected_artifacts=["/scratch/result"]),
            "expected_artifacts must remain within runtime.output.target",
        )
        self.assert_rejected(
            lambda m: m["model"].update(credential_broker_ref="broker-a"),
            "must resolve to gateway.credential_broker",
        )

    def test_rejects_non_integer_discrete_resource_limits(self):
        self.assert_rejected(
            lambda m: m["resources"]["processes"].update(limit=1.5),
            "positive integer",
        )


class AppleContainerCompilerTests(unittest.TestCase):
    def test_create_is_allowlisted_argv_with_pinned_identity(self):
        manifest = valid_manifest()
        argv = compiler.compile_command(manifest, "create")
        self.assertEqual(argv[:2], ["container", "create"])
        for option in ("--read-only", "--cap-drop", "--network"):
            self.assertIn(option, argv)
        self.assertIn("ghcr.io/example/agent-build:1.0@sha256:" + "c" * 64, argv)
        for option in ("--ssh", "--publish-socket", "--virtualization", "--cap-add", "--publish"):
            self.assertNotIn(option, argv)
        mounts = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--mount"]
        self.assertIn("readonly", mounts[0])
        self.assertNotIn("readonly", mounts[1])
        self.assertNotIn("/var/tmp/agent-inputs/test-task", mounts[1:])

    def test_only_explicit_environment_values_are_emitted(self):
        manifest = valid_manifest()
        manifest["runtime"]["environment"] = {"B": "two", "A": "one"}
        argv = compiler.compile_command(manifest, "run")
        env_values = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--env"]
        self.assertEqual(env_values, ["A=one", "B=two"])

    def test_lifecycle_and_observability_commands_are_fixed(self):
        manifest = valid_manifest()
        self.assertEqual(compiler.compile_command(manifest, "start"), ["container", "start", "test-task"])
        self.assertEqual(compiler.compile_command(manifest, "stop"), ["container", "stop", "--time", "10", "test-task"])
        self.assertEqual(compiler.compile_command(manifest, "delete"), ["container", "delete", "test-task"])
        self.assertEqual(compiler.compile_command(manifest, "stats"), ["container", "stats", "--format", "json", "--no-stream", "test-task"])

    def test_volume_creation_uses_cli_1_2_size_flag(self):
        argv = compiler.compile_command(valid_manifest(), "create-scratch-volume")
        self.assertEqual(argv[:4], ["container", "volume", "create", "-s"])

    def test_unrecognized_action_is_not_forwarded(self):
        with self.assertRaisesRegex(ValueError, "unsupported action"):
            compiler.compile_command(valid_manifest(), "exec")


class LifecycleTests(unittest.TestCase):
    def test_allows_declared_transition(self):
        lifecycle.require_transition("Prepared", "Running")
        lifecycle.require_transition("Stopped", "Resuming")

    def test_rejects_invalid_or_terminal_transition(self):
        with self.assertRaisesRegex(ValueError, "Running -> Prepared"):
            lifecycle.require_transition("Running", "Prepared")
        with self.assertRaisesRegex(ValueError, "Succeeded -> Running"):
            lifecycle.require_transition("Succeeded", "Running")

    def test_stop_start_is_not_checkpoint_resume(self):
        lifecycle.require_transition("Stopping", "Stopped")
        with self.assertRaises(ValueError):
            lifecycle.require_transition("Stopped", "Running")
        lifecycle.require_transition("Stopped", "Resuming")
        lifecycle.require_transition("Resuming", "Running")

    def test_checkpoint_binds_task_and_hashes_and_reissues_leases(self):
        digest = "sha256:" + "e" * 64
        checkpoint = {
            "contract": "application-level", "task_id": "test-task",
            "manifest_hash": digest, "workspace_hash": digest, "state_hash": digest,
            "contains_direct_credentials": False, "leases_revalidated": True,
        }
        self.assertEqual(lifecycle.validate_checkpoint(
            checkpoint, task_id="test-task", manifest_hash=digest, workspace_hash=digest,
        ), [])
        checkpoint["leases_revalidated"] = False
        self.assertIn("revalidated", " ".join(lifecycle.validate_checkpoint(
            checkpoint, task_id="test-task", manifest_hash=digest, workspace_hash=digest,
        )))

    def test_event_requires_task_and_evidence_hashes(self):
        digest = "sha256:" + "f" * 64
        event = {
            "event_version": 1, "type": "container.stats", "timestamp": "2026-09-23T00:00:00Z",
            "task_id": "test-task", "manifest_hash": digest, "workspace_hash": digest,
            "source": "container stats --format json --no-stream", "payload": {},
        }
        self.assertEqual(lifecycle.validate_event(event), [])
        event.pop("manifest_hash")
        self.assertTrue(lifecycle.validate_event(event))

    def test_unrun_adversarial_tests_are_never_verified(self):
        self.assertEqual(lifecycle.verification_status({}), "unverified")
        results = {key: "passed" for key in (
            "mount", "credential", "network", "command-path", "resource", "supply-chain", "side-effect",
        )}
        self.assertEqual(lifecycle.verification_status(results), "verified for tested configuration")
        results["network"] = "blocked"
        self.assertEqual(lifecycle.verification_status(results), "blocked")


class GatewayPolicyTests(unittest.TestCase):
    def grant_manifest(self):
        manifest = valid_manifest()
        manifest["gateway"]["grants"] = [{
            "destination": "api.example.com", "scope": "/v1/responses", "protocol": "https",
            "port": 443, "method": "POST", "purpose": "model inference",
            "expiry": "2030-01-01T00:00:00Z", "max_bytes": 1024,
            "audit_record": "audit/grant-1.json",
        }]
        return manifest

    def request(self):
        return {
            "task_id": "test-task", "destination": "api.example.com", "scope": "/v1/responses",
            "protocol": "https", "port": 443, "method": "POST", "bytes": 512,
        }

    def test_allows_only_exact_active_bounded_grant(self):
        from datetime import datetime, timezone

        decision = gateway_policy.decide(
            self.grant_manifest(), self.request(), now=datetime(2029, 1, 1, tzinfo=timezone.utc),
        )
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["audit_record"], "audit/grant-1.json")

    def test_denies_mismatch_expiry_and_transfer_overage(self):
        from datetime import datetime, timezone

        cases = []
        wrong_method = self.request()
        wrong_method["method"] = "GET"
        cases.append((wrong_method, datetime(2029, 1, 1, tzinfo=timezone.utc)))
        over_limit = self.request()
        over_limit["bytes"] = 1025
        cases.append((over_limit, datetime(2029, 1, 1, tzinfo=timezone.utc)))
        cases.append((self.request(), datetime(2031, 1, 1, tzinfo=timezone.utc)))
        for request, now in cases:
            with self.subTest(request=request, now=now):
                self.assertFalse(gateway_policy.decide(self.grant_manifest(), request, now=now)["allowed"])


if __name__ == "__main__":
    unittest.main()
