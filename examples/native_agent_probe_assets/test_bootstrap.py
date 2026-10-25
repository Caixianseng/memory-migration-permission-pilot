"""Fake-installation checks; no CLI execution, credentials or network."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("prepare_native_probe_assets_tested", REPO / "scripts/prepare_native_probe_assets.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        results = REPO / "results"
        results.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="bootstrap_fake_", dir=results)
        self.base = Path(self.tmp.name).resolve()
        self.assertTrue(self.base.is_relative_to(results.resolve()))
        self.addCleanup(self.tmp.cleanup)
        self.clone = self.base / "clone"
        self.clone.mkdir()
        patcher = patch.object(bootstrap, "ROOT", self.clone)
        patcher.start(); self.addCleanup(patcher.stop)
        self.output = self.clone / bootstrap.PROBE_RELATIVE

    def installation(self, version="1.1.77"):
        package = self.base / "official-qoder-package"
        (package / "bundle").mkdir(parents=True)
        entry = package / "bundle/qodercli.js"
        entry.write_text("// fake public entry: do not execute", encoding="utf-8")
        (package / "package.json").write_text(json.dumps({"name": "@qoder-ai/qodercli", "version": version}), encoding="utf-8")
        node = self.base / "node.exe"
        node.write_bytes(b"FAKE_NODE_NEVER_EXECUTE")
        return entry, node

    def test_zero_execution_default_and_exact_guard_copy(self):
        with patch.object(subprocess, "Popen") as popen, patch.object(subprocess, "run") as run:
            result = bootstrap.prepare_assets()
        popen.assert_not_called(); run.assert_not_called()
        self.assertEqual(result["model_inference_calls"], 0)
        self.assertIs(result["credentials_read_or_copied"], False)
        self.assertEqual((self.output / "dsh_single_request_guard.mjs").read_bytes(),
                         (bootstrap.ASSETS / "dsh_single_request_guard.mjs").read_bytes())
        self.assertFalse((self.output / "qoder_capabilities.json").exists())
        self.assertFalse(list(self.output.rglob(".credentials.yaml")))
        rows = json.loads((self.output / "sdk_guard_metadata.patch.yml").read_text(encoding="utf-8"))
        self.assertNotIn("__RUNTIME_HOME__", json.dumps(rows))
        guard = next(row["insert"][0] for row in rows if "insert" in row)
        self.assertEqual(guard["name"], (self.output / "dsh_single_request_guard.mjs").as_uri())

    def test_manifest_version_is_checked_but_not_runtime_qualification(self):
        entry, node = self.installation()
        bootstrap.prepare_assets(qoder_cli_entry=entry, node_executable=node)
        cap = json.loads((self.output / "qoder_capabilities.example.json").read_text(encoding="utf-8"))
        self.assertEqual(cap["package_manifest_check"]["package_manifest_version"], "1.1.77")
        self.assertIsNone(cap["package_version_verified"])
        self.assertIs(cap["metadata_preflight_completed"], False)
        commands = json.loads((self.output / "manual_metadata_commands.json").read_text(encoding="utf-8"))
        self.assertEqual(len(commands["commands"]), 4)
        self.assertEqual(commands["commands"]["qoder_catalog"][-1], "--list-models")
        self.assertNotIn("--print", commands["commands"]["qoder_catalog"])
        self.assertEqual(commands["commands"]["qoder_catalog"][commands["commands"]["qoder_catalog"].index("--tools")+1], "")
        from memory_migration_study import qoder_native
        workspace = self.output / "metadata_workspace"
        (workspace / "AGENTS.md").write_text("Synthetic metadata boundary only.", encoding="utf-8")
        with patch.object(qoder_native, "_run_pipes") as process:
            result = qoder_native.run_qoder_question(workspace, "Synthetic question?",
                capabilities_path=self.output / "qoder_capabilities.example.json")
        self.assertEqual(result["error"], "cli_version_unverified")
        process.assert_not_called()

    def test_wrong_version_and_unpaired_paths_fail_without_output(self):
        entry, node = self.installation(version="1.1.78")
        with self.assertRaisesRegex(bootstrap.AssetPreparationError, "qoder_package_version_mismatch"):
            bootstrap.prepare_assets(qoder_cli_entry=entry, node_executable=node)
        with self.assertRaisesRegex(bootstrap.AssetPreparationError, "paths_must_be_paired"):
            bootstrap.prepare_assets(qoder_cli_entry=entry)
        self.assertFalse(self.output.exists())

    def test_no_overwrite_or_relocated_guard_root(self):
        bootstrap.prepare_assets()
        original = (self.output / "dsh_single_request_guard.mjs").read_bytes()
        with self.assertRaisesRegex(bootstrap.AssetPreparationError, "no_overwrite"):
            bootstrap.prepare_assets()
        self.assertEqual((self.output / "dsh_single_request_guard.mjs").read_bytes(), original)
        with self.assertRaisesRegex(bootstrap.AssetPreparationError, "frozen_runner_probe_root_required"):
            bootstrap.prepare_assets(self.clone / "results/another-root")

    def test_changed_public_guard_is_not_silently_accepted(self):
        modified = self.base / "modified-assets"
        shutil.copytree(bootstrap.ASSETS, modified)
        (modified / "dsh_single_request_guard.mjs").write_text("changed", encoding="utf-8")
        with patch.object(bootstrap, "ASSETS", modified):
            with self.assertRaisesRegex(bootstrap.AssetPreparationError, "public_asset_hash_changed"):
                bootstrap.prepare_assets()
        self.assertFalse(self.output.exists())

    def test_public_templates_contain_no_old_machine_paths(self):
        for filename in bootstrap._FILES:
            text = (bootstrap.ASSETS / filename).read_text(encoding="utf-8")
            for marker in ("CAI", "F:\\", "F:/", "file:///F:", "E:/", "sk-"):
                self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()
