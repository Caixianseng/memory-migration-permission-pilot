"""Small zero-model export boundary tests; real artifacts also have unpack audits."""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts import export_candidate_classifier_artifact as module


class CandidateClassifierArtifactTests(unittest.TestCase):
    @contextmanager
    def workspace(self):
        # A clean checkout has no ignored results directory yet.
        (module.ROOT / "results").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="candidate_export_fake_", dir=module.ROOT / "results") as directory:
            path = Path(directory).resolve()
            self.assertTrue(path.is_relative_to((module.ROOT / "results").resolve()))
            yield path

    def artifact(self, root, entries, *, extra=None, wrong_hash=False):
        manifest = {"files": {name: {"bytes": len(raw), "sha256": "bad" if wrong_hash else module.sha(raw)} for name, raw in entries.items()}}
        archive = root / "input.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("PUBLIC_ARTIFACT_MANIFEST.json", json.dumps(manifest))
            for name, raw in entries.items():
                output.writestr(name, raw)
            if extra:
                output.writestr(extra, b"not allowlisted")
        return archive

    def test_scanner_rejects_credential_shapes_and_restoration_fields(self):
        with self.assertRaises(ValueError):
            module.scan(("s" + "k-" + "A" * 32).encode(), ".json")
        for name in ("api_key", "restoration_map", "mapping", "private_key"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.scan(json.dumps({name: {"content": "fake"}}).encode(), ".json")

    def test_scanner_preserves_public_synthetic_values_and_hash_metadata(self):
        raw = json.dumps({"text": "Synthetic customer name Example Group, phone 13800138000.",
                          "model_id": "public-model-name", "sha256": "a" * 64}).encode()
        module.scan(raw, ".json")
        self.assertEqual(raw, json.dumps(json.loads(raw)).encode())

    def test_unpack_preserves_exact_whitelisted_bytes(self):
        with self.workspace() as root:
            entries = {"flat/report.json": b'{"status":"fake"}\n', "gliclass/frozen_source/code.py": b"# synthetic\r\n"}
            target = module.unpack_checked(self.artifact(root, entries), root / "unpacked")
            for name, raw in entries.items():
                self.assertEqual((target / name).read_bytes(), raw)

    def test_unpack_rejects_traversal_without_writing_outside_target(self):
        with self.workspace() as root:
            archive = self.artifact(root, {"../escape.json": b"{}"})
            with self.assertRaises(ValueError):
                module.unpack_checked(archive, root / "unpacked")
            self.assertFalse((root / "escape.json").exists())

    def test_unpack_rejects_extra_members_and_changed_bytes(self):
        with self.workspace() as root:
            archive = self.artifact(root, {"flat/report.json": b"{}"}, extra="gliclass/unregistered.bin")
            with self.assertRaises(ValueError):
                module.unpack_checked(archive, root / "unpacked")
        with self.workspace() as root:
            archive = self.artifact(root, {"flat/report.json": b"{}"}, wrong_hash=True)
            with self.assertRaises(ValueError):
                module.unpack_checked(archive, root / "unpacked")


if __name__ == "__main__":
    unittest.main()
