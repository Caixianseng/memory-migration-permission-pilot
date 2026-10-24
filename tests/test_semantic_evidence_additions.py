"""Provenance regressions: new source files cannot hide executed-source changes."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
PACKAGE = PROJECT / "memory_migration_study"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("semantic_fixture_for_provenance", PROJECT / "tests/test_study_semantic_memory_benchmark.py")
verifier = load("semantic_evidence_verifier_for_provenance", PROJECT / "scripts/verify_semantic_memory_evidence.py")


class VirtualSource:
    """Only the verifier sees this metadata; no real package files are written."""
    def __init__(self, name, data):
        self.name, self.data = name, data

    def read_bytes(self):
        return self.data


class SemanticEvidenceAdditionTests(unittest.TestCase):
    addition = "optional_metadata_checker_for_test.py"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.corpus, self.output = root / "corpus", root / "run"
        split = self.corpus / "development"
        split.mkdir(parents=True)
        runtime, evaluation = fixture.fixture()
        (split / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
        (split / "evaluation.json").write_text(json.dumps(evaluation), encoding="utf-8")
        # Run the existing complete fixture with every model-facing component
        # injected; these tests never load weights or contact a local service.
        with patch.object(fixture.benchmark, "LocalNerRuntime", return_value=fixture.FakeNerRuntime()), \
             patch.object(fixture.benchmark, "LocalMemoryBuilder", return_value=fixture.FakeModelBuilder()), \
             patch.object(fixture.benchmark, "LocalFactAnswerer", return_value=fixture.FakeAnswerer()), \
             patch.object(fixture.benchmark, "LocalQueryIntentClassifier", return_value=fixture.FakeClassifier()), \
             patch.object(fixture.benchmark.LocalSensitivityAgent, "health", return_value=None):
            fixture.benchmark.run(self.corpus, self.output, "no-model-assets", {})
        self.plan = json.loads((self.output / "plan.json").read_bytes())
        self.assertNotIn(self.addition, self.plan["implementation_sha256"])

    @contextmanager
    def current_view(self, *, additions=(), changed=(), removed=()):
        """Mock just the verifier's current-package inventory, not its archive."""
        original_glob = Path.glob
        virtual = {name: VirtualSource(name, data) for name, data in additions}
        for name in changed:
            data = (PACKAGE / name).read_bytes()
            self.assertTrue(data)
            virtual[name] = VirtualSource(name, bytes([data[0] ^ 1]) + data[1:])

        def glob(path, pattern, *args, **kwargs):
            entries = list(original_glob(path, pattern, *args, **kwargs))
            if path.resolve() != PACKAGE.resolve() or pattern != "*.py":
                return iter(entries)
            existing = {p.name: p for p in entries if p.name not in removed}
            existing.update(virtual)
            return iter(existing.values())

        with patch.object(Path, "glob", new=glob):
            yield

    def verify(self, **options):
        return verifier.verify(self.output, corpus=self.corpus, **options)

    def source_check(self, result):
        return next(c["passed"] for c in result["checks"]
                    if c["check"] == "executed_sources_unchanged_and_only_declared_additions")

    def test_identical_snapshot_passes_and_is_explicitly_identical(self):
        result = self.verify()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["current_snapshot_identical"])
        self.assertEqual(result["additional_current_sources"], [])
        self.assertEqual(result["declared_allowed_additions"], [])

    def test_default_rejects_extra_current_module(self):
        with self.current_view(additions=[(self.addition, b"# independent metadata check\n")]):
            result = self.verify()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.source_check(result))
        self.assertFalse(result["current_snapshot_identical"])
        self.assertEqual(result["additional_current_sources"], [self.addition])

    def test_explicit_new_basename_passes_without_claiming_identical_snapshot(self):
        with self.current_view(additions=[(self.addition, b"# independent metadata check\n")]):
            result = self.verify(allow_added_sources=[self.addition])
        self.assertEqual(result["status"], "passed")
        self.assertTrue(self.source_check(result))
        self.assertFalse(result["current_snapshot_identical"])
        self.assertEqual(result["additional_current_sources"], [self.addition])
        self.assertEqual(result["declared_allowed_additions"], [self.addition])

    def test_declaring_one_file_cannot_allow_an_unrelated_second_file(self):
        other = "unexpected_second_checker.py"
        with self.current_view(additions=[(self.addition, b"# approved\n"), (other, b"# unexpected\n")]):
            result = self.verify(allow_added_sources=[self.addition])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.source_check(result))
        self.assertEqual(result["additional_current_sources"], sorted([self.addition, other]))

    def test_executed_name_can_never_be_declared_as_new_even_if_unchanged(self):
        for changes in ((), ("privacy.py",)):
            with self.subTest(changes=changes), self.current_view(changed=changes):
                with self.assertRaisesRegex(ValueError, "invalid_declared_source_addition"):
                    self.verify(allow_added_sources=["privacy.py"])

    def test_one_changed_executed_byte_fails_without_real_source_mutation(self):
        original = (PACKAGE / "privacy.py").read_bytes()
        with self.current_view(changed=["privacy.py"]):
            result = self.verify()
        self.assertEqual((PACKAGE / "privacy.py").read_bytes(), original)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.source_check(result))
        self.assertFalse(result["current_snapshot_identical"])
        self.assertEqual(result["additional_current_sources"], [])

    def test_allowed_new_module_does_not_hide_change_to_executed_source(self):
        with self.current_view(additions=[(self.addition, b"# approved extra\n")], changed=["privacy.py"]):
            result = self.verify(allow_added_sources=[self.addition])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.source_check(result))
        self.assertEqual(result["additional_current_sources"], [self.addition])

    def test_removing_executed_module_cannot_be_offset_by_allowed_addition(self):
        with self.current_view(additions=[(self.addition, b"# new file\n")], removed=["privacy.py"]):
            result = self.verify(allow_added_sources=[self.addition])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.source_check(result))

    def test_paths_non_python_names_and_old_init_are_not_new_basenames(self):
        for name in ("../new.py", "nested/new.py", "new.txt", "__init__.py"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "invalid_declared_source_addition"):
                self.verify(allow_added_sources=[name])


if __name__ == "__main__":
    unittest.main()
