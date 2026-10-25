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

    def test_v2_missing_joint_score_key_cannot_downgrade_to_legacy_scoring(self):
        self.assertEqual(self.plan["score_schema_version"], 2)
        path = self.output/"rows.json"
        rows = json.loads(path.read_bytes())
        rows[0]["score"].pop("joint_correct_no_masking_gap")
        path.write_text(json.dumps(rows), encoding="utf-8")
        result = self.verify()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(next(check["passed"] for check in result["checks"] if check["check"] == "independent_per_task_scores"))

    def test_v1_plan_without_schema_uses_original_eight_score_fields(self):
        plan = dict(self.plan)
        plan.pop("score_schema_version")
        declared = plan.pop("entrypoint_sha256")
        for name in declared:
            archived = self.output/"implementation"/Path(name).name
            self.assertTrue(archived.resolve().is_relative_to((self.output/"implementation").resolve()))
            archived.unlink()
        (self.output/"plan.json").write_text(json.dumps(plan), encoding="utf-8")
        evaluation = json.loads((self.output/"evaluation.json").read_bytes())
        rows = json.loads((self.output/"rows.json").read_bytes())
        for row in rows:
            row["score"] = verifier.independent_score(row, evaluation[row["story_id"]])
            self.assertEqual(len(row["score"]), 8)
        (self.output/"rows.json").write_text(json.dumps(rows), encoding="utf-8")
        report = json.loads((self.output/"report.json").read_bytes())
        auxiliary = {"joint_masked_legal_tasks", "joint_correct_no_masking_gap", "secondary_serialization_legal_tasks",
                     "secondary_serialization_correct", "secondary_joint_correct_no_masking_gap"}
        report["arms"] = {arm: {key: value for key, value in metrics.items() if key not in auxiliary}
                          for arm, metrics in report["arms"].items()}
        (self.output/"report.json").write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual(self.verify()["status"], "passed")

    def test_declared_entrypoint_archive_is_not_exempt_from_hash_checks(self):
        entry = next(iter(self.plan["entrypoint_sha256"]))
        archived = self.output/"implementation"/Path(entry).name
        archived.write_bytes(archived.read_bytes()+b"\n# changed archived entrypoint\n")
        result = self.verify()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(next(check["passed"] for check in result["checks"] if check["check"] == "complete_executed_source_archive"))

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
