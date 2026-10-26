"""Synthetic dependency-contract fixtures; no model, network or holdout input."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_source_card_reader as reader
from scripts import verify_source_card_reader as verifier


V1 = "source_card_dependencies_v1"
V2 = "source_card_dependencies_v2"
_MISSING = object()
READER = "scripts/run_source_card_reader.py"


class SourceCardDependencyContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.number = 0

    def fixture(self, *, source_version=_MISSING, plan_version=_MISSING, members=None, trailer=""):
        self.number += 1
        base = self.root / str(self.number)
        current, archive = base / "current", base / "archive"
        version = V1 if source_version is _MISSING else source_version
        members = tuple(sorted(verifier.DEPENDENCY_CONTRACTS.get(version, verifier.DEPENDENCY_CONTRACTS[V2]))) if members is None else tuple(members)
        declaration = "REGISTERED_DEPENDENCIES = " + repr(members) + "\n"
        if source_version is not _MISSING:
            declaration += "DEPENDENCY_CONTRACT_VERSION = " + repr(source_version) + "\n"
        declaration += trailer
        hashes = {}
        for name in members:
            data = (declaration if name == READER else "# Synthetic dependency fixture.\n").encode("utf-8")
            for root in (current, archive):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        plan = {"implementation_sha256": hashes}
        if plan_version is not _MISSING:
            plan["dependency_contract_version"] = plan_version
        return plan, current, archive

    def verify(self, fixture):
        plan, current, archive = fixture
        return verifier.verify_dependency_contract(plan, source_root=current, archive_root=archive)

    def test_old_implicit_and_explicit_v1_fifty_member_contract(self):
        for source, plan in ((_MISSING, _MISSING), (V1, V1), (_MISSING, V1), (V1, _MISSING)):
            with self.subTest(source=source, plan=plan):
                receipt = self.verify(self.fixture(source_version=source, plan_version=plan))
                self.assertEqual(receipt["version"], V1)
                self.assertEqual(receipt["member_count"], 50)
                self.assertTrue(receipt["exact_known_membership"])

    def test_new_v2_is_exactly_original_members_plus_principal_scope(self):
        self.assertEqual(len(verifier.DEPENDENCY_CONTRACTS[V1]), 50)
        self.assertEqual(verifier.DEPENDENCY_CONTRACTS[V2] - verifier.DEPENDENCY_CONTRACTS[V1],
                         {"memory_migration_study/principal_scope.py"})
        self.assertEqual(verifier.DEPENDENCY_CONTRACTS[V1] - verifier.DEPENDENCY_CONTRACTS[V2], set())
        receipt = self.verify(self.fixture(source_version=V2, plan_version=V2))
        self.assertEqual(receipt["member_count"], 51)
        self.assertTrue(receipt["current_and_archive_hashes_checked"])

    def test_missing_extra_and_same_count_replacement_in_source_are_rejected(self):
        for version in (V1, V2):
            original = tuple(sorted(verifier.DEPENDENCY_CONTRACTS[version]))
            removable = next(name for name in original if name != READER)
            for variant in ("missing", "extra", "same_count_replacement", "duplicate"):
                members = [name for name in original if name != removable] if variant in {"missing", "same_count_replacement"} else list(original)
                if variant in {"extra", "same_count_replacement"}:
                    members.append("scripts/unregistered_dependency.py")
                elif variant == "duplicate":
                    members.append(removable)
                with self.subTest(version=version, variant=variant), self.assertRaisesRegex(
                        ValueError, "dependency_source_membership_invalid"):
                    self.verify(self.fixture(source_version=version, plan_version=version, members=members))

    def test_missing_extra_and_same_count_manifest_replacement_are_rejected(self):
        for variant in ("missing", "extra", "same_count_replacement"):
            fixture = self.fixture(source_version=V2, plan_version=V2)
            hashes = fixture[0]["implementation_sha256"]
            if variant in {"missing", "same_count_replacement"}:
                del hashes["memory_migration_study/principal_scope.py"]
            if variant in {"extra", "same_count_replacement"}:
                hashes["scripts/unregistered_dependency.py"] = "0" * 64
            with self.subTest(variant=variant), self.assertRaisesRegex(ValueError, "dependency_manifest_invalid"):
                self.verify(fixture)

    def test_unknown_and_non_string_versions_are_rejected(self):
        for source, plan in (("source_card_dependencies_v999", V2), (V2, "source_card_dependencies_v999"),
                             (None, V2), (V2, None), (1, V2), (V2, 1)):
            with self.subTest(source=source, plan=plan), self.assertRaisesRegex(
                    ValueError, "dependency_source_version_unknown|dependency_plan_version_unknown"):
                self.verify(self.fixture(source_version=source, plan_version=plan))

    def test_source_plan_version_mixing_including_omitted_old_default_is_rejected(self):
        for source, plan in ((V1, V2), (V2, V1), (_MISSING, V2), (V2, _MISSING)):
            with self.subTest(source=source, plan=plan), self.assertRaisesRegex(ValueError, "dependency_contract_version_mismatch"):
                self.verify(self.fixture(source_version=source, plan_version=plan))

    def test_archive_membership_and_both_source_hashes_are_required(self):
        for variant in ("archive_extra", "archive_missing", "archive_hash", "current_hash", "current_missing", "manifest_hash"):
            fixture = self.fixture(source_version=V2, plan_version=V2)
            plan, current, archive = fixture
            name = "memory_migration_study/privacy.py"
            if variant == "archive_extra":
                (archive / "scripts/extra.py").write_text("# unregistered\n", encoding="utf-8")
            elif variant == "archive_missing":
                (archive / name).unlink()
            elif variant == "current_missing":
                (current / name).unlink()
            elif variant == "manifest_hash":
                plan["implementation_sha256"][name] = "not-a-sha256"
            else:
                ((archive if variant == "archive_hash" else current) / name).write_text("# changed\n", encoding="utf-8")
            with self.subTest(variant=variant), self.assertRaisesRegex(
                    ValueError, "dependency_archive_membership_invalid|dependency_source_or_archive_hash_mismatch|"
                                "dependency_file_missing_or_linked|dependency_manifest_invalid"):
                self.verify(fixture)

    def test_saved_source_is_parsed_without_executing_it(self):
        fixture = self.fixture(source_version=V2, plan_version=V2,
                               trailer='raise RuntimeError("Saved source must never execute during this check")\n')
        plan, current, archive = fixture
        before = {str(path): path.read_bytes() for path in (current / READER, archive / READER)}
        receipt = self.verify(fixture)
        self.assertFalse(receipt["saved_code_executed"])
        self.assertEqual(before, {str(path): path.read_bytes() for path in (current / READER, archive / READER)})

    def test_dynamic_duplicate_and_invalid_syntax_declarations_are_rejected(self):
        for variant in ("dynamic", "duplicate", "syntax"):
            fixture = self.fixture(source_version=V2, plan_version=V2)
            plan, current, archive = fixture
            source = (archive / READER).read_text(encoding="utf-8")
            if variant == "dynamic":
                source = source.replace(repr(V2), 'str("source_card_dependencies_v2")')
            elif variant == "duplicate":
                source += "DEPENDENCY_CONTRACT_VERSION = " + repr(V2) + "\n"
            else:
                source += "def unfinished(\n"
            for root in (current, archive):
                (root / READER).write_text(source, encoding="utf-8")
            plan["implementation_sha256"][READER] = hashlib.sha256((archive / READER).read_bytes()).hexdigest()
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                self.verify(fixture)

    def test_current_protocol_pins_v2_and_exact_real_ast_import_closure(self):
        corpus = self.root / "synthetic-corpus"
        (corpus / "development").mkdir(parents=True)
        runtime = [{"story_id": "synthetic-" + str(i), "language": "en" if i < 4 else "zh",
                    "source": {"text": "A synthetic public statement."}, "policy": deepcopy(reader.POLICY),
                    "tasks": [{"task_id": "task-" + str(j), "actor_id": "owner" if j < 4 else "outsider"}
                              for j in range(5)]} for i in range(8)]
        (corpus / "development/runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
        (corpus / "development/evaluation.json").write_text("{}", encoding="utf-8")
        with patch.object(reader, "LocalSourceCardReader", return_value=SimpleNamespace(cache_identity=lambda: {"test": "no-model"})):
            plan, observed, _ = reader.protocol(corpus, {})
        self.assertEqual(observed, runtime)
        self.assertEqual(reader.DEPENDENCY_CONTRACT_VERSION, V2)
        self.assertEqual(plan["dependency_contract_version"], V2)
        self.assertEqual(set(plan["implementation_sha256"]), verifier.DEPENDENCY_CONTRACTS[V2])
        self.assertEqual(set(verifier._declaration(Path(reader.__file__).read_text(encoding="utf-8"))), verifier.DEPENDENCY_CONTRACTS[V2])


if __name__ == "__main__":
    unittest.main()
