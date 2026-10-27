"""Offline preregistration, accounting and scoring tests; no model is loaded."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from memory_migration_study.local_detector import (
    PROMPT_VERSION, REPAIR_PROMPT, SYSTEM_PROMPT, LocalSensitivityAgent,
)
from memory_migration_study.privacy import _digest
from memory_migration_study.sensitivity_contract import category_contract
from scripts import run_ontology_contract_probe as probe


class OntologyProbeTests(unittest.TestCase):
    def test_policies_offer_identical_definition_bytes_in_separate_trusted_channels(self):
        policies = probe.make_policies()
        for profile in probe.PROFILES:
            old = policies[profile][probe.ARMS[0]]
            new = policies[profile][probe.ARMS[1]]
            self.assertNotIn("category_contract", old)
            self.assertEqual(new["instructions"], probe.SCOPE)
            self.assertEqual(old["instructions"], probe.SCOPE + "\nCUSTOMER definition: "
                             + new["category_contract"]["definitions"]["CUSTOMER"])
            self.assertEqual(new, policies[profile][probe.ARMS[2]])
            self.assertEqual(old["entity_registry"], new["entity_registry"])

    def test_fixed_schedule_has_96_opportunities_and_no_reference_inputs(self):
        schedule = probe.make_schedule()
        self.assertEqual(len(schedule), 96)
        self.assertEqual(len({(cell["text_index"], cell["profile"], cell["arm"]) for cell in schedule}), 96)
        self.assertEqual(sum(cell["arm"] != probe.ARMS[2] for cell in schedule), 64)
        self.assertEqual(sum(cell["arm"] == probe.ARMS[2] and cell["profile"] == probe.ANY_SPECIFIC_ORGANIZATION
                             for cell in schedule), 16)
        self.assertTrue(all(set(cell) == {"text_index", "profile", "arm"} for cell in schedule))

    def test_production_helper_preserves_legacy_messages_and_exact_budget(self):
        policy = {"version": "v1", "protected_categories": ["CUSTOMER"], "instructions": "Protect customers."}
        data, trusted = LocalSensitivityAgent._validate_inputs("Plain text", "probe", policy, [])
        messages, version = LocalSensitivityAgent._prepare_messages(data, trusted)
        historical = [{"role": "system", "content": SYSTEM_PROMPT + "\n\nTrusted sensitivity policy JSON:\n"
                       + json.dumps(trusted, ensure_ascii=False, separators=(",", ":"))},
                      {"role": "user", "content": json.dumps(data, ensure_ascii=False, separators=(",", ":"))}]
        self.assertEqual(messages, historical)
        self.assertEqual(version, PROMPT_VERSION)
        size = sum(len(message["content"].encode()) for message in historical)
        self.assertEqual(LocalSensitivityAgent._request_budget(messages), size + 256 + 1024)
        repaired = [*messages, {"role": "user", "content": REPAIR_PROMPT}]
        self.assertEqual(LocalSensitivityAgent._request_budget(repaired, repair=True),
                         size + len(REPAIR_PROMPT.encode()) + 320 + 1024)

    def test_preflight_checks_all_qwen_initial_and_repair_packages(self):
        texts = ["Organization record " + str(index) for index in range(16)]
        result = probe.preflight(texts, probe.make_policies(), probe.make_schedule())
        self.assertEqual(len(result["cells"]), 64)
        self.assertTrue(result["all_fit"])
        self.assertGreater(result["maximum_repair_bound"], result["maximum_initial_bound"])
        long = probe.preflight(["名字" * 1600] * 16, probe.make_policies(), probe.make_schedule())
        self.assertFalse(long["all_fit"])

    def test_freeze_archives_invalid_json_reference_opaquely_without_model_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir()
            runtime = {"schema_version": "ontology_contract_probe_runtime_v1", "texts": ["Text " + str(i) for i in range(16)]}
            probe.save(data / "runtime.json", runtime)
            reference = b"REFERENCE OPAQUE: deliberately invalid JSON; must not be parsed"
            (data / "evaluation.json").write_bytes(reference)
            prereg = root / "prereg.md"
            prereg.write_text("Frozen test preregistration", encoding="utf-8")
            with patch.object(probe, "checked_assets", return_value={"test": "offline-only"}), \
                 patch.object(probe, "LocalNerRuntime", side_effect=AssertionError("model loading forbidden")):
                result = probe.freeze(root / "out", data, root / "unused-model", prereg)
            self.assertEqual(result["status"], "frozen_not_executed")
            self.assertEqual(result["model_calls"], 0)
            self.assertEqual((root / "out/evaluation.opaque.json").read_bytes(), reference)
            self.assertEqual(result["plan_sha256"], probe.sha(root / "out/plan.json"))
            with self.assertRaisesRegex(ValueError, "output_already_exists"):
                probe.freeze(root / "out", data, root / "unused-model", prereg)

    def test_closed_evidence_creation_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "predictions.json"
            probe.save_exclusive(path, [{"status": "ok"}])
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                probe.save_exclusive(path, [{"status": "changed"}])
            self.assertEqual(path.read_bytes(), original)

    def test_implementation_archive_rejects_changed_missing_extra_and_linked_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "implementation"
            archive.mkdir()
            module = archive / "fixture.py"
            module.write_text("# fixture\n", encoding="utf-8")
            sources = {"fixture.py": probe.sha(module)}
            probe.verify_implementation_archive(root, sources)
            for variant in ("changed", "missing", "extra", "linked"):
                module.write_text("# fixture\n", encoding="utf-8")
                if variant == "changed":
                    module.write_text("# changed\n", encoding="utf-8")
                elif variant == "missing":
                    module.unlink()
                elif variant == "extra":
                    (archive / "extra.py").write_text("# extra\n", encoding="utf-8")
                if variant == "linked":
                    # Link rejection must not depend on Windows symlink rights.
                    with patch.object(Path, "is_symlink", return_value=True), self.assertRaisesRegex(
                            ValueError, "frozen_implementation_archive"):
                        probe.verify_implementation_archive(root, sources)
                else:
                    with self.assertRaisesRegex(ValueError, "frozen_implementation_archive"):
                        probe.verify_implementation_archive(root, sources)
                (archive / "extra.py").unlink(missing_ok=True)

    def execute_snapshot_fixture(self, *, tamper=False):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "implementation").mkdir()
            fixture = output / "implementation/fixture.py"
            fixture.write_text("# frozen offline fixture\n", encoding="utf-8")
            sources = {"fixture.py": probe.sha(fixture)}
            reference = output / "evaluation.opaque.json"
            probe.save(reference, {"runtime_sha256": "offline-runtime"})
            for name in ("http_transport_capture.json", "ner_infer_capture.json"):
                probe.save(output / name, [])
            plan = {"qwen": {"timeout_seconds": 120}, "assets": {"root": "unused"},
                    "gliner": {"threads": 4, "splitter": "cjk_aware", "threshold": .5},
                    "source_sha256": sources, "reference_opaque_sha256": probe.sha(reference),
                    "runtime_sha256": "offline-runtime", "scope": "offline-test"}
            local = Mock(side_effect=lambda **kwargs: {"status": "ok", "errors": [], "findings": [], "local_calls": 0})
            local.health.return_value = {}
            local.cache_identity.return_value = {}
            def ner_response(**kwargs):
                if kwargs["policy"]["category_contract"]["ontology_id"] == probe.STRICT_CUSTOMER_RELATION:
                    return {"status": "needs_review", "errors": ["unsupported_category_contract"],
                            "findings": [], "local_calls": 0}
                return {"status": "ok", "errors": [], "findings": [], "local_calls": 0}
            ner = Mock(side_effect=ner_response)
            ner.cache_identity.return_value = {}
            touched = []
            original_read_text = Path.read_text
            def guarded_read_text(path, *args, **kwargs):
                if path == reference:
                    snapshot = output / "predictions.json"
                    closure = json.loads((output / "prediction_phase_closed.json").read_bytes())
                    self.assertEqual(closure["predictions_sha256"], probe.sha(snapshot))
                    self.assertEqual(closure["source_sha256"], sources)
                    self.assertEqual(closure["completed_opportunities"], 96)
                    self.assertFalse(closure["reference_parsed"])
                    self.assertTrue(closure["implementation_and_archive_verified"])
                    self.assertEqual(set(closure["capture_objects_sha256"]),
                                     {"http_transport_capture.json", "ner_infer_capture.json"})
                    self.assertTrue(all("score" not in row for row in json.loads(snapshot.read_bytes())))
                    touched.append("reference-after-bound-snapshot")
                return original_read_text(path, *args, **kwargs)
            def score(rows, value, texts):
                self.assertEqual(touched, ["reference-after-bound-snapshot"])
                rows[0]["score"] = {"offline_marker": True}
                if tamper:
                    probe.save(output / "predictions.json", [{"tampered": True}])
                return {}
            with patch.object(probe, "verify_frozen", return_value=(plan, ["Text " + str(i) for i in range(16)],
                              probe.make_policies(), probe.make_schedule())), \
                 patch.object(probe, "source_hashes", return_value=sources), \
                 patch.object(probe, "install_network_guard"), \
                 patch.object(probe, "LocalSensitivityAgent", return_value=local), \
                 patch.object(probe, "LocalNerRuntime", return_value=SimpleNamespace(identity={}, initialization_seconds=0)), \
                 patch.object(probe, "GlinerEntityAgent", return_value=ner), \
                 patch.object(probe, "print"), \
                 patch.object(Path, "read_text", guarded_read_text), \
                 patch.object(probe, "score_rows", side_effect=score):
                if tamper:
                    with self.assertRaisesRegex(ValueError, "probe_closed_evidence_changed"):
                        probe.execute(output, "offline-test-plan")
                else:
                    result = probe.execute(output, "offline-test-plan")
            if tamper:
                self.assertFalse((output / "report.json").exists())
                self.assertFalse((output / "scored_rows.json").exists())
                execution = json.loads((output / "execution.json").read_bytes())
                self.assertEqual(execution["status"], "stopped")
                self.assertEqual(execution["error_code"], "probe_closed_evidence_changed")
                return
            self.assertEqual(result["status"], "complete")
            raw = json.loads((output / "predictions.json").read_bytes())
            scored = json.loads((output / "scored_rows.json").read_bytes())
            progress = json.loads((output / "rows.json").read_bytes())
            self.assertEqual(len(raw), 96)
            self.assertTrue(all("score" not in row for row in raw))
            self.assertEqual(raw, progress)
            self.assertEqual(scored[0]["score"], {"offline_marker": True})
            self.assertEqual(result["predictions_sha256"], probe.sha(output / "predictions.json"))

    def test_execute_closes_unscored_predictions_before_reference_and_scores_only_copy(self):
        self.execute_snapshot_fixture()

    def test_scoring_tamper_of_closed_snapshot_stops_without_complete_report(self):
        self.execute_snapshot_fixture(tamper=True)

    def test_status_keeps_semantic_review_unsupported_and_engineering_errors_distinct(self):
        review = {"status": "needs_review", "errors": ["semantic_uncertainty"], "findings": [], "local_calls": 1}
        unsupported = dict(review, errors=["unsupported_category_contract"], local_calls=0)
        broken = dict(review, errors=["local_transport_failed"])
        self.assertEqual(probe.observation_status(review), "needs_review")
        self.assertEqual(probe.observation_status(unsupported, expected_unsupported=True), "unsupported")
        self.assertEqual(probe.observation_status(unsupported), "engineering_error")
        self.assertEqual(probe.observation_status(review, expected_unsupported=True), "engineering_error")
        self.assertEqual(probe.observation_status(broken), "engineering_error")

    def test_generation_and_infer_budgets_stop_before_exceeding_limits(self):
        budget = probe.Budget()
        budget.posts = probe.LIMITS["qwen_post_attempts"]
        with self.assertRaisesRegex(RuntimeError, "probe_generation_budget_exceeded"):
            budget.generation()
        self.assertEqual(budget.posts, 128)
        budget.infers = probe.LIMITS["gliner_infer_invocations"]
        with self.assertRaisesRegex(RuntimeError, "probe_infer_budget_exceeded"):
            budget.inference()
        self.assertEqual(budget.infers, 16)
        budget.started -= probe.LIMITS["wall_seconds"]
        with self.assertRaisesRegex(RuntimeError, "probe_wall_budget_exceeded"):
            budget.check()

    def test_capture_blocks_strict_before_spending_an_infer_or_calling_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            actual = SimpleNamespace(identity={}, infer=Mock(return_value={"entities": {}}))
            budget = probe.Budget()
            captured = probe.CapturedNer(actual, budget, Path(directory))
            captured.cell = {"profile": probe.STRICT_CUSTOMER_RELATION, "arm": probe.ARMS[2]}
            with self.assertRaisesRegex(RuntimeError, "probe_ner_profile_forbidden"):
                captured.infer("Plain text", {"organization": "description"})
            actual.infer.assert_not_called()
            self.assertEqual(budget.infers, 0)
            self.assertEqual(captured.events, [])
            captured.cell = {"profile": probe.ANY_SPECIFIC_ORGANIZATION, "arm": probe.ARMS[2]}
            self.assertEqual(captured.infer("Plain text", {"organization": "description"}), {"entities": {}})
            actual.infer.assert_called_once()
            self.assertEqual(budget.infers, 1)

    def test_capture_checks_wall_budget_after_transport_and_ner_return(self):
        for kind in ("transport", "ner"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                now = [0.0]
                def actual(*args, **kwargs):
                    now[0] = probe.LIMITS["wall_seconds"]
                    return {"returned": True}
                with patch.object(probe.time, "monotonic", side_effect=lambda: now[0]):
                    budget = probe.Budget()
                    if kind == "transport":
                        captured = probe.CapturedTransport(actual, budget, Path(directory))
                        invoke = lambda: captured("POST", "/api/chat", {})
                    else:
                        captured = probe.CapturedNer(SimpleNamespace(identity={}, infer=actual), budget, Path(directory))
                        captured.cell = {"profile": probe.ANY_SPECIFIC_ORGANIZATION, "arm": probe.ARMS[2]}
                        invoke = lambda: captured.infer("Plain text", {"organization": "description"})
                    with self.assertRaisesRegex(RuntimeError, "probe_wall_budget_exceeded"):
                        invoke()
                    self.assertEqual(captured.events[0]["decoded_response"], {"returned": True})
                    self.assertEqual(captured.events[0]["error_type"], "RuntimeError")
                    self.assertEqual((budget.posts, budget.infers), (1, 0) if kind == "transport" else (0, 1))

    def test_execute_expiry_after_last_return_or_before_close_stops_without_reference(self):
        for expiry_stage in ("return", "close"):
            with self.subTest(expiry_stage=expiry_stage), tempfile.TemporaryDirectory() as directory:
                now = [0.0]
                local = Mock()
                local.health.return_value = {}
                local.cache_identity.return_value = {}
                def detect(**kwargs):
                    if expiry_stage == "return":
                        now[0] = probe.LIMITS["wall_seconds"]
                    return {"status": "ok", "errors": [], "findings": [], "local_calls": 0}
                local.side_effect = detect
                ner = Mock()
                ner.cache_identity.return_value = {}
                def after_progress(*args, **kwargs):
                    if expiry_stage == "close":
                        now[0] = probe.LIMITS["wall_seconds"]
                plan = {"qwen": {"timeout_seconds": 120}, "assets": {"root": "unused"},
                        "gliner": {"threads": 4, "splitter": "cjk_aware", "threshold": .5}}
                schedule = [{"text_index": 0, "profile": probe.ANY_SPECIFIC_ORGANIZATION, "arm": probe.ARMS[1]}]
                with patch.object(probe, "verify_frozen", return_value=(plan, ["Plain text"], probe.make_policies(), schedule)), \
                     patch.object(probe, "install_network_guard"), \
                     patch.object(probe, "LocalSensitivityAgent", return_value=local), \
                     patch.object(probe, "LocalNerRuntime", return_value=SimpleNamespace(identity={}, initialization_seconds=0)), \
                     patch.object(probe, "GlinerEntityAgent", return_value=ner), \
                     patch.object(probe.time, "monotonic", side_effect=lambda: now[0]), \
                     patch.object(probe, "print", side_effect=after_progress), \
                     patch.object(probe, "sha", side_effect=AssertionError("reference must remain opaque")) as reference_hash, \
                     patch.object(probe, "score_rows", side_effect=AssertionError("scoring forbidden")) as scorer:
                    with self.assertRaisesRegex(RuntimeError, "probe_wall_budget_exceeded"):
                        probe.execute(directory, "offline-test-plan")
                reference_hash.assert_not_called()
                scorer.assert_not_called()
                execution = json.loads((Path(directory) / "execution.json").read_text(encoding="utf-8"))
                self.assertEqual(execution["status"], "stopped")
                self.assertEqual(execution["error_code"], "probe_wall_budget_exceeded")
                self.assertEqual(execution["completed_opportunities"], 1)
                self.assertFalse(execution.get("reference_parsed", False))
                self.assertFalse((Path(directory) / "report.json").exists())

    def test_scoring_separates_exact_spans_review_and_unsupported(self):
        import hashlib
        texts = ["Alder Works record " + str(i) for i in range(16)]
        expected = {"decision": "sensitive", "spans": [{"start": 0, "end": 11,
                     "text": "Alder Works", "category": "CUSTOMER"}]}
        cases = [{"text_index": i, "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "expected": {profile: copy.deepcopy(expected) for profile in probe.PROFILES}} for i, text in enumerate(texts)]
        cases[1]["expected"][probe.STRICT_CUSTOMER_RELATION] = {"decision": "needs_review", "spans": []}
        cases[4]["expected"][probe.STRICT_CUSTOMER_RELATION] = {"decision": "not_sensitive", "spans": []}
        reference = {"schema_version": "ontology_contract_probe_evaluation_v1", "runtime_sha256": "opaque",
                     "profile_contract_sha256": {p: _digest(category_contract(p)) for p in probe.PROFILES}, "cases": cases}
        def row(index, arm, status, findings=()):
            return {"cell": {"text_index": index, "profile": probe.STRICT_CUSTOMER_RELATION, "arm": arm},
                    "status": status, "response": {"findings": list(findings)}}
        rows = [row(0, probe.ARMS[1], "needs_review"), row(1, probe.ARMS[1], "needs_review"),
                row(1, probe.ARMS[2], "unsupported"),
                row(2, probe.ARMS[1], "ok", [{"start": 6, "end": 11, "quote": "Works", "category": "CUSTOMER"}]),
                row(3, probe.ARMS[1], "ok", [{"start": 0, "end": 11, "quote": "Alder Works", "category": "CUSTOMER"}]),
                row(4, probe.ARMS[1], "ok")]
        summary = probe.score_rows(rows, reference, texts)
        qwen = summary[probe.STRICT_CUSTOMER_RELATION + "/" + probe.ARMS[1]]
        self.assertEqual(qwen["fn"], 2)
        self.assertEqual(qwen["reference_review_matches"], 1)
        self.assertEqual(qwen["decision_matches"], 4)
        self.assertEqual(qwen["determinate_applicable_cells"], 4)
        self.assertEqual(qwen["determinate_exact_matches"], 2)
        self.assertEqual(qwen["determinate_exact_match_rate"], .5)
        self.assertFalse(rows[0]["score"]["determinate_exact_match"])
        self.assertIsNone(rows[1]["score"]["determinate_exact_match"])
        self.assertIsNone(rows[2]["score"]["determinate_exact_match"])
        self.assertTrue(rows[3]["score"]["decision_matches"])
        self.assertFalse(rows[3]["score"]["determinate_exact_match"])
        self.assertTrue(rows[4]["score"]["determinate_exact_match"])
        self.assertTrue(rows[5]["score"]["determinate_exact_match"])
        ner = summary[probe.STRICT_CUSTOMER_RELATION + "/" + probe.ARMS[2]]
        self.assertEqual(ner["reference_review_matches"], 0)
        self.assertEqual(ner["unsupported"], 1)
        self.assertFalse(ner["eligible_for_same_profile_ranking"])
        self.assertIsNone(ner["recall"])
        self.assertEqual(ner["determinate_applicable_cells"], 0)
        self.assertEqual(ner["determinate_exact_matches"], 0)
        self.assertIsNone(ner["determinate_exact_match_rate"])


if __name__ == "__main__":
    unittest.main()
