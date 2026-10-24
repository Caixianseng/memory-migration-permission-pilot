import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("semantic_detection_benchmark", Path(__file__).resolve().parents[1] / "scripts/run_semantic_detection_benchmark.py")
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)
from memory_migration_study.union_detector import IndependentUnionDetector


class EmptyAgent:
    def __init__(self, output):
        self.output = output
        self.calls = []

    def cache_identity(self):
        return {"kind": "test_instrument"}

    def __call__(self, **kwargs):
        assert set(kwargs) == {"text", "source_id", "policy", "rule_findings"}
        assert not (self.output / "evaluation.json").exists()
        self.calls.append(kwargs)
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 1, "elapsed_seconds": 0}


class EmptyRuntime:
    identity = {"weights_sha256": "0" * 64, "kind": "test_instrument"}

    def infer(self, text, labels, **options):
        assert options == {"splitter": "cjk_aware", "threshold": .5}
        return {"entities": {label: [] for label in labels}}


class InstrumentUnion:
    """Test interface only; real union behavior has separate package tests."""
    def __init__(self, *, first, second, member_kinds):
        self.members, self.kinds = (first, second), member_kinds

    def cache_identity(self):
        return {"kind": "injected_union_instrument"}

    def __call__(self, **kwargs):
        responses = [member(**kwargs) for member in self.members]
        typed = {kind: 0 for kind in benchmark.INFERENCE_KINDS}
        for kind, result in zip(self.kinds, responses):
            typed[kind] += result["local_calls"]
        return {"status": "ok" if all(r["status"] == "ok" for r in responses) else "needs_review",
                "findings": [finding for r in responses for finding in r["findings"]],
                "errors": [e for r in responses for e in r.get("errors", [])],
                "local_calls": sum(typed.values()), "elapsed_seconds": 0, "inference_counts": typed,
                "member_observations": [{"kind": kind, "local_calls": r["local_calls"]} for kind, r in zip(self.kinds, responses)]}


class FixedMember:
    """A model-free member that reports one encoder or a two-call repair path."""
    def __init__(self, calls, findings=()):
        self.max_local_calls = calls
        self.calls, self.findings = calls, findings

    def cache_identity(self):
        return {"kind": "fixed_contract_instrument", "max_local_calls": self.max_local_calls}

    def __call__(self, **kwargs):
        return {"status": "ok", "findings": list(self.findings), "errors": [], "local_calls": self.calls,
                "local_calls_complete": True, "elapsed_seconds": 0}


class SemanticDetectionBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"query": "Check this field.", "memories": [{"source_id": "m", "text": "Name: Mira"}]}
        self.finding = {"source_id": "m", "start": 6, "end": 10, "category": "PERSON"}
        self.gold = {"findings": [self.finding]}

    def test_exact_match_uses_source_full_boundary_and_category(self):
        for changes in ({"start": 7}, {"category": "CUSTOMER"}, {"source_id": "__query__", "start": 0, "end": 4}):
            result = {"status": "ok", "findings": [dict(self.finding, **changes)]}
            score = benchmark.score_detection(result, self.gold, self.payload)
            self.assertEqual((score["accepted"]["tp"], score["accepted"]["fp"], score["accepted"]["fn"]), (0, 1, 1))

    def test_needs_review_retains_gold_false_negative_not_candidate_credit(self):
        score = benchmark.score_detection({"status": "needs_review", "findings": [self.finding]}, self.gold, self.payload)
        self.assertEqual(score["accepted"]["tp"], 0)
        self.assertEqual(score["accepted"]["fn"], 1)
        self.assertEqual(score["validated_candidate"]["tp"], 1)
        self.assertFalse(score["accepted_complete_exact"])

    def test_invalid_candidate_blocks_main_acceptance_and_does_not_erase_fn(self):
        invalid = dict(self.finding, end=999)
        score = benchmark.score_detection({"status": "ok", "findings": [invalid]}, self.gold, self.payload)
        self.assertEqual(score["invalid_candidate_count"], 1)
        self.assertEqual(score["accepted"]["fn"], 1)
        self.assertFalse(score["accepted_complete_exact"])

    def test_empty_denominators_are_unavailable_not_perfect_precision(self):
        score = benchmark.score_detection({"status": "ok", "findings": []}, {"findings": []}, self.payload)
        self.assertIsNone(score["accepted"]["precision"])
        self.assertIsNone(score["accepted"]["recall"])
        self.assertTrue(score["accepted_complete_exact"])

    def test_union_counter_preserves_two_generations_and_one_encoding(self):
        response = {"status": "ok", "local_calls": 3,
                    "inference_counts": {"local_encoder": 1, "local_generation": 2},
                    "member_observations": [{"kind": "local_generation", "local_calls": 2}]}
        observer = benchmark.CountingAgent(lambda **_: response, "independent_union")
        self.assertIs(observer(text="example"), response)
        result = observer.accounting({"local_calls": 3, "local_calls_complete": True})
        self.assertTrue(result["complete"])
        self.assertEqual(result["inference_counts"], {"local_encoder": 1, "local_generation": 2, "unknown": 0})
        self.assertEqual(result["observations"][0]["member_observations"][0]["local_calls"], 2)

    def test_union_missing_typed_counts_is_unclassified_not_pure_generation(self):
        observer = benchmark.CountingAgent(lambda **_: {"local_calls": 3}, "independent_union")
        observer(text="example")
        result = observer.accounting({"local_calls": 3, "local_calls_complete": True})
        self.assertFalse(result["complete"])
        self.assertEqual(result["unclassified_reported_calls"], 3)
        self.assertEqual(result["inference_counts"], {"local_encoder": 0, "local_generation": 0, "unknown": 3})

    def test_real_union_three_call_contract_survives_counting_and_host_validation(self):
        ner = FixedMember(1, [{"quote": "Mira", "start": 6, "end": 10, "category": "PERSON"}])
        repair = FixedMember(2)
        union = IndependentUnionDetector(first=ner, second=repair, member_kinds=("local_encoder", "local_generation"))
        observer = benchmark.CountingAgent(union, "independent_union")
        self.assertEqual(observer.max_local_calls, 3)
        payload = {"query": "", "memories": self.payload["memories"]}
        result = benchmark.detect_sensitive(payload, {"version": "1", "protected_categories": ["PERSON"]}, mode="agent", agent=observer)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["local_calls"], 3)
        self.assertTrue(result["local_calls_complete"])
        counter = observer.accounting(result)
        self.assertTrue(counter["complete"])
        self.assertEqual(counter["inference_counts"], {"local_encoder": 1, "local_generation": 2, "unknown": 0})
        self.assertEqual(counter["unclassified_reported_calls"], 0)

    def test_real_union_unknown_member_is_explicitly_incomplete(self):
        union = IndependentUnionDetector(FixedMember(1), FixedMember(2), member_kinds=("unknown", "local_generation"))
        observer = benchmark.CountingAgent(union, "independent_union")
        response = observer(text="Mira", source_id="m", policy={"version": "1", "protected_categories": ["PERSON"]}, rule_findings=[])
        self.assertEqual(response["local_calls"], 3)
        counter = observer.accounting({"local_calls": 3, "local_calls_complete": True})
        self.assertFalse(counter["complete"])
        self.assertEqual(counter["inference_counts"], {"local_encoder": 0, "local_generation": 2, "unknown": 1})
        self.assertEqual(counter["unclassified_reported_calls"], 1)

    def test_budget_excess_is_retained_and_flagged_not_clipped(self):
        observer = benchmark.CountingAgent(lambda **_: {"local_calls": 4,
            "inference_counts": {"local_encoder": 1, "local_generation": 3}}, "independent_union")
        observer(text="example")
        result = observer.accounting({"local_calls": 4, "local_calls_complete": True})
        self.assertFalse(result["complete"])
        self.assertEqual(result["inference_counts"]["local_generation"], 3)
        self.assertIn("per_source_adapter_budget_exceeded", result["observations"][0]["errors"])

    def make_data(self, root):
        split = root / "development"
        split.mkdir(parents=True)
        payload = {"query": "Check the current field.", "memories": [{"source_id": "m", "text": "mail@unit.example"}]}
        private = {"case_id": "private", "language": "en", "template_family": "instrument", "policy": {"version": "p", "protected_categories": ["EMAIL"]}, "payload": payload}
        public = {"case_id": "public", "language": "en", "template_family": "instrument", "policy": {"version": "u", "protected_categories": []}, "payload": payload}
        gold = {"private": {"findings": [{"source_id": "m", "start": 0, "end": 17, "category": "EMAIL"}], "policy_pair_id": "pair"},
                "public": {"findings": [], "policy_pair_id": "pair"}}
        benchmark.save(split / "runtime.json", [private, public])
        benchmark.save(split / "evaluation.json", gold)
        manifest = {"files": {"development/" + n: {"sha256": hashlib.sha256((split / n).read_bytes()).hexdigest()} for n in ("runtime.json", "evaluation.json")},
                    "splits": {"development": {"materials": 2}}}
        benchmark.save(root / "manifest.json", manifest)

    def test_injected_end_to_end_keeps_all_arms_pairs_and_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, output = Path(tmp) / "data", Path(tmp) / "output"
            self.make_data(root)
            baseline = EmptyAgent(output)
            report = benchmark.run(root, "development", output, {}, None, baseline=baseline, runtime_model=EmptyRuntime(), union_factory=InstrumentUnion)
            self.assertEqual(len(report["rows"]), 10)
            self.assertTrue(report["implementation_unchanged"])
            self.assertEqual(report["arms"], benchmark.summarize(report["rows"]))
            self.assertEqual(report["qwen_generations_reported"], 6)
            self.assertEqual(report["encoder_invocations_reported"], 4)
            self.assertTrue(report["complete_call_accounting"])
            self.assertEqual(report["arms"]["union_combined"]["qwen_generations_reported"], 2)
            self.assertEqual(report["arms"]["union_combined"]["encoder_invocations_reported"], 2)
            self.assertEqual(report["cloud_calls"], 0)
            self.assertEqual(report["arms"]["qwen_agent"]["accepted"]["fn"], 1)
            self.assertEqual(report["arms"]["rules"]["policy_pairs"]["both_materials_complete_exact"], 1)
            self.assertEqual(report["arms"]["qwen_agent"]["policy_pairs"]["both_materials_complete_exact"], 0)
            self.assertFalse((root / "heldout").exists())

    def test_rules_only_selection_does_not_initialize_or_call_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, output = Path(tmp) / "data", Path(tmp) / "output"
            self.make_data(root)
            def fail(*args, **kwargs):
                raise AssertionError("models must not initialize")
            with patch.object(benchmark, "LocalSensitivityAgent", fail), patch.object(benchmark, "LocalNerRuntime", fail):
                report = benchmark.run(root, "development", output, {}, None, arms=["rules"])
            self.assertEqual(list(report["arms"]), ["rules"])
            self.assertEqual(len(report["rows"]), 2)
            self.assertEqual(report["qwen_generations_reported"], 0)
            self.assertEqual(report["encoder_invocations_reported"], 0)

    def test_saved_member_cost_recheck_preserves_original_predictions_and_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            detection = {"status": "ok", "findings": [self.finding], "errors": [],
                         "local_calls": 0, "local_calls_complete": False, "agent_elapsed_seconds": 0}
            member_observations = [
                {"index": 0, "inference_kind": "local_encoder", "local_calls": 1, "local_calls_complete": True},
                {"index": 1, "inference_kind": "local_generation", "local_calls": 2, "local_calls_complete": True}]
            row = {"case_id": "unit", "language": "en", "template_family": "unit", "arm": "union_combined",
                   "policy_scope": "private_type", "policy_pair_id": None, "wall_seconds": 0,
                   "detection": detection, "score": benchmark.score_detection(detection, self.gold, self.payload),
                   "qwen_generations": 0, "encoder_invocations": 0,
                   "accounting": {"observations": [{"member_observations": member_observations,
                                                      "errors": ["invalid_typed_accounting"]}]}}
            benchmark.save(root / "rows.json", [row])
            benchmark.save(root / "report.json", {"rows": [row]})
            old_report = (root / "report.json").read_bytes()
            old_rows = (root / "rows.json").read_bytes()
            result = benchmark.recheck_saved_accounting(root, root / "accounting_recheck.json")
            self.assertEqual(result["qwen_generations_recomputed"], 2)
            self.assertEqual(result["encoder_invocations_recomputed"], 1)
            self.assertTrue(result["complete_reconstructed_call_accounting"])
            self.assertEqual(result["original_host_incomplete_union_rows"], 1)
            self.assertEqual(result["original_host_mismatched_union_rows"], 1)
            self.assertTrue(result["predictions_and_scores_unchanged"])
            self.assertEqual((root / "report.json").read_bytes(), old_report)
            self.assertEqual((root / "rows.json").read_bytes(), old_rows)
            with self.assertRaises(FileExistsError):
                benchmark.recheck_saved_accounting(root, root / "accounting_recheck.json")

    def test_changed_input_hash_fails_before_models_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, output = Path(tmp) / "data", Path(tmp) / "output"
            self.make_data(root)
            with (root / "development/runtime.json").open("a", encoding="utf-8") as handle:
                handle.write(" ")
            with self.assertRaisesRegex(ValueError, "frozen_input_hash_mismatch"):
                benchmark.run(root, "development", output, {}, None, baseline=EmptyAgent(output), runtime_model=EmptyRuntime())
            self.assertFalse(output.exists())

    def test_network_guard_rejects_non_loopback_connect_without_real_network(self):
        network = {"allowed_loopback_connections": 0, "blocked_external_connections": 0}
        hooks = []
        with patch.object(benchmark.sys, "addaudithook", hooks.append):
            benchmark.install_network_guard(network)
        hooks[0]("socket.connect", (None, ("127.0.0.1", 11435)))
        with self.assertRaisesRegex(RuntimeError, "external_network_disabled"):
            hooks[0]("socket.connect", (None, ("example.com", 443)))
        self.assertEqual(network, {"allowed_loopback_connections": 1, "blocked_external_connections": 1})


if __name__ == "__main__":
    unittest.main()
