import copy
import json
from pathlib import Path
import tempfile
import unittest

from memory_migration_study.privacy_corpus import (
    _digest, _write, build_corpus, evaluate_corpus, validate_corpus, write_corpus,
)


class PrivacyCorpusTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.runtime, self.evaluation = build_corpus()
        self.runtime_path = self.base / "runtime.json"
        self.evaluation_path = self.base / "evaluation.json"
        _write(self.runtime_path, self.runtime)
        _write(self.evaluation_path, self.evaluation)

    def run_evaluation(self, detector, **kwargs):
        return evaluate_corpus(self.runtime_path, self.evaluation_path, detector=detector, **kwargs)

    def test_balanced_authored_corpus_has_disjoint_template_and_story_splits(self):
        cases = self.runtime["cases"]
        self.assertEqual(len(cases), 120)
        self.assertEqual(sum(case["language"] == "zh" for case in cases), 60)
        self.assertEqual(sum(case["language"] == "en" for case in cases), 60)
        self.assertEqual(sum(case["split"] == "dev" for case in cases), 80)
        self.assertEqual(sum(case["split"] == "heldout" for case in cases), 40)
        for field in ("template_family", "story_id"):
            dev = {case[field] for case in cases if case["split"] == "dev"}
            heldout = {case[field] for case in cases if case["split"] == "heldout"}
            self.assertFalse(dev & heldout)
        self.assertIsNone(self.evaluation["human_review"])
        self.assertEqual(build_corpus(), (self.runtime, self.evaluation))

    def test_policy_twins_change_sensitivity_without_changing_content(self):
        cases = {case["case_id"]: case for case in self.runtime["cases"]}
        gold = {case["case_id"]: case for case in self.evaluation["cases"]}
        for family in ("policy_pair", "publication_notice"):
            for language in ("en", "zh"):
                private, public = (cases[f"{family}-{language}-{j:02d}"] for j in (0, 1))
                self.assertEqual(private["payload"]["memories"][0]["text"], public["payload"]["memories"][0]["text"])
                self.assertEqual(private["story_id"], public["story_id"])
                self.assertTrue(gold[private["case_id"]]["findings"])
                self.assertEqual(gold[public["case_id"]]["findings"], [])

    def test_detector_receives_only_runtime_payload_and_trusted_policy(self):
        calls = []
        def detector(payload, policy, **kwargs):
            self.assertEqual(set(payload), {"query", "memories"})
            self.assertEqual(set(policy), {"version", "protected_categories"})
            for memory in payload["memories"]:
                self.assertEqual(set(memory), {"source_id", "text"})
            calls.append(payload)
            payload["query"] = "mutated copy"
            return {"status": "ok", "findings": [], "errors": []}
        report = self.run_evaluation(detector, modes=("rules",))
        self.assertEqual(len(calls), 120)
        self.assertEqual(report["case_count"], 120)
        self.assertEqual(report["remote_model_calls"], 0)
        self.assertEqual(self.runtime["cases"][0]["payload"]["query"], "")
        self.assertFalse(any("findings" in case for case in self.runtime["cases"]))

    def test_failure_samples_remain_in_denominator_and_block_gate(self):
        def broken(*args, **kwargs):
            raise RuntimeError("content that must not enter report")
        report = self.run_evaluation(broken, modes=("combined",))
        heldout = next(row for row in report["summaries"] if row["split"] == "heldout" and row["language"] == "all")
        self.assertEqual(heldout["cases"], 40)
        self.assertEqual(heldout["needs_review"], 40)
        self.assertEqual(heldout["recall"], 0)
        self.assertIsNone(heldout["precision"])
        self.assertFalse(report["heldout_gate"]["passed"])
        self.assertNotIn("content that must", json.dumps(report))

    def test_exact_typed_span_scoring_differs_from_character_coverage(self):
        # Deliberately wrong type has full coverage, but is not an exact match.
        gold = {row["case_id"]: row["findings"] for row in self.evaluation["cases"]}
        def wrong_type(payload, policy, **kwargs):
            case_id = payload["memories"][0]["source_id"].removeprefix("memory-")
            findings = copy.deepcopy(gold[case_id])
            for finding in findings:
                finding["category"] = "DATE" if finding["category"] != "DATE" else "PERSON"
            return {"status": "ok", "findings": findings, "errors": []}
        report = self.run_evaluation(wrong_type, modes=("rules",))
        overall = report["summaries"][0]
        self.assertEqual(overall["recall"], 0)
        self.assertEqual(overall["character_recall"], 1)
        self.assertGreater(overall["fp"], 0)

    def test_invalid_predictions_are_visible_errors(self):
        def invalid(payload, policy, **kwargs):
            return {"status": "ok", "findings": [{"source_id": "not-present", "start": 0,
                       "end": 2, "category": "PERSON"}], "errors": []}
        report = self.run_evaluation(invalid, modes=("combined",))
        self.assertEqual(report["summaries"][0]["error_cases"], 120)
        self.assertFalse(report["heldout_gate"]["passed"])

    def test_cache_reuses_failures_but_rejects_changed_runtime_or_model(self):
        calls = []
        def detector(*args, **kwargs):
            calls.append(True)
            return {"status": "needs_review", "findings": [], "errors": ["parse_error"]}
        cache = self.base / "cache.json"
        self.run_evaluation(detector, modes=("rules",), cache_path=cache)
        replay = self.run_evaluation(detector, modes=("rules",), cache_path=cache)
        self.assertEqual(len(calls), 120)
        self.assertEqual(replay["summaries"][0]["cached_cases"], 120)
        with self.assertRaisesRegex(ValueError, "stale_detection_cache"):
            self.run_evaluation(detector, modes=("rules",), cache_path=cache,
                                detector_provenance={"model_digest": "different"})

    def test_agent_cache_requires_model_and_prompt_provenance(self):
        with self.assertRaisesRegex(ValueError, "requires_model_and_prompt"):
            self.run_evaluation(lambda *args, **kwargs: {}, modes=("agent",),
                                cache_path=self.base / "cache.json", agent=object())

    def test_gate_requires_preregistered_case_count(self):
        gold = {row["case_id"]: row["findings"] for row in self.evaluation["cases"]}
        def exact(payload, policy, **kwargs):
            cid = payload["memories"][0]["source_id"].removeprefix("memory-")
            return {"status": "ok", "findings": copy.deepcopy(gold[cid]), "errors": []}
        matching = self.run_evaluation(exact, modes=("combined",))
        self.assertTrue(matching["heldout_gate"]["passed"])
        wrong = self.run_evaluation(exact, modes=("combined",), expected_heldout_cases=48)
        self.assertFalse(wrong["heldout_gate"]["passed"])
        self.assertEqual(wrong["heldout_gate"]["required_heldout_cases"], 48)

    def test_gold_is_bound_to_runtime_and_destinations_not_overwritten(self):
        mutated = copy.deepcopy(self.runtime)
        mutated["cases"][0]["payload"]["query"] = "changed"
        with self.assertRaisesRegex(ValueError, "gold_runtime_hash_mismatch"):
            validate_corpus(mutated, self.evaluation)
        with self.assertRaises(FileExistsError):
            write_corpus(self.base)
        gold = copy.deepcopy(self.evaluation)
        gold["cases"][0]["findings"][0]["end"] = 100000
        with self.assertRaisesRegex(ValueError, "invalid_gold_span"):
            validate_corpus(self.runtime, gold)


if __name__ == "__main__":
    unittest.main()
