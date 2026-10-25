"""Paired development integration with tiny fixtures and fake local models."""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import semantic_memory_benchmark as benchmark
from memory_migration_study.memory_labels import MemoryLabelAuthority
from tests.test_study_semantic_memory_benchmark import (CANARY, OUTSIDER_QUERY, fixture,
    FakeModelBuilder, FakeNerRuntime, FakeAnswerer, FakeClassifier)


class BareTokenAnswerer(FakeAnswerer):
    def __call__(self, payload):
        result = super().__call__(payload)
        if isinstance(result.get("answer"), str) and re.fullmatch(r"\[PVT_[A-F0-9]{24}_[A-Z]+_[0-9]+\]", result["answer"]):
            result["answer"] = result["answer"][1:-1]
        return result


class SemanticMemoryBoundaryTests(unittest.TestCase):
    def test_paired_protocol_refuses_other_splits_detectors_and_non_boolean_flag(self):
        for split, detector in (("heldout", "gliner"), ("development", "union")):
            with self.subTest(split=split, detector=detector), self.assertRaises(ValueError):
                benchmark.run("not-read", "not-created", "not-loaded", {}, split=split,
                              detector_kind=detector, paired_boundary=True)
        with self.assertRaises(ValueError):
            benchmark.study_arms(1)

    def test_oversized_registered_protocol_rejected_before_loading_model(self):
        runtime, _ = fixture()
        larger = [dict(copy.deepcopy(runtime[0]), story_id=f"authored-{index}") for index in range(9)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            split = root/"corpus"/"development"
            split.mkdir(parents=True)
            (split/"runtime.json").write_text(json.dumps(larger), encoding="utf-8")
            (split/"evaluation.json").write_text("{}", encoding="utf-8")
            with patch.object(benchmark, "LocalNerRuntime", side_effect=AssertionError("must_not_load_model")) as model:
                with self.assertRaisesRegex(ValueError, "generation_budget"):
                    benchmark.run(root/"corpus", root/"output", "not-loaded", {}, paired_boundary=True)
            model.assert_not_called()
            self.assertFalse((root/"output").exists())

    def run_fixture(self, *, model_failure=False, bare_token=False, poisoned_answers=False):
        runtime, evaluation = fixture()
        if poisoned_answers:
            evaluation[runtime[0]["story_id"]]["answers"] = {task: CANARY for task in evaluation[runtime[0]["story_id"]]["answers"]}
        model, ner = FakeModelBuilder(model_failure), FakeNerRuntime()
        answerer, classifier, prepares, progress = (BareTokenAnswerer() if bare_token else FakeAnswerer()), FakeClassifier(), [], []
        real_prepare = benchmark.prepare_labeled_transfer
        def prepare(*args, **kwargs):
            prepares.append({"record_ids": [r["record_id"] for r in args[0]], "query": args[1],
                "pipeline": kwargs.get("privacy_pipeline"), "mode": kwargs.get("mode"), "actor": kwargs.get("actor_id")})
            return real_prepare(*args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            split, output = root/"corpus"/"development", root/"output"
            split.mkdir(parents=True)
            (split/"runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            gold_text = json.dumps(evaluation)
            (split/"evaluation.json").write_text(gold_text, encoding="utf-8")
            original_loads, gold_reads = json.loads, []
            def guarded_loads(value, *args, **kwargs):
                if value == gold_text or value == gold_text.encode("utf-8"):
                    fixed = original_loads((output/"rows.json").read_text(encoding="utf-8"))
                    self.assertEqual(len(fixed), 55)
                    self.assertTrue(all("score" not in row for row in fixed))
                    self.assertEqual(len(classifier.calls), 4)
                    self.assertEqual(len(model.calls), 1)
                    self.assertFalse((output/"evaluation.json").exists())
                    gold_reads.append("after_all_models")
                return original_loads(value, *args, **kwargs)
            with patch.object(benchmark, "LocalNerRuntime", return_value=ner), \
                 patch.object(benchmark, "LocalMemoryBuilder", return_value=model), \
                 patch.object(benchmark, "LocalFactAnswerer", return_value=answerer), \
                 patch.object(benchmark, "LocalQueryIntentClassifier", return_value=classifier), \
                 patch.object(benchmark.LocalSensitivityAgent, "health", return_value=None), \
                 patch.object(benchmark, "prepare_labeled_transfer", side_effect=prepare), \
                 patch.object(benchmark.json, "loads", side_effect=guarded_loads), \
                 patch("socket.socket.connect", side_effect=AssertionError("no_real_models_or_network")):
                report = benchmark.run(root/"corpus", output, "no-model-assets", {}, paired_boundary=True, progress=progress.append)
            rows = original_loads((output/"rows.json").read_text(encoding="utf-8"))
            builds = original_loads((output/"builds.json").read_text(encoding="utf-8"))
            plan = original_loads((output/"plan.json").read_text(encoding="utf-8"))
            self.assertEqual(gold_reads, ["after_all_models"])
            raw = json.dumps({"answer": answerer.calls, "classifier": classifier.calls, "builder": model.calls, "ner": ner.calls})
            self.assertNotIn(CANARY, raw)
            self.assertNotIn(OUTSIDER_QUERY, raw)
            self.assertNotIn('"answers"', raw)
            self.assertNotIn('"sensitive_spans"', raw)
            self.assertNotIn('"mapping"', (output/"rows.json").read_text(encoding="utf-8"))
            return report, rows, builds, plan, model, ner, answerer, classifier, prepares, progress

    def test_default_six_unchanged_and_paired_eleven_complete_grid(self):
        self.assertEqual(benchmark.study_arms(), benchmark.ARMS)
        arms = benchmark.study_arms(True)
        self.assertEqual(len(arms), 11)
        self.assertEqual(sum(spec[1] == "raw" for spec in arms.values()), 1)
        report, rows, builds, plan, model, ner, answerer, classifier, prepares, progress = self.run_fixture()
        self.assertEqual((report["registered_rows"], report["recorded_rows"], report["legal_rows"], report["outsider_rows"]), (55, 55, 44, 11))
        self.assertEqual({(row["task_id"], row["arm"]) for row in rows},
                         {(task, arm) for task in ("name", "status", "repeat", "mail", "outsider") for arm in arms})
        self.assertEqual(len(builds), 2)
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(len(classifier.calls), 4)
        self.assertEqual(len(answerer.calls), 44)
        self.assertEqual(report["migration_encoder_calls"], 72)
        self.assertEqual(report["coverage_builder_encoder_calls"], 1)
        self.assertEqual(report["answer_generations"], 44)
        self.assertEqual((progress[-1]["completed"], progress[-1]["expected"]), (55, 55))
        self.assertTrue(all(event["correct"] is None for event in progress))
        self.assertEqual(plan["evaluation_timing"], "after_all_model_processing")
        self.assertTrue(plan["entrypoint_sha256"])
        self.assertEqual(plan["expected_rows"], 55)
        for arm, metrics in report["arms"].items():
            self.assertEqual((metrics["registered_tasks"], metrics["legal_tasks"], metrics["outsider_blocked"]), (5, 4, 1))
            self.assertEqual(metrics["unauthorized_output"], 0)
            if arm == "coverage_raw_local":
                self.assertIsNone(metrics["joint_correct_no_masking_gap"])
                self.assertEqual(metrics["joint_masked_legal_tasks"], 0)
                self.assertIsNone(metrics["secondary_serialization_correct"])
            else:
                self.assertEqual(metrics["joint_masked_legal_tasks"], 4)
                self.assertEqual(metrics["joint_correct_no_masking_gap"], 4)
                self.assertEqual(metrics["secondary_serialization_legal_tasks"], 4)
                self.assertEqual(metrics["secondary_serialization_correct"], 4)
        by_key = {}
        for item in prepares:
            by_key.setdefault((item["query"], item["mode"], tuple(item["record_ids"])), set()).add(item["pipeline"])
        self.assertTrue(all(value == {"legacy", "boundary"} for value in by_key.values()))
        for row in rows:
            if row["actor_id"] == "outsider":
                self.assertEqual(row["detector_calls"], 0)
                self.assertEqual(row["answer_calls"], 0)

    def test_model_build_failure_preserves_both_paired_arms_and_all_denominators(self):
        report, rows, builds, _, _, _, answerer, _, _, _ = self.run_fixture(model_failure=True)
        self.assertEqual(len(rows), 55)
        self.assertEqual(len(answerer.calls), 36)
        for arm in ("model_build_migration__legacy", "model_build_migration__boundary"):
            metrics = report["arms"][arm]
            self.assertEqual((metrics["registered_tasks"], metrics["legal_tasks"], metrics["build_block"]), (5, 4, 4))
            self.assertEqual(metrics["build_successes"], 0)
            self.assertEqual(metrics["joint_correct_no_masking_gap"], 0)
            self.assertEqual(metrics["secondary_serialization_legal_tasks"], 4)
            self.assertEqual(metrics["secondary_serialization_correct"], 0)
        self.assertEqual(next(build for build in builds if build["builder"] == "model")["stored_characters"], 0)

    def test_secondary_serialization_reuses_same_response_without_changing_primary(self):
        report, rows, _, _, _, _, answerer, _, _, _ = self.run_fixture(bare_token=True)
        self.assertEqual(len(answerer.calls), 44)
        changed = [row for row in rows if (row.get("secondary_serialization") or {}).get("decision") == "added_outer_brackets"]
        self.assertTrue(changed)
        for row in changed:
            self.assertFalse(row["score"]["correct"])
            self.assertTrue(row["score"]["secondary_serialization_correct"])
            self.assertEqual(row["restoration_status"], "blocked")
            self.assertEqual(row["secondary_serialization"]["restoration_status"], "ok")
            self.assertEqual(row["answer_calls"], 1)
        self.assertEqual(report["answer_generations"], 44)

    def test_joint_metric_cannot_credit_correct_answer_with_a_masking_gap(self):
        _, gold = fixture()
        label = gold["authored-fixture"]
        row = {"task_id": "status", "actor_id": "owner", "final_answer": "approved", "mode": "migration",
               "prepare_status": "ok", "build_status": "ok", "masking": {"ready": True, "partial": 1, "unmasked": 0}}
        scored = benchmark.score(row, label)
        self.assertTrue(scored["correct"])
        self.assertFalse(scored["joint_correct_no_masking_gap"])
        row["masking"].update(partial=0, unmasked=1)
        self.assertFalse(benchmark.score(row, label)["joint_correct_no_masking_gap"])
        row["masking"].update(unmasked=0)
        self.assertTrue(benchmark.score(row, label)["joint_correct_no_masking_gap"])
        row["masking"].pop("ready")
        self.assertFalse(benchmark.score(row, label)["joint_correct_no_masking_gap"])

    def test_poisoned_scores_do_not_enter_models_or_canonicalization(self):
        report, rows, _, _, _, _, _, _, _, _ = self.run_fixture(poisoned_answers=True)
        self.assertEqual(len(rows), 55)
        self.assertTrue(all(metrics["correct"] == 0 for metrics in report["arms"].values()))
        self.assertTrue(all(metrics["secondary_serialization_correct"] in (None, 0) for metrics in report["arms"].values()))


if __name__ == "__main__":
    unittest.main()
