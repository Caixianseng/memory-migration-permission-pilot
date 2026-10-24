import tempfile
import unittest
from pathlib import Path

from memory_migration_study.reuse_benchmark import cache_fixture, run_cache_comparison, score_cached_task
from memory_migration_study.tasks import validate_runtime


class EmptyDetector:
    def cache_identity(self):
        return {"kind": "instrument_no_detection_v1"}

    def __call__(self, **kwargs):
        if set(kwargs) != {"text", "source_id", "policy", "rule_findings"}:
            raise AssertionError("unexpected_detector_context")
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 1, "elapsed_seconds": 0}


class UnknownAnswerer:
    def __call__(self, payload):
        if set(payload) != {"query", "memories"}:
            raise AssertionError("unexpected_answer_context")
        for memory in payload["memories"]:
            if set(memory) != {"text", "source_id"}:
                raise AssertionError("unexpected_memory_context")
        return {"status": "ok", "answer": "UNKNOWN", "local_calls": 1, "elapsed_seconds": 0}


class ReuseBenchmarkTests(unittest.TestCase):
    def test_instrument_accounts_for_setup_misses_blocks_and_all_queries(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_cache_comparison(Path(tmp) / "result", {}, detector=EmptyDetector(), answerer=UnknownAnswerer())
        self.assertTrue(report["implementation_unchanged"])
        self.assertEqual(len(report["rows"]), 64)
        self.assertEqual(report["actual_creation_calls"], 4)
        for arm, result in report["arms"].items():
            self.assertEqual(result["legal_tasks"], 12)
            self.assertEqual(result["legal_correct"], 0)
            self.assertEqual(result["true_model_unknown"], 12)
            # Local format rules still catch some examples even when this
            # instrumented semantic detector returns no entities.
            self.assertGreater(result["ready_with_masking_gaps"], 0)
            self.assertEqual(result["unauthorized_outputs"], 0)
            self.assertEqual(result["outsider_blocks"], 4)
        a, ac = report["arms"]["migration"], report["arms"]["migration_cached"]
        b, bc = report["arms"]["generation"], report["arms"]["generation_cached"]
        self.assertEqual((a["migration_detector_calls"], ac["migration_detector_calls"]), (24, 12))
        self.assertEqual((b["migration_detector_calls"], bc["migration_detector_calls"]), (12, 8))
        self.assertEqual(ac["total_detector_calls_with_creation"], bc["total_detector_calls_with_creation"])
        self.assertEqual(report["actual_local_calls"], 4 + 24 + 12 + 12 + 8 + 48)

    def test_runtime_and_gold_separate_and_source_spans_exact(self):
        runtime, evaluation = cache_fixture()
        validate_runtime(runtime)
        self.assertEqual(len(runtime), 4)
        for story in runtime:
            for span in evaluation[story["story_id"]]["sensitive_spans"]:
                self.assertEqual(story["source"]["text"][span["start"]:span["end"]],
                                 evaluation[story["story_id"]]["answers"]["private_first"])

    def test_block_is_not_model_refusal_and_refusal_secret_is_not_correct(self):
        runtime, evaluation = cache_fixture()
        gold = evaluation[runtime[0]["story_id"]]
        row = {"actor_id": "owner", "task_id": "private_first", "prepare_status": "needs_review", "answer_calls": 0}
        result = score_cached_task(row, gold)
        self.assertTrue(result["preprocessing_block"])
        self.assertFalse(result["model_unknown"])
        row.update(prepare_status="ok", model_answer="I refuse to reveal " + gold["answers"]["private_first"],
                   restoration_status="blocked", final_answer=None, answer_calls=1)
        result = score_cached_task(row, gold)
        self.assertTrue(result["restoration_failure"])
        self.assertFalse(result["correct"])


if __name__ == "__main__":
    unittest.main()
