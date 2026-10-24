import tempfile
import unittest
from pathlib import Path

from memory_migration_study.ner_benchmark import ARMS, aggregate, corpus, run
from memory_migration_study.tasks import validate_runtime


class EmptyRuntime:
    identity = {"weights_sha256": "0" * 64, "kind": "instrument"}
    initialization_seconds = 0
    def infer(self, text, labels, *, splitter, threshold):
        return {"entities": {label: [] for label in labels}}


class EmptyBaseline:
    def cache_identity(self):
        return {"version": "instrument"}

    def __call__(self, **kwargs):
        if set(kwargs) != {"text", "source_id", "policy", "rule_findings"}:
            raise AssertionError("unexpected_detector_input")
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 1, "elapsed_seconds": 0}


class UnknownAnswerer:
    def __call__(self, payload):
        if set(payload) != {"query", "memories"}:
            raise AssertionError("unexpected_answer_input")
        return {"status": "ok", "answer": "UNKNOWN", "local_calls": 1}


class NerBenchmarkTests(unittest.TestCase):
    def test_runtime_gold_separation_exact_spans_and_sensitive_query_control(self):
        runtime, evaluation = corpus()
        validate_runtime(runtime)
        self.assertEqual(len(runtime), 8)
        self.assertEqual(sum(r["language"] == "zh" for r in runtime), 4)
        for story in runtime:
            gold = evaluation[story["story_id"]]
            span = gold["sensitive_spans"][0]
            value = story["source"]["text"][span["start"]:span["end"]]
            self.assertEqual(value, gold["answers"]["private"])
            self.assertIn(value, story["tasks"][2]["query"])

    def test_instrument_keeps_failures_and_full_denominators(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run(Path(tmp) / "result", None, {}, runtime_model=EmptyRuntime(),
                         baseline=EmptyBaseline(), answerer=UnknownAnswerer())
        self.assertEqual(len(report["rows"]), 128)
        self.assertTrue(report["implementation_unchanged"])
        self.assertEqual(report["arms"], aggregate(report["rows"]))
        self.assertEqual(report["qwen_detector_generations"], 48)
        self.assertEqual(report["encoder_invocations"], 144)
        self.assertEqual(report["answer_generations"], 96)
        for arm in ARMS:
            metrics = report["arms"][arm]
            self.assertEqual(metrics["legal_tasks"], 24)
            self.assertEqual(metrics["correct"], 0)
            self.assertEqual(metrics["true_model_unknown"], 24)
            self.assertEqual(metrics["outsider_blocks"], 8)
            self.assertEqual(metrics["unauthorized_outputs"], 0)
            self.assertGreater(metrics["ready_with_memory_gaps"], 0)
            self.assertGreater(metrics["ready_with_query_gaps"], 0)


if __name__ == "__main__":
    unittest.main()
