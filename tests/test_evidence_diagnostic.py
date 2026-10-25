import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.run_evidence_answer_diagnostic import run


class EvidenceDiagnosticTests(unittest.TestCase):
    def test_all_tasks_repetitions_and_failure_denominators_remain(self):
        class FakeAnswerer:
            def identity(self):
                return {"test_only": True}

            def __call__(self, payload, *, mode, candidates):
                answer = '{"answer_id":"UNKNOWN"}' if mode == "evidence_id" else "UNKNOWN"
                return {"status": "ok", "answer": answer, "local_calls": 0, "error": None}

        with tempfile.TemporaryDirectory() as directory, patch(
            "scripts.run_evidence_answer_diagnostic.LocalEvidenceFactAnswerer", return_value=FakeAnswerer()
        ), patch("scripts.run_evidence_answer_diagnostic.LocalSensitivityAgent.health", return_value={"test_only": True}):
            output = Path(directory)/"test_only"
            report = run("results/native_llm_contexts_20261022/contexts_llm.json",
                         "results/deepseek_llm_20261022/run/evaluation_frozen.json",
                         "results/privacy_agent_20261023/sensitivity_audit.json",
                         "examples/study_demo/privacy_policy.registry.example.json", output, {})
            self.assertEqual(report["local_answer_generations"], 0)
            rows = json.loads((output/"rows.json").read_text(encoding="utf-8"))
            self.assertEqual(len(rows), 42)
            for group in report["groups"].values():
                self.assertEqual(group["registered"], 14)
                self.assertEqual(group["legal"], 8)
                self.assertEqual(group["denied"], 6)
                self.assertEqual(group["legal_correct"], 0)
                self.assertEqual(group["denied_correct"], 6)
                self.assertEqual(group["not_run"], 0)
                self.assertEqual(group["input_exposure_requests"], 0)
            self.assertIn("not_established", report["overall_acceptance"])


if __name__ == "__main__":
    unittest.main()
