"""No model imports; host/worker boundary and fail-closed scoring checks."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nli_diagnostic_driver_test", ROOT / "scripts/run_nli_candidate_diagnostic.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class NLICandidateDriverTests(unittest.TestCase):
    def test_runtime_inputs_reject_even_unused_answer_metadata(self):
        rows = [{"case_id": str(i), "payload": {}, "policy": {}, "pool": {}} for i in range(120)]
        driver.validate_inputs(rows)
        rows[0]["expected_answer"] = "never pass to ML child"
        with self.assertRaisesRegex(ValueError, "runtime_input_extra_fields"):
            driver.validate_inputs(rows)

    def test_duplicate_cases_do_not_replace_failed_materials(self):
        rows = [{"case_id": "same", "payload": {}, "policy": {}, "pool": {}} for _ in range(120)]
        with self.assertRaisesRegex(ValueError, "runtime_input_count_invalid"):
            driver.validate_inputs(rows)

    def test_scoring_refuses_unclosed_predictions_before_reading_gold(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "results", prefix="nli_driver_fake_") as folder:
            out = Path(folder)
            (out / "model_phase_closed.json").write_text(json.dumps({"closed": False}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "predictions_not_closed"):
                driver.score_closed(out, {}, {})

    def test_second_execution_stops_before_child_launch(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "results", prefix="nli_driver_fake_") as folder:
            out = Path(folder)
            (out / "plan.json").write_text("{}", encoding="utf-8")
            (out / "execution_started.json").write_text("{}", encoding="utf-8")
            plan = {"output": out.relative_to(ROOT).as_posix()}
            with patch.object(driver, "approved", return_value=plan), patch.object(driver, "launch_phase") as launch:
                with self.assertRaises(FileExistsError):
                    driver.execute(out / "plan.json")
                launch.assert_not_called()

    def test_inherited_guard_denies_gold_and_reference_archive(self):
        q = driver.qualifier()
        q.build_plan(ROOT / "results/nli_guard_fake_unused")
        with tempfile.TemporaryDirectory(dir=ROOT / "results", prefix="nli_driver_fake_") as folder:
            out = Path(folder)
            guard = q.WorkerGuard(q.load_common(), out / "worker_job.json", out)
            for target in (out.parent / "heldout/evaluation.json", ROOT / "benchmarks/artifacts/context_candidate_detection_20261026_v2.zip"):
                with self.subTest(target=target), self.assertRaises(PermissionError):
                    guard("open", (str(target), "rb", 0))
            self.assertEqual(guard.accounting()["blocked_attempts"], 2)


if __name__ == "__main__":
    unittest.main()
