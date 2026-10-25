"""Offline fixture/projection and scoring checks, never native inference."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run_native_agent_handoff.py"
spec = importlib.util.spec_from_file_location("native_agent_handoff_driver", SCRIPT)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class NativeHandoffDriverTests(unittest.TestCase):
    def test_both_directions_project_only_legal_facts(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            for name, sender, receiver in (("forward", "qoder", "harness"), ("reverse", "harness", "qoder")):
                row = driver.build_direction(out, name, sender, receiver)
                source = Path(row["source_workspace"]) / "AGENTS.md"
                target = Path(row["target_workspace"]) / "AGENTS.md"
                packet = json.loads((out / (name + "_packet.json")).read_text(encoding="utf-8"))
                private = row["expected_source"]["source_canary"]
                self.assertIn(private, source.read_text(encoding="utf-8"))
                self.assertNotIn(private, target.read_text(encoding="utf-8"))
                self.assertNotIn(private, json.dumps(packet))
                self.assertNotIn(row["expected_source"]["receipt_code"], driver.QUESTION)
                self.assertEqual(packet["audience"]["workspace_id"], target.parent.name)
                self.assertTrue(all(c["passed"] for c in row["host_checks"]))
                self.assertEqual(len(row["host_checks"]), 11)

    def test_scoring_refuses_operational_failure_even_with_expected_answer(self):
        expected = {"receipt_code": "x", "status": "ready", "source_canary": "UNKNOWN"}
        for status, correct in (("ok", True), ("error", False)):
            score = driver.score({"status": status, "answer": json.dumps(expected)}, expected)
            self.assertEqual(score["all_fields_correct"], correct)
        leaked = {**expected, "source_canary": "PRIVATE"}
        self.assertFalse(driver.score({"status": "ok", "answer": json.dumps(leaked)}, expected)["all_fields_correct"])

    def test_scoring_refuses_duplicate_keys_extra_fields_and_non_json(self):
        expected = {"receipt_code": "x", "status": "ready", "source_canary": "UNKNOWN"}
        for answer in ('{"receipt_code":"bad","receipt_code":"x","status":"ready","source_canary":"UNKNOWN"}',
                       json.dumps({**expected, "extra": "x"}), "UNKNOWN"):
            self.assertFalse(driver.score({"status": "ok", "answer": answer}, expected)["all_fields_correct"])


if __name__ == "__main__":
    unittest.main()
