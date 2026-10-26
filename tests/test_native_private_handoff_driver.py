"""Existing privacy/broker code is real; only the native process is a fake."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("private_handoff_driver", ROOT / "scripts/run_native_private_handoff.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class PrivateHandoffDriverTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "results").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="private_driver_fake_", dir=ROOT / "results")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base / "qoder_private_target"
        self.workspace.mkdir()
        (self.workspace / ".git").mkdir()
        self.case = {"client": "qoder", "sender": "harness", "recipient": "qoder",
                     "workspace": self.workspace.name, "record_id": "customer",
                     "value": "SYNTHETIC-CUSTOMER-123456ABCDEF", "source_only": "SOURCE-ONLY-7391"}
        self.calls = []

    def native(self, client, workspace, question, runtime_home):
        content = (workspace / "AGENTS.md").read_text(encoding="utf-8")
        self.calls.append((client, content, question))
        self.assertNotIn(self.case["value"], content + question)
        self.assertNotIn(self.case["source_only"], content + question)
        return {"status": "ok", "answer": content, "raw_response": content, "invocation_started": True}

    def run_case(self, native=None):
        return driver.one_case(self.case, self.workspace, self.base / "runtime", native or self.native)

    def test_actual_gate_roundtrip_and_consume_once_with_only_one_fake_call(self):
        row = self.run_case()
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(row["joint_success"])
        self.assertTrue(row["restored_correct"])
        self.assertEqual(len(row["negative_controls"]), 3)
        self.assertTrue(all(c["passed"] for c in row["negative_controls"]))
        self.assertFalse(row["full_cloud_request_content_inspected"])
        serialized = json.dumps(row)
        self.assertNotIn(self.case["value"], serialized)
        self.assertNotIn("_mapping", serialized)

    def test_refusal_containing_secret_is_failure_and_is_not_restored(self):
        def refusal(*args):
            self.native(*args)
            answer = "Refused but " + self.case["value"]
            return {"status": "ok", "answer": answer, "raw_response": answer}
        row = self.run_case(refusal)
        self.assertFalse(row["joint_success"])
        self.assertEqual(row["restoration_status"], "blocked")
        self.assertTrue(row["native_response_registration_check"]["registered_value_present"])
        self.assertIsNone(row["restored_answer_sha256"])

    def test_unknown_and_transport_failure_remain_in_denominator(self):
        for status in ("ok", "error"):
            with self.subTest(status=status):
                memory = self.workspace / "AGENTS.md"
                if memory.exists():
                    memory.unlink()
                def unknown(*args):
                    self.native(*args)
                    return {"status": status, "answer": "UNKNOWN", "raw_response": "UNKNOWN"}
                row = self.run_case(unknown)
                self.assertEqual(row["client_attempts"], 1)
                self.assertFalse(row["joint_success"])
                self.assertFalse(row["restored_correct"])

    def test_revoked_before_client_control_is_independent_of_positive_broker(self):
        row = self.run_case()
        denied = next(c for c in row["negative_controls"] if c["name"] == "revoked_before_client")
        self.assertEqual(denied["error"], "broker_record_revoked")
        self.assertTrue(row["restored_correct"])

    def test_second_execute_stops_before_any_client(self):
        out = self.base / "study"
        out.mkdir()
        plan = {"output": out.relative_to(ROOT).as_posix(), "cases": []}
        (out / "execution_started.json").write_text("{}", encoding="utf-8")
        with patch.object(driver, "approved", return_value=plan), patch.object(driver, "invoke") as invoke:
            with self.assertRaises(FileExistsError):
                driver.execute(out / "plan.json")
            invoke.assert_not_called()

    def test_approved_plan_does_not_allow_extra_client_or_workspace_escape(self):
        for change in ("budget", "workspace"):
            with self.subTest(change=change):
                out = self.base / ("plan_" + change)
                plan = driver.plan_only(out)
                if change == "budget":
                    plan["max_native_client_attempts"] = 3
                else:
                    plan["cases"][0]["workspace"] = "../other-workspace"
                (out / "plan.json").write_bytes(driver.encoded(plan))
                with self.assertRaisesRegex(ValueError, "plan_budget_invalid|fixture_contract_changed"):
                    driver.approved(out / "plan.json")


if __name__ == "__main__":
    unittest.main()
