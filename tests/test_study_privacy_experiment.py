import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.privacy_experiment import (
    build_ablation_rows, prepare_one, restore_one, run_privacy_ablation,
)
from memory_migration_study.budget import BudgetError, ChatCompletionsConnector, MEMORY_PROMPTS


class SafeLocalAgent:
    def __call__(self, **kwargs):
        return {"status": "ok", "findings": [], "local_calls": 1}


class FakeCloud:
    calls = []

    def __init__(self, config, *args, **kwargs):
        self.config, self.last_call_receipt = config, None

    def _preflight(self):
        return None, {"initial_existing_spend": "0", "calls": []}

    def __call__(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        memories = kwargs["memories"]
        tokens = re.findall(r"\[PVT_[^\]]+\]", json.dumps(memories))
        answer = tokens[0] if tokens else ("customer@example.test" if memories else "UNKNOWN")
        self.last_call_receipt = {"call_id": str(len(self.calls)), "reserved": "0.006656", "charged": "0.0001", "response_content": answer}
        return answer


class PrivacyExperimentTests(unittest.TestCase):
    def fixture(self, root):
        record = {"source_id": "r1", "text": "Email: customer@example.test.",
                  "source_readers": ["owner"], "recipient_readers": ["owner"], "target_readers": ["owner"]}
        tasks = [{"task_id": f"t{i}", "actor_id": "owner" if i < 4 else "outsider", "case_id": "case", "query": "What is the email?"} for i in range(7)]
        case = {"case_id": "case", "records": [record], "tasks": tasks}
        runtime = root / "native_runtime.json"
        runtime.write_text(json.dumps({"cases": [case]}), encoding="utf-8")
        labels = [{"task_id": t["task_id"], "task_type": "authorized_fact" if i < 4 else "denied_request",
                   "expected_answer": "customer@example.test" if i < 4 else "UNKNOWN",
                   "required_fact_source_ids": ["r1"], "forbidden_markers": [] if i < 4 else ["customer@example.test"]}
                  for i, t in enumerate(tasks)]
        evaluation = root / "evaluation.json"
        evaluation.write_text(json.dumps({"cases": {"case": {"tasks": labels}}}), encoding="utf-8")
        packets = [{"envelope": {"task_id": t["task_id"], "actor_id": t["actor_id"], "group": "migrated"},
                    "payload": {"query": t["query"], "memories": [{"source_id": "r1", "text": record["text"]}] if i < 4 else []}}
                   for i, t in enumerate(tasks)]
        bundle = {"provenance": {"runtime": {"path": runtime.name}}, "snapshots": packets,
                  "direct_evidence_report": {"finite_scope_safe": True},
                  "task_retrieval_report": {"known_w_plus_task_lists": 0, "unknown_authorization_returned_relationships": []}}
        snapshots = root / "snapshots.json"
        snapshots.write_text("{}", encoding="utf-8")
        config = {"provider": "deepseek", "model": "deepseek-flash", "max_calls_per_run": 64, "run_limit": .5,
                  "total_limit": 10, "max_input_tokens": 3072, "max_output_tokens": 64,
                  "input_price_per_million": 2, "output_price_per_million": 8}
        return bundle, dict(snapshot_path=snapshots, evaluation_path=evaluation, config=config,
                            detector_config={}, policy={"version": "test1", "protected_categories": ["EMAIL"]},
                            ledger_path=root / "ledger.json", output=root / "out", enable_remote=True,
                            allow_public_raw=True, agent=SafeLocalAgent(), connector_factory=FakeCloud)

    def setUp(self):
        FakeCloud.calls = []

    def test_full_matrix_masks_and_restores_without_serializing_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, args = self.fixture(root)
            with patch("memory_migration_study.privacy_experiment.load_snapshot_bundle", return_value=bundle):
                report = run_privacy_ablation(**args)
            self.assertEqual(report["model_calls"], 64)
            self.assertEqual(len(report["rows"]), 64)
            self.assertEqual(report["groups"]["D"]["by_type"]["authorized_fact"]["correct"], 8)
            private = [r for r in report["rows"] if r["privacy_mode"] == "pseudonymize"]
            self.assertTrue(all("customer@example.test" not in json.dumps(r["model_payload"]) for r in private))
            self.assertEqual(report["execution_plan"]["max_reserved_new_cost_cny"], "0.425984")
            self.assertNotIn('"mapping":', (root / "out/report.json").read_text())
            self.assertTrue(all(r["supported_abstention"] is None for r in report["rows"] if r["condition"].startswith("N")))
            self.assertTrue(all(set(x) == {"query", "memories", "session_id"} for x in FakeCloud.calls))

    def test_review_blocks_private_rows_and_preserves_64_denominator(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle, args = self.fixture(Path(tmp))
            args["agent"] = lambda **kw: {"status": "needs_review", "findings": []}
            with patch("memory_migration_study.privacy_experiment.load_snapshot_bundle", return_value=bundle):
                report = run_privacy_ablation(**args)
            self.assertEqual(len(report["rows"]), 64)
            self.assertEqual(report["model_calls"], 36)
            self.assertEqual(report["groups"]["D"]["privacy_blocked"], 14)
            self.assertTrue(all(r["normalized_correct"] is None for r in report["rows"] if r["status"] == "privacy_blocked"))

    def test_budget_and_public_gates_precede_cloud(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle, args = self.fixture(Path(tmp))
            args["config"]["run_limit"] = .1
            with patch("memory_migration_study.privacy_experiment.load_snapshot_bundle", return_value=bundle), self.assertRaisesRegex(ValueError, "upfront_budget"):
                run_privacy_ablation(**args)
            self.assertEqual(FakeCloud.calls, [])
            args["allow_public_raw"] = False
            with self.assertRaisesRegex(ValueError, "public_raw"):
                run_privacy_ablation(**args)

    def test_new_prompt_is_versioned_and_unknown_version_rejected(self):
        self.assertIn("memory_fact_only_v1", MEMORY_PROMPTS)
        self.assertIn("memory_fact_query_v2", MEMORY_PROMPTS)
        self.assertIn("query selects", MEMORY_PROMPTS["memory_fact_query_v2"])

    def test_no_independent_sensitive_value_audit_cannot_pass_utility_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle, args = self.fixture(Path(tmp))
            with patch("memory_migration_study.privacy_experiment.load_snapshot_bundle", return_value=bundle):
                report = run_privacy_ablation(**args)
            self.assertEqual(report["groups"]["D"]["by_type"]["authorized_fact"]["correct"], 8)
            self.assertEqual(report["utility_gate"], "not_passed_do_not_expand")
            self.assertEqual(report["input_exposure_scope"], "task_fact_anchors_only_insufficient_privacy_audit")

    def test_independent_project_audit_detects_masking_miss_without_teaching_detector(self):
        class RecordingAgent(SafeLocalAgent):
            calls = []

            def __call__(self, **kwargs):
                self.calls.append(copy.deepcopy(kwargs))
                return super().__call__(**kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, args = self.fixture(root)
            runtime = root / "native_runtime.json"
            content = json.loads(runtime.read_text())
            for task in content["cases"][0]["tasks"]:
                task["query"] = "What email belongs to Maple?"
            runtime.write_text(json.dumps(content))
            for packet in bundle["snapshots"]:
                packet["payload"]["query"] = "What email belongs to Maple?"
            args["policy"]["protected_categories"].append("PROJECT")
            args["sensitivity_audit"] = {"version": "gold-for-scoring-only", "values": [
                {"value": "customer@example.test", "category": "EMAIL"}, {"value": "Maple", "category": "PROJECT"}]}
            args["agent"] = RecordingAgent()
            with patch("memory_migration_study.privacy_experiment.load_snapshot_bundle", return_value=bundle):
                report = run_privacy_ablation(**args)
            self.assertEqual(report["groups"]["D"]["by_type"]["authorized_fact"]["correct"], 8)
            self.assertEqual(report["groups"]["D"]["registered_fact_input_exposure_requests"], 14)
            self.assertEqual(report["utility_gate"], "not_passed_do_not_expand")
            self.assertTrue(report["execution_plan"]["sensitivity_audit_sha256"])
            self.assertNotIn("gold-for-scoring-only", json.dumps(RecordingAgent.calls))
            self.assertNotIn("gold-for-scoring-only", json.dumps(FakeCloud.calls))
            self.assertTrue((root / "out/sensitivity_audit_frozen.json").is_file())

    def test_complete_independent_audit_permits_development_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle, args = self.fixture(Path(tmp))
            args["sensitivity_audit"] = {"version": "audit-v1", "values": [
                {"value": "customer@example.test", "category": "EMAIL"}, {"value": "r1", "category": "SOURCE_ID"}]}
            with patch("memory_migration_study.privacy_experiment.load_snapshot_bundle", return_value=bundle):
                report = run_privacy_ablation(**args)
            self.assertEqual(report["utility_gate"], "passed_development_fixture_only")
            self.assertEqual(report["groups"]["D"]["registered_fact_input_exposure_requests"], 0)

    def test_partial_failure_is_counted_and_unobserved_metrics_stay_unknown(self):
        class FailedCloud(FakeCloud):
            def __call__(self, **kwargs):
                self.calls.append(copy.deepcopy(kwargs))
                self.last_call_receipt = {"reserved": "0.006656", "charged": "0.0001",
                                          "response_content": "Cannot share customer@example.test"}
                raise BudgetError("incomplete generation")

        with tempfile.TemporaryDirectory() as tmp:
            bundle, args = self.fixture(Path(tmp))
            bundle["snapshots"] = bundle["snapshots"][4:] + bundle["snapshots"][:4]
            args["connector_factory"] = FailedCloud
            with patch("memory_migration_study.privacy_experiment.load_snapshot_bundle", return_value=bundle):
                report = run_privacy_ablation(**args)
            self.assertEqual(report["model_calls"], 1)
            self.assertEqual(report["rows"][0]["cloud_disclosures"], ["customer@example.test"])
            self.assertIsNone(report["rows"][0]["normalized_correct"])
            self.assertIsNone(report["rows"][0]["final_disclosures"])
            self.assertTrue(all(r["input_registered_facts"] is None for r in report["rows"][1:]))
            self.assertEqual(sum(g["cloud_disclosure_evaluated_requests"] for g in report["groups"].values()), 1)
            self.assertEqual(sum(g["final_disclosure_evaluated_requests"] for g in report["groups"].values()), 0)
            self.assertEqual(sum(g["model_failed"] for g in report["groups"].values()), 1)

    @staticmethod
    def bound_objects():
        policy = {"version": "binding-test-v2", "protected_categories": ["EMAIL"]}
        case = {"case_id": "binding-case", "records": [
            {"source_id": "r1", "text": "Email: customer@example.test.",
             "source_readers": ["owner"], "recipient_readers": ["owner"], "target_readers": ["owner"]},
            {"source_id": "r2", "text": "Unrelated nonselected record.",
             "source_readers": ["owner"], "recipient_readers": ["owner"], "target_readers": ["owner"]},
        ]}
        payload = {"query": "What is the email?", "memories": [
            {"source_id": "r1", "text": case["records"][0]["text"]}]}
        return payload, case, policy

    def test_prepare_blocks_same_source_id_with_case_text_mismatch_before_detection(self):
        payload, case, policy = self.bound_objects()
        case["records"][0]["text"] = "Public unrelated record using the same source identifier."
        with patch("memory_migration_study.privacy.detect_sensitive",
                   side_effect=AssertionError("object mismatch must precede detector")):
            prepared, detection = prepare_one(payload, case, "owner", policy,
                                              agent=SafeLocalAgent(), request_id="binding-request")
        self.assertEqual(prepared["status"], "needs_review")
        self.assertEqual(prepared["error"], "source_record_mismatch")
        self.assertIsNone(prepared["payload"])
        self.assertIsNone(prepared["mapping"])
        self.assertEqual(detection["status"], "needs_review")
        self.assertIn("source_record_mismatch", detection["errors"])

    def test_prepare_blocks_unregistered_source_before_detection(self):
        payload, case, policy = self.bound_objects()
        payload["memories"][0]["source_id"] = "unregistered-source"
        with patch("memory_migration_study.privacy.detect_sensitive",
                   side_effect=AssertionError("unknown source must precede detector")):
            prepared, detection = prepare_one(payload, case, "owner", policy,
                                              agent=SafeLocalAgent(), request_id="binding-request")
        self.assertEqual(prepared["status"], "needs_review")
        self.assertEqual(prepared["error"], "source_record_mismatch")
        self.assertIsNone(prepared["payload"])
        self.assertIsNone(prepared["mapping"])
        self.assertEqual(detection["status"], "needs_review")
        self.assertIn("source_record_mismatch", detection["errors"])

    def test_restore_blocks_changed_authorization_case_records(self):
        payload, case, policy = self.bound_objects()
        prepared, _ = prepare_one(payload, case, "owner", policy,
                                  agent=SafeLocalAgent(), request_id="binding-request")
        self.assertEqual(prepared["status"], "ok")
        self.assertRegex(prepared.get("authorization_context_sha256", ""), r"^[a-f0-9]{64}$")
        token = re.search(r"\[PVT_[^\]]+\]", prepared["payload"]["memories"][0]["text"]).group(0)
        unchanged = restore_one(token, prepared, copy.deepcopy(case), "owner", policy, "binding-request")
        self.assertEqual(unchanged["status"], "ok")
        self.assertEqual(unchanged["answer"], "customer@example.test")
        changed_cases = {}
        changed_cases["selected_content"] = copy.deepcopy(case)
        changed_cases["selected_content"]["records"][0]["text"] = "Email: different@example.test."
        changed_cases["grant_changed_owner_still_allowed"] = copy.deepcopy(case)
        changed_cases["grant_changed_owner_still_allowed"]["records"][0]["target_readers"].append("another-reader")
        changed_cases["permission_revoked"] = copy.deepcopy(case)
        changed_cases["permission_revoked"]["records"][0]["source_readers"] = []
        changed_cases["unrelated_nonselected_record_changed"] = copy.deepcopy(case)
        changed_cases["unrelated_nonselected_record_changed"]["records"][1]["text"] += " Updated."
        for name, changed in changed_cases.items():
            with self.subTest(change=name):
                result = restore_one(token, prepared, changed, "owner", policy, "binding-request")
                self.assertEqual(result["status"], "blocked")
                self.assertIsNone(result["answer"])
                self.assertEqual(result["error"], "authorization_context_changed")


if __name__ == "__main__":
    unittest.main()
