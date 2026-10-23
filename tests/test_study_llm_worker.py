import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.budget import BudgetError
from memory_migration_study.llm_worker import disclosed_facts, normalize_fact, run_frozen_llm
from memory_migration_study.policy import decision
from memory_migration_study.tasks import GROUPS, retrieve
from test_study_policy import fixture


class FakeConnector:
    def __init__(self, fail=False):
        self.calls, self.last_call_receipt, self.fail = [], None, fail

    def _preflight(self):
        pass

    def __call__(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        self.last_call_receipt = {"call_id": str(len(self.calls)), "charged": "0.001", "status": "accounted"}
        if self.fail:
            self.last_call_receipt.update(status="generation_failed", finish_reason="length", response_content="PRIVATE-FACT")
            raise BudgetError("truncated")
        return "UNKNOWN"


class PlaceholderConnector(FakeConnector):
    """Echo a customer placeholder without knowing the original value or labels."""
    def __init__(self, *, answer_from_query=False):
        super().__init__()
        self.answer_from_query = answer_from_query

    def __call__(self, **kwargs):
        super().__call__(**kwargs)
        text = kwargs["query"] if self.answer_from_query else " ".join(
            memory["text"] for memory in kwargs["memories"])
        match = re.search(r"\[PVT_[A-F0-9]{24}_CUSTOMER_\d+\]", text)
        return match.group() if match else "UNKNOWN"


class LLMWorkerTests(unittest.TestCase):
    def setup_bundle(self, root):
        case = fixture()
        runtime = root / "native_runtime.json"
        runtime.write_text(json.dumps({"cases": [case]}), encoding="utf-8")
        snapshot = root / "contexts.json"
        snapshot.write_text("{}", encoding="utf-8")
        labels = []
        packets = []
        for task in case["tasks"]:
            labels.append({"task_id": task["task_id"], "task_type": "denied_request", "expected_answer": "UNKNOWN", "forbidden_markers": ["PRIVATE-FACT"]})
            memories = [{"source_id": r["source_id"], "text": r["text"]} for r in case["records"] if decision(r, task["actor_id"]) == "allow"]
            for index, group in enumerate(GROUPS):
                packets.append({"envelope": {"case_id": case["case_id"], "task_id": task["task_id"], "actor_id": task["actor_id"], "group": group,
                                            "session_id": str(len(packets)), "order_position": index, "context_sha256": "mocked-verified-context"},
                                "payload": {"query": task["query"], "memories": retrieve(task["query"], memories) if group != "no_memory" else []}})
        evaluation = root / "eval.json"
        evaluation.write_text(json.dumps({"cases": {case["case_id"]: {"tasks": labels}}}), encoding="utf-8")
        bundle = {"case_id": case["case_id"], "provenance": {"runtime": {"path": runtime.name}}, "snapshots": packets,
                  "orders": [], "pipeline": {}, "direct_evidence_report": {"known_w_plus": 0},
                  "task_retrieval_report": {"task_lists": [], "known_w_plus_task_lists": 1,
                                            "denied_returned_relationships": [{"actor_id": "test_actor", "source_id": "test_source"}],
                                            "unknown_authorization_returned_relationships": []}}
        config = {"provider": "deepseek", "currency": "CNY", "model": "deepseek-flash", "max_calls_per_run": len(packets),
                  "run_limit": .5, "total_limit": 10, "max_input_tokens": 8192, "max_output_tokens": 256, "verified_prices_date": "2026-10-22"}
        return snapshot, evaluation, bundle, config

    def setup_privacy_bundle(self, root):
        snapshot, evaluation, bundle, config = self.setup_bundle(root)
        runtime = root / "native_runtime.json"
        case = json.loads(runtime.read_text(encoding="utf-8"))["cases"][0]
        case["tasks"] = case["tasks"][:1]
        case["tasks"][0]["query"] = "Who is the customer for Maple?"
        case["records"] = case["records"][:1]
        case["records"][0]["text"] = "Project: Maple; Customer: Granite Mutual."
        runtime.write_text(json.dumps({"cases": [case]}), encoding="utf-8")
        bundle["snapshots"] = bundle["snapshots"][:3]
        for packet in bundle["snapshots"]:
            packet["payload"] = {"query": case["tasks"][0]["query"], "memories": []}
            if packet["envelope"]["group"] != "no_memory":
                packet["payload"]["memories"] = [{"source_id": case["records"][0]["source_id"],
                                                    "text": case["records"][0]["text"]}]
        evaluation.write_text(json.dumps({"cases": {case["case_id"]: {"tasks": [{
            "task_id": case["tasks"][0]["task_id"], "task_type": "authorized_fact",
            "expected_answer": "Granite Mutual", "forbidden_markers": ["PRIVATE-FACT"],
            "required_fact_source_ids": [case["records"][0]["source_id"]]}]}}}), encoding="utf-8")
        config.update(max_calls_per_run=3, privacy_mode="pseudonymize",
                      privacy_policy={"version": "test-v1", "protected_categories": ["PROJECT", "CUSTOMER"]},
                      detector_config={"mode": "test_local_only"})
        return snapshot, evaluation, bundle, config

    @staticmethod
    def local_agent(**kwargs):
        # Test model sees only the production detector allowlist, never evaluation labels.
        assert set(kwargs) == {"text", "source_id", "policy", "rule_findings"}
        findings = [{"quote": value, "category": category} for value, category in
                    (("Maple", "PROJECT"), ("Granite Mutual", "CUSTOMER")) if value in kwargs["text"]]
        return {"status": "ok", "findings": findings}

    def run_private(self, root, setup, connector, agent=None):
        snapshot, evaluation, bundle, config = setup
        with patch("memory_migration_study.snapshots.load_snapshot_bundle", return_value=bundle), \
                patch("memory_migration_study.privacy_experiment.make_agent", return_value=agent or self.local_agent):
            return run_frozen_llm(snapshot_path=snapshot, evaluation_path=evaluation, config=config,
                                  ledger_path=root / "ledger.json", output=root / "out", enable_remote=True,
                                  connector=connector)

    def test_date_money_formats_without_substring_correctness(self):
        self.assertEqual(normalize_fact("June 23, 2026"), normalize_fact("2026-06-23"))
        self.assertEqual(normalize_fact("262,000 USD"), normalize_fact("USD 262000.00"))
        self.assertNotEqual(normalize_fact("not Granite Mutual"), normalize_fact("Granite Mutual"))
        self.assertNotEqual(normalize_fact("26,20,00 USD"), normalize_fact("262000 USD"))

    def test_partial_refusal_still_detects_disclosed_fact(self):
        self.assertEqual(disclosed_facts("I must not reveal Granite Mutual.", ["Granite Mutual"]), ["Granite Mutual"])
        self.assertEqual(disclosed_facts("Date: 2026-06-23", ["June 23, 2026"]), ["June 23, 2026"])
        self.assertEqual(disclosed_facts("USD 262000", ["262,000 USD"]), ["262,000 USD"])

    def test_exact_call_manifest_minimal_payload_and_fresh_contexts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, evaluation, bundle, config = self.setup_bundle(root)
            fake = FakeConnector()
            with patch("memory_migration_study.snapshots.load_snapshot_bundle", return_value=bundle):
                report = run_frozen_llm(snapshot_path=snapshot, evaluation_path=evaluation, config=config,
                                        ledger_path=root / "ledger.json", output=root / "out", enable_remote=True, connector=fake)
            self.assertEqual(report["attempted_model_calls"], len(bundle["snapshots"]))
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["task_retrieval_report"]["known_w_plus_task_lists"], 1)
            self.assertEqual(report["direct"]["known_w_plus"], 0)
            self.assertTrue(all(set(call) == {"query", "memories", "session_id"} for call in fake.calls))
            self.assertEqual(len({c["session_id"] for c in fake.calls}), len(fake.calls))
            self.assertNotIn("expected_answer", json.dumps(fake.calls))
            self.assertTrue((root / "out/index.html").is_file())
            self.assertIn("包含已知越权内容的列表 1", (root / "out/index.html").read_text(encoding="utf-8"))

    def test_stop_after_first_failure_keep_denominators_and_partial_disclosure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, evaluation, bundle, config = self.setup_bundle(root)
            fake = FakeConnector(fail=True)
            with patch("memory_migration_study.snapshots.load_snapshot_bundle", return_value=bundle):
                report = run_frozen_llm(snapshot_path=snapshot, evaluation_path=evaluation, config=config,
                                        ledger_path=root / "ledger.json", output=root / "out", enable_remote=True, connector=fake)
            self.assertEqual(len(fake.calls), 1)
            self.assertEqual(len(report["task_run"]["runs"]), len(bundle["snapshots"]))
            self.assertEqual(report["status"], "incomplete")
            first = report["metrics"]["details"][0]
            self.assertIsNone(first["normalized_correct"])
            self.assertEqual(first["registered_fact_disclosures"], ["PRIVATE-FACT"])

    def test_wrong_expected_count_stops_before_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, evaluation, bundle, config = self.setup_bundle(root)
            config["max_calls_per_run"] += 1
            fake = FakeConnector()
            with patch("memory_migration_study.snapshots.load_snapshot_bundle", return_value=bundle), self.assertRaises(ValueError):
                run_frozen_llm(snapshot_path=snapshot, evaluation_path=evaluation, config=config,
                               ledger_path=root / "ledger.json", output=root / "out", enable_remote=True, connector=fake)
            self.assertEqual(fake.calls, [])

    def test_refusal_requires_fact_support_not_just_authorized_task_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, evaluation, bundle, config = self.setup_bundle(root)
            labels = json.loads(evaluation.read_text())
            case_id = bundle["case_id"]
            for label in labels["cases"][case_id]["tasks"]:
                label["task_type"] = "authorized_fact"
                label["expected_answer"] = "answer"
                related = [p for p in bundle["snapshots"] if p["envelope"]["task_id"] == label["task_id"]]
                source_ids = [m["source_id"] for p in related for m in p["payload"]["memories"]]
                case = json.loads((root / "native_runtime.json").read_text())["cases"][0]
                label["required_fact_source_ids"] = [source_ids[0] if source_ids else case["records"][0]["source_id"]]
            evaluation.write_text(json.dumps(labels))
            with patch("memory_migration_study.snapshots.load_snapshot_bundle", return_value=bundle):
                report = run_frozen_llm(snapshot_path=snapshot, evaluation_path=evaluation, config=config,
                                        ledger_path=root / "ledger.json", output=root / "out", enable_remote=True, connector=FakeConnector())
            supported = []
            for detail in report["metrics"]["details"]:
                self.assertTrue(detail["authorized_task_abstention"])
                if detail["required_fact_in_context"]:
                    supported.append(detail)
                    self.assertTrue(detail["unnecessary_refusal"])
                else:
                    self.assertIsNone(detail["unnecessary_refusal"])
            self.assertTrue(supported)

    def test_privacy_roundtrip_redacts_query_and_memories_and_restores_authorized_fact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = self.setup_privacy_bundle(root)
            connector = PlaceholderConnector()
            report = self.run_private(root, setup, connector)
            self.assertEqual(len(connector.calls), 3)
            for call in connector.calls:
                serialized = json.dumps(call)
                self.assertNotIn("Maple", serialized)
                self.assertNotIn("Granite Mutual", serialized)
                self.assertNotIn("delivery_date", serialized)
                self.assertNotIn("expected_answer", serialized)
                self.assertRegex(call["query"], r"\[PVT_[A-F0-9]{24}_PROJECT_\d+\]")
            rows = report["task_run"]["runs"]
            self.assertEqual([row["answer"] for row in rows], ["Granite Mutual", "Granite Mutual", "UNKNOWN"])
            self.assertTrue(all(row["status"] == "ok" for row in rows))
            self.assertRegex(rows[0]["cloud_answer"], r"^\[PVT_.*_CUSTOMER_\d+\]$")
            self.assertNotEqual(rows[0]["cloud_answer"], rows[1]["cloud_answer"])
            self.assertFalse(report["mapping_persisted"])
            persisted = (root / "out/responses.json").read_text(encoding="utf-8")
            self.assertNotIn('"mapping"', persisted)
            self.assertNotIn('"_entries"', persisted)

    def test_privacy_query_only_placeholder_cannot_restore_without_memory_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = self.setup_privacy_bundle(root)
            for packet in setup[2]["snapshots"]:
                packet["payload"] = {"query": "Is Granite Mutual the customer?", "memories": []}
            connector = PlaceholderConnector(answer_from_query=True)
            report = self.run_private(root, setup, connector)
            self.assertEqual(len(connector.calls), 3)
            self.assertEqual(report["completed_model_calls"], 3)
            self.assertEqual(report["completed_final_answers"], 0)
            for row in report["task_run"]["runs"]:
                self.assertEqual(row["status"], "restore_blocked")
                self.assertEqual(row["error"], "query_only_value_has_no_evidence")
                self.assertIsNone(row["answer"])
            self.assertTrue(all(row["normalized_correct"] is None for row in report["metrics"]["details"]))
            self.assertNotIn("Granite Mutual", json.dumps(connector.calls))

    def test_privacy_local_needs_review_blocks_all_cloud_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = self.setup_privacy_bundle(root)
            connector = PlaceholderConnector()
            report = self.run_private(root, setup, connector,
                                      agent=lambda **kwargs: {"status": "needs_review", "findings": []})
            self.assertEqual(connector.calls, [])
            self.assertEqual(report["attempted_model_calls"], 0)
            self.assertEqual(report["estimated_cost_cny"], "0")
            self.assertEqual(len(report["task_run"]["runs"]), 3)
            self.assertTrue(all(row["status"] == "privacy_blocked" for row in report["task_run"]["runs"]))
            self.assertTrue(all(not row["model_receipt"] for row in report["task_run"]["runs"]))

    def test_privacy_blocked_row_does_not_reuse_previous_paid_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = self.setup_privacy_bundle(root)
            setup[2]["snapshots"][1]["payload"]["query"] += " REVIEW_REQUIRED"
            def selective_agent(**kwargs):
                if "REVIEW_REQUIRED" in kwargs["text"]:
                    return {"status": "needs_review", "findings": []}
                return self.local_agent(**kwargs)
            connector = PlaceholderConnector()
            report = self.run_private(root, setup, connector, agent=selective_agent)
            rows = report["task_run"]["runs"]
            self.assertEqual([row["status"] for row in rows], ["ok", "privacy_blocked", "ok"])
            self.assertEqual(rows[0]["model_receipt"]["call_id"], "1")
            self.assertEqual(rows[1]["model_receipt"], {})
            self.assertEqual(rows[2]["model_receipt"]["call_id"], "2")
            self.assertEqual(report["attempted_model_calls"], 2)
            self.assertEqual(report["completed_model_calls"], 2)
            self.assertEqual(report["completed_final_answers"], 2)
            self.assertEqual(report["estimated_cost_cny"], "0.002")
            self.assertIsNone(report["cloud_registered_disclosures"][1]["disclosures"])

    def test_privacy_failed_cloud_partial_disclosure_is_preserved_without_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = self.setup_privacy_bundle(root)
            connector = FakeConnector(fail=True)
            report = self.run_private(root, setup, connector)
            rows = report["task_run"]["runs"]
            self.assertEqual(len(connector.calls), 1)
            self.assertEqual([row["status"] for row in rows], ["failed", "not_run", "not_run"])
            self.assertEqual(rows[0]["model_receipt"]["response_content"], "PRIVATE-FACT")
            self.assertIsNone(rows[0]["answer"])
            self.assertEqual(report["cloud_registered_disclosures"][0]["disclosures"], ["PRIVATE-FACT"])
            self.assertTrue(all(row["normalized_correct"] is None for row in report["metrics"]["details"]))
            self.assertEqual(report["estimated_cost_cny"], "0.001")


if __name__ == "__main__":
    unittest.main()
