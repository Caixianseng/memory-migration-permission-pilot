"""Saved-evidence tamper checks. All model/native inputs are synthetic/injected."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.evidence_answerer import LocalEvidenceFactAnswerer

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("evidence_diagnostic_verifier_tested", PROJECT / "scripts/verify_evidence_answer_diagnostic.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class EvidenceDiagnosticVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.run.mkdir()
        archive = self.run / "implementation"
        archive.mkdir()
        self.code = {}
        for name in verifier.CODE_NAMES:
            folder = "scripts" if name.startswith("run_") else "memory_migration_study"
            source, current = PROJECT / folder / name, self.root / folder / name
            current.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, current)
            shutil.copyfile(source, archive / name)
            self.code[str(current)] = verifier.sha(current.read_bytes())

        self.token = "[PVT_0123456789ABCDEF01234567_CUSTOMER_1]"
        policy = {"version": "synthetic-policy", "protected_categories": ["CUSTOMER"],
                  "entity_registry": [{"category": "CUSTOMER", "value": "Synthetic Private Company"}]}
        record = {"source_id": "source-one", "text": "Customer: Synthetic Private Company",
                  "source_readers": ["owner"], "recipient_readers": ["owner"], "target_readers": ["owner"]}
        case = {"case_id": "synthetic", "records": [record], "tasks": [
            {"task_id": "task" + str(i), "actor_id": "owner", "query": "Customer?" if i < 4 else "Missing fact?"}
            for i in range(7)]}
        packets = [{"envelope": {"group": "migrated", "task_id": task["task_id"], "actor_id": "owner"},
                    "payload": {"query": task["query"], "memories": [{"source_id": record["source_id"], "text": record["text"]}]}}
                   for task in case["tasks"]]
        self.bundle = {"snapshots": packets, "provenance": {"runtime": {"path": "native_runtime.json"}},
                       "direct_evidence_report": {"finite_scope_safe": True},
                       "task_retrieval_report": {"known_w_plus_task_lists": 0, "unknown_authorization_returned_relationships": []}}
        evaluation = {"tasks": [{"task_id": task["task_id"], "task_type": "authorized_fact" if i < 4 else "denied_request",
                                 "expected_answer": "Synthetic Private Company" if i < 4 else "UNKNOWN", "forbidden_markers": []}
                                for i, task in enumerate(case["tasks"])]}
        data = self.root / "inputs"
        input_values = {"contexts_llm.json": self.bundle, "native_runtime.json": {"cases": [case]},
                        "evaluation_frozen.json": evaluation, "privacy_policy.registry.example.json": policy,
                        "sensitivity_audit.json": {"values": [{"value": "Synthetic Private Company"}]}}
        self.inputs = {}
        for name, value in input_values.items():
            path = data / name
            save(path, value)
            self.inputs[str(path)] = verifier.sha(path.read_bytes())
        # identity() only reads constants/source bytes; no health/inference request.
        config = {"endpoint": "http://127.0.0.1:11435", "model": "qwen3:4b-instruct-2507-q4_K_M",
                  "expected_version": "0.40.8", "expected_digest": "0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"}
        identity = LocalEvidenceFactAnswerer(config).identity()
        self.plan = {"arms": list(verifier.ARMS), "repetitions": 2, "expected_rows": 42,
                     "max_local_answer_generations": 42, "new_detector_generations": 0, "new_encoder_calls": 0,
                     "source_sha256": self.inputs, "implementation_sha256": self.code, "policy": policy,
                     "answerer_identity": identity,
                     "runtime_identity": {"version": "0.40.8", "model": "qwen3:4b-instruct-2507-q4_K_M",
                         "digest": "0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0", "endpoint": "http://127.0.0.1:11435"},
                     "config": identity["client"]["config"]}
        self.rows = []
        for repeat in range(2):
            for i, packet in enumerate(packets):
                payload = {"query": packet["payload"]["query"], "memories": [{"source_id": "m_request_0", "text": "Customer: " + self.token}]}
                choice = {"answer_id": "E_" + format(repeat * 7 + i, "016X") + "_1", "token": self.token}
                for arm in verifier.ARMS:
                    choices = None if arm == "free" else [choice]
                    user = copy.deepcopy(payload)
                    if choices is not None:
                        user["answer_candidates"] = choices
                    schema = None if arm != "evidence_id" else {"type": "object", "additionalProperties": False, "required": ["answer_id"],
                        "properties": {"answer_id": {"type": "string", "enum": ["UNKNOWN", choice["answer_id"]]}}}
                    messages = [{"role": "system", "content": identity["prompts"][arm]},
                                {"role": "user", "content": json.dumps(user, ensure_ascii=False, separators=(",", ":"))}]
                    actual = {"messages": messages, "format": schema}
                    answer = self.token if i < 4 else "UNKNOWN"
                    if arm == "evidence_id":
                        answer = json.dumps({"answer_id": choice["answer_id"] if i < 4 else "UNKNOWN"})
                    meta = {"status": "ok", "answer": answer, "local_calls": 1, "mode": arm,
                            "input_sha256": verifier.digest(actual), "schema_sha256": verifier.digest(schema) if schema else None,
                            "input_budget_upper_bound": len(json.dumps(actual, ensure_ascii=False, separators=(",", ":")).encode()) + 384,
                            "prompt_eval_count": 100, "eval_count": 20}
                    self.rows.append({"task_id": packet["envelope"]["task_id"], "actor_id": "owner", "repeat": repeat, "arm": arm,
                        "request_id": "request" + str(repeat * 7 + i), "source_payload": packet["payload"], "model_payload": payload,
                        "actual_candidate_view": choices, "candidate_count": 1, "prepare_status": "ok", "evidence_status": "ok",
                        "detection": {"status": "ok", "mode": "rules", "errors": [], "local_calls": 0,
                            "local_calls_complete": True, "agent_observations": [],
                            "payload_sha256": verifier.digest(packet["payload"]), "policy_version": policy["version"]},
                        "model_status": "ok", "answer_calls": 1, "model_answer": answer, "response_metadata": meta,
                        "evidence_resolution_status": "ok" if arm == "evidence_id" else None, "evidence_resolution_error": None,
                        "restoration_status": "ok", "restoration_error": None,
                        "final_answer": "Synthetic Private Company" if i < 4 else "UNKNOWN",
                        "task_type": "authorized_fact" if i < 4 else "denied_request", "correct": True,
                        "model_input_exposures": [], "unauthorized_final_disclosures": [], "legal_model_unknown": False})
        groups = {arm: {"registered": 14, "legal": 8, "legal_correct": 8, "denied": 6, "denied_correct": 6,
                       "legal_unknown": 0, "model_errors": 0, "not_run": 0, "input_exposure_requests": 0,
                       "unauthorized_final_disclosures": 0, "local_generations": 14} for arm in verifier.ARMS}
        self.report = {"groups": groups, "local_answer_generations": 42, "new_encoder_calls": 0, "new_detector_generations": 0,
                       "cloud_calls": 0, "api_cost_cny": 0, "source_stories": 1, "original_data_unchanged": True,
                       "implementation_unchanged": True, "overall_acceptance": "not_established_development_answer_format_only"}
        self.write_artifacts()
        save(self.run / "network_audit.json", {"allowed_loopback_connections": 44, "blocked_external_connections": 0})

    def write_artifacts(self):
        for name, value in (("plan.json", self.plan), ("rows.json", self.rows), ("report.json", self.report)):
            save(self.run / name, value)

    def verify(self):
        with patch.object(verifier, "load_snapshot_bundle", return_value=self.bundle):
            return verifier.verify(self.run, project=self.root)

    def assert_fails(self, name):
        result = self.verify()
        self.assertEqual(result["status"], "failed")
        self.assertIn(name, result["failed_checks"])

    def test_complete_injected_fixture_passes_without_model_calls(self):
        result = self.verify()
        self.assertEqual(result["status"], "passed", result["failed_checks"])
        self.assertEqual(result["check_count"], 28)
        self.assertFalse(result["source_scope"]["all_execution_dependencies_frozen"])
        self.assertIn("not anonymous", result["privacy_scope"])
        self.assertIn("message.content", result["response_scope"])

    def test_dropped_or_duplicated_row_fails_matrix_and_denominator(self):
        self.rows[-1] = copy.deepcopy(self.rows[0])
        self.write_artifacts()
        self.assert_fails("complete_unique_42_task_repeat_arm_matrix")
        self.rows.pop()
        self.write_artifacts()
        self.assert_fails("report_groups_denominators_match_independent_aggregation")

    def test_changed_actual_input_hash_fails(self):
        self.rows[0]["response_metadata"]["input_sha256"] = "0" * 64
        self.write_artifacts()
        self.assert_fails("reconstructed_actual_messages_schema_input_hashes")

    def test_changed_report_score_is_not_accepted(self):
        self.report["groups"]["free"]["legal_correct"] = 7
        self.write_artifacts()
        self.assert_fails("report_groups_denominators_match_independent_aggregation")

    def test_whole_free_response_cannot_be_truncated_to_a_token(self):
        raw = self.rows[0]["model_answer"] + " trailing private content"
        self.rows[0]["model_answer"] = raw
        self.rows[0]["response_metadata"]["answer"] = raw
        self.write_artifacts()
        self.assert_fails("strict_saved_evidence_resolution_and_source_fact_presence")

    def test_prompt_change_cannot_be_hidden_by_rehashing_rows(self):
        self.plan["answerer_identity"]["prompts"]["free"] += " unregistered side information"
        for row in self.rows:
            if row["arm"] == "free":
                actual = {"messages": [{"role": "system", "content": self.plan["answerer_identity"]["prompts"]["free"]},
                                        {"role": "user", "content": json.dumps(row["model_payload"], ensure_ascii=False, separators=(",", ":"))}], "format": None}
                row["response_metadata"]["input_sha256"] = verifier.digest(actual)
                row["response_metadata"]["input_budget_upper_bound"] = len(json.dumps(actual, ensure_ascii=False, separators=(",", ":")).encode()) + 384
        self.write_artifacts()
        self.assert_fails("fixed_three_prompt_views")
        self.assertNotIn("reconstructed_actual_messages_schema_input_hashes", self.verify()["failed_checks"])

    def test_changed_per_row_score_fails_independent_recalculation(self):
        self.rows[0]["correct"] = False
        self.write_artifacts()
        self.assert_fails("independent_registered_scans_and_whole_answer_scores")

    def test_missing_memory_candidate_cannot_be_hidden_by_rehashing(self):
        self.rows[1]["actual_candidate_view"] = []
        self.write_artifacts()
        self.assert_fails("all_and_only_memory_token_candidates_no_query_evidence")

    def test_unauthorized_source_actor_fails(self):
        self.rows[0]["actor_id"] = "outsider"
        self.write_artifacts()
        self.assert_fails("source_payload_native_actor_authority_and_paired_preparation")

    def test_bool_or_extra_calls_and_oversized_usage_fail(self):
        self.rows[0]["answer_calls"] = True
        self.rows[1]["response_metadata"]["prompt_eval_count"] = 3073
        self.write_artifacts()
        self.assert_fails("one_generation_per_row_complete_content_preserved")
        self.assert_fails("reconstructed_preflight_and_actual_token_budgets")

    def test_changed_archived_code_or_input_hash_fails(self):
        (self.run / "implementation/privacy.py").write_bytes(b"# changed archive\n")
        self.assert_fails("seven_archived_source_hashes")
        path = next(iter(self.inputs))
        self.plan["source_sha256"][path] = "0" * 64
        self.write_artifacts()
        self.assert_fails("five_explicit_input_hashes")

    def test_internal_map_fields_are_never_a_valid_receipt_input(self):
        self.rows[0]["mapping"] = {"private": "not a real RestorationMap"}
        self.write_artifacts()
        self.assert_fails("no_internal_restoration_map_fields_saved")

    def test_receipt_writer_refuses_existing_paths(self):
        path = self.run / "report.json"
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            verifier.write_new(path, {"replacement": True})
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
