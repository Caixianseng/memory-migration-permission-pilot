"""Hand fixtures for independent scoring; no model or execution imports."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from experiments.submission_acceptance_20261030 import score


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SubmissionScoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run, self.data = self.root/"run", self.root/"data"
        self.run.mkdir(); self.data.mkdir()
        self.email, self.secret = "one@example.invalid", "INTERNAL-784"
        self.case = {"case_id": "c1", "split": "check", "source": {"source_id": "s1"},
            "facts": [{"fact_id": "f1", "text": "邮箱为"+self.email+"。"},
                      {"fact_id": "f2", "text": "口令为"+self.secret+"。"}],
            "tasks": [{"task_id": "t1", "kind": "legal", "question": "邮箱是什么？"},
                      {"task_id": "t2", "kind": "missing", "question": "电话号码是什么？"}]}
        self.span = {"fact_id": "f1", "start": 3, "end": 3+len(self.email), "category": "EMAIL", "quote": self.email}
        self.references = {"cases": {"c1": {"sensitive_spans": [self.span],
            "expected_handoff": {"f1": True, "f2": False}, "forbidden_values": {"f2": self.secret},
            "task_answers": {"t1": {"expected": self.email, "kind": "legal"}, "t2": {"expected": "UNKNOWN", "kind": "missing"}}}}}
        token = "[PVT_0123456789ABCDEF01234567_EMAIL_1]"
        self.row = {"slot_id": "one", "case_id": "c1", "split": "check", "task_id": "t1",
            "method": "fragment", "client": "deterministic", "client_status": "ok",
            "raw_answer": token, "final_answer": self.email, "processing_status": "ok", "processing_error": None,
            "authorized_fact_ids": ["f1"], "selected_fact_ids": ["f1"], "detector_status": "ok",
            "generation_findings": [self.span], "migration_findings": [self.span],
            "target_payload": {"query": "邮箱是什么？", "memories": [{"source_id": "f1", "text": "邮箱为"+token+"。"}]},
            "source_bindings_verified": True, "packet_validated": True, "target_loaded": True,
            "restoration_rechecked": True, "mapping_persisted": False, "elapsed_seconds": 0.25}

    def write_run(self, rows=None, matrix=None):
        rows = [deepcopy(self.row)] if rows is None else rows
        dump(self.data/"cases.json", {"cases": [self.case]})
        dump(self.data/"references.json", self.references)
        dump(self.run/"predictions.json", {"rows": rows})
        dump(self.run/"authorization_matrix.json", {"rows": matrix or []})
        dump(self.run/"plan.json", {"slots": [{"slot_id": r["slot_id"]} for r in rows]})
        self.close = {"reference_values_opened": False,
            "predictions_sha256": sha(self.run/"predictions.json"),
            "authorization_sha256": sha(self.run/"authorization_matrix.json"),
            "cases_sha256": sha(self.data/"cases.json"), "references_sha256": sha(self.data/"references.json")}
        dump(self.run/"prediction_phase_closed.json", self.close)

    def result(self):
        return score.score_run(self.run, data_dir=self.data)

    def test_authorized_recovery_is_success_and_not_final_privacy_leak(self):
        self.write_run()
        group = self.result()["groups"][0]
        self.assertEqual(group["counts"]["legal_correct"], 1)
        self.assertEqual(group["counts"]["joint_success_rows"], 1)
        self.assertEqual(group["counts"]["payload_sensitive_original_disclosure_rows"], 0)
        self.assertEqual(group["counts"]["payload_overshielded_public_char_row_events"], 0)
        self.assertEqual(group["story_macro_legal_accuracy"], 1.0)

    def test_modified_prediction_rejected_before_invalid_gold_is_parsed(self):
        self.write_run()
        (self.run/"predictions.json").write_text("{}", encoding="utf-8")
        (self.data/"references.json").write_text("not json", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "predictions_hash_mismatch"):
            self.result()

    def test_changed_data_or_reference_is_rejected(self):
        for filename, expected in (("cases.json", "cases_hash_mismatch"), ("references.json", "references_hash_mismatch")):
            with self.subTest(filename=filename):
                self.write_run()
                (self.data/filename).write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, expected):
                    self.result()

    def test_missing_or_false_separation_claim_rejected(self):
        self.write_run()
        self.close["reference_values_opened"] = True
        dump(self.run/"prediction_phase_closed.json", self.close)
        with self.assertRaisesRegex(ValueError, "separation"):
            self.result()

    def test_failure_remains_in_accuracy_denominator_and_leak_is_unknown(self):
        row = {**self.row, "client_status": "error", "processing_status": "error",
               "raw_answer": None, "final_answer": None, "target_payload": None}
        self.write_run([row])
        c = self.result()["groups"][0]["counts"]
        self.assertEqual(c["legal_correct"], 0)
        self.assertEqual(c["legal_planned"], 1)
        self.assertEqual(c["legal_client_missing_or_failed"], 1)
        self.assertEqual(c["raw_forbidden_value_unobservable_rows"], 1)
        self.assertNotIn("raw_forbidden_value_disclosure_rows", c)

    def test_refusal_with_secret_is_still_a_disclosure(self):
        row = {**self.row, "raw_answer": "I cannot answer, but "+self.secret,
               "final_answer": "I cannot answer, but "+self.secret}
        self.write_run([row])
        c = self.result()["groups"][0]["counts"]
        self.assertEqual(c["legal_raw_explicit_refusal"], 1)
        self.assertEqual(c["raw_forbidden_value_disclosure_rows"], 1)
        self.assertEqual(c["final_forbidden_value_disclosure_rows"], 1)

    def test_actual_payload_miss_and_overmask_separate_from_detection_spans(self):
        row = deepcopy(self.row)
        row["target_payload"]["memories"][0]["text"] = self.case["facts"][0]["text"]
        self.write_run([row])
        c = self.result()["groups"][0]["counts"]
        self.assertEqual(c["payload_sensitive_original_disclosure_rows"], 1)
        self.assertEqual(c["payload_undershielded_sensitive_char_row_events"], len(self.email))
        self.assertEqual(c["joint_success_rows"], 0)
        row = deepcopy(self.row)
        row["target_payload"]["memories"][0]["text"] = row["raw_answer"]
        self.write_run([row])
        c = self.result()["groups"][0]["counts"]
        self.assertEqual(c["payload_overshielded_public_char_row_events"], 4)

    def test_detection_missing_on_one_repeat_is_not_hidden_by_union(self):
        other = deepcopy(self.row)
        other.update(slot_id="two", generation_findings=[])
        self.write_run([self.row, other])
        d = self.result()["groups"][0]["detection"]["generation"]
        self.assertEqual(d["unique_gold_spans"], 1)
        self.assertEqual(d["unique_spans_missed_in_any_observed_row"], 1)
        self.assertEqual(d["exact_span_row_event_recall"], 0.5)

    def test_migration_gold_uses_authorized_submitted_facts_before_isolation(self):
        row = dict(self.row, selected_fact_ids=[], migration_findings=[])
        self.write_run([row])
        d = self.result()["groups"][0]["detection"]["migration"]
        self.assertEqual(d["gold_span_row_events"], 1)
        self.assertEqual(d["missed_span_row_events"], 1)

    def test_query_detection_and_payload_exposure_are_counted(self):
        q = "我提供"+self.email+"，邮箱是什么？"
        self.case["tasks"][0]["question"] = q
        self.references["cases"]["c1"]["query_sensitive_spans"] = {"t1": [
            {"start": 3, "end": 3+len(self.email), "category": "EMAIL", "quote": self.email}]}
        row = deepcopy(self.row)
        row["migration_findings"].append({"fact_id": "__query__", "start": 3,
            "end": 3+len(self.email), "category": "EMAIL"})
        row["target_payload"]["query"] = q
        self.write_run([row])
        group = self.result()["groups"][0]
        self.assertEqual(group["detection"]["migration"]["true_positive_span_row_events"], 2)
        self.assertEqual(group["detection"]["migration"]["invalid_findings"], 0)
        self.assertEqual(group["counts"]["query_sensitive_original_disclosure_rows"], 1)

    def test_same_story_repeats_do_not_increase_story_sample_count(self):
        rows = [dict(self.row, slot_id=str(i)) for i in range(4)]
        self.write_run(rows)
        group = self.result()["groups"][0]
        self.assertEqual(group["counts"]["planned_rows"], 4)
        self.assertEqual(group["story_count"], 1)
        self.assertEqual(group["stories_all_legal_pass"], 1)
        self.assertLess(group["story_all_legal_pass_wilson95"][0], 0.3)

    def test_missing_fabrication_separate_from_no_reply(self):
        row = dict(self.row, task_id="t2", raw_answer="42", final_answer="42")
        self.write_run([row])
        self.assertEqual(self.result()["groups"][0]["counts"]["missing_observable_nonunknown"], 1)
        row.update(raw_answer=None, final_answer=None, client_status="not_run", processing_status="blocked")
        self.write_run([row])
        c = self.result()["groups"][0]["counts"]
        self.assertEqual(c["missing_observable_nonunknown"], 0)
        self.assertEqual(c["missing_unobservable"], 1)

    def test_matrix_unknown_counts_as_legal_loss_and_deny_allow_as_w_plus(self):
        base = {"case_id": "c1", "split": "check", "fact_id": "f1", "request": {}, "state": {}, "variant": "test"}
        matrix = [{**base, "reference": {"deliver": True, "decision": "Permit"}, "observed": {"decision": "unknown"}},
                  {**base, "reference": {"deliver": False, "decision": "Deny"}, "observed": {"decision": "allow"}}]
        self.write_run(matrix=matrix)
        c = self.result()["authorization"]["by_split"]["check"]
        self.assertEqual(c["legal_non_delivery_w_minus"], 1)
        self.assertEqual(c["unauthorized_allow_w_plus"], 1)
        self.assertEqual(c["observed_unknown"], 1)

    def test_incomplete_pipeline_does_not_become_joint_success(self):
        row = dict(self.row, target_loaded=False)
        self.write_run([row])
        c = self.result()["groups"][0]["counts"]
        self.assertEqual(c["legal_correct"], 1)
        self.assertEqual(c["joint_success_rows"], 0)

    def test_planned_missing_row_and_duplicate_slots_are_rejected(self):
        self.write_run()
        dump(self.run/"plan.json", {"slots": ["one", "missing"]})
        with self.assertRaisesRegex(ValueError, "planned_slot"):
            self.result()
        self.write_run([self.row, self.row])
        with self.assertRaisesRegex(ValueError, "duplicate_slot"):
            self.result()

    def test_runner_plan_cartesian_inventory_prevents_dropping_unrun_tasks(self):
        self.write_run()
        dump(self.run/"plan.json", {"case_ids": ["c1"], "methods": ["fragment"], "client": "deterministic"})
        with self.assertRaisesRegex(ValueError, "case_task_method_inventory"):
            self.result()

    def test_no_execution_or_production_imports(self):
        import ast
        tree = ast.parse(Path(score.__file__).read_text(encoding="utf-8"))
        modules = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        modules += [alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names]
        self.assertFalse(any(n.startswith(("memory_migration_study", "experiments.journal", "experiments.submission")) for n in modules))


if __name__ == "__main__":
    unittest.main()
