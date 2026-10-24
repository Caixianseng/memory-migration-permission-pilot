"""Independent offline instruments; no study corpus, model, or cloud calls."""
import copy
import json
import unittest

from memory_migration_study.local_detector import MODEL
from memory_migration_study.memory_generation_experiment import (
    LocalFactAnswerer, MODES, score_masking, score_task, summarize,
)
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer


class FakeAnswerTransport:
    def __init__(self, override=None):
        self.override = override or {}
        self.requests = []

    def __call__(self, method, path, body=None):
        self.requests.append((method, path, copy.deepcopy(body)))
        return {"model": MODEL, "done": True, "done_reason": "stop",
                "message": {"content": "Amber Works"}, **self.override}


class LocalFactAnswererTests(unittest.TestCase):
    def test_answerer_only_receives_query_and_memory_text_not_scoring_reference(self):
        transport = FakeAnswerTransport()
        payload = {"query": "Which customer?", "memories": [
            {"source_id": "opaque-id", "text": "The customer is Amber Works."}]}
        result = LocalFactAnswerer(transport=transport)(payload)
        self.assertEqual((result["status"], result["answer"], result["local_calls"]), ("ok", "Amber Works", 1))
        self.assertEqual(len(transport.requests), 1)
        method, path, body = transport.requests[0]
        self.assertEqual((method, path), ("POST", "/api/chat"))
        self.assertEqual(json.loads(body["messages"][1]["content"]), payload)
        self.assertEqual(set(body), {"model", "messages", "stream", "keep_alive", "options"})
        self.assertEqual(body["options"], {"num_ctx": 4096, "num_predict": 64, "temperature": 0, "seed": 42})
        self.assertNotIn("Amber Works", body["messages"][0]["content"])

    def test_unexpected_gold_or_policy_fields_rejected_before_model(self):
        clean = {"query": "Which customer?", "memories": [{"source_id": "m", "text": "A fact."}]}
        variants = [dict(clean, evaluation_answer="GOLD_NEVER_SEND"),
                    dict(clean, policy={"expected_answer": "GOLD_NEVER_SEND"}),
                    {"query": "Which customer?", "memories": [dict(clean["memories"][0], expected_answer="GOLD_NEVER_SEND")]},
                    {"query": 123, "memories": []},
                    {"query": "Question", "memories": [{"source_id": "m", "text": 123}]}]
        for payload in variants:
            with self.subTest(payload=payload):
                transport = FakeAnswerTransport()
                result = LocalFactAnswerer(transport=transport)(payload)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["local_calls"], 0)
                self.assertIsNone(result["answer"])
                self.assertEqual(transport.requests, [])

    def test_nonstop_empty_tools_and_reasoning_cannot_be_task_answers(self):
        overrides = [{"done": False}, {"done_reason": "length"}, {"model": "untrusted"},
                     {"message": {"content": ""}}, {"message": {"content": "  "}},
                     {"message": {"content": "Amber Works", "tool_calls": [{"name": "send"}]}},
                     {"message": {"content": "Amber Works", "thinking": "private reasoning"}},
                     {"message": None}]
        for override in overrides:
            with self.subTest(override=override):
                result = LocalFactAnswerer(transport=FakeAnswerTransport(override))({"query": "q", "memories": []})
                self.assertEqual(result["status"], "error")
                self.assertIsNone(result["answer"])
                self.assertEqual(result["local_calls"], 1)
                self.assertNotIn("private reasoning", json.dumps(result))

    def test_budget_overflow_never_calls_local_or_remote_model(self):
        transport = FakeAnswerTransport()
        result = LocalFactAnswerer(transport=transport)({"query": "秘密" * 5000, "memories": []})
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(result["error"], "answer_input_budget_exceeded")
        self.assertEqual(transport.requests, [])

    def test_transport_failure_does_not_log_secret_or_fall_back(self):
        calls = []
        def broken(method, path, body=None):
            calls.append((method, path))
            raise RuntimeError("SENSITIVE_ERROR_784")
        result = LocalFactAnswerer(transport=broken)({"query": "q", "memories": []})
        self.assertEqual(result["error"], "local_answer_failed")
        self.assertEqual(calls, [("POST", "/api/chat")])
        self.assertNotIn("SENSITIVE_ERROR_784", json.dumps(result))


class TaskScoringTests(unittest.TestCase):
    def row(self, **kwargs):
        return dict({"status": "ok", "final_answer": "UNKNOWN", "model_status": "ok",
                     "required_fact_in_generated_memory": True}, **kwargs)

    def label(self, authorized=True):
        return {"expected_answer": "Amber Works" if authorized else "UNKNOWN", "authorized": authorized}

    def test_refusal_requires_actual_successful_model_unknown_with_retained_fact(self):
        refused = score_task(self.row(), self.label())
        self.assertTrue(refused["model_refusal_with_fact"])
        self.assertTrue(refused["authorized_no_answer"])
        self.assertFalse(refused["correct"])
        missing = score_task(self.row(required_fact_in_generated_memory=False), self.label())
        self.assertFalse(missing["model_refusal_with_fact"])
        self.assertTrue(missing["authorized_no_answer"])

    def test_preprocessing_and_restoration_failures_are_not_model_refusals(self):
        processing = score_task(self.row(status="blocked", final_answer=None, model_status=None), self.label())
        restoration = score_task(self.row(status="blocked", final_answer=None, restoration_status="blocked"), self.label())
        failed_model = score_task(self.row(status="error", final_answer=None, model_status="error"), self.label())
        self.assertTrue(processing["processing_blocked"])
        self.assertFalse(processing["restore_failed"])
        self.assertTrue(restoration["restore_failed"])
        for value in (processing, restoration, failed_model):
            self.assertFalse(value["model_refusal_with_fact"])
            self.assertTrue(value["authorized_no_answer"])
            self.assertFalse(value["correct"])

    def test_correct_recovery_and_denied_task_are_separate_from_refusal(self):
        correct = score_task(self.row(final_answer=" amber works "), self.label())
        self.assertTrue(correct["correct"])
        self.assertFalse(correct["authorized_no_answer"])
        denied = score_task(self.row(status="blocked", model_status=None), self.label(False))
        self.assertTrue(denied["correct"])
        self.assertFalse(denied["authorized"])
        self.assertFalse(denied["authorized_no_answer"])
        self.assertFalse(denied["model_refusal_with_fact"])

    def test_refusal_phrase_that_contains_secret_is_not_safe_unknown(self):
        row = self.row(final_answer="UNKNOWN, but the customer is Amber Works")
        score = score_task(row, self.label(False))
        self.assertFalse(score["correct"])
        self.assertFalse(score["model_refusal_with_fact"])

    def test_restoration_failure_is_not_a_preprocessing_block(self):
        row = self.row(status="blocked", final_answer=None, model_status="ok",
                       restoration_status="blocked")
        score = score_task(row, self.label())
        self.assertTrue(score["restore_failed"])
        self.assertFalse(score["processing_blocked"])
        self.assertFalse(score["model_refusal_with_fact"])
        self.assertTrue(score["authorized_no_answer"])


class MaskingScoringTests(unittest.TestCase):
    def setUp(self):
        self.authority = MemoryLabelAuthority(b"offline-scoring-only-authority-32-bytes")
        # Natural wording without a labelled field avoids rules completing our
        # deliberately partial/missing native labels in scorer instruments.
        self.text = "We work with Amber Works. Public note."
        self.case = {"source": {"source_id": "synthetic-conversation", "text": self.text}}
        self.policy = {"version": "unit-policy", "protected_categories": ["CUSTOMER"]}
        self.gold_start = self.text.index("Amber Works")
        self.labels = {"sensitive_spans": [{"start": self.gold_start,
                                            "end": self.gold_start + len("Amber Works"), "category": "CUSTOMER"}]}

    def record(self, selected=None, marked="Amber Works"):
        selected = self.text if selected is None else selected
        start = self.text.index(selected)
        findings = []
        if marked is not None:
            field_start = selected.index(marked)
            findings = [{"start": field_start, "end": field_start + len(marked), "category": "CUSTOMER"}]
        fact = {"text": selected, "source_start": start, "source_end": start + len(selected), "findings": findings}
        return self.authority.build_record(self.case["source"], fact, self.policy,
            owner_id="owner", readers=["owner"], agent_id="local-agent", builder_version="stub-builder-v1")

    def prepare(self, records, query=""):
        def empty_semantic_detector(**kwargs):
            return {"status": "ok", "findings": [], "errors": [], "local_calls": 1,
                    "elapsed_seconds": 0.0}
        return prepare_labeled_transfer(records, query, self.policy, authority=self.authority,
            actor_id="owner", agent_id="local-agent", request_id="local-request", mode="generation",
            agent=empty_semantic_detector)

    def test_actual_label_preparation_masks_memory_and_question_repetitions(self):
        records = [self.record()]
        prepared = self.prepare(records, query="Is AMBER WORKS the customer?")
        self.assertEqual(prepared["status"], "ok")
        self.assertNotIn("amber works", json.dumps(prepared["payload"]).lower())
        result = score_masking(self.case, self.labels, records, prepared)
        self.assertTrue(result["ready"])
        self.assertEqual((result["complete"], result["partial"], result["unmasked"]), (2, 0, 0))
        self.assertEqual(result["missing_extraction_sensitive_characters"], 0)
        self.assertEqual(result["extra_masked_characters"], 0)

    def test_actual_partial_label_is_partial_not_full_coverage(self):
        records = [self.record(marked="Amber")]
        prepared = self.prepare(records)
        self.assertEqual(prepared["status"], "ok")
        # This deliberately weak generation label exercises the scorer through
        # actual privacy transforms, rather than claiming a fake token is safe.
        result = score_masking(self.case, self.labels, records, prepared)
        self.assertEqual((result["complete"], result["partial"], result["unmasked"]), (0, 1, 0))
        self.assertEqual(result["retained_sensitive_characters"], len("Amber Works"))

    def test_retained_but_unlabeled_value_scores_unmasked(self):
        records = [self.record(marked=None)]
        prepared = self.prepare(records)
        self.assertEqual(prepared["status"], "ok")
        result = score_masking(self.case, self.labels, records, prepared)
        self.assertEqual((result["complete"], result["partial"], result["unmasked"]), (0, 0, 1))

    def test_missing_extraction_is_loss_even_if_prepared_text_has_no_secret(self):
        records = [self.record(selected="Public note.", marked=None)]
        prepared = self.prepare(records)
        self.assertEqual(prepared["status"], "ok")
        result = score_masking(self.case, self.labels, records, prepared)
        self.assertEqual(result["missing_extraction_sensitive_characters"], len("Amber Works"))
        self.assertEqual(result["retained_sensitive_characters"], 0)
        self.assertEqual(result["retained_gold_spans"], 0)
        self.assertEqual(result["complete"], 0)

    def test_half_extracted_name_fully_masked_still_not_complete_field(self):
        records = [self.record(selected="Amber", marked="Amber")]
        prepared = self.prepare(records)
        self.assertEqual(prepared["status"], "ok")
        self.assertNotIn("Amber", json.dumps(prepared["payload"]))
        score = score_masking(self.case, self.labels, records, prepared)
        self.assertEqual((score["complete"], score["partial"], score["unmasked"]), (0, 1, 0))
        self.assertEqual(score["fully_retained_source_spans"], 0)
        self.assertEqual(score["partially_retained_source_spans"], 1)
        self.assertEqual(score["retained_sensitive_characters"], len("Amber"))
        self.assertEqual(score["missing_extraction_sensitive_characters"], len(" Works"))

    def test_blocked_payload_keeps_source_and_extraction_counts_with_null_masking(self):
        records = [self.record()]
        prepared = self.prepare(records, query="[PVT_forged]")
        self.assertNotEqual(prepared["status"], "ok")
        result = score_masking(self.case, self.labels, records, prepared)
        self.assertFalse(result["ready"])
        self.assertEqual(result["source_sensitive_characters"], len("Amber Works"))
        self.assertEqual(result["retained_sensitive_characters"], len("Amber Works"))
        for key in ("complete", "partial", "unmasked", "extra_masked_characters"):
            self.assertIsNone(result[key])

    def test_scoring_gold_changes_score_not_actual_payload_or_authority_label(self):
        records = [self.record()]
        prepared = self.prepare(records)
        original = copy.deepcopy(prepared["payload"])
        signed_label = copy.deepcopy(records[0]["label"])
        first = score_masking(self.case, self.labels, records, prepared)
        second = score_masking(self.case, {"sensitive_spans": []}, records, prepared)
        self.assertEqual(first["complete"], 1)
        self.assertEqual(second["complete"], 0)
        self.assertEqual(prepared["payload"], original)
        self.assertEqual(records[0]["label"], signed_label)
        self.assertNotIn("sensitive_spans", signed_label)


class SummaryDenominatorTests(unittest.TestCase):
    def make_row(self, mode, *, authorized, status, error=None, answer=None, supported=True, ready=False):
        row = {"case_id": "synthetic-denominator-case", "mode": mode, "split": "heldout", "status": status, "error": error,
               "final_answer": answer, "model_status": "ok" if status == "ok" else None,
               "required_fact_in_generated_memory": supported,
               "detector_calls": 0, "answer_calls": int(status == "ok")}
        if ready:
            row["masking"] = {"ready": True, "complete": 1, "partial": 0, "unmasked": 0,
                              "extra_masked_characters": 0, "source_sensitive_characters": 11,
                              "retained_sensitive_characters": 11, "missing_extraction_sensitive_characters": 0,
                              "fully_retained_source_spans": 1, "partially_retained_source_spans": 0,
                              "missing_source_spans": 0}
        row["score"] = score_task(row, {"expected_answer": "Amber Works" if authorized else "UNKNOWN",
                                        "authorized": authorized})
        return row

    def test_all_four_modes_keep_legal_and_denied_tasks_in_separate_denominators(self):
        rows = []
        for mode in MODES:
            rows.extend([
                self.make_row(mode, authorized=True, status="ok", answer="Amber Works", ready=True),
                self.make_row(mode, authorized=True, status="blocked", error="detector_uncertain"),
                self.make_row(mode, authorized=True, status="ok", answer="UNKNOWN"),
                self.make_row(mode, authorized=True, status="blocked", error="memory_build_unavailable", supported=False),
                self.make_row(mode, authorized=False, status="blocked", error="authorization_denied", answer="UNKNOWN"),
                self.make_row(mode, authorized=False, status="blocked", error="detector_uncertain"),
                self.make_row(mode, authorized=False, status="ok", answer="UNKNOWN, Amber Works"),
            ])
        report = summarize(rows, [{"status": "ok", "local_calls": 1, "elapsed_seconds": 0.1},
                                  {"status": "needs_review", "local_calls": 2, "elapsed_seconds": 0.2}])
        self.assertEqual(report["build_cases"], 2)
        self.assertEqual(report["build_successes"], 1)
        self.assertEqual(report["builder_calls"], 3)
        self.assertEqual(report["new_cloud_calls"], 0)
        for mode in MODES:
            summary = next(s for s in report["summaries"] if s["split"] == "heldout" and s["mode"] == mode)
            self.assertEqual(summary["registered_tasks"], 7)
            self.assertEqual((summary["authorized_tasks"], summary["denied_tasks"]), (4, 3))
            self.assertEqual(summary["authorized_correct"], 1)
            self.assertEqual(summary["authorized_no_answer"], 3)
            self.assertEqual(summary["processing_blocked_authorized"], 2)
            self.assertEqual(summary["model_refusal_with_fact"], 1)
            self.assertEqual(summary["supported_authorized_tasks"], 3)
            self.assertEqual(summary["denied_correctly_blocked"], 1)
            self.assertEqual(summary["denied_received_answer"], 1)
            self.assertEqual(summary["ready_masked_requests"], 1)
        dev = [s for s in report["summaries"] if s["split"] == "dev"]
        self.assertTrue(all(s["registered_tasks"] == 0 for s in dev))

    def test_unavailable_build_keeps_original_extraction_denominator_once_per_story(self):
        text = "Client Amber Works will be archived."
        start = text.index("Amber Works")
        case = {"source": {"source_id": "synthetic-source", "text": text}}
        labels = {"sensitive_spans": [{"start": start, "end": start + len("Amber Works"),
                                        "category": "CUSTOMER"}]}
        missing = score_masking(case, labels, [], {"status": "blocked"})
        rows = []
        for mode in MODES:
            for task in ("private", "public", "denied"):
                row = self.make_row(mode, authorized=task != "denied", status="blocked",
                                    error="memory_build_unavailable", supported=False)
                row.update(case_id="missing-build-story", task_id=task)
                if mode != "raw_reference":
                    row["masking"] = copy.deepcopy(missing)
                rows.append(row)
        report = summarize(rows, [{"case_id": "missing-build-story", "status": "needs_review",
                                   "local_calls": 1, "elapsed_seconds": 0.1}])
        self.assertEqual(report["build_cases"], 1)
        self.assertEqual(report["build_successes"], 0)
        self.assertEqual(len(report["extraction_per_story"]), 1)
        extracted = report["extraction_per_story"][0]
        self.assertEqual(extracted["source_sensitive_characters"], len("Amber Works"))
        self.assertEqual(extracted["retained_sensitive_characters"], 0)
        self.assertEqual(extracted["missing_extraction_sensitive_characters"], len("Amber Works"))
        self.assertEqual(extracted["missing_source_spans"], 1)
        for mode in MODES:
            summary = next(s for s in report["summaries"] if s["split"] == "heldout" and s["mode"] == mode)
            self.assertEqual(summary["registered_tasks"], 3)
            self.assertEqual(summary["authorized_tasks"], 2)
            self.assertEqual(summary["authorized_correct"], 0)
            self.assertEqual(summary["processing_blocked_authorized"], 2)


if __name__ == "__main__":
    unittest.main()
