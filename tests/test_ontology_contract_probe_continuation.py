"""Offline continuation evidence, total-cap, classification and scoring tests."""
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import run_ontology_contract_probe as base
from scripts import run_ontology_contract_probe_continuation as continuation


def response(status="ok", *, failure=False):
    diagnostics = ([{"attempt": attempt, "stage": "output", "code": "invalid_span"} for attempt in (1, 2)]
                   if failure else ([{"attempt": 1, "stage": "semantic", "code": "semantic_uncertainty"}]
                                    if status == "needs_review" else []))
    return {"status": "needs_review" if failure else status, "findings": [],
            "errors": ["format_or_span_invalid"] if failure else (["semantic_uncertainty"] if status == "needs_review" else []),
            "diagnostics": diagnostics, "local_calls": 2 if failure else 1, "elapsed_seconds": .001}


def post_event(cell, text, policy, *, repair=False, failure=False, status="ok"):
    body = continuation.request_body(text, policy, repair=repair)
    content = {"status": status, "findings": [{"quote": "ABSENT QUOTE", "category": "CUSTOMER"}] if failure else []}
    return {"cell": copy.deepcopy(cell), "method": "POST", "path": "/api/chat", "fixed_host": "127.0.0.1:11435",
            "request_object": body, "request_object_sha256": base._digest(body),
            "decoded_response": {"model": base.MODEL, "done": True, "done_reason": "stop",
                                 "message": {"content": json.dumps(content)}}}


class LocalFixture(base.LocalSensitivityAgent):
    """Only a unit-test transport; the continuation has no fake-runtime option."""
    post_calls = 0
    transport_failure = False
    invalid_first = False

    def _transport(self, method, path, body=None):
        if path == "/api/version":
            return {"version": base.QWEN_RUNTIME_VERSION}
        if path == "/api/tags":
            return {"models": [{"name": base.MODEL, "digest": base.DIGEST}]}
        type(self).post_calls += 1
        if type(self).transport_failure:
            raise ValueError("local_http_failure")
        failure = type(self).invalid_first and type(self).post_calls <= 2
        return {"model": base.MODEL, "done": True, "done_reason": "stop",
                "message": {"content": json.dumps({"status": "ok", "findings": [
                    {"quote": "ABSENT QUOTE", "category": "CUSTOMER"}] if failure else []})}}


class NerFixture:
    identity = {"weights_sha256": "0" * 64, "test": "offline fixture"}
    initialization_seconds = 0

    def __init__(self, *args, **kwargs):
        self.calls = []

    def infer(self, text, labels, **options):
        self.calls.append((text, labels, options))
        return {"entities": {label: [] for label in labels}}


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.texts = ["Synthetic organization record " + str(index) + "." for index in range(16)]
        self.schedule, self.policies = base.make_schedule(), base.make_policies()
        LocalFixture.post_calls, LocalFixture.transport_failure, LocalFixture.invalid_first = 0, False, False

    def make_prefix(self):
        rows, posts, infers = [], [], []
        review_count = 0
        for index, cell in enumerate(self.schedule[:32]):
            text, policy = self.texts[cell["text_index"]], self.policies[cell["profile"]][cell["arm"]]
            if cell["arm"] == base.ARMS[2]:
                strict = cell["profile"] == base.STRICT_CUSTOMER_RELATION
                observed = {"status": "needs_review" if strict else "ok", "findings": [], "errors": [
                    "unsupported_category_contract"] if strict else [], "diagnostics": [],
                    "local_calls": 0 if strict else 1, "elapsed_seconds": .001}
                if not strict:
                    infers.append({"cell": cell, "text": text, "labels": {"organization": "fixed"},
                                   "decoded_response": {"entities": {"organization": []}}})
                status, calls = ("unsupported", 0) if strict else ("ok", 1)
                rows.append({"cell": cell, "status": status, "response": observed,
                             "qwen_post_attempts": 0, "gliner_infer_invocations": calls})
            else:
                failure = index == 31
                status = "needs_review" if review_count < 2 else "ok"
                review_count += int(status == "needs_review")
                observed = response(status, failure=failure)
                for attempt in range(observed["local_calls"]):
                    posts.append(post_event(cell, text, policy, repair=attempt == 1, failure=failure, status=status))
                rows.append({"cell": cell, "status": "engineering_error" if failure else status,
                             "response": observed, "qwen_post_attempts": observed["local_calls"], "gliner_infer_invocations": 0})
        self.assertEqual(Counter(row["status"] for row in rows), {"ok": 24, "needs_review": 2, "unsupported": 5, "engineering_error": 1})
        return rows, posts, infers

    def evidence(self):
        rows, posts, infers = self.make_prefix()
        parent = self.root / "parent"
        parent.mkdir()
        parent_plan = {"source_sha256": base.source_hashes(), "qwen": {"timeout_seconds": 120},
                       "assets": {"root": "unused-test-model"}, "gliner": {"threads": 4, "splitter": "cjk_aware", "threshold": .5}}
        parent_hash = "fixture-parent-plan"
        for name in continuation.PARENT_FILES:
            (parent / name).write_text("opaque fixture", encoding="utf-8")
        for name, value in (("rows.json", rows), ("aborted_predictions.json", rows),
                            ("http_transport_capture.json", posts), ("ner_infer_capture.json", infers)):
            base.save(parent / name, value)
        execution = {"status": "stopped", "completed_opportunities": 32, "qwen_post_attempts": 22,
                     "gliner_infer_invocations": 6, "wall_seconds": 68.734, "network": {"blocked_connects": 0},
                     "error_code": "probe_engineering_error_or_accounting_mismatch"}
        base.save(parent / "execution.json", execution)
        closure = {"schema": "ontology_probe_aborted_closure_v1", "plan_sha256": parent_hash,
                   "reference_parsed": False, "all_96_predictions_closed": False, "completed_opportunities": 32,
                   "unexecuted_opportunities": 64, "qwen_post_attempts": 22, "gliner_infer_invocations": 6,
                   "source_sha256": parent_plan["source_sha256"], "source_and_archive_verified": True,
                   "rows_sha256": base.sha(parent / "rows.json"), "aborted_predictions_sha256": base.sha(parent / "aborted_predictions.json"),
                   "original_execution_sha256": base.sha(parent / "execution.json"),
                   "capture_objects_sha256": {name: base.sha(parent / name) for name in ("http_transport_capture.json", "ner_infer_capture.json")}}
        base.save(parent / "aborted_phase_closed.json", closure)
        actual_ner = NerFixture()
        ner = base.GlinerEntityAgent(actual_ner, approved_policies=[self.policies[p][base.ARMS[2]] for p in base.PROFILES])
        detectors = {"qwen_health": LocalFixture().health(), "qwen_identity": LocalFixture({"timeout_seconds": 120}).cache_identity(),
                     "ner_identity": ner.cache_identity()}
        base.save(parent / "detectors.json", detectors)
        with patch.object(base, "verify_frozen", return_value=(parent_plan, self.texts, self.policies, self.schedule)):
            evidence = continuation.read_parent(parent, parent_hash, base.sha(parent / "aborted_phase_closed.json"))
        return evidence, parent_hash, base.sha(parent / "aborted_phase_closed.json")

    def test_parent_snapshot_is_verified_and_prefix_is_projected_without_mutation(self):
        evidence, _, _ = self.evidence()
        parent = Path(evidence["parent"])
        original = continuation.read_json(parent / "rows.json")
        self.assertEqual(evidence["remaining"], self.schedule[32:])
        self.assertEqual(len(evidence["remaining"]), 64)
        self.assertEqual(evidence["projected"][-1]["status"], "model_output_invalid")
        self.assertEqual(evidence["projected"][-1]["original_status"], "engineering_error")
        self.assertEqual(evidence["projected"][-1]["original_errors"], ["format_or_span_invalid"])
        self.assertEqual(original[-1]["status"], "engineering_error")
        self.assertNotIn("origin", original[-1])
        self.assertEqual(evidence["projected"][-1]["original_row_sha256"], base._digest(original[-1]))

    def test_parent_capture_or_prefix_tamper_is_rejected(self):
        evidence, parent_hash, closure_hash = self.evidence()
        parent = Path(evidence["parent"])
        posts = continuation.read_json(parent / "http_transport_capture.json")
        posts[-1]["decoded_response"]["done"] = False
        base.save(parent / "http_transport_capture.json", posts)
        with patch.object(base, "verify_frozen", return_value=(evidence["plan"], self.texts, self.policies, self.schedule)):
            with self.assertRaisesRegex(ValueError, "parent_evidence_hash_changed"):
                continuation.read_parent(parent, parent_hash, closure_hash)
        rows, posts, infers = self.make_prefix()
        rows[0]["cell"] = self.schedule[32]
        with self.assertRaisesRegex(ValueError, "parent_prefix_changed"):
            continuation.validate_prefix(rows, self.schedule, posts, infers, self.texts, self.policies)

    def test_only_two_complete_replayable_output_failures_are_reclassified_for_both_arms_profiles(self):
        for profile in base.PROFILES:
            for arm in base.ARMS[:2]:
                cell = {"text_index": 0, "profile": profile, "arm": arm}
                policy = self.policies[profile][arm]
                events = [post_event(cell, self.texts[0], policy, failure=True, repair=i == 1) for i in range(2)]
                self.assertEqual(continuation.classify(cell, response(failure=True), events, self.texts[0], policy), "model_output_invalid")
                for variant in ("transport", "envelope", "missing", "prompt", "valid_replay", "diagnostic"):
                    changed, observed = copy.deepcopy(events), response(failure=True)
                    if variant == "transport": changed[1]["error_type"] = "RuntimeError"
                    elif variant == "envelope": changed[1]["decoded_response"]["done_reason"] = "length"
                    elif variant == "missing": changed.pop()
                    elif variant == "prompt": changed[1]["request_object"]["messages"][0]["content"] += " altered"
                    elif variant == "valid_replay": changed[1]["decoded_response"]["message"]["content"] = '{"status":"ok","findings":[]}'
                    else: observed["diagnostics"][1]["stage"] = "transport"
                    with self.subTest(profile=profile, arm=arm, variant=variant):
                        self.assertEqual(continuation.classify(cell, observed, changed, self.texts[0], policy), "engineering_error")

    def test_inherited_budget_spends_original_total_and_active_wall(self):
        with patch.object(base.time, "monotonic", return_value=1000):
            budget = continuation.InheritedBudget(68.734)
            self.assertAlmostEqual(budget.started, 931.266)
            self.assertEqual((budget.posts, budget.infers), (22, 6))
            for _ in range(106): budget.generation()
            for _ in range(10): budget.inference()
            with self.assertRaisesRegex(RuntimeError, "generation_budget_exceeded"): budget.generation()
            with self.assertRaisesRegex(RuntimeError, "infer_budget_exceeded"): budget.inference()
        with patch.object(base.time, "monotonic", return_value=1000 + 3531.267):
            with self.assertRaisesRegex(RuntimeError, "wall_budget_exceeded"): budget.check()

    def test_missing_or_nonstring_content_is_engineering_error_but_empty_string_is_output_invalid(self):
        cell = {"text_index": 0, "profile": base.ANY_SPECIFIC_ORGANIZATION, "arm": base.ARMS[0]}
        policy = self.policies[cell["profile"]][cell["arm"]]
        for variant in ("missing", "none", "dict", "empty"):
            events = [post_event(cell, self.texts[0], policy, failure=True, repair=index == 1) for index in range(2)]
            observed = response(failure=True)
            code = "json_syntax_invalid" if variant == "empty" else "invalid_schema"
            observed["diagnostics"] = [{"attempt": attempt, "stage": "output", "code": code} for attempt in (1, 2)]
            for event in events:
                message = event["decoded_response"]["message"]
                if variant == "missing":
                    del message["content"]
                else:
                    message["content"] = {"none": None, "dict": {}, "empty": ""}[variant]
            with self.subTest(variant=variant):
                expected = "model_output_invalid" if variant == "empty" else "engineering_error"
                self.assertEqual(continuation.classify(cell, observed, events, self.texts[0], policy), expected)

    def test_plan_only_binds_cap_archive_and_exact_remaining_schedule_with_no_model(self):
        evidence, parent_hash, closure_hash = self.evidence()
        prereg = self.root / "prereg.md"
        prereg.write_text("Offline continuation fixture", encoding="utf-8")
        output = self.root / "continuation"
        with patch.object(continuation, "read_parent", return_value=evidence), \
             patch.object(base, "LocalNerRuntime", side_effect=AssertionError("model forbidden")):
            result = continuation.plan_only(evidence["parent"], output, prereg,
                                           expected_parent_plan=parent_hash, expected_parent_closure=closure_hash)
        self.assertEqual(result["model_calls"], 0)
        plan = continuation.read_json(output / "plan.json")
        self.assertEqual(plan["remaining_schedule"], self.schedule[32:])
        self.assertEqual(plan["cap"]["remaining_post_cap"], 106)
        self.assertEqual(plan["cap"]["remaining_infer_cap"], 10)
        self.assertEqual(plan["cap"]["remaining_gliner_strict_gates"], 11)
        continuation.verify_current(output, plan, check_parent=False)
        cap = continuation.read_json(output / "continuation_cap.json")
        cap["remaining_post_cap"] = 128
        base.save(output / "continuation_cap.json", cap)
        with self.assertRaisesRegex(ValueError, "frozen_sidecar_changed"):
            continuation.verify_current(output, plan, check_parent=False)

    def reference_fixture(self):
        cases = []
        for index, text in enumerate(self.texts):
            expected = {"decision": "sensitive", "spans": [{"start": 0, "end": 9, "text": "Synthetic", "category": "CUSTOMER"}]}
            cases.append({"text_index": index, "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                          "expected": {profile: copy.deepcopy(expected) for profile in base.PROFILES}})
        cases[1]["expected"][base.STRICT_CUSTOMER_RELATION] = {"decision": "not_sensitive", "spans": []}
        cases[2]["expected"][base.STRICT_CUSTOMER_RELATION] = {"decision": "needs_review", "spans": []}
        return {"schema_version": "ontology_contract_probe_evaluation_v1", "runtime_sha256": "opaque",
                "profile_contract_sha256": {p: base._digest(base.category_contract(p)) for p in base.PROFILES}, "cases": cases}

    def test_output_failure_scoring_keeps_fn_and_never_becomes_correct_negative_or_review(self):
        rows = [{"cell": {"text_index": index, "profile": base.STRICT_CUSTOMER_RELATION, "arm": base.ARMS[0]},
                 "status": "model_output_invalid", "response": {"findings": []}} for index in range(3)]
        before = copy.deepcopy(rows)
        scored, summary = continuation.score_merged(rows, self.reference_fixture(), self.texts)
        self.assertEqual(rows, before)
        group = summary[base.STRICT_CUSTOMER_RELATION + "/" + base.ARMS[0]]
        self.assertEqual((group["cells"], group["model_output_invalid"], group["fn"]), (3, 3, 1))
        self.assertEqual(group["decision_matches"], 0)
        self.assertEqual(group["processable_rate"], 0)
        self.assertEqual(group["reference_review_matches"], 0)
        self.assertEqual(group["determinate_exact_matches"], 0)
        self.assertTrue(all(row["score"]["actual_decision"] == "model_output_invalid" for row in scored))

    def execution_fixture(self, *, invalid=False, transport_failure=False):
        evidence, parent_hash, closure_hash = self.evidence()
        output = self.root / "execute"
        output.mkdir()
        plan = {"version": continuation.VERSION, "parent": evidence["parent"], "remaining_schedule": evidence["remaining"],
                "parent_plan_sha256": parent_hash, "parent_closure_sha256": closure_hash,
                "parent_artifacts_sha256": evidence["hashes"]}
        base.save(output / "plan.json", plan)
        LocalFixture.invalid_first, LocalFixture.transport_failure = invalid, transport_failure
        close = Mock(return_value={"status": "offline-test-complete"})
        with patch.object(continuation, "verify_current"), patch.object(continuation, "read_parent", return_value=evidence), \
             patch.object(base, "install_network_guard"), patch.object(base, "LocalSensitivityAgent", LocalFixture), \
             patch.object(base, "LocalNerRuntime", NerFixture), patch.object(continuation, "close_and_score", close), \
             patch.object(continuation, "print"):
            if transport_failure:
                with self.assertRaisesRegex(ValueError, "engineering_error_or_accounting_mismatch"):
                    continuation.execute(output, base.sha(output / "plan.json"))
            else:
                continuation.execute(output, base.sha(output / "plan.json"))
        return output, evidence, close

    def test_execution_calls_only_original_remaining_64_and_keeps_parent_failure(self):
        output, evidence, close = self.execution_fixture()
        rows = continuation.read_json(output / "rows.json")
        self.assertEqual([row["cell"] for row in rows], self.schedule)
        self.assertEqual(len(rows), 96)
        self.assertEqual(rows[31]["status"], "model_output_invalid")
        self.assertEqual(rows[31]["origin"], "parent")
        self.assertEqual(rows[32]["origin"], "continuation")
        self.assertEqual(LocalFixture.post_calls, 43)
        self.assertEqual(len(continuation.read_json(output / "ner_infer_capture.json")), 10)
        execution = continuation.read_json(output / "execution.json")
        self.assertEqual((execution["qwen_post_attempts_cumulative"], execution["gliner_infer_invocations_cumulative"]), (65, 16))
        self.assertEqual(close.call_count, 1)

    def test_verified_later_output_failure_is_retained_without_outer_retry(self):
        output, _, _ = self.execution_fixture(invalid=True)
        rows = continuation.read_json(output / "rows.json")
        self.assertEqual(len(rows), 96)
        self.assertEqual(rows[32]["status"], "model_output_invalid")
        self.assertEqual(rows[32]["original_status"], "engineering_error")
        self.assertEqual(rows[32]["response"]["local_calls"], 2)
        self.assertEqual(LocalFixture.post_calls, 44)

    def test_transport_failure_stops_without_scoring_or_outer_retry(self):
        output, _, close = self.execution_fixture(transport_failure=True)
        rows = continuation.read_json(output / "rows.json")
        self.assertEqual(len(rows), 33)
        self.assertEqual(rows[-1]["status"], "engineering_error")
        self.assertEqual(LocalFixture.post_calls, 1)
        close.assert_not_called()
        self.assertFalse((output / "predictions.json").exists())

    def test_all_merged_predictions_close_before_reference_and_raw_snapshot_is_unchanged(self):
        evidence, _, _ = self.evidence()
        output = self.root / "close"
        output.mkdir()
        rows = evidence["projected"] + [{"cell": cell, "status": "ok", "response": {"findings": []}} for cell in self.schedule[32:]]
        plan = {"parent": evidence["parent"], "parent_artifacts_sha256": evidence["hashes"],
                "classification_amendment": "disclosed fixture"}
        for name in ("http_transport_capture.json", "ner_infer_capture.json"): base.save(output / name, [])
        real_read = continuation.read_json
        reference = self.reference_fixture()
        reference["runtime_sha256"] = evidence["hashes"]["runtime.json"]
        touched = []
        def guarded_read(path):
            if Path(path).name == "evaluation.opaque.json":
                raw = real_read(output / "predictions.json")
                closure = real_read(output / "prediction_phase_closed.json")
                self.assertEqual(len(raw), 96)
                self.assertTrue(all("score" not in row for row in raw))
                self.assertFalse(closure["reference_parsed"])
                self.assertEqual(closure["predictions_sha256"], base.sha(output / "predictions.json"))
                touched.append(True)
                return reference
            return real_read(path)
        with patch.object(continuation, "verify_current"), patch.object(continuation, "read_json", side_effect=guarded_read), \
             patch.object(base, "read_runtime", return_value=self.texts):
            result = continuation.close_and_score(output, plan, "test-plan", rows, continuation.InheritedBudget(68.734))
        self.assertEqual(touched, [True])
        self.assertEqual(real_read(output / "predictions.json"), rows)
        self.assertNotIn("score", rows[0])
        self.assertIn("score", real_read(output / "scored_rows.json")[0])
        self.assertEqual(result["opportunities"], 96)


if __name__ == "__main__":
    unittest.main()
