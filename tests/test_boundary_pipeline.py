"""Model-free boundary integration checks using newly authored tiny fixtures."""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.boundary_detector import detect_with_boundaries, refine_detection
from memory_migration_study.privacy import (_digest, detect_sensitive, prepare_private_payload,
                                          restore_answer)
from memory_migration_study.privacy_egress import validate_outbound
from scripts import run_boundary_detection_diagnostic as runner
from scripts.run_semantic_detection_benchmark import CountingAgent


class FakeSpanAgent:
    """Exact test spans only; this instrument cannot load or call a model."""
    max_local_calls = 1

    def __init__(self, findings=None, *, fail_text=None):
        self.findings = findings or {}
        self.fail_text, self.calls = fail_text, []

    def __call__(self, **kwargs):
        if set(kwargs) != {"text", "source_id", "policy", "rule_findings"} or kwargs["rule_findings"] != []:
            raise AssertionError("unexpected_runtime_contract")
        self.calls.append(copy.deepcopy(kwargs))
        failed = kwargs["text"] == self.fail_text
        return {"status": "needs_review" if failed else "ok", "errors": ["local_failure"] if failed else [],
                "findings": copy.deepcopy(self.findings.get(kwargs["source_id"], [])),
                "local_calls": 1, "local_calls_complete": True, "elapsed_seconds": 0.0,
                "inference_counts": {"local_encoder": 1, "local_generation": 0, "unknown": 0}}

    def cache_identity(self):
        return {"kind": "fake_exact_span_instrument_not_a_model"}


class BoundaryPipelineTests(unittest.TestCase):
    def policy(self, categories=None):
        return {"version": "boundary-pipeline-test", "protected_categories":
                ["CUSTOMER"] if categories is None else categories}

    def payload(self, text, query=""):
        return {"query": query, "memories": [{"source_id": "m", "text": text}]}

    def span(self, text, quote, category="CUSTOMER", *, start=None):
        start = text.index(quote) if start is None else start
        self.assertEqual(text[start:start+len(quote)], quote)
        return {"start": start, "end": start+len(quote), "quote": quote, "category": category}

    def baseline(self, payload, policy, findings):
        agent = FakeSpanAgent(findings)
        result = detect_sensitive(payload, policy, agent=agent, mode="agent")
        self.assertEqual(result["status"], "ok", result)
        return result, agent

    def prepare(self, payload, policy, detection, authorizer=None):
        return prepare_private_payload(payload, detection, actor_id="owner", request_id="request",
            policy_version=policy["version"], sensitivity_policy=policy,
            authorizer=authorizer or (lambda sid, actor, version: sid == "m" and actor == "owner"
                                     and version == policy["version"]))

    def restore(self, answer, prepared, policy, authorizer=None, **changes):
        scope = dict(actor_id="owner", request_id="request", policy_version=policy["version"],
                     sensitivity_policy=policy, authorizer=authorizer or (lambda *args: True))
        scope.update(changes)
        return restore_answer(answer, prepared["mapping"], **scope)

    def token(self, text):
        match = re.search(r"\[PVT_[A-F0-9]{24}_[A-Z]+_[0-9]+\]", text)
        self.assertIsNotNone(match, text)
        return match.group()

    def test_failed_baseline_or_errors_never_upgrade_or_invoke_reconciler(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, _ = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        for changes in ({"status": "needs_review"}, {"errors": ["local_failure"]},
                        {"local_calls_complete": False}, {"local_calls": True}, {"local_calls": -1}):
            with self.subTest(changes=changes), patch(
                    "memory_migration_study.boundary_reconciliation.reconcile_boundaries") as reconcile:
                result = refine_detection(payload, policy, dict(base, **changes))
                self.assertEqual(result["status"], "needs_review")
                self.assertNotEqual(self.prepare(payload, policy, result)["status"], "ok")
                reconcile.assert_not_called()

    def test_detection_binding_tampering_cannot_be_rebound(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, _ = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        for field, value in (("payload_sha256", "0"*64), ("policy_sha256", "1"*64),
                             ("policy_id", "another"), ("policy_version", "other"),
                             ("protected_categories", [])):
            with self.subTest(field=field):
                result = refine_detection(payload, policy, dict(base, **{field: value}))
                self.assertEqual(result["status"], "needs_review")
        self.assertEqual(refine_detection(self.payload("Customer: Maple Labs"), policy, base)["status"], "needs_review")
        changed = dict(policy, instructions="new independently supplied business policy")
        self.assertEqual(refine_detection(payload, changed, base)["status"], "needs_review")

    def test_invalid_seed_positions_categories_and_policy_ids_block(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, _ = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        for changes in ({"start": True}, {"start": -1}, {"end": 999}, {"source_id": "unknown"},
                        {"category": "AMOUNT"}, {"policy_id": "other"}):
            broken = copy.deepcopy(base)
            broken["findings"][0].update(changes)
            with self.subTest(changes=changes):
                self.assertEqual(refine_detection(payload, policy, broken)["status"], "needs_review")

    def test_refinement_is_immutable_and_preserves_real_accounting(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, agent = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        before = copy.deepcopy((payload, policy, base))
        result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual((payload, policy, base), before)
        self.assertEqual(len(agent.calls), 1)
        for field in ("local_calls", "local_calls_complete", "agent_elapsed_seconds", "agent_observations"):
            self.assertEqual(result[field], base[field])
        self.assertEqual(result["boundary_refinement"]["new_model_calls"], 0)
        self.assertEqual(result["boundary_refinement"]["source_detection_sha256"], _digest(base))

    def test_reconciliation_failure_and_invalid_exact_output_do_not_pass(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, _ = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        invalid_quote = dict(self.span(payload["memories"][0]["text"], "Cedar Labs"), source_id="m", quote="injected")
        invalid_source = dict(invalid_quote, source_id="elsewhere")
        for reconciliation in ({"status": "needs_review", "findings": []},
                               {"status": "ok", "findings": [invalid_quote]},
                               {"status": "ok", "findings": [invalid_source]}):
            with self.subTest(result=reconciliation), patch(
                    "memory_migration_study.boundary_reconciliation.reconcile_boundaries", return_value=reconciliation):
                result = refine_detection(payload, policy, base)
                self.assertEqual(result["status"], "needs_review")
                self.assertNotEqual(self.prepare(payload, policy, result)["status"], "ok")

    def test_unexpected_reconciler_exception_is_recorded_not_material_omission(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, _ = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        with patch("memory_migration_study.boundary_reconciliation.reconcile_boundaries", side_effect=ValueError("instrumented_failure")):
            result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["local_calls"], base["local_calls"])

    def test_missing_reconciler_fields_are_recorded_not_success_or_crash(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, _ = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        with patch("memory_migration_study.boundary_reconciliation.reconcile_boundaries", return_value={"status": "ok"}):
            result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "needs_review")

    def test_same_word_key_and_real_value_is_not_globally_deleted(self):
        text, policy = "客户：客户", self.policy()
        payload = self.payload(text)
        base, _ = self.baseline(payload, policy, {"m": [self.span(text, "客户", start=3)]})
        result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "ok", result)
        reconciliation = result["boundary_refinement"]["reconciliation"]
        self.assertTrue(any(row["action"] == "field_key" for row in reconciliation["decisions"]))
        self.assertTrue(any(row["source_id"] == "m" and row["start"] <= 3 and row["end"] >= 5 for row in result["findings"]))
        prepared = self.prepare(payload, policy, result)
        self.assertEqual(prepared["status"], "ok", prepared)
        self.assertEqual(validate_outbound(payload, prepared, result, policy)["status"], "ok")
        value_token = self.token(prepared["payload"]["memories"][0]["text"].split("：")[1])
        self.assertEqual(self.restore(value_token, prepared, policy)["answer"], "客户")

    def test_crossing_amount_is_fully_masked_and_restored_as_full_literal(self):
        text, policy = "预算：人民币318,600元；状态：待批", self.policy(["AMOUNT"])
        payload = self.payload(text)
        base, _ = self.baseline(payload, policy, {"m": [self.span(text, "人民币318,600", "AMOUNT"),
                                                      self.span(text, "318,600元", "AMOUNT")]})
        result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual([(row["start"], row["end"]) for row in result["findings"]], [(3, 14)])
        prepared = self.prepare(payload, policy, result)
        self.assertEqual(prepared["status"], "ok", prepared)
        outbound = prepared["payload"]["memories"][0]["text"]
        self.assertNotIn("318,600", outbound)
        self.assertEqual(validate_outbound(payload, prepared, result, policy)["status"], "ok")
        self.assertEqual(self.restore(self.token(outbound), prepared, policy)["answer"], "人民币318,600元")

    def test_cross_next_field_requires_independent_typed_tail_coverage(self):
        text, policy = "Project: Elm Date: 2035-08-24", self.policy(["PROJECT", "DATE"])
        payload = self.payload(text)
        base, _ = self.baseline(payload, policy, {"m": [self.span(text, "Elm Date: 2035-08-24", "PROJECT"),
                                                      self.span(text, "2035-08-24", "DATE")]})
        result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "ok", result)
        prepared = self.prepare(payload, policy, result)
        self.assertEqual(prepared["status"], "ok", prepared)
        outbound = prepared["payload"]["memories"][0]["text"]
        self.assertNotIn("Elm", outbound)
        self.assertNotIn("2035-08-24", outbound)
        self.assertIn("Project:", outbound)
        self.assertIn("Date:", outbound)
        self.assertEqual(validate_outbound(payload, prepared, result, policy)["status"], "ok")
        values = {self.restore(token, prepared, policy)["answer"] for token in prepared["mapping"]._entries}
        self.assertEqual(values, {"Elm", "2035-08-24"})

    def test_uncovered_cross_field_residue_stays_blocked(self):
        text, policy = "Project: Elm Status: ready", self.policy(["PROJECT"])
        payload = self.payload(text)
        base, _ = self.baseline(payload, policy, {"m": [self.span(text, "Elm Status: ready", "PROJECT")]})
        result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "needs_review")
        self.assertNotEqual(self.prepare(payload, policy, result)["status"], "ok")

    def test_query_only_value_never_gains_memory_evidence(self):
        query, policy = "Project: Indigo", self.policy(["PROJECT"])
        payload = self.payload("Status: ready", query=query)
        base, _ = self.baseline(payload, policy, {"__query__": [self.span(query, "Indigo", "PROJECT")]})
        result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "ok", result)
        prepared = self.prepare(payload, policy, result)
        self.assertEqual(prepared["status"], "ok", prepared)
        token = self.token(prepared["payload"]["query"])
        restored = self.restore(token, prepared, policy)
        self.assertEqual(restored["status"], "blocked")
        self.assertEqual(restored["error"], "query_only_value_has_no_evidence")

    def test_current_permissions_request_scope_forged_token_and_raw_secret(self):
        text, policy = "Customer: Cedar Labs", self.policy()
        payload = self.payload(text)
        result = detect_with_boundaries(payload, policy, agent=FakeSpanAgent({"m": [self.span(text, "Cedar Labs")]}), mode="agent")
        self.assertEqual(result["status"], "ok", result)
        self.assertNotEqual(self.prepare(payload, policy, result, authorizer=lambda *args: False)["status"], "ok")
        prepared = self.prepare(payload, policy, result)
        token = self.token(prepared["payload"]["memories"][0]["text"])
        for scope in ({"actor_id": "outsider"}, {"request_id": "other-request"}):
            self.assertEqual(self.restore(token, prepared, policy, **scope)["status"], "blocked")
        self.assertEqual(self.restore(token, prepared, policy, authorizer=lambda *args: False)["status"], "blocked")
        def broken_authorizer(*args):
            raise RuntimeError("authorization_unavailable")
        self.assertEqual(self.restore(token, prepared, policy, authorizer=broken_authorizer)["status"], "blocked")
        self.assertEqual(self.restore("[PVT_"+"0"*24+"_CUSTOMER_1]", prepared, policy)["status"], "blocked")
        refused = self.restore("I refuse, but the name is Cedar Labs", prepared, policy)
        self.assertEqual(refused["status"], "blocked")
        self.assertEqual(refused["error"], "raw_protected_value_in_answer")
        with self.assertRaises(TypeError):
            json.dumps(prepared["mapping"])

    def test_reserved_input_token_cannot_be_laundered_by_refinement(self):
        payload, policy = self.payload("Customer: [PVT_"+"0"*24+"_CUSTOMER_1]"), self.policy()
        result = detect_with_boundaries(payload, policy, agent=FakeSpanAgent(), mode="combined")
        self.assertEqual(result["status"], "needs_review")
        self.assertNotEqual(self.prepare(payload, policy, result)["status"], "ok")

    def test_explicit_current_registry_still_protects_a_recognized_field_key(self):
        text = "Status: ready"
        policy = dict(self.policy(["PROJECT"]), entity_registry=[{"value": "Status", "category": "PROJECT"}])
        payload = self.payload(text)
        result = detect_with_boundaries(payload, policy, agent=FakeSpanAgent(), mode="combined")
        self.assertEqual(result["status"], "ok", result)
        decisions = result["boundary_refinement"]["reconciliation"]["decisions"]
        self.assertTrue(any(row["action"] == "field_key" for row in decisions))
        self.assertTrue(any(row["source_id"] == "m" and row["start"] == 0 and row["end"] == 6
                            and row["category"] == "PROJECT" for row in result["findings"]))
        prepared = self.prepare(payload, policy, result)
        self.assertEqual(prepared["status"], "ok", prepared)
        self.assertNotIn("Status", prepared["payload"]["memories"][0]["text"])
        self.assertEqual(validate_outbound(payload, prepared, result, policy)["status"], "ok")

    def test_method_string_cannot_create_a_registry_declaration(self):
        text, policy = "Customer: Open Labs", self.policy()
        payload = self.payload(text)
        base, _ = self.baseline(payload, policy, {"m": [self.span(text, "Customer")]})
        base["findings"][0]["method"] = "registry"
        result = refine_detection(payload, policy, base)
        self.assertEqual(result["status"], "ok", result)
        # The currently supplied registry is empty: a caller's method label
        # cannot override the independently parsed key occurrence.
        self.assertEqual(result["findings"], [])

    def test_noop_rehost_does_not_upgrade_bad_payload_or_policy_binding(self):
        payload, policy = self.payload("Customer: Cedar Labs"), self.policy()
        base, _ = self.baseline(payload, policy, {"m": [self.span(payload["memories"][0]["text"], "Cedar Labs")]})
        for changes in ({"payload_sha256": "f"*64}, {"policy_sha256": "f"*64},
                        {"policy_version": "wrong"}, {"policy_id": "wrong"},
                        {"protected_categories": []}, {"errors": ["local_failure"]},
                        {"local_calls_complete": False}):
            with self.subTest(changes=changes):
                result = runner.rehost(payload, policy, dict(base, **changes))
                self.assertNotEqual(result["status"], "ok")


class BoundaryRunnerTests(unittest.TestCase):
    def fixture(self, folder):
        runtime = [
            {"case_id": "good", "language": "en", "template_family": "fixture-a", "policy":
             {"version": "runner-test", "protected_categories": ["CUSTOMER"]},
             "payload": {"query": "", "memories": [{"source_id": "m", "text": "Customer: Rowan Labs"}]}},
            {"case_id": "failure", "language": "en", "template_family": "fixture-b", "policy":
             {"version": "runner-test", "protected_categories": ["CUSTOMER"]},
             "payload": {"query": "", "memories": [{"source_id": "m", "text": "Customer: Fallen Labs"}]}},
            {"case_id": "public", "language": "zh", "template_family": "fixture-c", "policy":
             {"version": "runner-test", "protected_categories": []},
             "payload": {"query": "", "memories": [{"source_id": "m", "text": "状态：正常"}]}}]
        labels = {case["case_id"]: {"findings": []} for case in runtime}
        for case, quote in zip(runtime[:2], ("Rowan Labs", "Fallen Labs")):
            text = case["payload"]["memories"][0]["text"]
            start = text.index(quote)
            labels[case["case_id"]]["findings"].append({"source_id": "m", "start": start,
                "end": start+len(quote), "category": "CUSTOMER"})
        saved = []
        for case in runtime:
            observer = CountingAgent(FakeSpanAgent(fail_text="Customer: Fallen Labs"), "local_encoder")
            detection = detect_sensitive(case["payload"], case["policy"], mode="combined", agent=observer)
            accounting = observer.accounting(detection)
            saved.append({"case_id": case["case_id"], "arm": "gliner_combined", "detection": detection,
                          "accounting": accounting, "encoder_invocations": accounting["inference_counts"]["local_encoder"],
                          "qwen_generations": accounting["inference_counts"]["local_generation"]})
        folder.mkdir()
        for name, value in (("runtime.json", runtime), ("rows.json", saved), ("evaluation.json", labels)):
            (folder/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
        return runtime, labels

    def assert_denominators(self, report, output):
        self.assertEqual(report["material_count"], 3)
        rows = json.loads((output/"rows.json").read_text(encoding="utf-8"))
        self.assertEqual(len(rows), 9)
        for arm in runner.ARMS:
            metrics = report["arms"][arm]
            self.assertEqual(metrics["materials"], 3)
            self.assertEqual(metrics["gold_spans"], 2)
            self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (1, 0, 1))
            self.assertEqual(metrics["needs_review"], 1)
            self.assertEqual(metrics["unmasked_or_not_ready_spans"], 1)
            self.assertEqual(metrics["fully_masked_spans"], 1)
        self.assertEqual(report["overall_effectiveness_acceptance"], "not_established")
        self.assertEqual(report["cloud_calls"], 0)
        self.assertTrue(report["baseline_call_accounting_complete"])
        self.assertTrue(report["source_unchanged"])
        serialized = (output/"rows.json").read_text(encoding="utf-8")
        self.assertNotIn('"mapping"', serialized)
        self.assertNotIn('"_entries"', serialized)
        self.assertNotIn('"_nonce"', serialized)
        return rows

    def test_fresh_fake_runner_preserves_failures_gold_phase_and_shared_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root/"source", root/"output"
            self.fixture(source)
            fake = FakeSpanAgent(fail_text="Customer: Fallen Labs")
            gold_text = (source/"evaluation.json").read_text(encoding="utf-8")
            real_loads, observations = json.loads, []
            def guarded_loads(value, *args, **kwargs):
                if value == gold_text:
                    self.assertEqual(len(fake.calls), 2)
                    fixed_rows = real_loads((output/"rows.json").read_text(encoding="utf-8"))
                    self.assertEqual(len(fixed_rows), 9)
                    self.assertTrue(all("prepared_payload" in row for row in fixed_rows))
                    observations.append("labels_after_all_preparation")
                return real_loads(value, *args, **kwargs)
            with patch("memory_migration_study.ner_detector.LocalNerRuntime", side_effect=AssertionError("no_model_loading")) as model, \
                 patch("socket.socket.connect", side_effect=AssertionError("no_network")) as network, \
                 patch.object(runner.json, "loads", side_effect=guarded_loads):
                report = runner.run(source, output, fresh=True, detector=fake)
            model.assert_not_called()
            network.assert_not_called()
            self.assertEqual(observations, ["labels_after_all_preparation"])
            self.assertEqual(len(fake.calls), 2)
            self.assertEqual(report["new_inference_counts"], {"local_encoder": 2, "local_generation": 0})
            self.assertEqual(report["historical_encoder_calls_referenced_once"], 0)
            rows = self.assert_denominators(report, output)
            for row in rows:
                self.assertEqual(row["detection"]["local_calls"], 0 if row["case_id"] == "public" else 1)

    def test_saved_runner_has_no_new_detector_calls_and_complete_denominators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root/"source", root/"output"
            self.fixture(source)
            with patch("memory_migration_study.ner_detector.LocalNerRuntime", side_effect=AssertionError("no_model_loading")) as model, \
                 patch("socket.socket.connect", side_effect=AssertionError("no_network")) as network:
                report = runner.run(source, output, fresh=False, detector=lambda **kwargs: self.fail("saved_mode_invoked_model"))
            model.assert_not_called()
            network.assert_not_called()
            self.assertEqual(report["baseline_origin"], "saved_host_findings")
            self.assertEqual(report["new_inference_counts"], {"local_encoder": 0, "local_generation": 0})
            self.assertEqual(report["historical_encoder_calls_referenced_once"], 2)
            self.assert_denominators(report, output)

    def test_unknown_inference_kind_stays_explicit_and_incomplete(self):
        class UnknownAgent(FakeSpanAgent):
            def __call__(self, **kwargs):
                result = super().__call__(**kwargs)
                result["inference_counts"] = {"local_encoder": 0, "local_generation": 0, "unknown": 1}
                return result
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root/"source", root/"output"
            self.fixture(source)
            with patch("socket.socket.connect", side_effect=AssertionError("no_network")):
                report = runner.run(source, output, fresh=True, detector=UnknownAgent(fail_text="Customer: Fallen Labs"))
            self.assertFalse(report["baseline_call_accounting_complete"])
            rows = json.loads((output/"rows.json").read_text(encoding="utf-8"))
            physical = [row["shared_baseline_accounting"] for row in rows[::3]]
            self.assertEqual(sum(item["inference_counts"]["unknown"] for item in physical), 2)
            self.assertTrue(all(not row["shared_baseline_accounting"]["complete"]
                                for row in rows if row["case_id"] != "public"))

    def test_runtime_gold_fields_and_missing_baseline_are_rejected_not_filtered(self):
        for change in ("gold_in_runtime", "missing_baseline"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output = root/"source", root/"output"
                runtime, _ = self.fixture(source)
                if change == "gold_in_runtime":
                    runtime[0]["expected_answer"] = "scoring_only_never_runtime"
                    (source/"runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
                else:
                    (source/"rows.json").write_text("[]", encoding="utf-8")
                with self.assertRaises(ValueError):
                    runner.run(source, output, fresh=False)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
