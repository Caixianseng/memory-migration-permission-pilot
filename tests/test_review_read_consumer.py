"""Real authorization and placeholder recovery; only native/model IO is fake."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.local_detector import MODEL
from memory_migration_study.review_read_consumer import ReadChainConsumer


class ReviewConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.text = "TEST_ONLY_RESTRICTED_813"
        self.principal = {"user_id": "user.alice", "agent_id": "agent.reader"}
        self.calls = []

    def current_read(self, principal, oid):
        self.calls.append((deepcopy(principal), oid))
        if principal != self.principal:
            return {"decision": "deny"}
        return {"decision": "allow", "content_sha256": hashlib.sha256(self.text.encode()).hexdigest()}

    def context(self, condition="N", *, allowed=True, phase="initial", oid="fact.readonly"):
        return {"direction": "webui_to_cognee", "phase": phase, "condition": condition,
            "object_id": oid, "principal_id": "alice.reader", "principal": deepcopy(self.principal),
            "read_allowed": allowed, "delivery_status": "available" if allowed else "denied",
            "memory_text": self.text if condition != "none" and allowed else None,
            "current_source_read": self.current_read}

    def test_fixed_consumer_uses_actual_masked_payload_and_recovers_after_current_checks(self):
        consumer = ReadChainConsumer(self.root / "fixed")
        receipt = consumer(self.context())
        self.assertEqual(receipt["status"], "ok", receipt)
        self.assertEqual(receipt["model_calls"], 0)
        self.assertEqual(consumer.predictions[0]["final_answer"], self.text)
        self.assertGreaterEqual(len(self.calls), 4)
        self.assertNotIn("raw_response", receipt)
        self.assertNotIn("final_answer", receipt)
        self.assertNotIn("mapping", json.dumps(receipt))

    def test_no_memory_abstention_is_not_legal_task_correctness(self):
        consumer = ReadChainConsumer(self.root / "none")
        consumer(self.context("source"))
        consumer(self.context("none"))
        report = consumer.finalize()
        self.assertEqual(report["groups"]["webui_to_cognee:source"]["correct"], 1)
        control = report["groups"]["webui_to_cognee:none"]
        self.assertEqual((control["legal"], control["correct"], control["control_abstentions"]), (1, 0, 1))
        self.assertTrue((consumer.output / "prediction_phase_closed.json").is_file())

    def test_denied_context_never_calls_transport_or_current_source(self):
        consumer = ReadChainConsumer(self.root / "denied", sender=lambda raw: self.fail("no transport"))
        receipt = consumer(self.context(allowed=False))
        self.assertEqual(receipt["failure_class"], "policy_denied")
        self.assertEqual(self.calls, [])

    def test_source_unavailability_is_unknown_and_preserved(self):
        consumer = ReadChainConsumer(self.root / "unknown")
        ctx = self.context()
        ctx["current_source_read"] = lambda *args: {"decision": "unknown"}
        receipt = consumer(ctx)
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["authorization_decision"], "unknown")
        report = consumer.finalize()
        self.assertEqual(report["groups"]["webui_to_cognee:N"]["unknown_or_failed"], 1)

    def test_local_mode_observes_wire_bytes_but_does_not_claim_native_sdk_observation(self):
        wires = []
        def sender(raw):
            wires.append(raw)
            self.assertNotIn(self.text.encode(), raw)
            body = json.loads(raw)
            payload = json.loads(body["messages"][1]["content"])
            self.assertEqual(payload["fact_cards"][0]["answer_id"], "F1")
            return {"done": True, "done_reason": "stop", "model": MODEL,
                    "message": {"content": '{"answer_id":"F1"}'}}
        with patch("memory_migration_study.review_read_consumer.LocalSensitivityAgent.health", return_value={"test_only": True}):
            consumer = ReadChainConsumer(self.root / "local", model_mode="local", max_model_calls=1, sender=sender)
        receipt = consumer(self.context())
        self.assertEqual(receipt["status"], "ok", receipt)
        self.assertEqual(receipt["model_calls"], 1)
        self.assertTrue(receipt["full_http_request_observed"])
        self.assertFalse(receipt["native_sdk_full_request_observed"])
        self.assertEqual(len(wires), 1)
        self.assertEqual(consumer(self.context())["failure_class"], "model_budget_exhausted")

    def test_same_native_chain_callback_current_authority_and_recovery_full_denominators(self):
        from tests import test_review_native_read_chain as fixture
        setup = fixture.ReviewNativeReadChainTests()
        setup.setUp()
        self.addCleanup(setup.doCleanups)
        consumer = ReadChainConsumer(self.root / "integrated")
        result, registry, out = setup.execute(consumer=consumer)
        self.assertEqual(result["status"], "fake_protocol_completed", result["failure"])
        self.assertEqual(result["consumer_calls"], 192)
        report = consumer.finalize()
        self.assertEqual(len(consumer.predictions), 192)
        for name, group in report["groups"].items():
            self.assertEqual(group["registered"], 24)
            self.assertEqual(group["legal"], 7)
            self.assertEqual(group["policy_denied"], 17)
            self.assertEqual(group["unknown_or_failed"], 0)
            self.assertEqual(group["correct"], 0 if name.endswith(":none") else 7)
        for name, native in registry.items():
            self.assertLessEqual(len(native.requests), 200, name)
        from scripts.run_review_read_integration import score_after_close
        scores = score_after_close(out, consumer, "fixed")
        self.assertEqual(scores["all_task_arm_rows"], 192)
        self.assertEqual(scores["arms"]["N"]["legal_task_correct"], 14)
        self.assertEqual(scores["arms"]["G"]["legal_task_correct"], 14)
        self.assertEqual(scores["arms"]["none"]["legal_task_correct"], 0)
        self.assertIsNone(scores["comparisons"]["G_vs_N"]["legal_task"]["cluster_bootstrap_interval_95"])

    def test_flat_id_cannot_create_evidence_or_hide_abstention_and_bad_output(self):
        cases = [("none", '{"answer_id":"F1"}', "blocked", "selection_has_no_memory_evidence"),
                 ("N", '{"answer_id":"F2"}', "blocked", "answer_schema_invalid"),
                 ("N", '{"answer_id":"UNKNOWN","answer_id":"F1"}', "blocked", "answer_schema_invalid"),
                 ("N", '{"answer_id":"UNKNOWN"}', "ok", None)]
        for i, (condition, reply, status, error) in enumerate(cases):
            with self.subTest(condition=condition, reply=reply):
                def sender(raw):
                    return {"model": MODEL, "done": True, "done_reason": "stop", "message": {"content": reply}}
                with patch("memory_migration_study.review_read_consumer.LocalSensitivityAgent.health", return_value={"test_only": True}):
                    consumer = ReadChainConsumer(self.root / ("selection-" + str(i)), model_mode="local",
                                                 max_model_calls=1, sender=sender)
                receipt = consumer(self.context(condition))
                self.assertEqual(receipt["status"], status)
                self.assertEqual(receipt["error"], error)
                if condition == "N" and status == "ok":
                    self.assertEqual(consumer.predictions[0]["final_answer"], "UNKNOWN")
                    self.assertEqual(receipt["failure_class"], "model_unknown")

    def test_invalid_usage_is_recorded_before_json_receipt_and_does_not_crash_finalize(self):
        for index, value in enumerate((float("nan"), float("inf"), True, -1, 65, 1.5)):
            with self.subTest(value=value):
                def sender(raw):
                    return {"model": MODEL, "done": True, "done_reason": "stop", "eval_count": value,
                            "message": {"content": '{"answer_id":"F1"}'}}
                with patch("memory_migration_study.review_read_consumer.LocalSensitivityAgent.health", return_value={"test_only": True}):
                    consumer = ReadChainConsumer(self.root / ("bad-usage-" + str(index)), model_mode="local",
                                                 max_model_calls=1, sender=sender)
                receipt = consumer(self.context())
                self.assertEqual(receipt["status"], "error")
                self.assertEqual(receipt["model_calls"], 1)
                self.assertEqual(receipt["failure_class"], "model_response_protocol_error")
                summary = consumer.finalize()
                self.assertEqual(summary["groups"]["webui_to_cognee:N"]["unknown_or_failed"], 1)


if __name__ == "__main__":
    unittest.main()
