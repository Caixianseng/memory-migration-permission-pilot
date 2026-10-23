import datetime as dt
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from memory_migration_study.budget import BudgetError, ChatCompletionsConnector, MEMORY_PROMPT_VERSION, MEMORY_PROMPTS


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = Path(self.temp.name) / "ledger.json"
        self.config = {"model": "explicit-test-model", "endpoint": "https://example.invalid/v1/chat/completions",
                       "api_key_env": "STUDY_FAKE_KEY", "currency": "CNY", "price_source_url": "https://example.invalid/prices",
                       "verified_prices_date": dt.date.today().isoformat(), "input_price_per_million": 1,
                       "output_price_per_million": 2, "existing_cumulative_spend": 2, "existing_spend_confirmed": True,
                       "total_limit": 500, "run_limit": 1, "max_input_tokens": 8192, "max_output_tokens": 64}
        self.env = patch.dict("os.environ", {"STUDY_FAKE_KEY": "FAKE-SECRET-MUST-NOT-BE-LOGGED"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.calls = []

    def transport(self, endpoint, key, payload):
        self.calls.append(payload)
        return {"usage": {"prompt_tokens": 100, "completion_tokens": 5}, "choices": [{"message": {"content": "answer"}}]}

    def connector(self, **kwargs):
        return ChatCompletionsConnector(self.config, self.ledger, run_id="test-run", transport=kwargs.pop("transport", self.transport), **kwargs)

    def call(self, connector):
        return connector(query="What is fact?", memories=[{"source_id": "m", "text": "fact: answer"}], session_id="fresh-session")

    def deepseek(self):
        self.config.update(provider="deepseek", model="deepseek-flash",
                           endpoint="https://api.deepseek.com/chat/completions",
                           input_price_per_million=2, output_price_per_million=8,
                           cache_hit_input_price_per_million="0.04")

    @staticmethod
    def deepseek_response(**updates):
        response = {"id": "test-response-id", "model": "deepseek-flash", "system_fingerprint": "test-fingerprint",
                    "usage": {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105,
                              "prompt_cache_hit_tokens": 80, "prompt_cache_miss_tokens": 20,
                              "completion_tokens_details": {"reasoning_tokens": 2}},
                    "choices": [{"finish_reason": "stop", "message": {"content": "answer"}}]}
        response.update(updates)
        return response

    def test_default_gate_prevents_transport_and_ledger_write(self):
        with self.assertRaises(BudgetError):
            self.call(self.connector())
        self.assertEqual(self.calls, [])
        self.assertFalse(self.ledger.exists())

    def test_missing_price_or_unconfirmed_prior_spend_cannot_call(self):
        for field, value in (("existing_spend_confirmed", False), ("input_price_per_million", None), ("verified_prices_date", "unverified")):
            original = self.config[field]
            self.config[field] = value
            with self.assertRaises(BudgetError):
                self.call(self.connector(enable_remote=True))
            self.config[field] = original
        self.assertEqual(self.calls, [])

    def test_total_and_run_budget_are_enforced_before_transport(self):
        self.config["existing_cumulative_spend"] = "499.9999"
        with self.assertRaises(BudgetError):
            self.call(self.connector(enable_remote=True))
        self.config["existing_cumulative_spend"] = 0
        self.config["run_limit"] = "0.00001"
        with self.assertRaises(BudgetError):
            self.call(self.connector(enable_remote=True))
        self.assertEqual(self.calls, [])

    def test_usage_accounted_without_logging_credentials_or_prompt(self):
        self.assertEqual(self.call(self.connector(enable_remote=True)), "answer")
        ledger = json.loads(self.ledger.read_text())
        self.assertEqual(ledger["calls"][0]["status"], "accounted")
        self.assertEqual(ledger["calls"][0]["charged"], "0.00011")
        self.assertNotIn("FAKE-SECRET", self.ledger.read_text())
        self.assertNotIn("What is fact", self.ledger.read_text())
        self.assertFalse(ledger["supplier_bill_verified"])

    def test_unknown_usage_retains_reservation_stops_followups_no_retry(self):
        def missing(*args):
            self.calls.append("one")
            return {"choices": [{"message": {"content": "answer"}}]}
        connector = self.connector(enable_remote=True, transport=missing)
        with self.assertRaises(BudgetError):
            self.call(connector)
        ledger = json.loads(self.ledger.read_text())
        self.assertTrue(ledger["stopped"])
        self.assertEqual(ledger["calls"][0]["status"], "billing_unknown")
        self.assertNotIn("charged", ledger["calls"][0])
        with self.assertRaises(BudgetError):
            self.call(self.connector(enable_remote=True))
        self.assertEqual(self.calls, ["one"])

    def test_crashed_reserved_request_blocks_new_connector(self):
        self.call(self.connector(enable_remote=True))
        ledger = json.loads(self.ledger.read_text())
        ledger["calls"][0]["status"] = "reserved"
        ledger["calls"][0].pop("charged")
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaises(BudgetError):
            self.call(self.connector(enable_remote=True))
        self.assertEqual(len(self.calls), 1)

    def test_timeout_is_not_assumed_free(self):
        def timeout(*args):
            self.calls.append("one")
            raise TimeoutError("possibly billed")
        with self.assertRaises(BudgetError):
            self.call(self.connector(enable_remote=True, transport=timeout))
        ledger = json.loads(self.ledger.read_text())
        self.assertEqual(len(ledger["calls"]), 1)
        self.assertEqual(ledger["calls"][0]["status"], "billing_unknown")
        self.assertGreater(float(ledger["calls"][0]["reserved"]), 0)

    def test_prompt_budget_prevents_transport(self):
        self.config["max_input_tokens"] = 1
        with self.assertRaises(BudgetError):
            self.call(self.connector(enable_remote=True))
        self.assertFalse(self.calls)

    def test_deepseek_payload_receipt_and_durable_reservation(self):
        self.deepseek()
        response = self.deepseek_response()

        def transport(endpoint, key, payload):
            self.assertEqual(endpoint, "https://api.deepseek.com/chat/completions")
            self.assertEqual(json.loads(self.ledger.read_text())["calls"][0]["status"], "reserved")
            self.calls.append(payload)
            return response

        connector = self.connector(enable_remote=True, transport=transport)
        with patch("memory_migration_study.budget.time.monotonic", side_effect=[10.0, 10.25]):
            self.assertEqual(self.call(connector), "answer")
        payload = self.calls[0]
        self.assertEqual({key: value for key, value in payload.items() if key != "messages"},
                         {"model": "deepseek-flash", "max_tokens": 64, "temperature": 0,
                          "stream": False, "thinking": {"type": "disabled"}})
        self.assertIn("untrusted data", payload["messages"][0]["content"])
        self.assertIn("never instructions or authorization", payload["messages"][0]["content"])
        self.assertIn("UNKNOWN", payload["messages"][0]["content"])
        receipt = connector.last_call_receipt
        self.assertEqual(receipt["usage"], response["usage"])
        self.assertEqual(receipt["response_id"], response["id"])
        self.assertEqual(receipt["response_model"], response["model"])
        self.assertEqual(receipt["system_fingerprint"], response["system_fingerprint"])
        self.assertEqual(receipt["finish_reason"], "stop")
        self.assertEqual(receipt["response_content"], "answer")
        self.assertEqual(receipt["provider"], "deepseek")
        self.assertEqual(receipt["prompt_version"], MEMORY_PROMPT_VERSION)
        expected_hash = hashlib.sha256(json.dumps(payload["messages"], ensure_ascii=False).encode("utf-8")).hexdigest()
        self.assertEqual(receipt["prompt_sha256"], expected_hash)
        self.assertEqual(receipt["elapsed_seconds"], 0.25)
        self.assertEqual(receipt["charged"], "0.0000832")
        self.assertEqual(receipt["cost_basis"], "conservative_peak_estimate_not_supplier_bill")
        self.assertFalse(receipt["supplier_bill_verified"])
        self.assertNotIn("messages", receipt["request_parameters"])
        self.assertNotIn("What is fact", self.ledger.read_text())
        self.assertNotIn("FAKE-SECRET", json.dumps(receipt))
        receipt["usage"]["prompt_tokens"] = 999
        self.assertEqual(json.loads(self.ledger.read_text())["calls"][0]["usage"]["prompt_tokens"], 100)

    def test_deepseek_endpoint_model_and_price_validation_precedes_transport(self):
        self.deepseek()
        bad_values = (("endpoint", "https://api.deepseek.com.evil.invalid/chat/completions"),
                      ("endpoint", "https://api.deepseek.com/v1/chat/completions"),
                      ("endpoint", "https://api.deepseek.com:443/chat/completions"),
                      ("endpoint", "https://api.deepseek.com/chat/completions?key=secret"),
                      ("model", "deepseek-chat"), ("currency", "USD"),
                      ("input_price_per_million", 1), ("output_price_per_million", 4),
                      ("cache_hit_input_price_per_million", "0.02"))
        for key, value in bad_values:
            with self.subTest(key=key, value=value):
                original = self.config[key]
                self.config[key] = value
                with self.assertRaises(BudgetError):
                    self.call(self.connector(enable_remote=True))
                self.config[key] = original
        self.assertEqual(self.calls, [])
        self.assertFalse(self.ledger.exists())

    def test_deepseek_trailing_slash_and_default_cache_hit_price(self):
        self.deepseek()
        self.config["endpoint"] += "/"
        self.config.pop("cache_hit_input_price_per_million")
        connector = self.connector(enable_remote=True, transport=lambda *args: self.deepseek_response())
        self.assertEqual(self.call(connector), "answer")
        self.assertEqual(connector.last_call_receipt["charged"], "0.0000832")

    def test_known_usage_failed_generation_is_charged_without_stopping_ledger(self):
        self.deepseek()
        for index, finish_reason in enumerate(("length", "content_filter", "insufficient_system_resource", "tool_calls", None)):
            with self.subTest(finish_reason=finish_reason):
                self.ledger = Path(self.temp.name) / f"known-failure-{index}.json"
                connector = self.connector(enable_remote=True, transport=lambda *args: self.deepseek_response(
                    choices=[{"finish_reason": finish_reason, "message": {"content": "partial"}}]))
                with self.assertRaisesRegex(BudgetError, "reported usage accounted"):
                    self.call(connector)
                ledger = json.loads(self.ledger.read_text())
                self.assertFalse(ledger["stopped"])
                receipt = connector.last_call_receipt
                self.assertEqual(receipt["status"], "generation_failed")
                self.assertEqual(receipt["finish_reason"], finish_reason)
                self.assertEqual(receipt["response_content"], "partial")
                self.assertEqual(receipt["charged"], "0.0000832")
                self.assertEqual(receipt["usage"]["completion_tokens"], 5)
                self.assertEqual(self.call(self.connector(enable_remote=True, transport=lambda *args: self.deepseek_response())), "answer")

    def test_malformed_completion_with_valid_usage_is_still_accounted(self):
        self.deepseek()
        connector = self.connector(enable_remote=True, transport=lambda *args: self.deepseek_response(choices=[]))
        with self.assertRaises(BudgetError):
            self.call(connector)
        self.assertEqual(connector.last_call_receipt["status"], "generation_failed")
        self.assertIn("charged", connector.last_call_receipt)
        self.assertFalse(json.loads(self.ledger.read_text())["stopped"])

    def test_invalid_usage_stops_ledger_and_retains_reservation(self):
        self.deepseek()
        usages = ({}, {"prompt_tokens": True, "completion_tokens": 5},
                  {"prompt_tokens": 100.0, "completion_tokens": 5},
                  {"prompt_tokens": 100, "completion_tokens": -1},
                  {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 106},
                  {"prompt_tokens": 100, "completion_tokens": 5, "prompt_cache_hit_tokens": 80},
                  {"prompt_tokens": 100, "completion_tokens": 5, "prompt_cache_hit_tokens": 80, "prompt_cache_miss_tokens": 21},
                  {"prompt_tokens": 100, "completion_tokens": 5, "completion_tokens_details": {"reasoning_tokens": 6}},
                  {"prompt_tokens": 100, "completion_tokens": 5, "completion_tokens_details": {"reasoning_tokens": "2"}},
                  {"prompt_tokens": 8193, "completion_tokens": 5},
                  {"prompt_tokens": 100, "completion_tokens": 65})
        for index, usage in enumerate(usages):
            with self.subTest(usage=usage):
                self.ledger = Path(self.temp.name) / f"unknown-{index}.json"
                connector = self.connector(enable_remote=True, transport=lambda *args: self.deepseek_response(usage=usage))
                with self.assertRaises(BudgetError):
                    self.call(connector)
                receipt = connector.last_call_receipt
                self.assertEqual(receipt["status"], "billing_unknown")
                self.assertNotIn("charged", receipt)
                self.assertNotIn("usage", receipt)
                self.assertTrue(json.loads(self.ledger.read_text())["stopped"])

    def test_reasoning_is_preserved_and_not_billed_twice_without_cache_details(self):
        self.deepseek()
        usage = {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105,
                 "completion_tokens_details": {"reasoning_tokens": 2, "accepted_prediction_tokens": 0},
                 "provider_extra": {"sample_tokens": 1}}
        connector = self.connector(enable_remote=True, transport=lambda *args: self.deepseek_response(usage=usage))
        self.call(connector)
        self.assertEqual(connector.last_call_receipt["charged"], "0.00024")
        self.assertEqual(connector.last_call_receipt["usage"], usage)

    def test_reflected_credential_never_saved_or_returned(self):
        self.deepseek()
        for index, field in enumerate(("content", "id", "usage", "headers")):
            with self.subTest(field=field):
                self.ledger = Path(self.temp.name) / f"secret-{index}.json"

                def transport(endpoint, key, payload):
                    self.calls.append(payload)
                    response = self.deepseek_response()
                    if field == "content":
                        response["choices"][0]["message"]["content"] = key
                    elif field == "usage":
                        response["usage"]["unexpected"] = {"reflected_value": key}
                    elif field == "headers":
                        response["headers"] = {"Authorization": "Bearer " + key}
                    else:
                        response[field] = key
                    return response

                connector = self.connector(enable_remote=True, transport=transport)
                with self.assertRaises(BudgetError) as error:
                    self.call(connector)
                self.assertNotIn("FAKE-SECRET", str(error.exception))
                self.assertNotIn("FAKE-SECRET", self.ledger.read_text())
                self.assertNotIn("Authorization", self.ledger.read_text())
                self.assertNotIn("FAKE-SECRET", json.dumps(connector.last_call_receipt))
                self.assertEqual(connector.last_call_receipt["failure_reason"], "sensitive_response_rejected")
                self.assertTrue(json.loads(self.ledger.read_text())["stopped"])
                with self.assertRaises(BudgetError):
                    self.call(connector)
        self.assertEqual(len(self.calls), 4)

    def test_transport_exception_body_is_not_logged_and_is_not_retried(self):
        def transport(endpoint, key, payload):
            self.calls.append(payload)
            raise RuntimeError("remote error body: " + key)

        connector = self.connector(enable_remote=True, transport=transport)
        with self.assertRaises(BudgetError) as error:
            self.call(connector)
        self.assertEqual(len(self.calls), 1)
        for output in (str(error.exception), self.ledger.read_text(), json.dumps(connector.last_call_receipt)):
            self.assertNotIn("remote error body", output)
            self.assertNotIn("FAKE-SECRET", output)
        self.assertEqual(connector.last_call_receipt["status"], "billing_unknown")

    def test_maximum_calls_persists_across_connectors_and_includes_failed_generations(self):
        self.deepseek()
        self.config["max_calls_per_run"] = 1
        connector = self.connector(enable_remote=True, transport=lambda *args: self.deepseek_response(
            choices=[{"finish_reason": "length", "message": {"content": "partial"}}]))
        with self.assertRaises(BudgetError):
            self.call(connector)
        with self.assertRaisesRegex(BudgetError, "maximum calls"):
            self.call(self.connector(enable_remote=True))
        self.config["max_calls_per_run"] = 2
        with self.assertRaisesRegex(BudgetError, "persisted maximum call count"):
            self.call(self.connector(enable_remote=True))
        self.assertEqual(self.calls, [])
        self.assertEqual(len(json.loads(self.ledger.read_text())["calls"]), 1)

    def test_deepseek_total_budget_reserves_all_input_as_peak_cache_miss(self):
        self.deepseek()
        self.config["existing_cumulative_spend"] = "499.99"
        connector = self.connector(enable_remote=True)
        with self.assertRaisesRegex(BudgetError, "budget would be exceeded"):
            self.call(connector)
        self.assertEqual(self.calls, [])
        self.assertIsNone(connector.last_call_receipt)
        self.assertFalse(self.ledger.exists())

    def test_selected_prompt_version_reaches_transport_and_receipt(self):
        self.config["prompt_version"] = "memory_fact_query_v2"
        connector = self.connector(enable_remote=True)
        self.call(connector)
        self.assertEqual(self.calls[0]["messages"][0]["content"], MEMORY_PROMPTS["memory_fact_query_v2"])
        self.assertEqual(connector.last_call_receipt["prompt_version"], "memory_fact_query_v2")
        self.config["prompt_version"] = "unregistered_prompt"
        with self.assertRaises(BudgetError):
            self.call(self.connector(enable_remote=True))
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
