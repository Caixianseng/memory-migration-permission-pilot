import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from memory_migration_study.budget import BudgetError, ChatCompletionsConnector


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


if __name__ == "__main__":
    unittest.main()
