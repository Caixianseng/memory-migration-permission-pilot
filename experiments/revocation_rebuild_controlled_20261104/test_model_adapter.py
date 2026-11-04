"""Offline evidence and failure-boundary tests. No real providers or sockets."""
import copy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from .model_adapter import AdapterError, ControlledFlashClient, ENDPOINT, encoded, http_transport, parse

KEY = "FAKE-KEY-NEVER-PERSIST-012345"


def reply():
    return {"id": "fake-response-1", "model": "V4.1-Flash-1017", "system_fingerprint": "fake-fingerprint",
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
                      "prompt_cache_hit_tokens": 60, "prompt_cache_miss_tokens": 40,
                      "completion_tokens_details": {"reasoning_tokens": 0}},
            "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "memory text"}}]}


class ControlledFlashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "budget"
        self.config = {"model": "deepseek-flash", "endpoint": ENDPOINT, "budget_cap_cny": "1",
                       "prior_budget_reference": "historical_window_not_reset"}
        self.calls = []
        self.response = reply()
        self.wallet = lambda: {"wallet_cny": "1", "observed_at_unix": time.time(), "account_sha256": "a" * 64}
        guard = patch("socket.create_connection", side_effect=AssertionError("network forbidden"))
        guard.start()
        self.addCleanup(guard.stop)

    def transport(self, endpoint, key, body):
        self.calls.append(body)
        self.assertEqual(endpoint, ENDPOINT)
        self.assertEqual(key, KEY)
        self.assertTrue((self.root / "exclusive.runlock").exists())
        self.assertTrue((self.root / "job-source1" / "reservation.json").exists())
        self.assertTrue((self.root / "job-source1" / "dispatch.json").exists())
        return 200, encoded(self.response)

    def client(self, **kwargs):
        return ControlledFlashClient(self.config, self.root, lambda: KEY,
                                     kwargs.pop("wallet", self.wallet), kwargs.pop("transport", self.transport))

    def generate(self, client=None):
        return (client or self.client()).generate([{"role": "user", "content": "Only this source. 中文"}],
                                                  "source1", 2048, "source")

    def test_reservation_precedes_single_http_and_receipt_binds_exact_bytes(self):
        client = self.client()
        result = self.generate(client)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["output"], "memory text")
        body = parse(self.calls[0])
        self.assertEqual(body["thinking"], {"type": "disabled"})
        self.assertEqual(body["stream"], False)
        self.assertNotIn("tools", body)
        self.assertEqual(result["input_token_bound"], len(self.calls[0]) + 2048)
        self.assertEqual(Decimal(result["reservation_cny"]),
                         Decimal((len(self.calls[0]) + 2048) * 2 + 2048 * 8) / 1_000_000)
        self.assertEqual(result["estimated_peak_cost_cny"], "0.00036")
        self.assertIsNone(result["actual_invoice_cny"])
        self.assertEqual(Path(result["raw_response_path"]).read_bytes(), encoded(self.response))
        self.assertEqual(client._totals()[:2], (Decimal("0.00036"), Decimal(0)))
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(KEY.encode(), path.read_bytes())

    def test_same_job_never_replays_even_from_new_client(self):
        self.generate()
        with self.assertRaisesRegex(AdapterError, "job_already"):
            self.generate(self.client())
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.root / "exclusive.runlock").exists())

    def test_transport_exception_retains_reservation_and_stops_next_job(self):
        calls = []
        def fail(*args):
            calls.append(1)
            raise TimeoutError(KEY)
        client = self.client(transport=fail)
        result = self.generate(client)
        self.assertEqual(result["status"], "billing_unknown")
        self.assertEqual(result["http_attempts"], 1)
        self.assertEqual(client._totals()[1], Decimal(result["reservation_cny"]))
        self.assertNotIn(KEY, json.dumps(result))
        with self.assertRaisesRegex(AdapterError, "run_stopped"):
            client.generate([{"role": "user", "content": "x"}], "source2", 2048, "source")
        self.assertEqual(calls, [1])

    def test_stale_wallet_and_insufficient_wallet_prevent_dispatch(self):
        for wallet in ({"wallet_cny": "1", "observed_at_unix": time.time() - 20},
                       {"wallet_cny": "0", "observed_at_unix": time.time()}):
            with self.subTest(wallet=wallet), tempfile.TemporaryDirectory() as temp:
                client = ControlledFlashClient(self.config, Path(temp), lambda: KEY, lambda: wallet,
                                               lambda *args: self.fail("must not dispatch"))
                result = self.generate(client)
                self.assertEqual(result["status"], "not_dispatched")
                self.assertEqual(result["http_attempts"], 0)
                self.assertEqual(client._totals()[1], 0)
                self.assertTrue((Path(temp) / "STOPPED.json").exists())

    def test_scalar_wallet_is_supported(self):
        result = self.generate(self.client(wallet=lambda: Decimal("1")))
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["wallet_snapshot"]["provider_supplied_current_scalar"])

    def test_budget_and_exclusive_lock_block_before_provider(self):
        self.config["budget_cap_cny"] = "0.000001"
        client = self.client(wallet=lambda: self.fail("wallet must not be called"))
        with self.assertRaisesRegex(AdapterError, "budget_cap"):
            self.generate(client)
        self.assertFalse(self.calls)
        (self.root / "exclusive.runlock").write_text("prior crashed process")
        with self.assertRaisesRegex(AdapterError, "runlock"):
            self.generate(client)

    def test_concurrent_clients_cannot_send_two_requests(self):
        entered, release = threading.Event(), threading.Event()
        calls, outcomes = [], []
        def transport(*args):
            calls.append(1)
            entered.set()
            self.assertTrue(release.wait(2))
            return 200, encoded(reply())
        first, second = self.client(transport=transport), self.client(transport=transport)
        thread = threading.Thread(target=lambda: outcomes.append(self.generate(first)))
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            with self.assertRaisesRegex(AdapterError, "runlock"):
                second.generate([{"role": "user", "content": "x"}], "source2", 2048, "source")
        finally:
            release.set()
            thread.join(2)
        self.assertEqual(calls, [1])
        self.assertEqual(outcomes[0]["status"], "ok")

    def test_truncation_thinking_tools_empty_and_invalid_usage_stop(self):
        cases = []
        for edit in (lambda r: r["choices"][0].update(finish_reason="length"),
                     lambda r: r["choices"][0]["message"].update(reasoning_content="thinking"),
                     lambda r: r["choices"][0]["message"].update(tool_calls=[{"id": "x"}]),
                     lambda r: r["choices"][0]["message"].update(content=""),
                     lambda r: r["usage"]["completion_tokens_details"].update(reasoning_tokens=1),
                     lambda r: r["usage"].update(prompt_tokens=100000, total_tokens=100020)):
            value = reply()
            edit(value)
            cases.append(value)
        for response in cases:
            with self.subTest(response=response), tempfile.TemporaryDirectory() as temp:
                client = ControlledFlashClient(self.config, Path(temp), lambda: KEY, self.wallet,
                                               lambda *args: (200, encoded(response)))
                result = self.generate(client)
                self.assertEqual(result["status"], "billing_unknown")
                self.assertIsNone(result["output"])
                self.assertEqual(result["raw_response"], response)
                self.assertEqual(client._totals()[1], Decimal(result["reservation_cny"]))
                self.assertTrue((Path(temp) / "STOPPED.json").exists())

    def test_credential_reflection_never_persists_raw_or_exception(self):
        self.response["choices"][0]["message"]["content"] = "leak " + KEY
        result = self.generate()
        self.assertEqual(result["error"], "credential_reflection")
        self.assertIsNone(result["raw_response"])
        self.assertFalse((self.root / "job-source1" / "response.raw.json").exists())
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(KEY.encode(), path.read_bytes())

    def test_malformed_http_and_frozen_configuration_are_preserved(self):
        result = self.generate(self.client(transport=lambda *args: (502, b"not valid json")))
        self.assertEqual(result["status"], "billing_unknown")
        self.assertEqual(Path(result["raw_response_path"]).read_bytes(), b"not valid json")
        changed = copy.deepcopy(self.config)
        changed["budget_cap_cny"] = "2"
        with self.assertRaisesRegex(AdapterError, "frozen_config_changed"):
            ControlledFlashClient(changed, self.root, lambda: KEY, self.wallet, self.transport)

    def test_default_http_has_exact_host_path_body_and_one_attempt(self):
        class Response:
            status = 200
            def read(self, size):
                return encoded(reply())
        with patch("http.client.HTTPSConnection") as constructor:
            connection = constructor.return_value
            connection.getresponse.return_value = Response()
            status, raw = http_transport(ENDPOINT, KEY, b"exact-body")
            constructor.assert_called_once_with("api.deepseek.com", timeout=120)
            connection.request.assert_called_once_with("POST", "/chat/completions", body=b"exact-body",
                headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
            connection.close.assert_called_once()
            self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
