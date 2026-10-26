"""Final request-byte contracts with fake senders; no network or models."""
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from memory_migration_study.private_request_boundary import (
    BoundaryTransportError, LoopbackJSONSender, PrivateRequestBoundary, SCOPE)


MODEL = "qwen3:4b-instruct-2507-q4_K_M"
SECRET = "PRIVATE-CUSTOMER-7391"
MASK = "[PVT_AAAAAAAAAAAAAAAAAAAAAAAA_CUSTOMER_1]"
MESSAGES = [{"role": "system", "content": "Answer only from supplied masked facts."},
            {"role": "user", "content": "Customer: " + MASK + ". Return that customer."}]
OPTIONS = {"num_ctx": 4096, "num_predict": 64, "temperature": 0, "seed": 42}


class RequestBoundaryTests(unittest.TestCase):
    def setUp(self):
        network = patch("socket.create_connection", side_effect=AssertionError("test must not connect"))
        network.start()
        self.addCleanup(network.stop)
        self.body = {"model": MODEL, "messages": deepcopy(MESSAGES), "stream": False,
                     "options": dict(OPTIONS)}
        self.boundary = PrivateRequestBoundary(deepcopy(MESSAGES), [SECRET], MODEL, 1)
        self.seen = []

    def transport(self, raw):
        self.assertIsInstance(raw, bytes)
        self.seen.append(raw)
        return {"message": {"role": "assistant", "content": MASK}}

    def blocked(self, body, code=None, boundary=None):
        result = (boundary or self.boundary).send(body, self.transport)
        self.assertEqual(result.receipt["status"], "blocked")
        if code is not None:
            self.assertEqual(result.receipt["code"], code)
        self.assertIsNone(result.response)
        self.assertFalse(result.receipt["transport_attempted"])
        self.assertFalse(result.receipt["full_request_observed"])
        self.assertEqual(self.seen, [])
        return result

    def test_complete_masked_body_and_same_bytes_are_sent_once(self):
        result = self.boundary.send(self.body, self.transport)
        self.assertEqual(result.receipt["status"], "sent")
        self.assertEqual(json.loads(self.seen[0]), self.body)
        self.assertEqual(result.receipt["request_body_sha256"], hashlib.sha256(self.seen[0]).hexdigest())
        self.assertEqual(result.receipt["request_body_bytes"], len(self.seen[0]))
        self.assertTrue(result.receipt["full_request_observed"])
        self.assertEqual(result.receipt["observation_scope"], SCOPE)
        self.assertFalse(result.receipt["sdk_request_observed"])
        self.assertFalse(result.receipt["model_invocations_verified"])
        self.assertEqual(result.response["message"]["content"], MASK)
        self.assertEqual(self.boundary.snapshot(), {"attempted": 1, "succeeded": 1, "failed": 0, "blocked": 0})

    def test_history_system_tools_or_unknown_keys_cannot_hide_registered_values(self):
        for condition in ("history", "system", "tools", "extra-key", "secret-key", "schema"):
            with self.subTest(condition=condition):
                body = deepcopy(self.body)
                boundary = self.boundary
                if condition == "history":
                    body["messages"].append({"role": "assistant", "content": SECRET})
                elif condition == "system":
                    body["messages"][0]["content"] += SECRET
                elif condition == "tools":
                    body["tools"] = [{"description": SECRET}]
                elif condition == "extra-key":
                    body["history"] = SECRET
                elif condition == "secret-key":
                    body[SECRET] = "not a message"
                else:
                    schema = {"type": "string", "description": SECRET}
                    body["format"] = schema
                    boundary = PrivateRequestBoundary(MESSAGES, [SECRET], MODEL, 1, expected_format=schema)
                self.blocked(body, "registered_sensitive_value_present", boundary)

    def test_all_extra_context_is_rejected_even_when_it_contains_no_known_value(self):
        for condition in ("history", "system", "tool-role", "tools", "unknown-field"):
            with self.subTest(condition=condition):
                body = deepcopy(self.body)
                if condition == "history":
                    body["messages"].insert(1, {"role": "assistant", "content": "extra context"})
                elif condition == "system":
                    body["messages"][0]["content"] += " extra automatic instruction"
                elif condition == "tool-role":
                    body["messages"][1]["role"] = "tool"
                elif condition == "tools":
                    body["tools"] = []
                else:
                    body["keep_alive"] = "5m"
                self.blocked(body)

    def test_literal_unicode_escapes_and_compatibility_forms_are_scanned(self):
        secret = "机密客户🔐"
        escaped = json.dumps(secret, ensure_ascii=True)[1:-1]
        for value in (secret, escaped, escaped.replace("\\", "\\\\")):
            with self.subTest(value_form=len(value)):
                messages = deepcopy(MESSAGES)
                messages[1]["content"] = value
                boundary = PrivateRequestBoundary(messages, [secret], MODEL, 1)
                body = deepcopy(self.body)
                body["messages"] = messages
                self.blocked(body, "registered_sensitive_value_present", boundary)
        messages = deepcopy(MESSAGES)
        messages[1]["content"] = "ＰＲＩＶＡＴＥ customer"
        body = deepcopy(self.body)
        body["messages"] = messages
        boundary = PrivateRequestBoundary(messages, ["private"], MODEL, 1)
        self.blocked(body, "registered_sensitive_value_present", boundary)

    def test_mutating_the_dictionary_after_validation_cannot_change_sent_bytes(self):
        real_check = self.boundary._check_bytes

        def check_and_mutate(raw):
            real_check(raw)
            self.body["messages"][1]["content"] = SECRET
            self.body["history"] = SECRET

        with patch.object(self.boundary, "_check_bytes", side_effect=check_and_mutate):
            result = self.boundary.send(self.body, self.transport)
        self.assertEqual(result.receipt["status"], "sent")
        self.assertIn(SECRET, json.dumps(self.body))
        self.assertNotIn(SECRET, self.seen[0].decode())
        self.assertEqual(json.loads(self.seen[0])["messages"], MESSAGES)
        self.assertEqual(result.receipt["request_body_sha256"], hashlib.sha256(self.seen[0]).hexdigest())

    def test_expected_context_and_format_are_frozen_against_caller_mutation(self):
        messages, schema = deepcopy(MESSAGES), {"type": "string", "enum": ["C001", "UNKNOWN"]}
        boundary = PrivateRequestBoundary(messages, [SECRET], MODEL, 1, expected_format=schema)
        body = deepcopy(self.body)
        body["format"] = deepcopy(schema)
        messages[1]["content"] = SECRET
        schema["description"] = SECRET
        result = boundary.send(body, self.transport)
        self.assertEqual(result.receipt["status"], "sent")
        self.assertNotIn(SECRET, self.seen[0].decode())

    def test_format_must_be_registered_and_match_the_host_schema(self):
        body = deepcopy(self.body)
        body["format"] = "json"
        self.blocked(body, "request_fields_not_registered")
        boundary = PrivateRequestBoundary(MESSAGES, [SECRET], MODEL, 1,
                                          expected_format={"type": "string", "enum": ["C001", "UNKNOWN"]})
        body["format"] = {"type": "string", "enum": ["C001", "UNKNOWN"], "description": "extra context"}
        self.blocked(body, "output_format_changed", boundary)

    def test_options_stream_model_and_non_json_material_fail_closed(self):
        for condition in ("tokens", "context", "temperature", "seed", "extra-option", "bool-seed", "stream", "model", "nan", "set", "non-string-key"):
            with self.subTest(condition=condition):
                body = deepcopy(self.body)
                if condition == "tokens": body["options"]["num_predict"] = 65
                elif condition == "context": body["options"]["num_ctx"] = 8192
                elif condition == "temperature": body["options"]["temperature"] = 0.1
                elif condition == "seed": body["options"]["seed"] = 2
                elif condition == "extra-option": body["options"]["stop"] = ["text"]
                elif condition == "bool-seed": body["options"]["seed"] = True
                elif condition == "stream": body["stream"] = True
                elif condition == "model": body["model"] = "other-model"
                elif condition == "nan": body["options"]["temperature"] = float("nan")
                elif condition == "set": body["options"]["extra"] = {"not", "json"}
                else: body[7] = "not a JSON key"
                self.blocked(body)

    def test_transport_failure_consumes_attempt_and_is_not_retried(self):
        calls = []

        class PrivateFailure(Exception):
            def __str__(self):
                raise AssertionError("never serialize private exception")

        def fail(raw):
            calls.append(raw)
            raise PrivateFailure(SECRET)

        result = self.boundary.send(self.body, fail)
        self.assertEqual(result.receipt["status"], "transport_failed")
        self.assertIsNone(result.response)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.boundary.snapshot(), {"attempted": 1, "succeeded": 0, "failed": 1, "blocked": 0})
        blocked = self.boundary.send(self.body, self.transport)
        self.assertEqual(blocked.receipt["code"], "transport_attempt_budget_exhausted")
        self.assertEqual(self.seen, [])
        self.assertEqual(len(calls), 1)
        self.assertNotIn(SECRET, json.dumps(result.receipt))

    def test_successful_send_cannot_be_repeated_over_the_budget(self):
        first = self.boundary.send(self.body, self.transport)
        second = self.boundary.send(self.body, self.transport)
        self.assertEqual(first.receipt["status"], "sent")
        self.assertEqual(second.receipt["code"], "transport_attempt_budget_exhausted")
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(second.receipt["counters"], {"attempted": 1, "succeeded": 1, "failed": 0, "blocked": 1})

    def test_zero_budget_and_byte_limit_block_before_transport(self):
        boundary = PrivateRequestBoundary(MESSAGES, [SECRET], MODEL, 0)
        self.blocked(self.body, "transport_attempt_budget_exhausted", boundary)
        boundary = PrivateRequestBoundary(MESSAGES, [SECRET], MODEL, 1, byte_limit=50)
        self.blocked(self.body, "request_byte_limit_exceeded", boundary)

    def test_receipts_and_repr_do_not_keep_body_values_or_response_secrets(self):
        result = self.boundary.send(self.body, lambda raw: {"private_response": SECRET})
        encoded = json.dumps(result.receipt)
        for forbidden in (SECRET, MASK, MESSAGES[0]["content"], "private_response", "messages", "mapping"):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn(SECRET, repr(result))
        self.assertNotIn(MASK, repr(self.boundary))
        self.assertEqual(result["response"], {"private_response": SECRET})
        receipt, response = result
        self.assertEqual(receipt, result["receipt"])
        self.assertEqual(response, result.response)

    def test_unregistered_semantics_are_explicitly_outside_the_claim(self):
        messages = deepcopy(MESSAGES)
        messages[1]["content"] = "Unregistered project inference may remain possible."
        boundary = PrivateRequestBoundary(messages, [SECRET], MODEL, 1)
        body = deepcopy(self.body)
        body["messages"] = messages
        result = boundary.send(body, self.transport)
        self.assertEqual(result.receipt["status"], "sent")
        self.assertEqual(result.receipt["observation_scope"], SCOPE)
        self.assertFalse(result.receipt["sdk_request_observed"])

    def test_fixed_http_sender_hands_the_same_bytes_to_http_client_and_closes(self):
        events = []

        class Response:
            status = 200
            def read(self, limit):
                events.append(("read", limit))
                return b'{"done":true,"message":{"content":"UNKNOWN"}}'

        class Connection:
            def __init__(self, host, port, timeout):
                events.append(("connect", host, port, timeout))
            def request(self, method, path, *, body, headers):
                self.raw = body
                events.append(("request", method, path, body, headers))
            def getresponse(self): return Response()
            def close(self): events.append(("close",))

        with patch("http.client.HTTPConnection", Connection):
            result = self.boundary.send(self.body, LoopbackJSONSender())
        self.assertEqual(result.receipt["status"], "sent")
        request = next(event for event in events if event[0] == "request")
        self.assertEqual(events[0], ("connect", "127.0.0.1", 11435, 60))
        self.assertEqual(request[1:3], ("POST", "/api/chat"))
        self.assertEqual(hashlib.sha256(request[3]).hexdigest(), result.receipt["request_body_sha256"])
        self.assertEqual(int(request[4]["Content-Length"]), len(request[3]))
        self.assertNotIn("Authorization", request[4])
        self.assertEqual(events[-1], ("close",))

    def test_http_failures_keep_fixed_diagnostics_and_close_without_retry(self):
        for condition in ("status", "oversize", "invalid-json", "transport"):
            with self.subTest(condition=condition):
                events = []

                class Response:
                    status = 403 if condition == "status" else 200
                    def read(self, limit):
                        if condition == "oversize": return b"x" * limit
                        return SECRET.encode()

                class Connection:
                    def __init__(self, *args, **kwargs): events.append("connect")
                    def request(self, *args, **kwargs):
                        events.append("request")
                        if condition == "transport": raise OSError(SECRET)
                    def getresponse(self): return Response()
                    def close(self): events.append("close")

                with patch("http.client.HTTPConnection", Connection):
                    boundary = PrivateRequestBoundary(MESSAGES, [SECRET], MODEL, 1)
                    result = boundary.send(self.body, LoopbackJSONSender(max_response_bytes=32))
                self.assertEqual(result.receipt["status"], "transport_failed")
                self.assertEqual(result.receipt["counters"]["failed"], 1)
                self.assertIsNone(result.response)
                self.assertEqual(events.count("connect"), 1)
                self.assertEqual(events[-1], "close")
                self.assertNotIn(SECRET, json.dumps(result.receipt))


if __name__ == "__main__":
    unittest.main()
