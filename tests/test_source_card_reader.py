"""Injected complete-context card reader tests, never a local model."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import source_card_reader as module
import tests.test_source_fact_cards as fixtures


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.SourceCardTests("runTest")
        self.fx.setUp()
        _, self.prepared, self.projected = self.fx.setup_projection()
        self.calls = []
        self.change = None
        self.raw = None

    def transport(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        choices = body["format"]["properties"]["card_id"]["enum"]
        result = {"model": module.MODEL, "done": True, "done_reason": "stop",
                  "message": {"role": "assistant", "content": self.raw if self.raw is not None else json.dumps({"card_id": choices[-1]})},
                  "prompt_eval_count": 500, "eval_count": 12}
        if self.change:
            self.change(result)
        return result

    def read(self, arm="source", view=None):
        reader = module.LocalSourceCardReader(transport=self.transport)
        return reader(self.projected["views"][arm] if view is None else view, self.projected["table"],
            self.prepared, self.fx.records, self.fx.policy, arm=arm, request_id="request-1", **self.fx.scope())

    def test_exact_same_model_prompt_schema_context_and_pool(self):
        self.assertEqual(self.read("flat")["status"], "ok")
        self.assertEqual(self.read("source")["status"], "ok")
        flat, rich = (call[2] for call in self.calls)
        self.assertEqual(flat["options"], {"num_ctx": 4096, "num_predict": 64, "temperature": 0, "seed": 42})
        self.assertEqual(flat["format"], rich["format"])
        self.assertEqual(flat["messages"][0], rich["messages"][0])
        a, b = (json.loads(body["messages"][1]["content"]) for body in (flat, rich))
        self.assertEqual(a["query"], b["query"])
        self.assertEqual(a["memories"], b["memories"])
        self.assertEqual(a["fact_cards"], [{k: v for k, v in c.items() if k not in {"role", "support"}} for c in b["fact_cards"]])
        self.assertEqual(set(a), {"query", "memories", "fact_cards"})
        wire = json.dumps([flat, rich])
        for secret in ("Redwood Labs", "Beacon Audit", "access_signature", '"answers"', '"record_id"'):
            self.assertNotIn(secret, wire)

    def test_revoked_or_changed_view_is_rejected_without_transport(self):
        view = deepcopy(self.projected["views"]["source"])
        view["fact_cards"][0]["value"] = "RAW PRIVATE VALUE"
        self.assertEqual(self.read(view=view)["status"], "blocked")
        self.fx.authority.revoke(self.fx.records[0]["record_id"])
        self.assertEqual(self.read()["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_json_unknown_is_genuine_only_with_valid_envelope_and_usage(self):
        self.raw = '{"card_id":"UNKNOWN"}'
        result = self.read()
        self.assertEqual((result["status"], result["decision"]), ("ok", "UNKNOWN"))
        self.change = lambda response: response.update(eval_count=-1)
        result = self.read()
        self.assertEqual(result["error"], "card_reader_usage_invalid")
        self.assertIsNone(result["decision"])

    def test_duplicate_extra_unknown_and_secret_outputs_are_not_repaired(self):
        for raw in ('{"card_id":"UNKNOWN","card_id":"UNKNOWN"}', '{"card_id":"UNKNOWN","more":1}',
                    '{"card_id":"FORGED"}', 'Refused but Redwood Labs', '{"card_id":"UNKNOWN"} trailing'):
            self.raw = raw
            result = self.read()
            self.assertEqual(result["status"], "error")
            self.assertIsNone(result["answer"])
            self.assertIsNone(result["decision"])
            self.assertNotIn("Redwood Labs", json.dumps(result))
        self.assertEqual(len(self.calls), 5)

    def test_runtime_tokens_and_truncation_are_bounded(self):
        changes = (lambda r: r.update(eval_count=65), lambda r: r.update(prompt_eval_count=3073),
                   lambda r: r.update(done_reason="length"),
                   lambda r: r["message"].update(thinking="hidden"), lambda r: r["message"].update(tool_calls=[{}]))
        for change in changes:
            self.change = change
            self.assertEqual(self.read()["status"], "error")
        self.assertEqual(len(self.calls), len(changes))

    def test_input_limit_fails_without_truncation_or_transport(self):
        with patch.object(module, "SYSTEM_PROMPT", "X"*4096):
            result = self.read()
        self.assertEqual(result["error"], "card_reader_input_budget_exceeded")
        self.assertEqual((result["local_calls"], self.calls), (0, []))


if __name__ == "__main__":
    unittest.main()
