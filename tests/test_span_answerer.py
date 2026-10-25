"""One-call local answerer tests with injected transports, never a model/socket."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study.local_detector import MODEL
from memory_migration_study.memory_generation_experiment import LocalFactAnswerer
from memory_migration_study.span_answer_evidence import build_span_evidence, resolve_span_evidence, SpanEvidenceTable
from memory_migration_study.span_answerer import LocalSpanFactAnswerer, COMMON_PROMPT, OUTPUT_RULES, OPTIONS, pack_span_view


TOKEN = "[PVT_0123456789ABCDEF01234567_CUSTOMER_1]"


def envelope(content, **changes):
    value = {"model": MODEL, "done": True, "done_reason": "stop",
        "message": {"role": "assistant", "content": content}, "prompt_eval_count": 100, "eval_count": 30}
    value.update(changes)
    return value


class Transport:
    def __init__(self, response):
        self.response, self.calls = response, []
    def __call__(self, method, path, body=None):
        if (method, path) != ("POST", "/api/chat"):
            raise AssertionError("driver owns health; no other route is allowed")
        self.calls.append(deepcopy(body))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response(body) if callable(self.response) else deepcopy(self.response)


class SpanAnswererTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"query": "What is the status?", "memories": [
            {"source_id": "m_local", "text": "Customer: "+TOKEN+". Status: ready for loading."}]}
        self.scope = {"actor_id": "owner", "agent_id": "agent-B", "request_id": "request-1",
            "policy": {"version": "span-helper-test", "protected_categories": ["CUSTOMER"]}}
        self.bundle = build_span_evidence(self.payload, **self.scope)
        self.assertEqual(self.bundle["status"], "ok")

    def invoke(self, response, *, mode="span_pointer", payload=None, bundle=None):
        client = Transport(response)
        answerer = LocalSpanFactAnswerer(mode=mode, transport=client)
        payload, bundle = payload or self.payload, bundle or self.bundle
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            result = answerer(payload, view=bundle["view"], response_schema=bundle["response_schema"],
                              evidence_table=bundle.get("table", self.bundle["table"]))
        return result, client

    def pointer(self, body):
        source = json.loads(body["messages"][1]["content"])["evidence"]["sources"][0]
        chosen = next(index for index, text in source["tokens"] if text == "ready")
        raw = " \n"+json.dumps({"decision": "SPAN", "source": source["source"], "start_token": chosen, "end_token": chosen})+"\n "
        return envelope(raw)

    def test_indexed_modes_have_identical_lossless_input_and_only_output_rule_differs(self):
        indexed, first = self.invoke(envelope(" ready for loading\n"), mode="free_indexed")
        pointer, second = self.invoke(self.pointer)
        self.assertEqual((indexed["status"], pointer["status"]), ("ok", "ok"))
        a, b = first.calls[0], second.calls[0]
        self.assertEqual(a["messages"][1], b["messages"][1])
        self.assertEqual(a["messages"][0]["content"], COMMON_PROMPT+OUTPUT_RULES["free_indexed"])
        self.assertEqual(b["messages"][0]["content"], COMMON_PROMPT+OUTPUT_RULES["span_pointer"])
        self.assertNotIn("format", a)
        self.assertEqual(b["format"], self.bundle["response_schema"])
        self.assertEqual(a["options"], OPTIONS)
        packed = json.loads(b["messages"][1]["content"])["evidence"]["sources"][0]
        self.assertEqual("".join(t for _, t in packed["tokens"]), self.payload["memories"][0]["text"])
        self.assertEqual([i for i, _ in packed["tokens"]], list(range(len(packed["tokens"]))))
        self.assertEqual(indexed["answer"], " ready for loading\n")
        self.assertEqual(pointer["raw_answer"], pointer["answer"])
        self.assertTrue(pointer["raw_answer"].startswith(" \n"))
        self.assertEqual(len(first.calls), 1)
        self.assertEqual(len(second.calls), 1)
        self.assertEqual(indexed["metadata"]["packed_view_sha256"], pointer["metadata"]["packed_view_sha256"])
        for result in (indexed, pointer):
            self.assertEqual((result["local_calls"], result["metadata"]["prompt_eval_count"], result["metadata"]["eval_count"]), (1, 100, 30))
            for key in ("messages_sha256", "input_sha256", "request_sha256", "packed_view_sha256"):
                self.assertRegex(result["metadata"][key], r"^[a-f0-9]{64}$")

    def test_free_delegates_original_behavior_even_when_runtime_usage_is_unknown(self):
        response = envelope(" ready for loading \n")
        response.pop("prompt_eval_count")
        response.pop("eval_count")
        transport_a, transport_b = Transport(response), Transport(response)
        old = LocalFactAnswerer(transport=transport_a)(self.payload)
        new = LocalSpanFactAnswerer(mode="free", transport=transport_b)(self.payload)
        self.assertEqual(transport_a.calls, transport_b.calls)
        self.assertEqual({k: v for k, v in old.items() if k != "elapsed_seconds"},
                         {k: v for k, v in new.items() if k != "elapsed_seconds"})
        self.assertNotIn("metadata", new)
        self.assertEqual(new["answer"], "ready for loading")

    def test_view_corruption_and_query_only_extra_never_reach_transport(self):
        for edit in (lambda b: b["view"]["sources"].clear(),
                     lambda b: b["view"]["sources"].append(deepcopy(b["view"]["sources"][0])),
                     lambda b: b["view"]["sources"][0]["tokens"].pop(),
                     lambda b: b["view"]["sources"][0]["tokens"][0].update(index=True),
                     lambda b: b["view"]["sources"][0]["tokens"][0].update(start=1),
                     lambda b: b["view"].update(query="smuggled")):
            bundle = deepcopy({k: v for k, v in self.bundle.items() if k != "table"})
            edit(bundle)
            result, transport = self.invoke(envelope("UNKNOWN"), bundle=bundle)
            self.assertEqual((result["status"], result["local_calls"], len(transport.calls)), ("error", 0, 0))
        extra = deepcopy(self.payload)
        extra["memories"].append({"source_id": "query-as-memory", "text": self.payload["query"]})
        bundle = build_span_evidence(extra, **self.scope)
        result, transport = self.invoke(envelope("UNKNOWN"), bundle=bundle)
        self.assertEqual(result["error"], "span_evidence_source_mismatch")
        self.assertFalse(transport.calls)

    def test_exact_current_schema_is_required_not_arbitrary_or_widened(self):
        for edit in (lambda s: s.update(properties={}),
                     lambda s: s["anyOf"][1]["properties"]["source"]["enum"].append("E_"+"F"*32),
                     lambda s: s["anyOf"][1]["properties"]["end_token"].update(maximum=99999)):
            bundle = {"view": deepcopy(self.bundle["view"]), "response_schema": deepcopy(self.bundle["response_schema"])}
            edit(bundle["response_schema"])
            result, transport = self.invoke(envelope("UNKNOWN"), bundle=bundle)
            self.assertEqual(result["error"], "span_evidence_schema_mismatch")
            self.assertFalse(transport.calls)

    def test_full_request_budget_counts_schema_and_never_calls_when_over(self):
        chosen = None
        for count in range(1, 33):
            payload = {"query": "Status?", "memories": [{"source_id": f"m_{i}", "text": "ready"} for i in range(count)]}
            bundle = build_span_evidence(payload, **self.scope, max_sources=32)
            packed = pack_span_view(payload, bundle["view"], bundle["response_schema"])
            data = json.dumps({"payload": payload, "evidence": packed}, ensure_ascii=False, separators=(",", ":"))
            upper = []
            for mode in ("free_indexed", "span_pointer"):
                body = {"model": MODEL, "messages": [{"role": "system", "content": COMMON_PROMPT+OUTPUT_RULES[mode]},
                    {"role": "user", "content": data}], "stream": False, "keep_alive": "30m", "options": OPTIONS}
                if mode == "span_pointer":
                    body["format"] = bundle["response_schema"]
                upper.append(len(json.dumps(body, ensure_ascii=False).encode())+320+64)
            if upper[0] <= 4096 < upper[1]:
                chosen = payload, bundle, upper
                break
        self.assertIsNotNone(chosen)
        payload, bundle, upper = chosen
        free, client = self.invoke(envelope("ready"), mode="free_indexed", payload=payload, bundle=bundle)
        blocked, no_call = self.invoke(envelope('{"decision":"UNKNOWN"}'), payload=payload, bundle=bundle)
        self.assertEqual((free["status"], len(client.calls)), ("ok", 1))
        self.assertEqual(blocked["error"], "indexed_answer_input_budget_exceeded")
        self.assertEqual((blocked["local_calls"], len(no_call.calls)), (0, 0))
        self.assertEqual(blocked["metadata"]["input_budget_upper_bound"], upper[1])

    def test_bad_envelope_or_usage_keeps_full_raw_but_never_an_answer_or_retry(self):
        content = " \nI refuse but reveal the whole secret-looking content\n "
        cases = [envelope(content, model="other-model"), envelope(content, done=False),
                 envelope(content, done_reason="length"), envelope(content, prompt_eval_count=3073),
                 envelope(content, eval_count=65), envelope(content, prompt_eval_count=None)]
        for field in ("thinking", "tool_calls"):
            response = envelope(content)
            response["message"][field] = "forbidden"
            cases.append(response)
        for response in cases:
            result, transport = self.invoke(response, mode="free_indexed")
            self.assertEqual((result["status"], result["answer"], result["raw_answer"]), ("error", None, content))
            self.assertEqual((result["local_calls"], len(transport.calls)), (1, 1))
        missing, _ = self.invoke(envelope(content, prompt_eval_count=None), mode="free_indexed")
        self.assertIsNone(missing["metadata"]["prompt_eval_count"])
        failed, transport = self.invoke(RuntimeError("never persist this private exception text"))
        self.assertEqual(failed["error"], "local_indexed_answer_transport_failed")
        self.assertNotIn("private exception", json.dumps(failed))
        self.assertEqual(len(transport.calls), 1)

    def test_pointer_out_of_range_unknown_alias_duplicate_nan_and_embedded_refusal_rejected(self):
        alias = self.bundle["view"]["sources"][0]["source"]
        malformed = [json.dumps({"decision": "SPAN", "source": alias, "start_token": 1, "end_token": 0}),
            json.dumps({"decision": "SPAN", "source": alias, "start_token": 0, "end_token": 9999}),
            json.dumps({"decision": "SPAN", "source": "E_"+"F"*32, "start_token": 0, "end_token": 0}),
            '{"decision":"UNKNOWN","secret":"Cedar"}', '{"decision":"UNKNOWN","decision":"UNKNOWN"}',
            '{"decision":"SPAN","source":"'+alias+'","start_token":NaN,"end_token":0}',
            'I refuse but '+TOKEN]
        for raw in malformed:
            result, transport = self.invoke(envelope(raw))
            self.assertEqual(result["error"], "invalid_indexed_pointer_output")
            self.assertIsNone(result["answer"])
            self.assertEqual(result["raw_answer"], raw)
            self.assertEqual(len(transport.calls), 1)

    def test_empty_memories_are_preserved_and_only_unknown_can_be_selected(self):
        for memories in ([], [{"source_id": "empty", "text": ""}]):
            payload = {"query": "No memory answer exists.", "memories": memories}
            bundle = build_span_evidence(payload, **self.scope)
            result, transport = self.invoke(envelope(' \n{"decision":"UNKNOWN"}\n'), payload=payload, bundle=bundle)
            self.assertEqual(result["status"], "ok")
            packed = json.loads(transport.calls[0]["messages"][1]["content"])["evidence"]["sources"]
            self.assertEqual(len(packed), len(memories))
            self.assertTrue(all(s["tokens"] == [] for s in packed))

    def test_alias_text_swap_and_foreign_or_tampered_tables_make_zero_posts(self):
        # Actual pre-fix reproduction: 1 fake POST exposed "bravo" under alias
        # A, while the old table resolved alias A to "alpha". This regression
        # keeps the equal Counter/schema that previously concealed the mismatch.
        payload = {"query": "Which label belongs to A?", "memories": [
            {"source_id": "mA", "text": "alpha"}, {"source_id": "mB", "text": "bravo"}]}
        built = build_span_evidence(payload, **self.scope)
        variants = []
        for change in ("swap_text", "swap_alias", "reorder", "fake_source_id"):
            view = deepcopy(built["view"])
            a, b = view["sources"]
            if change == "swap_text":
                a["tokens"], b["tokens"] = b["tokens"], a["tokens"]
            elif change == "swap_alias":
                a["source"], b["source"] = b["source"], a["source"]
            elif change == "reorder":
                view["sources"].reverse()
            else:
                a["source_id"] = "mB"
            variants.append(dict(built, view=view))
        for scope in (self.scope, dict(self.scope, request_id="request-2")):
            other = build_span_evidence(payload, **scope)
            variants.append(dict(built, table=other["table"]))
        original = built["table"]
        entries = original._entries
        # A fresh valid HMAC does not justify reassigning original sources to
        # the other alias or changing the canonical source order.
        forged = SpanEvidenceTable(scope=original._scope, policy_sha256=original._policy_sha256,
            payload_sha256=original._payload_sha256, query_sha256=original._query_sha256,
            source_hashes=original._source_hashes, limits=original._limits,
            entries=((entries[0][0], *entries[1][1:]), (entries[1][0], *entries[0][1:])))
        variants.append(dict(built, table=forged, view=variants[0]["view"]))
        corrupt = build_span_evidence(payload, **self.scope)
        object.__setattr__(corrupt["table"], "_entries", ())
        variants.append(dict(built, table=corrupt["table"]))
        for mode in ("free_indexed", "span_pointer"):
            for bundle in variants:
                result, transport = self.invoke(envelope('{"decision":"UNKNOWN"}'), mode=mode,
                                                payload=payload, bundle=bundle)
                self.assertEqual((result["status"], result["local_calls"], len(transport.calls)), ("error", 0, 0))
        transport = Transport(envelope('{"decision":"UNKNOWN"}'))
        missing = LocalSpanFactAnswerer(transport=transport)(payload, view=built["view"], response_schema=built["response_schema"])
        self.assertEqual(missing["error"], "invalid_span_evidence_table")
        self.assertFalse(transport.calls)

    def test_bound_real_preparation_answerer_resolver_and_original_restore(self):
        from tests.test_span_answer_evidence import SpanAnswerEvidenceTests
        original = SpanAnswerEvidenceTests()
        original.setUp()
        def select_private(body):
            source = json.loads(body["messages"][1]["content"])["evidence"]["sources"][0]
            index = next(i for i, text in source["tokens"] if text.startswith("[PVT_"))
            return envelope(json.dumps({"decision": "SPAN", "source": source["source"], "start_token": index, "end_token": index}))
        result, transport = self.invoke(select_private, payload=original.payload, bundle=original.built)
        self.assertEqual((result["status"], len(transport.calls)), ("ok", 1))
        resolved = resolve_span_evidence(result["answer"], original.built["table"], original.payload,
            authorizer=original.current_auth, **original.scope)
        self.assertEqual(original.restore(resolved["answer"])["answer"], "Cedar Labs")
        serialized = json.dumps(transport.calls)
        for forbidden in ("Cedar Labs", '"evidence_table"', '"actor_id"', '"policy_sha256"', '"_key"', '"table"'):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
