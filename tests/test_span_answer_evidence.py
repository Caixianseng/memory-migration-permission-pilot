"""Source-span pointers with real authority/prepare/restore, zero model calls."""
import copy
import json
import logging
import pickle
import re
import unittest
from unittest.mock import patch

from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.span_answer_evidence import (build_span_evidence, resolve_span_evidence,
    validate_span_view_binding, SpanEvidenceTable)


class ZeroDetector:
    max_local_calls = 1
    def __call__(self, **kwargs):
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 0, "elapsed_seconds": 0.0}


class SpanAnswerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"version": "span-test-v1", "protected_categories": ["CUSTOMER"],
                       "instructions": "Customer names stay private.", "business_purpose": {"operation": "answer"}}
        self.authority = MemoryLabelAuthority(b"span-pointer-real-authority-test-key"*2)
        text = "Customer: Cedar Labs; Status: ready for loading. 中文状态：待装车。"
        start = text.index("Cedar Labs")
        self.source = {"source_id": "source-A", "text": text}
        fact = {"text": text, "source_start": 0, "source_end": len(text),
                "findings": [{"start": start, "end": start+len("Cedar Labs"), "category": "CUSTOMER"}]}
        record = self.authority.build_record(self.source, fact, self.policy, owner_id="owner", readers=["owner"],
            agent_id="agent-A", allowed_agent_ids=["agent-B"], builder_version="test-source-v1", detector_version="test-label-v1")
        self.records = json.loads(json.dumps([record]))
        self.scope = {"actor_id": "owner", "agent_id": "agent-B", "request_id": "request-1", "policy": self.policy}
        self.prepared = prepare_labeled_transfer(self.records, "What is the customer and status?", self.policy,
            authority=self.authority, actor_id="owner", agent_id="agent-B", request_id="request-1",
            mode="generation", agent=ZeroDetector())
        self.assertEqual(self.prepared["status"], "ok")
        self.payload = self.prepared["payload"]
        self.built = build_span_evidence(self.payload, **self.scope)
        self.assertEqual(self.built["status"], "ok")

    def current_auth(self, sid, actor, version):
        for before, after in zip(self.prepared["original_payload"]["memories"], self.payload["memories"]):
            if after["source_id"] == sid:
                record = next(r for r in self.records if r["record_id"] == before["source_id"])
                return self.authority.validate_access(record, actor_id=actor, agent_id="agent-B", policy_version=version) is None
        return False

    def selection(self, value, *, built=None):
        source = (built or self.built)["view"]["sources"][0]
        text = "".join(t["text"] for t in source["tokens"])
        start = text.index(value)
        end = start+len(value)
        left = next(t["index"] for t in source["tokens"] if t["start"] == start)
        right = next(t["index"] for t in source["tokens"] if t["end"] == end)
        return {"decision": "SPAN", "source": source["source"], "start_token": left, "end_token": right}

    def resolve(self, selection, *, table=None, payload=None, authorizer=None, **changes):
        raw = selection if isinstance(selection, str) else json.dumps(selection)
        return resolve_span_evidence(raw, self.built["table"] if table is None else table,
            self.payload if payload is None else payload, authorizer=self.current_auth if authorizer is None else authorizer,
            **dict(self.scope, **changes))

    def restore(self, answer, *, records=None, **changes):
        scope = {k: v for k, v in self.scope.items() if k != "policy"}
        return restore_labeled_answer(answer, self.prepared, self.records if records is None else records,
            self.policy, authority=self.authority, **dict(scope, **changes))

    def test_real_a_signed_json_handoff_pointer_and_original_restore(self):
        self.assertEqual(validate_span_view_binding(self.built["table"], self.payload,
            self.built["view"], self.built["response_schema"]), {"status": "ok", "error": None})
        token = next(t["text"] for t in self.built["view"]["sources"][0]["tokens"] if t["text"].startswith("[PVT_"))
        resolved = self.resolve(self.selection(token))
        self.assertEqual(resolved["answer"], token)
        self.assertNotIn("Cedar Labs", json.dumps(self.built["view"]))
        self.assertEqual(self.restore(resolved["answer"])["answer"], "Cedar Labs")
        selected = resolved["source_span"]
        self.assertEqual(self.payload["memories"][0]["text"][selected["start"]:selected["end"]], token)

    def test_lossless_words_numbers_han_punctuation_whitespace_and_pvt_atomicity(self):
        opaque = "[PVT_0123456789ABCDEF01234567_CUSTOMER_1]"
        text = " Aster-84 262,000.50 -12.5 2.3e-4 ١٢٣\t中文，"+opaque+"!\n"
        payload = {"query": "not a candidate", "memories": [{"source_id": "m", "text": text}]}
        built = build_span_evidence(payload, **self.scope)
        tokens = built["view"]["sources"][0]["tokens"]
        self.assertEqual("".join(t["text"] for t in tokens), text)
        self.assertEqual([t["index"] for t in tokens], list(range(len(tokens))))
        self.assertEqual([t["start"] for t in tokens], [0]+[t["end"] for t in tokens[:-1]])
        for value in ("Aster-84", "262,000.50", "-12.5", "2.3e-4", "١٢٣", "中", "文", opaque):
            self.assertIn(value, [t["text"] for t in tokens])
        self.assertEqual(sum(opaque in t["text"] for t in tokens), 1)

    def test_non_sensitive_multiword_and_chinese_status_use_exact_original_spans(self):
        for literal in ("ready for loading", "待装车"):
            answer = self.resolve(self.selection(literal))
            self.assertEqual(answer["answer"], literal)
            self.assertEqual(self.restore(answer["answer"])["answer"], literal)

    def test_unknown_is_bound_but_never_authorizes_or_uses_query_as_memory(self):
        query_secret = "[PVT_0123456789ABCDEF01234567_PROJECT_2]"
        payload = {"query": "User supplied "+query_secret, "memories": []}
        built = build_span_evidence(payload, **self.scope)
        self.assertEqual(built["view"], {"sources": []})
        self.assertEqual(len(built["response_schema"]["anyOf"]), 1)
        self.assertNotIn(query_secret, json.dumps(built["view"]))
        unknown = self.resolve({"decision": "UNKNOWN"}, table=built["table"], payload=payload,
                               authorizer=lambda *_: self.fail("UNKNOWN has no selected source"))
        self.assertEqual(unknown["answer"], "UNKNOWN")
        changed = copy.deepcopy(payload)
        changed["query"] += " changed"
        self.assertEqual(self.resolve({"decision": "UNKNOWN"}, table=built["table"], payload=changed)["status"], "blocked")
        self.assertEqual(self.resolve({"decision": "SPAN", "source": "E_"+"A"*32, "start_token": 0, "end_token": 0},
            table=built["table"], payload=payload)["error"], "unknown_span_evidence_source")

    def test_scope_source_query_order_and_full_policy_changes_are_denied(self):
        selection = self.selection("ready for loading")
        for change in ({"actor_id": "outsider"}, {"agent_id": "agent-C"}, {"request_id": "request-2"}):
            self.assertEqual(self.resolve(selection, **change)["error"], "span_evidence_scope_mismatch")
        policy = copy.deepcopy(self.policy)
        policy["business_purpose"]["operation"] = "export"
        self.assertEqual(self.resolve(selection, policy=policy)["error"], "span_evidence_policy_mismatch")
        for edit in (lambda p: p.update(query="Different question"),
                     lambda p: p["memories"][0].update(text=p["memories"][0]["text"]+" changed"),
                     lambda p: p["memories"][0].update(source_id="another source")):
            payload = copy.deepcopy(self.payload)
            edit(payload)
            self.assertEqual(self.resolve(selection, payload=payload)["status"], "blocked")
        newer = build_span_evidence(self.payload, **dict(self.scope, request_id="request-2"))
        self.assertEqual(self.resolve(selection, table=newer["table"], request_id="request-2")["error"], "unknown_span_evidence_source")
        two = copy.deepcopy(self.payload)
        two["memories"].append({"source_id": "second", "text": "Public note."})
        built = build_span_evidence(two, **self.scope)
        two["memories"].reverse()
        self.assertEqual(self.resolve({"decision": "UNKNOWN"}, table=built["table"], payload=two)["error"], "span_evidence_payload_mismatch")

    def test_real_revocation_before_resolve_and_after_resolve_and_table_is_not_grant(self):
        selection = self.selection("ready for loading")
        def fails(*_):
            raise RuntimeError("Cedar Labs must not enter exception diagnostics")
        for authorizer in (lambda *_: False, lambda *_: 1, fails):
            self.assertEqual(self.resolve(selection, authorizer=authorizer)["error"], "span_evidence_authorization_failed")
        resolved = self.resolve(selection)
        self.authority.revoke_source(self.source["source_id"])
        self.assertEqual(self.resolve(selection)["error"], "span_evidence_authorization_failed")
        self.assertEqual(self.restore(resolved["answer"])["error"], "grant_revoked")
        # A dishonest outer callback cannot make the original trusted restore
        # forget that source authorization was revoked.
        result = self.resolve(selection, authorizer=lambda *_: True)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.restore(result["answer"])["error"], "grant_revoked")

    def test_invalid_indices_extra_keys_refusal_secrets_duplicate_keys_and_nan_are_denied(self):
        selected = self.selection("ready for loading")
        for changes in ({"start_token": True}, {"end_token": 1.0}, {"start_token": -1},
                        {"end_token": 100000}, {"start_token": selected["end_token"]+1},
                        {"answer": "Cedar Labs"}, {"source": "__query__"}):
            self.assertEqual(self.resolve(dict(selected, **changes))["status"], "blocked")
        for raw in ('{"decision":"UNKNOWN","answer":"Cedar Labs"}',
                    '{"decision":"UNKNOWN","decision":"SPAN"}',
                    '{"decision":"SPAN","source":"E_'+"A"*32+'","start_token":NaN,"end_token":1}',
                    "I refuse but Cedar Labs", "x"*4097):
            self.assertEqual(self.resolve(raw)["status"], "blocked")

    def test_whitespace_and_embedded_private_parent_ranges_are_not_single_answers(self):
        view = self.built["view"]["sources"][0]
        space = next(t["index"] for t in view["tokens"] if t["text"].isspace())
        self.assertEqual(self.resolve({"decision": "SPAN", "source": view["source"], "start_token": space, "end_token": space})["error"], "empty_span_answer")
        self.assertEqual(self.resolve({"decision": "SPAN", "source": view["source"], "start_token": 0,
            "end_token": len(view["tokens"])-1})["error"], "span_answer_not_single_value")

    def test_table_integrity_immutability_serialization_and_public_view_mutation(self):
        table, selected = self.built["table"], self.selection("ready for loading")
        self.assertIsInstance(table, SpanEvidenceTable)
        with self.assertLogs("span-evidence-test", level=logging.INFO) as logs:
            logging.getLogger("span-evidence-test").info("local table=%r", table)
        for secret in (self.built["view"]["sources"][0]["source"], "Cedar Labs", "request-1"):
            self.assertNotIn(secret, "".join(logs.output))
        for encoder in (json.dumps, pickle.dumps):
            with self.assertRaises(TypeError):
                encoder(table)
        with self.assertRaises(AttributeError):
            table._entries = ()
        with self.assertRaises(AttributeError):
            del table._entries
        self.built["view"]["sources"][0]["tokens"].clear()
        self.assertEqual(self.resolve(selected)["answer"], "ready for loading")
        object.__setattr__(table, "_entries", ())
        self.assertEqual(self.resolve(selected)["error"], "invalid_span_evidence_table")

    def test_freshly_sealed_malicious_table_cannot_split_private_token_or_english_word(self):
        original = self.built["table"]
        for target in ("[PVT_", "ready"):
            entries = list(original._entries)
            alias, sid, text_hash, tokens = entries[0]
            text = self.payload["memories"][0]["text"]
            index = next(i for i, (a, b) in enumerate(tokens) if text[a:b].startswith(target))
            a, b = tokens[index]
            changed = tokens[:index]+((a, a+1), (a+1, b))+tokens[index+1:]
            entries[0] = (alias, sid, text_hash, changed)
            forged = SpanEvidenceTable(scope=original._scope, policy_sha256=original._policy_sha256,
                payload_sha256=original._payload_sha256, query_sha256=original._query_sha256,
                source_hashes=original._source_hashes, entries=entries, limits=original._limits)
            self.assertTrue(forged._intact())
            self.assertEqual(validate_span_view_binding(forged, self.payload, self.built["view"],
                self.built["response_schema"])["error"], "invalid_span_evidence_table")
            result = self.resolve({"decision": "SPAN", "source": alias, "start_token": index, "end_token": index}, table=forged)
            self.assertEqual(result["error"], "invalid_span_evidence_table")
            self.assertEqual(self.resolve({"decision": "UNKNOWN"}, table=forged)["error"], "invalid_span_evidence_table")

    def test_explicit_budgets_never_truncate_and_malformed_tokens_never_split(self):
        for changes in ({"max_sources": 0}, {"max_total_tokens": True}):
            self.assertEqual(build_span_evidence(self.payload, **self.scope, **changes)["status"], "blocked")
        for changes in ({"max_total_chars": 2}, {"max_tokens_per_source": 1}, {"max_total_tokens": 1}):
            result = build_span_evidence(self.payload, **self.scope, **changes)
            self.assertEqual(result["status"], "needs_review")
            self.assertIsNone(result["table"])
            self.assertEqual(result["view"], {"sources": []})
        policy = dict(self.policy, max_text_chars=2)
        self.assertEqual(build_span_evidence(self.payload, **dict(self.scope, policy=policy))["status"], "needs_review")
        for bad in ("[PVT_BROKEN_CUSTOMER_1]", "PVT_0123456789ABCDEF01234567_CUSTOMER_1", "[PVT_0123456789ABCDEF01234567_BAD_1]"):
            payload = {"query": "test", "memories": [{"source_id": "m", "text": bad}]}
            self.assertEqual(build_span_evidence(payload, **self.scope)["error"], "malformed_private_token")
        with patch("memory_migration_study.span_answer_evidence.secrets.token_hex", return_value="A"*32):
            payload = {"query": "test", "memories": [{"source_id": "m1", "text": "one"}, {"source_id": "m2", "text": "two"}]}
            self.assertEqual(build_span_evidence(payload, **self.scope)["error"], "span_evidence_alias_collision")

    def test_schema_complete_branches_alias_entropy_and_no_query_or_authority_fields(self):
        branches = self.built["response_schema"]["anyOf"]
        self.assertEqual(len(branches), 2)
        for branch in branches:
            self.assertEqual(branch["type"], "object")
            self.assertIs(branch["additionalProperties"], False)
            self.assertNotIn("anyOf", branch)
            self.assertEqual(next(iter(branch["properties"])), "decision")
        self.assertRegex(self.built["view"]["sources"][0]["source"], r"^E_[A-F0-9]{32}$")
        encoded = json.dumps({"view": self.built["view"], "schema": self.built["response_schema"], "metadata": self.built["metadata"]})
        for value in ("Cedar Labs", self.records[0]["record_id"], "request-1", '"actor_id"', '"agent_id"', '"query"'):
            self.assertNotIn(value, encoded)


if __name__ == "__main__":
    unittest.main()
