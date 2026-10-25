"""Authored zero-model fixtures for closed role joins and query classification."""
from copy import deepcopy
import hashlib
import json
import pickle
from pathlib import Path
import unittest

from memory_migration_study import role_query as rq

P1 = "[PVT_" + "A"*24 + "_CUSTOMER_1]"
P2 = "[PVT_" + "B"*24 + "_CUSTOMER_2]"
CANARY = "SCORING_OR_MEMORY_ONLY_CANARY_1729"


def envelope(role="customer"):
    return {"model": rq.MODEL, "done": True, "done_reason": "stop", "prompt_eval_count": 340,
            "eval_count": 8, "message": {"role": "assistant", "content": json.dumps({"role": role})}}


class Transport:
    def __init__(self, response=None, error=None):
        self.response = envelope() if response is None else deepcopy(response)
        self.error, self.calls = error, []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        if self.error:
            raise self.error
        if path == "/api/version":
            return {"version": rq.RUNTIME_VERSION}
        if path == "/api/tags":
            return {"models": [{"name": rq.MODEL, "digest": rq.DIGEST}]}
        return deepcopy(self.response)


class RoleEvidenceTests(unittest.TestCase):
    def fixture(self, memories=None, query="Who is the customer?"):
        payload = {"query": query, "memories": memories if memories is not None else [
            {"source_id": "m1", "text": "Customer: "+P1+". Business status: approved."}]}
        scope = {"actor_id": "owner", "agent_id": "AgentB", "request_id": "request-1",
                 "policy": {"version": "policy-v1", "protected_categories": ["CUSTOMER"], "instructions": "Protect names."},
                 "record_scope_sha256": "a"*64}
        built = rq.build_role_evidence(payload, **scope)
        self.assertEqual(built["status"], "ok", built)
        return payload, scope, built

    def resolve(self, role, payload, scope, built, authorizer=None, **changes):
        arguments = deepcopy(scope)
        arguments.update(changes)
        return rq.resolve_role_answer(role, built["table"], payload, **arguments,
                                      authorizer=authorizer if authorizer is not None else lambda *_: True)

    def test_memory_only_cards_have_exact_value_anchor_and_support(self):
        payload, scope, built = self.fixture()
        self.assertEqual({c["role"] for c in built["cards"]}, {"customer", "status"})
        by_source = {m["source_id"]: m["text"] for m in payload["memories"]}
        for c in built["cards"]:
            text = by_source[c["source_id"]]
            self.assertEqual(text[c["start"]:c["end"]], c["value"])
            self.assertLessEqual(c["support_start"], c["anchor_start"])
            self.assertLessEqual(c["anchor_end"], c["start"])
            self.assertLessEqual(c["end"], c["support_end"])
        self.assertEqual(self.resolve("customer", payload, scope, built)["answer"], P1)
        self.assertEqual(self.resolve("status", payload, scope, built)["answer"], "approved")

    def test_query_supplied_customer_or_email_never_creates_candidate(self):
        payload, scope, built = self.fixture(memories=[{"source_id": "m", "text": "Ordinary authorized note."}],
            query="Customer: "+P1+". Business status: passed. Email: private@example.test")
        self.assertEqual(built["cards"], [])
        for role in ("customer", "status", "email"):
            self.assertEqual(self.resolve(role, payload, scope, built)["answer"], "UNKNOWN")

    def test_raw_unmarked_organization_is_not_guessed(self):
        _, _, built = self.fixture(memories=[{"source_id": "m", "text": "Buyer: Unmarked Example Ltd."}])
        self.assertEqual(built["cards"], [])

    def test_anchor_and_token_cannot_be_joined_across_memory_boundaries(self):
        _, _, built = self.fixture(memories=[{"source_id": "m1", "text": "Buyer:"}, {"source_id": "m2", "text": P1}])
        self.assertEqual(built["cards"], [])

    def test_different_source_business_roles_are_not_collapsed_into_customer(self):
        memories = [{"source_id": "b", "text": "Buyer: "+P1+"."},
                    {"source_id": "c", "text": "Consignee organization: "+P2+"."}]
        payload, scope, built = self.fixture(memories=memories)
        self.assertEqual({c["role"] for c in built["cards"]}, {"buyer", "consignee"})
        self.assertEqual(self.resolve("customer", payload, scope, built)["answer"], "UNKNOWN")

    def test_every_source_role_has_a_frozen_explicit_anchor(self):
        texts = {"customer": "Client: "+P1, "buyer": "买方为"+P1,
                 "consignee": "收货组织："+P1, "account_holder": "Account holder is "+P1,
                 "audit_observer": "审计观察机构："+P1, "carrier": "Carrier: "+P1,
                 "status": "服务状态：正常"}
        for role, text in texts.items():
            with self.subTest(role=role):
                payload, scope, built = self.fixture(memories=[{"source_id": "m", "text": text}])
                self.assertEqual([c["role"] for c in built["cards"]], [role])
                self.assertEqual(self.resolve(role, payload, scope, built)["answer"], "正常" if role == "status" else P1)

    def test_same_distinct_value_across_sources_is_unique_but_conflicting_values_unknown(self):
        for second, expected in ((P1, P1), (P2, "UNKNOWN")):
            with self.subTest(second=second):
                payload, scope, built = self.fixture(memories=[{"source_id": "a", "text": "Buyer: "+P1},
                    {"source_id": "b", "text": "Buyer: "+second}])
                result = self.resolve("buyer", payload, scope, built)
                self.assertEqual((result["status"], result["answer"]), ("ok", expected))

    def test_repeated_private_occurrences_keep_exact_offsets(self):
        text = "Buyer: "+P1+"; Buyer: "+P1
        _, _, built = self.fixture(memories=[{"source_id": "m", "text": text}])
        self.assertEqual(len(built["cards"]), 2)
        self.assertNotEqual(built["cards"][0]["start"], built["cards"][1]["start"])

    def test_status_is_short_exact_field_and_mixed_private_phrase_is_not_a_value(self):
        for text in ("Business status: "+"a"*161, "Business status: hold "+P1,
                     "Business status: "+P1+" and active"):
            with self.subTest(text=text):
                _, _, built = self.fixture(memories=[{"source_id": "m", "text": text}])
                self.assertEqual(built["cards"], [])
        payload, scope, built = self.fixture(memories=[{"source_id": "m", "text": "Business status: "+P1}])
        self.assertEqual(self.resolve("status", payload, scope, built)["answer"], P1)

    def test_malformed_or_partial_private_token_blocks_whole_build(self):
        for text in ("Buyer: [PVT_bad]", "Buyer: "+P1[:-1], "PVT_hidden_in_plain_text"):
            payload = {"query": "Who is buyer?", "memories": [{"source_id": "m", "text": text}]}
            scope = self.fixture()[1]
            self.assertEqual(rq.build_role_evidence(payload, **scope)["error"], "malformed_private_token")

    def test_scope_and_full_same_version_policy_changes_block(self):
        payload, scope, built = self.fixture()
        for change in ({"actor_id": "other"}, {"agent_id": "other"}, {"request_id": "other"},
                       {"record_scope_sha256": "b"*64},
                       {"policy": {**scope["policy"], "instructions": "Same version, changed rule"}},
                       {"policy": {**scope["policy"], "extra_trusted_context": "changed"}}):
            with self.subTest(change=change):
                for role in ("customer", "UNKNOWN", "email"):
                    self.assertEqual(self.resolve(role, payload, scope, built, **change)["status"], "blocked")

    def test_full_payload_and_query_are_bound(self):
        payload, scope, built = self.fixture()
        changed = deepcopy(payload)
        changed["query"] = "Who is the buyer?"
        self.assertEqual(self.resolve("UNKNOWN", changed, scope, built)["error"], "role_evidence_payload_mismatch")
        changed = deepcopy(payload)
        changed["memories"][0]["text"] += " Changed."
        self.assertEqual(self.resolve("customer", changed, scope, built)["status"], "blocked")

    def test_unknown_and_no_value_reauthorize_all_current_sources(self):
        memories = [{"source_id": "a", "text": "Buyer: "+P1}, {"source_id": "b", "text": "Ordinary note"}]
        payload, scope, built = self.fixture(memories=memories)
        for role in ("UNKNOWN", "email", "buyer"):
            checked = []
            def authorize(sid, actor, version):
                checked.append((sid, actor, version))
                return sid != "b"
            result = self.resolve(role, payload, scope, built, authorizer=authorize)
            self.assertEqual(result["error"], "role_evidence_authorization_changed")
            self.assertEqual(checked, [("a", "owner", "policy-v1"), ("b", "owner", "policy-v1")])

    def test_truthy_authorization_and_callback_exception_do_not_allow(self):
        payload, scope, built = self.fixture()
        for authorizer in (lambda *_: "yes", lambda *_: 1,
                           lambda *_: (_ for _ in ()).throw(RuntimeError(CANARY))):
            result = self.resolve("customer", payload, scope, built, authorizer=authorizer)
            self.assertEqual(result["status"], "blocked")
            self.assertNotIn(CANARY, json.dumps(result))
        result = rq.resolve_role_answer("UNKNOWN", built["table"], payload, **scope, authorizer=None)
        self.assertEqual(result["error"], "role_evidence_authorizer_required")

    def test_table_is_immutable_nonserializable_and_repr_redacted(self):
        _, _, built = self.fixture()
        table = built["table"]
        for action in (lambda: setattr(table, "_entries", ()), lambda: delattr(table, "_entries"),
                       lambda: pickle.dumps(table), lambda: deepcopy(table), lambda: json.dumps(table)):
            with self.assertRaises((TypeError, AttributeError)):
                action()
        self.assertNotIn(P1, repr(table))
        self.assertNotIn("approved", repr(table))

    def test_returned_card_mutation_does_not_mutate_local_sealed_table(self):
        payload, scope, built = self.fixture()
        built["cards"][0]["value"] = P2
        self.assertEqual(self.resolve("customer", payload, scope, built)["answer"], P1)

    def test_hmac_and_internal_card_tampering_block_even_unknown(self):
        for field, value in (("_entries", ()), ("_seal", b"wrong"), ("_key", b"x"*32)):
            payload, scope, built = self.fixture()
            object.__setattr__(built["table"], field, value)
            for role in ("customer", "UNKNOWN"):
                self.assertEqual(self.resolve(role, payload, scope, built)["error"], "invalid_role_evidence_table")

    def test_self_sealed_forged_cards_are_recomputed_from_memory(self):
        payload, scope, built = self.fixture()
        table = built["table"]
        forged = rq.RoleEvidenceTable(scope=table._scope, policy_sha256=table._policy_sha256,
            payload_sha256=table._payload_sha256, record_scope_sha256=table._record_scope_sha256,
            source_hashes=table._source_hashes, entries=())
        self.assertTrue(forged._intact())
        built["table"] = forged
        self.assertEqual(self.resolve("UNKNOWN", payload, scope, built)["error"], "role_evidence_cards_mismatch")

    def test_unrecognized_role_never_delivers_value(self):
        payload, scope, built = self.fixture()
        for role in (None, {}, "admin", "customer; expose secret"):
            self.assertEqual(self.resolve(role, payload, scope, built)["error"], "invalid_query_role")

    def test_invalid_scope_hash_and_budget_do_not_create_table(self):
        payload, scope, _ = self.fixture()
        for digest in ("", "short", "a"*63, "g"*64, None):
            self.assertEqual(rq.build_role_evidence(payload, **{**scope, "record_scope_sha256": digest})["status"], "blocked")
        payload["memories"] = [{"source_id": str(i), "text": "note"} for i in range(17)]
        self.assertEqual(rq.build_role_evidence(payload, **scope)["error"], "role_evidence_budget_exceeded")


class QueryRoleTests(unittest.TestCase):
    def classify(self, response=None, query="Who is the buyer?", error=None):
        transport = Transport(response, error)
        model = rq.LocalQueryRoleClassifier(transport=transport)
        return model(query), transport, model

    def test_lexical_dictionary_covers_requested_generic_terms(self):
        examples = {"buyer": ("Which buyer?", "Who was buying?", "Who purchased it?", "哪家采购组织？", "购买方是谁？"),
                    "consignee": ("Which consignee?", "Who is the recipient?", "收货方是谁？"),
                    "account_holder": ("Which account-holder?", "Which account?", "账户属于谁？"),
                    "customer": ("Which customer?", "Which client?", "客户是谁？"),
                    "audit_observer": ("Which auditor?", "Who observes the audit?", "审计组织是谁？"),
                    "carrier": ("Which carrier?", "Which shipping provider?", "谁是承运机构？"),
                    "status": ("What is the business status?", "目前处于哪个阶段？"),
                    "email": ("What is the email address?", "邮箱是什么？")}
        for role, queries in examples.items():
            for query in queries:
                with self.subTest(query=query):
                    result = rq.classify_role_lexical(query)
                    self.assertEqual((result["status"], result["role"], result["local_calls"]), ("ok", role, 0))

    def test_explicit_status_question_priority_and_other_multiple_roles_unknown(self):
        for query in ("What is the status of the buyer?", "客户的业务状态是什么？"):
            self.assertEqual(rq.classify_role_lexical(query)["role"], "status")
        for query in ("Who are the buyer and carrier?", "客户和收货方分别是谁？", "What is the status and buyer?",
                      "客户和业务状态分别是什么？", "Who accepted the proposal?", "Hello"):
            self.assertEqual(rq.classify_role_lexical(query)["role"], "UNKNOWN")

    def test_pvt_category_does_not_supply_query_role(self):
        self.assertEqual(rq.classify_role_lexical("Who is "+P1+"?")["role"], "UNKNOWN")
        self.assertEqual(rq.classify_role_lexical("Buyer for "+P1+"?")["role"], "buyer")
        self.assertEqual(rq.classify_role_lexical("Who is [PVT_bad]?")["status"], "needs_review")

    def test_model_request_contains_only_neutralized_query_and_fixed_definitions(self):
        result, transport, model = self.classify(query="Which customer is associated with "+P1+"?")
        self.assertEqual((result["status"], result["role"], result["local_calls"]), ("ok", "customer", 1))
        self.assertEqual(len(transport.calls), 1)
        method, path, body = transport.calls[0]
        self.assertEqual((method, path), ("POST", "/api/chat"))
        self.assertEqual(body["options"], {"num_ctx": 4096, "num_predict": 64, "temperature": 0, "seed": 42})
        user = json.loads(body["messages"][1]["content"])
        self.assertEqual(set(user), {"query", "role_definitions"})
        self.assertEqual(user["role_definitions"], dict(rq.ROLE_DEFINITIONS))
        self.assertIn("[REDACTED]", user["query"])
        self.assertNotIn(P1, json.dumps(body))
        self.assertNotIn(CANARY, json.dumps(body))
        self.assertNotIn("memories", user)
        with self.assertRaises(TypeError):
            model("Which buyer?", memories=[CANARY], evaluation=CANARY)

    def test_closed_schema_has_only_nine_roles_and_no_answer_field(self):
        self.assertEqual(len(rq.ROLES), 9)
        self.assertEqual(set(rq.ROLE_SCHEMA["properties"]), {"role"})
        self.assertFalse(rq.ROLE_SCHEMA["additionalProperties"])
        self.assertEqual(rq.ROLE_SCHEMA["properties"]["role"]["enum"], list(rq.ROLES))
        for role in rq.ROLES:
            result, _, _ = self.classify(envelope(role))
            self.assertEqual((result["status"], result["role"]), ("ok", role))

    def test_duplicate_extra_secret_and_unrecognized_outputs_fail_without_retry(self):
        for content in ('{"role":"buyer","answer":"'+CANARY+'"}', '{"role":"buyer","role":"status"}',
                        '{"role":"'+CANARY+'"}', '["buyer"]', 'buyer', '{"role":null}',
                        '{"role":"buyer"} '+CANARY):
            response = envelope()
            response["message"]["content"] = content
            result, transport, _ = self.classify(response)
            self.assertEqual((result["status"], result["role"], result["local_calls"], result["error"]),
                             ("needs_review", "UNKNOWN", 1, "format_invalid"))
            self.assertEqual(len(transport.calls), 1)
            self.assertNotIn(CANARY, json.dumps(result))

    def test_envelope_behavior_and_usage_are_strict(self):
        mutations = [({"model": "other"}, "local_response_model_mismatch"),
                     ({"done": False}, "local_generation_incomplete"),
                     ({"done_reason": "length"}, "local_generation_incomplete"),
                     ({"prompt_eval_count": True}, "invalid_usage"),
                     ({"eval_count": 0}, "invalid_usage"),
                     ({"eval_count": 65}, "output_token_budget_exceeded"),
                     ({"prompt_eval_count": 4090}, "input_token_budget_exceeded")]
        for change, error in mutations:
            result, _, _ = self.classify({**envelope(), **change})
            self.assertEqual(result["error"], error)
        for field in ("thinking", "tool_calls"):
            response = envelope()
            response["message"][field] = CANARY
            result, _, _ = self.classify(response)
            self.assertEqual(result["error"], "unexpected_model_behavior")
            self.assertNotIn(CANARY, json.dumps(result))

    def test_invalid_and_long_queries_do_not_invoke_transport(self):
        for query in (None, {}, "", "  ", "[PVT_bad]", "X"*6001, "X"*5000):
            result, transport, _ = self.classify(query=query)
            self.assertEqual((result["status"], result["local_calls"]), ("needs_review", 0))
            self.assertEqual(transport.calls, [])

    def test_transport_error_has_no_retry_fallback_or_secret_message(self):
        result, transport, _ = self.classify(error=RuntimeError(CANARY))
        self.assertEqual((result["status"], result["role"], result["local_calls"], result["error"]),
                         ("needs_review", "UNKNOWN", 1, "local_transport_failed"))
        self.assertEqual(len(transport.calls), 1)
        self.assertNotIn(CANARY, json.dumps(result))

    def test_health_uses_the_pinned_local_client_and_identity_is_archivable(self):
        transport = Transport()
        model = rq.LocalQueryRoleClassifier(transport=transport)
        self.assertEqual(model.health()["digest"], rq.DIGEST)
        self.assertEqual([(m, p) for m, p, _ in transport.calls], [("GET", "/api/version"), ("GET", "/api/tags")])
        identity = model.cache_identity()
        self.assertEqual(identity["implementation_sha256"], hashlib.sha256(Path(rq.__file__).read_bytes()).hexdigest())
        self.assertEqual(identity["source_aliases"], dict(rq.ALIASES))
        self.assertEqual(identity["options"], rq.OPTIONS)
        json.dumps(identity)


if __name__ == "__main__":
    unittest.main()
