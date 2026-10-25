import copy
import json
import pickle
import re
import unittest
from unittest.mock import patch

from memory_migration_study.answer_evidence import build_answer_evidence, resolve_answer_evidence
from memory_migration_study.privacy import detect_sensitive, prepare_private_payload, restore_answer


TOKEN_A = "[PVT_0123456789ABCDEF01234567_CUSTOMER_1]"
TOKEN_B = "[PVT_0123456789ABCDEF01234567_PERSON_2]"
QUERY_TOKEN = "[PVT_0123456789ABCDEF01234567_PROJECT_3]"


class AnswerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"query": "Ask about " + QUERY_TOKEN,
                        "memories": [{"source_id": "m_a", "text": "Customer is " + TOKEN_A + ". State: ready."},
                                     {"source_id": "m_b", "text": "Contact is " + TOKEN_B}]}
        self.scope = {"actor_id": "owner-sensitive-identity", "agent_id": "agent-one", "request_id": "request-one",
                      "policy": {"version": "1", "protected_categories": ["CUSTOMER", "PERSON", "PROJECT"],
                                 "instructions": "Protect the declared entity categories."}}
        self.built = build_answer_evidence(self.payload, **self.scope)
        self.assertEqual(self.built["status"], "ok")

    def resolve(self, raw=None, table=None, payload=None, authorizer=None, **changes):
        scope = dict(self.scope, **changes)
        return resolve_answer_evidence(raw if raw is not None else json.dumps({"answer_id": self.built["candidates"][0]["answer_id"]}),
            self.built["table"] if table is None else table,
            payload=self.payload if payload is None else payload,
            authorizer=(lambda *_: True) if authorizer is None else authorizer, **scope)

    def test_candidates_only_complete_tokens_in_memory_never_query(self):
        candidates = self.built["candidates"]
        self.assertEqual([c["token"] for c in candidates], [TOKEN_A, TOKEN_B])
        self.assertNotIn(QUERY_TOKEN, json.dumps(candidates))
        self.assertTrue(all(set(c) == {"answer_id", "token"} for c in candidates))
        self.assertTrue(all(re.fullmatch(r"E_[A-F0-9]{16}_\d+", c["answer_id"]) for c in candidates))
        self.assertEqual(self.built["response_schema"]["properties"]["answer_id"]["enum"],
                         ["UNKNOWN"] + [c["answer_id"] for c in candidates])

    def test_resolver_returns_original_complete_token_not_original_private_value(self):
        result = self.resolve()
        self.assertEqual(result, {"status": "ok", "token": TOKEN_A, "error": None})

    def test_table_is_opaque_immutable_and_cannot_be_serialized(self):
        table = self.built["table"]
        shown = repr(table)
        self.assertNotIn(TOKEN_A, shown)
        self.assertNotIn(self.scope["actor_id"], shown)
        self.assertNotIn(self.scope["request_id"], shown)
        self.assertNotIn(self.built["candidates"][0]["answer_id"], shown)
        with self.assertRaises(TypeError):
            json.dumps(table)
        with self.assertRaises(TypeError):
            pickle.dumps(table)
        with self.assertRaises(AttributeError):
            table._scope = ("attacker", "agent-one", "request-one")
        self.assertNotIn(self.scope["actor_id"], json.dumps(self.built["metadata"]))

    def test_cloud_candidate_or_metadata_mutation_does_not_mutate_local_mapping(self):
        identifier = self.built["candidates"][0]["answer_id"]
        self.built["candidates"][0]["token"] = QUERY_TOKEN
        self.built["metadata"]["payload_sha256"] = "0" * 64
        result = self.resolve(json.dumps({"answer_id": identifier}))
        self.assertEqual(result["token"], TOKEN_A)

    def test_local_table_integrity_detects_direct_attribute_corruption(self):
        table = self.built["table"]
        object.__setattr__(table, "_payload_sha256", "0" * 64)
        self.assertEqual(self.resolve()["error"], "invalid_evidence_table")

    def test_cross_actor_agent_request_scope_is_blocked(self):
        for changes in ({"actor_id": "other-owner"}, {"agent_id": "agent-two"}, {"request_id": "request-two"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.resolve(**changes)["error"], "evidence_scope_mismatch")

    def test_same_version_policy_change_and_extra_field_change_are_bound(self):
        for policy in (dict(self.scope["policy"], instructions="Different privacy restriction."),
                       dict(self.scope["policy"], protected_categories=["CUSTOMER"]),
                       dict(self.scope["policy"], business_purpose="new purpose")):
            with self.subTest(policy=policy):
                self.assertEqual(self.resolve(policy=policy)["error"], "evidence_policy_mismatch")

    def test_memory_source_id_text_or_unrelated_memory_change_is_blocked(self):
        for edit in (lambda p: p["memories"][0].update(source_id="other-source"),
                     lambda p: p["memories"][0].update(text="No token remains."),
                     lambda p: p["memories"][1].update(text=p["memories"][1]["text"] + " changed")):
            payload = copy.deepcopy(self.payload)
            edit(payload)
            self.assertEqual(self.resolve(payload=payload)["error"], "evidence_source_mismatch")

    def test_query_change_or_memory_order_change_is_payload_mismatch(self):
        for edit in (lambda p: p.update(query="A different query."), lambda p: p["memories"].reverse()):
            payload = copy.deepcopy(self.payload)
            edit(payload)
            self.assertEqual(self.resolve(payload=payload)["error"], "evidence_payload_mismatch")

    def test_revocation_authorizer_failure_and_truthy_nonboolean_are_denied(self):
        def fails(*_):
            raise RuntimeError("private original value must never escape in an exception")
        for authorizer in (lambda *_: False, lambda *_: 1, fails):
            result = self.resolve(authorizer=authorizer)
            self.assertEqual(result["error"], "answer_evidence_authorization_failed")
            self.assertNotIn("private original", json.dumps(result))

    def test_duplicate_token_binds_every_actual_memory_source(self):
        payload = {"query": TOKEN_A,
                   "memories": [{"source_id": "one", "text": TOKEN_A + " " + TOKEN_A},
                                {"source_id": "two", "text": "Again " + TOKEN_A}]}
        built = build_answer_evidence(payload, **self.scope)
        self.assertEqual(len(built["candidates"]), 1)
        observed = []
        def authorizer(sid, actor, version):
            observed.append((sid, actor, version))
            return True
        raw = json.dumps({"answer_id": built["candidates"][0]["answer_id"]})
        result = self.resolve(raw, table=built["table"], payload=payload, authorizer=authorizer)
        self.assertEqual(result["token"], TOKEN_A)
        self.assertEqual(observed, [("one", self.scope["actor_id"], "1"), ("two", self.scope["actor_id"], "1")])
        self.assertEqual(self.resolve(raw, table=built["table"], payload=payload,
            authorizer=lambda sid, *_: sid != "two")["status"], "blocked")

    def test_empty_memory_query_token_has_no_candidate_and_only_unknown_resolves(self):
        payload = {"query": "I supplied " + QUERY_TOKEN, "memories": []}
        built = build_answer_evidence(payload, **self.scope)
        self.assertEqual(built["candidates"], [])
        self.assertEqual(built["response_schema"]["properties"]["answer_id"]["enum"], ["UNKNOWN"])
        def must_not_authorize(*_):
            raise AssertionError("UNKNOWN has no value/source to authorize")
        result = self.resolve('{"answer_id":"UNKNOWN"}', table=built["table"], payload=payload, authorizer=must_not_authorize)
        self.assertEqual(result, {"status": "ok", "token": "UNKNOWN", "error": None})
        self.assertEqual(self.resolve(json.dumps({"answer_id": QUERY_TOKEN}), table=built["table"], payload=payload)["error"],
                         "unknown_answer_evidence_id")

    def test_unknown_or_previous_request_id_is_not_accepted(self):
        self.assertEqual(self.resolve('{"answer_id":"E_UNKNOWN_1"}')["error"], "unknown_answer_evidence_id")
        newer = build_answer_evidence(self.payload, **dict(self.scope, request_id="request-two"))
        old_id = self.built["candidates"][0]["answer_id"]
        self.assertNotIn(old_id, [c["answer_id"] for c in newer["candidates"]])
        result = self.resolve(json.dumps({"answer_id": old_id}), table=newer["table"], request_id="request-two")
        self.assertEqual(result["error"], "unknown_answer_evidence_id")

    def test_strict_full_json_schema_and_refusal_containing_secret_are_blocked(self):
        identifier = self.built["candidates"][0]["answer_id"]
        malformed = [json.dumps({"answer_id": identifier}) + " private-secret",
                     json.dumps({"answer_id": identifier, "refusal": "I refuse but private-secret"}),
                     '{"answer_id":"UNKNOWN","answer_id":"' + identifier + '"}',
                     'I refuse. {"answer_id":"UNKNOWN"}',
                     '```json\n{"answer_id":"UNKNOWN"}\n```',
                     '{"answer_id":null}', '{"answer_id":7}', '{}', '[{"answer_id":"UNKNOWN"}]',
                     '{"answer_id":NaN}', '"UNKNOWN"', '{"answer_id":"UNKNOWN"}{}']
        for raw in malformed:
            with self.subTest(raw=raw):
                result = self.resolve(raw)
                self.assertEqual(result["status"], "blocked")
                self.assertIsNone(result["token"])
                self.assertNotIn("private-secret", json.dumps(result))

    def test_outer_json_whitespace_allowed_but_identifier_not_normalized(self):
        self.assertEqual(self.resolve(' \n {"answer_id":"UNKNOWN"} \t ')["token"], "UNKNOWN")
        for value in ("unknown", " UNKNOWN ", self.built["candidates"][0]["answer_id"].lower()):
            self.assertEqual(self.resolve(json.dumps({"answer_id": value}))["status"], "blocked")

    def test_candidate_overflow_blocks_without_partial_table_or_silent_truncation(self):
        tokens = [f"[PVT_0123456789ABCDEF01234567_CUSTOMER_{i}]" for i in range(1, 34)]
        payload = {"query": "Customer name?", "memories": [{"source_id": "m", "text": " ".join(tokens)}]}
        result = build_answer_evidence(payload, **self.scope, max_candidates=32)
        self.assertEqual(result["error"], "evidence_candidate_limit_exceeded")
        self.assertIsNone(result["table"])
        self.assertEqual(result["candidates"], [])
        payload["memories"][0]["text"] = " ".join([TOKEN_A] * 33)
        self.assertEqual(build_answer_evidence(payload, **self.scope, max_candidates=1)["status"], "ok")

    def test_partial_tokens_do_not_create_candidates(self):
        payload = {"query": QUERY_TOKEN,
                   "memories": [{"source_id": "m", "text": TOKEN_A[:-1] + " [PVT_short_PERSON_2]"}]}
        self.assertEqual(build_answer_evidence(payload, **self.scope)["candidates"], [])

    def test_marker_collision_is_retried_and_explicitly_blocked_if_rng_cannot_escape(self):
        tag = "A" * 16
        payload = {"query": "Existing literal E_" + tag + "_1", "memories": self.payload["memories"]}
        with patch("memory_migration_study.answer_evidence.secrets.token_hex", return_value=tag):
            result = build_answer_evidence(payload, **self.scope)
        self.assertEqual(result["error"], "evidence_id_namespace_collision")
        self.assertEqual(result["candidates"], [])

    def test_invalid_scope_payload_policy_and_limits_fail_explicitly(self):
        self.assertEqual(build_answer_evidence(self.payload, **dict(self.scope, actor_id=""))["status"], "blocked")
        self.assertEqual(build_answer_evidence({"query": "x", "memories": [], "gold": "not allowed"}, **self.scope)["status"], "blocked")
        self.assertEqual(build_answer_evidence(self.payload, **dict(self.scope, policy={"version": "1", "protected_categories": ["BAD"]}))["status"], "blocked")
        for limit in (0, -1, True, 1.5, 4097):
            self.assertEqual(build_answer_evidence(self.payload, **self.scope, max_candidates=limit)["error"], "invalid_evidence_candidate_limit")

    def test_new_tables_for_same_request_still_have_distinct_display_tags(self):
        another = build_answer_evidence(self.payload, **self.scope)
        self.assertNotEqual(self.built["candidates"][0]["answer_id"], another["candidates"][0]["answer_id"])

    def test_resolved_token_still_requires_old_authenticated_source_restoration(self):
        # Rules-only preparation exercises the actual existing privacy layer;
        # no model, external data or evaluation answers participate.
        policy = dict(self.scope["policy"], entity_registry=[
            {"value": "Harbor Test Cooperative", "category": "CUSTOMER"},
            {"value": "QuestionOnly-47", "category": "PROJECT"}])
        original = {"query": "Tell me about QuestionOnly-47.",
                    "memories": [{"source_id": "authenticated-source", "text": "Customer: Harbor Test Cooperative"}]}
        detected = detect_sensitive(original, policy, mode="rules")
        prepared = prepare_private_payload(original, detected, actor_id=self.scope["actor_id"],
            request_id=self.scope["request_id"], policy_version=policy["version"], sensitivity_policy=policy,
            authorizer=lambda sid, *_: sid == "authenticated-source")
        self.assertEqual(prepared["status"], "ok")
        scope = dict(self.scope, policy=policy)
        built = build_answer_evidence(prepared["payload"], **scope)
        self.assertEqual(len(built["candidates"]), 1)
        self.assertNotIn("Harbor Test Cooperative", json.dumps(built["candidates"]))
        actual_prepared_ids = {m["source_id"] for m in prepared["payload"]["memories"]}
        resolved = resolve_answer_evidence(json.dumps({"answer_id": built["candidates"][0]["answer_id"]}),
            built["table"], payload=prepared["payload"], authorizer=lambda sid, *_: sid in actual_prepared_ids, **scope)
        self.assertEqual(resolved["status"], "ok")
        self.assertTrue(resolved["token"].startswith("[PVT_"))
        final = restore_answer(resolved["token"], prepared["mapping"], actor_id=scope["actor_id"],
            request_id=scope["request_id"], policy_version=policy["version"], sensitivity_policy=policy,
            authorizer=lambda sid, *_: sid == "authenticated-source")
        self.assertEqual(final["answer"], "Harbor Test Cooperative")
        revoked = restore_answer(resolved["token"], prepared["mapping"], actor_id=scope["actor_id"],
            request_id=scope["request_id"], policy_version=policy["version"], sensitivity_policy=policy,
            authorizer=lambda *_: False)
        self.assertEqual(revoked["error"], "restoration_authorization_failed")


if __name__ == "__main__":
    unittest.main()
