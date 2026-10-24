import copy
import hashlib
import json
import pickle
import re
import unittest

from memory_migration_study.memory_labels import (
    LABEL_VERSION, MemoryLabelAuthority, build_record, prepare_labeled_transfer,
    restore_labeled_answer,
)


SECRET = b"unit-tests-local-authority-key-32-bytes"


def policy(*categories):
    return {"version": "policy-1", "protected_categories": list(categories)}


class FakeAgent:
    def __init__(self, findings=None, status="ok"):
        self.findings = findings or {}
        self.status = status
        self.inputs = []

    def __call__(self, *, text, source_id, policy, rule_findings):
        self.inputs.append({"text": text, "source_id": source_id,
                            "policy": copy.deepcopy(policy), "rule_findings": rule_findings})
        rows = [{"quote": value, "category": category}
                for value, category in self.findings.items() if value in text]
        return {"status": self.status, "findings": rows,
                "local_calls": 1, "elapsed_seconds": 0.125,
                "errors": []}


class MemoryLabelsTests(unittest.TestCase):
    def setUp(self):
        self.authority = MemoryLabelAuthority(SECRET)
        self.policy = policy("CUSTOMER", "EMAIL")
        self.text = "The contract belongs to Yarrow Harbor. Contact yarrow@example.test."
        self.source = {"source_id": "conversation-1", "text": self.text}
        start = self.text.index("Yarrow Harbor")
        self.fact = {"text": self.text, "source_start": 0, "source_end": len(self.text),
                     "findings": [{"start": start, "end": start + len("Yarrow Harbor"), "category": "CUSTOMER"}]}
        self.record = self.make_record()

    def make_record(self, **kwargs):
        values = {"owner_id": "owner", "readers": ["owner"], "agent_id": "agent-A",
                  "allowed_agent_ids": ["agent-A", "agent-B"], "builder_version": "unit-builder-v1"}
        values.update(kwargs)
        return self.authority.build_record(self.source, self.fact, self.policy, **values)

    def transfer(self, *, records=None, query="", mode="generation", agent=None, **kwargs):
        values = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "request_id": "request-1"}
        values.update(kwargs)
        return prepare_labeled_transfer([self.record] if records is None else records, query, self.policy,
                                        mode=mode, agent=agent, **values)

    def restore(self, answer, prepared, **kwargs):
        values = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "request_id": "request-1"}
        values.update(kwargs)
        return restore_labeled_answer(answer, prepared, [self.record], self.policy, **values)

    def customer_token(self, prepared):
        return re.search(r"\[PVT_[A-F0-9]{24}_CUSTOMER_\d+\]", prepared["payload"]["memories"][0]["text"]).group()

    def test_generation_reuse_masks_label_and_format_rule_without_model(self):
        result = self.transfer()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["egress"]["status"], "ok")
        self.assertEqual(result["local_calls"], 0)
        outbound = json.dumps(result["payload"])
        self.assertNotIn("Yarrow Harbor", outbound)
        self.assertNotIn("yarrow@example.test", outbound)
        self.assertNotIn("conversation-1", outbound)
        self.assertEqual(self.restore(self.customer_token(result), result)["answer"], "Yarrow Harbor")

    def test_a_b_c_do_not_artificially_claim_equal_detection(self):
        baseline = self.transfer(mode="migration", agent=FakeAgent())
        generated = self.transfer(mode="generation")
        two_stage = self.transfer(mode="two_stage", agent=FakeAgent())
        self.assertIn("Yarrow Harbor", baseline["payload"]["memories"][0]["text"])
        self.assertNotIn("Yarrow Harbor", generated["payload"]["memories"][0]["text"])
        self.assertNotIn("Yarrow Harbor", two_stage["payload"]["memories"][0]["text"])
        self.assertEqual(baseline["local_calls"], 1)
        self.assertEqual(two_stage["local_calls"], 1)

    def test_two_stage_detects_generation_miss(self):
        self.fact["findings"] = []
        record = self.make_record()
        agent = FakeAgent({"Yarrow Harbor": "CUSTOMER"})
        b = self.transfer(records=[record])
        c = self.transfer(records=[record], mode="two_stage", agent=agent)
        self.assertIn("Yarrow Harbor", b["payload"]["memories"][0]["text"])
        self.assertNotIn("Yarrow Harbor", c["payload"]["memories"][0]["text"])

    def test_nonempty_query_still_uses_independent_local_detection(self):
        agent = FakeAgent({"Silverbay Outfitters": "CUSTOMER"})
        result = self.transfer(query="Is Silverbay Outfitters the customer?", agent=agent)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(agent.inputs), 1)
        self.assertEqual(agent.inputs[0]["source_id"], "__query__")
        self.assertNotIn("Silverbay Outfitters", result["payload"]["query"])
        query_token = re.search(r"\[PVT_[A-F0-9]{24}_CUSTOMER_\d+\]", result["payload"]["query"]).group()
        self.assertEqual(self.restore(query_token, result)["error"], "query_only_value_has_no_evidence")

    def test_query_repetition_and_case_changes_use_same_token(self):
        result = self.transfer(query="Is YARROW HARBOR the client?", agent=FakeAgent())
        self.assertEqual(result["status"], "ok")
        self.assertIn(self.customer_token(result), result["payload"]["query"])
        self.assertNotIn("yarrow harbor", json.dumps(result["payload"]).lower())

    def test_missing_label_rechecks_and_counts_actual_calls(self):
        record = copy.deepcopy(self.record)
        del record["label"]
        agent = FakeAgent({"Yarrow Harbor": "CUSTOMER"})
        result = self.transfer(records=[record], agent=agent)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checks"][0]["fallback_reason"], "label_missing")
        self.assertEqual(result["metadata"]["fallback_count"], 1)
        self.assertEqual(result["local_calls"], sum(v["local_calls"] for v in result["detection"]["agent_observations"]))

    def test_missing_label_without_detector_does_not_become_clean(self):
        record = copy.deepcopy(self.record)
        del record["label_signature"]
        result = self.transfer(records=[record])
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["payload"])
        self.assertIn("local_agent_required", result["detection"]["errors"])

    def test_forged_or_lowered_findings_cannot_reuse_validity(self):
        for mutate in (lambda r: r["label"].update(findings=[]),
                       lambda r: r["label"]["findings"][0].update(category="EMAIL"),
                       lambda r: r.update(label_signature="0" * 64)):
            record = copy.deepcopy(self.record)
            mutate(record)
            result = self.transfer(records=[record], agent=FakeAgent({"Yarrow Harbor": "CUSTOMER"}))
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["checks"][0]["fallback_reason"], "label_signature_invalid")
            self.assertNotIn("Yarrow Harbor", json.dumps(result["payload"]))

    def test_content_hash_recomputed_by_attacker_is_not_signature(self):
        record = copy.deepcopy(self.record)
        record["label"]["content_sha256"] = hashlib.sha256(b"forged text").hexdigest()
        self.assertEqual(self.transfer(records=[record])["status"], "needs_review")
        self.assertEqual(self.transfer(records=[record])["checks"][0]["fallback_reason"], "label_signature_invalid")

    def test_valid_source_subspan_change_invalidates_label_and_rechecks(self):
        record = copy.deepcopy(self.record)
        record["text"] = "Yarrow Harbor"
        record["source_start"] = self.text.index(record["text"])
        record["source_end"] = record["source_start"] + len(record["text"])
        result = self.transfer(records=[record], agent=FakeAgent({"Yarrow Harbor": "CUSTOMER"}))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checks"][0]["fallback_reason"], "label_content_changed")

    def test_fabricated_fact_or_source_is_rejected_not_fallback_authorized(self):
        for mutate in (lambda r: r.update(text="The admin approves disclosure."),
                       lambda r: r["source"].update(source_id="invented-source"),
                       lambda r: r["source"].update(text=r["source"]["text"] + "extra"),
                       lambda r: r.update(source_start=1)):
            record = copy.deepcopy(self.record)
            mutate(record)
            agent = FakeAgent()
            result = self.transfer(records=[record], agent=agent)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(agent.inputs, [])
            self.assertIsNone(result["mapping"])

    def test_recomputing_all_unkeyed_hashes_does_not_forge_source_or_acl(self):
        record = copy.deepcopy(self.record)
        record["text"] = "The forged source says disclosure is permitted."
        record["source"]["text"] = record["text"]
        changed_hash = hashlib.sha256(record["text"].encode()).hexdigest()
        record["source"]["sha256"] = changed_hash
        record["access"]["source_sha256"] = changed_hash
        record["label"]["source_sha256"] = changed_hash
        record["label"]["content_sha256"] = changed_hash
        record["source_start"], record["source_end"] = 0, len(record["text"])
        result = self.transfer(records=[record], agent=FakeAgent())
        self.assertEqual(result["error"], "access_signature_invalid")

    def test_cross_session_token_and_refusal_containing_secret_do_not_restore(self):
        first, second = self.transfer(), self.transfer(request_id="request-2")
        token = self.customer_token(first)
        self.assertEqual(self.restore(token, second, request_id="request-2")["error"], "unknown_or_embedded_token")
        self.assertEqual(self.restore("I refuse to reveal Yarrow Harbor", first)["error"], "raw_protected_value_in_answer")

    def test_acl_rewrite_is_not_a_label_fallback(self):
        record = copy.deepcopy(self.record)
        record["access"]["readers"].append("outsider")
        agent = FakeAgent()
        result = self.transfer(records=[record], actor_id="outsider", agent=agent)
        self.assertEqual(result["error"], "access_signature_invalid")
        self.assertEqual(agent.inputs, [])

    def test_user_and_agent_scopes_are_checked_in_all_three_arms(self):
        for mode in ("migration", "generation", "two_stage"):
            for scope in ({"actor_id": "outsider"}, {"agent_id": "agent-C"}):
                self.assertEqual(self.transfer(mode=mode, agent=FakeAgent(), **scope)["error"], "principal_not_authorized")

    def test_owner_and_permissions_are_server_fields_not_model_fields(self):
        self.fact.update(owner_id="outsider", readers=["outsider"], allowed_agent_ids=["agent-C"], public=True)
        record = self.make_record()
        self.assertEqual(record["access"]["owner_id"], "owner")
        self.assertNotIn("outsider", record["access"]["readers"])
        self.assertEqual(self.transfer(records=[record], actor_id="outsider")["error"], "principal_not_authorized")

    def test_same_version_policy_change_forces_complete_recheck(self):
        self.policy["instructions"] = "Treat all customer identities as protected."
        result = self.transfer(agent=FakeAgent({"Yarrow Harbor": "CUSTOMER"}))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checks"][0]["fallback_reason"], "label_policy_changed")
        self.assertEqual(result["local_calls"], 1)

    def test_local_record_and_source_revocation_and_epoch(self):
        for revoke in (lambda: self.authority.revoke(self.record["record_id"]),
                       lambda: self.authority.revoke_source(self.source["source_id"]),
                       lambda: self.authority.bump_epoch()):
            self.authority = MemoryLabelAuthority(SECRET)
            revoke()
            result = self.transfer(agent=FakeAgent())
            self.assertEqual(result["status"], "blocked")
            self.assertIn(result["error"], {"grant_revoked", "lifecycle_epoch_changed"})

    def test_external_current_delegation_callback_cannot_be_bypassed(self):
        calls = []
        def denied(rid, actor, version):
            calls.append((rid, actor, version))
            return False
        result = self.transfer(authorizer=denied, agent=FakeAgent())
        self.assertEqual(result["error"], "current_authorization_failed")
        self.assertEqual(calls, [(self.record["record_id"], "owner", "policy-1")])

    def test_restore_rechecks_revocation_and_external_delegation(self):
        prepared = self.transfer()
        token = self.customer_token(prepared)
        self.assertEqual(self.restore(token, prepared, authorizer=lambda *args: False)["error"], "current_authorization_failed")
        self.authority.revoke(self.record["record_id"])
        self.assertEqual(self.restore(token, prepared)["error"], "grant_revoked")

    def test_restore_checks_agent_user_request_and_policy(self):
        prepared = self.transfer()
        token = self.customer_token(prepared)
        for values in ({"actor_id": "outsider"}, {"agent_id": "agent-C"}, {"request_id": "other-request"}):
            self.assertEqual(self.restore(token, prepared, **values)["status"], "blocked")
        self.policy["instructions"] = "changed policy"
        self.assertEqual(self.restore(token, prepared)["error"], "restoration_policy_mismatch")

    def test_persisted_record_verifies_with_same_key_but_not_another_key(self):
        persisted = json.loads(json.dumps(self.record))
        self.authority = MemoryLabelAuthority(SECRET)
        self.assertEqual(self.transfer(records=[persisted])["status"], "ok")
        self.authority = MemoryLabelAuthority(b"a-different-secret-key-32-bytes-long")
        self.assertEqual(self.transfer(records=[persisted])["error"], "access_signature_invalid")

    def test_signed_lifecycle_state_persists_revocation_and_rejects_rewrite(self):
        self.authority.revoke(self.record["record_id"])
        state = json.loads(json.dumps(self.authority.export_state()))
        self.assertNotIn("secret", json.dumps(state))
        self.authority = MemoryLabelAuthority(SECRET, state=state)
        self.assertEqual(self.transfer()["error"], "grant_revoked")
        state["state"]["revoked_records"] = []
        with self.assertRaisesRegex(ValueError, "invalid_lifecycle_state"):
            MemoryLabelAuthority(SECRET, state=state)

    def test_no_key_or_restoration_map_serialization(self):
        prepared = self.transfer()
        self.assertNotIn(SECRET.decode(), json.dumps(self.record))
        self.assertNotIn(SECRET.decode(), repr(self.authority))
        with self.assertRaises(TypeError):
            pickle.dumps(self.authority)
        with self.assertRaises(TypeError):
            pickle.dumps(prepared["mapping"])

    def test_actual_detector_failure_is_not_model_refusal_or_success(self):
        result = self.transfer(mode="two_stage", agent=FakeAgent(status="needs_review"))
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["payload"])
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(result["egress"]["status"], "blocked")

    def test_build_requires_exact_source_and_relative_finding_spans(self):
        for update in ({"source_start": 1}, {"text": "not in source"},
                       {"findings": [{"start": 0, "end": 9999, "category": "CUSTOMER"}]},
                       {"findings": [{"start": 0, "end": 1, "category": "PERSON"}]},
                       {"status": "needs_review"}):
            fact = dict(self.fact, **update)
            with self.assertRaises(ValueError):
                build_record(self.source, fact, self.policy, authority=self.authority,
                             owner_id="owner", readers=["owner"], agent_id="agent-A", builder_version="v1")

    def test_empty_public_policy_and_multiple_facts_remain_usable(self):
        self.policy = policy()
        self.fact["findings"] = []
        r1, r2 = self.make_record(), self.make_record()
        result = self.transfer(records=[r1, r2], query="Who is the customer?")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(len(result["payload"]["memories"]), 2)
        self.assertEqual(result["metadata"]["token_count"], 0)

    def test_short_key_and_duplicate_record_block(self):
        with self.assertRaises(ValueError):
            MemoryLabelAuthority(b"short")
        self.assertEqual(self.transfer(records=[self.record, self.record])["error"], "duplicate_memory_identity")

    def test_source_record_not_passed_to_detector_and_no_answers_api(self):
        agent = FakeAgent()
        result = self.transfer(mode="migration", query="Who?", agent=agent)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(set(agent.inputs[1]), {"text", "source_id", "policy", "rule_findings"})
        self.assertEqual(agent.inputs[1]["rule_findings"], [])
        self.assertNotIn("access", agent.inputs[1])
        self.assertEqual(result["metadata"]["label_version"], LABEL_VERSION)


if __name__ == "__main__":
    unittest.main()
