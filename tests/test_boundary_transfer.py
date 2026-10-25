"""Real signed A->B transfer integration; detectors are zero-model stubs."""
import copy
import json
import unittest

from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.privacy import _TOKEN


SECRET = b"boundary-transfer-test-authority-key-32-bytes"


class ZeroModelAgent:
    max_local_calls = 1

    def __init__(self, query_seed=False, value=None):
        self.query_seed, self.value, self.inputs = query_seed, value, []

    def __call__(self, *, text, source_id, policy, rule_findings):
        self.inputs.append((text, source_id, copy.deepcopy(policy), rule_findings))
        findings = []
        if self.query_seed and source_id == "__query__" and text == "客户":
            findings = [{"start": 0, "end": 2, "quote": text, "category": "CUSTOMER"}]
        elif self.value and self.value in text:
            start = text.index(self.value)
            findings = [{"start": start, "end": start+len(self.value), "quote": self.value, "category": "CUSTOMER"}]
        return {"status": "ok", "findings": findings, "errors": [], "local_calls": 0, "elapsed_seconds": 0.0}


class BoundaryTransferTests(unittest.TestCase):
    def setUp(self):
        self.authority = MemoryLabelAuthority(SECRET)
        self.policy = {"version": "a-to-b-v1", "protected_categories": ["CUSTOMER"]}
        self.record = self.make_record()

    def make_record(self, text="Customer: Cedar Labs", *, findings=None, source_id="conversation-A"):
        if findings is None:
            start = text.index("Cedar Labs")
            findings = [{"start": start, "end": start+len("Cedar Labs"), "category": "CUSTOMER"}]
        source = {"source_id": source_id, "text": text}
        fact = {"text": text, "source_start": 0, "source_end": len(text), "findings": findings}
        record = self.authority.build_record(source, fact, self.policy, owner_id="owner", readers=["owner"],
            agent_id="agent-A", allowed_agent_ids=["agent-B"], builder_version="fixed-exact-source-v1", detector_version="fixed-label-v1")
        # Actual persistence/transfer representation, with neither key nor map.
        return json.loads(json.dumps(record, ensure_ascii=False))

    def transfer(self, *, records=None, query="", mode="generation", pipeline="boundary", agent=None, **changes):
        options = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "request_id": "request-B-1"}
        options.update(changes)
        return prepare_labeled_transfer([self.record] if records is None else records, query, self.policy,
            mode=mode, privacy_pipeline=pipeline, agent=agent, **options)

    def restore(self, answer, prepared, *, records=None, **changes):
        options = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "request_id": "request-B-1"}
        options.update(changes)
        return restore_labeled_answer(answer, prepared, [self.record] if records is None else records, self.policy, **options)

    def memory_token(self, prepared):
        return _TOKEN.search(prepared["payload"]["memories"][0]["text"]).group()

    def test_signed_a_build_json_handoff_b_prepare_restore_preserves_fact(self):
        agent = ZeroModelAgent()
        prepared = self.transfer(agent=agent)
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(prepared["egress"]["status"], "ok")
        self.assertEqual(prepared["local_calls"], 0)
        self.assertEqual(agent.inputs, [])
        self.assertNotIn("Cedar Labs", json.dumps(prepared["payload"]))
        self.assertEqual(self.restore(self.memory_token(prepared), prepared)["answer"], "Cedar Labs")

    def test_default_pipeline_remains_legacy_and_unknown_enum_fails_before_detector(self):
        default = prepare_labeled_transfer([self.record], "", self.policy, authority=self.authority,
            actor_id="owner", agent_id="agent-B", request_id="request-B-1", mode="generation")
        explicit = self.transfer(pipeline="legacy")
        self.assertEqual(default["status"], explicit["status"])
        self.assertEqual(self.restore(self.memory_token(default), default)["answer"], "Cedar Labs")
        for invalid in ("all", "Boundary", None, True):
            fake = ZeroModelAgent()
            result = self.transfer(pipeline=invalid, agent=fake)
            self.assertEqual(result["status"], "blocked")
            self.assertIsNone(result["payload"])
            self.assertEqual(fake.inputs, [])

    def test_foreign_actor_or_unapproved_agent_denied_before_any_detection(self):
        for changes in ({"actor_id": "outsider"}, {"agent_id": "agent-C"}):
            fake = ZeroModelAgent()
            result = self.transfer(query="Customer?", agent=fake, **changes)
            self.assertEqual(result["error"], "principal_not_authorized")
            self.assertEqual(fake.inputs, [])
            self.assertEqual(result["local_calls"], 0)
            self.assertIsNone(result["payload"])

    def test_source_or_acl_tamper_cannot_become_valid_via_boundary(self):
        for edit in (lambda r: r["access"]["readers"].append("outsider"),
                     lambda r: r["source"].update(text=r["source"]["text"]+" forged"),
                     lambda r: r.update(source_end=r["source_end"]-1)):
            changed = copy.deepcopy(self.record)
            edit(changed)
            fake = ZeroModelAgent()
            result = self.transfer(records=[changed], agent=fake)
            self.assertEqual(result["status"], "blocked")
            self.assertIn(result["error"], {"access_signature_invalid", "source_identity_changed", "fact_source_location_invalid"})
            self.assertEqual(fake.inputs, [])

    def test_invalid_label_signature_triggers_real_fallback_without_granting_access(self):
        changed = copy.deepcopy(self.record)
        changed["label_signature"] = "0" * 64
        fake = ZeroModelAgent(value="Cedar Labs")
        result = self.transfer(records=[changed], agent=fake)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checks"][0]["fallback_reason"], "label_signature_invalid")
        self.assertEqual(len(fake.inputs), 1)
        self.assertEqual(self.restore(self.memory_token(result), result, records=[changed])["answer"], "Cedar Labs")

    def test_valid_signed_generation_spans_cannot_be_removed_as_field_keys(self):
        text = "Customer:"
        record = self.make_record(text, findings=[{"start": 0, "end": 8, "category": "CUSTOMER"}])
        for mode in ("generation", "two_stage"):
            result = self.transfer(records=[record], mode=mode, agent=ZeroModelAgent())
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["checks"][0]["label_valid"], True)
            self.assertNotIn("Customer", result["payload"]["memories"][0]["text"])
            self.assertTrue(any(f["source_id"] == record["record_id"] and f["start"] <= 0 and f["end"] >= 8
                                for f in result["detection"]["findings"]))

    def test_query_key_only_fails_as_business_evidence_on_real_transfer_chain(self):
        record = self.make_record("客户：尚未填写", findings=[])
        results = {}
        for pipeline in ("legacy", "boundary"):
            prepared = self.transfer(records=[record], query="客户", mode="migration", pipeline=pipeline,
                agent=ZeroModelAgent(query_seed=True))
            self.assertEqual(prepared["status"], "ok")
            results[pipeline] = self.restore(prepared["payload"]["query"], prepared, records=[record])
        self.assertEqual(results["legacy"]["answer"], "客户")
        self.assertEqual(results["boundary"]["error"], "query_only_value_has_no_evidence")

    def test_true_same_name_value_in_a_memory_still_restores(self):
        record = self.make_record("客户：客户", findings=[{"start": 3, "end": 5, "category": "CUSTOMER"}])
        prepared = self.transfer(records=[record], query="客户", agent=ZeroModelAgent(query_seed=True))
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(self.restore(prepared["payload"]["query"], prepared, records=[record])["answer"], "客户")

    def test_record_revoke_blocks_old_restore_and_old_request_replay(self):
        prepared = self.transfer()
        value = self.memory_token(prepared)
        self.authority.revoke(self.record["record_id"])
        self.assertEqual(self.restore(value, prepared)["error"], "grant_revoked")
        fake = ZeroModelAgent()
        replay = self.transfer(query="Customer?", agent=fake)
        self.assertEqual(replay["error"], "grant_revoked")
        self.assertEqual(fake.inputs, [])

    def test_source_revocation_or_epoch_change_blocks_transfer(self):
        for action, expected in ((lambda: self.authority.revoke_source("conversation-A"), "grant_revoked"),
                                 (lambda: self.authority.bump_epoch(), "lifecycle_epoch_changed")):
            self.authority = MemoryLabelAuthority(SECRET)
            action()
            fake = ZeroModelAgent()
            result = self.transfer(agent=fake)
            self.assertEqual(result["error"], expected)
            self.assertEqual(fake.inputs, [])

    def test_restore_rechecks_actor_agent_request_and_external_authorizer(self):
        prepared = self.transfer()
        value = self.memory_token(prepared)
        for change in ({"actor_id": "outsider"}, {"agent_id": "agent-C"}, {"request_id": "other-request"},
                       {"authorizer": lambda *_: False}):
            self.assertEqual(self.restore(value, prepared, **change)["status"], "blocked")

    def test_strict_all_record_recheck_survives_source_relation_tightening(self):
        key = self.make_record("客户：尚未填写", findings=[], source_id="key-source")
        real = self.make_record("客户：客户", findings=[{"start": 3, "end": 5, "category": "CUSTOMER"}], source_id="real-source")
        records = [key, real]
        prepared = self.transfer(records=records, query="客户", agent=ZeroModelAgent(query_seed=True))
        self.assertEqual(self.restore(prepared["payload"]["query"], prepared, records=records)["answer"], "客户")
        self.authority.revoke(key["record_id"])
        self.assertEqual(self.restore(prepared["payload"]["query"], prepared, records=records)["error"], "grant_revoked")

    def test_secret_bearing_refusal_is_rejected_by_real_b_restore(self):
        prepared = self.transfer()
        self.assertEqual(self.restore("I refuse, but Cedar Labs", prepared)["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
