"""Record-level grant regression tests; all material is self-authored, no model."""
import copy
import json
import unittest

from memory_migration_study.memory_labels import (
    ACCESS_SCOPE_VERSION, MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer,
)
from memory_migration_study.privacy import _TOKEN, _digest


class ZeroModelAgent:
    max_local_calls = 1

    def __init__(self):
        self.inputs = []

    def __call__(self, **kwargs):
        self.inputs.append(kwargs)
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 0, "elapsed_seconds": 0.0}


class MemoryAccessContentBindingTests(unittest.TestCase):
    def setUp(self):
        self.key = b"self-authored-binding-regression-key-32-bytes"
        self.authority = MemoryLabelAuthority(self.key)
        self.policy = {"version": "content-bound-v1", "protected_categories": ["CUSTOMER"]}
        first = "Customer: Cedar Collective"
        second = "Customer: Pine Reserve"
        self.source = {"source_id": "synthetic-conversation", "text": first+"\n"+second+"\n"+first}
        self.record = self.authority.build_record(self.source,
            {"text": first, "source_start": 0, "source_end": len(first), "findings": [
                {"start": len("Customer: "), "end": len(first), "category": "CUSTOMER"}]},
            self.policy, owner_id="owner", readers=["alice"], agent_id="agent-A", allowed_agent_ids=["agent-B"],
            builder_version="exact-source-fixture", detector_version="zero-model-fixture")

    def access(self, record):
        return self.authority.validate_access(record, actor_id="alice", agent_id="agent-B", policy_version=self.policy["version"])

    def prepare(self, record, agent):
        return prepare_labeled_transfer([record], "", self.policy, authority=self.authority,
            actor_id="alice", agent_id="agent-B", request_id="binding-request", mode="generation",
            privacy_pipeline="boundary", agent=agent)

    def test_new_grant_explicitly_signs_exact_content_and_source_occurrence(self):
        grant = self.record["access"]
        self.assertEqual(grant["scope_version"], ACCESS_SCOPE_VERSION)
        self.assertEqual(grant["source_start"], self.record["source_start"])
        self.assertEqual(grant["source_end"], self.record["source_end"])
        self.assertEqual(len(grant["content_sha256"]), 64)
        self.assertIsNone(self.access(self.record))
        self.assertEqual(self.record["label"]["access_sha256"], _digest(grant))

    def test_consistent_other_slice_same_source_does_not_become_label_fallback(self):
        changed = copy.deepcopy(self.record)
        start = self.source["text"].index("Customer: Pine Reserve")
        end = self.source["text"].index("\n", start)
        changed.update(text=self.source["text"][start:end], source_start=start, source_end=end)
        self.assertEqual(changed["source"]["sha256"], self.record["source"]["sha256"])
        self.assertEqual(changed["access_signature"], self.record["access_signature"])
        self.assertEqual(self.access(changed), "access_content_changed")
        self.assertEqual(self.authority.validate_label(changed, self.policy), "label_content_changed")
        fake = ZeroModelAgent()
        result = self.prepare(changed, fake)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["error"], "access_content_changed")
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(fake.inputs, [])
        self.assertIsNone(result["payload"])
        self.assertIsNone(result["mapping"])

    def test_identical_text_at_second_source_occurrence_is_not_same_granted_fact(self):
        changed = copy.deepcopy(self.record)
        start = self.source["text"].rindex(self.record["text"])
        changed.update(source_start=start, source_end=start+len(self.record["text"]))
        self.assertEqual(changed["text"], self.record["text"])
        self.assertNotEqual(changed["source_start"], self.record["source_start"])
        self.assertEqual(self.access(changed), "access_content_changed")
        fake = ZeroModelAgent()
        result = self.prepare(changed, fake)
        self.assertEqual(result["error"], "access_content_changed")
        self.assertEqual(fake.inputs, [])

    def test_invalid_or_missing_label_correct_access_scope_still_falls_back(self):
        for remove in (False, True):
            with self.subTest(remove=remove):
                changed = copy.deepcopy(self.record)
                if remove:
                    changed.pop("label")
                    changed.pop("label_signature")
                else:
                    changed["label_signature"] = "0"*64
                self.assertIsNone(self.access(changed))
                fake = ZeroModelAgent()
                result = self.prepare(changed, fake)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["metadata"]["fallback_count"], 1)
                self.assertEqual(len(fake.inputs), 1)
                token = _TOKEN.search(result["payload"]["memories"][0]["text"]).group()
                restored = restore_labeled_answer(token, result, [changed], self.policy, authority=self.authority,
                    actor_id="alice", agent_id="agent-B", request_id="binding-request")
                self.assertEqual(restored["answer"], "Cedar Collective")

    def test_authentic_legacy_grant_missing_binding_is_explicitly_rejected_not_upgraded(self):
        legacy = copy.deepcopy(self.record)
        for field in ("scope_version", "content_sha256", "source_start", "source_end"):
            legacy["access"].pop(field)
        # Reproduce a legitimately signed old format, not merely an unsigned
        # attacker edit. Historical signature verification remains available.
        legacy["access_signature"] = self.authority._sign("access", legacy["access"])
        before = json.dumps(legacy, sort_keys=True)
        self.assertTrue(self.authority._valid_signature("access", legacy["access"], legacy["access_signature"]))
        self.assertEqual(self.access(legacy), "access_content_binding_missing")
        fake = ZeroModelAgent()
        result = self.prepare(legacy, fake)
        self.assertEqual(result["error"], "access_content_binding_missing")
        self.assertEqual(fake.inputs, [])
        self.assertEqual(json.dumps(legacy, sort_keys=True), before)

    def test_binding_fields_cannot_be_rewritten_without_invalidating_access_signature(self):
        for field, value in (("scope_version", "other"), ("content_sha256", "0"*64), ("source_start", 1), ("source_end", 1)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.record)
                changed["access"][field] = value
                self.assertEqual(self.access(changed), "access_signature_invalid")

    def test_signed_unsupported_or_malformed_binding_fails_closed(self):
        for field, value, expected in (("scope_version", "future-v99", "access_scope_version_unsupported"),
                                       ("content_sha256", "not-a-hash", "access_content_binding_invalid"),
                                       ("source_start", True, "access_content_binding_invalid"),
                                       ("source_end", 1.5, "access_content_binding_invalid")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.record)
                changed["access"][field] = value
                changed["access_signature"] = self.authority._sign("access", changed["access"])
                self.assertEqual(self.access(changed), expected)

    def test_acl_and_full_source_tampering_remain_denied_before_fallback(self):
        for edit, expected in ((lambda r: r["access"]["readers"].append("outsider"), "access_signature_invalid"),
                               (lambda r: r["source"].update(text=r["source"]["text"]+"changed"), "source_identity_changed")):
            with self.subTest(expected=expected):
                changed = copy.deepcopy(self.record)
                edit(changed)
                fake = ZeroModelAgent()
                result = self.prepare(changed, fake)
                self.assertEqual(result["error"], expected)
                self.assertEqual(fake.inputs, [])

    def test_lifecycle_state_export_import_and_revocation_contract_unchanged(self):
        self.authority.revoke(self.record["record_id"])
        state = json.loads(json.dumps(self.authority.export_state()))
        reloaded = MemoryLabelAuthority(self.key, state=state)
        self.assertEqual(reloaded.validate_access(self.record, actor_id="alice", agent_id="agent-B"), "grant_revoked")
        state["state"]["revoked_records"] = []
        with self.assertRaises(ValueError):
            MemoryLabelAuthority(self.key, state=state)


if __name__ == "__main__":
    unittest.main()
