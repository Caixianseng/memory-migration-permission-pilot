import copy
import json
import pickle
import unittest
from unittest.mock import patch

from memory_migration_study import boundary_preparation as boundary
from memory_migration_study.boundary_preparation import prepare_boundary_payload
from memory_migration_study.privacy import detect_sensitive, prepare_private_payload, restore_answer


class BoundaryPreparationTests(unittest.TestCase):
    def policy(self):
        return {"version": "evidence-test", "protected_categories": ["CUSTOMER"]}

    def data(self, memories, query="Customer: Customer"):
        return {"query": query, "memories": [{"source_id": sid, "text": text} for sid, text in memories]}

    def authorized(self, sid, actor_id, version):
        return actor_id == "owner" and version == "evidence-test"

    def prepare(self, data, *, old=False, authorizer=None):
        policy = self.policy()
        detection = detect_sensitive(data, policy, mode="rules")
        function = prepare_private_payload if old else prepare_boundary_payload
        return function(data, detection, actor_id="owner", request_id="r1", policy_version=policy["version"],
                        authorizer=authorizer or self.authorized, sensitivity_policy=policy)

    def token(self, prepared, value="Customer"):
        return next(token for token, entry in prepared["mapping"]._entries.items() if entry.value.casefold() == value.casefold())

    def restore(self, prepared, *, value="Customer", **changes):
        options = {"actor_id": "owner", "request_id": "r1", "policy_version": "evidence-test",
                   "authorizer": self.authorized, "sensitivity_policy": self.policy()}
        options.update(changes)
        return restore_answer(self.token(prepared, value), prepared["mapping"], **options)

    def test_actual_key_only_witness_old_returns_query_fact_new_has_no_memory_evidence(self):
        data = self.data([("m", "Customer:")])
        old = self.prepare(data, old=True)
        new = self.prepare(data)
        self.assertEqual(old["status"], "ok")
        self.assertEqual(new["status"], "ok")
        self.assertEqual(self.restore(old)["answer"], "Customer")
        self.assertEqual(self.restore(new)["error"], "query_only_value_has_no_evidence")
        stats = new["metadata"]["boundary_preparation"]
        self.assertEqual(stats["source_relations_before"], 1)
        self.assertEqual(stats["source_relations_after"], 0)
        self.assertEqual(stats["removed_key_only_source_relations"], 1)
        self.assertEqual(new["mapping"]._entries[self.token(new)].sources, ())

    def test_true_same_named_value_in_same_source_still_restores(self):
        data = self.data([("m", "Customer: Customer")])
        new = self.prepare(data)
        self.assertEqual(new["status"], "ok")
        self.assertEqual(self.restore(new)["answer"], "Customer")
        self.assertEqual(new["mapping"]._entries[self.token(new)].sources, ("m",))
        self.assertEqual(new["metadata"]["boundary_preparation"]["removed_key_only_source_relations"], 0)

    def test_true_same_named_value_in_another_source_only_key_source_removed(self):
        data = self.data([("key_only", "Customer:"), ("fact", "Customer: Customer")])
        new = self.prepare(data)
        self.assertEqual(new["status"], "ok")
        self.assertEqual(new["mapping"]._entries[self.token(new)].sources, ("fact",))
        self.assertEqual(self.restore(new)["answer"], "Customer")
        self.assertEqual(new["metadata"]["boundary_preparation"]["removed_key_only_source_relations"], 1)
        # A key-only source is no longer asserted to be a factual dependency.
        answer = self.restore(new, authorizer=lambda sid, actor, version: sid == "fact")
        self.assertEqual(answer["answer"], "Customer")

    def test_query_only_value_without_any_memory_remains_blocked(self):
        new = self.prepare(self.data([]))
        self.assertEqual(new["status"], "ok")
        self.assertEqual(self.restore(new)["error"], "query_only_value_has_no_evidence")
        self.assertEqual(new["metadata"]["boundary_preparation"]["source_relations_before"], 0)

    def test_chinese_true_name_equal_to_field_key_keeps_real_value_occurrence(self):
        data = self.data([("m", "客户：客户")], query="客户：客户")
        new = self.prepare(data)
        self.assertEqual(new["status"], "ok")
        self.assertEqual(self.restore(new, value="客户")["answer"], "客户")
        key_only = self.prepare(self.data([("m", "客户：")], query="客户：客户"))
        self.assertEqual(self.restore(key_only, value="客户")["error"], "query_only_value_has_no_evidence")

    def test_one_nonkey_interval_keeps_source_even_when_other_intervals_are_keys(self):
        data = self.data([("m", 'Customer: "Customer"; Notes: Customer')])
        new = self.prepare(data)
        self.assertEqual(new["status"], "ok")
        self.assertEqual(self.restore(new)["answer"], "Customer")
        self.assertEqual(new["mapping"]._entries[self.token(new)].sources, ("m",))

    def test_actual_interval_must_be_fully_inside_key_not_merely_overlap(self):
        data = self.data([("m", "Customer:")], query="")
        policy = self.policy()
        detection = detect_sensitive(data, policy, mode="rules")
        detection["findings"] = [{"source_id": "m", "start": 0, "end": len("Customer:"),
                                   "category": "CUSTOMER", "policy_id": policy["version"], "method": "controlled_interval"}]
        new = prepare_boundary_payload(data, detection, actor_id="owner", request_id="r1", policy_version=policy["version"],
                                       authorizer=self.authorized, sensitivity_policy=policy)
        self.assertEqual(new["status"], "ok")
        self.assertEqual(self.restore(new, value="Customer:")["answer"], "Customer:")
        self.assertEqual(new["metadata"]["boundary_preparation"]["removed_key_only_source_relations"], 0)

    def test_original_prepare_authorization_cannot_be_bypassed_by_key_pruning(self):
        calls = []
        def denied(sid, actor, version):
            calls.append(sid)
            return False
        new = self.prepare(self.data([("key_only", "Customer:")]), authorizer=denied)
        self.assertEqual(new["status"], "needs_review")
        self.assertEqual(new["error"], "memory_authorization_failed")
        self.assertIsNone(new["mapping"])
        self.assertIsNone(new["payload"])
        self.assertEqual(calls, ["key_only"])

    def test_all_remaining_real_sources_still_need_current_authorization(self):
        data = self.data([("first", "Customer: Customer"), ("second", "Customer: Customer"), ("key", "Customer:")])
        new = self.prepare(data)
        self.assertEqual(new["status"], "ok")
        self.assertEqual(new["mapping"]._entries[self.token(new)].sources, ("first", "second"))
        self.assertEqual(self.restore(new)["answer"], "Customer")
        revoked = self.restore(new, authorizer=lambda sid, actor, version: sid == "first")
        self.assertEqual(revoked["error"], "restoration_authorization_failed")

    def test_bindings_policy_changes_and_unknown_token_checks_unchanged(self):
        new = self.prepare(self.data([("m", "Customer: Customer")]))
        for change in ({"actor_id": "other"}, {"request_id": "r2"}, {"policy_version": "next"}):
            with self.subTest(change=change):
                self.assertEqual(self.restore(new, **change)["error"], "restoration_scope_mismatch")
        changed_policy = {**self.policy(), "instructions": "Different current policy."}
        self.assertEqual(self.restore(new, sensitivity_policy=changed_policy)["error"], "restoration_policy_mismatch")
        result = restore_answer("[PVT_000000000000000000000000_CUSTOMER_99]", new["mapping"],
            actor_id="owner", request_id="r1", policy_version="evidence-test", authorizer=self.authorized)
        self.assertEqual(result["error"], "unknown_or_embedded_token")

    def test_masking_payload_intervals_and_all_non_source_map_fields_unchanged(self):
        data = self.data([("key", "Customer:"), ("fact", "Customer: Customer")])
        with patch("memory_migration_study.privacy.secrets.token_hex", return_value="a"*24):
            old, new = self.prepare(data, old=True), self.prepare(data)
        self.assertEqual(old["payload"], new["payload"])
        for name in ("_actor_id", "_request_id", "_policy_version", "_policy_sha256", "_source_payload_sha256", "_nonce",
                     "_memories", "_protected_values", "_sensitive_spans"):
            self.assertEqual(getattr(old["mapping"], name), getattr(new["mapping"], name))
        for token, entry in new["mapping"]._entries.items():
            original = old["mapping"]._entries[token]
            self.assertEqual((entry.value, entry.categories), (original.value, original.categories))
            self.assertTrue(set(entry.sources).issubset(original.sources))

    def test_new_capability_nested_maps_immutable_nonserializable_and_no_aliases(self):
        data = self.data([("key", "Customer:"), ("fact", "Customer: Customer")])
        captured = []
        original_prepare = prepare_private_payload
        def capture(*args, **kwargs):
            result = original_prepare(*args, **kwargs)
            captured.append(result["mapping"])
            return result
        with patch.object(boundary, "prepare_private_payload", side_effect=capture):
            new = self.prepare(data)
        mapping, token = new["mapping"], self.token(new)
        with self.assertRaises(TypeError):
            mapping._entries[token] = mapping._entries[token]
        with self.assertRaises(TypeError):
            mapping._memories["fact"] = "altered"
        with self.assertRaises(TypeError):
            mapping._sensitive_spans["fact"] = ()
        with self.assertRaises(AttributeError):
            mapping._nonce = "other"
        with self.assertRaises(Exception):
            mapping._entries[token].sources = ("new",)
        with self.assertRaises(TypeError):
            pickle.dumps(mapping)
        with self.assertRaises(TypeError):
            json.dumps(mapping)
        self.assertNotIn("Customer", repr(mapping))
        captured[0]._entries.clear()
        captured[0]._memories.clear()
        captured[0]._sensitive_spans.clear()
        self.assertEqual(self.restore(new)["answer"], "Customer")

    def test_parser_failure_or_binding_mismatch_discards_payload_and_mapping(self):
        data = self.data([("m", "Customer: Customer")])
        with patch.object(boundary, "propose_field_findings", return_value={"status": "needs_review"}):
            failed = self.prepare(data)
        self.assertEqual(failed["status"], "needs_review")
        self.assertEqual(failed["error"], "field_evidence_parse_failed")
        self.assertIsNone(failed["mapping"])
        self.assertIsNone(failed["payload"])
        original_parser = boundary.propose_field_findings
        def changed(*args, **kwargs):
            result = original_parser(*args, **kwargs)
            result["full_policy_sha256"] = "0"*64
            return result
        with patch.object(boundary, "propose_field_findings", side_effect=changed):
            failed = self.prepare(data)
        self.assertIsNone(failed["mapping"])
        self.assertIsNone(failed["payload"])
        with patch.object(boundary, "propose_field_findings", side_effect=RuntimeError("SECRET_EXCEPTION")):
            failed = self.prepare(data)
        self.assertIsNone(failed["mapping"])
        self.assertNotIn("SECRET_EXCEPTION", repr(failed))

    def test_caller_inputs_unchanged_metadata_has_no_value_token_or_per_entry_map(self):
        data, policy = self.data([("m", "Customer: Very Private Name")], query="Who is the customer?"), self.policy()
        detection = detect_sensitive(data, policy, mode="rules")
        original = copy.deepcopy((data, detection, policy))
        result = prepare_boundary_payload(data, detection, actor_id="owner", request_id="r1", policy_version=policy["version"],
                                          authorizer=self.authorized, sensitivity_policy=policy)
        self.assertEqual(result["status"], "ok")
        self.assertEqual((data, detection, policy), original)
        serialized = json.dumps(result["metadata"])
        self.assertNotIn("Very Private Name", serialized)
        self.assertNotIn("[PVT_", serialized)
        self.assertNotIn("mapping", serialized)
        self.assertEqual(result["metadata"]["token_count"], len(result["mapping"]._entries))


if __name__ == "__main__":
    unittest.main()
