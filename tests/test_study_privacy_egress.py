import copy
import unittest

from memory_migration_study.privacy import _digest, detect_sensitive, prepare_private_payload
from memory_migration_study.privacy_egress import validate_outbound


class EgressTests(unittest.TestCase):
    def setup_payload(self):
        source = {"query": "Who handles the customer?", "memories": [
            {"source_id": "local-private-id", "text": "Customer: Aster Cooperative; Budget: 470,000 USD."}]}
        policy = {"version": "egress-test", "protected_categories": ["CUSTOMER", "AMOUNT"]}
        found = detect_sensitive(source, policy, mode="rules")
        prepared = prepare_private_payload(source, found, actor_id="owner", request_id="request",
                    policy_version=policy["version"], sensitivity_policy=policy, authorizer=lambda *args: True)
        return source, policy, found, prepared

    def test_ready_payload_and_incidental_nonce_not_treated_as_plaintext(self):
        source, policy, found, prepared = self.setup_payload()
        self.assertEqual(validate_outbound(source, prepared, found, policy)["status"], "ok")

    def test_modified_payload_and_original_source_id_are_blocked(self):
        source, policy, found, prepared = self.setup_payload()
        prepared["payload"]["query"] += " changed"
        self.assertEqual(validate_outbound(source, prepared, found, policy)["code"], "outbound_payload_changed")
        prepared["payload"]["memories"][0]["source_id"] = "local-private-id"
        prepared["metadata"]["payload_sha256"] = _digest(prepared["payload"])
        self.assertEqual(validate_outbound(source, prepared, found, policy)["code"], "original_source_identifier_present")

    def test_known_value_remains_even_if_payload_hash_is_recomputed(self):
        source, policy, found, prepared = self.setup_payload()
        prepared["payload"]["query"] += " Aster Cooperative"
        prepared["metadata"]["payload_sha256"] = _digest(prepared["payload"])
        self.assertEqual(validate_outbound(source, prepared, found, policy)["code"], "known_sensitive_value_remains")

    def test_same_version_policy_change_is_blocked(self):
        source, policy, found, prepared = self.setup_payload()
        changed = copy.deepcopy(policy)
        changed["protected_categories"] = []
        self.assertEqual(validate_outbound(source, prepared, found, changed)["code"], "sensitivity_policy_changed")

    def test_same_memories_with_mapping_from_another_query_is_blocked(self):
        source, policy, found, prepared = self.setup_payload()
        other = copy.deepcopy(source)
        other["query"] = "Use another query with these identical memories."
        other_found = detect_sensitive(other, policy, mode="rules")
        other_prepared = prepare_private_payload(other, other_found, actor_id="owner", request_id="other",
                            policy_version=policy["version"], sensitivity_policy=policy, authorizer=lambda *args: True)
        prepared["mapping"] = other_prepared["mapping"]
        self.assertEqual(validate_outbound(source, prepared, found, policy)["code"], "mapping_source_mismatch")

    def test_metadata_cannot_substitute_a_different_policy_mapping(self):
        source, policy, found, prepared = self.setup_payload()
        prepared["metadata"]["policy_sha256"] = "0" * 64
        self.assertEqual(validate_outbound(source, prepared, found, policy)["code"], "mapping_policy_mismatch")

    def test_unknown_token_is_blocked_without_serializing_mapping(self):
        source, policy, found, prepared = self.setup_payload()
        prepared["payload"]["query"] += " [PVT_" + "A" * 24 + "_CUSTOMER_999]"
        prepared["metadata"]["payload_sha256"] = _digest(prepared["payload"])
        self.assertEqual(validate_outbound(source, prepared, found, policy)["code"], "unregistered_outbound_token")

    def test_partial_name_with_surviving_ascii_suffix_is_blocked(self):
        source = {"query": "Project Alder?", "memories": [
            {"source_id": "s", "text": "Aldermark is a separate project."}]}
        policy = {"version": "v", "protected_categories": ["PROJECT"]}
        found = detect_sensitive(source, policy, mode="rules")
        prepared = prepare_private_payload(source, found, actor_id="owner", request_id="r", policy_version="v",
                                           sensitivity_policy=policy, authorizer=lambda *args: True)
        self.assertEqual(validate_outbound(source, prepared, found, policy)["status"], "ok")
        # Simulate a later corruption that appends an inferable entity suffix.
        prepared["payload"]["memories"][0]["text"] = prepared["payload"]["memories"][0]["text"].replace("]", "]mark", 1)
        prepared["metadata"]["payload_sha256"] = _digest(prepared["payload"])
        self.assertEqual(validate_outbound(source, prepared, found, policy)["code"], "ambiguous_entity_boundary")

    def test_short_name_does_not_block_a_different_ordinary_word(self):
        source = {"query": "", "memories": [{"source_id": "s", "text": "Name: A; The camera is ready."}]}
        policy = {"version": "v", "protected_categories": ["PERSON"]}
        found = detect_sensitive(source, policy, mode="rules")
        prepared = prepare_private_payload(source, found, actor_id="owner", request_id="r", policy_version="v",
                                           sensitivity_policy=policy, authorizer=lambda *args: True)
        self.assertEqual(validate_outbound(source, prepared, found, policy)["status"], "ok")
        self.assertIn("camera", prepared["payload"]["memories"][0]["text"])

    def test_cannot_claim_unknown_semantic_values_are_safe(self):
        source = {"query": "Which project is Saffron?", "memories": []}
        policy = {"version": "v", "protected_categories": ["PROJECT"]}
        found = detect_sensitive(source, policy, mode="rules")
        prepared = prepare_private_payload(source, found, actor_id="owner", request_id="r", policy_version="v",
                                           sensitivity_policy=policy, authorizer=lambda *args: True)
        result = validate_outbound(source, prepared, found, policy)
        self.assertEqual(result["scope"], "known_values_and_payload_integrity_only")


if __name__ == "__main__":
    unittest.main()
