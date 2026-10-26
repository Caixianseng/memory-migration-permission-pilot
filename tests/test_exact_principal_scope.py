"""Exact host-authenticated principal contracts; synthetic data, no models."""
from copy import deepcopy
import hashlib
import hmac
import unittest
from unittest.mock import patch

from memory_migration_study.detection_cache import DetectionCache
from memory_migration_study.memory_labels import (
    LABEL_VERSION, MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer,
)
from memory_migration_study.principal_scope import (
    EXACT_PRINCIPAL_SCOPE_VERSION, LEGACY_CARTESIAN_SCOPE_VERSION, PrincipalIdentity,
    grant_allows_principal, legacy_lists_for_exact_pairs, normalize_principal,
    normalize_principal_pairs, principal_scope_version,
)
from memory_migration_study.privacy import _digest


SECRET = b"test-only-exact-principal-key-32-bytes"
PAIRS = [{"user_id": "alice", "agent_id": "A"}, {"user_id": "bob", "agent_id": "B"}]


class FakeDetector:
    """A deterministic unit seam, not a local model invocation."""
    def __init__(self):
        self.calls = 0

    def cache_identity(self):
        return {"fixture": "exact-principal-unit-detector-v1"}

    def __call__(self, *, text, **kwargs):
        self.calls += 1
        findings = [{"quote": "Cedar Lane", "category": "CUSTOMER"}] if "Cedar Lane" in text else []
        return {"status": "ok", "findings": findings, "errors": [],
                "local_calls": 1, "elapsed_seconds": 0.0}


class ExactPrincipalScopeTests(unittest.TestCase):
    def setUp(self):
        self.authority = MemoryLabelAuthority(SECRET)
        self.policy = {"version": "test-exact-policy-v1", "protected_categories": ["CUSTOMER"]}
        text = "Customer is Cedar Lane."
        self.source = {"source_id": "test-only-source", "text": text}
        start = text.index("Cedar Lane")
        self.fact = {"text": text, "source_start": 0, "source_end": len(text),
                     "findings": [{"start": start, "end": start + len("Cedar Lane"), "category": "CUSTOMER"}]}
        self.record = self.build()

    def build(self, pairs=None, **kwargs):
        return self.authority.build_record(self.source, self.fact, self.policy,
            owner_id="owner", agent_id="builder", builder_version="test-exact-builder-v1",
            allowed_principals=PAIRS if pairs is None else pairs, **kwargs)

    def prepare(self, *, user="alice", agent_id="A", record=None, request="request-1", **kwargs):
        kwargs.setdefault("mode", "generation")
        return prepare_labeled_transfer([record or self.record], "", self.policy,
            authority=self.authority, actor_id=user, agent_id=agent_id, request_id=request, **kwargs)

    def restore(self, prepared, *, user="alice", agent="A", record=None, request="request-1"):
        token = next(iter(prepared["mapping"]._entries))
        return restore_labeled_answer(token, prepared, [record or self.record], self.policy,
            authority=self.authority, actor_id=user, agent_id=agent, request_id=request)

    def test_exact_matrix_is_two_pairs_and_never_four_cross_products(self):
        for user in ("alice", "bob"):
            for agent in ("A", "B"):
                with self.subTest(user=user, agent=agent):
                    reason = self.authority.validate_access(self.record, actor_id=user, agent_id=agent)
                    self.assertEqual(reason, None if (user, agent) in {("alice", "A"), ("bob", "B")}
                                     else "principal_not_authorized")
        self.assertEqual(principal_scope_version(self.record["access"]), EXACT_PRINCIPAL_SCOPE_VERSION)
        self.assertNotIn("readers", self.record["access"])
        self.assertNotIn("allowed_agent_ids", self.record["access"])

    def test_owner_is_not_implicitly_added_to_exact_execution_pairs(self):
        for agent in ("A", "B", "builder"):
            self.assertEqual(self.authority.validate_access(self.record, actor_id="owner", agent_id=agent),
                             "principal_not_authorized")

    def test_normalization_matches_reference_actor_shape_and_is_immutable(self):
        identity = normalize_principal({"user_id": "alice", "agent_id": "A"})
        self.assertEqual(identity, PrincipalIdentity("alice", "A"))
        copy = identity.to_dict()
        copy["agent_id"] = "B"
        self.assertEqual(identity.agent_id, "A")
        for bad in ({"user_id": "alice", "agent_id": "A", "admin": True},
                    {"user_id": " alice", "agent_id": "A"},
                    {"user_id": "alice", "agent_id": ""}, "alice:A"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_principal(bad)

    def test_pairs_are_canonicalized_at_issuance_not_reinterpreted_at_read(self):
        record = self.build([PAIRS[1], PAIRS[0], PAIRS[0]])
        self.assertEqual(record["access"]["principal_scope"]["principals"], PAIRS)
        self.assertEqual(normalize_principal_pairs([PrincipalIdentity("alice", "A")]), [PAIRS[0]])
        for bad in ([], [{"user_id": "alice", "agent_id": "A", "public": True}], ["alice"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.build(bad)

    def test_legacy_and_exact_issuance_inputs_cannot_be_mixed(self):
        for extra in ({"readers": []}, {"readers": ["alice"]}, {"allowed_agent_ids": ["A"]}):
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "mixed_principal_scope"):
                self.build(**extra)

    def test_external_pair_rewrite_fails_signature_before_any_fallback(self):
        changed = deepcopy(self.record)
        changed["access"]["principal_scope"]["principals"].append({"user_id": "alice", "agent_id": "B"})
        detector = FakeDetector()
        prepared = self.prepare(user="alice", agent_id="B", record=changed, agent=detector)
        self.assertEqual(prepared["error"], "access_signature_invalid")
        self.assertEqual(detector.calls, 0)
        self.assertIsNone(prepared["payload"])

    def test_even_trusted_mixed_or_unknown_scope_is_refused_not_flattened(self):
        for change in ("mixed", "unknown", "noncanonical"):
            changed = deepcopy(self.record)
            if change == "mixed":
                changed["access"].update(readers=["alice", "bob"], allowed_agent_ids=["A", "B"])
            elif change == "unknown":
                changed["access"]["principal_scope"]["version"] = "guessed-pairs-v0"
            else:
                changed["access"]["principal_scope"]["principals"].reverse()
            changed["access_signature"] = self.authority._sign("access", changed["access"])
            with self.subTest(change=change):
                self.assertEqual(self.authority.validate_access(changed, actor_id="alice", agent_id="A"), "invalid_record")

    def test_legacy_grant_keeps_old_fields_signature_and_cartesian_meaning(self):
        self.assertEqual(self.authority.verification_mode, "offline_snapshot")
        self.assertEqual(self.authority.contract_version, "offline_signed_snapshot_v1")
        with patch("memory_migration_study.memory_labels.secrets.token_hex", return_value="f" * 32):
            record = self.authority.build_record(self.source, self.fact, self.policy,
                owner_id="alice", readers=["bob"], agent_id="builder", allowed_agent_ids=["A", "B"],
                builder_version="test-exact-builder-v1")
        grant = record["access"]
        self.assertEqual(list(grant), ["record_id", "owner_id", "readers", "origin_agent_id", "allowed_agent_ids",
            "source_id", "source_sha256", "epoch", "scope_version", "content_sha256", "source_start", "source_end"])
        self.assertEqual(principal_scope_version(grant), LEGACY_CARTESIAN_SCOPE_VERSION)
        self.assertNotIn("principal_scope", grant)
        expected = hmac.new(SECRET, (LABEL_VERSION + ":access:" + _digest(grant)).encode("ascii"), hashlib.sha256).hexdigest()
        self.assertEqual(record["access_signature"], expected)
        for user in ("alice", "bob"):
            for agent in ("A", "B"):
                self.assertIsNone(self.authority.validate_access(record, actor_id=user, agent_id=agent))
        self.assertEqual(self.prepare(record=record)["status"], "ok")
        self.assertNotIn("principal_binding", self.prepare(record=record))

    def test_lossless_legacy_conversion_rejects_noncartesian_pairs_and_added_owner(self):
        with self.assertRaisesRegex(ValueError, "not_cartesian"):
            legacy_lists_for_exact_pairs(PAIRS, owner_id="alice")
        all_pairs = [{"user_id": user, "agent_id": agent} for user in ("alice", "bob") for agent in ("A", "B")]
        converted = legacy_lists_for_exact_pairs(all_pairs, owner_id="alice")
        self.assertEqual(converted, {"readers": ["alice", "bob"], "allowed_agent_ids": ["A", "B"]})
        with self.assertRaisesRegex(ValueError, "owner_would_expand"):
            legacy_lists_for_exact_pairs(all_pairs, owner_id="owner")
        for pair in all_pairs:
            self.assertTrue(grant_allows_principal(converted, **pair))

    def test_all_transfer_arms_check_pairs_before_detection(self):
        for mode in ("migration", "generation", "two_stage"):
            detector = FakeDetector()
            with self.subTest(mode=mode):
                blocked = self.prepare(user="alice", agent_id="B", mode=mode, agent=detector)
                self.assertEqual(blocked["error"], "principal_not_authorized")
                self.assertEqual(detector.calls, 0)
                allowed = self.prepare(mode=mode, agent=detector)
                self.assertEqual(allowed["status"], "ok")
                self.assertEqual(self.restore(allowed)["answer"], "Cedar Lane")

    def test_restore_rejects_other_legal_pair_without_leaking_value(self):
        prepared = self.prepare()
        self.assertIsNone(self.authority.validate_access(self.record, actor_id="bob", agent_id="B"))
        denied = self.restore(prepared, user="bob", agent="B")
        self.assertEqual(denied["error"], "restoration_principal_binding_mismatch")
        self.assertIsNone(denied["answer"])

    def test_same_user_two_legal_agents_cannot_exchange_recovery_capability(self):
        record = self.build([{"user_id": "alice", "agent_id": agent} for agent in ("A", "B")])
        prepared = self.prepare(record=record)
        self.assertEqual(self.restore(prepared, record=record)["answer"], "Cedar Lane")
        self.assertIsNone(self.authority.validate_access(record, actor_id="alice", agent_id="B"))
        self.assertEqual(self.restore(prepared, record=record, agent="B")["error"], "restoration_principal_binding_mismatch")

    def test_changing_binding_metadata_or_removing_it_cannot_change_agent(self):
        record = self.build([{"user_id": "alice", "agent_id": agent} for agent in ("A", "B")])
        for change in ("agent", "remove", "outbound", "map"):
            prepared = self.prepare(record=record)
            if change == "agent":
                prepared["principal_binding"]["binding"]["principal"]["agent_id"] = "B"
            elif change == "remove":
                del prepared["principal_binding"]
            elif change == "outbound":
                prepared["payload"]["query"] = "changed public metadata"
            else:
                prepared["mapping"] = self.prepare(record=record)["mapping"]
            with self.subTest(change=change):
                self.assertEqual(self.restore(prepared, record=record)["status"], "blocked")

    def test_restoration_rechecks_exact_grant_and_revocation(self):
        prepared = self.prepare()
        self.authority.revoke(self.record["record_id"])
        self.assertEqual(self.restore(prepared)["error"], "grant_revoked")

    def test_detection_cache_cannot_cross_user_agent_scope_or_bypass_pair_check(self):
        cache, detector = DetectionCache(), FakeDetector()
        first = self.prepare(mode="migration", agent=detector, detection_cache=cache)
        again = self.prepare(mode="migration", agent=detector, detection_cache=cache, request="request-2")
        second = self.prepare(user="bob", agent_id="B", mode="migration", agent=detector, detection_cache=cache)
        self.assertEqual([row["status"] for row in (first, again, second)], ["ok"] * 3)
        self.assertEqual([first["local_calls"], again["local_calls"], second["local_calls"]], [1, 0, 1])
        self.assertEqual(detector.calls, 2)
        before = cache.stats()
        blocked = self.prepare(user="alice", agent_id="B", mode="migration", agent=detector, detection_cache=cache)
        self.assertEqual(blocked["error"], "principal_not_authorized")
        self.assertEqual(detector.calls, 2)
        self.assertEqual(cache.stats(), before)


if __name__ == "__main__":
    unittest.main()
