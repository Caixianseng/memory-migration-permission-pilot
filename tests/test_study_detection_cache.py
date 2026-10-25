import copy
import pickle
import re
import unittest

from memory_migration_study.detection_cache import DetectionCache
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer


class Detector:
    def __init__(self):
        self.version, self.calls, self.status = "test-detector-1", 0, "ok"
        self.bad_span = False

    def cache_identity(self):
        return {"version": self.version, "parameters": {"seed": 42}}

    def __call__(self, *, text, source_id, policy, rule_findings):
        self.calls += 1
        findings = []
        for match in re.finditer("Aster Bay", text):
            findings.append({"quote": "Aster Bay", "category": "CUSTOMER", "start": match.start(), "end": match.end()})
        if self.bad_span:
            findings = [{"quote": "not in input", "category": "CUSTOMER"}]
        return {"status": self.status, "findings": findings, "errors": [], "local_calls": 1, "elapsed_seconds": .01}


class DetectionCacheTests(unittest.TestCase):
    def setUp(self):
        self.detector = Detector()
        self.now = [10.0]
        self.cache = DetectionCache(clock=lambda: self.now[0])
        self.authority = MemoryLabelAuthority(b"synthetic-test-key-not-a-credential-32")
        self.policy = {"version": "policy-1", "protected_categories": ["CUSTOMER"], "instructions": "Protect customer names."}
        self.text = "The customer is Aster Bay."
        start = self.text.index("Aster Bay")
        self.record = self.authority.build_record(
            {"source_id": "conversation", "text": self.text},
            {"text": self.text, "source_start": 0, "source_end": len(self.text),
             "findings": [{"start": start, "end": start + 9, "category": "CUSTOMER"}]},
            self.policy, owner_id="owner", readers=["colleague"], agent_id="source-agent",
            allowed_agent_ids=["target-agent", "other-agent"], builder_version="builder-1", detector_version="generation-detector-1")

    def transfer(self, **overrides):
        args = dict(authority=self.authority, actor_id="owner", agent_id="target-agent", request_id="request-1",
                    mode="migration", agent=self.detector, detection_cache=self.cache)
        args.update(overrides)
        return prepare_labeled_transfer([self.record], "Who is the customer?", self.policy, **args)

    def test_warm_cache_avoids_real_calls_but_new_tokens_are_fresh(self):
        cold = self.transfer()
        warm = self.transfer(request_id="request-2")
        self.assertEqual((cold["local_calls"], warm["local_calls"]), (2, 0))
        self.assertEqual(warm["metadata"]["detection_cache"]["hits"], 2)
        self.assertEqual(cold["detection"]["findings"], warm["detection"]["findings"])
        self.assertNotEqual(cold["payload"]["memories"][0]["text"], warm["payload"]["memories"][0]["text"])
        token = re.search(r"\[PVT_[^\]]+\]", warm["payload"]["memories"][0]["text"]).group()
        restored = restore_labeled_answer(token, warm, [self.record], self.policy, authority=self.authority,
                                         actor_id="owner", agent_id="target-agent", request_id="request-2")
        self.assertEqual(restored["answer"], "Aster Bay")

    def test_current_authorization_precedes_even_warm_cache(self):
        self.transfer()
        calls = self.detector.calls
        denied = self.transfer(authorizer=lambda *args: False)
        self.assertEqual(denied["error"], "current_authorization_failed")
        self.assertEqual(self.detector.calls, calls)
        self.authority.revoke(self.record["record_id"])
        self.assertEqual(self.transfer()["error"], "grant_revoked")
        self.assertEqual(self.detector.calls, calls)

    def test_revoke_after_cached_preparation_still_blocks_restoration(self):
        self.transfer()
        warm = self.transfer()
        token = re.search(r"\[PVT_[^\]]+\]", warm["payload"]["memories"][0]["text"]).group()
        self.authority.revoke_source("conversation")
        restored = restore_labeled_answer(token, warm, [self.record], self.policy, authority=self.authority,
                                         actor_id="owner", agent_id="target-agent", request_id="request-1")
        self.assertEqual(restored["error"], "grant_revoked")

    def test_cache_isolated_by_user_agent_and_authority(self):
        self.transfer()
        self.assertEqual(self.transfer(actor_id="colleague")["local_calls"], 2)
        self.assertEqual(self.transfer(agent_id="other-agent")["local_calls"], 2)
        other = MemoryLabelAuthority(b"different-authority-test-key-32-bytes")
        self.assertEqual(self.transfer(authority=other)["error"], "access_signature_invalid")

    def test_full_policy_change_with_unchanged_version_invalidates_cache(self):
        self.transfer()
        self.policy["instructions"] += " Also protect client aliases."
        self.assertEqual(self.transfer()["local_calls"], 2)

    def test_detector_change_and_ttl_force_new_detection(self):
        self.transfer()
        self.detector.version = "test-detector-2"
        self.assertEqual(self.transfer()["local_calls"], 2)
        self.now[0] += 301
        again = self.transfer()
        self.assertEqual(again["local_calls"], 2)
        self.assertEqual(again["metadata"]["detection_cache"]["expired"], 2)

    def test_modified_fact_cannot_reuse_old_offsets(self):
        self.transfer()
        calls = self.detector.calls
        self.record["text"] = "Aster Bay"
        self.record["source_start"] = self.text.index("Aster Bay")
        self.record["source_end"] = self.record["source_start"] + 9
        new = self.transfer()
        # A changed exact-fact record has no authorization. Do not classify it
        # or let a cached query turn label fallback into a fresh access grant.
        self.assertEqual(new["error"], "access_content_changed")
        self.assertEqual(new["local_calls"], 0)
        self.assertEqual(self.detector.calls, calls)
        self.assertIsNone(new["payload"])

    def test_newly_authorized_changed_fact_misses_old_scope_and_uses_new_offsets(self):
        self.transfer()
        calls = self.detector.calls
        start = self.text.index("Aster Bay")
        # Only the trusted host can issue a new exact fact grant. Retain the old
        # cache to exercise changed content and grant-domain invalidation.
        self.record = self.authority.build_record(
            {"source_id": "conversation", "text": self.text},
            {"text": "Aster Bay", "source_start": start, "source_end": start + 9,
             "findings": [{"start": 0, "end": 9, "category": "CUSTOMER"}]},
            self.policy, owner_id="owner", readers=["colleague"], agent_id="source-agent",
            allowed_agent_ids=["target-agent", "other-agent"], builder_version="builder-1", detector_version="generation-detector-1")
        new = self.transfer()
        self.assertEqual(new["status"], "ok")
        # Current cache scope includes the signed grants, so both the identical
        # query and the changed memory legitimately miss in this new scope.
        self.assertEqual(new["local_calls"], 2)
        self.assertEqual(self.detector.calls - calls, 2)
        self.assertEqual(new["metadata"]["detection_cache"]["hits"], 0)
        self.assertEqual(new["metadata"]["detection_cache"]["misses"], 2)
        memory_findings = [f for f in new["detection"]["findings"] if f["source_id"] == self.record["record_id"]]
        self.assertTrue(any((f["start"], f["end"]) == (0, 9) for f in memory_findings))
        self.assertNotIn("Aster Bay", new["payload"]["memories"][0]["text"])
        self.assertEqual(self.transfer()["local_calls"], 0)

    def test_needs_review_and_invalid_spans_are_never_cached(self):
        for attr, value in (("status", "needs_review"), ("bad_span", True)):
            self.detector = Detector()
            self.cache.clear()
            setattr(self.detector, attr, value)
            first, second = self.transfer(), self.transfer()
            self.assertEqual(first["status"], "needs_review")
            self.assertEqual(second["local_calls"], 2)
            self.assertEqual(self.cache.stats()["entries"], 0)

    def test_mutated_result_and_repr_cannot_poison_or_expose_cache(self):
        cold = self.transfer()
        cold["detection"]["findings"].clear()
        self.assertTrue(self.transfer()["detection"]["findings"])
        self.assertNotIn("Aster Bay", repr(self.cache))
        self.assertNotIn("Aster Bay", str(self.cache.stats()))
        with self.assertRaises(TypeError):
            pickle.dumps(self.cache)

    def test_lru_bound_and_clear(self):
        self.cache = DetectionCache(max_entries=1)
        self.transfer()
        self.assertEqual(self.cache.stats()["entries"], 1)
        self.assertEqual(self.cache.stats()["evictions"], 1)
        self.cache.clear()
        self.assertEqual(self.cache.stats()["entries"], 0)

    def test_unversioned_detector_is_explicit_bypass(self):
        result = self.transfer(agent=lambda **kwargs: self.detector(**kwargs))
        self.assertEqual(result["metadata"]["detection_cache"]["bypasses"], 2)
        self.assertEqual(self.cache.stats()["entries"], 0)

    def test_stale_label_detector_and_builder_require_fallback(self):
        for requirements, reason in (
            ({"expected_detector_version": "generation-detector-2"}, "label_detector_changed"),
            ({"expected_builder_version": "builder-2"}, "label_builder_changed"),
        ):
            self.cache.clear()
            result = self.transfer(mode="generation", label_requirements=requirements)
            self.assertEqual(result["checks"][0]["fallback_reason"], reason)
            self.assertEqual(result["local_calls"], 2)
            self.assertNotIn("Aster Bay", result["payload"]["memories"][0]["text"])
        self.assertEqual(self.transfer(mode="generation", label_requirements={"expected_builder_version": "builder-2"},
                                       agent=None)["status"], "needs_review")

    def test_valid_label_still_saves_memory_check_on_cold_cache(self):
        requirements = {"expected_builder_version": "builder-1", "expected_detector_version": "generation-detector-1"}
        result = self.transfer(mode="generation", label_requirements=requirements)
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(result["metadata"]["fallback_count"], 0)

    def test_context_change_during_detection_is_not_cached(self):
        inner = self.detector
        class Changing(Detector):
            def __call__(self, **kwargs):
                response = inner(**kwargs)
                self.version += "-changed"
                return response
        self.transfer(agent=Changing())
        self.assertEqual(self.cache.stats()["entries"], 0)


if __name__ == "__main__":
    unittest.main()
