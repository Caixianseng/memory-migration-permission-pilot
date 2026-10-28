"""Raw local-adapter accounting through validation, strict transfer and cache."""
import copy
import unittest
from unittest.mock import patch

from memory_migration_study import detection_cache
from memory_migration_study.detection_cache import DetectionCache
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer
from memory_migration_study.privacy import detect_sensitive
from memory_migration_study.sensitivity_contract import STRICT_CUSTOMER_RELATION, bind_category_contract


MISSING = object()
NON_TRUE = (False, None, 0, 1, "true", 1.0, [], {})
MODES = ("migration", "generation", "two_stage")
NAME = "River Glass Ltd."
TEXT = f"Our customer is {NAME}"


class RawAdapter:
    """An in-process adapter with real host validation and no model or HTTP."""
    max_local_calls = 2

    def __init__(self, complete=MISSING, *, calls=1, per_source=None):
        self.complete = complete
        self.calls = calls
        self.per_source = per_source or {}
        self.invocations = []

    def cache_identity(self):
        return {"adapter": "offline-accounting-fixture-v1", "max_local_calls": self.max_local_calls}

    def __call__(self, *, text, source_id, policy, rule_findings):
        self.invocations.append(source_id)
        response = {"status": "ok", "errors": [], "elapsed_seconds": .01,
                    "findings": [{"quote": NAME, "category": "CUSTOMER"}] if NAME in text else []}
        if self.calls is not MISSING:
            response["local_calls"] = self.calls
        complete = self.per_source.get(source_id, self.complete)
        if complete is not MISSING:
            response["local_calls_complete"] = copy.deepcopy(complete)
        return response


class DetectorAccountingCompletenessTests(unittest.TestCase):
    def setUp(self):
        self.policy = bind_category_contract(
            {"version": "accounting-test-v1", "protected_categories": ["CUSTOMER"]},
            STRICT_CUSTOMER_RELATION)
        self.payload = {"query": "", "memories": [{"source_id": "source", "text": TEXT}]}
        self.authority = MemoryLabelAuthority(b"offline-accounting-tests-authority-32-bytes")
        self.record = self.authority.build_record(
            {"source_id": "source", "text": TEXT},
            {"text": TEXT, "source_start": 0, "source_end": len(TEXT), "findings": []},
            self.policy, owner_id="owner", readers=[], agent_id="reader", builder_version="unit-v1")

    def transfer(self, adapter, mode, cache=None):
        return prepare_labeled_transfer(
            [self.record], "Summarize the record.", self.policy, authority=self.authority,
            actor_id="owner", agent_id="reader", request_id="request", mode=mode,
            agent=adapter, detection_cache=cache)

    def test_legacy_missing_flag_and_explicit_true_keep_valid_scalar_contract(self):
        for complete in (MISSING, True):
            for calls in (0, 1, 2):
                with self.subTest(complete=complete, calls=calls):
                    result = detect_sensitive(self.payload, self.policy,
                                              agent=RawAdapter(complete, calls=calls))
                    self.assertEqual(result["status"], "ok")
                    self.assertIs(result["local_calls_complete"], True)
                    self.assertEqual(result["local_calls"], calls)

    def test_explicit_non_true_flag_cannot_promote_valid_scalar_or_erase_findings(self):
        for complete in NON_TRUE:
            for mode in ("agent", "combined"):
                with self.subTest(complete=complete, mode=mode):
                    adapter = RawAdapter(complete)
                    result = detect_sensitive(self.payload, self.policy, agent=adapter, mode=mode)
                    self.assertIs(result["local_calls_complete"], False)
                    self.assertEqual(result["local_calls"], 1)
                    # Accounting incompleteness does not invent semantic uncertainty.
                    self.assertEqual((result["status"], result["errors"]), ("ok", []))
                    self.assertTrue(any(TEXT[f["start"]:f["end"]] == NAME
                                        for f in result["findings"]))
                    self.assertEqual(adapter.invocations, ["source"])

    def test_missing_or_invalid_scalar_is_incomplete_even_with_true_flag(self):
        for complete in (MISSING, True, False):
            for calls in (MISSING, None, True, -1, 3, 1.0, "1"):
                with self.subTest(complete=complete, calls=calls):
                    result = detect_sensitive(self.payload, self.policy,
                                              agent=RawAdapter(complete, calls=calls))
                    self.assertIs(result["local_calls_complete"], False)
                    self.assertEqual(result["local_calls"], 0)

    def test_one_incomplete_source_is_sticky_across_later_complete_sources(self):
        payload = {"query": "Summarize the record.", "memories": [
            {"source_id": "first", "text": TEXT}, {"source_id": "last", "text": "Ordinary prose."}]}
        for source_id in ("__query__", "first", "last"):
            for complete in NON_TRUE:
                with self.subTest(source_id=source_id, complete=complete):
                    adapter = RawAdapter(True, per_source={source_id: complete})
                    result = detect_sensitive(payload, self.policy, agent=adapter)
                    self.assertEqual(adapter.invocations, ["__query__", "first", "last"])
                    self.assertIs(result["local_calls_complete"], False)
                    self.assertEqual(result["local_calls"], 3)
                    self.assertTrue(result["findings"])

    def test_strict_modes_accept_legacy_and_explicitly_complete_raw_adapters(self):
        for mode in MODES:
            for complete in (MISSING, True):
                with self.subTest(mode=mode, complete=complete):
                    adapter = RawAdapter(complete)
                    result = self.transfer(adapter, mode)
                    self.assertEqual(result["status"], "ok")
                    self.assertIs(result["local_calls_complete"], True)
                    self.assertEqual(result["local_calls"], 2)
                    self.assertEqual(adapter.invocations, ["__query__", self.record["record_id"]])
                    self.assertNotIn(NAME, result["payload"]["memories"][0]["text"])

    def test_strict_modes_reject_raw_incomplete_adapters_despite_signed_empty_labels(self):
        for mode in MODES:
            for complete in NON_TRUE:
                with self.subTest(mode=mode, complete=complete):
                    adapter = RawAdapter(complete)
                    result = self.transfer(adapter, mode)
                    self.assertEqual(result["status"], "needs_review")
                    self.assertIsNone(result["payload"])
                    self.assertIsNone(result["mapping"])
                    self.assertIs(result["local_calls_complete"], False)
                    self.assertEqual(result["local_calls"], 2)
                    self.assertTrue(result["checks"][0]["label_valid"])
                    self.assertIn("unsupported_category_contract", result["detection"]["errors"])
                    self.assertTrue(result["detection"]["findings"])
                    self.assertEqual(adapter.invocations, ["__query__", self.record["record_id"]])

    def test_explicit_non_true_responses_never_store_or_hit_cache(self):
        for complete in NON_TRUE:
            with self.subTest(complete=complete):
                adapter, cache = RawAdapter(complete), DetectionCache()
                wrapped = cache.bind(adapter, scope={"authority": "offline-test-domain"})
                first = detect_sensitive(self.payload, self.policy, agent=wrapped)
                second = detect_sensitive(self.payload, self.policy, agent=wrapped)
                self.assertIs(first["local_calls_complete"], False)
                self.assertIs(second["local_calls_complete"], False)
                self.assertEqual((first["local_calls"], second["local_calls"]), (1, 1))
                self.assertEqual(len(adapter.invocations), 2)
                stats = cache.stats()
                self.assertEqual((stats["stores"], stats["hits"], stats["entries"], stats["misses"]),
                                 (0, 0, 0, 2))

    def test_strict_modes_with_cache_cannot_turn_incomplete_into_success_on_retry(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                adapter, cache = RawAdapter(False), DetectionCache()
                for _ in range(2):
                    result = self.transfer(adapter, mode, cache)
                    self.assertEqual(result["status"], "needs_review")
                    self.assertIsNone(result["payload"])
                    self.assertIs(result["local_calls_complete"], False)
                    self.assertEqual(result["local_calls"], 2)
                stats = cache.stats()
                self.assertEqual((stats["stores"], stats["hits"], stats["entries"], stats["misses"]),
                                 (0, 0, 0, 4))
                self.assertEqual(len(adapter.invocations), 4)

    def test_complete_responses_remain_cacheable_and_hits_report_zero_complete_calls(self):
        for complete in (MISSING, True):
            with self.subTest(complete=complete):
                adapter, cache = RawAdapter(complete), DetectionCache()
                wrapped = cache.bind(adapter, scope={"authority": "offline-test-domain"})
                first = detect_sensitive(self.payload, self.policy, agent=wrapped)
                second = detect_sensitive(self.payload, self.policy, agent=wrapped)
                self.assertEqual((first["local_calls"], second["local_calls"]), (1, 0))
                self.assertIs(first["local_calls_complete"], True)
                self.assertIs(second["local_calls_complete"], True)
                self.assertEqual(first["findings"], second["findings"])
                self.assertEqual(len(adapter.invocations), 1)
                self.assertEqual((cache.stats()["stores"], cache.stats()["hits"]), (1, 1))

    def test_new_cache_contract_cannot_reuse_legacy_namespace_entries(self):
        adapter, cache = RawAdapter(True), DetectionCache()
        wrapped = cache.bind(adapter, scope={"authority": "offline-test-domain"})
        # Seed the old key namespace without executing historical validator code.
        with patch.object(detection_cache, "CACHE_VERSION", "scoped_semantic_cache_v1"):
            detect_sensitive(self.payload, self.policy, agent=wrapped)
        self.assertNotEqual(detection_cache.CACHE_VERSION, "scoped_semantic_cache_v1")
        adapter.complete = False
        result = detect_sensitive(self.payload, self.policy, agent=wrapped)
        self.assertIs(result["local_calls_complete"], False)
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(len(adapter.invocations), 2)
        self.assertEqual((cache.stats()["stores"], cache.stats()["hits"], cache.stats()["misses"]),
                         (1, 0, 2))


if __name__ == "__main__":
    unittest.main()
