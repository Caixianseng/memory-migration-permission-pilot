import unittest

from memory_migration_study.detection_cache import DetectionCache
from memory_migration_study.privacy import detect_sensitive


class Detector:
    max_local_calls = 3
    def __init__(self):
        self.invocations = 0

    def cache_identity(self):
        return {"trusted_contract": "two_members_v1", "max_local_calls": self.max_local_calls}

    def __call__(self, **kwargs):
        self.invocations += 1
        return {"status": "ok", "findings": [], "local_calls": 3,
                "elapsed_seconds": .1, "errors": [], "diagnostics": []}


class CallContractTests(unittest.TestCase):
    policy = {"version": "1", "protected_categories": ["CUSTOMER"]}
    payload = {"query": "", "memories": [{"source_id": "one", "text": "Ordinary public prose."}]}

    def test_explicit_composite_budget_records_three_physical_calls(self):
        result = detect_sensitive(self.payload, self.policy, agent=Detector())
        self.assertEqual(result["local_calls"], 3)
        self.assertTrue(result["local_calls_complete"])

    def test_model_reply_cannot_increase_default_two_call_contract(self):
        detector = lambda **kwargs: {"status": "ok", "findings": [], "local_calls": 3, "max_local_calls": 3}
        result = detect_sensitive(self.payload, self.policy, agent=detector)
        self.assertFalse(result["local_calls_complete"])
        self.assertEqual(result["local_calls"], 0)

    def test_invalid_callable_budget_blocks_before_invocation(self):
        for invalid in (True, 0, -1, 5, "3"):
            detector = Detector()
            detector.max_local_calls = invalid
            result = detect_sensitive(self.payload, self.policy, agent=detector)
            self.assertEqual(detector.invocations, 0)
            self.assertIn("invalid_local_agent_call_contract", result["errors"])
            self.assertFalse(result["local_calls_complete"])

    def test_scoped_cache_retains_trusted_budget_without_replaying_compute(self):
        detector = Detector()
        cache = DetectionCache()
        wrapped = cache.bind(detector, scope={"actor": "a", "agent": "b", "source_grant": "signed-domain"})
        first = detect_sensitive(self.payload, self.policy, agent=wrapped)
        second = detect_sensitive(self.payload, self.policy, agent=wrapped)
        self.assertEqual((first["local_calls"], second["local_calls"]), (3, 0))
        self.assertTrue(first["local_calls_complete"] and second["local_calls_complete"])
        self.assertEqual(detector.invocations, 1)


if __name__ == "__main__":
    unittest.main()
