import copy
import unittest

from memory_migration_study.ner_detector import CjkAwareSplitter, GlinerEntityAgent
from memory_migration_study.privacy import detect_sensitive


class Runtime:
    identity = {"model": "instrument", "weights_sha256": "0" * 64}
    def __init__(self):
        self.calls = []
        self.result = {"entities": {"organization": []}}
        self.error = None

    def infer(self, text, labels, **options):
        self.calls.append((text, labels, options))
        if self.error:
            raise self.error
        return copy.deepcopy(self.result)


class NerDetectorTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Runtime()
        self.policy = {"version": "1", "protected_categories": ["CUSTOMER"],
                       "instructions": "Customer names are sensitive; other organizations may be masked conservatively."}
        self.agent = GlinerEntityAgent(self.runtime, approved_policies=[self.policy])
        self.text = "Client: River Glass Ltd."

    def detect(self, **changes):
        params = dict(text=self.text, source_id="record", policy=self.policy, rule_findings=[])
        params.update(changes)
        return self.agent(**params)

    def test_exact_original_spans_and_only_text_schema_enter_model(self):
        self.runtime.result = {"entities": {"organization": [
            {"text": "River Glass Ltd.", "start": 8, "end": len(self.text), "confidence": .8}]}}
        result = self.detect()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"][0]["category"], "CUSTOMER")
        self.assertEqual(self.runtime.calls[0][2], {"splitter": "cjk_aware", "threshold": .5})
        self.assertNotIn("instructions", self.runtime.calls[0][1])

    def test_clean_empty_extraction_is_not_permission_and_still_uses_rules(self):
        result = detect_sensitive({"query": "Who is the customer?", "memories": []}, self.policy, agent=self.agent)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["local_calls"], 1)
        self.assertNotIn("readers", result)

    def test_same_version_policy_change_requires_new_trusted_approval(self):
        changed = dict(self.policy, instructions="Only mask names when the customer is confidential.")
        result = self.detect(policy=changed)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(self.runtime.calls, [])

    def test_missing_explicit_policy_contract_rejected(self):
        with self.assertRaises(ValueError):
            GlinerEntityAgent(self.runtime, approved_policies=[])

    def test_bad_offsets_labels_confidence_and_fabrication_fail_closed(self):
        valid = {"text": "River Glass Ltd.", "start": 8, "end": len(self.text), "confidence": .8}
        for update in ({"text": "Hallucinated Co"}, {"start": 0}, {"end": 999}, {"confidence": float("nan")},
                       {"confidence": .2}, {"start": True}):
            self.runtime.result = {"entities": {"organization": [dict(valid, **update)]}}
            self.assertEqual(self.detect()["status"], "needs_review")
        self.runtime.result = {"entities": {"person": []}}
        self.assertEqual(self.detect()["status"], "needs_review")

    def test_no_silent_truncation_or_remote_fallback(self):
        self.runtime.error = ValueError("input_budget_exceeded")
        result = self.detect()
        self.assertEqual(result["errors"], ["input_budget_exceeded"])
        self.assertEqual(result["local_calls"], 0)
        self.runtime.error = RuntimeError("private text should not escape")
        result = self.detect()
        self.assertEqual(result["errors"], ["local_failure"])
        self.assertNotIn("private text", str(result))

    def test_splitter_threshold_and_policy_are_bound_to_cache_identity(self):
        standard = GlinerEntityAgent(self.runtime, approved_policies=[self.policy], splitter="whitespace")
        self.assertNotEqual(standard.cache_identity(), self.agent.cache_identity())
        strict = GlinerEntityAgent(self.runtime, approved_policies=[self.policy], threshold=.7)
        self.assertNotEqual(strict.cache_identity(), self.agent.cache_identity())

    def test_model_cannot_override_permission_or_policy_fields(self):
        self.runtime.result = {"entities": {"organization": []}, "readers": ["outsider"]}
        self.assertEqual(self.detect()["status"], "needs_review")
        self.assertEqual(self.detect(rule_findings=[{"public": True}])["local_calls"], 0)

    def test_cjk_refinement_preserves_latin_punctuation_and_exact_offsets(self):
        text = "青禾Cooperative."
        def base(text, lower=False):
            yield text[:-1], 0, len(text)-1
            yield ".", len(text)-1, len(text)
        tokens = list(CjkAwareSplitter(base)(text, lower=False))
        self.assertEqual([t[0] for t in tokens], ["青", "禾", "Cooperative", "."])
        self.assertTrue(all(text[a:b] == token for token, a, b in tokens))

    def test_unicode_lowercase_does_not_corrupt_offsets(self):
        text = "İB客户𠮷"
        splitter = CjkAwareSplitter(lambda text, lower=False: [(text, 0, len(text))])
        tokens = list(splitter(text))
        self.assertEqual([(a, b) for _, a, b in tokens], [(0, 2), (2, 3), (3, 4), (4, 5)])
        self.assertEqual(tokens[0][0], "i\u0307b")


if __name__ == "__main__":
    unittest.main()
