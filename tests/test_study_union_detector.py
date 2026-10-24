import copy
import json
import unittest

from memory_migration_study.privacy import detect_sensitive
from memory_migration_study.union_detector import IndependentUnionDetector


class Detector:
    def __init__(self, findings=(), *, calls=1, cap=1, version="one", status="ok", errors=()):
        self.max_local_calls = cap
        self.version, self.inputs = version, []
        self.response = {"status": status, "findings": list(findings), "errors": list(errors),
                         "local_calls": calls, "elapsed_seconds": 0.01}
        self.mutate, self.error = False, None

    def cache_identity(self):
        return {"version": self.version}

    def __call__(self, **kwargs):
        self.inputs.append(copy.deepcopy(kwargs))
        if self.mutate:
            kwargs["policy"]["protected_categories"].clear()
            kwargs["rule_findings"].append({"forged": True})
        if self.error:
            raise self.error
        return copy.deepcopy(self.response)


def span(text, quote, category="CUSTOMER", *, start=None):
    a = text.index(quote) if start is None else start
    return {"start": a, "end": a+len(quote), "quote": quote, "category": category}


class UnionDetectorTests(unittest.TestCase):
    text = "North Lake Ltd. meets 南原设备合作社."
    policy = {"version": "union1", "protected_categories": ["CUSTOMER", "PERSON"]}

    def call(self, detector, **changes):
        args = dict(text=self.text, source_id="source-1", policy=self.policy, rule_findings=[])
        args.update(changes)
        return detector(**args)

    def test_independent_members_get_identical_original_input_despite_mutation(self):
        first = Detector([span(self.text, "North Lake Ltd.")])
        second = Detector([span(self.text, "南原设备合作社")])
        first.mutate = True
        union = IndependentUnionDetector(first, second)
        result = self.call(union)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(first.inputs, second.inputs)
        self.assertEqual(second.inputs[0]["rule_findings"], [])
        self.assertEqual(self.policy["protected_categories"], ["CUSTOMER", "PERSON"])
        self.assertEqual(result["findings"], [span(self.text, "North Lake Ltd."), span(self.text, "南原设备合作社")])

    def test_raw_contained_crossing_and_category_distinct_spans_are_not_unified(self):
        text = "Alphabeta Cooperative"
        first = Detector([span(text, "Alpha"), span(text, "beta", "PERSON")])
        second = Detector([span(text, "Alphabeta"), span(text, "beta Cooperative")])
        result = self.call(IndependentUnionDetector(first, second), text=text)
        self.assertEqual(result["status"], "ok")
        self.assertEqual({(f["start"], f["end"], f["category"]) for f in result["findings"]},
                         {(0, 5, "CUSTOMER"), (5, 9, "PERSON"), (0, 9, "CUSTOMER"), (5, 21, "CUSTOMER")})

    def test_exact_duplicates_deduplicated_without_expansion(self):
        first = Detector([span(self.text, "North Lake Ltd.")])
        second = Detector([{"quote": "North Lake Ltd.", "category": "CUSTOMER"}])
        result = self.call(IndependentUnionDetector(first, second))
        self.assertEqual(result["findings"], [span(self.text, "North Lake Ltd.")])
        self.assertEqual(result["local_calls"], 2)

    def test_ner_one_plus_generation_repair_two_counts_three_through_host(self):
        first = Detector([span(self.text, "North Lake Ltd.")], calls=1, cap=1)
        second = Detector([span(self.text, "南原设备合作社")], calls=2, cap=2)
        union = IndependentUnionDetector(first, second)
        result = self.call(union)
        self.assertEqual(union.max_local_calls, 3)
        self.assertEqual(result["local_calls"], 3)
        self.assertEqual(result["inference_counts"], {"local_encoder": 1, "local_generation": 2, "unknown": 0})
        checked = detect_sensitive({"query": "", "memories": [{"source_id": "src", "text": self.text}]},
                                   self.policy, mode="agent", agent=union)
        self.assertEqual(checked["status"], "ok")
        self.assertEqual(checked["local_calls"], 3)
        self.assertTrue(checked["local_calls_complete"])
        self.assertEqual(checked["agent_observations"][0]["local_calls"], 3)

    def test_uncertain_member_cannot_be_ignored_and_both_are_called(self):
        first = Detector(status="needs_review", errors=["semantic_uncertainty"])
        second = Detector([span(self.text, "南原设备合作社")])
        result = self.call(IndependentUnionDetector(first, second))
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(len(first.inputs), 1)
        self.assertEqual(len(second.inputs), 1)

    def test_exception_is_unknown_count_not_zero_and_no_exception_text_leaks(self):
        first, second = Detector(), Detector()
        first.error = RuntimeError("private secret detail")
        result = self.call(IndependentUnionDetector(first, second))
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["local_calls"])
        self.assertFalse(result["local_calls_complete"])
        self.assertEqual(result["known_local_calls"], 1)
        self.assertEqual(len(second.inputs), 1)
        self.assertNotIn("private secret detail", json.dumps(result))

    def test_invalid_spans_ambiguous_quotes_categories_and_errors_fail_host_validation(self):
        for findings, errors in (([{"quote": "fabricated", "category": "CUSTOMER"}], []),
                                 ([dict(span(self.text, "North Lake Ltd."), end=999)], []),
                                 ([span(self.text, "North Lake Ltd.", "EMAIL")], []),
                                 ([], ["secret error text"])):
            first, second = Detector(findings, errors=errors), Detector()
            result = self.call(IndependentUnionDetector(first, second))
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(result["local_calls"], 2)
            self.assertNotIn("secret error text", json.dumps(result))
        repeated = "Orchid Orchid"
        first = Detector([{"quote": "Orchid", "category": "CUSTOMER"}])
        self.assertEqual(self.call(IndependentUnionDetector(first, Detector()), text=repeated)["status"], "needs_review")

    def test_authority_fields_rejected_and_never_propagated(self):
        for extra in ("response", "finding"):
            first = Detector([span(self.text, "North Lake Ltd.")])
            if extra == "response":
                first.response["readers"] = ["outsider-secret"]
            else:
                first.response["findings"][0]["permissions"] = "export-secret"
            result = self.call(IndependentUnionDetector(first, Detector()))
            self.assertEqual(result["status"], "needs_review")
            self.assertNotIn("outsider-secret", json.dumps(result))
            self.assertNotIn("export-secret", json.dumps(result))
            self.assertNotIn("readers", result)

    def test_member_count_must_obey_trusted_cap_not_response_claim(self):
        first = Detector(calls=2, cap=1)
        first.response["max_local_calls"] = 4
        result = self.call(IndependentUnionDetector(first, Detector()))
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["local_calls"])
        self.assertEqual(result["known_local_calls"], 1)
        self.assertIn("invalid_member_call_count", result["member_observations"][0]["errors"])

    def test_cache_identity_binds_order_kind_versions_and_member_contract(self):
        first, second = Detector(version="one"), Detector(version="two")
        union = IndependentUnionDetector(first, second)
        original = union.cache_identity()
        self.assertNotEqual(original, IndependentUnionDetector(second, first).cache_identity())
        self.assertNotEqual(original, IndependentUnionDetector(first, second, member_kinds=("unknown", "local_generation")).cache_identity())
        first.version = "new"
        self.assertNotEqual(original, union.cache_identity())
        first.max_local_calls = 2
        with self.assertRaises(ValueError):
            union.cache_identity()
        self.assertEqual(self.call(union)["status"], "needs_review")

    def test_bad_constructor_and_oversized_preflight_never_call_members(self):
        with self.assertRaises(ValueError):
            IndependentUnionDetector(Detector(cap=3), Detector(cap=2))
        with self.assertRaises(ValueError):
            IndependentUnionDetector(Detector(cap=True), Detector())
        with self.assertRaises(ValueError):
            IndependentUnionDetector(Detector(), Detector(), member_kinds=("gpu", "secret"))
        first, second = Detector(), Detector()
        result = self.call(IndependentUnionDetector(first, second), text="x"*6001)
        self.assertEqual((result["status"], result["local_calls"]), ("needs_review", 0))
        self.assertEqual(first.inputs, [])
        self.assertEqual(second.inputs, [])

    def test_empty_text_or_empty_scope_skips_both_models(self):
        first, second = Detector(), Detector()
        union = IndependentUnionDetector(first, second)
        for changes in ({"text": ""}, {"policy": {"version": "public", "protected_categories": []}}):
            result = self.call(union, **changes)
            self.assertEqual((result["status"], result["local_calls"]), ("ok", 0))
        self.assertEqual(first.inputs, [])
        self.assertEqual(second.inputs, [])


if __name__ == "__main__":
    unittest.main()
