"""Independent adversarial review cases; synthetic inputs and no model calls."""
import unittest

from memory_migration_study.boundary_detector import refine_detection
from memory_migration_study.boundary_reconciliation import reconcile_boundaries
from memory_migration_study.privacy import _TOKEN, detect_sensitive, prepare_private_payload, restore_answer
from memory_migration_study.privacy_egress import validate_outbound


class BoundaryIndependentReviewTests(unittest.TestCase):
    def policy(self, category, registry=()):
        return {"version": "independent-review-v1", "protected_categories": [category],
                "entity_registry": [{"category": category, "value": value} for value in registry]}

    def payload(self, text):
        return {"query": "Show it", "memories": [{"source_id": "source", "text": text}]}

    def prepared(self, payload, policy, detection):
        return prepare_private_payload(payload, detection, actor_id="owner", request_id="review-request",
            policy_version=policy["version"], sensitivity_policy=policy,
            authorizer=lambda sid, actor, version: sid == "source" and actor == "owner" and version == policy["version"])

    def test_explicit_registry_value_identical_to_key_stays_private_and_restorable(self):
        # No repeated copy in the query/value can accidentally rescue this key.
        payload, policy = self.payload("Project: "), self.policy("PROJECT", ["Project"])
        baseline = detect_sensitive(payload, policy, mode="rules")
        result = refine_detection(payload, policy, baseline)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(any(f["source_id"] == "source" and f["start"] == 0 and f["end"] == 7 for f in result["findings"]))
        self.assertEqual(result["boundary_refinement"]["explicit_registry_occurrences_retained"], 1)
        prepared = self.prepared(payload, policy, result)
        self.assertEqual(validate_outbound(payload, prepared, result, policy)["status"], "ok")
        self.assertNotIn("Project", prepared["payload"]["memories"][0]["text"])
        token = _TOKEN.search(prepared["payload"]["memories"][0]["text"]).group()
        restored = restore_answer(token, prepared["mapping"], actor_id="owner", request_id="review-request",
            policy_version=policy["version"], sensitivity_policy=policy, authorizer=lambda sid, *_: sid == "source")
        self.assertEqual(restored["answer"], "Project")

    def test_same_word_real_value_survives_key_classification_at_other_offset(self):
        payload, policy = self.payload("Name: Name"), self.policy("PERSON", ["Name"])
        result = refine_detection(payload, policy, detect_sensitive(payload, policy, mode="rules"))
        self.assertEqual(result["status"], "ok")
        for left, right in ((0, 4), (6, 10)):
            self.assertTrue(any(f["source_id"] == "source" and f["start"] <= left and f["end"] >= right for f in result["findings"]))
        prepared = self.prepared(payload, policy, result)
        self.assertEqual(validate_outbound(payload, prepared, result, policy)["status"], "ok")

    def test_crossing_generic_notes_key_cannot_drop_untyped_tail(self):
        text = "Project: Branch-2\nNotes: confidential tail"
        payload, policy = self.payload(text), self.policy("PROJECT")
        start = text.index("Branch-2")
        def detector(**kwargs):
            findings = [] if kwargs["source_id"] != "source" else [
                {"start": start, "end": len(text), "quote": text[start:], "category": "PROJECT"}]
            return {"status": "ok", "findings": findings, "errors": [], "local_calls": 0, "elapsed_seconds": 0.0}
        baseline = detect_sensitive(payload, policy, mode="agent", agent=detector)
        result = refine_detection(payload, policy, baseline)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(self.prepared(payload, policy, result)["status"], "needs_review")
        audit = result["boundary_refinement"]["reconciliation"]
        self.assertIn("uncovered_cross_field_residual", audit["errors"])
        self.assertTrue(any(d.get("residual_spans") for d in audit["decisions"]))

    def test_equal_currency_and_number_at_different_offsets_are_not_same_core(self):
        text = "USD 50 USD / USD 50 USD"
        payload, policy = self.payload(text), self.policy("AMOUNT")
        first, second = text.index("USD 50"), text.rindex("50 USD")
        inputs = [{"source_id": "source", "start": left, "end": left+len(quote), "quote": quote, "category": "AMOUNT"}
                  for left, quote in ((first, "USD 50"), (second, "50 USD"))]
        result = reconcile_boundaries(payload, policy, inputs)
        self.assertEqual(result["status"], "ok")
        expected = {(f["source_id"], f["start"], f["end"], f["category"]) for f in inputs}
        self.assertEqual({(f["source_id"], f["start"], f["end"], f["category"]) for f in result["findings"]}, expected)
        self.assertTrue(all(d["action"] == "retained" for d in result["decisions"]))


if __name__ == "__main__":
    unittest.main()
