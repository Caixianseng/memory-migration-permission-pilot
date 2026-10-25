import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from memory_migration_study import boundary_reconciliation as reconciliation
from memory_migration_study.boundary_reconciliation import reconcile_boundaries


class BoundaryReconciliationTests(unittest.TestCase):
    def payload(self, text, query=""):
        return {"query": query, "memories": [{"source_id": "m", "text": text}]}

    def policy(self, categories=None):
        return {"version": "boundary-test", "protected_categories": list(categories) if categories is not None
                else ["CUSTOMER", "PROJECT", "AMOUNT", "EMAIL"]}

    def finding(self, text, quote, category, start=None):
        start = text.index(quote) if start is None else start
        return {"source_id": "m", "start": start, "end": start+len(quote), "quote": quote, "category": category,
                "method": "self_authored_fixture"}

    def pairs(self, result):
        return [(row["category"], row["quote"]) for row in result["findings"]]

    def assert_exact(self, payload, result):
        sources = {"__query__": payload["query"], **{row["source_id"]: row["text"] for row in payload["memories"]}}
        for row in result["findings"]:
            self.assertEqual(sources[row["source_id"]][row["start"]:row["end"]], row["quote"])
        self.assertEqual(len(result["decisions"]), len(result["original_findings"]))
        self.assertEqual(result["local_calls"], 0)

    def test_partial_organization_suffix_completed_only_at_typed_field_occurrence(self):
        text = "Customer: Birch Research Ltd.\nElsewhere Ltd. is just a token.\n"
        payload = self.payload(text)
        inputs = [self.finding(text, "Ltd.", "CUSTOMER"), self.finding(text, "Ltd.", "CUSTOMER", start=text.rindex("Ltd."))]
        result = reconcile_boundaries(payload, self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.pairs(result), [("CUSTOMER", "Birch Research Ltd."), ("CUSTOMER", "Ltd.")])
        self.assertEqual([d["action"] for d in result["decisions"]], ["field_completion", "retained"])
        self.assertEqual(result["original_findings"], inputs)
        self.assert_exact(payload, result)

    def test_field_key_reference_removed_by_position_real_same_name_retained(self):
        text = "Project reference: reference\nA body reference is not a field key.\n"
        payload = self.payload(text)
        starts = [text.index("reference"), text.index("reference", text.index(":")+1), text.rindex("reference")]
        inputs = [self.finding(text, "reference", "PROJECT", start=start) for start in starts]
        result = reconcile_boundaries(payload, self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual([d["action"] for d in result["decisions"]], ["field_key", "retained", "retained"])
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual([f["start"] for f in result["findings"]], starts[1:])
        self.assert_exact(payload, result)

    def test_generic_nonsensitive_key_has_no_category_but_is_explicit_key_evidence(self):
        text = "Reference: ordinary lookup\nProject: Reference\n"
        inputs = [self.finding(text, "Reference", "PROJECT"),
                  self.finding(text, "Reference", "PROJECT", start=text.rindex("Reference"))]
        result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual([d["action"] for d in result["decisions"]], ["field_key", "retained"])
        self.assertEqual(self.pairs(result), [("PROJECT", "Reference")])

    def test_cross_next_field_corrected_when_independent_typed_tail_covers_data(self):
        text = "Project: Blue-7\nBudget: USD 120 USD\n"
        bad = "Blue-7\nBudget: USD 120 USD"
        inputs = [self.finding(text, bad, "PROJECT"), self.finding(text, "USD 120 USD", "AMOUNT")]
        payload = self.payload(text)
        result = reconcile_boundaries(payload, self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.pairs(result), [("PROJECT", "Blue-7"), ("AMOUNT", "USD 120 USD")])
        self.assertEqual(result["decisions"][0]["action"], "cross_field_corrected")
        self.assertNotIn(bad, [row["quote"] for row in result["findings"]])
        self.assert_exact(payload, result)

    def test_cross_next_field_with_untyped_tail_requires_review_not_silent_deletion(self):
        text = "Project: Blue-7\nBudget: USD 120 USD\n"
        inputs = [self.finding(text, "Blue-7\nBudget: USD 120 USD", "PROJECT")]
        result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["findings"], [])
        self.assertIn("uncovered_cross_field_residual", result["errors"])
        self.assertEqual(result["decisions"][0]["action"], "needs_review")
        self.assertTrue(result["decisions"][0]["residual_spans"])
        self.assertEqual(result["original_findings"], inputs)

    def test_span_crossing_only_next_key_and_syntax_can_be_corrected(self):
        for separator in ("\n", "; ", "；"):
            with self.subTest(separator=separator):
                text = "Project: B-4"+separator+"Status: ready"
                inputs = [self.finding(text, "B-4"+separator+"Status", "PROJECT")]
                result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(self.pairs(result), [("PROJECT", "B-4")])
                self.assertEqual(result["decisions"][0]["action"], "cross_field_corrected")

    def test_multiline_name_without_following_explicit_key_never_truncated(self):
        text = "Birch Research\nInternational Holdings"
        inputs = [self.finding(text, text, "CUSTOMER")]
        result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.pairs(result), [("CUSTOMER", text)])
        self.assertEqual(result["decisions"][0]["action"], "retained")

    def test_no_schema_only_values_promoted_without_matching_typed_seeds(self):
        text = "Customer: Birch Group\nProject: P-4\nBudget: 500 USD\n"
        empty = reconcile_boundaries(self.payload(text), self.policy(), [])
        self.assertEqual(empty["status"], "ok")
        self.assertEqual(empty["findings"], [])
        self.assertEqual(empty["decisions"], [])
        wrong_class = [self.finding(text, "Birch", "PROJECT")]
        result = reconcile_boundaries(self.payload(text), self.policy(), wrong_class)
        self.assertEqual(self.pairs(result), [("PROJECT", "Birch")])
        self.assertEqual(result["additions"], [])

    def test_quoted_value_contains_key_looking_words_without_inventing_boundary(self):
        text = 'Customer: “Project reference: Birch”\n'
        inputs = [self.finding(text, "Birch", "CUSTOMER")]
        result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.pairs(result), [("CUSTOMER", "Project reference: Birch")])
        self.assertEqual(result["decisions"][0]["action"], "field_completion")

    def test_crossing_same_currency_amounts_completed_and_originals_audited(self):
        text = "Budget: USD 9,500.25 USD\n"
        inputs = [self.finding(text, "USD 9,500.25", "AMOUNT"), self.finding(text, "9,500.25 USD", "AMOUNT")]
        payload = self.payload(text)
        result = reconcile_boundaries(payload, self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.pairs(result), [("AMOUNT", "USD 9,500.25 USD")])
        self.assertTrue(all(d["action"] == "amount_completion" for d in result["decisions"]))
        self.assertEqual(result["original_findings"], inputs)
        self.assertEqual(len(result["findings"][0]["provenance"]), 2)
        self.assert_exact(payload, result)

    def test_existing_complete_compatible_amount_can_replace_its_contained_part(self):
        text = "USD 80 USD"
        inputs = [self.finding(text, "USD 80 USD", "AMOUNT"), self.finding(text, "80 USD", "AMOUNT")]
        result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.pairs(result), [("AMOUNT", "USD 80 USD")])
        self.assertEqual(result["decisions"][1]["reason"], "same_currency_same_numeric_interval")

    def test_incompatible_currencies_and_bare_numeric_spans_are_never_absorbed(self):
        text = "Budget: USD 120 EUR\n"
        inputs = [self.finding(text, "USD 120", "AMOUNT"), self.finding(text, "120 EUR", "AMOUNT"),
                  self.finding(text, "120", "AMOUNT")]
        result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual({row["quote"] for row in result["findings"]}, {"USD 120", "120 EUR", "120"})
        self.assertTrue(all(d["action"] == "retained" for d in result["decisions"]))
        self.assertIn("incompatible_currencies", result["amount_evidence"]["unmerged_reasons"])

    def test_unstructured_contained_same_category_is_not_generic_maximalization(self):
        text = "Alder Cooperative"
        inputs = [self.finding(text, text, "CUSTOMER"), self.finding(text, "Alder", "CUSTOMER")]
        result = reconcile_boundaries(self.payload(text), self.policy(), inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(all(d["action"] == "retained" for d in result["decisions"]))

    def test_scope_changed_full_binding_and_out_of_scope_decision_not_permission(self):
        text = "Customer: Birch Group\nProject: P-8\n"
        inputs = [self.finding(text, "Birch", "CUSTOMER"), self.finding(text, "P-8", "PROJECT")]
        payload = self.payload(text)
        policy = self.policy(["PROJECT"])
        result = reconcile_boundaries(payload, policy, inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.pairs(result), [("PROJECT", "P-8")])
        self.assertEqual(result["decisions"][0]["action"], "out_of_scope")
        other = reconcile_boundaries(payload, {**policy, "gold": "SCORING_CANARY"}, inputs)
        self.assertEqual(other["findings"], result["findings"])
        self.assertNotEqual(other["full_policy_sha256"], result["full_policy_sha256"])

    def test_malformed_span_source_category_authority_and_policy_binding_fail_closed(self):
        text = "Project: P-3\n"
        payload, policy = self.payload(text), self.policy()
        good = self.finding(text, "P-3", "PROJECT")
        for change in ({"source_id": "missing"}, {"start": -1}, {"start": True}, {"quote": "wrong"},
                       {"category": "ADMIN"}, {"owner": "admin"}, {"policy_id": "another-policy"}):
            with self.subTest(change=change):
                result = reconcile_boundaries(payload, policy, [{**good, **change}])
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["findings"], [])

    def test_all_dependency_or_budget_failures_preserve_input_audit_and_fail_closed(self):
        text = "Project: P-3\nCustomer: Birch Group\n"
        inputs = [self.finding(text, "P-3", "PROJECT")]
        payload, policy = self.payload(text), self.policy()
        over = reconcile_boundaries(payload, policy, inputs, max_candidates=1)
        self.assertEqual(over["status"], "needs_review")
        self.assertEqual(over["findings"], [])
        self.assertEqual(over["original_findings"], inputs)
        self.assertEqual(len(over["decisions"]), 1)
        self.assertEqual(over["decisions"][0]["action"], "needs_review")
        with patch.object(reconciliation, "propose_field_findings", return_value={"status": "candidates_only"}):
            failed = reconcile_boundaries(payload, policy, inputs)
        self.assertEqual(failed["status"], "needs_review")
        self.assertEqual(failed["findings"], [])
        self.assertEqual(len(failed["decisions"]), 1)
        with patch.object(reconciliation, "propose_field_findings", side_effect=RuntimeError("SECRET_EXCEPTION_TEXT")):
            crashed = reconcile_boundaries(payload, policy, inputs)
        self.assertEqual(crashed["status"], "needs_review")
        self.assertEqual(crashed["findings"], [])
        self.assertEqual(len(crashed["decisions"]), 1)
        self.assertNotIn("SECRET_EXCEPTION_TEXT", repr(crashed))

    def test_pure_no_file_io_or_model_and_caller_inputs_unchanged(self):
        text = "Customer: Birch Group\n"
        payload, policy = self.payload(text), self.policy()
        inputs = [self.finding(text, "Birch", "CUSTOMER")]
        original = copy.deepcopy((payload, policy, inputs))
        with patch("builtins.open", side_effect=AssertionError("No file/gold I/O")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("No source file I/O")):
            result = reconcile_boundaries(payload, policy, inputs)
        self.assertEqual(result["status"], "ok")
        self.assertEqual((payload, policy, inputs), original)
        self.assertNotIn("permissions", result)
        self.assertNotIn("policy_version", result)  # Not a complete privacy detection.


if __name__ == "__main__":
    unittest.main()
