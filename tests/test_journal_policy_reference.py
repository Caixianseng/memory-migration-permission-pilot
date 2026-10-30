"""Tests of the independent finite policy model, never production self-oracles."""
from copy import deepcopy
from pathlib import Path
import ast
import json
import unittest

from experiments.journal_methods_20261030 import policy_semantics_reference as ref


def condition(field, value):
    return {"op": "eq", "field": field, "value": value}


def policy(*rules, required=()):
    return {"schema": ref.SCHEMA, "version": "frozen-v1", "combining": ref.COMBINING,
            "rules": list(rules), "required_obligations": list(required)}


def rule(effect="Permit", *, rid="r1", conditions=(), target=(), obligations=()):
    return {"id": rid, "effect": effect, "target": list(target), "conditions": list(conditions),
            "obligations": list(obligations)}


class IndependentPolicyReferenceTests(unittest.TestCase):
    def test_explicit_permit_with_completed_obligations(self):
        result = ref.evaluate(policy(rule(obligations=["binding"])), {}, {"binding": True})
        self.assertEqual((result["decision"], result["deliver"]), ("Permit", True))

    def test_four_decisions_are_distinct(self):
        fixtures = [(policy(rule()), {}, "Permit"), (policy(rule("Deny")), {}, "Deny"),
                    (policy(rule(conditions=[condition("operation", "read")])), {"operation": "export"}, "NotApplicable"),
                    (policy(rule(conditions=[condition("operation", "read")])), {}, "Indeterminate")]
        for pol, request, expected in fixtures:
            with self.subTest(expected=expected):
                result = ref.evaluate(pol, request)
                self.assertEqual(result["decision"], expected)
                self.assertEqual(result["deliver"], expected == "Permit")

    def test_explicit_target_deny_wins_over_source_permit(self):
        pol = policy(rule(), rule("Deny", rid="target_reject"))
        self.assertEqual(ref.evaluate(pol, {})["decision"], "Deny")

    def test_applicable_unknown_prevents_permit(self):
        pol = policy(rule(), rule(rid="missing", conditions=[condition("source_id", "s1")]))
        self.assertEqual(ref.evaluate(pol, {})["decision"], "Indeterminate")

    def test_inapplicable_rule_does_not_pollute_missing_attributes(self):
        pol = policy(rule(), rule(rid="other", conditions=[condition("operation", "export"), condition("source_id", "s1")]))
        result = ref.evaluate(pol, {"operation": "read"})
        self.assertEqual((result["decision"], result["rules"][1]["decision"]), ("Permit", "NotApplicable"))

    def test_false_dominates_unknown_independent_of_condition_order(self):
        conditions = [condition("operation", "export"), {"op": "unsupported"}]
        for items in (conditions, conditions[::-1]):
            result = ref.evaluate(policy(rule(conditions=items)), {"operation": "read"})
            self.assertEqual(result["decision"], "NotApplicable")

    def test_no_implicit_cartesian_product_in_principal_scope(self):
        pol = policy(rule(conditions=[{"op": "principal", "pairs": [["alice", "qoder"], ["bob", "harness"]]}]))
        for user, agent, allowed in (("alice", "qoder", True), ("bob", "harness", True),
                                     ("alice", "harness", False), ("bob", "qoder", False)):
            result = ref.evaluate(pol, {"user_id": user, "agent_id": agent})
            self.assertEqual(result["deliver"], allowed)

    def test_principal_missing_and_inapplicable_component(self):
        pol = policy(rule(conditions=[{"op": "principal", "pairs": [["alice", "qoder"]]}]))
        self.assertEqual(ref.evaluate(pol, {"user_id": "alice"})["decision"], "Indeterminate")
        self.assertEqual(ref.evaluate(pol, {"user_id": "other"})["decision"], "NotApplicable")

    def test_empty_membership_or_principal_allows_nobody(self):
        for c in ({"op": "in", "field": "audience", "values": []}, {"op": "principal", "pairs": []}):
            result = ref.evaluate(policy(rule(conditions=[c])), {})
            self.assertEqual(result["decision"], "NotApplicable")

    def test_read_does_not_imply_export_or_restore(self):
        pol = policy(rule(conditions=[condition("operation", "read")]))
        for op in ("export", "restore"):
            self.assertEqual(ref.evaluate(pol, {"operation": op})["decision"], "NotApplicable")

    def test_bound_fields_are_independent_requirements(self):
        request = {"memory_id": "m1", "source_id": "s1", "audience": "receiver", "policy_version": "v1"}
        pol = policy(rule(conditions=[condition(k, v) for k, v in request.items()]))
        self.assertTrue(ref.evaluate(pol, request)["deliver"])
        for key in request:
            wrong = {**request, key: "other"}
            self.assertFalse(ref.evaluate(pol, wrong)["deliver"])

    def test_finite_time_window_is_half_open(self):
        pol = policy(rule(conditions=[{"op": "time_window", "field": "now", "start": 10, "end": 20}]))
        for instant, expected in ((9, False), (10, True), (19.5, True), (20, False)):
            self.assertEqual(ref.evaluate(pol, {"now": instant})["deliver"], expected)

    def test_time_bool_nan_infinity_or_missing_is_unknown(self):
        pol = policy(rule(conditions=[{"op": "time_window", "field": "now", "start": 0, "end": 20}]))
        for value in (True, float("nan"), float("inf"), "10", None):
            self.assertEqual(ref.evaluate(pol, {"now": value})["decision"], "Indeterminate")

    def test_strict_scalar_types_do_not_grant_true_as_one(self):
        pol = policy(rule(conditions=[condition("flag", True)]))
        self.assertEqual(ref.evaluate(pol, {"flag": 1})["decision"], "Indeterminate")

    def test_string_booleans_do_not_become_truthy_permissions(self):
        pol = policy(rule(conditions=[condition("export_allowed", True)]))
        for value in ("false", "true", "False", 1, None):
            result = ref.evaluate(pol, {"export_allowed": value})
            self.assertEqual((result["decision"], result["deliver"]), ("Indeterminate", False))
        self.assertEqual(ref.evaluate(pol, {"export_allowed": False})["decision"], "NotApplicable")

    def test_empty_rules_are_not_applicable(self):
        result = ref.evaluate(policy(), {})
        self.assertEqual((result["decision"], result["deliver"]), ("NotApplicable", False))

    def test_invalid_time_window_is_unknown(self):
        for start, end in (("0", 20), (False, 20), (0, float("inf")), (20, 20), (30, 20)):
            pol = policy(rule(conditions=[{"op": "time_window", "field": "now", "start": start, "end": end}]))
            self.assertEqual(ref.evaluate(pol, {"now": 10})["decision"], "Indeterminate")

    def test_large_finite_json_integer_does_not_crash_time_evaluation(self):
        instant = 10 ** 1000
        pol = policy(rule(conditions=[{"op": "time_window", "field": "now", "start": 0, "end": instant + 1}]))
        self.assertTrue(ref.evaluate(pol, {"now": instant})["deliver"])
        pol = policy(rule(conditions=[{"op": "in", "field": "flag", "values": [True]}]))
        self.assertEqual(ref.evaluate(pol, {"flag": 1})["decision"], "Indeterminate")

    def test_failed_missing_or_invalid_obligations_preserve_business_permit(self):
        pol = policy(rule(obligations=["pseudonymize"]), required=["source_binding"])
        for actual, expected in ((False, "failed"), (None, "invalid"), (1, "invalid")):
            result = ref.evaluate(pol, {}, {"pseudonymize": actual, "source_binding": True})
            self.assertEqual(result["decision"], "Permit")
            self.assertFalse(result["deliver"])
            self.assertEqual(result["obligations"][0]["status"], expected)
        result = ref.evaluate(pol, {})
        self.assertEqual([row["status"] for row in result["obligations"]], ["missing", "missing"])

    def test_obligations_from_inapplicable_rule_are_not_required(self):
        pol = policy(rule(), rule(rid="other", conditions=[condition("operation", "export")], obligations=["not_due"]))
        self.assertTrue(ref.evaluate(pol, {"operation": "read"})["deliver"])

    def test_all_permit_obligations_combine_without_duplicates(self):
        pol = policy(rule(obligations=["binding"]), rule(rid="second", obligations=["binding", "mask"]))
        result = ref.evaluate(pol, {}, {"binding": True, "mask": True})
        self.assertEqual([row["id"] for row in result["obligations"]], ["binding", "mask"])

    def test_engineering_failure_is_not_reported_as_business_deny(self):
        result = ref.evaluate(policy(rule(obligations=["load"])), {}, {"load": False})
        self.assertEqual((result["decision"], result["enforcement_status"]), ("Permit", "obligations_unsatisfied"))

    def test_invalid_or_unsupported_policy_fails_closed(self):
        pol = policy(rule())
        for update in ({"schema": "facpl"}, {"combining": "permit_overrides"}, {"extra": True}, {"version": None}):
            result = ref.evaluate({**pol, **update}, {})
            self.assertEqual((result["decision"], result["deliver"]), ("Indeterminate", False))

    def test_duplicate_rule_ids_fail_closed(self):
        self.assertEqual(ref.evaluate(policy(rule(), rule()), {})["decision"], "Indeterminate")

    def test_malformed_rule_cannot_be_ignored_beside_permit(self):
        pol = policy(rule(), {"id": "bad", "effect": "Allow"})
        self.assertEqual(ref.evaluate(pol, {})["decision"], "Indeterminate")

    def test_unsupported_condition_is_unknown_when_applicable(self):
        self.assertEqual(ref.evaluate(policy(rule(conditions=[{"op": "regex"}])), {})["decision"], "Indeterminate")

    def test_finite_domain_contains_all_requests_without_granting_cross_pairs(self):
        pol = policy(rule(conditions=[{"op": "principal", "pairs": [["alice", "qoder"], ["bob", "harness"]]}]))
        rows = ref.evaluate_domain(pol, {"user_id": ["alice", "bob"], "agent_id": ["qoder", "harness"], "operation": ["read", "export"]})
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row["reference"]["deliver"] for row in rows), 4)

    def test_invalid_domains_are_rejected(self):
        for domain in ({}, {"x": []}, {"x": [float("nan")]}, {"x": [None]}):
            with self.assertRaises(ValueError):
                list(ref.enumerate_requests(domain))

    def test_result_is_json_serializable_and_input_is_unchanged(self):
        pol, request = policy(rule()), {"operation": "read"}
        before = deepcopy((pol, request))
        json.dumps(ref.evaluate(pol, request), allow_nan=False)
        self.assertEqual((pol, request), before)

    def test_no_production_authorizer_imports(self):
        tree = ast.parse(Path(ref.__file__).read_text(encoding="utf-8"))
        imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        imports += [name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names]
        self.assertFalse(any(name.startswith("memory_migration_study") for name in imports))


if __name__ == "__main__":
    unittest.main()
