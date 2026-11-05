"""Offline falsifiable mechanism/safety tests; no provider, network or account."""
import copy
import itertools
import math
import unittest

try:
    from .planner import METHODS, plan_layout
except ImportError:
    from planner import METHODS, plan_layout


def sources(lengths):
    return [{"source_id": sid, "text": "x" * nbytes} for sid, nbytes in lengths.items()]


def transition(before, after, **extra):
    return {"before": list(before), "after": list(after), **extra}


def retained(order, lengths, after):
    total = 0
    for sid in order:
        if sid not in after:
            break
        total += lengths[sid]
    return total


class PlannerTests(unittest.TestCase):
    def correlated_case(self):
        lengths = {"A": 10, "B": 40, "C": 80, "D": 40, "E": 10}
        events = [("BC", 1), ("ABD", 6), ("ABC", 2), ("CE", 8), ("BCD", 5), ("ABCD", 3)]
        history = [transition(lengths, set(lengths) - set(mask)) for mask, count in events for _ in range(count)]
        return lengths, history

    def test_correlated_dp_counterexample_beats_all_three_scalar_rules(self):
        lengths, history = self.correlated_case()
        results = {method: plan_layout(sources(lengths), history, [], {"method": method})
                   for method in ("risk", "risk_length_ratio", "static_joint_dp")}
        dp = results["static_joint_dp"]
        self.assertEqual(dp["ordered_source_ids"], list("DABCE"))
        self.assertAlmostEqual(dp["details"]["static_proxy_optimal_expected_retained_bytes"], 34)
        self.assertEqual(results["risk"]["ordered_source_ids"], list("EADBC"))
        self.assertEqual(results["risk_length_ratio"]["ordered_source_ids"], list("DCEBA"))
        for method, expected in (("risk", 10.8), ("risk_length_ratio", 17.6)):
            actual = sum(retained(results[method]["ordered_source_ids"], lengths, row["after"])
                         for row in history) / len(history)
            self.assertAlmostEqual(actual, expected)
        # Independent exhaustive oracle, not a second copy of the DP recurrence.
        oracle = max(sum(retained(order, lengths, row["after"]) for row in history) / len(history)
                     for order in itertools.permutations(lengths))
        self.assertAlmostEqual(oracle, 34)

    def test_independent_risk_length_ratio_matches_exact_proxy_optimum(self):
        lengths = {"A": 2, "B": 9, "C": 4, "D": 1}
        # Uniform repetition realises independent removal probabilities 1/2,
        # 1/4, 3/4, 1/2 without floating-point samples or future test events.
        probabilities = {"A": .5, "B": .25, "C": .75, "D": .5}
        history = []
        for mask in range(1 << len(lengths)):
            after = {sid for bit, sid in enumerate(lengths) if not mask & (1 << bit)}
            weight = math.prod((1 - probabilities[sid]) if sid in after else probabilities[sid] for sid in lengths)
            history.extend([transition(lengths, after)] * round(weight * 256))
        ratio = plan_layout(sources(lengths), history, [], {"method": "risk_length_ratio"})
        dp = plan_layout(sources(lengths), history, [], {"method": "static_joint_dp"})
        self.assertEqual(ratio["ordered_source_ids"], dp["ordered_source_ids"])

    def switching_case(self):
        lengths = {"A": 10, "B": 10, "C": 20, "D": 20}
        current = sources({sid: lengths[sid] for sid in "ACD"})
        history = [transition("ACD", "BCD") for _ in range(8)] + [transition("ACD", "ACD") for _ in range(2)]
        return current, history, {"known_source_lengths_bytes": lengths}

    def test_causal_two_step_pays_now_to_establish_next_lawful_prefix(self):
        current, history, cfg = self.switching_case()
        result = plan_layout(current, history, [["A"]], {**cfg, "method": "causal_two_step"})
        greedy = plan_layout(current, history, [["A"]], {**cfg, "method": "cache_greedy"})
        self.assertEqual(result["ordered_source_ids"], list("CDA"))
        self.assertEqual(result["predicted_now_miss_bytes"], 50)
        self.assertAlmostEqual(result["predicted_next_miss_bytes"], 8)
        self.assertEqual(greedy["predicted_now_miss_bytes"], 40)
        self.assertAlmostEqual(greedy["predicted_next_miss_bytes"], 40)
        self.assertLess(result["details"]["predicted_two_step_miss_objective_bytes"],
                        greedy["details"]["predicted_two_step_miss_objective_bytes"])
        self.assertEqual(result["details"]["forecast_confidence"]["conditional_state_samples"], 10)

    def test_same_history_but_full_hot_view_changes_causal_decision(self):
        current, history, cfg = self.switching_case()
        result = plan_layout(current, history, [list("ACD")], {**cfg, "method": "causal_two_step"})
        static = plan_layout(current, history, [list("ACD")], {**cfg, "method": "conditional_static"})
        self.assertEqual(result["ordered_source_ids"], list("ACD"))
        self.assertEqual(result["predicted_now_miss_bytes"], 0)
        self.assertAlmostEqual(result["predicted_next_miss_bytes"], 40)
        self.assertEqual(static["ordered_source_ids"], list("CDA"))
        self.assertEqual(static["predicted_now_miss_bytes"], 50)

    def test_partial_hot_strong_counterexample_and_risk_cut_matches_candidate(self):
        lengths = {"A": 5, "B": 1, "C": 10, "X": 7}
        current = sources({sid: lengths[sid] for sid in "ABC"})
        history = [transition("ABC", "AC") for _ in range(9)] + [transition("ABC", "C")]
        cfg = {"known_source_lengths_bytes": lengths}
        results = {method: plan_layout(current, history, [list("ABX")], {**cfg, "method": method})
                   for method in ("cache_greedy", "conditional_static", "causal_two_step", "cache_greedy_risk_cut")}
        for method, expected in (("cache_greedy", 20), ("conditional_static", 16),
                                 ("causal_two_step", 12), ("cache_greedy_risk_cut", 12)):
            self.assertAlmostEqual(results[method]["details"]["predicted_two_step_miss_objective_bytes"], expected)
        self.assertEqual(results["causal_two_step"]["ordered_source_ids"], list("ACB"))
        # This witness demonstrates a mechanism, NOT superiority to the stronger
        # threshold baseline, which deliberately matches it.
        self.assertEqual(results["cache_greedy_risk_cut"]["ordered_source_ids"], list("ACB"))

    def test_cache_cannot_skip_a_now_forbidden_prefix(self):
        current = sources({"A": 10, "C": 20})
        result = plan_layout(current, [], [list("BAC")], {"method": "cache_greedy"})
        self.assertEqual(result["predicted_now_miss_bytes"], 30)
        self.assertEqual(set(result["ordered_source_ids"]), {"A", "C"})
        self.assertNotIn("B", result["ordered_source_ids"])

    def test_cache_prefix_of_an_old_larger_view_can_be_fully_hot(self):
        current = sources({"A": 10, "C": 20})
        result = plan_layout(current, [], [list("CAB")], {"method": "full_hot_else_static"})
        self.assertEqual(result["ordered_source_ids"], list("CA"))
        self.assertEqual(result["predicted_now_miss_bytes"], 0)

    def test_fallback_reports_missing_support_and_never_reads_unknown_body(self):
        result = plan_layout(sources({"A": 10, "C": 20}), [transition("A", "AB")], [],
                             {"method": "causal_two_step"})
        confidence = result["details"]["forecast_confidence"]
        self.assertTrue(confidence["fallback"])
        self.assertEqual(confidence["conditional_state_samples"], 0)
        self.assertEqual(confidence["unknown_next_length_ids"], ["B"])
        self.assertEqual(result["details"]["current_source_length_bytes"], {"A": 10, "C": 20})

    def test_observable_context_conditions_only_matching_past_rows(self):
        current = sources({"A": 10, "C": 20})
        history = [transition("AC", "A", context="x") for _ in range(2)] + [transition("AC", "C", context="y") for _ in range(3)]
        result = plan_layout(current, history, [], {"context": "x", "method": "conditional_static"})
        self.assertEqual(result["ordered_source_ids"], list("AC"))
        self.assertEqual(result["details"]["forecast_confidence"]["conditional_state_samples"], 2)

    def test_every_arm_is_a_complete_permutation_and_inputs_unchanged(self):
        lengths, history = self.correlated_case()
        current, cache = sources(lengths), [list("AB"), list("ACDE")]
        before = copy.deepcopy((current, history, cache))
        for method in METHODS:
            result = plan_layout(current, history, cache, {"method": method, "max_candidates": 32})
            self.assertEqual(sorted(result["ordered_source_ids"]), sorted(lengths))
            self.assertEqual(len(result["ordered_source_ids"]), len(lengths))
            self.assertLessEqual(result["details"]["candidate_count"], 32)
            self.assertFalse(result["details"]["supplier_cost_or_token_prediction"])
        self.assertEqual((current, history, cache), before)

    def test_disallowed_future_data_and_malformed_inputs_are_rejected(self):
        current = sources({"A": 10})
        for bad_history in ([{"before": ["A"], "after": [], "future_events": []}],
                            [{"before": ["A"], "after": [], "context": {"answers": []}}],
                            [{"before": ["A", "A"], "after": []}]):
            with self.assertRaises(ValueError):
                plan_layout(current, bad_history, [], {})
        for cfg in ({"questions": []}, {"max_candidates": 1},
                    {"next_cost_weight": float("nan")},
                    {"known_source_lengths_bytes": {"A": 9}}):
            with self.assertRaises(ValueError):
                plan_layout(current, [], [], cfg)
        with self.assertRaises(ValueError):
            plan_layout([{**current[0], "allow": False}], [], [], {})

    def test_utf8_lengths_and_deterministic_ties_are_explicit(self):
        current = [{"source_id": "B", "text": "中"}, {"source_id": "A", "text": "ab"}]
        first = plan_layout(current, [], [], {"method": "original"})
        self.assertEqual(first["ordered_source_ids"], ["B", "A"])
        self.assertEqual(first["predicted_now_miss_bytes"], 5)
        second = plan_layout(current, [], [], {"method": "original"})
        first.pop("planning_ms")
        second.pop("planning_ms")
        self.assertEqual(first, second)

    def test_empty_current_view_is_valid_and_twelve_source_dp_runs(self):
        empty = plan_layout([], [], [], {"method": "causal_two_step"})
        self.assertEqual(empty["ordered_source_ids"], [])
        self.assertEqual(empty["predicted_now_miss_bytes"], 0)
        lengths = {f"S{i:02d}": 10 + i for i in range(12)}
        result = plan_layout(sources(lengths), [transition(lengths, lengths)], [], {"method": "static_joint_dp"})
        self.assertEqual(set(result["ordered_source_ids"]), set(lengths))
        with self.assertRaises(ValueError):
            plan_layout(sources({f"S{i:02d}": 10 for i in range(13)}), [], [], {})


if __name__ == "__main__":
    unittest.main()
