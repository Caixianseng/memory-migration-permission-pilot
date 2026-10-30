"""Pure mathematical tests: no dataset, model, network or production imports."""
from dataclasses import FrozenInstanceError
from fractions import Fraction
import itertools
import json
import math
import unittest

from experiments.algorithm_ports_20261029.ltt_port import (
    LTTPlan, binomial_lower_tail, calibrate_bernoulli, calibrate_counts, make_plan,
)


class ExactBinomialTests(unittest.TestCase):
    def test_hand_computed_cdf(self):
        self.assertEqual(binomial_lower_tail(0, 3, "1/2"), Fraction(1, 8))
        self.assertEqual(binomial_lower_tail(1, 3, "1/2"), Fraction(1, 2))
        self.assertEqual(binomial_lower_tail(1, 10, "1/2"), Fraction(11, 1024))
        self.assertEqual(binomial_lower_tail(0, 2, "1/3"), Fraction(4, 9))
        self.assertEqual(binomial_lower_tail(1, 2, "1/3"), Fraction(8, 9))

    def test_mathematical_boundaries(self):
        self.assertEqual(binomial_lower_tail(0, 0, "1/2"), 1)
        self.assertEqual(binomial_lower_tail(2, 2, "1/3"), 1)
        self.assertEqual(binomial_lower_tail(0, 3, 0), 1)
        self.assertEqual(binomial_lower_tail(0, 3, 1), 0)
        self.assertEqual(binomial_lower_tail(3, 3, 1), 1)

    def test_decimal_float_contract_is_explicit_and_exact(self):
        self.assertEqual(binomial_lower_tail(0, 32, 0.1), Fraction(9, 10) ** 32)
        self.assertEqual(binomial_lower_tail(1, 8, 0.15), binomial_lower_tail(1, 8, "0.15"))

    def test_against_independent_enumeration_of_bernoulli_sequences(self):
        # Enumerate elementary sequences rather than the production comb sum.
        for n in range(1, 7):
            for alpha in (Fraction(1, 3), Fraction(1, 2), Fraction(4, 5)):
                totals = [Fraction(0) for _ in range(n + 1)]
                for sample in itertools.product((0, 1), repeat=n):
                    probability = math.prod(alpha if x else 1 - alpha for x in sample)
                    for k in range(sum(sample), n + 1):
                        totals[k] += probability
                for k, expected in enumerate(totals):
                    self.assertEqual(binomial_lower_tail(k, n, alpha), expected)

    def test_lower_tail_orientation_and_discrete_null_validity(self):
        for n in range(1, 9):
            alpha = Fraction(1, 4)
            p_values = [binomial_lower_tail(k, n, alpha) for k in range(n + 1)]
            self.assertEqual(p_values, sorted(p_values))
            for true_risk in (alpha, Fraction(1, 2), Fraction(3, 4)):
                for threshold in p_values:
                    rejection_probability = sum(
                        Fraction(math.comb(n, k)) * true_risk ** k * (1 - true_risk) ** (n - k)
                        for k in range(n + 1) if p_values[k] <= threshold)
                    self.assertLessEqual(rejection_probability, threshold)

    def test_invalid_counts_and_probabilities_fail(self):
        for k, n in ((True, 2), (0, True), (0.0, 2), (0, 2.0), (-1, 2), (3, 2), (0, -1)):
            with self.subTest(k=k, n=n), self.assertRaises(ValueError):
                binomial_lower_tail(k, n, "1/2")
        for alpha in (True, float("nan"), float("inf"), "nan", "1/0", -0.1, 1.1, None):
            with self.subTest(alpha=alpha), self.assertRaises(ValueError):
                binomial_lower_tail(0, 2, alpha)


class LTTSelectionTests(unittest.TestCase):
    def plan(self, *, alpha="1/2", delta="1/4", order=("cheap", "full")):
        return make_plan(("cheap", "full"), alpha=alpha, delta=delta, cost_order=order)

    def test_plan_immutable_copy_and_digest(self):
        configs, order = ["cheap", "full"], ["full", "cheap"]
        plan = make_plan(configs, alpha=0.1, delta="1/20", cost_order=order)
        configs.reverse(); order.reverse()
        self.assertEqual(plan.config_ids, ("cheap", "full"))
        self.assertEqual(plan.cost_order, ("full", "cheap"))
        with self.assertRaises(FrozenInstanceError):
            plan.alpha = Fraction(1, 2)
        twin = make_plan(("cheap", "full"), alpha="1/10", delta=0.05, cost_order=("full", "cheap"))
        self.assertEqual(plan.sha256, twin.sha256)
        self.assertNotEqual(plan.sha256, self.plan().sha256)

    def test_bonferroni_exact_equality_is_accepted(self):
        # P[Bin(3,1/2)=0]=1/8 = delta/m, not an upper-tail test.
        result = calibrate_counts(self.plan(), {"cheap": 0, "full": 3}, n=3)
        self.assertEqual(result["bonferroni_threshold_exact"], {"numerator": 1, "denominator": 8})
        self.assertEqual(result["qualified_configs"], ["cheap"])
        self.assertEqual(result["selected_config"], "cheap")

    def test_multiplicity_changes_decision(self):
        one = make_plan(("cheap",), alpha="1/2", delta="1/20", cost_order=("cheap",))
        self.assertEqual(calibrate_counts(one, {"cheap": 0}, n=5)["selected_config"], "cheap")
        two = self.plan(delta="1/20")
        result = calibrate_counts(two, {"cheap": 0, "full": 5}, n=5)
        self.assertEqual(result["qualified_configs"], [])
        self.assertIsNone(result["selected_config"])

    def test_zero_failures_can_still_return_empty(self):
        result = calibrate_counts(self.plan(alpha="1/10", delta="1/20"), {"cheap": 0, "full": 0}, n=32)
        self.assertEqual(result["qualified_configs"], [])
        self.assertEqual(result["status"], "no_qualified_configuration")

    def test_selection_uses_declared_cost_not_failure_ranking_or_mapping_order(self):
        plan = self.plan(delta="1/2", order=("full", "cheap"))
        result = calibrate_counts(plan, {"full": 1, "cheap": 0}, n=6)
        self.assertEqual(result["qualified_configs"], ["cheap", "full"])
        self.assertEqual(result["selected_config"], "full")

    def test_full_is_selected_if_only_full_qualifies(self):
        result = calibrate_counts(self.plan(), {"cheap": 3, "full": 0}, n=3)
        self.assertEqual(result["selected_config"], "full")

    def test_bernoulli_and_count_interfaces_agree_and_are_json_safe(self):
        plan = self.plan()
        observations = {"cheap": [0, 0, 0], "full": [1, 1, 1]}
        a = calibrate_bernoulli(plan, observations)
        b = calibrate_counts(plan, {"cheap": 0, "full": 3}, n=3)
        self.assertEqual(a, b)
        self.assertEqual(json.loads(json.dumps(a, allow_nan=False)), a)
        self.assertIsNone(a["human_semantic_validation"])
        self.assertFalse(a["paper_experiments_reproduced"])

    def test_same_calibration_tasks_may_yield_identical_config_losses(self):
        result = calibrate_bernoulli(self.plan(), {"cheap": [0] * 3, "full": [0] * 3})
        self.assertEqual(result["qualified_configs"], ["cheap", "full"])
        self.assertEqual(result["family_size"], 2)  # Correlation does not remove correction.

    def test_fixed_family_and_cost_order_required(self):
        for configs, order in (([], []), (["a", "a"], ["a"]), (["a"], []),
                               (["a"], ["b"]), ([" a"], [" a"]), ("a", ["a"]),
                               (["a", "b"], ["a", "a"])):
            with self.subTest(configs=configs, order=order), self.assertRaises(ValueError):
                make_plan(configs, alpha="1/2", delta="1/4", cost_order=order)
        for value in (0, 1, True, float("nan")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(alpha=value)
            with self.subTest(delta=value), self.assertRaises(ValueError):
                self.plan(delta=value)
        with self.assertRaises(ValueError):
            LTTPlan(("a",), 0.5, Fraction(1, 4), ("a",))

    def test_missing_extra_and_invalid_counts_not_silently_omitted(self):
        plan = self.plan()
        for counts in ({"cheap": 0}, {"cheap": 0, "full": 0, "new": 0},
                       {"cheap": True, "full": 0}, {"cheap": 0.0, "full": 0},
                       {"cheap": -1, "full": 0}, {"cheap": 4, "full": 0}):
            with self.subTest(counts=counts), self.assertRaises(ValueError):
                calibrate_counts(plan, counts, n=3)
        for n in (0, -1, True, 3.0):
            with self.subTest(n=n), self.assertRaises(ValueError):
                calibrate_counts(plan, {"cheap": 0, "full": 0}, n=n)

    def test_bernoulli_data_must_be_complete_strict_and_nonempty(self):
        plan = self.plan()
        for losses in ({"cheap": [], "full": []}, {"cheap": [0], "full": [0, 1]},
                       {"cheap": [False], "full": [0]}, {"cheap": [0.0], "full": [0]},
                       {"cheap": [2], "full": [0]}, {"cheap": "0", "full": [0]},
                       {"cheap": [None], "full": [0]}):
            with self.subTest(losses=losses), self.assertRaises(ValueError):
                calibrate_bernoulli(plan, losses)


if __name__ == "__main__":
    unittest.main()
