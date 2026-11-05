"""Independent small-n exhaustive checks of the exact two-step BYTE proxy.

These are mathematical/mechanism tests, never real fee/quality evidence.
The independent oracle computes longest common prefixes and future legal-prefix
hits directly; it does not reuse the solver's delta table or DP recurrence.
"""
import itertools
import math
import random
import unittest

try:
    from .exact_planner import ExactProblem, plan_layout, solve_exact
    from . import planner as frozen_planner
except ImportError:
    from exact_planner import ExactProblem, plan_layout, solve_exact
    import planner as frozen_planner


def oracle_scorer(lengths, states, cache, weight, known=None):
    known = {**(known or {}), **lengths}
    probability_sum = sum(probability for _, probability in states)
    workspace = []
    for allowed, probability in states:
        allowed = set(allowed)
        old_hit = 0
        for old in cache:
            value = 0
            for sid in old:
                if sid not in allowed:
                    break
                value += known[sid]
            old_hit = max(old_hit, value)
        workspace.append((allowed, probability / probability_sum, old_hit))

    def score(order):
        current = 0
        for old in cache:
            value = 0
            for index, sid in enumerate(order):
                if index >= len(old) or old[index] != sid:
                    break
                value += lengths[sid]
            current = max(current, value)
        future = 0.0
        for allowed, probability, old_hit in workspace:
            retained = 0
            for sid in order:
                if sid not in allowed:
                    break
                retained += lengths[sid]
            future += probability * max(old_hit, retained)
        return current + weight * future, current, future

    return score


class ExactPlannerTests(unittest.TestCase):
    def test_residual_future_coverage_differs_from_unconditional_prefix_dp(self):
        # A is highly likely next, but the long old U,A prefix already covers it.
        # B should lead the new layout to cover the previously uncovered state.
        lengths = {"A": 1, "B": 1}
        known = {**lengths, "U": 100}
        states, cache = [(set("UA"), .9), ({"B"}, .1)], [list("UA")]
        result = solve_exact(lengths, states, cache, 1, known)
        self.assertEqual(result["ordered_source_ids"], list("BA"))
        self.assertAlmostEqual(result["expectedobj"], 91)
        self.assertEqual(result["predicted_now_miss_bytes"], 2)
        self.assertAlmostEqual(result["predicted_next_miss_bytes"], 0)
        problem = ExactProblem(lengths, states, cache, 1, known)
        self.assertEqual(problem.delta[0][problem.index["A"]], 0)
        self.assertAlmostEqual(problem.delta[0][problem.index["B"]], .1)
        history = [{"before": list("AB"), "after": list("UA")} for _ in range(9)] + [
            {"before": list("AB"), "after": ["B"]}]
        old = frozen_planner.plan_layout([
            {"source_id": sid, "text": "x" * length} for sid, length in lengths.items()], history, cache,
            {"method": "conditional_static", "known_source_lengths_bytes": known})
        self.assertEqual(old["ordered_source_ids"], list("AB"))

    def test_cache_prefix_enumeration_counts_actual_continuation_hit(self):
        lengths = {sid: 1 for sid in "ABC"}
        result = solve_exact(lengths, [(set("ABC"), 1)], [list("ABC")])
        self.assertEqual(result["ordered_source_ids"], list("ABC"))
        self.assertEqual(result["current_hit_bytes"], 3)
        self.assertEqual(result["expectedobj"], 6)
        self.assertEqual(result["details"]["number_legal_cache_trie_nodes"], 4)

    def test_now_forbidden_first_cached_source_cannot_be_skipped(self):
        result = solve_exact({"A": 3, "C": 5}, [(set("AC"), 1)], [list("BAC")],
                             known_source_lengths_bytes={"B": 7})
        self.assertEqual(result["current_hit_bytes"], 0)
        self.assertEqual(result["predicted_now_miss_bytes"], 8)
        self.assertEqual(set(result["ordered_source_ids"]), set("AC"))
        self.assertEqual(result["details"]["number_legal_cache_trie_nodes"], 1)

    def test_no_future_increment_after_a_missing_prefix_source(self):
        problem = ExactProblem({"A": 3, "B": 5, "C": 7}, [({"A", "C"}, 1)], [])
        mask_ab = (1 << problem.index["A"]) | (1 << problem.index["B"])
        self.assertEqual(problem.delta[mask_ab][problem.index["C"]], 0)
        self.assertEqual(problem.score_order(list("ABC"))["expected_next_hit_bytes"], 3)

    def test_weight_zero_never_reintroduces_future_as_a_tiebreak(self):
        result = solve_exact({sid: 1 for sid in "ABC"}, [(set("AC"), 1)], [["A"]], 0)
        self.assertEqual(result["ordered_source_ids"], list("ABC"))
        self.assertEqual(result["expectedobj"], 1)
        self.assertEqual(result["predicted_next_miss_bytes"], 1)

    def test_empty_and_single_source_views_are_exact(self):
        empty = solve_exact({}, [({"U"}, 1)], [["U"]], known_source_lengths_bytes={"U": 7})
        self.assertEqual(empty["ordered_source_ids"], [])
        self.assertEqual(empty["predicted_next_miss_bytes"], 0)
        single = solve_exact({"A": 3}, [(set(), 1)], [])
        self.assertEqual(single["ordered_source_ids"], ["A"])
        self.assertEqual(single["predicted_now_miss_bytes"], 3)

    def test_missing_cached_or_future_lengths_are_rejected(self):
        for states, cache in (([({"A"}, 1)], [["U"]]), ([({"A", "U"}, 1)], [])):
            with self.assertRaises(ValueError):
                solve_exact({"A": 3}, states, cache)
        with self.assertRaises(ValueError):
            solve_exact({"A": 3}, [({"A"}, 1)], [], known_source_lengths_bytes={"A": 4})

    def test_invalid_probability_lengths_and_permutations_fail_closed(self):
        for states in ([], [({"A"}, 0)], [({"A"}, float("nan"))], [({"A"}, -1)], [({"A", "A"}, True)]):
            with self.assertRaises(ValueError):
                solve_exact({"A": 3}, states, [])
        for length in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                solve_exact({"A": length}, [({"A"}, 1)], [])
        problem = ExactProblem({"A": 3, "B": 5}, [(set("AB"), 1)], [])
        for order in (["A"], ["A", "A"], ["A", "U"]):
            with self.assertRaises(ValueError):
                problem.score_order(order)

    def test_wrapper_reuses_frozen_predictor_and_preserves_all_legal_text_ids(self):
        materials = [{"source_id": "A", "text": "中"}, {"source_id": "B", "text": "bb"}]
        history = [{"before": list("AB"), "after": ["B"]} for _ in range(3)]
        result = plan_layout(materials, history, [["A"]], {
            "method": "exact_two_step", "forecast_model": "joint_delta"})
        self.assertEqual(set(result["ordered_source_ids"]), set("AB"))
        self.assertEqual(result["details"]["current_source_length_bytes"], {"A": 3, "B": 2})
        self.assertEqual(result["details"]["forecast_confidence"]["forecast_model"], "joint_delta")
        self.assertTrue(result["details"]["exact_for_frozen_two_step_ideal_byte_prefix_objective"])
        with self.assertRaises(ValueError):
            plan_layout(materials, history, [], {"method": "causal_two_step"})
        with self.assertRaises(ValueError):
            plan_layout(materials, history, [], {"future_events": []})

    def test_fixed_development_fixture_exposes_old_bounded_pool_gap(self):
        # Mechanism fixture found at trial 40 of fixed seed 2026110507. It is NOT
        # a selected item in any aggregate development/held-out performance table.
        lengths = {"A": 4, "B": 4, "C": 13, "D": 7, "E": 8, "F": 15, "U": 10, "V": 15}
        after = ("CEFU", "ABCUV", "ABCEFV", "ACFUV", "ACDFU", "ABCDEFV", "ABCEFUV", "ACDEF",
                 "ABCDEV", "BCDFUV", "ACDEUV")
        history = [{"before": list("ABCDEF"), "after": list(state)} for state in after]
        cache = [list(order) for order in ("FCVA", "UV", "BVCED FUA".replace(" ", ""), "CE")]
        current_lengths = {sid: lengths[sid] for sid in "ABCDEF"}
        materials = [{"source_id": sid, "text": "x" * length} for sid, length in current_lengths.items()]
        exact = plan_layout(materials, history, cache, {"known_source_lengths_bytes": lengths})
        bounded = frozen_planner.plan_layout(materials, history, cache, {
            "method": "causal_two_step", "known_source_lengths_bytes": lengths})
        self.assertEqual(exact["ordered_source_ids"], list("FCADEB"))
        self.assertAlmostEqual(exact["expectedobj"], 772 / 11)
        self.assertGreater(bounded["details"]["predicted_two_step_miss_objective_bytes"],
                           exact["expected_two_step_miss_bytes"] + .6)
        direct = oracle_scorer(current_lengths, [(set(state), 1) for state in after], cache, 1, lengths)
        self.assertAlmostEqual(exact["expectedobj"], max(direct(order)[0] for order in itertools.permutations(current_lengths)))

    def test_random_n_one_through_seven_match_independent_all_permutations(self):
        rng = random.Random(2026110511)
        checked = 0
        for n in range(1, 8):
            for example in range(12):
                ids = [f"S{i}" for i in range(n)]
                universe = ids + ["OLD_U", "OLD_V"]
                known = {sid: rng.randint(1, 17) for sid in universe}
                lengths = {sid: known[sid] for sid in ids}
                states = [(set(rng.sample(universe, rng.randrange(len(universe) + 1))), rng.randint(1, 7))
                          for _ in range(rng.randint(1, 9))]
                cache = [rng.sample(universe, rng.randrange(len(universe) + 1))
                         for _ in range(rng.randrange(7))]
                weight = (0, .5, 1, 2, 8)[example % 5]
                direct = oracle_scorer(lengths, states, cache, weight, known)
                result = solve_exact(lengths, states, cache, weight, known)
                best_direct = max(direct(order)[0] for order in itertools.permutations(ids))
                with self.subTest(n=n, example=example, weight=weight):
                    self.assertAlmostEqual(result["expectedobj"], best_direct, places=8)
                    actual = direct(result["ordered_source_ids"])
                    self.assertAlmostEqual(result["expectedobj"], actual[0], places=8)
                    self.assertEqual(result["current_hit_bytes"], actual[1])
                    self.assertAlmostEqual(result["expected_next_hit_bytes"], actual[2], places=8)
                    self.assertEqual(set(result["ordered_source_ids"]), set(ids))
                checked += 1
        self.assertEqual(checked, 84)

    def test_shared_delta_score_matches_direct_score_for_every_five_source_order(self):
        lengths = {sid: index + 2 for index, sid in enumerate("ABCDE")}
        known = {**lengths, "U": 23}
        states = [(set("ACEU"), 3), (set("BCDE"), 2), (set("ABDEU"), 1)]
        cache = [list("ACE"), list("UAB"), list("BD")]
        problem = ExactProblem(lengths, states, cache, 2, known)
        direct = oracle_scorer(lengths, states, cache, 2, known)
        for order in itertools.permutations(lengths):
            self.assertAlmostEqual(problem.score_order(order)["expectedobj"], direct(order)[0], places=9)
        self.assertLessEqual(problem.solve()["details"]["dp_state_transitions"], 5 * 2 ** 4)


if __name__ == "__main__":
    unittest.main()
