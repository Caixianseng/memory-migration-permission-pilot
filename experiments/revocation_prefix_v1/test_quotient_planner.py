"""Independent quotient checks, including partial-class cached prefixes."""
import itertools
import random
import unittest

try:
    from .quotient_planner import QuotientProblem, solve_quotient, plan_layout
    from .exact_planner import solve_exact
    from .test_exact_planner import oracle_scorer
except ImportError:
    from quotient_planner import QuotientProblem, solve_quotient, plan_layout
    from exact_planner import solve_exact
    from test_exact_planner import oracle_scorer


def cohort_fixture(n=24, k=4):
    groups = [[f"G{group:02d}S{index:03d}" for index in range(n // k)] for group in range(k)]
    lengths = {sid: 32 for group in groups for sid in group}
    states = [(set(sid for j, group in enumerate(groups) if j != missing for sid in group), 1)
              for missing in range(k)]
    caches = [groups[0][:1] + groups[1][:1] + groups[0][1:3],
              groups[1][:2] + groups[2][:1], groups[-1][:2] + groups[0][:2]]
    return groups, lengths, states, caches


class QuotientTests(unittest.TestCase):
    def test_partial_cohort_prefix_has_correct_remaining_bytes_and_active_states(self):
        lengths = {"A": 2, "B": 9, "C": 5, "D": 7}
        states = [(set("ABCD"), 1), (set("CD"), 2), (set("AB"), 3)]
        caches = [["A"], list("CA"), list("DB")]
        problem = QuotientProblem(lengths, states, caches)
        result = problem.solve()
        self.assertEqual(result["details"]["forecast_signature_cohort_count"], 2)
        self.assertGreater(result["details"]["partial_cohort_prefixes"], 0)
        self.assertTrue(all(node["future_gain"] == 0 for node in problem.trie))
        full = solve_exact(lengths, states, caches)
        self.assertAlmostEqual(result["expectedobj"], full["expectedobj"])
        oracle = oracle_scorer(lengths, states, caches, 1)
        self.assertAlmostEqual(result["expectedobj"], max(oracle(order)[0] for order in itertools.permutations(lengths)))

    def test_cached_prefix_future_residual_is_always_already_covered(self):
        lengths = {sid: i + 2 for i, sid in enumerate("ABCDE")}
        states = [(set("ABCE"), 2), (set("BCDE"), 3), (set("ACD"), 1)]
        problem = QuotientProblem(lengths, states, [list("ABCD"), list("BCE"), list("DA")])
        oracle = oracle_scorer(lengths, states, problem.cache, 1)
        for node in problem.trie:
            # Direct retained(prefix,A) <= old b_A in each forecast state.
            for allowed, _ in problem.states:
                retained = 0
                for sid in node["prefix"]:
                    if sid not in allowed:
                        break
                    retained += lengths[sid]
                old = 0
                for order in problem.cache:
                    value = 0
                    for sid in order:
                        if sid not in allowed:
                            break
                        value += lengths[sid]
                    old = max(old, value)
                self.assertLessEqual(retained, old)
        result = problem.solve()
        self.assertAlmostEqual(result["expectedobj"], oracle(result["ordered_source_ids"])[0])

    def test_zero_mass_states_do_not_split_a_membership_cohort(self):
        result = solve_quotient({"A": 2, "B": 5, "C": 7},
                                [(set("AB"), 1), ({"A"}, 0), ({"C"}, 1)], [])
        self.assertEqual(result["details"]["forecast_signature_cohort_count"], 2)

    def test_old_only_future_metadata_and_crossing_cache_floor(self):
        lengths = {"A": 2, "B": 11, "C": 5, "D": 7}
        known = {**lengths, "U": 17}
        states = [(set("ABU"), 3), (set("CDU"), 2), (set("ABCD"), 1)]
        cache = [list("UAB"), list("CA"), list("D")]
        quotient = solve_quotient(lengths, states, cache, 2, known)
        exact = solve_exact(lengths, states, cache, 2, known)
        self.assertAlmostEqual(quotient["expectedobj"], exact["expectedobj"])
        self.assertNotIn("U", quotient["ordered_source_ids"])
        self.assertAlmostEqual(quotient["expectedobj"], oracle_scorer(lengths, states, cache, 2, known)(quotient["ordered_source_ids"])[0])

    def test_empty_and_weight_zero_views(self):
        empty = solve_quotient({}, [({"U"}, 1)], [["U"]], known_source_lengths_bytes={"U": 9})
        self.assertEqual(empty["ordered_source_ids"], [])
        self.assertEqual(empty["predicted_next_miss_bytes"], 0)
        zero = solve_quotient({sid: 1 for sid in "ABC"}, [(set("AC"), 1)], [["A"]], 0)
        self.assertEqual(zero["ordered_source_ids"], list("ABC"))
        self.assertEqual(zero["details"]["total_dp_subset_states_across_prefixes"], 0)

    def test_grouping_dominance_for_each_positive_state_after_fixed_prefix(self):
        rng = random.Random(2026110521)
        for _ in range(100):
            groups = [list("AB"), list("CDE"), list("FG")]
            states = []
            # Explicit correlated states guarantee the proposed class identity.
            for _ in range(5):
                states.append(set(sid for group in groups if rng.random() < .6 for sid in group))
            order = rng.sample(list("ABCDEFG"), 7)
            cutoff = rng.randrange(8)
            prefix, tail = order[:cutoff], order[cutoff:]
            grouped = []
            for first in tail:
                if first in grouped:
                    continue
                group = next(group for group in groups if first in group)
                grouped.extend(sid for sid in tail if sid in group)
            lengths = {sid: rng.randint(1, 13) for sid in order}
            for state in states:
                def retained(candidate):
                    value = 0
                    for sid in candidate:
                        if sid not in state:
                            break
                        value += lengths[sid]
                    return value
                self.assertGreaterEqual(retained(prefix + grouped), retained(order))

    def test_random_small_n_matches_full_source_dp_and_independent_factorial_oracle(self):
        rng = random.Random(2026110523)
        partial_cases = 0
        for n in range(1, 8):
            for example in range(12):
                ids = [f"S{i}" for i in range(n)]
                k = rng.randint(1, min(4, n))
                shuffled = rng.sample(ids, n)
                groups = [shuffled[index::k] for index in range(k)]
                universe = ids + ["OLD_U", "OLD_V"]
                known = {sid: rng.randint(1, 15) for sid in universe}
                lengths = {sid: known[sid] for sid in ids}
                states = []
                for _ in range(rng.randint(1, 8)):
                    state = {sid for group in groups if rng.random() < .6 for sid in group}
                    state.update(sid for sid in universe[n:] if rng.random() < .5)
                    states.append((state, rng.randint(1, 6)))
                cache = [rng.sample(universe, rng.randrange(len(universe) + 1)) for _ in range(rng.randint(1, 6))]
                weight = (0, .5, 1, 2, 8)[example % 5]
                quotient = solve_quotient(lengths, states, cache, weight, known)
                exact = solve_exact(lengths, states, cache, weight, known)
                oracle = oracle_scorer(lengths, states, cache, weight, known)
                optimum = max(oracle(order)[0] for order in itertools.permutations(ids))
                with self.subTest(n=n, example=example):
                    self.assertAlmostEqual(quotient["expectedobj"], exact["expectedobj"], places=8)
                    self.assertAlmostEqual(quotient["expectedobj"], optimum, places=8)
                    self.assertAlmostEqual(quotient["expectedobj"], oracle(quotient["ordered_source_ids"])[0], places=8)
                    self.assertEqual(set(quotient["ordered_source_ids"]), set(ids))
                partial_cases += int(quotient["details"]["partial_cohort_prefixes"] > 0)
        self.assertGreater(partial_cases, 10)

    def test_ninety_six_sources_use_eight_dimensional_tail_dps(self):
        _, lengths, states, cache = cohort_fixture(96, 8)
        result = solve_quotient(lengths, states, cache)
        details = result["details"]
        self.assertEqual(len(result["ordered_source_ids"]), 96)
        self.assertEqual(details["forecast_signature_cohort_count"], 8)
        self.assertEqual(details["maximum_remaining_cohort_count"], 8)
        self.assertLessEqual(details["total_dp_subset_states_across_prefixes"], details["legal_cache_trie_nodes"] * 256)
        self.assertEqual(details["uncompressed_source_subset_count"], 2 ** 96)

    def test_no_unconditional_scalability_when_signatures_are_distinct(self):
        lengths = {f"S{i}": 1 for i in range(1, 14)}
        states = [({f"S{i}" for i in range(1, 14) if i & (1 << bit)}, 1) for bit in range(4)]
        with self.assertRaisesRegex(ValueError, "signature_count_exceeds_exact_limit"):
            solve_quotient(lengths, states, [])

    def test_large_wrapper_uses_explicit_joint_history_without_old_twelve_source_cap(self):
        _, lengths, states, cache = cohort_fixture(24, 4)
        sources = [{"source_id": sid, "text": "x" * length} for sid, length in lengths.items()]
        history = [{"before": list(lengths), "after": sorted(state)} for state, _ in states]
        result = plan_layout(sources, history, cache, {"forecast_model": "joint_delta"})
        self.assertEqual(len(result["ordered_source_ids"]), 24)
        self.assertEqual(result["details"]["forecast_signature_cohort_count"], 4)
        with self.assertRaisesRegex(ValueError, "independent_forecast_support_too_large"):
            plan_layout(sources, history, cache, {"forecast_model": "independent_status_marginal"})

    def test_strong_longest_hot_baseline_preserves_full_current_prefix_with_same_group_tail(self):
        lengths = {"A": 5, "B": 1, "C": 10}
        known = {**lengths, "X": 7}
        states, cache = [(set("AC"), 9), ({"C"}, 1)], [list("ABX")]
        problem = QuotientProblem(lengths, states, cache, known_source_lengths_bytes=known)
        baseline = problem.solve(prefix_mode="longest_hot")
        exact = problem.solve(prefix_mode="all")
        self.assertEqual(baseline["ordered_source_ids"][:2], list("AB"))
        self.assertEqual(baseline["current_hit_bytes"], 6)
        self.assertEqual(exact["ordered_source_ids"], list("ACB"))
        self.assertEqual(set(baseline["ordered_source_ids"]), set(exact["ordered_source_ids"]))
        self.assertGreater(exact["expectedobj"], baseline["expectedobj"])
        self.assertFalse(baseline["details"]["exact_for_frozen_two_step_ideal_byte_prefix_objective"])
        self.assertTrue(baseline["details"]["tail_exact_for_each_considered_fixed_prefix"])
        self.assertEqual(baseline["details"]["prefix_dps_evaluated"], 1)
        materials = [{"source_id": sid, "text": "x" * length} for sid, length in lengths.items()]
        history = [{"before": list("ABC"), "after": list(state)} for state, mass in states for _ in range(mass)]
        wrapped = plan_layout(materials, history, cache, {
            "method": "quotient_cache_greedy", "known_source_lengths_bytes": known})
        self.assertEqual(wrapped["ordered_source_ids"], baseline["ordered_source_ids"])

    def test_invalid_ordered_cache_and_forbidden_source_body_rejected(self):
        with self.assertRaises(ValueError):
            solve_quotient({"A": 1}, [({"A"}, 1)], [{"A"}])
        with self.assertRaises(ValueError):
            plan_layout([{"source_id": "A", "text": "a", "allow": False}], [], [], {})
        with self.assertRaises(ValueError):
            plan_layout([{"source_id": "A", "text": "a"}], [], [], {"answers": []})


if __name__ == "__main__":
    unittest.main()
