"""Fixed decision inventory for the exact optimizer, not a fee/workload trial.

All n=8/10/12 cases, caches and correlated forecast distributions are retained.
The legacy bounded optimizer and exact solver receive the SAME forecast, weight
and source bytes. A current-cache greedy baseline uses no future information.
No planner or frozen screen is edited. No model/network/credential access.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import time

try:
    from . import exact_planner, planner
except ImportError:
    import exact_planner
    import planner


SEED = 2026110519
HERE = Path(__file__).resolve().parent


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(encoded(value))


def make_inventory(per_size=24):
    cases = []
    for n in (8, 10, 12):
        for number in range(per_size):
            seed = SEED + n * 100003 + number * 1009
            rng = random.Random(seed)
            ids = [f"S{i + 1:02d}" for i in range(n)]
            outsiders = [f"OLD{i + 1}" for i in range(min(2, 12 - n))]
            universe = ids + outsiders
            lengths = {sid: 64 * rng.randint(1, 48) for sid in universe}
            # The current view is never fully hot: each actual historical raw
            # view contains at most n-1 current sources. Old views may include
            # currently forbidden IDs, whose TEXT is never supplied to a planner.
            caches = []
            for index in range(rng.randint(4, 12)):
                old = rng.sample(ids, rng.randint(1, n - 1))
                if outsiders and index % 3 != 0:
                    insertion = rng.randrange(len(old) + 1)
                    old.insert(insertion, rng.choice(outsiders))
                caches.append(old)
            perm = rng.sample(ids, n)
            groups = [perm[index:index + 2] for index in range(0, n, 2)]
            forecast = []
            for _ in range(rng.randint(4, 16)):
                draw = rng.random()
                if draw < .35:
                    allowed = set(rng.choice(caches))
                elif draw < .85:
                    allowed = {sid for group in groups if rng.random() < .65 for sid in group}
                    allowed.update(sid for sid in outsiders if rng.random() < .35)
                else:
                    allowed = {sid for sid in universe if rng.random() < .65}
                forecast.append({"allowed": sorted(allowed), "mass": rng.randint(1, 8)})
            cases.append({"case_id": f"decision-n{n:02d}-{number:02d}", "seed": seed,
                          "current_ids": ids, "known_lengths": lengths,
                          "prior_actual_orders_proxy": caches, "forecast_states": forecast})
    return cases


def greedy_current_cache_only(ids, lengths, cache):
    current, best = set(ids), ()
    best_key = (0, ())
    for old in cache:
        prefix = []
        for sid in old:
            if sid not in current:
                break
            prefix.append(sid)
        key = (-sum(lengths[sid] for sid in prefix), tuple(prefix))
        if key < best_key:
            best_key, best = key, tuple(prefix)
    return list(best) + sorted(current - set(best))


def independent_score(order, current_lengths, states, cache, known):
    """No solver delta table: direct prefix scoring of the three chosen actions."""
    now_hit = 0
    for old in cache:
        value = 0
        for index, sid in enumerate(order):
            if index >= len(old) or sid != old[index]:
                break
            value += current_lengths[sid]
        now_hit = max(now_hit, value)
    probability_sum = sum(mass for _, mass in states)
    future_hit, next_total = 0.0, 0.0
    for state, mass in states:
        state = set(state)
        hit = 0
        for old in list(cache) + [order]:
            value = 0
            for sid in old:
                if sid not in state:
                    break
                value += known[sid]
            hit = max(hit, value)
        probability = mass / probability_sum
        future_hit += probability * hit
        next_total += probability * sum(known[sid] for sid in state)
    now_miss = sum(current_lengths.values()) - now_hit
    future_miss = next_total - future_hit
    return {"objective_hit_bytes": now_hit + future_hit, "now_miss_bytes": now_miss,
            "expected_next_miss_bytes": future_miss, "two_step_miss_bytes": now_miss + future_miss}


def run(output, per_size=24):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    cases = make_inventory(per_size)
    contract = {
        "schema": "exact-two-step-fixed-decision-inventory-v1", "seed": SEED,
        "current_source_sizes": [8, 10, 12], "cases_per_size": per_size,
        "old_orders_range": [4, 12], "forecast_state_draw_range": [4, 16],
        "current_cache_state": "partial_hot_only_never_a_full_hot_current_view",
        "forecast": "explicit_correlated_weighted_states_encoded_as_empirical_past_transitions",
        "same_forecast_for_bounded_and_exact": True,
        "weight": 1.0, "bounded_candidate_cap": 192,
        "greedy_baseline": "longest_current_legal_cached_prefix_then_ID_tail_NO_future_information",
        "measurement": "expected_two_step_ideal_source_UTF8_byte_prefix_objective_ONLY",
        "all_fixed_cases_retained_no_seed_selection": True,
        "not_lifecycle_fee_latency_or_semantic_quality_evidence": True,
        "model_calls": 0,
        "code_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in (Path(__file__), Path(exact_planner.__file__), Path(planner.__file__))},
        "inventory_sha256": hashlib.sha256(encoded(cases)).hexdigest(),
    }
    save(output / "frozen_contract.json", contract)
    save(output / "all_fixed_cases.json", cases)
    results, started = [], time.time()
    for index, case in enumerate(cases):
        known, ids = case["known_lengths"], case["current_ids"]
        current_lengths = {sid: known[sid] for sid in ids}
        states = [(set(row["allowed"]), row["mass"]) for row in case["forecast_states"]]
        cache = case["prior_actual_orders_proxy"]
        history = [{"before": ids, "after": row["allowed"]} for row in case["forecast_states"]
                   for _ in range(row["mass"])]
        # Only current legal original fixture bodies reach either planner.
        sources = [{"source_id": sid, "text": chr(65 + bit) * known[sid]} for bit, sid in enumerate(ids)]
        cfg = {"known_source_lengths_bytes": known, "forecast_model": "conditional_state",
               "next_cost_weight": 1.0, "max_candidates": 192, "min_conditional_samples": 2}
        exact = exact_planner.plan_layout(sources, history, cache, {**cfg, "method": "exact_two_step"})
        bounded = planner.plan_layout(sources, history, cache, {**cfg, "method": "causal_two_step"})
        tick = time.perf_counter()
        greedy_order = greedy_current_cache_only(ids, known, cache)
        greedy_ms = (time.perf_counter() - tick) * 1000
        scores = {name: independent_score(order, current_lengths, states, cache, known)
                  for name, order in (("exact", exact["ordered_source_ids"]),
                                      ("bounded", bounded["ordered_source_ids"]),
                                      ("current_cache_greedy", greedy_order))}
        if abs(scores["exact"]["objective_hit_bytes"] - exact["expectedobj"]) > 1e-7:
            raise AssertionError("independent_exact_score_disagrees")
        if abs(scores["bounded"]["two_step_miss_bytes"] - bounded["details"]["predicted_two_step_miss_objective_bytes"]) > 1e-7:
            raise AssertionError("bounded_forecast_not_equal_to_explicit_distribution")
        if scores["exact"]["objective_hit_bytes"] + 1e-7 < max(value["objective_hit_bytes"] for value in scores.values()):
            raise AssertionError("exact_optimizer_loses_feasible_action")
        row = {"case_id": case["case_id"], "current_source_count": len(ids), "scores": scores,
               "orders": {"exact": exact["ordered_source_ids"], "bounded": bounded["ordered_source_ids"],
                          "current_cache_greedy": greedy_order},
               "planning_ms": {"exact_total_with_preprocessing": exact["planning_ms"],
                               "bounded_total": bounded["planning_ms"],
                               "current_cache_greedy_without_forecast_or_score_evaluation": greedy_ms},
               "exact_details": exact["details"],
               "bounded_candidate_count": bounded["details"]["candidate_count"],
               "exact_vs_bounded_gap_bytes": scores["bounded"]["two_step_miss_bytes"] - scores["exact"]["two_step_miss_bytes"],
               "exact_vs_greedy_gap_bytes": scores["current_cache_greedy"]["two_step_miss_bytes"] - scores["exact"]["two_step_miss_bytes"],
               "direct_prefix_score_checks_passed": True}
        results.append(row)
        if (index + 1) % per_size == 0:
            print(json.dumps({"stage": "inventory_size_complete", "n": len(ids), "completed": index + 1,
                              "total": len(cases)}), flush=True)
    aggregate = {}
    for key in ("all", "8", "10", "12"):
        selected = results if key == "all" else [row for row in results if row["current_source_count"] == int(key)]
        totals = {name: sum(row["scores"][name]["two_step_miss_bytes"] for row in selected)
                  for name in ("exact", "bounded", "current_cache_greedy")}
        gaps = [row["exact_vs_bounded_gap_bytes"] for row in selected]
        aggregate[key] = {"decisions": len(selected), "expected_two_step_miss_byte_totals": totals,
                          "exact_relative_miss_reduction_vs_bounded": 1 - totals["exact"] / totals["bounded"],
                          "exact_relative_miss_reduction_vs_no_future_greedy": 1 - totals["exact"] / totals["current_cache_greedy"],
                          "exact_strict_improvements_vs_bounded": sum(gap > 1e-7 for gap in gaps),
                          "exact_equal_objective_vs_bounded": sum(abs(gap) <= 1e-7 for gap in gaps),
                          "maximum_bounded_proxy_suboptimality_bytes": max(gaps),
                          "mean_exact_planning_ms": sum(row["planning_ms"]["exact_total_with_preprocessing"] for row in selected) / len(selected)}
    summary = {"status": "completed", "measurement": contract["measurement"], "all_cases_retained": True,
               "aggregate": aggregate, "elapsed_seconds": time.time() - started,
               "all_independent_prefix_score_checks_passed": True,
               "supplier_cost_or_quality_advantage_established": False}
    save(output / "all_decision_results.json", results)
    save(output / "summary.json", summary)
    print(json.dumps({"status": "completed", "summary": aggregate["all"]}), flush=True)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "exact_inventory_v1")
    parser.add_argument("--cases-per-size", type=int, default=24)
    options = parser.parse_args()
    if options.cases_per_size < 1:
        parser.error("cases-per-size must be positive")
    run(options.output, options.cases_per_size)
