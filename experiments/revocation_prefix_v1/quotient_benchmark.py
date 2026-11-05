"""Whole-planner scale benchmark for the exact forecast-signature quotient.

All 18 fixed cases n=24/48/96 x k=4/6/8 x 2 seeds are retained. Each source
contains 32 UTF-8 bytes; this is an algorithm benchmark, not a context pressure,
supplier fee, QA or lifecycle-benefit experiment. Every legal cached prefix's DP
is charged in the reported all-prefix solve, never only one class-subset DP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import time

try:
    from .quotient_planner import QuotientProblem
except ImportError:
    from quotient_planner import QuotientProblem


HERE = Path(__file__).resolve().parent
SEED = 2026110529


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(encoded(value))


def make_cases():
    cases = []
    for n in (24, 48, 96):
        for k in (4, 6, 8):
            for repeat in range(2):
                seed = SEED + n * 100003 + k * 1009 + repeat * 13
                rng = random.Random(seed)
                groups = [[f"G{group:02d}S{i:03d}" for i in range(n // k)] for group in range(k)]
                ids = [sid for group in groups for sid in group]
                known = {sid: 32 for sid in ids + ["OLD_U", "OLD_V"]}
                signatures = rng.sample(range(1, (1 << 16) - 1), k)
                states = []
                for index in range(16):
                    allowed = {sid for signature, group in zip(signatures, groups) if signature & (1 << index) for sid in group}
                    allowed.update(sid for sid in ("OLD_U", "OLD_V") if rng.random() < .5)
                    states.append({"allowed": sorted(allowed), "mass": rng.randint(1, 8)})
                cache = []
                for index in range(rng.randint(4, 12)):
                    length = rng.randint(max(2, n // 6), n * 3 // 4)
                    leading_group = groups[index % k]
                    leading = rng.sample(leading_group, rng.randint(1, max(1, len(leading_group) - 1)))
                    rest = rng.sample([sid for sid in ids if sid not in leading], max(0, length - len(leading)))
                    order = leading + rest
                    if index % 4 == 0:
                        order.insert(rng.randrange(len(order) + 1), rng.choice(["OLD_U", "OLD_V"]))
                    cache.append(order)
                cases.append({"case_id": f"scale-n{n:03d}-k{k:02d}-{repeat}", "seed": seed,
                              "source_count": n, "designed_k": k, "current_ids": ids,
                              "known_lengths": known, "states": states, "prior_actual_orders_proxy": cache})
    return cases


def direct_score(order, lengths, states, cache, known):
    now = 0
    for old in cache:
        hit = 0
        for i, sid in enumerate(order):
            if i >= len(old) or old[i] != sid:
                break
            hit += lengths[sid]
        now = max(now, hit)
    total_mass = sum(mass for _, mass in states)
    future = 0.0
    for allowed, mass in states:
        best = 0
        for candidate in list(cache) + [order]:
            hit = 0
            for sid in candidate:
                if sid not in allowed:
                    break
                hit += known[sid]
            best = max(best, hit)
        future += mass / total_mass * best
    return now + future


def run(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    cases = make_cases()
    contract = {"schema": "forecast-signature-quotient-scale-benchmark-v1", "seed": SEED,
                "source_counts": [24, 48, 96], "designed_signature_counts": [4, 6, 8],
                "repeats_per_cell": 2, "source_utf8_bytes_each": 32, "forecast_state_draws": 16,
                "prior_order_count_range": [4, 12], "weight": 1,
                "all_cases_retained_no_tuning": True, "timing_includes_every_prefix_dp": True,
                "measurement": "Python_algorithm_runtime_and_exact_ideal_prefix_proxy_ONLY",
                "no_fees_quality_or_actual_model_calls": True,
                "code_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                for name in ("quotient_planner.py", "test_quotient_planner.py", "quotient_benchmark.py")},
                "cases_sha256": hashlib.sha256(encoded(cases)).hexdigest()}
    save(output / "frozen_contract.json", contract)
    save(output / "all_fixed_cases.json", cases)
    results = []
    for case in cases:
        lengths = {sid: case["known_lengths"][sid] for sid in case["current_ids"]}
        states = [(set(row["allowed"]), row["mass"]) for row in case["states"]]
        cache = case["prior_actual_orders_proxy"]
        started = time.perf_counter()
        problem = QuotientProblem(lengths, states, cache, 1, case["known_lengths"])
        all_prefix = problem.solve("all")
        wall = (time.perf_counter() - started) * 1000
        # It is the SAME predictor, residual-cache objective and exact class DP;
        # the strong baseline fixes just the longest current legal hot prefix.
        longest = problem.solve("longest_hot")
        for decision in (all_prefix, longest):
            checked = direct_score(decision["ordered_source_ids"], lengths, states, cache, case["known_lengths"])
            if abs(checked - decision["expectedobj"]) > 1e-7:
                raise AssertionError("independent_whole_order_prefix_score_disagrees")
            if len(decision["ordered_source_ids"]) != case["source_count"] or set(decision["ordered_source_ids"]) != set(lengths):
                raise AssertionError("not_all_raw_source_ids_preserved")
        if all_prefix["expectedobj"] + 1e-7 < longest["expectedobj"]:
            raise AssertionError("exact_all_prefix_optimizer_loses_its_feasible_baseline")
        row = {"case_id": case["case_id"], "source_count": case["source_count"],
               "actual_signature_count": all_prefix["details"]["forecast_signature_cohort_count"],
               "actual_positive_forecast_states": all_prefix["details"]["forecast_state_count"],
               "legal_cache_trie_nodes_T": all_prefix["details"]["legal_cache_trie_nodes"],
               "all_prefix_dps_actually_evaluated": all_prefix["details"]["prefix_dps_evaluated"],
               "partial_cohort_prefixes": all_prefix["details"]["partial_cohort_prefixes"],
               "all_prefix_dp_subset_states_total": all_prefix["details"]["total_dp_subset_states_across_prefixes"],
               "uncompressed_source_subset_count": 1 << case["source_count"],
               "all_prefix_total_wall_ms": wall,
               "all_prefix_reported_total_ms": all_prefix["planning_ms"],
               "shared_preprocessing_ms": problem.preprocessing_ms,
               "longest_hot_total_ms_charging_shared_preprocessing": longest["planning_ms"],
               "exact_objective_hit_bytes": all_prefix["expectedobj"],
               "longest_hot_objective_hit_bytes": longest["expectedobj"],
               "exact_expected_two_step_miss_bytes": all_prefix["expected_two_step_miss_bytes"],
               "longest_hot_expected_two_step_miss_bytes": longest["expected_two_step_miss_bytes"],
               "all_current_raw_source_ids_preserved": True,
               "independent_direct_score_checks_passed": True}
        results.append(row)
        print(json.dumps({"case": case["case_id"], "n": case["source_count"], "k": row["actual_signature_count"],
                          "T": row["legal_cache_trie_nodes_T"], "all_prefix_ms": wall}), flush=True)
    summary = {"status": "completed", "cases": len(results), "all_cases_retained": True,
               "all_independent_direct_score_checks_passed": True,
               "all_prefix_runtime_ms_range": [min(row["all_prefix_total_wall_ms"] for row in results),
                                                max(row["all_prefix_total_wall_ms"] for row in results)],
               "max_sources": max(row["source_count"] for row in results),
               "max_actual_k": max(row["actual_signature_count"] for row in results),
               "current_source_payloads_all_preserved": True,
               "worst_case_k_equals_n_is_still_exponential": True,
               "scalability_is_conditional_on_small_forecast_signature_count": True,
               "real_supplier_fee_or_QA_advantage_measured": False,
               "results": results}
    save(output / "summary.json", summary)
    print(json.dumps({"status": "completed", "cases": len(results),
                      "runtime_ms_range": summary["all_prefix_runtime_ms_range"]}), flush=True)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "quotient_benchmark_v1")
    run(parser.parse_args().output)
