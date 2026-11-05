"""Frozen-seed synthetic Markov screen, using an ideal byte-prefix ledger.

Run from the repository root:
  python -B -X utf8 -m experiments.revocation_prefix_v1.offline_screen

This generates JSON artifacts, not a paper or a provider-cost result. Source
texts are explicit synthetic length fixtures, never a capacity/budget trick.
Every arm receives every currently allowed source. Histories are independent
training traces; the planner never receives the reserved test continuation.
All priming is charged. No model, credential, network or supplier cache is used.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import random
import statistics
import time

try:
    from .planner import METHODS, plan_layout
except ImportError:
    from planner import METHODS, plan_layout


SEED = 2026110501
REGIMES = ("coordinated", "independent", "ood")
WARM_MODES = ("partial", "full")
THRESHOLDS = (0.0, .1, .25, .5, .75, 1.0)
SHUFFLE_ARM = "causal_two_step_shuffled_history"
ARMS = METHODS + (SHUFFLE_ARM,)
HERE = Path(__file__).resolve().parent


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(encoded(value))


def _step(state, rng, parameters, kind):
    state = set(state)
    if kind == "ood" and rng.random() < .55:
        kind = "independent"
    if kind == "independent":
        for sid in parameters["ids"]:
            probability = parameters["leave"][sid] if sid in state else parameters["enter"][sid]
            if rng.random() < probability:
                state.symmetric_difference_update({sid})
        return sorted(state)
    draw = rng.random()
    groups = parameters["shift_groups"] if kind == "ood" else parameters["groups"]
    if draw < .22:
        return sorted(state)
    if draw < .78:
        state.symmetric_difference_update(rng.choice(groups))
    elif draw < .93:
        chosen = rng.sample(groups, 2)
        state.symmetric_difference_update(set(chosen[0]) | set(chosen[1]))
    else:
        state.symmetric_difference_update({rng.choice(parameters["ids"])})
    return sorted(state)


def _states(seed, parameters, kind, count, burn):
    rng = random.Random(seed)
    state = list(parameters["ids"])
    for _ in range(burn):
        state = _step(state, rng, parameters, kind)
    result = [state]
    for _ in range(count - 1):
        state = _step(state, rng, parameters, kind)
        result.append(state)
    return result


def _transitions(states):
    return [{"before": before, "after": after} for before, after in zip(states, states[1:])]


def make_cases(replicates=8, train_steps=128, test_steps=16):
    result = []
    for regime_index, regime in enumerate(REGIMES):
        for replicate in range(replicates):
            seed = SEED + regime_index * 100000 + replicate * 1009
            rng = random.Random(seed)
            ids = [f"S{i + 1:02d}" for i in range(8)]
            permutation = rng.sample(ids, len(ids))
            lengths = rng.sample([320, 640, 1280, 2560, 384, 768, 1536, 3072], 8)
            multiplier = (1, 2, 4)[replicate % 3]
            lengths = {sid: length * multiplier for sid, length in zip(ids, lengths)}
            leave = rng.sample([.06, .12, .22, .4, .05, .17, .3, .55], 8)
            enter = rng.sample([.35, .3, .2, .12, .5, .25, .18, .08], 8)
            shifted = permutation[1:] + permutation[:1]
            parameters = {
                "ids": ids,
                "groups": [permutation[i:i + 2] for i in range(0, 8, 2)],
                "shift_groups": [shifted[i:i + 2] for i in range(0, 8, 2)],
                "leave": dict(zip(ids, leave)), "enter": dict(zip(ids, enter)),
            }
            train_kind = "coordinated" if regime == "ood" else regime
            train = _states(seed + 100003, parameters, train_kind, train_steps + 1, 32)
            test = _states(seed + 900007, parameters, regime, test_steps, 17)
            result.append({
                "case_id": f"{regime}-{replicate:02d}", "regime": regime,
                "replicate": replicate, "seed": seed, "lengths": lengths,
                "parameters": parameters, "train_kind": train_kind,
                "training_states": train, "training_transitions": _transitions(train),
                "test_states": test,
            })
    return result


def catalog(case):
    # Distinct bytes prevent accidental partial matches between different blocks;
    # the ledger intentionally measures WHOLE source-block prefixes only.
    return {sid: {"source_id": sid, "text": chr(65 + index) * nbytes}
            for index, (sid, nbytes) in enumerate(sorted(case["lengths"].items()))}


def prime_order(case, current, warm):
    rng = random.Random(case["seed"] + (300001 if warm == "partial" else 400003))
    order = rng.sample(sorted(current), len(current))
    if warm == "partial" and len(order) > 1:
        return order[:rng.randrange(1, len(order))]
    return order


def ledger_miss(order, earlier_actual_orders, lengths):
    """Independent adjudicator; receives actual test order only AFTER planning."""
    best = 0
    for earlier in earlier_actual_orders:
        matched = 0
        for index, sid in enumerate(order):
            if index >= len(earlier) or earlier[index] != sid:
                break
            matched += lengths[sid]
        best = max(best, matched)
    return sum(lengths[sid] for sid in order) - best


def _shuffled_history(history, seed):
    # Keeps the complete multiset of after labels (and its marginal prevalence),
    # breaks their pairing with before labels. Removal marginals need not remain
    # unchanged, which is explicitly reported rather than mislabelled.
    after = [row["after"] for row in history]
    random.Random(seed).shuffle(after)
    return [{"before": row["before"], "after": replacement} for row, replacement in zip(history, after)]


def rollout(case, states, history, warm, arm, threshold, *, rows=False):
    materials, lengths = catalog(case), case["lengths"]
    prime = prime_order(case, states[0], warm)
    actual_orders = [prime] if prime else []
    initial_bytes = sum(lengths[sid] for sid in prime)
    total_miss, total_raw = initial_bytes, initial_bytes
    output_rows, planning, counts = [], [], Counter()
    method = "causal_two_step" if arm == SHUFFLE_ARM else arm
    planner_history = (_shuffled_history(history, case["seed"] + 700009)
                       if arm == SHUFFLE_ARM else history)
    for tick, allowed in enumerate(states):
        # No next state is accessed here or passed to the planner. Only current
        # legal bodies, frozen training and already-dispatched orders are inputs.
        decision = plan_layout([materials[sid] for sid in sorted(allowed)], planner_history,
                               actual_orders, {
                                   "method": method,
                                   "known_source_lengths_bytes": lengths,
                                   "risk_cut_threshold": threshold,
                                   "min_conditional_samples": 2,
                                   "max_candidates": 192,
                               })
        order = decision["ordered_source_ids"]
        if len(order) != len(allowed) or set(order) != set(allowed):
            raise AssertionError("planner_failed_exact_current_legal_source_set")
        # This is the first use of the newly chosen test action by the ledger.
        miss = ledger_miss(order, actual_orders, lengths)
        if miss != decision["predicted_now_miss_bytes"]:
            raise AssertionError("current_proxy_prediction_disagrees_with_independent_ledger")
        raw = sum(lengths[sid] for sid in allowed)
        total_miss += miss
        total_raw += raw
        planning.append(decision["planning_ms"])
        detail = decision["details"]
        counts["fallback"] += int(detail["forecast_confidence"]["fallback"])
        counts["full_hot"] += int(detail["full_current_view_is_hot_under_proxy"])
        counts["candidate_count_sum"] += detail["candidate_count"]
        counts["candidate_limit_reached"] += int(detail["candidate_count"] >= detail["candidate_limit"])
        counts["conditional_sample_sum"] += detail["forecast_confidence"]["conditional_state_samples"]
        if rows:
            output_rows.append({
                "tick": tick, "allowed_source_ids": list(allowed),
                "ordered_source_ids": order, "raw_source_bytes": raw,
                "actual_ideal_prefix_miss_bytes": miss,
                "predicted_now_miss_bytes": decision["predicted_now_miss_bytes"],
                "predicted_next_miss_bytes": decision["predicted_next_miss_bytes"],
                "forecast_confidence": detail["forecast_confidence"],
                "candidate_count": detail["candidate_count"],
                "selected_candidate_origin": detail["selected_candidate_origin"],
                "planning_ms": decision["planning_ms"],
            })
        # The observation is appended only after the simulated actual dispatch.
        actual_orders.append(order)
    return {
        "case_id": case["case_id"], "regime": case["regime"], "warm_mode": warm,
        "arm": arm, "ticks": len(states), "prime_actual_order": prime,
        "prime_miss_bytes_charged": initial_bytes,
        "lifecycle_source_raw_bytes": total_raw,
        "lifecycle_ideal_prefix_miss_bytes": total_miss,
        "lifecycle_ideal_prefix_read_bytes": total_raw - total_miss,
        "planning_ms_total": sum(planning), "planning_ms_mean": statistics.mean(planning),
        "counters": dict(counts), "rows": output_rows,
    }


def tune_risk_cut(cases):
    # Last 12 TRAINING transitions are development. Reserved test traces are not
    # referenced in this function; one global threshold is frozen for every arm.
    scores = {threshold: 0 for threshold in THRESHOLDS}
    for case in cases:
        training = case["training_states"]
        development = training[-13:]
        earlier_history = _transitions(training[:-12])
        for warm in WARM_MODES:
            for threshold in THRESHOLDS:
                result = rollout(case, development, earlier_history, warm,
                                 "cache_greedy_risk_cut", threshold)
                scores[threshold] += result["lifecycle_ideal_prefix_miss_bytes"]
    selected = min(THRESHOLDS, key=lambda threshold: (scores[threshold], threshold))
    return {
        "development_from": "last_12_training_transitions_only",
        "reserved_test_used": False, "one_global_threshold_for_all_regimes_and_warm_modes": True,
        "candidate_thresholds": list(THRESHOLDS),
        "development_lifecycle_miss_bytes": {str(key): value for key, value in scores.items()},
        "selected_threshold": selected,
    }


def _saving(candidate, baseline):
    return (baseline - candidate) / baseline if baseline else 0.0


def _summary_table(results):
    table = {}
    for arm in ARMS:
        selected = [row for row in results if row["arm"] == arm]
        table[arm] = {
            "lifecycle_miss_bytes": sum(row["lifecycle_ideal_prefix_miss_bytes"] for row in selected),
            "lifecycle_read_bytes": sum(row["lifecycle_ideal_prefix_read_bytes"] for row in selected),
            "lifecycle_raw_bytes": sum(row["lifecycle_source_raw_bytes"] for row in selected),
            "prime_miss_bytes": sum(row["prime_miss_bytes_charged"] for row in selected),
            "planning_ms_total": sum(row["planning_ms_total"] for row in selected),
            "fallback_calls": sum(row["counters"].get("fallback", 0) for row in selected),
            "planned_calls": sum(row["ticks"] for row in selected),
        }
    return table


def summarize(results):
    simple = tuple(method for method in METHODS if method != "causal_two_step")
    all_table = _summary_table(results)
    best = min(simple, key=lambda arm: (all_table[arm]["lifecycle_miss_bytes"], arm))
    candidate_total = all_table["causal_two_step"]["lifecycle_miss_bytes"]
    baseline_total = all_table[best]["lifecycle_miss_bytes"]
    by_regime, by_warm, by_cell = {}, {}, {}
    for regime in REGIMES:
        table = _summary_table([row for row in results if row["regime"] == regime])
        strongest = min(simple, key=lambda arm: (table[arm]["lifecycle_miss_bytes"], arm))
        by_regime[regime] = {"arms": table, "best_simple_arm_posthoc_diagnostic": strongest,
                             "candidate_saving_vs_best_simple": _saving(table["causal_two_step"]["lifecycle_miss_bytes"],
                                                                          table[strongest]["lifecycle_miss_bytes"])}
        for warm in WARM_MODES:
            by_cell[regime + "/" + warm] = _summary_table([row for row in results if row["regime"] == regime and row["warm_mode"] == warm])
    for warm in WARM_MODES:
        by_warm[warm] = _summary_table([row for row in results if row["warm_mode"] == warm])
    paired = defaultdict(dict)
    for row in results:
        key = (row["case_id"], row["warm_mode"])
        paired[key][row["arm"]] = row
    counts, equal_layouts = Counter(), Counter()
    cluster = defaultdict(lambda: [0, 0])
    oracle_simple = 0
    for (case_id, _), arms in paired.items():
        a = arms["causal_two_step"]["lifecycle_ideal_prefix_miss_bytes"]
        b = arms[best]["lifecycle_ideal_prefix_miss_bytes"]
        counts["win" if a < b else "loss" if a > b else "tie"] += 1
        cluster[case_id][0] += a
        cluster[case_id][1] += b
        oracle_simple += min(arms[arm]["lifecycle_ideal_prefix_miss_bytes"] for arm in simple)
        for arm in simple + (SHUFFLE_ARM,):
            equal_layouts[arm] += sum(a["ordered_source_ids"] == b["ordered_source_ids"]
                                     for a, b in zip(arms["causal_two_step"]["rows"], arms[arm]["rows"]))
    values = list(cluster.values())
    rng = random.Random(SEED + 800011)
    bootstrap = []
    for _ in range(1000):
        sample = [rng.choice(values) for _ in values]
        bootstrap.append(_saving(sum(v[0] for v in sample), sum(v[1] for v in sample)))
    bootstrap.sort()
    total_calls = all_table["causal_two_step"]["planned_calls"]
    savings = _saving(candidate_total, baseline_total)
    return {
        "measurement": "synthetic_source_UTF8_bytes_with_IDEAL_prefix_cache_only",
        "real_provider_hit_cost_latency_or_task_quality_measured": False,
        "all_arms": all_table,
        "best_fixed_simple_arm_posthoc_diagnostic": best,
        "posthoc_baseline_selection_is_not_a_deployable_policy": True,
        "candidate_saving_vs_best_fixed_simple": savings,
        "candidate_saving_vs_per_trajectory_oracle_simple_diagnostic": _saving(candidate_total, oracle_simple),
        "win_tie_loss_trajectories_vs_best_fixed_simple": dict(counts),
        "paired_bootstrap_cluster_count": len(values),
        "warm_modes_of_same_case_are_one_bootstrap_cluster": True,
        "descriptive_synthetic_cluster_bootstrap_95pct": [bootstrap[24], bootstrap[974]],
        "by_regime": by_regime, "by_warm_mode": by_warm, "by_regime_and_warm_mode": by_cell,
        "candidate_layout_equal_fraction": {arm: count / total_calls for arm, count in equal_layouts.items()},
        "candidate_saving_vs_shuffled_after_labels": _saving(candidate_total, all_table[SHUFFLE_ARM]["lifecycle_miss_bytes"]),
        "shuffle_preserves_after_label_marginals_not_removal_marginals": True,
        "twenty_percent_proxy_screen_pass": savings >= .2 and sum(cell["candidate_saving_vs_best_simple"] > 0 for cell in by_regime.values()) >= 2,
        "verdict": ("proxy_headroom_only_requires_real_provider_and_quality_validation" if savings >= .2
                    else "no_twenty_percent_unique_proxy_advantage_over_strong_simple_baseline"),
        "mechanism_diagnostics": {
            "next_step_planner_assumes_best_legal_cached_prefix_but_future_policy_may_reorder_again": True,
            "full_state_hot_and_empty_views_are_retained_in_matrix": True,
            "all_source_length_and_event_seeds_frozen_no_test_tuning": True,
            "negative_ood_and_all_registered_arms_retained": True,
        },
    }


def run(output, replicates=8, train_steps=128, test_steps=16):
    started = time.time()
    cases = make_cases(replicates, train_steps, test_steps)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                for name in ("planner.py", "test_planner.py", "offline_screen.py")}
    contract = {
        "schema": "revocation-prefix-offline-screen-v1", "seed": SEED,
        "arms": list(ARMS), "regimes": list(REGIMES), "warm_modes": list(WARM_MODES),
        "replicates_per_regime": replicates, "train_transitions": train_steps, "test_ticks": test_steps,
        "source_count": 8, "source_length_values_before_scale": [320, 640, 1280, 2560, 384, 768, 1536, 3072],
        "source_length_scale_cycle": [1, 2, 4], "lengths_are_synthetic_fixtures": True,
        "byte_model": "sum_source_text_UTF8_excluding_wrappers",
        "cache_model": "unbounded_all_source_block_prefixes_of_actual_prior_dispatches_ideal_proxy",
        "priming_charged_in_full_lifecycle": True,
        "history_update_policy": "frozen_training_only_no_test_transition_updates",
        "test_trace_available_to_planner": False,
        "all_current_legal_raw_sources_in_every_arm": True,
        "risk_cut_tuning": "one_global_threshold_from_training_development_only",
        "shuffle": "fixed_seed_permutation_of_training_after_labels_across_before_labels",
        "screen_threshold": "20pct_lifecycle_proxy_MISS_vs_strongest_fixed_simple_and_positive_in_2_regimes",
        "model_calls": 0, "supplier_costs": None, "quality": None,
        "code_manifest_sha256": manifest,
        "traces_sha256": hashlib.sha256(encoded(cases)).hexdigest(),
    }
    save(output / "frozen_contract.json", contract)
    save(output / "frozen_traces.json", cases)
    tuning = tune_risk_cut(cases)
    save(output / "training_only_risk_cut_tuning.json", tuning)
    threshold = tuning["selected_threshold"]
    print(json.dumps({"stage": "threshold_frozen_before_reserved_test", "threshold": threshold,
                      "case_clusters": len(cases), "arms": len(ARMS)}, ensure_ascii=False), flush=True)
    results = []
    for index, case in enumerate(cases):
        for warm in WARM_MODES:
            for arm in ARMS:
                result = rollout(case, case["test_states"], case["training_transitions"], warm,
                                 arm, threshold, rows=True)
                results.append(result)
                save(output / "trajectories" / f"{case['case_id']}-{warm}-{arm}.json", result)
        print(json.dumps({"stage": "cluster_complete", "cluster": case["case_id"],
                          "completed": index + 1, "total": len(cases)}, ensure_ascii=False), flush=True)
    summary = summarize(results)
    summary["risk_cut_frozen_threshold"] = threshold
    summary["elapsed_seconds"] = time.time() - started
    summary["status"] = "completed"
    save(output / "summary.json", summary)
    save(output / "all_trajectory_totals.json", [{key: value for key, value in row.items() if key != "rows"} for row in results])
    print(json.dumps({"status": "completed", "output": str(output),
                      "best_simple": summary["best_fixed_simple_arm_posthoc_diagnostic"],
                      "candidate_saving": summary["candidate_saving_vs_best_fixed_simple"],
                      "verdict": summary["verdict"]}, ensure_ascii=False), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "offline_screen_v1")
    parser.add_argument("--replicates", type=int, default=8)
    parser.add_argument("--train-steps", type=int, default=128)
    parser.add_argument("--test-steps", type=int, default=16)
    args = parser.parse_args()
    if args.replicates < 1 or args.train_steps < 24 or args.test_steps < 2:
        parser.error("replicates >= 1, train-steps >= 24 and test-steps >= 2 required")
    run(args.output, args.replicates, args.train_steps, args.test_steps)


if __name__ == "__main__":
    main()
