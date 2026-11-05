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
import math
from pathlib import Path
import random
import statistics
import time

try:
    from .planner import METHODS, plan_layout, _forecast
except ImportError:
    from planner import METHODS, plan_layout, _forecast


SEED = 2026110501
REGIMES = ("coordinated", "independent", "ood")
WARM_MODES = ("partial", "full")
THRESHOLDS = (0.0, .1, .25, .5, .75, 1.0)
SHUFFLE_ARM = "causal_two_step_shuffled_history"
ARMS = ("original", "risk", "risk_length_ratio", "static_joint_dp", "cache_greedy",
        "full_hot_else_static", "conditional_static", "cache_greedy_risk_cut",
        "causal_two_step", SHUFFLE_ARM)
FORECAST_COMPARISON_METHODS = ("cache_greedy_forecast_tail", "cache_greedy_risk_cut",
                               "conditional_static", "causal_two_step")
V2_ARMS = ARMS + ("conditional_state__cache_greedy_forecast_tail",) + tuple(
    model + "__" + method for model in ("joint_delta", "independent_status_marginal")
    for method in FORECAST_COMPARISON_METHODS)
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


def make_cases(replicates=8, train_steps=128, test_steps=16, seed_root=SEED):
    result = []
    for regime_index, regime in enumerate(REGIMES):
        for replicate in range(replicates):
            seed = seed_root + regime_index * 100000 + replicate * 1009
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
    model = "conditional_state"
    if "__" in arm:
        model, method = arm.split("__", 1)
    else:
        method = "causal_two_step" if arm == SHUFFLE_ARM else arm
    planner_history = (_shuffled_history(history, case["seed"] + 700009)
                       if arm == SHUFFLE_ARM else history)
    for tick, allowed in enumerate(states):
        # No next state is accessed here or passed to the planner. Only current
        # legal bodies, frozen training and already-dispatched orders are inputs.
        decision = plan_layout([materials[sid] for sid in sorted(allowed)], planner_history,
                               actual_orders, {
                                   "method": method,
                                   "forecast_model": model,
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


def _summary_table(results, arms=ARMS):
    table = {}
    for arm in arms:
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
    simple = tuple(method for method in ARMS if method in METHODS and method != "causal_two_step")
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


def forecast_loss_audit(cases):
    """Score predictions before revealing the next development state to scorer.

    Multiclass joint Brier and mean source-presence Brier are proper scoring
    rules. Clipped joint log loss also reports zero-support counts explicitly.
    These are synthetic development predictions, not a new held-out test.
    """
    totals = defaultdict(lambda: defaultdict(float))
    for case in cases:
        history = [(frozenset(row["before"]), frozenset(row["after"]), "null")
                   for row in case["training_transitions"]]
        states = case["test_states"]
        for tick in range(len(states) - 1):
            current = states[tick]
            for model in ("conditional_state", "joint_delta", "independent_status_marginal"):
                predicted, diagnostic = _forecast(current, history, case["lengths"],
                                                  {"forecast_model": model}, 2)
                # Actual next is used ONLY by this scorer, after prediction.
                actual = frozenset(states[tick + 1])
                mass = dict(predicted)
                p_actual = mass.get(actual, 0.0)
                source_brier = sum((sum(probability for state, probability in predicted if sid in state)
                                    - int(sid in actual)) ** 2 for sid in case["lengths"]) / 8
                for group in ("all", case["regime"]):
                    bucket = totals[(group, model)]
                    bucket["predictions"] += 1
                    bucket["joint_brier_sum"] += 1 - 2 * p_actual + sum(p * p for p in mass.values())
                    bucket["source_brier_sum"] += source_brier
                    bucket["clipped_joint_logloss_sum"] += -math.log(max(1e-12, p_actual))
                    bucket["actual_state_zero_support_count"] += int(not p_actual)
                    bucket["fallback_count"] += int(diagnostic["fallback"])
    return {group: {model: {
        "predictions": int(totals[(group, model)]["predictions"]),
        "joint_brier": totals[(group, model)]["joint_brier_sum"] / totals[(group, model)]["predictions"],
        "source_presence_brier": totals[(group, model)]["source_brier_sum"] / totals[(group, model)]["predictions"],
        "clipped_joint_logloss": totals[(group, model)]["clipped_joint_logloss_sum"] / totals[(group, model)]["predictions"],
        "joint_logloss_probability_floor": 1e-12,
        "actual_state_zero_support_count": int(totals[(group, model)]["actual_state_zero_support_count"]),
        "fallback_count": int(totals[(group, model)]["fallback_count"]),
    } for model in ("conditional_state", "joint_delta", "independent_status_marginal")}
            for group in ("all",) + REGIMES}


def run_v2(output):
    started = time.time()
    old = HERE / "offline_screen_v1"
    cases = json.loads((old / "frozen_traces.json").read_bytes())
    threshold = json.loads((old / "training_only_risk_cut_tuning.json").read_bytes())["selected_threshold"]
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    # A different, fixed seed root reserves 16 NEW clusters. They are persisted
    # and hashed, but never evaluated by this development-only function.
    prospective = make_cases(6, 128, 16, seed_root=SEED + 5000019)
    limits = {"coordinated": 6, "independent": 5, "ood": 5}
    reserved = [case for case in prospective if case["replicate"] < limits[case["regime"]]]
    for case in reserved:
        case["case_id"] = "reserved-v2-" + case["case_id"]
    contract = {
        "schema": "revocation-prefix-joint-delta-development-v2",
        "development_status": "all_24_old_v1_seed_clusters_reused_for_development_NOT_HELDOUT",
        "development_clusters": len(cases), "arms": list(V2_ARMS),
        "forecast_operator": "xor(before,after), empirical_joint_distribution_applied_to_current",
        "forecast_operator_changes_only_prediction_not_two_step_objective_or_candidate_pool": True,
        "history_update_policy": "frozen_training_only",
        "risk_cut_threshold_frozen_from_v1_training": threshold,
        "risk_cut_retuned_on_development_or_reserved_test": False,
        "same_predictor_comparisons": list(FORECAST_COMPARISON_METHODS),
        "source_payloads": "all_current_legal_raw_sources_only",
        "metric": "lifecycle_ideal_source_UTF8_prefix_MISS_bytes_including_actual_simulated_priming",
        "reserved_clusters": len(reserved), "reserved_new_seed_root": SEED + 5000019,
        "reserved_cluster_counts": limits, "reserved_evaluated": False,
        "reserved_condition": "lock_candidate_after_development_before_any_reserved_evaluation",
        "development_traces_sha256": hashlib.sha256(encoded(cases)).hexdigest(),
        "reserved_traces_sha256": hashlib.sha256(encoded(reserved)).hexdigest(),
        "model_calls": 0,
        "code_manifest_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                 for name in ("planner.py", "test_planner.py", "offline_screen.py")},
    }
    save(output / "frozen_contract.json", contract)
    save(output / "development_traces.json", cases)
    save(output / "reserved_16_clusters_NOT_EVALUATED.json", reserved)
    loss = forecast_loss_audit(cases)
    save(output / "forecast_loss_development.json", loss)
    print(json.dumps({"stage": "v2_forecast_audit_complete_reserved_untouched", "development_clusters": len(cases),
                      "reserved_clusters": len(reserved), "arms": len(V2_ARMS)}, ensure_ascii=False), flush=True)
    results = []
    for index, case in enumerate(cases):
        for warm in WARM_MODES:
            for arm in V2_ARMS:
                result = rollout(case, case["test_states"], case["training_transitions"], warm,
                                 arm, threshold, rows=True)
                results.append(result)
                save(output / "trajectories" / f"{case['case_id']}-{warm}-{arm}.json", result)
        print(json.dumps({"stage": "v2_development_cluster_complete", "cluster": case["case_id"],
                          "completed": index + 1, "total": len(cases)}, ensure_ascii=False), flush=True)
    table = _summary_table(results, V2_ARMS)
    candidate = "joint_delta__causal_two_step"
    simple = [arm for arm in V2_ARMS if "causal_two_step" not in arm]
    best = min(simple, key=lambda arm: (table[arm]["lifecycle_miss_bytes"], arm))
    same_predictor = ["joint_delta__" + method for method in FORECAST_COMPARISON_METHODS if method != "causal_two_step"]
    best_same = min(same_predictor, key=lambda arm: (table[arm]["lifecycle_miss_bytes"], arm))
    by_regime = {}
    for regime in REGIMES:
        subtable = _summary_table([row for row in results if row["regime"] == regime], V2_ARMS)
        strongest = min(simple, key=lambda arm: (subtable[arm]["lifecycle_miss_bytes"], arm))
        by_regime[regime] = {"arms": subtable, "best_simple_arm_posthoc": strongest,
                             "candidate_saving_vs_best_simple": _saving(subtable[candidate]["lifecycle_miss_bytes"],
                                                                          subtable[strongest]["lifecycle_miss_bytes"])}
    summary = {
        "status": "completed", "development_only": True, "reserved_evaluated": False,
        "candidate_arm": candidate, "all_arms": table, "forecast_loss": loss,
        "best_simple_arm_posthoc_diagnostic": best,
        "candidate_saving_vs_best_simple": _saving(table[candidate]["lifecycle_miss_bytes"], table[best]["lifecycle_miss_bytes"]),
        "best_same_predictor_simple_arm": best_same,
        "candidate_saving_vs_same_predictor_simple": _saving(table[candidate]["lifecycle_miss_bytes"], table[best_same]["lifecycle_miss_bytes"]),
        "candidate_saving_vs_old_d2": _saving(table[candidate]["lifecycle_miss_bytes"], table["causal_two_step"]["lifecycle_miss_bytes"]),
        "candidate_saving_vs_independent_predictor_ablation": _saving(table[candidate]["lifecycle_miss_bytes"], table["independent_status_marginal__causal_two_step"]["lifecycle_miss_bytes"]),
        "by_regime": by_regime, "risk_cut_frozen_threshold": threshold,
        "elapsed_seconds": time.time() - started,
        "new_algorithm_advantage_established": False,
        "source_semantic_quality_or_supplier_fee_measured": False,
    }
    save(output / "summary.json", summary)
    save(output / "all_trajectory_totals.json", [{key: value for key, value in row.items() if key != "rows"} for row in results])
    print(json.dumps({"status": "v2_development_completed", "best_simple": best,
                      "candidate_saving": summary["candidate_saving_vs_best_simple"],
                      "same_predictor_saving": summary["candidate_saving_vs_same_predictor_simple"],
                      "reserved_evaluated": False}, ensure_ascii=False), flush=True)
    return summary


def _paired_reserved_interval(results, candidate, baseline):
    clusters = defaultdict(lambda: {"candidate": 0, "baseline": 0, "regime": None})
    trajectory_counts = Counter()
    pair = defaultdict(dict)
    for row in results:
        if row["arm"] in {candidate, baseline}:
            pair[(row["case_id"], row["warm_mode"])][row["arm"]] = row
    for (case_id, _), arms in pair.items():
        a = arms[candidate]["lifecycle_ideal_prefix_miss_bytes"]
        b = arms[baseline]["lifecycle_ideal_prefix_miss_bytes"]
        clusters[case_id]["candidate"] += a
        clusters[case_id]["baseline"] += b
        clusters[case_id]["regime"] = arms[candidate]["regime"]
        trajectory_counts["win" if a < b else "loss" if a > b else "tie"] += 1
    grouped = {regime: [row for row in clusters.values() if row["regime"] == regime] for regime in REGIMES}
    rng = random.Random(SEED + 1900013)
    saving_samples, delta_samples = [], []
    for _ in range(10000):
        sample = [rng.choice(values) for values in grouped.values() for _ in values]
        a = sum(row["candidate"] for row in sample)
        b = sum(row["baseline"] for row in sample)
        saving_samples.append(_saving(a, b))
        delta_samples.append(b - a)
    saving_samples.sort()
    delta_samples.sort()
    cluster_counts = Counter("win" if row["candidate"] < row["baseline"] else
                             "loss" if row["candidate"] > row["baseline"] else "tie"
                             for row in clusters.values())
    a, b = sum(row["candidate"] for row in clusters.values()), sum(row["baseline"] for row in clusters.values())
    return {"candidate_arm": candidate, "baseline_arm_frozen_in_development": baseline,
            "candidate_lifecycle_miss_bytes": a, "baseline_lifecycle_miss_bytes": b,
            "baseline_minus_candidate_bytes": b - a, "candidate_relative_saving": _saving(a, b),
            "stratified_cluster_bootstrap_relative_saving_95pct": [saving_samples[249], saving_samples[9749]],
            "stratified_cluster_bootstrap_byte_delta_95pct": [delta_samples[249], delta_samples[9749]],
            "bootstrap_replicates": 10000, "cluster_count": len(clusters),
            "warm_modes_are_paired_inside_each_cluster": True,
            "cluster_win_tie_loss": dict(cluster_counts), "trajectory_win_tie_loss": dict(trajectory_counts),
            "case_cluster_pairs": dict(clusters)}


def run_reserved_v2(output):
    """One locked evaluation of all 16 reserved clusters; no policy selection."""
    started = time.time()
    development = HERE / "offline_screen_v2"
    development_contract = json.loads((development / "frozen_contract.json").read_bytes())
    development_summary = json.loads((development / "summary.json").read_bytes())
    cases = json.loads((development / "reserved_16_clusters_NOT_EVALUATED.json").read_bytes())
    if len(cases) != 16 or hashlib.sha256(encoded(cases)).hexdigest() != development_contract["reserved_traces_sha256"]:
        raise ValueError("reserved_trace_count_or_hash_changed")
    for name in ("planner.py", "test_planner.py"):
        if hashlib.sha256((HERE / name).read_bytes()).hexdigest() != development_contract["code_manifest_sha256"][name]:
            raise ValueError("locked_algorithm_or_mechanism_tests_changed")
    candidate = "joint_delta__causal_two_step"
    frozen_best = "independent_status_marginal__cache_greedy_forecast_tail"
    same_joint = "joint_delta__cache_greedy_forecast_tail"
    if development_summary["best_simple_arm_posthoc_diagnostic"] != frozen_best:
        raise ValueError("unexpected_development_baseline_do_not_reselect_on_reserved")
    threshold = .75
    if development_contract["risk_cut_threshold_frozen_from_v1_training"] != threshold:
        raise ValueError("locked_threshold_changed")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    contract = {
        "schema": "revocation-prefix-joint-delta-reserved-v2",
        "candidate_locked_before_reserved": {"method": "causal_two_step", "forecast_model": "joint_delta",
                                            "next_cost_weight": 1.0, "risk_cut_threshold": threshold,
                                            "max_candidates": 192, "min_conditional_samples": 2},
        "primary_baselines_frozen_from_development": [frozen_best, same_joint],
        "all_arms": list(V2_ARMS), "all_16_reserved_clusters_evaluated_no_selection": True,
        "regime_counts": dict(Counter(case["regime"] for case in cases)),
        "reserved_trace_sha256": development_contract["reserved_traces_sha256"],
        "algorithm_code_manifest": {name: development_contract["code_manifest_sha256"][name]
                                    for name in ("planner.py", "test_planner.py")},
        "development_code_snapshot": "snapshots/locked_joint_delta_v2",
        "validation_driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "history_update_policy": "frozen_training_only",
        "heldout_tuning_or_threshold_selection": False,
        "metric": "ideal_source_UTF8_prefix_MISS_bytes_including_priming",
        "model_calls": 0, "supplier_cost": None, "task_quality": None,
    }
    save(output / "frozen_contract.json", contract)
    save(output / "frozen_reserved_traces.json", cases)
    results = []
    for index, case in enumerate(cases):
        for warm in WARM_MODES:
            for arm in V2_ARMS:
                result = rollout(case, case["test_states"], case["training_transitions"], warm,
                                 arm, threshold, rows=True)
                results.append(result)
                save(output / "trajectories" / f"{case['case_id']}-{warm}-{arm}.json", result)
        print(json.dumps({"stage": "reserved_locked_cluster_complete", "case": case["case_id"],
                          "completed": index + 1, "total": len(cases)}, ensure_ascii=False), flush=True)
    table = _summary_table(results, V2_ARMS)
    primary = {baseline: _paired_reserved_interval(results, candidate, baseline)
               for baseline in (frozen_best, same_joint)}
    regime_tables = {regime: _summary_table([row for row in results if row["regime"] == regime], V2_ARMS)
                     for regime in REGIMES}
    summary = {
        "status": "completed", "candidate_locked": True, "reserved_clusters": len(cases),
        "candidate_arm": candidate, "primary_frozen_baseline_comparisons": primary,
        "all_arms": table, "by_regime_all_arms": regime_tables,
        "by_regime_frozen_baseline_savings": {
            regime: {baseline: _saving(subtable[candidate]["lifecycle_miss_bytes"], subtable[baseline]["lifecycle_miss_bytes"])
                     for baseline in (frozen_best, same_joint)} for regime, subtable in regime_tables.items()},
        "forecast_loss_reserved_after_lock": forecast_loss_audit(cases),
        "candidate_saving_vs_independent_predictor_ablation": _saving(table[candidate]["lifecycle_miss_bytes"],
                table["independent_status_marginal__causal_two_step"]["lifecycle_miss_bytes"]),
        "real_supplier_fees_hits_latency_quality_or_innovation_established": False,
        "elapsed_seconds": time.time() - started,
    }
    save(output / "summary.json", summary)
    save(output / "all_trajectory_totals.json", [{key: value for key, value in row.items() if key != "rows"} for row in results])
    print(json.dumps({"status": "reserved_completed", "primary_saving": primary[frozen_best]["candidate_relative_saving"],
                      "primary_ci": primary[frozen_best]["stratified_cluster_bootstrap_relative_saving_95pct"],
                      "same_joint_saving": primary[same_joint]["candidate_relative_saving"]}, ensure_ascii=False), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screen-version", choices=("v1", "v2", "v2_reserved"), default="v1")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--replicates", type=int, default=8)
    parser.add_argument("--train-steps", type=int, default=128)
    parser.add_argument("--test-steps", type=int, default=16)
    args = parser.parse_args()
    if args.replicates < 1 or args.train_steps < 24 or args.test_steps < 2:
        parser.error("replicates >= 1, train-steps >= 24 and test-steps >= 2 required")
    destination = args.output or HERE / ("offline_screen_" + args.screen_version)
    if args.screen_version == "v2_reserved":
        run_reserved_v2(destination)
    elif args.screen_version == "v2":
        run_v2(destination)
    else:
        run(destination, args.replicates, args.train_steps, args.test_steps)


if __name__ == "__main__":
    main()
