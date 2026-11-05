"""Causal ordering of ALL currently lawful raw sources; no LLM or network.

Every byte count is a SOURCE-TEXT UTF-8 / ideal-prefix planning proxy. It excludes
headers, JSON escaping, system prompts and questions. An observed order means an
actual earlier dispatch, NOT proof that the provider persisted all its prefixes.
Callers must scope source IDs to immutable content versions, or discard stale
observations before calling. No old source body is accepted through the cache.

The static subset DP is exact only for its empirical retained-prefix objective,
at <= 12 sources. The two-step method searches a bounded candidate pool; it is
neither a globally optimal controller nor a supplier-cache/cost guarantee.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import time


METHODS = (
    "original", "risk", "risk_length_ratio", "static_joint_dp",
    "cache_greedy", "full_hot_else_static", "conditional_static", "cache_greedy_risk_cut", "causal_two_step",
)
_FORBIDDEN = frozenset({
    "future_events", "future_trace", "test_trace", "reserved_trace", "events",
    "answers", "questions", "evaluation", "reference_answers", "future_states",
})
_CONFIG = frozenset({
    "method", "context", "min_conditional_samples", "next_cost_weight",
    "max_candidates", "max_observed_orders", "known_source_lengths_bytes",
    "risk_cut_threshold",
})


def _no_future(value):
    if isinstance(value, dict):
        if _FORBIDDEN.intersection(value):
            raise ValueError("future_or_evaluation_data_not_allowed")
        for child in value.values():
            _no_future(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _no_future(child)


def _ids(value, name):
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(name + "_must_be_source_id_collection")
    result = tuple(value)
    if any(not isinstance(sid, str) or not sid for sid in result) or len(result) != len(set(result)):
        raise ValueError(name + "_invalid_or_duplicate_source_id")
    return result


def _positive_int(value, name, maximum=None):
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise ValueError("invalid_" + name)
    return value


def _prepare(allowed_sources, historical_transitions, observed_cache_orders, config):
    if not isinstance(allowed_sources, (list, tuple)):
        raise ValueError("allowed_sources_must_be_sequence")
    records, original, lengths, hashes = {}, [], {}, {}
    for source in allowed_sources:
        if not isinstance(source, dict):
            raise ValueError("source_object_required")
        sid, body = source.get("source_id"), source.get("text")
        if not isinstance(sid, str) or not sid or sid in records:
            raise ValueError("invalid_or_duplicate_source_id")
        if not isinstance(body, str) or not body:
            raise ValueError("nonempty_source_text_required")
        if source.get("allow", True) is not True or source.get("allowed", True) is not True:
            raise ValueError("forbidden_source_received")
        raw = body.encode("utf-8")
        records[sid] = source
        original.append(sid)
        lengths[sid] = len(raw)
        hashes[sid] = hashlib.sha256(raw).hexdigest()
    if len(original) > 12:
        raise ValueError("exact_planner_supports_at_most_12_current_sources")
    cfg = dict(config or {})
    _no_future(cfg)
    if set(cfg) - _CONFIG:
        raise ValueError("unknown_config_key")
    method = cfg.get("method", "causal_two_step")
    if method not in METHODS:
        raise ValueError("unknown_method")
    minimum = _positive_int(cfg.get("min_conditional_samples", 2), "min_conditional_samples")
    cap = _positive_int(cfg.get("max_candidates", 192), "max_candidates", 2048)
    if cap < len(METHODS):
        raise ValueError("candidate_cap_must_preserve_all_baselines")
    cache_cap = _positive_int(cfg.get("max_observed_orders", 128), "max_observed_orders", 4096)
    weight = cfg.get("next_cost_weight", 1.0)
    if isinstance(weight, bool) or not isinstance(weight, (float, int)) or not math.isfinite(weight) or weight < 0:
        raise ValueError("invalid_next_cost_weight")
    threshold = cfg.get("risk_cut_threshold", .5)
    if isinstance(threshold, bool) or not isinstance(threshold, (float, int)) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("invalid_risk_cut_threshold")
    known = cfg.get("known_source_lengths_bytes", {})
    if not isinstance(known, dict):
        raise ValueError("known_source_lengths_bytes_must_be_metadata_mapping")
    for sid, nbytes in known.items():
        if not isinstance(sid, str) or not sid or type(nbytes) is not int or nbytes < 1:
            raise ValueError("invalid_known_source_length")
        if sid in lengths and nbytes != lengths[sid]:
            raise ValueError("current_source_length_metadata_mismatch")
    known_lengths = {**known, **lengths}
    if len(known_lengths) > 12:
        raise ValueError("marginal_forecast_supports_at_most_12_known_sources")
    if not isinstance(historical_transitions, (list, tuple)):
        raise ValueError("historical_transitions_must_be_sequence")
    history = []
    for row in historical_transitions:
        if not isinstance(row, dict):
            raise ValueError("transition_object_required")
        _no_future(row)
        if not {"before", "after"} <= row.keys() or set(row) - {"before", "after", "context"}:
            raise ValueError("transition_requires_only_before_after_optional_context")
        before, after = frozenset(_ids(row["before"], "before")), frozenset(_ids(row["after"], "after"))
        # Context is observable metadata, not free-form planner instructions.
        try:
            context = json.dumps(row.get("context"), sort_keys=True, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError):
            raise ValueError("context_must_be_finite_json_metadata") from None
        history.append((before, after, context))
    if not isinstance(observed_cache_orders, (list, tuple)):
        raise ValueError("observed_cache_orders_must_be_sequence")
    cache = [tuple(_ids(order, "observed_order")) for order in observed_cache_orders]
    # An unknown future source is an omitted constant ONLY if it is absent from
    # every cached order. Otherwise its unknown bytes may change which hot
    # prefix wins, and consequently reverse the layout decision. Fail closed;
    # callers can supply trusted historical LENGTH metadata without old bodies.
    cached_ids = set().union(*(set(order) for order in cache)) if cache else set()
    if cached_ids - known_lengths.keys():
        raise ValueError("observed_cache_source_length_metadata_required")
    omitted = max(0, len(cache) - cache_cap)
    # Most recent actual dispatches only; dropping old observations is explicit.
    cache = list(dict.fromkeys(cache[-cache_cap:]))
    return original, lengths, hashes, known_lengths, history, cache, cfg, minimum, cap, float(weight), omitted


def _compress(states):
    mass = Counter()
    for state, probability in states:
        if probability > 0:
            mass[frozenset(state)] += probability
    total = sum(mass.values())
    if not total:
        return [(frozenset(), 1.0)]
    return [(state, probability / total) for state, probability in sorted(mass.items(), key=lambda item: tuple(sorted(item[0])))]


def _forecast(current, history, known_lengths, cfg, minimum):
    current = frozenset(current)
    context_key = json.dumps(cfg.get("context"), sort_keys=True, ensure_ascii=False, allow_nan=False)
    conditional = [after for before, after, context in history
                   if before == current and ("context" not in cfg or context == context_key)]
    unknown = sorted(set().union(*(after for _, after, _ in history)) - known_lengths.keys()) if history else []
    diagnostics = {
        "historical_transition_samples": len(history),
        "conditional_state_samples": len(conditional),
        "minimum_conditional_samples": minimum,
        "unknown_next_length_ids": unknown,
        "unknown_next_lengths_are_omitted_not_guessed": True,
    }
    if len(conditional) >= minimum:
        diagnostics.update(forecast="empirical_exact_before_state", fallback=False,
                           marginal_observation_counts={})
        return _compress((state, 1.0) for state in conditional), diagnostics
    # Independent marginal fallback: condition each source on its CURRENT
    # present/absent status, using earlier transition opportunities only.
    # No evidence => persist current state; this avoids invented future churn.
    universe = sorted(known_lengths)
    states = [(frozenset(), 1.0)]
    counts = {}
    for sid in universe:
        opportunities = [after for before, after, _ in history if (sid in before) == (sid in current)]
        counts[sid] = len(opportunities)
        probability = (sum(sid in after for after in opportunities) / len(opportunities)
                       if opportunities else float(sid in current))
        expanded = []
        for state, mass in states:
            if probability < 1:
                expanded.append((state, mass * (1 - probability)))
            if probability > 0:
                expanded.append((state | {sid}, mass * probability))
        states = expanded
    diagnostics.update(forecast="independent_status_conditioned_marginals" if history else "no_history_persist_current",
                       fallback=True, marginal_observation_counts=counts)
    return _compress(states), diagnostics


def _suffix_policy(ids, lengths, states):
    """Exact fixed-order retained-prefix DP for every fixed prefix SET.

    A prefix's order changes its already-earned reward, but not its optimal tail.
    F(S)=P(S subset next); value[S]=max_i L_i F(S+i)+value[S+i].
    """
    ids = tuple(sorted(ids))
    n, size = len(ids), 1 << len(ids)
    index = {sid: i for i, sid in enumerate(ids)}
    mass = [0.0] * size
    for state, probability in states:
        mask = sum(1 << index[sid] for sid in state if sid in index)
        mass[mask] += probability
    survival = mass[:]
    for bit in range(n):
        for mask in range(size):
            if not mask & (1 << bit):
                survival[mask] += survival[mask | (1 << bit)]
    values, choices = [0.0] * size, [-1] * size
    for mask in range(size - 2, -1, -1):
        best = -math.inf
        for bit, sid in enumerate(ids):
            if not mask & (1 << bit):
                enlarged = mask | (1 << bit)
                value = lengths[sid] * survival[enlarged] + values[enlarged]
                if value > best + 1e-9:
                    best, choices[mask] = value, bit
        values[mask] = best

    def tail(prefix=()):
        mask = sum(1 << index[sid] for sid in prefix)
        result = []
        while mask != size - 1:
            bit = choices[mask]
            result.append(ids[bit])
            mask |= 1 << bit
        return tuple(result)

    return tail, values[0], {sid: 1.0 - survival[1 << bit] for bit, sid in enumerate(ids)}


def _usable_prefix(order, allowed):
    prefix = []
    for sid in order:
        if sid not in allowed:
            break
        prefix.append(sid)
    return tuple(prefix)


def _nbytes(order, lengths):
    return sum(lengths.get(sid, 0) for sid in order)


def _common_bytes(left, right, lengths):
    result = 0
    for a, b in zip(left, right):
        if a != b:
            break
        result += lengths.get(a, 0)
    return result


def _best_cached_prefix(cache, allowed, lengths):
    candidates = {_usable_prefix(order, allowed) for order in cache}
    return min(candidates, key=lambda prefix: (-_nbytes(prefix, lengths), prefix)) if candidates else ()


def plan_layout(allowed_sources, historical_transitions, observed_cache_orders, config=None):
    """Return an exact permutation of current legal IDs, never selected text.

    Historical transitions contain before/after ID collections and optionally
    observable context. Config may supply trusted, previously known source byte
    lengths (including currently forbidden IDs), never their old bodies. Future
    newly legal unknown-length sources contribute an explicitly omitted constant
    only when they occur in no observed cache order. Every cached ID requires
    its trusted length metadata even when that source is currently forbidden.
    All cache orders must be earlier ACTUAL dispatches of the same content IDs.
    """
    started = time.perf_counter()
    original, lengths, hashes, known, history, cache, cfg, minimum, cap, weight, omitted = _prepare(
        allowed_sources, historical_transitions, observed_cache_orders, config)
    current = frozenset(original)
    conditional_states, confidence = _forecast(current, history, known, cfg, minimum)
    # Global static masks: remove before-minus-after, counterfactually from the
    # current legal set. All rows have equal weight; absent-before is no removal.
    static_states = _compress((current - (before - after), 1.0) for before, after, _ in history) if history else [(current, 1.0)]
    static_tail, static_value, risks = _suffix_policy(current, lengths, static_states)
    conditional_tail, conditional_value, conditional_risks = _suffix_policy(current, lengths, conditional_states)
    static = static_tail()
    hot_prefix = _best_cached_prefix(cache, current, lengths)
    full_hot = len(hot_prefix) == len(current)
    cut_prefix = []
    for sid in hot_prefix:
        if conditional_risks[sid] >= cfg.get("risk_cut_threshold", .5) - 1e-12:
            break
        cut_prefix.append(sid)
    cut_prefix = tuple(cut_prefix)
    baseline_orders = {
        "original": tuple(original),
        "risk": tuple(sorted(current, key=lambda sid: (risks[sid], sid))),
        "risk_length_ratio": tuple(sorted(current, key=lambda sid: (
            risks[sid] / (lengths[sid] * (1 - risks[sid])) if risks[sid] < 1 - 1e-12 else math.inf, sid))),
        "static_joint_dp": static,
        "cache_greedy": hot_prefix + static_tail(hot_prefix),
        "full_hot_else_static": hot_prefix if full_hot else static,
        "conditional_static": conditional_tail(),
        "cache_greedy_risk_cut": cut_prefix + conditional_tail(cut_prefix),
    }
    total = _nbytes(current, lengths)
    # This history/cached-prefix work is shared by all candidates, not repeated
    # by a quadratic order-by-order future permutation enumeration.
    next_states = [(state, probability, _nbytes(state, known),
                    _nbytes(_best_cached_prefix(cache, state, known), known))
                   for state, probability in conditional_states]

    def score(order):
        now_hit = max((_common_bytes(order, old, lengths) for old in cache), default=0)
        now_miss = total - now_hit
        future = 0.0
        for state, probability, next_total, old_hit in next_states:
            new_hit = _nbytes(_usable_prefix(order, state), known)
            future += probability * max(0, next_total - max(old_hit, new_hit))
        return now_miss + weight * future, now_miss, future, order

    def score_key(order):
        objective, now_miss, _, identity = score(order)
        # With next_cost_weight=0 the future must not sneak back through a
        # secondary tie-break. Ties use current MISS then lexical order only.
        return objective, now_miss, identity

    method = cfg.get("method", "causal_two_step")
    candidate_orders, origins = [], {}

    def add(order, origin):
        order = tuple(order)
        if order not in origins and len(candidate_orders) < cap:
            if len(order) != len(current) or frozenset(order) != current:
                raise AssertionError("candidate_is_not_full_lawful_permutation")
            candidate_orders.append(order)
            origins[order] = origin

    for name, order in baseline_orders.items():
        add(order, name)
    if method == "causal_two_step":
        prefixes = {prefix[:k] for old in cache
                    for prefix in [_usable_prefix(old, current)]
                    for k in range(len(prefix) + 1)}
        for prefix in sorted(prefixes, key=lambda prefix: (-_nbytes(prefix, lengths), prefix)):
            add(prefix + conditional_tail(prefix), "hot_prefix_cut_conditional_tail")
            add(prefix + static_tail(prefix), "hot_prefix_cut_static_tail")
        # A bounded local expansion, preserving every registered baseline.
        seeds = sorted(candidate_orders, key=score_key)[:16]
        for order in seeds:
            for index in range(max(0, len(order) - 1)):
                swapped = list(order)
                swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
                add(swapped, "adjacent_swap")
        selected = min(candidate_orders, key=score_key)
    else:
        selected = baseline_orders[method]
    objective, now, future, _ = score(selected)
    details = {
        "method": method,
        "length_model": "sum_source_text_utf8_bytes_excludes_headers_escaping_system_questions",
        "cache_model": "ideal_all_prefixes_of_prior_actual_orders_PLANNING_PROXY_ONLY",
        "cache_orders_are_not_evidence_of_provider_persistence": True,
        "source_ids_must_be_content_version_scoped": True,
        "all_current_legal_sources_included_exactly_once": True,
        "supplier_cost_or_token_prediction": False,
        "current_source_sha256": hashes,
        "current_source_length_bytes": lengths,
        "known_source_length_metadata_ids": sorted(known),
        "observed_order_count_used": len(cache),
        "observed_order_count_omitted_by_recent_limit": omitted,
        "global_static_mask_samples": len(history),
        "risk_denominator": "all_historical_transitions; absent_before_is_no_removal",
        "global_static_marginal_removal_probability": risks,
        "forecast_confidence": confidence,
        "forecast_distinct_next_states": len(next_states),
        "static_proxy_optimal_expected_retained_bytes": static_value,
        "conditional_proxy_optimal_expected_retained_bytes": conditional_value,
        "dp_exact_only_for_fixed_order_empirical_retained_prefix_proxy": True,
        "two_step_is_bounded_pool_not_global_optimum": True,
        "candidate_count": len(candidate_orders),
        "candidate_limit": cap,
        "selected_candidate_origin": origins.get(selected, method),
        "next_cost_weight": weight,
        "risk_cut_threshold": cfg.get("risk_cut_threshold", .5),
        "predicted_two_step_miss_objective_bytes": objective,
        "full_current_view_is_hot_under_proxy": full_hot,
        "baseline_orders": {name: list(order) for name, order in baseline_orders.items()},
    }
    return {
        "ordered_source_ids": list(selected),
        "predicted_now_miss_bytes": now,
        "predicted_next_miss_bytes": future,
        "details": details,
        "planning_ms": (time.perf_counter() - started) * 1000,
    }
