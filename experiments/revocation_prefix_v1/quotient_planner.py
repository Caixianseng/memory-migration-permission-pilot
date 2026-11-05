"""Exact two-step prefix optimization compressed by forecast membership classes.

For a fixed legal old-cache prefix P, sources left in its tail with identical
membership in EVERY positive-mass forecast state can be made contiguous without
reducing retained-prefix bytes in any state. If a class is absent, its first
member already stops that state's prefix; if present, advancing later members
can only move the first forbidden source later. max(old_hit,retained) is monotone.
P remains untouched, even when it contains only part of a class.

Thus, for EACH legal cached prefix P, recompute remaining class weights and solve
a class-subset DP with initial length L(P) and only states containing all of P.
Attach the class tail, then evaluate the ACTUAL current trie hit. Enumerating the
optimal order's longest cached prefix proves global optimality for this frozen
two-step proxy. Partial classes require separate per-prefix DPs.

Main work O(T*M*k*2**k + n*T), plus forecast/cache preprocessing; k is the number
of distinct forecast membership signatures, NOT the source count n. Worst case
k=n remains exponential; there is no unconditional scalable guarantee. Only the
IDEAL whole-source UTF-8 prefix model is exact, never supplier fees or QA quality.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import math
import time

try:
    from . import planner as predictor
    from .exact_planner import _lengths, _id_order
except ImportError:
    import planner as predictor
    from exact_planner import _lengths, _id_order


class QuotientProblem:
    def __init__(self, lengths, states, cache, weight=1.0, known_source_lengths_bytes=None,
                 max_signature_groups=12):
        started = time.perf_counter()
        self.lengths = _lengths(lengths, "current_lengths")
        if len(self.lengths) > 128:
            raise ValueError("quotient_current_source_limit_is_128")
        self.known = _lengths(known_source_lengths_bytes or {}, "known_lengths")
        if any(sid in self.known and self.known[sid] != value for sid, value in self.lengths.items()):
            raise ValueError("current_and_known_lengths_conflict")
        self.known.update(self.lengths)
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight < 0:
            raise ValueError("weight_must_be_finite_nonnegative")
        if type(max_signature_groups) is not int or not 1 <= max_signature_groups <= 20:
            raise ValueError("max_signature_groups_must_be_1_to_20")
        self.weight, self.limit = float(weight), max_signature_groups
        if not isinstance(cache, (list, tuple)):
            raise ValueError("cache_must_be_prior_order_sequence")
        if any(not isinstance(order, (list, tuple)) for order in cache):
            raise ValueError("cached_orders_must_be_ORDERED_lists_or_tuples")
        self.cache = tuple(dict.fromkeys(_id_order(order, "cached_order") for order in cache))
        if len(self.cache) > 128:
            raise ValueError("quotient_observed_order_limit_is_128")
        if any(sid not in self.known for order in self.cache for sid in order):
            raise ValueError("all_cached_ids_require_known_lengths")
        mass = Counter()
        if not isinstance(states, (list, tuple)) or not states:
            raise ValueError("nonempty_weighted_next_states_required")
        for row in states:
            if not isinstance(row, (list, tuple)) or len(row) != 2:
                raise ValueError("next_state_requires_ids_and_mass")
            state, probability = row
            state = frozenset(_id_order(state, "next_state"))
            if state - self.known.keys():
                raise ValueError("all_forecast_ids_require_known_lengths")
            if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not math.isfinite(probability) or probability < 0:
                raise ValueError("state_mass_must_be_finite_nonnegative")
            if probability:
                mass[state] += probability
        total_mass = sum(mass.values())
        if total_mass <= 0 or not math.isfinite(total_mass):
            raise ValueError("positive_finite_state_total_mass_required")
        self.states = tuple((state, probability / total_mass) for state, probability
                            in sorted(mass.items(), key=lambda row: tuple(sorted(row[0]))))
        if len(self.states) > 256:
            raise ValueError("quotient_explicit_positive_state_limit_is_256")
        self.ids = tuple(sorted(self.lengths))
        self.index = {sid: bit for bit, sid in enumerate(self.ids)}
        self.total = sum(self.lengths.values())
        self.workspace = []
        for state, probability in self.states:
            old_hit = 0
            for old in self.cache:
                value = 0
                for sid in old:
                    if sid not in state:
                        break
                    value += self.known[sid]
                old_hit = max(old_hit, value)
            mask = sum(1 << self.index[sid] for sid in state if sid in self.index)
            self.workspace.append((mask, probability, old_hit, sum(self.known[sid] for sid in state)))
        self.base_hit = sum(p * old for _, p, old, _ in self.workspace)
        self.next_total = sum(p * total for _, p, _, total in self.workspace)
        groups = defaultdict(list)
        for sid in self.ids:
            signature = sum(1 << j for j, (state, _) in enumerate(self.states) if sid in state)
            groups[signature].append(sid)
        self.cohorts = tuple((signature, tuple(members)) for signature, members
                             in sorted(groups.items(), key=lambda row: tuple(row[1])))
        if self.weight and len(self.cohorts) > self.limit:
            raise ValueError("forecast_signature_count_exceeds_exact_limit_k_equals_n_in_worst_case")
        self.trie = [{"children": {}, "prefix": (), "mask": 0, "length": 0, "future_gain": 0.0}]
        for old in self.cache:
            node = 0
            for sid in old:
                if sid not in self.index:
                    break
                if sid not in self.trie[node]["children"]:
                    parent = self.trie[node]
                    enlarged = parent["mask"] | (1 << self.index[sid])
                    after_length = parent["length"] + self.lengths[sid]
                    # This is an actual OLD cached prefix. In every next state
                    # its retained prefix is already covered by b_A; therefore
                    # its future residual reward is exactly zero, irrespective
                    # of its internal order or a partial cohort boundary.
                    child = len(self.trie)
                    parent["children"][sid] = child
                    self.trie.append({"children": {}, "prefix": parent["prefix"] + (sid,),
                                      "mask": enlarged, "length": after_length,
                                      "future_gain": 0.0})
                node = self.trie[node]["children"][sid]
        self.preprocessing_ms = (time.perf_counter() - started) * 1000

    def _current_hit(self, order):
        node, value = 0, 0
        for sid in order:
            child = self.trie[node]["children"].get(sid)
            if child is None:
                break
            value += self.lengths[sid]
            node = child
        return value

    def _metrics(self, order, now_hit, next_hit):
        now_miss, next_miss = self.total - now_hit, max(0.0, self.next_total - next_hit)
        return {"ordered_source_ids": list(order), "expectedobj": now_hit + self.weight * next_hit,
                "current_hit_bytes": now_hit, "expected_next_hit_bytes": next_hit,
                "predicted_now_miss_bytes": now_miss, "predicted_next_miss_bytes": next_miss,
                "expected_two_step_miss_bytes": now_miss + self.weight * next_miss}

    def score_order(self, order):
        """Direct state-wise scoring, independent of quotient DP bookkeeping."""
        if not isinstance(order, (list, tuple)):
            raise ValueError("candidate_order_must_be_ordered_sequence")
        order = _id_order(order, "candidate_order")
        if len(order) != len(self.ids) or set(order) != set(self.ids):
            raise ValueError("candidate_must_include_all_current_legal_ids_once")
        future = 0.0
        for (state, _), (_, p, old_hit, _) in zip(self.states, self.workspace):
            retained = 0
            for sid in order:
                if sid not in state:
                    break
                retained += self.lengths[sid]
            future += p * max(old_hit, retained)
        return self._metrics(order, self._current_hit(order), future)

    def solve(self, prefix_mode="all"):
        if prefix_mode not in {"all", "longest_hot"}:
            raise ValueError("prefix_mode_must_be_all_or_longest_hot")
        started = time.perf_counter()
        best, best_key = None, None
        subset_states, transitions, state_checks, partial_prefixes, max_k = 0, 0, 0, 0, 0
        prefix_nodes = (self.trie if prefix_mode == "all" else [min(
            self.trie, key=lambda node: (-node["length"], node["prefix"]))])
        for prefix_node in prefix_nodes:
            prefix = prefix_node["prefix"]
            prefix_ids = set(prefix)
            if not self.weight:
                order = list(prefix) + sorted(set(self.ids) - prefix_ids)
                now_hit = self._current_hit(order)
                key = (-now_hit, tuple(order))
                if best_key is None or key < best_key:
                    best_key, best = key, {"ordered_source_ids": order}
                continue
            remaining_groups = []
            is_partial = False
            for signature, members in self.cohorts:
                remaining = tuple(sid for sid in members if sid not in prefix_ids)
                if remaining:
                    remaining_groups.append((signature, remaining, sum(self.lengths[sid] for sid in remaining)))
                    is_partial |= len(remaining) != len(members)
            partial_prefixes += int(is_partial)
            k, size = len(remaining_groups), 1 << len(remaining_groups)
            max_k = max(max_k, k)
            subset_states += size
            active = sum(1 << j for j, (state_mask, _, _, _) in enumerate(self.workspace)
                         if prefix_node["mask"] & state_mask == prefix_node["mask"])
            covered, subset_bytes = [0] * size, [0] * size
            covered[0], subset_bytes[0] = active, prefix_node["length"]
            for mask in range(1, size):
                low = mask & -mask
                bit, previous = low.bit_length() - 1, mask ^ low
                covered[mask] = covered[previous] & remaining_groups[bit][0]
                subset_bytes[mask] = subset_bytes[previous] + remaining_groups[bit][2]
            value, choice = [0.0] * size, [-1] * size
            for mask in range(size - 2, -1, -1):
                best_value = -math.inf
                for bit, (_, _, group_bytes) in enumerate(remaining_groups):
                    if mask & (1 << bit):
                        continue
                    transitions += 1
                    enlarged = mask | (1 << bit)
                    eligible = covered[enlarged]
                    gain = 0.0
                    while eligible:
                        low = eligible & -eligible
                        j = low.bit_length() - 1
                        _, probability, old_hit, _ = self.workspace[j]
                        gain += probability * (max(old_hit, subset_bytes[mask] + group_bytes)
                                               - max(old_hit, subset_bytes[mask]))
                        state_checks += 1
                        eligible ^= low
                    candidate = gain + value[enlarged]
                    if candidate > best_value:
                        best_value, value[mask], choice[mask] = candidate, candidate, bit
            order, mask = list(prefix), 0
            while mask != size - 1:
                bit = choice[mask]
                order.extend(remaining_groups[bit][1])
                mask |= 1 << bit
            hit = self.base_hit + prefix_node["future_gain"] + value[0]
            metrics = self._metrics(order, self._current_hit(order), hit)
            key = (-metrics["expectedobj"], -metrics["current_hit_bytes"], tuple(order))
            if best_key is None or key < best_key:
                best_key, best = key, metrics
        # A direct per-state score of the final order validates all partial-
        # cohort base-length and active-state bookkeeping before returning.
        checked = self.score_order(best["ordered_source_ids"])
        if self.weight and not math.isclose(checked["expectedobj"], best["expectedobj"], rel_tol=1e-12, abs_tol=1e-7):
            raise AssertionError("quotient_prefix_dp_and_direct_state_score_disagree")
        checked["planning_ms"] = self.preprocessing_ms + (time.perf_counter() - started) * 1000
        checked["details"] = {
            "method": "quotient_two_step" if prefix_mode == "all" else "quotient_cache_greedy",
            "exact_for_frozen_two_step_ideal_byte_prefix_objective": prefix_mode == "all",
            "prefix_mode": prefix_mode,
            "tail_exact_for_each_considered_fixed_prefix": True,
            "compression_rule": "identical_membership_in_all_positive_mass_forecast_states",
            "cohorts_recomputed_after_each_fixed_cache_prefix": True,
            "source_count": len(self.ids), "forecast_state_count": len(self.states),
            "forecast_signature_cohort_count": len(self.cohorts), "maximum_remaining_cohort_count": max_k,
            "maximum_exact_signature_groups": self.limit, "worst_case_k_equals_n_remains_exponential": True,
            "legal_cache_trie_nodes": len(self.trie), "prefix_dps_evaluated": len(prefix_nodes),
            "partial_cohort_prefixes": partial_prefixes,
            "total_dp_subset_states_across_prefixes": subset_states,
            "dp_state_transitions": transitions, "active_forecast_state_checks": state_checks,
            "uncompressed_source_subset_count": 1 << len(self.ids),
            "old_cache_expected_next_hit_bytes": self.base_hit, "expected_next_raw_source_bytes": self.next_total,
            "next_cost_weight": self.weight, "candidate_count": len(prefix_nodes), "candidate_limit": None,
            "selected_candidate_origin": "legal_prefix_plus_forecast_signature_quotient_DP",
            "predicted_two_step_miss_objective_bytes": checked["expected_two_step_miss_bytes"],
            "length_model": "sum_source_text_UTF8_bytes_excludes_wrappers_system_questions",
            "cache_model": "ideal_all_source_prefixes_of_prior_actual_orders_PROXY_ONLY",
            "supplier_fee_hit_quality_or_forecast_correctness_guaranteed": False,
            "preprocessing_ms": self.preprocessing_ms,
        }
        return checked


def solve_quotient(lengths, states, cache, weight=1.0, known_source_lengths_bytes=None,
                   max_signature_groups=12, prefix_mode="all"):
    return QuotientProblem(lengths, states, cache, weight, known_source_lengths_bytes,
                           max_signature_groups).solve(prefix_mode)


def plan_layout(allowed_sources, historical_transitions, observed_cache_orders, config=None):
    """Large-source runner-compatible entry point; no unauthorised source bodies.

    Joint-delta or directly supported conditional forecasts use explicit history
    states. An independent fallback with excessive explicit support is rejected;
    forecast enumeration itself is not made scalable by this ordering theorem.
    """
    started = time.perf_counter()
    cfg = dict(config or {})
    predictor._no_future(cfg)
    if set(cfg) - predictor._CONFIG - {"max_signature_groups", "max_explicit_forecast_states"}:
        raise ValueError("unknown_quotient_config_key")
    method = cfg.get("method", "quotient_two_step")
    if method not in {"quotient_two_step", "quotient_exact_two_step", "quotient_cache_greedy"}:
        raise ValueError("quotient_module_requires_quotient_method")
    if not isinstance(allowed_sources, (list, tuple)):
        raise ValueError("allowed_sources_must_be_sequence")
    lengths, hashes = {}, {}
    for source in allowed_sources:
        if not isinstance(source, dict):
            raise ValueError("source_object_required")
        sid, text = source.get("source_id"), source.get("text")
        if not isinstance(sid, str) or not sid or sid in lengths or not isinstance(text, str) or not text:
            raise ValueError("invalid_current_source_identity_or_text")
        if source.get("allow", True) is not True or source.get("allowed", True) is not True:
            raise ValueError("forbidden_source_body_received")
        raw = text.encode("utf-8")
        lengths[sid], hashes[sid] = len(raw), hashlib.sha256(raw).hexdigest()
    known = _lengths(cfg.get("known_source_lengths_bytes", {}), "known_lengths")
    if any(sid in known and known[sid] != length for sid, length in lengths.items()):
        raise ValueError("current_and_known_lengths_conflict")
    known.update(lengths)
    if not isinstance(historical_transitions, (list, tuple)):
        raise ValueError("historical_transition_sequence_required")
    history = []
    import json
    for row in historical_transitions:
        if not isinstance(row, dict) or not {"before", "after"} <= row.keys() or set(row) - {"before", "after", "context"}:
            raise ValueError("history_requires_only_before_after_optional_context")
        predictor._no_future(row)
        history.append((frozenset(_id_order(row["before"], "before")),
                        frozenset(_id_order(row["after"], "after")),
                        json.dumps(row.get("context"), sort_keys=True, ensure_ascii=False, allow_nan=False)))
    minimum = cfg.get("min_conditional_samples", 2)
    if type(minimum) is not int or minimum < 1:
        raise ValueError("positive_min_conditional_samples_required")
    model = cfg.get("forecast_model", "conditional_state")
    if model not in {"conditional_state", "joint_delta", "independent_status_marginal"}:
        raise ValueError("unknown_forecast_model")
    context = json.dumps(cfg.get("context"), sort_keys=True, ensure_ascii=False, allow_nan=False)
    matching = sum(before == frozenset(lengths) and ("context" not in cfg or old_context == context)
                   for before, _, old_context in history)
    direct_forecast = (model == "joint_delta" and history) or (model == "conditional_state" and matching >= minimum)
    support_limit = cfg.get("max_explicit_forecast_states", 256)
    if type(support_limit) is not int or support_limit < 1:
        raise ValueError("positive_explicit_forecast_support_limit_required")
    if not direct_forecast:
        uncertain = 0
        for sid in known:
            opportunities = [after for before, after, _ in history if (sid in before) == (sid in lengths)]
            present = sum(sid in after for after in opportunities)
            uncertain += int(bool(opportunities) and 0 < present < len(opportunities))
        if (1 << uncertain) > support_limit or (len(lengths) > 12 and uncertain):
            raise ValueError("independent_forecast_support_too_large_supply_explicit_joint_history")
    states, confidence = predictor._forecast(frozenset(lengths), history, known, cfg, minimum)
    cache_cap = cfg.get("max_observed_orders", 128)
    if type(cache_cap) is not int or cache_cap < 1 or not isinstance(observed_cache_orders, (list, tuple)):
        raise ValueError("positive_cache_cap_and_observed_order_sequence_required")
    result = solve_quotient(lengths, states, observed_cache_orders[-cache_cap:], cfg.get("next_cost_weight", 1.0),
                            known, cfg.get("max_signature_groups", 12),
                            "longest_hot" if method == "quotient_cache_greedy" else "all")
    result["details"].update({"forecast_confidence": confidence, "current_source_sha256": hashes,
                               "current_source_length_bytes": lengths,
                               "known_source_length_metadata_ids": sorted(known),
                               "source_ids_must_be_content_version_scoped": True,
                               "all_current_legal_sources_included_exactly_once": True})
    result["planning_ms"] = (time.perf_counter() - started) * 1000
    return result
