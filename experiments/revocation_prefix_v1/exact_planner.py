"""Exact cache-aware two-step ordering under the IDEAL source-prefix proxy.

The predictor and input validation are reused unchanged from frozen planner.py;
this module changes only the ordering optimizer. No LLM, network or file I/O.
All source byte lengths are TEXT UTF-8 lengths, not supplier token/hit counts.

For current prefix set S and appended i, future retained-prefix hit increases by
  sum_A p(A) 1[S+i subset A]
        (max(b_A, L(S)+L_i) - max(b_A, L(S))),
where b_A is the best OLD cached prefix legal in next view A. Once a prefix
contains an illegal-next source, every subsequent indicator is zero. The above
increments therefore telescope to E[max(b_A, retainedPrefix(order,A))]-E[b_A].
They depend on S and i, not the order inside S: one subset DP solves every tail.

Enumerate each legal prefix P in the current cache trie and attach the DP tail
for set(P). Evaluate its ACTUAL current longest-prefix hit. For an optimal order
pi, its longest hot prefix P is enumerated. Replacing its tail by the best tail
cannot reduce future reward, and preserves at least P's current hit (possibly
more). Thus the best enumerated complete order attains the global optimum.

Work: O(n*2**n*number_next_states + n*number_legal_trie_nodes), memory O(n*2**n)
plus trie/states. Exactness concerns this TWO-STEP BYTE PROXY only, not supplier
cache persistence, future prediction correctness, semantic quality or fees.
"""
from __future__ import annotations

from collections import Counter
import math
import time

try:
    from . import planner as frozen_planner
except ImportError:
    import planner as frozen_planner


def _id_order(order, label):
    if not isinstance(order, (list, tuple, set, frozenset)):
        raise ValueError(label + "_must_be_source_id_collection")
    result = tuple(order)
    if any(not isinstance(sid, str) or not sid for sid in result) or len(result) != len(set(result)):
        raise ValueError(label + "_invalid_or_duplicate_ids")
    return result


def _lengths(value, label):
    if not isinstance(value, dict):
        raise ValueError(label + "_must_be_mapping")
    if any(not isinstance(sid, str) or not sid or type(length) is not int or length < 1
           for sid, length in value.items()):
        raise ValueError(label + "_must_have_positive_integer_byte_lengths")
    return dict(value)


class ExactProblem:
    """Reusable preprocessing for exact DP AND a fair 8!-enumeration benchmark.

    lengths maps CURRENT legal IDs to bytes. states is [(next_ID_set, mass),...].
    known_source_lengths_bytes supplies only trusted length metadata for any
    other historical/future ID. All cached and forecast IDs require known length.
    score_order reuses the SAME delta table and current cache trie as solve(),
    so brute-force timing need not recompute forecasts or state-wise prefixes.
    """

    def __init__(self, lengths, states, cache, weight=1.0, known_source_lengths_bytes=None):
        started = time.perf_counter()
        self.lengths = _lengths(lengths, "current_lengths")
        if len(self.lengths) > 12:
            raise ValueError("exact_solver_supports_at_most_12_current_sources")
        known = _lengths(known_source_lengths_bytes or {}, "known_lengths")
        if any(sid in known and known[sid] != length for sid, length in self.lengths.items()):
            raise ValueError("current_and_known_length_metadata_conflict")
        self.known = {**known, **self.lengths}
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight < 0:
            raise ValueError("weight_must_be_finite_nonnegative")
        self.weight = float(weight)
        if not isinstance(cache, (list, tuple)):
            raise ValueError("cache_must_be_prior_actual_orders")
        self.cache = tuple(dict.fromkeys(_id_order(order, "cached_order") for order in cache))
        if any(sid not in self.known for order in self.cache for sid in order):
            raise ValueError("all_cached_ids_require_known_length_metadata")
        if not isinstance(states, (list, tuple)) or not states:
            raise ValueError("nonempty_weighted_next_states_required")
        mass = Counter()
        for row in states:
            if not isinstance(row, (list, tuple)) or len(row) != 2:
                raise ValueError("next_state_requires_id_collection_and_mass_pair")
            state, probability = row
            state = frozenset(_id_order(state, "next_state"))
            if state - self.known.keys():
                raise ValueError("all_forecast_ids_require_known_length_metadata")
            if (isinstance(probability, bool) or not isinstance(probability, (int, float))
                    or not math.isfinite(probability) or probability < 0):
                raise ValueError("next_state_mass_must_be_finite_nonnegative")
            if probability:
                mass[state] += probability
        total_mass = sum(mass.values())
        if not total_mass or not math.isfinite(total_mass):
            raise ValueError("positive_finite_next_state_total_mass_required")
        self.states = tuple((state, probability / total_mass) for state, probability
                            in sorted(mass.items(), key=lambda row: tuple(sorted(row[0]))))
        self.ids = tuple(sorted(self.lengths))
        self.index = {sid: index for index, sid in enumerate(self.ids)}
        self.n, self.size = len(self.ids), 1 << len(self.ids)
        self.bytes = [0] * self.size
        for mask in range(1, self.size):
            low_bit = mask & -mask
            sid = self.ids[low_bit.bit_length() - 1]
            self.bytes[mask] = self.bytes[mask ^ low_bit] + self.lengths[sid]
        self.current_total = self.bytes[-1]
        self.next_workspace = []
        for state, probability in self.states:
            state_mask = sum(1 << self.index[sid] for sid in state if sid in self.index)
            old_hit = 0
            for order in self.cache:
                value = 0
                for sid in order:
                    if sid not in state:
                        break
                    value += self.known[sid]
                old_hit = max(old_hit, value)
            next_total = sum(self.known[sid] for sid in state)
            self.next_workspace.append((state_mask, probability, old_hit, next_total))
        self.old_next_hit = sum(probability * old_hit for _, probability, old_hit, _ in self.next_workspace)
        self.expected_next_total = sum(probability * total for _, probability, _, total in self.next_workspace)
        self.delta = [[0.0] * self.n for _ in range(self.size)]
        self.delta_state_checks = 0
        for mask in range(self.size):
            for bit, sid in enumerate(self.ids):
                if mask & (1 << bit):
                    continue
                enlarged = mask | (1 << bit)
                before_len, after_len = self.bytes[mask], self.bytes[enlarged]
                gain = 0.0
                for state_mask, probability, old_hit, _ in self.next_workspace:
                    self.delta_state_checks += 1
                    if enlarged & state_mask == enlarged:
                        gain += probability * (max(old_hit, after_len) - max(old_hit, before_len))
                self.delta[mask][bit] = gain
        # Legal current cache trie. Stop at the first now-forbidden source;
        # deleting it and reusing later sources as a prefix would be incorrect.
        self.trie = [{"children": {}, "prefix": (), "mask": 0, "future_gain": 0.0}]
        for order in self.cache:
            node = 0
            for sid in order:
                if sid not in self.index:
                    break
                children = self.trie[node]["children"]
                if sid not in children:
                    parent = self.trie[node]
                    children[sid] = len(self.trie)
                    self.trie.append({
                        "children": {}, "prefix": parent["prefix"] + (sid,),
                        "mask": parent["mask"] | (1 << self.index[sid]),
                        "future_gain": parent["future_gain"] + self.delta[parent["mask"]][self.index[sid]],
                    })
                node = children[sid]
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

    def score_order(self, order):
        """O(n) full score after shared preprocessing, including true trie LCP."""
        order = _id_order(order, "candidate_order")
        if len(order) != self.n or frozenset(order) != frozenset(self.ids):
            raise ValueError("candidate_must_include_all_current_legal_ids_once")
        mask, future_gain = 0, 0.0
        for sid in order:
            bit = self.index[sid]
            future_gain += self.delta[mask][bit]
            mask |= 1 << bit
        return self._metrics(order, self._current_hit(order), self.old_next_hit + future_gain)

    def _metrics(self, order, now_hit, next_hit):
        now_miss = self.current_total - now_hit
        next_miss = max(0.0, self.expected_next_total - next_hit)
        return {"ordered_source_ids": list(order),
                "predicted_now_miss_bytes": now_miss,
                "predicted_next_miss_bytes": next_miss,
                "expectedobj": now_hit + self.weight * next_hit,
                "current_hit_bytes": now_hit, "expected_next_hit_bytes": next_hit,
                "expected_two_step_miss_bytes": now_miss + self.weight * next_miss}

    def solve(self):
        started = time.perf_counter()
        tail_gain, next_choice = [0.0] * self.size, [-1] * self.size
        transitions = 0
        for mask in range(self.size - 2, -1, -1):
            best_weighted_gain = -math.inf
            for bit, _ in enumerate(self.ids):
                if mask & (1 << bit):
                    continue
                transitions += 1
                enlarged = mask | (1 << bit)
                gain = self.delta[mask][bit] + tail_gain[enlarged]
                value = self.weight * gain
                # Sorted first IDs resolve ties lexically. Weight zero truly
                # disables future rewards, including secondary tie-breaking.
                if value > best_weighted_gain:
                    best_weighted_gain = value
                    tail_gain[mask], next_choice[mask] = gain, bit
        best, best_key = None, None
        for prefix_node in self.trie:
            mask = prefix_node["mask"]
            order = list(prefix_node["prefix"])
            remainder = mask
            while remainder != self.size - 1:
                bit = next_choice[remainder]
                order.append(self.ids[bit])
                remainder |= 1 << bit
            next_hit = self.old_next_hit + prefix_node["future_gain"] + tail_gain[mask]
            metrics = self._metrics(order, self._current_hit(order), next_hit)
            key = (-metrics["expectedobj"], -metrics["current_hit_bytes"], tuple(order))
            if best_key is None or key < best_key:
                best_key, best = key, metrics
        # This uses the shared delta table but recomputes the chosen path rather
        # than trusting prefix-node / DP reward bookkeeping.
        check = self.score_order(best["ordered_source_ids"])
        if not math.isclose(check["expectedobj"], best["expectedobj"], rel_tol=1e-12, abs_tol=1e-7):
            raise AssertionError("prefix_dp_and_selected_path_score_disagree")
        best = check
        best["planning_ms"] = self.preprocessing_ms + (time.perf_counter() - started) * 1000
        best["details"] = {
            "method": "exact_two_step", "optimizer": "future_residual_subset_DP_plus_all_legal_cache_trie_prefixes",
            "exact_for_frozen_two_step_ideal_byte_prefix_objective": True,
            "forecast_accuracy_or_supplier_cache_guaranteed": False,
            "length_model": "sum_source_text_UTF8_bytes_excludes_wrappers_system_questions",
            "cache_model": "all_prefixes_of_prior_actual_orders_IDEAL_PROXY_ONLY",
            "all_current_legal_sources_included_exactly_once": True,
            "number_current_sources": self.n, "number_subset_states": self.size,
            "number_forecast_states": len(self.states), "number_legal_cache_trie_nodes": len(self.trie),
            "dp_state_transitions": transitions, "delta_state_checks": self.delta_state_checks,
            "candidate_count": len(self.trie), "candidate_limit": None,
            "selected_candidate_origin": "exact_legal_cache_prefix_plus_residual_optimal_tail",
            "next_cost_weight": self.weight,
            "old_cache_expected_next_hit_bytes": self.old_next_hit,
            "expected_next_raw_source_bytes": self.expected_next_total,
            "expectedobj_units": "current_hit_bytes_plus_weight_times_expected_next_hit_bytes_MAXIMIZE",
            "predicted_two_step_miss_objective_bytes": best["expected_two_step_miss_bytes"],
            "cache_orders_are_not_provider_persistence_evidence": True,
            "preprocessing_ms": self.preprocessing_ms,
            "score_order_reuses_delta_table_and_cache_trie_for_fair_enumeration": True,
        }
        return best


def solve_exact(lengths, states, cache, weight=1.0, known_source_lengths_bytes=None):
    """Exact standalone solver; see ExactProblem for weighted-state input shape."""
    return ExactProblem(lengths, states, cache, weight, known_source_lengths_bytes).solve()


def plan_layout(allowed_sources, historical_transitions, observed_cache_orders, config=None):
    """Runner-compatible interface; existing predictor is unchanged.

    Accept method='exact_two_step'. The legacy candidate-pool limit is validated
    for compatibility but does not cap this exact optimizer. Every cached AND
    forecast source requires known trusted length metadata, including currently
    forbidden sources; no old source body is read from these metadata routes.
    """
    started = time.perf_counter()
    cfg = dict(config or {})
    method = cfg.pop("method", "exact_two_step")
    if method != "exact_two_step":
        raise ValueError("exact_module_requires_method_exact_two_step")
    original, lengths, hashes, known, history, cache, validated_cfg, minimum, _, weight, omitted = frozen_planner._prepare(
        allowed_sources, historical_transitions, observed_cache_orders, {**cfg, "method": "causal_two_step"})
    states, confidence = frozen_planner._forecast(frozenset(original), history, known, validated_cfg, minimum)
    result = solve_exact(lengths, states, cache, weight, known)
    result["details"].update({
        "forecast_confidence": confidence, "current_source_sha256": hashes,
        "current_source_length_bytes": lengths, "known_source_length_metadata_ids": sorted(known),
        "source_ids_must_be_content_version_scoped": True,
        "observed_order_count_used": len(cache),
        "observed_order_count_omitted_by_recent_limit": omitted,
        "legacy_candidate_pool_cap_does_not_apply": True,
    })
    result["planning_ms"] = (time.perf_counter() - started) * 1000
    return result
