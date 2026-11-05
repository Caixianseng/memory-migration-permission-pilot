"""Frozen initial grouping heuristics for the bounded D1 development experiment.

The planner receives only CURRENTLY allowed sources and independent historical
revocation masks.  A mask is a sample of sources revoked by one historical
change, NOT a future event or an answer.  No planner reads experiment files.

The cost model is an explicitly approximate, token-based planning objective. It
is neither a token counter nor a prediction of semantic accuracy.  Actual model
receipts and an independent evaluator must determine whether any method wins.
Text features and planning diagnostics MUST NOT be copied into group-generation
prompts: doing so would introduce additional cross-group business dependencies.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import math
import re
import time
from collections import defaultdict

METHODS = frozenset({"single", "whole", "fixed", "acl", "risk", "semantic", "joint"})
_STOP = frozenset("a an and are as at be by for from in is it of on or that the this to was were will with you your".split())


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _number(value, name, minimum=0.0):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < minimum:
        raise ValueError(f"invalid_{name}")
    return float(value)


def _sources(records):
    if not isinstance(records, (list, tuple)):
        raise ValueError("source_list_required")
    result = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("source_object_required")
        sid, text, version = record.get("source_id"), record.get("text"), record.get("version", 1)
        if not isinstance(sid, str) or not sid or sid in result:
            raise ValueError("invalid_or_duplicate_source_id")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("source_text_required")
        if not isinstance(version, (int, str)) or isinstance(version, bool) or version == "":
            raise ValueError("source_version_required")
        if record.get("allow", True) is not True or record.get("allowed", True) is not True:
            raise ValueError("planner_received_forbidden_source")
        acl = record.get("acl_group", "all-currently-allowed")
        if not isinstance(acl, (str, int)) or isinstance(acl, bool):
            raise ValueError("acl_group_must_be_scalar")
        result[sid] = {"source_id": sid, "text": text, "version": version, "acl_group": str(acl)}
    return dict(sorted(result.items()))


def _features(text):
    """Lexical proxy: English tokens and Chinese bigrams; no semantic model."""
    words = {"w:" + word for word in re.findall(r"[a-z][a-z0-9_-]{1,}", text.lower()) if word not in _STOP}
    for run in re.findall(r"[\u3400-\u9fff]+", text):
        words.update("c:" + run[i:i + 2] for i in range(max(0, len(run) - 1)))
        if len(run) == 1:
            words.add("c:" + run)
    return words


def _similarity(left, right):
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def plan(allowed_sources, past_event_stats=None, config=None):
    """Return an initial partition, using no future events or task answers.

    ``past_event_stats`` supports ``masks`` (list[list[source_id]]),
    ``expected_changes`` and ``expected_deliveries``.  Other keys are metadata
    only and are not read. IDs absent from the currently allowed input are
    ignored. ``semantic`` ignores ALL historical masks and change statistics;
    ``risk`` ignores ALL text similarity. These are decision-rule ablations,
    rather than claims about measured reconstruction quality.

    Planner cost includes one initial generation/group, partial-group rebuilds
    under independent historical masks, and repeated delivery input. Output
    length is a fixed compression proxy with a bounded lexical-redundancy term.
    No output length, quality or cost is asserted until actual generation.
    """
    started = time.perf_counter()
    records = _sources(allowed_sources)
    cfg, history = dict(config or {}), dict(past_event_stats or {})
    method = cfg.get("method", "joint")
    if method not in METHODS:
        raise ValueError("unknown_grouping_method")
    # Explicitly reject accidental use of the experiment's future sequence.
    if any(key in history for key in ("future_events", "events", "answers", "questions", "evaluation")):
        raise ValueError("planner_received_evaluation_or_future_events")
    max_group = cfg.get("max_group_sources", 4)
    fixed_size = cfg.get("fixed_group_size", 2)
    if type(max_group) is not int or max_group < 1 or type(fixed_size) is not int or fixed_size < 1:
        raise ValueError("invalid_group_size")
    overhead = _number(cfg.get("generation_input_overhead_tokens", 100), "generation_overhead")
    output_overhead = _number(cfg.get("output_overhead_tokens", 16), "output_overhead")
    compression = _number(cfg.get("output_ratio", 0.4), "output_ratio")
    redundancy = _number(cfg.get("redundancy_weight", 0.5), "redundancy_weight")
    if compression > 1 or redundancy > 0.8:
        raise ValueError("invalid_compression_proxy")
    input_price = _number(cfg.get("input_price_per_million", 2), "input_price")
    output_price = _number(cfg.get("output_price_per_million", 8), "output_price")
    deliveries = _number(history.get("expected_deliveries", cfg.get("expected_deliveries", 3)), "expected_deliveries")
    changes = _number(history.get("expected_changes", cfg.get("expected_changes", 4)), "expected_changes")
    masks = history.get("masks", [])
    if not isinstance(masks, list) or any(not isinstance(mask, (list, tuple)) or any(not isinstance(sid, str) for sid in mask) for mask in masks):
        raise ValueError("historical_masks_invalid")
    observed = [set(mask) & records.keys() for mask in masks]
    ids = list(records)
    # Length proxy (not a reservation bound), independent of future output or evaluation.
    token_lengths = {sid: max(1.0, len(records[sid]["text"].encode("utf-8")) / 3.0) for sid in ids}
    use_semantics, use_risk = method in ("semantic", "joint"), method in ("risk", "joint")
    features = {sid: _features(records[sid]["text"]) for sid in ids} if use_semantics else {}
    similarities = {(a, b): _similarity(features[a], features[b]) for a, b in itertools.combinations(ids, 2)} if use_semantics else {}

    def output_tokens(group):
        raw = sum(token_lengths[sid] for sid in group)
        pairs = list(itertools.combinations(sorted(group), 2))
        similarity = sum(similarities.get(pair, 0.0) for pair in pairs) / len(pairs) if pairs else 0.0
        return output_overhead + raw * compression * (1.0 - redundancy * similarity)

    def generation_cost(group):
        if not group:
            return 0.0
        return ((overhead + sum(token_lengths[sid] for sid in group)) * input_price
                + output_tokens(group) * output_price) / 1_000_000

    def group_cost(group):
        initial = generation_cost(group)
        # A revoked singleton or completely revoked group needs no generation.
        # A partly revoked group needs a NEW artifact from the surviving input.
        repair = 0.0
        if use_risk and observed:
            members = set(group)
            repair = changes * sum(generation_cost(sorted(members - mask))
                                   for mask in observed if members & mask and members - mask) / len(observed)
        # A planning approximation: later active fractions are not guessed using
        # held-out events. All groups pay the same expected delivery count.
        delivery = deliveries * output_tokens(group) * input_price / 1_000_000
        return initial + repair + delivery

    merges = []
    if method == "whole":
        groups = [ids] if ids else []
    elif method == "single":
        groups = [[sid] for sid in ids]
    elif method == "fixed":
        groups = [ids[i:i + fixed_size] for i in range(0, len(ids), fixed_size)]
    elif method == "acl":
        buckets = defaultdict(list)
        for sid in ids:
            buckets[records[sid]["acl_group"]].append(sid)
        groups = [bucket[i:i + max_group] for _, bucket in sorted(buckets.items()) for i in range(0, len(bucket), max_group)]
    else:
        groups = [[sid] for sid in ids]
        while True:
            best = None
            for i, j in itertools.combinations(range(len(groups)), 2):
                merged = sorted(groups[i] + groups[j])
                if len(merged) > max_group:
                    continue
                delta = group_cost(merged) - group_cost(groups[i]) - group_cost(groups[j])
                candidate = (delta, tuple(merged), i, j)
                if delta < -1e-12 and (best is None or candidate < best):
                    best = candidate
            if best is None:
                break
            delta, merged, i, j = best
            merges.append({"left": groups[i], "right": groups[j], "delta_estimated_cny": delta})
            groups = [group for k, group in enumerate(groups) if k not in (i, j)] + [list(merged)]
            groups.sort(key=tuple)
    groups = sorted((sorted(group) for group in groups), key=tuple)
    flattened = [sid for group in groups for sid in group]
    if sorted(flattened) != ids or len(flattened) != len(set(flattened)):
        raise AssertionError("planner_partition_not_exact")
    return {
        "method": method,
        "groups": groups,
        "estimated_cost": sum(group_cost(group) for group in groups),
        "planning_ms": (time.perf_counter() - started) * 1000,
        "details": {
            "cost_is_planning_proxy_not_measured_effect": True,
            "semantic_features": "English-word/Chinese-bigram Jaccard" if use_semantics else None,
            "risk_enabled": use_risk,
            "historical_masks_used": len(observed) if use_risk else 0,
            "expected_changes_used": changes if use_risk else 0,
            "expected_deliveries": deliveries,
            "source_feature_hashes": {sid: hashlib.sha256(records[sid]["text"].encode("utf-8")).hexdigest() for sid in ids},
            "merges": merges,
            "warnings": ["No quality guarantee, optimality guarantee, or side-channel noninterference claim.",
                         "Initial grouping only; later authorization is enforced by the shared host.",
                         "Do not include planner text features/diagnostics in generation prompts."],
        },
    }
