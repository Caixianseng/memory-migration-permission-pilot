"""Opt-in, exact-candidate sensitivity typing; never an authorization layer.

Semantic NER/rule candidates may be rejected by a bound contextual verdict.
Format protections and explicit registry findings cannot be removed. Existing
boundary/repetition closure remains in force; this module does not change the
default detector, preparation, restore, or source permissions.
"""
from __future__ import annotations

from copy import deepcopy

from .candidate_proposals import propose_candidates
from .context_candidate_typing import validate_typing
from .privacy import _digest, _policy, _sources, detect_sensitive

VERSION = "context_typed_detection_v1"
SEMANTIC = frozenset({"PERSON", "CUSTOMER", "PROJECT", "ADDRESS"})


def _key(item):
    return tuple(item[k] for k in ("source_id", "start", "end", "category"))


def compose_typed_detection(payload, policy, baseline, pool, typing, *, promote_untyped=True):
    """Apply a validated stage to a current host baseline, with no model calls.

    ``promote_untyped=False`` is a shared-verdict mechanism ablation, not an
    independently optimized competing detector. All uncertain/invalid stages
    remain processing failures in the full material denominator.
    """
    result = deepcopy(baseline) if isinstance(baseline, dict) else {}
    audit = {"version": VERSION, "promote_untyped": promote_untyped,
             "status": "needs_review", "new_model_calls": 0,
             "promoted_untyped": [], "removed_semantic": [], "retained_immutable": [],
             "closure_reintroduced_removed": []}
    result["context_typing"] = audit

    def fail(code):
        result.update(status="needs_review", errors=[code], strategy=VERSION)
        audit["error"] = code
        return result

    try:
        if type(promote_untyped) is not bool:
            return fail("invalid_promotion_mode")
        sources, normalized = _sources(payload), _policy(policy)
        if (not isinstance(baseline, dict) or baseline.get("status") != "ok"
                or baseline.get("errors") != [] or baseline.get("local_calls_complete") is not True
                or type(baseline.get("local_calls")) is not int or baseline["local_calls"] < 0
                or baseline.get("payload_sha256") != _digest(payload)
                or baseline.get("policy_sha256") != _digest(normalized)
                or baseline.get("policy_id") != normalized["policy_id"]
                or baseline.get("policy_version") != normalized["version"]
                or baseline.get("protected_categories") != normalized["protected_categories"]):
            return fail("context_baseline_binding_invalid")
        expected_pool = propose_candidates(payload, policy, baseline["findings"],
            max_candidates=pool.get("candidate_budget"), max_quote_chars=pool.get("quote_character_budget"))
        if expected_pool.get("status") != "candidates_only" or expected_pool != pool:
            return fail("context_pool_not_current_baseline")
        calls = typing.get("local_calls")
        if type(calls) is not int or not 0 <= calls <= 2 or typing.get("local_calls_complete") is not True:
            return fail("context_typing_accounting_invalid")
        result["local_calls"] = baseline["local_calls"] + calls
        result["local_counts"] = {"baseline_local_calls": baseline["local_calls"], "context_generations": calls}
        audit["generation_calls"] = calls
        if typing.get("status") != "typing_only":
            return fail("context_typing_needs_review")
        validated = validate_typing(payload, policy, pool, typing)
        verdicts = {item["cid"]: item for item in validated["verdicts"]}
        values = {item["cid"]: item for item in validated["findings"]}
        baseline_by_key = {_key(item): item for item in baseline["findings"]}
        seeds = []
        immutable = set()
        for item in baseline["findings"]:
            sid, start, end, category = _key(item)
            if (sid not in sources or type(start) is not int or type(end) is not int
                    or not 0 <= start < end <= len(sources[sid])
                    or category not in normalized["protected_categories"]):
                return fail("context_baseline_span_invalid")
            if category not in SEMANTIC or "registry" in item.get("method", "").split("+"):
                immutable.add(_key(item))
                seeds.append({"source_id": sid, "start": start, "end": end,
                              "category": category, "quote": sources[sid][start:end]})
                audit["retained_immutable"].append(list(_key(item)))
        for candidate in pool["candidates"]:
            cid = candidate["cid"]
            proposed = candidate["proposed_category"]
            original_key = (candidate["source_id"], candidate["start"], candidate["end"], proposed)
            if original_key in immutable:
                continue
            verdict = verdicts[cid]
            if verdict["mention_role"] == "uncertain":
                return fail("context_typing_uncertain")
            if verdict["mention_role"] != "value":
                if original_key in baseline_by_key:
                    audit["removed_semantic"].append({"cid": cid, "span": list(original_key),
                                                       "role": verdict["mention_role"]})
                continue
            value = values[cid]
            if proposed is not None and value["category"] != proposed:
                return fail("context_typed_category_changed")
            if proposed is None:
                if not promote_untyped:
                    continue
                audit["promoted_untyped"].append(cid)
            seeds.append({key: value[key] for key in ("source_id", "start", "end", "category", "quote")})
        by_source = {sid: [] for sid in sources}
        for item in seeds:
            by_source[item["source_id"]].append({k: item[k] for k in ("start", "end", "category", "quote")})
        def replay(**kwargs):
            return {"status": "ok", "findings": by_source[kwargs["source_id"]], "errors": [],
                    "local_calls": 0, "elapsed_seconds": 0.0}
        # Do not rerun combined mode: that would silently re-add rejected rules.
        closed = detect_sensitive(payload, policy, mode="agent", agent=replay)
        result.update({key: closed[key] for key in ("status", "findings", "errors")})
        result.update(strategy=VERSION, mode="optional_context_typed_detection")
        final = {_key(item) for item in result["findings"]}
        audit["closure_reintroduced_removed"] = [item for item in audit["removed_semantic"] if tuple(item["span"]) in final]
        audit.update(status=result["status"], baseline_sha256=_digest(baseline),
                     typing_sha256=_digest(typing), pool_sha256=pool["pool_sha256"],
                     default_preparation_unchanged=True, source_permissions_unchanged=True)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        return fail("context_typing_or_binding_invalid")
