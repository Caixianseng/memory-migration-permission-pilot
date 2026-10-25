"""Optional, unvalidated semantic stages over a bound host detection.

Exactly one already-executed completion or role receipt is consumed per call.
Public hashes provide consistency, not authentication: the caller must supply
trusted result receipts. This function never runs a model or grants permissions.
The legacy closure, preparation, egress and restoration contracts remain intact.
"""
from __future__ import annotations

from copy import deepcopy

from . import candidate_adjudicator as roles
from . import candidate_proposals as proposals
from . import local_detector as runtime
from .privacy import _digest, _policy, _sources, _rule_findings, detect_sensitive


VERSION = "optional_single_stage_semantic_refinement_v1"
SEMANTIC_CATEGORIES = frozenset({"PERSON", "ADDRESS", "CUSTOMER", "PROJECT"})
KINDS = ("local_encoder", "local_generation", "unknown")


def _key(item):
    return item["source_id"], item["start"], item["end"], item["category"]


def _counts(receipt):
    """Retain reported costs even on a rejected stage; never clip repairs."""
    counts, complete = dict.fromkeys(KINDS, 0), False
    if not isinstance(receipt, dict):
        return counts, complete
    typed, calls, attempts = receipt.get("local_counts"), receipt.get("local_calls"), receipt.get("attempts")
    valid_calls = type(calls) is int and calls >= 0
    if (isinstance(typed, dict) and set(typed) == set(KINDS)
            and all(type(value) is int and value >= 0 for value in typed.values())):
        counts = dict(typed)
        complete = (valid_calls and sum(counts.values()) == calls
                    and receipt.get("generation_attempts") == calls
                    and type(receipt.get("generation_attempts")) is int
                    and receipt.get("local_calls_complete") is True
                    and receipt.get("local_call_unit") == "chat_POST_attempts"
                    and isinstance(attempts, list) and len(attempts) == calls
                    and all(isinstance(item, dict) and type(item.get("attempt")) is int
                            and item["attempt"] == index+1 for index, item in enumerate(attempts))
                    and counts["local_encoder"] == counts["unknown"] == 0
                    and 0 <= counts["local_generation"] <= 2)
    elif valid_calls:
        counts["unknown"] = calls
    return counts, complete


def _bound_stage(stage, *, status, version, payload, policy, normalized, pool):
    if (not isinstance(stage, dict) or stage.get("status") != status or stage.get("version") != version
            or stage.get("errors") != [] or stage.get("error") is not None
            or stage.get("payload_sha256") != _digest(payload)
            or stage.get("policy_sha256") != _digest(normalized)
            or stage.get("full_policy_sha256") != _digest(policy)
            or stage.get("pool_sha256") != pool["pool_sha256"]
            or stage.get("candidate_count") != len(pool["candidates"])
            or type(stage.get("candidate_count")) is not int
            or stage.get("model") != runtime.MODEL or stage.get("digest") != runtime.DIGEST
            or stage.get("runtime") != runtime.VERSION):
        raise ValueError("semantic_stage_binding_invalid")


def _completion_findings(payload, policy, normalized, pool, completion, sources):
    from . import span_completion as module
    from .structured_candidates import propose_field_findings
    _bound_stage(completion, status="completed_only", version=module.COMPLETION_VERSION,
                 payload=payload, policy=policy, normalized=normalized, pool=pool)
    selected = [item for item in pool["candidates"] if item["proposed_category"] in SEMANTIC_CATEGORIES]
    maximum = completion.get("max_quote_chars")
    if (type(maximum) is not int or not 1 <= maximum <= module.MAX_QUOTE_CHARS
            or completion.get("semantic_candidate_count") != len(selected)
            or type(completion.get("semantic_candidate_count")) is not int
            or not isinstance(completion.get("completions"), list)):
        raise ValueError("semantic_completion_schema_invalid")
    raw = []
    for item in completion["completions"]:
        if not isinstance(item, dict) or set(item) != {"cid", "source_id", "start", "end", "quote", "category"}:
            raise ValueError("semantic_completion_schema_invalid")
        raw.append({"cid": item["cid"], "quote": item["quote"]})
    field = propose_field_findings(payload, policy, max_candidates=4096, max_value_chars=6000)
    if (field.get("status") != "candidates_only" or field.get("complete") is not True
            or field.get("payload_sha256") != _digest(payload)
            or field.get("full_policy_sha256") != _digest(policy)):
        raise ValueError("semantic_completion_field_evidence_invalid")
    grounded, uncertain = module._ground({"completions": raw}, selected, sources, field, maximum)
    if uncertain or grounded != completion["completions"]:
        raise ValueError("semantic_completion_grounding_invalid")
    by_id = {item["cid"]: item for item in grounded}
    expected, untyped = [], []
    for candidate in pool["candidates"]:
        category = candidate["proposed_category"]
        if category is None:
            untyped.append({key: candidate[key] for key in ("cid", "source_id", "start", "end")})
        elif category in SEMANTIC_CATEGORIES:
            expected.append(by_id[candidate["cid"]])
        else:
            expected.append({key: candidate[key] for key in ("cid", "source_id", "start", "end", "quote")}
                            | {"category": category})
    if completion.get("findings") != expected or completion.get("untyped_candidates") != untyped:
        raise ValueError("semantic_completion_passthrough_changed")
    return [{key: item[key] for key in ("source_id", "start", "end", "quote", "category")}
            for item in expected]


def refine_semantics(payload, policy, baseline_detection, *, pool, completion=None, adjudication=None):
    """Apply one optional semantic stage, preserving every unrelated protection.

    ``pool`` must exactly be propose_candidates(current baseline findings), with
    the supplied pool's budgets. For a completion+role chain, first call this
    function with completion, construct a NEW pool from its final host findings,
    then call with adjudication. Receipts from the old CID pool cannot be reused.

    ``local_calls``/observations retain the shared baseline cost. ``local_counts``
    records ONLY this consumed stage, not baseline or earlier pipeline stages;
    a DAG runner must count each actual receipt once. This function itself makes
    zero model calls. A filtered occurrence may reappear through legacy closure.
    """
    stage = completion if completion is not None else adjudication
    counts, complete = _counts(stage)
    original = deepcopy(baseline_detection) if isinstance(baseline_detection, dict) else {}
    audit = {"version": VERSION, "status": "needs_review", "optional_unvalidated": True,
             "stage": "completion" if completion is not None else "roles",
             "local_counts": counts, "local_counts_complete": complete,
             "new_model_calls_by_this_function": 0, "removed": [], "registry_occurrences_retained": 0,
             "cost_scope": "current_consumed_receipt_only_excludes_shared_baseline_and_prior_stages"}
    failed = {**original, "status": "needs_review", "strategy": VERSION,
              "errors": list(original.get("errors", [])) if isinstance(original.get("errors"), list)
                        and all(isinstance(item, str) for item in original["errors"]) else [],
              "local_counts": counts, "local_counts_complete": complete, "semantic_refinement": audit}

    def reject(code):
        failed["errors"] = sorted(set(failed["errors"]+[code]))
        audit["error"] = code
        return failed

    if (completion is None) == (adjudication is None):
        return reject("exactly_one_semantic_stage_required")
    try:
        payload, policy, pool, stage = deepcopy((payload, policy, pool, stage))
        sources, normalized = roles._verified_pool(payload, policy, pool)
        if (original.get("status") != "ok" or original.get("errors") != []
                or original.get("payload_sha256") != _digest(payload)
                or original.get("policy_sha256") != _digest(normalized)
                or original.get("policy_version") != normalized["version"]
                or original.get("policy_id") != normalized["policy_id"]
                or original.get("protected_categories") != normalized["protected_categories"]
                or not isinstance(original.get("findings"), list)
                or type(original.get("local_calls")) is not int or original["local_calls"] < 0
                or original.get("local_calls_complete") is not True):
            return reject("semantic_baseline_binding_or_status_invalid")
        seeds, seen = [], set()
        for item in original["findings"]:
            sid, start, end, quote = proposals._exact_reference(item, sources, category_required=True)
            if item.get("policy_id") != normalized["policy_id"] or item["category"] not in normalized["protected_categories"]:
                return reject("semantic_baseline_finding_invalid")
            identity = (sid, start, end, item["category"])
            if identity in seen:
                return reject("semantic_duplicate_baseline_finding")
            seen.add(identity)
            seeds.append({"source_id": sid, "start": start, "end": end, "quote": quote, "category": item["category"]})
        expected_pool = proposals.propose_candidates(payload, policy, seeds,
            max_candidates=pool["candidate_budget"], max_quote_chars=pool["quote_character_budget"])
        if expected_pool.get("status") != "candidates_only" or expected_pool.get("pool_sha256") != pool["pool_sha256"]:
            return reject("semantic_pool_not_current_baseline")
        audit.update(baseline_detection_sha256=_digest(original), payload_sha256=_digest(payload),
                     full_policy_sha256=_digest(policy), pool_sha256=pool["pool_sha256"], stage_sha256=_digest(stage))
        if not complete:
            return reject("semantic_stage_call_accounting_incomplete")
        if completion is not None:
            final_seeds = _completion_findings(payload, policy, normalized, pool, stage, sources)
        else:
            _bound_stage(stage, status="adjudicated_only", version=roles.ADJUDICATOR_VERSION,
                         payload=payload, policy=policy, normalized=normalized, pool=pool)
            verdicts, expected_findings = roles._validate_verdicts({"verdicts": stage.get("verdicts")}, pool,
                                                                normalized["protected_categories"])
            if any(item["role"] == "uncertain" for item in verdicts):
                return reject("semantic_role_uncertain")
            if stage.get("findings") != expected_findings:
                return reject("semantic_role_findings_changed")
            final_seeds = []
            for candidate, verdict in zip(pool["candidates"], verdicts, strict=True):
                category = candidate["proposed_category"]
                if category is None:
                    continue  # A quoted untyped candidate cannot create evidence.
                if verdict["role"] == "value" and verdict["category"] != category:
                    return reject("semantic_role_category_changed")
                item = {key: candidate[key] for key in ("source_id", "start", "end", "quote")}
                item["category"] = category
                if category in SEMANTIC_CATEGORIES and verdict["role"] != "value":
                    audit["removed"].append({"cid": candidate["cid"], "role": verdict["role"],
                        **{key: item[key] for key in ("source_id", "start", "end", "category")}})
                else:
                    final_seeds.append(item)
        for sid, text in sources.items():
            for item in _rule_findings(text, sid, normalized):
                if item["method"] == "registry":
                    final_seeds.append({key: item[key] for key in ("source_id", "start", "end", "category")}
                                       | {"quote": text[item["start"]:item["end"]]})
                    audit["registry_occurrences_retained"] += 1
        by_source = {sid: [] for sid in sources}
        for item in final_seeds:
            proposals._exact_reference(item, sources, category_required=True)
            by_source[item["source_id"]].append({key: item[key] for key in ("start", "end", "quote", "category")})
        def replay(**kwargs):
            return {"status": "ok", "errors": [], "local_calls": 0, "elapsed_seconds": 0.0,
                    "findings": by_source[kwargs["source_id"]]}
        closed = detect_sensitive(payload, policy, mode="agent", agent=replay)
        result = deepcopy(original)
        result.update({key: closed[key] for key in ("status", "findings", "errors")})
        result.update(strategy=VERSION, mode="optional_semantic_"+audit["stage"], local_counts=counts,
                      local_counts_complete=complete, semantic_refinement=audit)
        final_keys = {_key(item) for item in closed["findings"]}
        audit.update(status=closed["status"], closure_applied=True, preparation_unchanged=True,
            closure_reintroduced_removed_occurrences=[item for item in audit["removed"] if _key(item) in final_keys])
        return result
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        return reject("semantic_stage_invalid")
