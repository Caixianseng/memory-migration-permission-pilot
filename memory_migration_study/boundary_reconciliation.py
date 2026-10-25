"""Optional exact-occurrence reconciliation, retaining every input decision.

Only typed input findings may seed completion. Field labels alone do not make
all schema values sensitive. Structured field boundaries and literal same-core,
same-currency amounts may resolve a bad boundary; uncertain cross-field residue
blocks the result instead of being deleted. There is no lexical propagation,
registry-value lookup, model, filesystem access, or permission decision here.

This is a finding-set adapter, not a complete privacy detection. Existing
detect/prepare closure and egress checks are unchanged and may propagate a
retained literal back to another occurrence. Callers must measure that final
behavior independently rather than treating this audit as deployment evidence.
"""
from __future__ import annotations

from copy import deepcopy

from . import amount_candidates as amounts
from .candidate_proposals import _authority_fields, _exact_reference, _text_hash
from .privacy import _digest, _policy, _sources
from .structured_candidates import propose_field_findings


RECONCILIATION_VERSION = "typed_exact_occurrence_boundary_reconciliation_v1"
MAX_INPUT_FINDINGS = 4096
FIELD_VALUE_LIMIT = 256
_SEPARATORS = frozenset(":：=;；|｜")
_WRAPPERS_AND_TERMINATORS = frozenset("\"'“”‘’「」『』【】《》〈〉()（）[]{}<>,，。.!?！？")


def _ref(item):
    return {key: item[key] for key in ("source_id", "start", "end", "category")}


def _key(item):
    return item["source_id"], item["start"], item["end"], item["category"]


def _contains(outer, inner):
    return outer["source_id"] == inner["source_id"] and outer["start"] <= inner["start"] < inner["end"] <= outer["end"]


def _overlaps(first, second):
    return first["source_id"] == second["source_id"] and max(first["start"], second["start"]) < min(first["end"], second["end"])


def _amount_signature(sources, item):
    """No currency guessing: both sides must expose one literal currency/core."""
    sid, start, end = item["source_id"], item["start"], item["end"]
    text, literal = sources[sid], sources[sid][start:end]
    if not amounts._outer_boundary(text, start, end):
        return None
    full = amounts._FULL.fullmatch(literal)
    if full is not None:
        first = amounts._CURRENCIES[full["prefix"].casefold()]
        second = amounts._CURRENCIES[full["suffix"].casefold()]
        if first != second:
            return None
        return first, start+full.start("number"), start+full.end("number")
    for expression in (amounts._PREFIX, amounts._SUFFIX):
        match = expression.fullmatch(literal)
        if match is not None:
            return (amounts._CURRENCIES[match["currency"].casefold()],
                    start+match.start("number"), start+match.end("number"))
    return None


def _compatible_amount(sources, seed, target):
    first, second = _amount_signature(sources, seed), _amount_signature(sources, target)
    return first is not None and first == second


def _widest_nested(candidates):
    unique = {_key(item): item for item in candidates}
    if not unique:
        return None
    covering = [item for item in unique.values() if all(_contains(item, other) for other in unique.values())]
    if len(covering) != 1:
        raise ValueError("ambiguous_completion")
    return covering[0]


def _helper_bound(result, payload_hash, policy_hash, full_policy_hash, source_hashes):
    return (isinstance(result, dict) and result.get("status") == "candidates_only"
            and result.get("complete") is True and isinstance(result.get("findings"), list)
            and result.get("payload_sha256") == payload_hash and result.get("policy_sha256") == policy_hash
            and result.get("full_policy_sha256") == full_policy_hash and result.get("source_sha256") == source_hashes)


def reconcile_boundaries(payload, policy, existing_findings, *, max_candidates=128):
    """Return final candidate findings and complete local provenance decisions.

    A same-category seed inside an exact field value may be completed to that
    value. AMOUNT additionally requires matching literal currency and numerical
    source offsets. Only a recognized key occurrence can be classified as a
    field key; identical strings elsewhere are unaffected. A span crossing a
    proven key may be removed only when all its non-syntax characters remain
    covered by typed corrections/independent findings. Otherwise needs_review
    returns no usable findings. No schema-only value is automatically added.
    """
    result = {"version": RECONCILIATION_VERSION, "kind": "reconciled_findings_only",
              "status": "needs_review", "findings": [], "decisions": [], "additions": [],
              "errors": [], "original_findings": [], "payload_sha256": None, "policy_sha256": None,
              "full_policy_sha256": None, "existing_findings_sha256": None, "source_sha256": {},
              "candidate_limit": max_candidates if type(max_candidates) is int else None,
              "input_limit": MAX_INPUT_FINDINGS, "field_value_character_limit": FIELD_VALUE_LIMIT,
              "field_evidence": None, "amount_evidence": None,
              "local_calls": 0, "inference_kind": "deterministic",
              "scope": "typed_seeds_exact_occurrences_only_no_sensitivity_or_authorization_guarantee"}

    def fail(code):
        result.update(status="needs_review", findings=[])
        if code not in result["errors"]:
            result["errors"].append(code)
        recorded = {item["input_id"] for item in result["decisions"]}
        for index, original in enumerate(result["original_findings"]):
            iid = f"I{index+1:04d}"
            if iid not in recorded:
                result["decisions"].append({"input_id": iid, "input": _ref(original), "action": "needs_review",
                    "reason": code, "outputs": [], "evidence_ids": []})
        result["decisions"].sort(key=lambda item: item["input_id"])
        return result

    if type(max_candidates) is not int or not 1 <= max_candidates <= 4096:
        return fail("invalid_candidate_budget")
    if not isinstance(existing_findings, list) or len(existing_findings) > MAX_INPUT_FINDINGS:
        return fail("invalid_or_excessive_input_findings")
    if _authority_fields(payload) or _authority_fields(policy) or _authority_fields(existing_findings):
        return fail("authority_fields_not_allowed")
    try:
        payload, policy, originals = deepcopy((payload, policy, existing_findings))
        sources, normalized = _sources(payload), _policy(policy)
        result.update(payload_sha256=_digest(payload), policy_sha256=_digest(normalized),
                      full_policy_sha256=_digest(policy), existing_findings_sha256=_digest(originals),
                      source_sha256={sid: _text_hash(text) for sid, text in sources.items()})
        for item in originals:
            _exact_reference(item, sources, category_required=True)
            if "policy_id" in item and item["policy_id"] != normalized["policy_id"]:
                raise ValueError("invalid_input_binding")
        if any(len(text) > normalized["max_text_chars"] for text in sources.values()):
            return fail("source_character_budget_exceeded")
    except Exception:
        return fail("invalid_payload_policy_or_finding")
    result["original_findings"] = originals
    try:
        field = propose_field_findings(payload, policy, max_candidates=max_candidates,
                                      max_value_chars=FIELD_VALUE_LIMIT)
        amount = amounts.complete_amount_findings(payload, policy, originals, max_candidates=max_candidates)
        result.update(field_evidence=field, amount_evidence=amount)
        for value in (field, amount):
            if not _helper_bound(value, result["payload_sha256"], result["policy_sha256"],
                                 result["full_policy_sha256"], result["source_sha256"]):
                return fail("proposal_incomplete_or_binding_invalid")
            for item in value["findings"]:
                _exact_reference(item, sources, category_required=True)
        keys, boundaries = field["field_key_spans"], field["field_boundaries"]
        # Do not assume any upstream public hash authenticates a field key.
        for item in keys:
            sid, start, end = item["source_id"], item["start"], item["end"]
            if (sid not in sources or type(start) is not int or type(end) is not int
                    or not 0 <= start < end <= len(sources[sid]) or sources[sid][start:end] != item["quote"]):
                raise ValueError("invalid_field_evidence")
    except Exception:
        return fail("invalid_proposal_evidence")

    active = [dict(item, input_id=f"I{index+1:04d}") for index, item in enumerate(originals)
              if item["category"] in normalized["protected_categories"]]
    by_id = {item["input_id"]: item for item in active}
    target_catalog = [*field["findings"], *amount["findings"], *active]
    outputs, output_inputs, pending, decisions = {}, {}, [], {}

    def emit(item, input_id):
        identity = _key(item)
        if identity not in outputs:
            if len(outputs) == max_candidates:
                raise ValueError("output_candidate_budget_exceeded")
            outputs[identity] = {"source_id": item["source_id"], "start": item["start"], "end": item["end"],
                "quote": sources[item["source_id"]][item["start"]:item["end"]], "category": item["category"],
                "method": "exact_boundary_reconciliation"}
        output_inputs.setdefault(identity, set()).add(input_id)
        return _ref(outputs[identity])

    def decision(item, action, reason, refs=(), evidence=()):
        decisions[item["input_id"]] = {"input_id": item["input_id"], "input": _ref(item),
            "action": action, "reason": reason, "outputs": list(refs), "evidence_ids": list(evidence)}

    try:
        for item in active:
            contained_keys = [key for key in keys if _contains(key, item)]
            same_key = [key for key in contained_keys if key["category"] in {None, item["category"]}]
            if same_key:
                decision(item, "field_key", "exact_schema_key_occurrence", evidence=[key["key_id"] for key in same_key])
                continue
            # Crossing a known key is a syntactic conflict. A mere newline,
            # repeated word, or different literal elsewhere is never enough.
            crossed = [key for key in keys if _overlaps(key, item) and not _contains(key, item)]
            if crossed:
                pending.append((item, crossed))
                continue
            matching_fields = [target for target in field["findings"]
                if target["category"] == item["category"] and _contains(target, item)
                and (item["category"] != "AMOUNT" or _compatible_amount(sources, item, target))]
            target = _widest_nested(matching_fields)
            reason, action = "unchanged_typed_input", "retained"
            if target is not None and _key(target) != _key(item):
                reason, action = "same_category_exact_field_value", "field_completion"
            else:
                target = item
            if item["category"] == "AMOUNT":
                amount_targets = [candidate for candidate in target_catalog if candidate["category"] == "AMOUNT"
                    and _contains(candidate, item) and _compatible_amount(sources, item, candidate)]
                amount_target = _widest_nested(amount_targets)
                if amount_target is not None and _key(amount_target) != _key(item):
                    target, reason, action = amount_target, "same_currency_same_numeric_interval", "amount_completion"
            output_ref = emit(target, item["input_id"])
            decision(item, action, reason, [output_ref])

        # A crossing input may seed ONLY its overlapping same-category field
        # value. Different-category tail data needs independent typed coverage.
        for item, crossed in pending:
            for target in field["findings"]:
                if (target["category"] == item["category"] and _overlaps(target, item)
                        and (item["category"] != "AMOUNT" or _compatible_amount(sources, item, target))):
                    emit(target, item["input_id"])

        def covered_residue(item):
            text, left, right = sources[item["source_id"]], item["start"], item["end"]
            mask = [text[pos].isspace() for pos in range(left, right)]
            refs, evidence = [], []

            def cover(start, end):
                for pos in range(max(left, start), min(right, end)):
                    mask[pos-left] = True

            for out in outputs.values():
                if _overlaps(out, item):
                    cover(out["start"], out["end"])
                    refs.append(_ref(out))
            for key in keys:
                if _overlaps(key, item):
                    cover(key["start"], key["end"])
                    evidence.append(key["key_id"])
            for boundary in boundaries:
                if boundary["source_id"] != item["source_id"]:
                    continue
                start, end = boundary["value_container_start"], boundary["value_container_end"]
                if boundary["syntax"] != "markdown_header_cell":
                    a, b = boundary["key_end"], start
                    if a <= b and all(char.isspace() or char in _SEPARATORS for char in text[a:b]):
                        cover(a, b)
                a, b = boundary["value_start"], boundary["value_end"]
                if a is not None:
                    for x, y in ((start, a), (b, end)):
                        if all(char.isspace() or char in _WRAPPERS_AND_TERMINATORS for char in text[x:y]):
                            cover(x, y)
                next_key = boundary["next_key_start"]
                if next_key is not None and all(char.isspace() or char in _SEPARATORS for char in text[end:next_key]):
                    cover(end, next_key)
            residual, cursor = [], 0
            while cursor < len(mask):
                if mask[cursor]:
                    cursor += 1
                    continue
                finish = cursor+1
                while finish < len(mask) and not mask[finish]:
                    finish += 1
                residual.append({"source_id": item["source_id"], "start": left+cursor, "end": left+finish,
                                 "sha256": _text_hash(text[left+cursor:left+finish])})
                cursor = finish
            return residual, refs, evidence

        for item, crossed in pending:
            residue, refs, evidence = covered_residue(item)
            if residue:
                decision(item, "needs_review", "uncovered_cross_field_residual", refs,
                         [key["key_id"] for key in crossed])
                decisions[item["input_id"]]["residual_spans"] = residue
                result["errors"].append("uncovered_cross_field_residual")
            else:
                decision(item, "cross_field_corrected", "all_residual_covered_by_typed_values_or_field_syntax", refs, evidence)
        for index, item in enumerate(originals):
            iid = f"I{index+1:04d}"
            if iid not in by_id:
                decisions[iid] = {"input_id": iid, "input": _ref(item), "action": "out_of_scope",
                                  "reason": "outside_current_protected_categories", "outputs": [], "evidence_ids": []}
        result["decisions"] = [decisions[f"I{index+1:04d}"] for index in range(len(originals))]
        order = {sid: index for index, sid in enumerate(sources)}
        final = [outputs[key] for key in sorted(outputs, key=lambda key: (order[key[0]], key[1], key[2], key[3]))]
        original_keys = {_key(item) for item in originals}
        result["additions"] = [{"output": _ref(item), "seed_input_ids": sorted(output_inputs[_key(item)])}
                               for item in final if _key(item) not in original_keys]
        for item in final:
            item["provenance"] = [{"source_id": by_id[iid]["source_id"], "start": by_id[iid]["start"],
                                    "end": by_id[iid]["end"], "method": "reconciliation_typed_input"}
                                   for iid in sorted(output_inputs[_key(item)])]
        if result["errors"]:
            result["errors"] = sorted(set(result["errors"]))
            return fail("uncovered_cross_field_residual")
        result.update(status="ok", findings=final)
        return result
    except Exception:
        # Incomplete internal decisions never become an accepted partial pool.
        result["decisions"] = [decisions[key] for key in sorted(decisions)]
        return fail("reconciliation_invalid_or_over_budget")
