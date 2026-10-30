"""Source-context positive annotations projected onto exact extracted facts.

The trusted caller supplies original text, exact fact slices, policy, authority
and ACLs. The detector sees the full source once and proposes sensitivity spans
only. A signed label authenticates that proposal, not its semantic correctness
or complete coverage. Use the existing strict two-stage receiving path for a
current complete assessment; an empty source result never proves source safety.

Version 1 deliberately supports only CUSTOMER under the fixed strict relation
contract. Other categories require their own complete rule/semantic composition
and are refused rather than silently bypassing e.g. EMAIL rules.
"""
from __future__ import annotations

from copy import deepcopy
import math

from .memory_labels import MemoryLabelAuthority, _identifier, _version
from .principal_scope import normalize_principal_pairs
from .privacy import QUERY_SOURCE, _policy
from .sensitivity_contract import STRICT_CUSTOMER_RELATION, category_contract

VERSION = "source_context_exact_fact_annotation_v1"
COST_CONTRACT = "declared_adapter_bound_and_reported_calls_v1"


def _findings(values, text, categories, *, require_quote, code):
    if not isinstance(values, list):
        raise ValueError(code)
    result, seen = [], set()
    for item in values:
        required = {"start", "end", "category"} | ({"quote"} if require_quote else set())
        if (not isinstance(item, dict) or not required <= set(item)
                or set(item) - {"start", "end", "quote", "category"}
                or type(item.get("start")) is not int or type(item.get("end")) is not int
                or not 0 <= item["start"] < item["end"] <= len(text)
                or not isinstance(item.get("category"), str) or item["category"] not in categories
                or ("quote" in item and (not isinstance(item["quote"], str)
                    or item["quote"] != text[item["start"]:item["end"]]))):
            raise ValueError(code)
        key = (item["start"], item["end"], item["category"])
        if key in seen:
            raise ValueError(code + "_duplicate")
        # Nested positive constraints are safe to preserve. Partially crossing
        # spans are ambiguous annotations and require review, never clipping.
        for other in result:
            left, right = item["start"], item["end"]
            a, b = other["start"], other["end"]
            if left < b and a < right and not (left <= a and b <= right or a <= left and right <= b):
                raise ValueError(code + "_overlap")
        seen.add(key)
        result.append({"start": key[0], "end": key[1], "category": key[2]})
    return sorted(result, key=lambda row: (row["start"], row["end"], row["category"]))


def _facts(values, source_text, categories):
    if not isinstance(values, list) or not values:
        raise ValueError("invalid_exact_facts")
    result = []
    for fact in values:
        if not isinstance(fact, dict) or fact.get("status", "ok") != "ok":
            raise ValueError("invalid_exact_fact")
        start, end, text = fact.get("source_start"), fact.get("source_end"), fact.get("text")
        if (type(start) is not int or type(end) is not int or not isinstance(text, str)
                or not 0 <= start < end <= len(source_text) or source_text[start:end] != text):
            raise ValueError("fact_source_location_invalid")
        for other in result:
            if start < other["source_end"] and other["source_start"] < end:
                raise ValueError("duplicate_or_overlapping_exact_facts")
        positives = _findings(fact.get("findings"), text, categories,
                              require_quote=False, code="invalid_fact_finding")
        # Only these fields can reach authority.build_record. In particular,
        # model-supplied ownership, public/readers or grants are never forwarded.
        result.append({"text": text, "source_start": start, "source_end": end, "findings": positives})
    return result


def annotate_and_build_records(source, facts, policy, *, agent, authority,
                               owner_id, agent_id, allowed_principals,
                               builder_version, detector_version):
    """Assess full source once, validate exact facts, union positives, then sign.

    Findings returned by the callable must contain exact source-relative
    start/end/quote/category. Input fact findings are fact-relative positives;
    quote is optional there, but checked if supplied. Duplicate/overlapping facts,
    duplicate or partially crossing annotations, and source labels crossing a
    selected fact boundary all require review. Labels outside selected facts are
    counted and omitted, not relocated to equal strings elsewhere.

    A trusted adapter must explicitly declare max_local_calls (1..4) and return
    bounded integer local_calls plus finite nonnegative elapsed_seconds. For the
    existing OccurrenceQwenAgent, missing local_calls_complete means the reported
    bounded counter is complete under this wrapper's adapter contract; explicit
    False or malformed values are refused. This is cost accounting, not a claim
    that semantic extraction was exhaustive. No authority/key is returned.

    All failures return needs_review with no records, including source unknown,
    error, invalid spans or incomplete cost. Original responses are deep-copied
    before validation and preserved separately from wrapper metadata.
    """
    result = {"status": "needs_review", "records": [], "source_response": None,
              "annotation_state": "unavailable",
              "errors": [], "local_calls": 0, "local_calls_complete": True,
              "agent_elapsed_seconds": 0.0,
              "projection": {"version": VERSION, "cost_contract": COST_CONTRACT,
                  "assessment": "not_assessed", "semantic_completeness_proven": False,
                  "fact_count": 0, "source_finding_count": 0,
                  "projected_source_finding_count": 0, "unprojected_source_finding_count": 0,
                  "facts": []}}

    def fail(code):
        result["errors"].append(code)
        return result

    try:
        normalized = _policy(policy)
        if (normalized["protected_categories"] != ["CUSTOMER"]
                or normalized.get("category_contract") != category_contract(STRICT_CUSTOMER_RELATION)):
            return fail("unsupported_source_annotation_policy")
        if (not isinstance(source, dict) or not _identifier(source.get("source_id"))
                or source["source_id"] == QUERY_SOURCE or not isinstance(source.get("text"), str)
                or not source["text"] or len(source["text"]) > normalized["max_text_chars"]):
            return fail("invalid_source_annotation_input")
        trusted_source = {"source_id": source["source_id"], "text": source["text"]}
        safe_facts = _facts(facts, trusted_source["text"], normalized["protected_categories"])
        if (not isinstance(authority, MemoryLabelAuthority) or not callable(agent)
                or not _identifier(owner_id) or not _identifier(agent_id)
                or not _version(builder_version) or not _version(detector_version)):
            return fail("invalid_trusted_annotation_metadata")
        principals = normalize_principal_pairs(allowed_principals)
    except (ValueError, TypeError, KeyError):
        return fail("invalid_source_annotation_input")
    result["projection"]["fact_count"] = len(safe_facts)
    try:
        call_limit = getattr(agent, "max_local_calls", None)
    except Exception:
        call_limit = None
    if type(call_limit) is not int or not 1 <= call_limit <= 4:
        result["local_calls_complete"] = False
        return fail("invalid_source_agent_call_contract")
    try:
        response = agent(text=trusted_source["text"], source_id=trusted_source["source_id"],
                         policy=deepcopy(normalized), rule_findings=[])
        result["source_response"] = deepcopy(response)
    except Exception:
        result["local_calls_complete"] = False
        return fail("source_agent_error")
    result["projection"]["assessment"] = "requires_review"
    result["annotation_state"] = "needs_review"
    if not isinstance(response, dict):
        result["local_calls_complete"] = False
        return fail("invalid_source_agent_response")
    calls, elapsed = response.get("local_calls"), response.get("elapsed_seconds")
    if type(calls) is int and 0 <= calls <= call_limit:
        result["local_calls"] = calls
    else:
        result["local_calls_complete"] = False
        result["errors"].append("invalid_source_agent_calls")
    try:
        elapsed_valid = type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
    except OverflowError:
        elapsed_valid = False
    if elapsed_valid:
        result["agent_elapsed_seconds"] = elapsed
    else:
        result["local_calls_complete"] = False
        result["errors"].append("invalid_source_agent_elapsed")
    complete = response.get("local_calls_complete", True)
    result["projection"]["cost_completeness_basis"] = (
        "explicit_adapter_report" if "local_calls_complete" in response else "declared_adapter_counter_contract")
    if complete is not True:
        result["local_calls_complete"] = False
        result["errors"].append("source_agent_cost_incomplete")
    if response.get("status") != "ok":
        result["errors"].append("source_agent_requires_review")
    errors = response.get("errors")
    if not isinstance(errors, list) or errors:
        result["errors"].append("source_agent_reported_errors")
    if result["errors"]:
        return result
    try:
        positives = _findings(response.get("findings"), trusted_source["text"],
                              normalized["protected_categories"], require_quote=True,
                              code="invalid_source_finding")
        result["projection"]["source_finding_count"] = len(positives)
        for index, fact in enumerate(safe_facts):
            projected = []
            start, end = fact["source_start"], fact["source_end"]
            for finding in positives:
                if finding["start"] < end and start < finding["end"]:
                    if not start <= finding["start"] < finding["end"] <= end:
                        return fail("source_finding_crosses_fact_boundary")
                    projected.append({"start": finding["start"] - start, "end": finding["end"] - start,
                                      "category": finding["category"]})
            existing = fact["findings"]
            union = {(f["start"], f["end"], f["category"]) for f in existing + projected}
            fact["findings"] = _findings(
                [{"start": a, "end": b, "category": c} for a, b, c in sorted(union)],
                fact["text"], normalized["protected_categories"], require_quote=False,
                code="invalid_projected_fact_finding")
            result["projection"]["facts"].append({"fact_index": index, "source_start": start,
                "source_end": end, "existing_positive_count": len(existing),
                "projected_source_finding_count": len(projected), "union_positive_count": len(union)})
            result["projection"]["projected_source_finding_count"] += len(projected)
    except (ValueError, TypeError, KeyError):
        return fail("invalid_source_findings")
    result["projection"]["unprojected_source_finding_count"] = (
        len(positives) - result["projection"]["projected_source_finding_count"])
    # No record is exposed until every source span and fact has been validated.
    try:
        records = [authority.build_record(trusted_source, fact, normalized,
            owner_id=owner_id, agent_id=agent_id, allowed_principals=principals,
            builder_version=builder_version, detector_version=detector_version) for fact in safe_facts]
    except (ValueError, TypeError, KeyError):
        return fail("source_record_signing_failed")
    result.update(status="ok", records=records)
    result["annotation_state"] = "positive" if positives else "observed_empty"
    result["projection"]["assessment"] = "assessed_completeness_unproven"
    return result
