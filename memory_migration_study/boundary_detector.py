"""Optional boundary refinement with the existing privacy closure preserved.

This module does not authenticate saved detections or authorize memory. Callers
must use a trusted detector/result receipt and still use prepare/restore with
their real authorizer. Public hashes bind inputs, not provenance or identity.
"""
from __future__ import annotations

import copy

from .privacy import _digest, _policy, _sources, _rule_findings, detect_sensitive

VERSION = "boundary_refined_detection_v1"


def refine_detection(payload, policy, detection):
    """Refine one bound successful result, then run the normal final closure.

    Historical detector calls are retained, not counted as new inference.
    Malformed/non-ok input never becomes a successful empty detection.
    The optional result is directly compatible with prepare_private_payload.
    """
    from .boundary_reconciliation import reconcile_boundaries

    original = copy.deepcopy(detection) if isinstance(detection, dict) else {}
    failed = {**original, "status": "needs_review", "strategy": VERSION,
              "errors": sorted(set(original.get("errors", [])))
                        if isinstance(original.get("errors"), list)
                        and all(isinstance(x, str) for x in original["errors"]) else [],
              "boundary_refinement": {"status": "needs_review", "new_model_calls": 0}}

    def reject(error):
        failed["errors"] = sorted(set(failed["errors"] + [error]))
        failed["boundary_refinement"]["error"] = error
        return failed

    try:
        sources, normalized = _sources(payload), _policy(policy)
    except (TypeError, ValueError):
        return reject("boundary_invalid_input")
    if (original.get("status") != "ok" or original.get("errors") != []
            or original.get("payload_sha256") != _digest(payload)
            or original.get("policy_sha256") != _digest(normalized)
            or original.get("policy_id") != normalized["policy_id"]
            or original.get("policy_version") != normalized["version"]
            or original.get("protected_categories") != normalized["protected_categories"]
            or not isinstance(original.get("findings"), list)):
        return reject("boundary_detection_binding_invalid")
    if (type(original.get("local_calls")) is not int or original["local_calls"] < 0
            or original.get("local_calls_complete") is not True):
        return reject("boundary_source_call_accounting_incomplete")
    seeds = []
    for finding in original["findings"]:
        if not isinstance(finding, dict):
            return reject("boundary_invalid_seed")
        sid, start, end, cat = (finding.get(k) for k in ("source_id", "start", "end", "category"))
        if (not isinstance(sid, str) or sid not in sources or type(start) is not int
                or type(end) is not int or not 0 <= start < end <= len(sources[sid])
                or cat not in normalized["protected_categories"]
                or finding.get("policy_id") != normalized["policy_id"]):
            return reject("boundary_invalid_seed")
        seeds.append({"source_id": sid, "start": start, "end": end, "category": cat,
                      "quote": sources[sid][start:end]})
    try:
        reconciliation = reconcile_boundaries(payload, policy, seeds)
    except Exception:
        return reject("boundary_reconciliation_failed")
    if not isinstance(reconciliation, dict) or reconciliation.get("status") != "ok":
        failed["boundary_refinement"]["reconciliation"] = reconciliation
        return reject("boundary_reconciliation_needs_review")
    by_source = {sid: [] for sid in sources}
    try:
        if not isinstance(reconciliation.get("findings"), list):
            return reject("boundary_invalid_reconciled_findings")
        for finding in reconciliation["findings"]:
            sid = finding.get("source_id")
            if sid not in by_source:
                return reject("boundary_invalid_reconciled_source")
            by_source[sid].append({k: finding[k] for k in ("start", "end", "quote", "category")})
    except (AttributeError, KeyError, TypeError):
        return reject("boundary_invalid_reconciled_findings")
    # A structural interpretation cannot declassify a value explicitly named
    # by the current business policy. Reapply only registry declarations, not
    # the old generic field rules which are being evaluated for correction.
    registry_retained = 0
    for sid, text in sources.items():
        for finding in _rule_findings(text, sid, normalized):
            if finding["method"] == "registry":
                by_source[sid].append({k: finding[k] for k in ("start", "end", "category")}
                                     | {"quote": text[finding["start"]:finding["end"]]})
                registry_retained += 1

    # Replay only exact, deterministic spans. The normal host validator, bounded
    # expansion, propagation and maximalization are intentionally still applied.
    def replay(**kwargs):
        return {"status": "ok", "findings": by_source[kwargs["source_id"]],
                "local_calls": 0, "elapsed_seconds": 0.0, "errors": []}

    closed = detect_sensitive(payload, policy, mode="agent", agent=replay)
    result = copy.deepcopy(original)
    result.update({key: closed[key] for key in ("status", "findings", "errors")})
    result["strategy"] = VERSION
    result["mode"] = "boundary_refined_" + str(original.get("mode", "unknown"))
    result["boundary_refinement"] = {
        "status": closed["status"], "new_model_calls": 0,
        "source_detection_sha256": _digest(original),
        "full_policy_sha256": _digest(policy), "reconciliation": reconciliation,
        "closure_applied": True, "preparation_closure_unchanged": True,
        "explicit_registry_occurrences_retained": registry_retained,
    }
    return result


def detect_with_boundaries(payload, policy, *, agent, mode="combined"):
    """Run a real detector once, then apply the optional deterministic stage."""
    return refine_detection(payload, policy,
                            detect_sensitive(payload, policy, agent=agent, mode=mode))
