"""Offline response replay and scoring; this module never loads a model or a file.

The driver must close all raw predictions before loading and passing a reference.
Preparation accepts no reference, fact slot, or reference-derived registry.
"""
from __future__ import annotations

import copy
import hashlib
import json

from memory_migration_study import privacy
from memory_migration_study.sensitivity_contract import category_contract

PROFILES = ("strict_customer_relation", "any_specific_organization")
ARMS = ("occurrence_qwen", "gliner_relation", "nli_relation")
STATUSES = ("ok", "needs_review", "coverage_review", "unsupported", "engineering_error", "model_output_invalid", "invalid")
ACTOR = "probe_user"
WRONG_ACTOR = "probe_other"
VERSION = "relation_probe_scoring_v1"


def _hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def _text_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _runtime_hash(texts):
    runtime = {"schema_version": "relation_occurrence_probe_runtime_v1", "texts": texts}
    return hashlib.sha256((json.dumps(runtime, ensure_ascii=False, indent=2) + "\n").encode("utf-8")).hexdigest()


def _source_payload(text, source_id):
    if not isinstance(text, str) or not isinstance(source_id, str) or not source_id or source_id == "__query__":
        raise ValueError("relation_probe_invalid_source")
    return {"query": "", "memories": [{"source_id": source_id, "text": text}]}


class ReplayDetector:
    """Replay one captured response only for its exact source and normalized policy."""

    max_local_calls = 1

    def __init__(self, text, source_id, policy, response):
        self.payload = _source_payload(text, source_id)
        self.policy = privacy._policy(policy)
        self.response = copy.deepcopy(response)
        contract = self.policy.get("category_contract")
        self.binding = {"text_sha256": _text_hash(text), "source_id": source_id,
                        "source_payload_sha256": _hash(self.payload), "policy_sha256": _hash(self.policy),
                        "category_contract_sha256": _hash(contract) if contract is not None else None,
                        "response_sha256": _hash(self.response)}

    def __call__(self, *, text, source_id, policy, rule_findings):
        if (text != self.payload["memories"][0]["text"] or source_id != self.binding["source_id"]
                or _hash(privacy._policy(policy)) != self.binding["policy_sha256"] or rule_findings != []):
            raise ValueError("relation_probe_replay_binding_mismatch")
        response = copy.deepcopy(self.response)
        if isinstance(response, dict):
            # Historical physical calls remain in the driver's original response.
            # This operation performs no new generation or encoder inference.
            response.update(local_calls=0, elapsed_seconds=0.0)
        return response


def prepare_observation(text, policy, response, *, source_id="probe"):
    """Run the real combined detector and authorized preparation with a bound replay."""
    replay = ReplayDetector(text, source_id, policy, response)
    normalized = replay.policy
    payload = copy.deepcopy(replay.payload)
    detection = privacy.detect_sensitive(payload, normalized, agent=replay, mode="combined")
    binding = copy.deepcopy(replay.binding)
    binding_sha256 = _hash(binding)

    def authorizer(sid, actor, version):
        return sid == source_id and actor == ACTOR and version == normalized["version"]

    kwargs = {"request_id": "relation-probe-" + binding_sha256[:24],
              "policy_version": normalized["version"], "sensitivity_policy": normalized,
              "authorizer": authorizer}
    prepared = privacy.prepare_private_payload(payload, detection, actor_id=ACTOR, **kwargs)
    acl = {"status": "not_exercised", "reason": "primary_preparation_not_ready"}
    if prepared["status"] == "ok":
        denied = privacy.prepare_private_payload(payload, detection, actor_id=WRONG_ACTOR, **kwargs)
        if (denied.get("status") != "needs_review" or denied.get("error") != "memory_authorization_failed"
                or denied.get("payload") is not None):
            raise RuntimeError("relation_probe_acl_negative_control_failed")
        acl = {"status": "rejected", "actor_id": WRONG_ACTOR, "prepare_status": denied["status"],
               "error": denied["error"], "payload_is_none": True}
    # The RestorationMap capability stays in this stack frame and is never returned.
    return {"schema_version": "relation_probe_preparation_v1", "status": prepared["status"],
            "error": prepared["error"], "payload": copy.deepcopy(prepared["payload"]),
            "metadata": copy.deepcopy(prepared["metadata"]), "detection": copy.deepcopy(detection),
            "binding": binding, "binding_sha256": binding_sha256, "acl_negative_control": acl,
            "local_calls": 0, "new_model_calls": 0}


def _spans(findings, text, *, reference=False):
    if not isinstance(findings, list):
        raise ValueError("relation_probe_invalid_findings")
    result = set()
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("relation_probe_invalid_finding")
        start, end = item.get("start"), item.get("end")
        quote = item.get("text" if reference else "quote")
        if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text)
                or item.get("category") != "CUSTOMER" or quote != text[start:end]):
            raise ValueError("relation_probe_invalid_span")
        result.add((start, end, "CUSTOMER"))
    return result


def _validate_status(row, text):
    status, response = row["status"], row["response"]
    if status not in STATUSES:
        raise ValueError("relation_probe_invalid_status")
    if status in {"ok", "needs_review", "unsupported"}:
        if not isinstance(response, dict):
            raise ValueError("relation_probe_status_response_mismatch")
        wanted = [] if status == "ok" else (["semantic_uncertainty"] if status == "needs_review"
                                             else ["unsupported_category_contract"])
        if (response.get("status") != ("ok" if status == "ok" else "needs_review")
                or response.get("errors") != wanted):
            raise ValueError("relation_probe_status_response_mismatch")
        spans = _spans(response.get("findings"), text)
        if status == "unsupported" and (spans or response.get("local_calls") != 0):
            raise ValueError("relation_probe_invalid_unsupported")
        return spans if status == "ok" else set()
    # Invalid or engineering-failed model output is retained, never accepted as spans.
    return set()


def _payload_strings(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _payload_strings(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _payload_strings(item)]
    return []


def _validate_preparation(row, text):
    p = row["preparation"]
    if (not isinstance(p, dict) or p.get("schema_version") != "relation_probe_preparation_v1"
            or "mapping" in p or type(p.get("new_model_calls")) is not int or p["new_model_calls"] != 0
            or type(p.get("local_calls")) is not int or p["local_calls"] != 0):
        raise ValueError("relation_probe_invalid_preparation")
    b, detection = p.get("binding"), p.get("detection")
    if not isinstance(b, dict) or not isinstance(detection, dict) or p.get("binding_sha256") != _hash(b):
        raise ValueError("relation_probe_preparation_binding_mismatch")
    expected_payload = _source_payload(text, b.get("source_id"))
    if (b.get("text_sha256") != _text_hash(text) or b.get("source_payload_sha256") != _hash(expected_payload)
            or b.get("response_sha256") != _hash(row["response"])
            or b.get("category_contract_sha256") != _hash(category_contract(row["cell"]["profile"]))
            or detection.get("policy_sha256") != b.get("policy_sha256")
            or detection.get("payload_sha256") != b["source_payload_sha256"]
            or type(detection.get("local_calls")) is not int or detection["local_calls"] != 0):
        raise ValueError("relation_probe_preparation_binding_mismatch")
    acl = p.get("acl_negative_control")
    if not isinstance(acl, dict) or not isinstance(p.get("metadata"), dict):
        raise ValueError("relation_probe_invalid_preparation")
    if p.get("status") == "ok":
        if (row["status"] != "ok" or detection.get("status") != "ok" or detection.get("errors") != []
                or detection.get("local_calls_complete") is not True or p.get("error") is not None
                or not isinstance(p.get("payload"), dict) or p["metadata"].get("payload_sha256") != _hash(p["payload"])
                or p["metadata"].get("policy_sha256") != b["policy_sha256"]):
            raise ValueError("relation_probe_preparation_not_valid")
        sources = privacy._sources(p["payload"])
        if len(sources) != 2 or p["payload"].get("query") != "":
            raise ValueError("relation_probe_invalid_prepared_payload")
        if (acl.get("status") != "rejected" or acl.get("actor_id") != WRONG_ACTOR
                or acl.get("prepare_status") != "needs_review" or acl.get("error") != "memory_authorization_failed"
                or acl.get("payload_is_none") is not True):
            raise ValueError("relation_probe_acl_evidence_invalid")
        return True, _payload_strings(p["payload"])
    if (p.get("status") != "needs_review" or p.get("payload") is not None
            or not isinstance(p.get("error"), str) or not p["error"] or acl.get("status") != "not_exercised"):
        raise ValueError("relation_probe_invalid_blocked_preparation")
    return False, []


def _validate_grid(rows, texts, allow_small_sample):
    if (type(allow_small_sample) is not bool or not isinstance(texts, list) or not texts
            or any(not isinstance(t, str) or not t for t in texts) or len(set(texts)) != len(texts)
            or (not allow_small_sample and len(texts) != 12) or not isinstance(rows, list)):
        raise ValueError("relation_probe_invalid_runtime_or_rows")
    expected = {(i, p, a) for i in range(len(texts)) for p in PROFILES for a in ARMS}
    actual = []
    for row in rows:
        if not isinstance(row, dict) or not {"cell", "response", "status", "preparation"} <= set(row):
            raise ValueError("relation_probe_invalid_row")
        cell = row["cell"]
        if (not isinstance(cell, dict) or set(cell) != {"text_index", "profile", "arm"}
                or type(cell["text_index"]) is not int or cell["profile"] not in PROFILES or cell["arm"] not in ARMS):
            raise ValueError("relation_probe_invalid_cell")
        actual.append((cell["text_index"], cell["profile"], cell["arm"]))
    if len(actual) != len(expected) or len(set(actual)) != len(actual) or set(actual) != expected:
        raise ValueError("relation_probe_incomplete_or_duplicate_rows")


def _validate_reference(reference, texts):
    if (not isinstance(reference, dict) or reference.get("schema_version") != "relation_occurrence_probe_evaluation_v1"
            or reference.get("runtime_sha256") != _runtime_hash(texts)
            or reference.get("profile_contract_sha256") != {p: _hash(category_contract(p)) for p in PROFILES}):
        raise ValueError("relation_probe_reference_binding_mismatch")
    cases = reference.get("cases")
    if not isinstance(cases, list) or len(cases) != len(texts):
        raise ValueError("relation_probe_reference_indices_invalid")
    by_index = {}
    for case in cases:
        if (not isinstance(case, dict) or type(case.get("text_index")) is not int
                or not 0 <= case["text_index"] < len(texts) or case["text_index"] in by_index):
            raise ValueError("relation_probe_reference_indices_invalid")
        text = texts[case["text_index"]]
        expected = case.get("expected")
        if (case.get("text_sha256") != _text_hash(text) or not isinstance(expected, dict)
                or set(expected) != set(PROFILES)):
            raise ValueError("relation_probe_reference_text_mismatch")
        for p in PROFILES:
            cell = case["expected"][p]
            if not isinstance(cell, dict) or cell.get("decision") not in {"sensitive", "not_sensitive", "needs_review"}:
                raise ValueError("relation_probe_reference_decision_invalid")
            spans = _spans(cell.get("spans"), text, reference=True)
            values = list(dict.fromkeys(s["text"] for s in cell["spans"]))
            if cell.get("must_mask_values") != values or bool(spans) != (cell["decision"] == "sensitive"):
                raise ValueError("relation_probe_reference_values_invalid")
        fact = case.get("allowed_fact")
        if (not isinstance(fact, dict) or not isinstance(fact.get("slot_id"), str) or not fact["slot_id"]
                or fact.get("match") != "exact_substring" or not isinstance(fact.get("text"), str) or not fact["text"]
                or type(fact.get("start")) is not int or type(fact.get("end")) is not int
                or not 0 <= fact["start"] < fact["end"] <= len(text)
                or text[fact["start"]:fact["end"]] != fact["text"] or text.count(fact["text"]) != 1
                or any(v.casefold() in fact["text"].casefold()
                       for v in case["expected"][PROFILES[1]]["must_mask_values"])):
            raise ValueError("relation_probe_reference_fact_invalid")
        by_index[case["text_index"]] = case
    return by_index


def _rate(numerator, denominator):
    return numerator / denominator if denominator else None


def score_rows(rows, reference, texts, *, allow_small_sample=False):
    """Score a complete grid, with no mutation and no file/model access.

    Default: exactly 12 texts * 2 profiles * 3 arms = 72 rows. Tests may opt into
    fewer texts, but still need every profile/arm for every supplied text.
    """
    # No reference access or scoring is allowed before completeness is established.
    _validate_grid(rows, texts, allow_small_sample)
    by_index = _validate_reference(reference, texts)
    scored, groups = copy.deepcopy(rows), {}
    for row in scored:
        cell = row["cell"]
        text, case = texts[cell["text_index"]], by_index[cell["text_index"]]
        predicted = _validate_status(row, text)
        sent, payload_strings = _validate_preparation(row, text)
        expected = case["expected"][cell["profile"]]
        known = expected["decision"] != "needs_review"
        gold = _spans(expected["spans"], text, reference=True)
        actual = ("sensitive" if predicted else "not_sensitive") if row["status"] == "ok" else row["status"]
        decision_match = actual == expected["decision"] and row["status"] in {"ok", "needs_review"}
        exact = (row["status"] == "ok" and decision_match and predicted == gold) if known else None
        span_score = {"tp": len(predicted & gold), "fp": len(predicted - gold), "fn": len(gold - predicted)} if known else None
        folded = [s.casefold() for s in payload_strings]
        leaked = sum(any(v.casefold() in s for s in folded) for v in expected["must_mask_values"]) if sent else 0
        retained = sent and any(case["allowed_fact"]["text"] in s for s in payload_strings)
        row["score"] = {"expected_decision": expected["decision"], "actual_decision": actual,
                        "decision_matches": decision_match, "determinate_exact_match": exact,
                        "span_score": span_score, "payload_sent": sent, "required_raw_leak": bool(leaked),
                        "leaked_required_value_count": leaked, "allowed_fact_retained": retained}
        key = cell["profile"] + "/" + cell["arm"]
        g = groups.setdefault(key, {"cells": 0, **{s: 0 for s in STATUSES}, "tp": 0, "fp": 0, "fn": 0,
            "decision_matches": 0, "determinate_cells": 0, "determinate_exact_matches": 0,
            "determinate_processable_cells": 0, "determinate_unnecessary_review_cells": 0,
            "unknown_cells": 0, "unknown_review_matches": 0, "unknown_clean_negative_cells": 0,
            "processable_cells": 0, "payload_sent_cells": 0, "required_raw_leak_cells": 0,
            "allowed_fact_retained_cells": 0, "determinate_payload_sent_cells": 0,
            "determinate_allowed_fact_retained_cells": 0, "acl_exercised": 0, "acl_rejected": 0,
            "acl_not_exercised": 0})
        g["cells"] += 1
        g[row["status"]] += 1
        for metric, value in (span_score or {}).items():
            g[metric] += value
        g["decision_matches"] += int(decision_match)
        g["determinate_cells"] += int(known)
        g["determinate_exact_matches"] += int(exact is True)
        g["determinate_processable_cells"] += int(known and row["status"] == "ok")
        g["determinate_unnecessary_review_cells"] += int(known and row["status"] == "needs_review")
        g["unknown_cells"] += int(not known)
        g["unknown_review_matches"] += int(not known and decision_match)
        g["unknown_clean_negative_cells"] += int(not known and row["status"] == "ok" and not predicted)
        g["processable_cells"] += int(row["status"] == "ok")
        g["payload_sent_cells"] += int(sent)
        g["required_raw_leak_cells"] += int(bool(leaked))
        g["allowed_fact_retained_cells"] += int(retained)
        g["determinate_payload_sent_cells"] += int(known and sent)
        g["determinate_allowed_fact_retained_cells"] += int(known and retained)
        g["acl_exercised"] += int(sent)
        g["acl_rejected"] += int(sent)
        g["acl_not_exercised"] += int(not sent)
    for g in groups.values():
        for name, numerator, denominator in (
            ("precision", g["tp"], g["tp"] + g["fp"]), ("recall", g["tp"], g["tp"] + g["fn"]),
            ("decision_match_rate", g["decision_matches"], g["cells"]),
            ("determinate_exact_match_rate", g["determinate_exact_matches"], g["determinate_cells"]),
            ("determinate_processable_rate", g["determinate_processable_cells"], g["determinate_cells"]),
            ("unknown_review_match_rate", g["unknown_review_matches"], g["unknown_cells"]),
            ("processable_rate", g["processable_cells"], g["cells"]),
            ("payload_sent_rate", g["payload_sent_cells"], g["cells"]),
            ("required_raw_leak_rate_all", g["required_raw_leak_cells"], g["cells"]),
            ("required_raw_leak_rate_sent", g["required_raw_leak_cells"], g["payload_sent_cells"]),
            ("allowed_fact_retention_rate_all", g["allowed_fact_retained_cells"], g["cells"]),
            ("allowed_fact_retention_rate_sent", g["allowed_fact_retained_cells"], g["payload_sent_cells"]),
            ("determinate_allowed_fact_retention_rate_all", g["determinate_allowed_fact_retained_cells"], g["determinate_cells"]),
            ("determinate_allowed_fact_retention_rate_sent", g["determinate_allowed_fact_retained_cells"], g["determinate_payload_sent_cells"]),
            ("acl_rejection_rate_exercised", g["acl_rejected"], g["acl_exercised"])):
            g[name] = _rate(numerator, denominator)
    return {"schema_version": VERSION, "scored_rows": scored, "by_profile_arm": groups,
            "reference_object_sha256": _hash(reference), "runtime_sha256": _runtime_hash(texts),
            "rows": len(scored), "new_model_calls": 0,
            "driver_must_verify_prediction_closure_before_reference_loading": True}
