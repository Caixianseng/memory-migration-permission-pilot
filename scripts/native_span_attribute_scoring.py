"""Single-arm scoring using the original response/preparation validators.

No I/O or model imports. The caller must close predictions before loading gold.
"""
import copy
from scripts import relation_probe_scoring as original

ARM = "native_span_attributes"


def score_rows(rows, reference, texts):
    expected = {(i, p, ARM) for i in range(len(texts)) for p in original.PROFILES}
    if not isinstance(rows, list) or len(texts) != 12 or len(rows) != len(expected):
        raise ValueError("native_attribute_incomplete_grid")
    actual = []
    for row in rows:
        cell = row.get("cell", {})
        if set(cell) != {"text_index", "profile", "arm"} or type(cell["text_index"]) is not int:
            raise ValueError("native_attribute_invalid_cell")
        actual.append((cell["text_index"], cell["profile"], cell["arm"]))
    if set(actual) != expected or len(set(actual)) != len(actual):
        raise ValueError("native_attribute_incomplete_grid")
    refs = original._validate_reference(reference, texts)
    scored, groups = copy.deepcopy(rows), {}
    for row in scored:
        cell = row["cell"]
        text, case = texts[cell["text_index"]], refs[cell["text_index"]]
        predicted = original._validate_status(row, text)
        sent, payload_strings = original._validate_preparation(row, text)
        truth = case["expected"][cell["profile"]]
        known = truth["decision"] != "needs_review"
        gold = original._spans(truth["spans"], text, reference=True)
        decision = ("sensitive" if predicted else "not_sensitive") if row["status"] == "ok" else row["status"]
        matches = decision == truth["decision"] and row["status"] in {"ok", "needs_review"}
        exact = row["status"] == "ok" and matches and predicted == gold if known else None
        spans = {"tp": len(predicted & gold), "fp": len(predicted - gold), "fn": len(gold - predicted)} if known else None
        leak = sent and any(v.casefold() in value.casefold() for v in truth["must_mask_values"] for value in payload_strings)
        retained = sent and any(case["allowed_fact"]["text"] in value for value in payload_strings)
        row["score"] = {"decision_matches": matches, "determinate_exact_match": exact,
                        "span_score": spans, "payload_sent": sent, "required_raw_leak": bool(leak),
                        "allowed_fact_retained": retained}
        g = groups.setdefault(cell["profile"] + "/" + ARM, {
            "cells": 0, **{s: 0 for s in original.STATUSES}, "tp": 0, "fp": 0, "fn": 0,
            "determinate_cells": 0, "determinate_exact_matches": 0, "determinate_processable_cells": 0,
            "unknown_cells": 0, "unknown_review_matches": 0, "unknown_clean_negative_cells": 0,
            "payload_sent_cells": 0, "required_raw_leak_cells": 0, "determinate_allowed_fact_retained_cells": 0,
            "acl_exercised": 0, "acl_rejected": 0, "acl_not_exercised": 0})
        g["cells"] += 1
        g[row["status"]] += 1
        for key, value in (spans or {}).items():
            g[key] += value
        g["determinate_cells"] += int(known)
        g["determinate_exact_matches"] += int(exact is True)
        g["determinate_processable_cells"] += int(known and row["status"] == "ok")
        g["unknown_cells"] += int(not known)
        g["unknown_review_matches"] += int(not known and matches)
        g["unknown_clean_negative_cells"] += int(not known and row["status"] == "ok" and not predicted)
        g["payload_sent_cells"] += int(sent)
        g["required_raw_leak_cells"] += int(bool(leak))
        g["determinate_allowed_fact_retained_cells"] += int(known and retained)
        g["acl_exercised"] += int(sent)
        g["acl_rejected"] += int(sent)
        g["acl_not_exercised"] += int(not sent)
    for g in groups.values():
        for name, numerator, denominator in (
                ("precision", g["tp"], g["tp"] + g["fp"]), ("recall", g["tp"], g["tp"] + g["fn"]),
                ("required_raw_leak_rate_all", g["required_raw_leak_cells"], g["cells"]),
                ("required_raw_leak_rate_sent", g["required_raw_leak_cells"], g["payload_sent_cells"])):
            g[name] = numerator / denominator if denominator else None
    return {"schema": "native_span_attribute_scoring_v1", "scored_rows": scored, "by_profile_arm": groups,
            "rows": len(rows), "new_model_calls": 0, "reference_object_sha256": original._hash(reference)}
