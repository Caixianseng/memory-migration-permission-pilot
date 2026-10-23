"""Score actual masking intervals after preparation; gold never enters the pipeline."""
from __future__ import annotations

import copy
import re
import uuid

from .privacy_corpus import _digest, validate_corpus


TOKEN = re.compile(r"\[PVT_[A-F0-9]{24}_[A-Z]+_\d+\]")


def masking_intervals(original, masked, entries):
    """Validate an exact left-to-right transformation, allowing spelling case.

    This is a local scoring instrument. It reads an ephemeral mapping but returns
    offsets only, never an exported token-to-plaintext dictionary.
    """
    source_cursor, masked_cursor, intervals = 0, 0, []
    for token in TOKEN.finditer(masked):
        unchanged = masked[masked_cursor:token.start()]
        if original[source_cursor:source_cursor + len(unchanged)] != unchanged:
            raise ValueError("mask_trace_unaligned")
        source_cursor += len(unchanged)
        entry = entries.get(token.group())
        if entry is None:
            raise ValueError("mask_trace_unknown_token")
        match = re.match(re.escape(entry.value), original[source_cursor:], re.IGNORECASE)
        if match is None:
            raise ValueError("mask_trace_value_mismatch")
        intervals.append((source_cursor, source_cursor + match.end()))
        source_cursor += match.end()
        masked_cursor = token.end()
    if original[source_cursor:] != masked[masked_cursor:]:
        raise ValueError("mask_trace_suffix_mismatch")
    return intervals


def evaluate_prepared_payloads(runtime, evaluation, detection_cache, *, privacy_module, egress_module):
    validate_corpus(runtime, evaluation)
    gold = {row["case_id"]: row["findings"] for row in evaluation["cases"]}
    rows = []
    for case in runtime["cases"]:
        source, policy = case["payload"], case["sensitivity_policy"]
        key = _digest({"case_id": case["case_id"], "payload": source, "policy": policy, "mode": "combined"})
        if key not in detection_cache["entries"]:
            raise ValueError("combined_detection_missing")
        detection = copy.deepcopy(detection_cache["entries"][key]["result"])
        ids = {m["source_id"] for m in source["memories"]}
        prepared = privacy_module.prepare_private_payload(copy.deepcopy(source), detection,
            actor_id="synthetic_owner", request_id=str(uuid.uuid4()), policy_version=policy["version"],
            sensitivity_policy=policy,
            authorizer=lambda sid, actor, version: sid in ids and actor == "synthetic_owner" and version == policy["version"])
        row = {"case_id": case["case_id"], "split": case["split"], "language": case["language"],
               "status": "blocked", "error": prepared.get("error"), "gold_spans": len(gold[case["case_id"]]),
               "complete_masked_spans": None, "partial_masked_spans": None, "unmasked_spans": None,
               "masked_unprotected_characters": None, "all_sensitive_spans_masked": None}
        if prepared["status"] == "ok":
            check = egress_module.validate_outbound(source, prepared, detection, policy)
            row["egress_status"], row["error"] = check["status"], check["code"]
            if check["status"] == "ok":
                try:
                    texts = [("__query__", source["query"], prepared["payload"]["query"])]
                    texts += [(m["source_id"], m["text"], out["text"]) for m, out in zip(source["memories"], prepared["payload"]["memories"])]
                    covered = {(sid, pos) for sid, text, masked in texts
                               for start, end in masking_intervals(text, masked, prepared["mapping"]._entries)
                               for pos in range(start, end)}
                    sensitive = set()
                    complete = partial = unmasked = 0
                    for span in gold[case["case_id"]]:
                        chars = {(span["source_id"], pos) for pos in range(span["start"], span["end"])}
                        sensitive |= chars
                        if chars <= covered:
                            complete += 1
                        elif chars & covered:
                            partial += 1
                        else:
                            unmasked += 1
                    row.update(status="ready", complete_masked_spans=complete, partial_masked_spans=partial,
                               unmasked_spans=unmasked, masked_unprotected_characters=len(covered - sensitive),
                               all_sensitive_spans_masked=partial + unmasked == 0)
                except ValueError as exc:
                    row.update(status="instrumentation_error", error=str(exc))
        prepared["mapping"] = None
        rows.append(row)
    summaries = []
    for split in ("all", "dev", "heldout"):
        selected = [r for r in rows if split == "all" or r["split"] == split]
        ready = [r for r in selected if r["status"] == "ready"]
        summaries.append({"split": split, "registered_cases": len(selected), "ready_cases": len(ready),
            "blocked_cases": sum(r["status"] == "blocked" for r in selected),
            "instrumentation_errors": sum(r["status"] == "instrumentation_error" for r in selected),
            "ready_cases_with_incomplete_masking": sum(r["all_sensitive_spans_masked"] is False for r in ready),
            "ready_gold_spans": sum(r["gold_spans"] for r in ready),
            "complete_masked_spans": sum(r["complete_masked_spans"] for r in ready),
            "partial_masked_spans": sum(r["partial_masked_spans"] for r in ready),
            "unmasked_spans": sum(r["unmasked_spans"] for r in ready),
            "masked_unprotected_characters": sum(r["masked_unprotected_characters"] for r in ready)})
    return {"schema_version": 1, "kind": "gold_scoring_of_actual_prepared_payloads", "rows": rows,
            "summaries": summaries, "remote_model_calls": 0, "additional_detector_calls": 0,
            "runtime_sha256": _digest(runtime), "evaluation_sha256": _digest(evaluation),
            "authorization_scope": "synthetic_owner_allowlist_for_runtime_memory_ids_only",
            "task_correctness": None, "mapping_persisted": False,
            "scope": "Gold used after preparation for scoring only; ready-only privacy rates must retain blocked denominator; no semantic reidentification claim."}
