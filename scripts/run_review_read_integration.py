"""Freeze and execute the finite read/permission/privacy/task integration.

Use --plan-only first, then --execute with that plan and a fresh output path.
Only --model-mode local enables bounded loopback model requests; no cloud API.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_review_native_read_chain as chain
from memory_migration_study.review_read_consumer import (
    CONSUMER_VERSION, MODEL, OPTIONS, QUERY, SYSTEM, ReadChainConsumer,
)


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def score_after_close(output, consumer, mode):
    from memory_migration_study.paired_task_metrics import close_predictions, score_closed
    cells = json.loads((output / "cells.json").read_text(encoding="utf-8"))
    snapshots = json.loads((output / "source_snapshots.json").read_text(encoding="utf-8"))
    if len(snapshots) != 6 or any(cell["source_status"] not in {"available", "denied"} for cell in cells):
        result = {"status": "not_scored_unqualified_source_reference", "registered_cells": len(cells),
                  "registered_task_arm_rows": len(cells) * 4,
                  "reason": "Raw registered cells and partial predictions are retained; no inferred native denial."}
        save(output / "paired_task_scores.json", result)
        return result
    references = {(view["direction"], oid): row["text"] for view in snapshots for oid, row in view["records"].items()}
    predictions = []
    query_sha = hashlib.sha256(QUERY.encode()).hexdigest()
    invariant = {"model": MODEL if mode == "local" else "deterministic-fixed-control",
        "prompt_version": CONSUMER_VERSION, "input_token_limit": 4096, "output_token_limit": 64,
        "retrieval_interface": "exact_object_id_raw", "ranking": "single_preselected_object",
        "answer_interface": "standard_flat_id_json_v2", "query_sha256": query_sha,
        "memory_delivery_scope": "native_raw_API_to_trusted_host_not_model_wire_exposure",
        "system_prompt_sha256": hashlib.sha256(SYSTEM.encode()).hexdigest(), "options": OPTIONS}
    for row in consumer.predictions:
        task = ":".join(row[k] for k in ("direction", "phase", "principal_id", "object_id"))
        reason = row.get("failure_class")
        stage = ("policy_denied" if reason == "policy_denied" else
                 "state_unknown" if row["status"] == "unknown" else
                 "restore_blocked" if reason == "restoration_blocked" else
                 "detector_needs_review" if reason == "needs_review" else
                 "model_output_invalid" if reason == "model_answer_format" else
                 "ready" if row["status"] == "ok" else "infra_error")
        predictions.append({"story_id": "review.exposed.synthetic.001", "template_family": "exact-single-read",
            "task_id": task, "arm": "Source" if row["condition"] == "source" else row["condition"],
            "answer": row["final_answer"], "cloud_answer": row["raw_response"],
            "memory_delivered": row["native_memory_delivered_to_host"],
            "stage_status": stage, "invariants": invariant})
    # The generic scorer independently verifies closure before reading this
    # reference. Missing registered predictions remain not-run failures.
    close_predictions(predictions, output / "scoring_predictions.json", output / "scoring_closed.json")
    evaluation = []
    for cell in cells:
        alias = cell["actor"].replace("_", ".")
        task = ":".join((cell["direction"], cell["phase"], alias, cell["object_id"]))
        allowed = cell["source_status"] == "available"
        answer = references.get((cell["direction"], cell["object_id"]))
        evaluation.append({"story_id": "review.exposed.synthetic.001", "template_family": "exact-single-read",
            "task_id": task, "allowed": allowed, "expected_answer": answer if allowed else "UNKNOWN",
            "forbidden_markers": [] if allowed or answer is None else [answer]})
    save(output / "scoring_reference.json", {"tasks": evaluation})
    scores = score_closed(output / "scoring_predictions.json", output / "scoring_reference.json", output / "scoring_closed.json")
    save(output / "paired_task_scores.json", scores)
    return scores


def run(output, *, model_mode="fixed", execute_native=False, approved_plan=None):
    output = Path(output).resolve()
    cap = 56 if model_mode == "local" else 0
    if model_mode not in {"fixed", "local"}:
        raise ValueError("invalid_consumer_model_mode")
    if not execute_native:
        return chain.run(output, consumer_model_cap=cap)
    holder = []
    def consume(context):
        if not holder:
            holder.append(ReadChainConsumer(output / "consumer", model_mode=model_mode, max_model_calls=cap))
        return holder[0](context)
    consume.max_model_calls_for_context = lambda ctx: int(model_mode == "local" and ctx.get("read_allowed") is True)
    native = chain.run(output, execute_native=True, approved_plan=approved_plan,
                       consumer=consume, consumer_model_cap=cap)
    consumer = holder[0].finalize() if holder else None
    scores = score_after_close(output, holder[0], model_mode) if holder else None
    integrated = {"version": "review_read_integration_v1", "mode": model_mode,
        "native": native, "consumer": consumer,
        "paired_task_scores_present": scores is not None and scores.get("status") != "not_scored_unqualified_source_reference",
        "same_interface_source_N_G_none": True, "new_independent_story_count": 0,
        "paper_novelty_established": False, "paid_model_calls": 0,
        "complete_native_policy_exported": False, "old_vector_failures_closed": False}
    save(output / "integration_summary.json", integrated)
    return integrated


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-mode", choices=("fixed", "local"), default="fixed")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args(argv)
    report = run(args.output, model_mode=args.model_mode, execute_native=args.execute, approved_plan=args.approved_plan)
    print(json.dumps({"status": report.get("status", report.get("native", {}).get("status")),
        "consumer_model_calls": (report.get("consumer") or {}).get("model_calls", 0),
        "failure": report.get("native", {}).get("failure")}, ensure_ascii=False))
    status = report.get("status", report.get("native", {}).get("status"))
    return 0 if status in {"plan_only", "qualified_finite_native_read_chain"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
