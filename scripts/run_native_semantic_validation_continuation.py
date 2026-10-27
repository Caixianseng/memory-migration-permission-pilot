"""Run exactly the 22 unstarted slots after the disclosed run-01 host bug.

Original evidence is immutable. Two old native receipts are revalidated with
fresh controlled-host capabilities, never replayed to a model. All 24 original
host inputs, aliases and ordering remain fixed. No transport injection exists
in this production continuation entry point.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_native_semantic_validation as base
from memory_migration_study.focused_semantic_reader import digest, parse_selection, require

VERSION = "native-semantic-validation-continuation-20261027-v1"
SELF = "scripts/run_native_semantic_validation_continuation.py"
TEST = "tests/test_native_semantic_validation_continuation.py"
PARENT_EXPECTED_PLAN_HASH = "ae9a1568fd285c62d77a5eafe3426d5658a7252007e5b550b8bb92c826208dc0"
PARENT_EXPECTED_PREDICTIONS_HASH = "b305bdcfbe16bce9fc65e622e2aebf7bff0bb7f0eb69ebc05ebe682ac19bb2ac"
INHERITED = (0, 1)
PENDING = tuple(range(2, 24))


def manifest():
    return {**base.manifest(), SELF: digest((ROOT / SELF).read_bytes()), TEST: digest((ROOT / TEST).read_bytes())}


def validate_receipt(client, receipt, memory_text, memory_sha):
    if client == "qoder":
        return base.validate_native_receipt(client, receipt, memory_text, memory_sha)
    # The old driver validates identity/cleanup/guard before its final, faulty
    # SHA256 baseline comparison. Accept only that exact final failure here;
    # independently require the genuine SHA1 baseline below. No receipt fields
    # are rewritten, including on a temporary proof projection.
    try:
        base.validate_native_receipt(client, receipt, memory_text, memory_sha)
    except ValueError as exc:
        require(str(exc) == "harness_memory_load_unproved", str(exc))
    require(receipt.get("native_instruction_loaded") is True, "harness_memory_load_unproved")
    matching = []
    expected_sha1 = hashlib.sha1(memory_text.encode()).hexdigest()
    for baseline in receipt.get("native_instruction_baselines", []):
        source = baseline.get("source") or {}
        rendered = "".join(block.get("text", "") for block in baseline.get("content", []) if block.get("type") == "text")
        changes = [c for c in source.get("changes", []) if c.get("digest") == expected_sha1
                   and str(c.get("path", "")).replace("\\", "/").endswith("AGENTS.md")]
        if source.get("kind") == "agent-instructions" and source.get("baseline") is True and memory_text.strip() in rendered and changes:
            require(digest(memory_text.encode()) == memory_sha, "harness_baseline_sha256_mismatch")
            matching.append(baseline)
    require(bool(matching), "harness_native_sha1_baseline_unproved")


def parent_evidence(parent):
    parent = base.scope(parent)
    plan_bytes = (parent / "plan.json").read_bytes()
    prediction_bytes = (parent / "predictions.json").read_bytes()
    require(digest(plan_bytes) == PARENT_EXPECTED_PLAN_HASH
            and digest(prediction_bytes) == PARENT_EXPECTED_PREDICTIONS_HASH, "parent_plan_or_predictions_changed")
    plan, rows = json.loads(plan_bytes), json.loads(prediction_bytes)
    require(plan["schema"] == base.VERSION and plan["budget"] == base.BUDGET and len(rows) == 24,
            "parent_contract_changed")
    require([r["index"] for r in rows if r["client_attempts"]] == list(INHERITED)
            and [r["client"] for r in rows[:2]] == ["qoder", "harness"]
            and all(r["status"] == "not_run" and r["client_attempts"] == 0 for r in rows[2:]), "parent_attempt_inventory_changed")
    require(rows[0]["status"] == "ok" and rows[1]["status"] == "error"
            and rows[1].get("error") == "harness_memory_load_unproved"
            and all(r.get("receipt", {}).get("status") == "ok" for r in rows[:2]), "parent_failure_not_the_frozen_host_bug")
    names = ["plan.json", "predictions.json", "prediction_phase_closed.json", "summary.json", "readonly_diagnosis.json"]
    for row in rows[:2]:
        names.extend((row["slot_id"] + "_result.json", row["slot_id"] + "_reservation.json", row["slot_id"] + "/AGENTS.md"))
    hashes = {name: digest((parent / name).read_bytes()) for name in names}
    closure = json.loads((parent / "prediction_phase_closed.json").read_bytes())
    require(closure["prediction_file_sha256"] == digest(prediction_bytes) and closure["reserved_attempts"] == 2
            and closure["all_24_slots_closed"] is True, "parent_not_closed")
    return plan, rows, hashes


class ContinuationBudget(base.AttemptBudget):
    def __init__(self, inherited_rows):
        super().__init__()
        require(len(inherited_rows) == 2 and all(r["client_attempts"] == 1 for r in inherited_rows), "two_parent_attempts_required")
        require(Counter(r["client"] for r in inherited_rows) == {"qoder": 1, "harness": 1}, "parent_per_client_budget_changed")
        self.attempts = 2
        self.clients.update({"qoder": 1, "harness": 1})


def plan_only(parent, output):
    parent, output = base.scope(parent), base.scope(output)
    require(not output.exists(), "fresh_output_required")
    original, rows, parent_hashes = parent_evidence(parent)
    installed = base.install_qualification()
    require(installed == original["install_qualification"], "install_changed_since_parent")
    frozen = manifest()
    require(all(frozen.get(name) == expected for name, expected in original["implementation_sha256"].items()), "original_frozen_source_changed")
    output.mkdir(parents=True)
    plan = {"schema": VERSION, "output": output.relative_to(ROOT).as_posix(),
        "parent_run": parent.relative_to(ROOT).as_posix(), "parent_artifacts_sha256": parent_hashes,
        "implementation_sha256": frozen, "install_qualification": installed,
        "budget": base.BUDGET, "budget_sha256": original["budget_sha256"],
        "inherited_attempts": 2, "new_attempt_cap": 22, "inherited_indices": list(INHERITED), "execute_indices": list(PENDING),
        "pairs": deepcopy(original["pairs"]), "slots": deepcopy(original["slots"]),
        "native_inputs_sha256": original["native_inputs_sha256"], "slot_order_sha256": original["slot_order_sha256"],
        "story_id": original["story_id"], "cost": original["cost"],
        "authoring_reference_exposure": original["authoring_reference_exposure"],
        "amendment": "Native instruction changes digest uses SHA1, while local file/receipt binding uses SHA256. Preserve original host failure, revalidate two receipts without inference using fresh host capabilities, launch only indices 2..23.",
        "reference_runtime_parse": "frozen opaque bytes parsed only after all 24 combined outputs are closed and hashed"}
    for name in frozen:
        target = output / "frozen_source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write((ROOT / name).read_bytes())
    for name in parent_hashes:
        target = output / "frozen_parent" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write((parent / name).read_bytes())
    base.save(output / "plan.json", plan)
    return plan


def approved(path):
    path = base.scope(path)
    plan = json.loads(path.read_bytes())
    require(path.read_bytes() == base.encoded(plan) and plan["schema"] == VERSION
            and path == ROOT / plan["output"] / "plan.json", "continuation_plan_binding_changed")
    require(plan["budget"] == base.BUDGET and plan["budget_sha256"] == digest(base.BUDGET)
            and plan["inherited_indices"] == list(INHERITED) and plan["execute_indices"] == list(PENDING)
            and plan["inherited_attempts"] == 2 and plan["new_attempt_cap"] == 22, "continuation_budget_changed")
    require(manifest() == plan["implementation_sha256"], "continuation_implementation_changed")
    parent = ROOT / plan["parent_run"]
    original, rows, hashes = parent_evidence(parent)
    require(hashes == plan["parent_artifacts_sha256"] and original["pairs"] == plan["pairs"]
            and original["slots"] == plan["slots"] and original["native_inputs_sha256"] == plan["native_inputs_sha256"]
            and original["slot_order_sha256"] == plan["slot_order_sha256"], "parent_evidence_or_inputs_changed")
    for name, expected in plan["implementation_sha256"].items():
        require(digest((path.parent / "frozen_source" / name).read_bytes()) == expected, "frozen_source_changed")
    for name, expected in hashes.items():
        require(digest((path.parent / "frozen_parent" / name).read_bytes()) == expected, "frozen_parent_changed")
    return plan, rows


def finish_response(slot, row, receipt, cap, story):
    validate_receipt(slot["client"], receipt, slot["agents_md"], digest(slot["agents_md"].encode()))
    try:
        selected = parse_selection(receipt.get("answer"))
    except (ValueError, TypeError):
        row.update(status="error", failure_class="format")
        return
    row["answer_id"] = selected
    restored = cap.restore(selected, story_id=story["id"], question_id=slot["question_id"], condition=cap.condition, request_id=cap.request_id)
    row["restoration_status"] = restored["status"]
    row["restoration_error"] = restored.get("error")
    expected = "UNKNOWN" if selected == "UNKNOWN" else next(f["value"] for f in cap.raw_candidates if f["id"] == selected)
    require(restored["status"] == "ok" and restored.get("answer") == expected, "restoration_failed")
    row["restored_answer_sha256"] = digest(expected.encode())
    row.update(status="ok", failure_class=None)


def close_cap(row, cap):
    cap.closed = True
    try:
        cap.restore("UNKNOWN", story_id=cap.story_id, question_id=cap.question_id, condition=cap.condition, request_id=cap.request_id)
        row.update(status="error", failure_class="engineering", error="closed_capability_replay_allowed", host_closed_capability_replay_blocked=False)
    except ValueError as exc:
        row["host_closed_capability_replay_blocked"] = str(exc) == "arm_capability_closed"
    row["restoration_capability_closed"] = True


def revalidate_inherited(slot, old, cap, state, story):
    row = deepcopy(old)
    row.update(original_status=old["status"], original_failure_class=old.get("failure_class"),
        original_restoration_status=old.get("restoration_status"), original_error=old.get("error"),
        evidence_origin="run01_native_receipt_zero_model_posthoc_revalidation", current_phase_model_calls=0,
        restoration_scope="fresh_run02_controlled_host_capability; not original call-time restoration",
        error=None)
    try:
        require(slot["view"] == "raw" and cap.check()["decision"] == "allow", "inherited_raw_host_guard_not_allow")
        require(digest(slot["agents_md"].encode()) == old.get("memory_before_sha256") == old.get("memory_after_sha256")
                == old["receipt"].get("agent_memory_file_sha256"), "parent_memory_binding_changed")
        finish_response(slot, row, old["receipt"], cap, story)
    except Exception as exc:
        row.update(status="error", failure_class="engineering", error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
    finally:
        close_cap(row, cap)
    return row


def call_slot(slot, cap, state, story, out, budget):
    row = {k: slot[k] for k in ("index", "slot_id", "pair_id", "direction", "question_id", "stage", "view", "client", "input_sha256")}
    row.update(status="not_run", failure_class=None, answer_id=None, client_attempts=0, restoration_status=None,
               evidence_origin="run02_new_native_invocation", current_phase_model_calls=0)
    started = time.monotonic()
    memory = state[slot["stage"]] / "AGENTS.md"
    registered = [*story["sensitive_values"], state["pair"]["source_only"]]
    try:
        before = digest(memory.read_bytes())
        require(before == digest(slot["agents_md"].encode()) and cap.check()["decision"] == "allow", "memory_or_host_guard_not_allow")
        if slot["view"] == "private":
            require(not base.scan_registered({"prompt": slot["prompt"], "agents_md": memory.read_text(encoding="utf-8")}, registered), "registered_raw_native_input")
        budget.reserve(slot["client"])
        row.update(client_attempts=1, current_phase_model_calls=1)
        base.save(out / (slot["slot_id"] + "_reservation.json"), {"slot_id": slot["slot_id"], "cumulative_ordinal": budget.attempts,
                  "client": slot["client"], "input_sha256": slot["input_sha256"], "memory_sha256": before})
        receipt = base.invoke(slot["client"], state[slot["stage"]], slot["prompt"], out / (slot["slot_id"] + "_runtime"))
        row["receipt"] = receipt
        observed = {key: receipt.get(key) for key in ("answer", "raw_response")}
        row.update(response_registered_raw_present=base.scan_registered(observed, registered),
            response_source_only_present=base.scan_registered(observed, [state["pair"]["source_only"]]),
            response_scan_available=any(isinstance(value, str) for value in observed.values()),
            memory_before_sha256=before, memory_after_sha256=digest(memory.read_bytes()))
        require(before == row["memory_after_sha256"] == receipt.get("agent_memory_file_sha256"), "memory_hash_or_native_receipt_mismatch")
        if receipt.get("status") != "ok":
            row.update(status="error", failure_class="interface", error=receipt.get("error"))
            return row
        if slot["view"] == "private":
            require(not row["response_registered_raw_present"], "registered_raw_private_response")
        finish_response(slot, row, receipt, cap, story)
        return row
    except Exception as exc:
        row.update(status="error", failure_class="engineering", error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        return row
    finally:
        close_cap(row, cap)
        row["elapsed_seconds"] = time.monotonic() - started


def execute(path):
    plan, inherited_rows = approved(path)
    out = ROOT / plan["output"]
    base.save(out / "execution_started.json", {"plan_file_sha256": digest(Path(path).read_bytes()),
        "inherited_attempts": 2, "new_attempt_cap": 22, "cumulative_cap": 24})
    rows = deepcopy(inherited_rows)
    budget, errors, caps, controls, qualifications = ContinuationBudget(rows[:2]), [], {}, [], []
    started = time.monotonic()
    reference_path = out / "frozen_source" / base.REFERENCE
    try:
        require(base.install_qualification() == plan["install_qualification"], "installed_assets_changed")
        require(digest(reference_path.read_bytes()) == plan["implementation_sha256"][base.REFERENCE], "frozen_reference_changed")
        story = base.story_material()
        states, caps = base.setup_caps(plan, out, story)
        controls = base.host_controls(states, caps, plan)
        qualifications = [state["evidence"] for state in states.values()]
        base.save(out / "qualifications.json", qualifications)
        base.save(out / "engineering_controls.json", controls)
        for index in INHERITED:
            slot = plan["slots"][index]
            rows[index] = revalidate_inherited(slot, inherited_rows[index], caps[slot["slot_id"]], states[slot["pair_id"]], story)
            base.save(out / (slot["slot_id"] + "_posthoc_revalidation.json"), rows[index])
        require(all(rows[index]["status"] == "ok" for index in INHERITED), "parent_zero_model_revalidation_failed")
        for index in PENDING:
            require(time.monotonic() - started < base.BUDGET["wall_seconds"], "wall_budget_exhausted")
            require(manifest() == plan["implementation_sha256"], "implementation_changed_between_clients")
            # Parent artifacts and closed outputs cannot change between calls.
            require(parent_evidence(ROOT / plan["parent_run"])[2] == plan["parent_artifacts_sha256"], "parent_changed_between_clients")
            slot = plan["slots"][index]
            row = call_slot(slot, caps[slot["slot_id"]], states[slot["pair_id"]], story, out, budget)
            rows[index] = row
            base.save(out / (slot["slot_id"] + "_result.json"), row)
            print(json.dumps({"index": index, "client": slot["client"], "stage": slot["stage"], "view": slot["view"],
                              "question": slot["question_id"], "status": row["status"], "failure_class": row["failure_class"]}), flush=True)
            if row["failure_class"] in {"interface", "engineering"}:
                errors.append({"slot_id": slot["slot_id"], "code": row.get("error"), "action": "stop_no_retry"})
                break
    except Exception as exc:
        errors.append({"code": str(exc) if isinstance(exc, ValueError) else type(exc).__name__, "action": "stop_no_retry"})
    finally:
        for cap in caps.values():
            cap.closed = True
    base.save(out / "predictions.json", rows)
    unchanged = manifest() == plan["implementation_sha256"]
    if not unchanged:
        errors.append({"code": "implementation_changed_at_closure", "action": "engineering_failure"})
    opaque = reference_path.read_bytes()
    closure = {"all_24_slots_closed": True, "prediction_file_sha256": digest((out / "predictions.json").read_bytes()),
        "inherited_attempts": 2, "new_attempts": budget.attempts - 2, "cumulative_attempts": budget.attempts,
        "implementation_unchanged": unchanged, "frozen_reference_sha256": digest(opaque)}
    base.save(out / "prediction_phase_closed.json", closure)
    try:
        require(digest(opaque) == plan["implementation_sha256"][base.REFERENCE]
                and digest(reference_path.read_bytes()) == digest(opaque), "frozen_reference_changed_at_closure")
        metrics = base.score_rows(rows, json.loads(opaque))
        require(digest(reference_path.read_bytes()) == digest(opaque), "frozen_reference_changed_during_scoring")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        metrics = {"denominator": 24, "classifications": {"unscored": 24}, "cells": {}, "scoring_blocked": True}
        errors.append({"code": str(exc) if isinstance(exc, ValueError) else type(exc).__name__, "action": "scoring_blocked"})
    unchanged = unchanged and manifest() == plan["implementation_sha256"]
    if not unchanged:
        errors.append({"code": "implementation_changed_after_closure", "action": "engineering_failure"})
    base.save(out / "metrics.json", metrics)
    failed = bool(errors or any(row["status"] != "ok" for row in rows))
    summary = {"schema": VERSION + "-summary", "continuation_phase_status": "engineering_failed" if failed else "completed",
        "status": "engineering_failed" if failed else "completed_with_disclosed_parent_engineering_failure",
        "parent_run_status_unchanged": "engineering_failed", "planned_slots": 24,
        "inherited_native_attempts": 2, "new_native_attempts": budget.attempts - 2, "cumulative_client_attempts": budget.attempts,
        "attempts_by_client": dict(budget.clients), "usable_responses_after_disclosed_revalidation": sum(r["status"] == "ok" for r in rows),
        "original_call_time_pipeline_successes": sum(r.get("original_status", r["status"]) == "ok" for r in rows),
        "parent_call_time_engineering_failures": sum(r.get("original_status") == "error" for r in rows[:2]),
        "metrics": metrics, "host_controls_passed": sum(c["passed"] for c in controls), "host_controls_total": len(controls),
        "harness_allowed_sdk_streams_cumulative": sum((r.get("receipt", {}).get("guard_counts") or {}).get("allowed_stream_count", 0) for r in rows),
        "client_invocations_started_cumulative": sum(r.get("receipt", {}).get("invocation_started") is True for r in rows),
        "registered_private_response_disclosures": sum(r.get("response_registered_raw_present") is True for r in rows if r["view"] == "private"),
        "elapsed_seconds": time.monotonic() - started, "errors": errors, "cost": plan["cost"],
        "new_raw_api_calls": 0, "mapping_object_persisted": False, "full_cloud_request_inspected": False,
        "native_read_acl_or_live_revocation": False, "cross_machine_network": False,
        "one_exposed_development_story": True, "fresh64_detection_or_novelty_acceptance": False,
        "authoring_reference_exposure": plan["authoring_reference_exposure"],
        "plan_file_sha256": digest(Path(path).read_bytes()), "parent_plan_file_sha256": PARENT_EXPECTED_PLAN_HASH,
        "budget_sha256": plan["budget_sha256"], "implementation_unchanged": unchanged,
        "parent_artifacts_unchanged": parent_evidence(ROOT / plan["parent_run"])[2] == plan["parent_artifacts_sha256"],
        "artifacts_sha256": {name: digest((out / name).read_bytes()) for name in
            ("plan.json", "predictions.json", "prediction_phase_closed.json", "metrics.json")}}
    for name in ("qualifications.json", "engineering_controls.json"):
        if (out / name).exists():
            summary["artifacts_sha256"][name] = digest((out / name).read_bytes())
    base.save(out / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--parent-run", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    if args.plan_only:
        require(args.parent_run is not None and args.output is not None, "parent_and_output_required")
        plan = plan_only(args.parent_run, args.output)
        print(json.dumps({"status": "plan_only", "new_model_calls": 0, "new_attempt_cap": 22,
            "cumulative_attempt_cap": 24, "inputs_sha256": plan["native_inputs_sha256"]}))
        return 0
    require(args.approved_plan is not None, "approved_plan_required")
    result = execute(args.approved_plan)
    print(json.dumps({"status": result["status"], "new_attempts": result["new_native_attempts"],
        "cumulative_attempts": result["cumulative_client_attempts"], "classifications": result["metrics"]["classifications"]}))
    return int(result["continuation_phase_status"] != "completed")


if __name__ == "__main__":
    raise SystemExit(main())
