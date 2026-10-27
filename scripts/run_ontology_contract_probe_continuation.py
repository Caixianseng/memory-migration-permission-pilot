"""Bounded continuation of the closed 32-opportunity ontology probe prefix.

Only execution/scoring treatment changes: twice-rejected, captured model output
remains a failed opportunity instead of stopping later opportunities. Production
adapters, policies, bodies, model identities and the original total caps remain
unchanged. Plan mode performs no model or client invocation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_ontology_contract_probe as base
from memory_migration_study import local_detector as local_adapter

VERSION = "ontology_contract_probe_continuation_v1"
PARENT_PLAN_SHA256 = "8d9efbdda7a2f269ea4e19dd792b659123c9b0cb142a0c2acd5593854e151478"
ABORTED_CLOSURE_SHA256 = "18c3b6462c8dcc65d7bde53c9e0516a65e15e8e0417400030066e0c9b1184edb"
INHERITED = {"opportunities": 32, "qwen_post_attempts": 22, "gliner_infer_invocations": 6}
NEW_SOURCE_FILES = ("scripts/run_ontology_contract_probe_continuation.py",
                    "tests/test_ontology_contract_probe_continuation.py")
PARENT_FILES = ("plan.json", "rows.json", "aborted_predictions.json", "aborted_phase_closed.json",
                "execution.json", "detectors.json", "http_transport_capture.json", "ner_infer_capture.json",
                "runtime.json", "policies.json", "schedule.json", "preflight.json",
                "preregistration.md", "evaluation.opaque.json")
OUTPUT_FAILURE = "model_output_invalid"


def require(condition, code):
    if not condition:
        raise ValueError("continuation_" + code)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def new_sources():
    return {name: base.sha(ROOT / name) for name in NEW_SOURCE_FILES}


def parent_hashes(parent):
    return {name: base.sha(Path(parent) / name) for name in PARENT_FILES}


def request_body(text, policy, *, repair=False):
    """Reconstruct only the production request contract, never a model answer."""
    data, trusted = local_adapter.LocalSensitivityAgent._validate_inputs(text, base.SOURCE_ID, policy, [])
    messages, _ = local_adapter.LocalSensitivityAgent._prepare_messages(data, trusted)
    if repair:
        messages = [*messages, {"role": "user", "content": local_adapter.REPAIR_PROMPT}]
    return {"model": local_adapter.MODEL, "messages": messages,
            "format": local_adapter._policy_schema(trusted["protected_categories"]),
            "stream": False, "keep_alive": "30m",
            "options": {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42}}


def verified_output_failure(cell, response, events, text, policy):
    """Require two real completed generations and replay their host validation.

    A transport/envelope/budget exception, missing capture, altered prompt, or
    successful replay cannot be relabelled as a model-output failure.
    """
    if (cell.get("arm") not in base.ARMS[:2] or not isinstance(response, dict)
            or response.get("status") != "needs_review" or response.get("errors") != ["format_or_span_invalid"]
            or response.get("findings") != [] or response.get("local_calls") != 2
            or not isinstance(response.get("diagnostics"), list) or len(response["diagnostics"]) != 2):
        return False
    posts = [event for event in events if event.get("cell") == cell and event.get("method") == "POST"]
    if len(posts) != 2:
        return False
    diagnostics = []
    for attempt, event in enumerate(posts, 1):
        if (event.get("error_type") is not None or event.get("path") != "/api/chat"
                or event.get("fixed_host") != "127.0.0.1:11435"
                or event.get("request_object") != request_body(text, policy, repair=attempt == 2)
                or event.get("request_object_sha256") != base._digest(event.get("request_object"))):
            return False
        envelope = event.get("decoded_response")
        if (not isinstance(envelope, dict) or envelope.get("model") != local_adapter.MODEL
                or envelope.get("done") is not True or envelope.get("done_reason") != "stop"
                or not isinstance(envelope.get("message"), dict)
                or not isinstance(envelope["message"].get("content"), str)
                or envelope["message"].get("thinking") or envelope["message"].get("tool_calls")):
            return False
        try:
            local_adapter.LocalSensitivityAgent._validate_output(
                local_adapter._strict_json(envelope["message"]["content"]), text, policy["protected_categories"])
        except (ValueError, TypeError, KeyError) as exc:
            code = local_adapter._safe_error_code(exc, "invalid_schema")
            diagnostics.append({"attempt": attempt, "stage": "output", "code": code})
        else:
            return False
    return response["diagnostics"] == diagnostics


def classify(cell, response, http_events, text, policy):
    original = base.observation_status(response, expected_unsupported=(cell["arm"] == base.ARMS[2]
                                       and cell["profile"] == base.STRICT_CUSTOMER_RELATION))
    if original == "engineering_error" and verified_output_failure(cell, response, http_events, text, policy):
        return OUTPUT_FAILURE
    return original


def validate_prefix(rows, schedule, http_events, ner_events, texts, policies):
    require(len(rows) == INHERITED["opportunities"] and [row.get("cell") for row in rows] == schedule[:32],
            "parent_prefix_changed")
    require(Counter(row.get("status") for row in rows) == {"ok": 24, "unsupported": 5,
            "needs_review": 2, "engineering_error": 1}, "parent_status_inventory_changed")
    posts = [event for event in http_events if event.get("method") == "POST"]
    require(len(posts) == 22 and len(ner_events) == 6, "parent_capture_counts_changed")
    require(all("error_type" not in event for event in http_events + ner_events), "parent_capture_exception")
    projected = []
    for index, row in enumerate(rows):
        cell = row["cell"]
        observed_posts = sum(event.get("cell") == cell for event in posts)
        observed_infers = sum(event.get("cell") == cell for event in ner_events)
        require(row.get("qwen_post_attempts") == observed_posts and row.get("gliner_infer_invocations") == observed_infers
                and row["response"].get("local_calls") == observed_posts + observed_infers,
                "parent_row_accounting_changed")
        expected_original = base.observation_status(row["response"], expected_unsupported=(cell["arm"] == base.ARMS[2]
                                                  and cell["profile"] == base.STRICT_CUSTOMER_RELATION))
        require(row["status"] == expected_original, "parent_original_classification_changed")
        base.exact_findings(row["response"], texts[cell["text_index"]])
        status = classify(cell, row["response"], http_events, texts[cell["text_index"]], policies[cell["profile"]][cell["arm"]])
        require(status != "engineering_error" and (status != OUTPUT_FAILURE or index == 31),
                "parent_failure_not_verified_output")
        projected.append(project_row(row, index=index, origin="parent", status=status))
    require(projected[-1]["status"] == OUTPUT_FAILURE, "parent_failed_slot_missing")
    require(all(event.get("cell", {}).get("profile") == base.ANY_SPECIFIC_ORGANIZATION for event in ner_events),
            "parent_strict_inference_detected")
    return projected


def project_row(row, *, index, origin, status):
    projected = copy.deepcopy(row)
    projected.update(schedule_index=index, origin=origin, original_status=row["status"],
                     original_errors=copy.deepcopy(row["response"].get("errors", [])),
                     original_row_sha256=base._digest(row), status=status,
                     classification_changed=status != row["status"])
    if status == OUTPUT_FAILURE:
        projected["classification_rule"] = "two_captured_completed_generations_rejected_by_host_output_validation"
    return projected


def read_parent(parent, expected_plan_sha256, expected_closure_sha256):
    parent = Path(parent).resolve()
    require(base.sha(parent / "aborted_phase_closed.json") == expected_closure_sha256, "parent_closure_hash_mismatch")
    plan, texts, policies, schedule = base.verify_frozen(parent, expected_plan_sha256)
    closure, execution = read_json(parent / "aborted_phase_closed.json"), read_json(parent / "execution.json")
    require(len(plan["source_sha256"]) == 87 and closure.get("source_sha256") == plan["source_sha256"]
            and closure.get("source_and_archive_verified") is True, "parent_source_binding_changed")
    require(closure.get("schema") == "ontology_probe_aborted_closure_v1"
            and closure.get("plan_sha256") == expected_plan_sha256
            and closure.get("reference_parsed") is False and closure.get("all_96_predictions_closed") is False
            and closure.get("completed_opportunities") == 32 and closure.get("unexecuted_opportunities") == 64
            and closure.get("qwen_post_attempts") == 22 and closure.get("gliner_infer_invocations") == 6,
            "parent_closure_contract_changed")
    checks = {"rows.json": closure.get("rows_sha256"), "execution.json": closure.get("original_execution_sha256"),
              "aborted_predictions.json": closure.get("aborted_predictions_sha256"), **closure.get("capture_objects_sha256", {})}
    require(set(checks) == {"rows.json", "execution.json", "aborted_predictions.json",
                            "http_transport_capture.json", "ner_infer_capture.json"}
            and all(base.sha(parent / name) == expected for name, expected in checks.items()), "parent_evidence_hash_changed")
    require(execution.get("status") == "stopped" and execution.get("completed_opportunities") == 32
            and execution.get("qwen_post_attempts") == 22 and execution.get("gliner_infer_invocations") == 6
            and execution.get("error_code") == "probe_engineering_error_or_accounting_mismatch"
            and type(execution.get("wall_seconds")) in (int, float) and 0 <= execution["wall_seconds"] < 3600
            and execution.get("network", {}).get("blocked_connects") == 0, "parent_execution_contract_changed")
    rows = read_json(parent / "aborted_predictions.json")
    require(rows == read_json(parent / "rows.json"), "parent_snapshot_not_original_rows")
    http_events, ner_events = read_json(parent / "http_transport_capture.json"), read_json(parent / "ner_infer_capture.json")
    projected = validate_prefix(rows, schedule, http_events, ner_events, texts, policies)
    require(sum(row["qwen_post_attempts"] for row in rows) == 22
            and sum(row["gliner_infer_invocations"] for row in rows) == 6, "parent_totals_changed")
    remaining = schedule[32:]
    require(len(remaining) == 64 and sum(cell["arm"] != base.ARMS[2] for cell in remaining) == 43
            and sum(cell["arm"] == base.ARMS[2] and cell["profile"] == base.ANY_SPECIFIC_ORGANIZATION for cell in remaining) == 10,
            "remaining_schedule_changed")
    return {"parent": str(parent), "plan": plan, "texts": texts, "policies": policies, "schedule": schedule,
            "remaining": remaining, "projected": projected, "wall_seconds": execution["wall_seconds"],
            "hashes": parent_hashes(parent), "detectors": read_json(parent / "detectors.json")}


def plan_only(parent, output, prereg, *, expected_parent_plan=PARENT_PLAN_SHA256,
              expected_parent_closure=ABORTED_CLOSURE_SHA256):
    output, prereg = Path(output).resolve(), Path(prereg).resolve()
    require(not output.exists(), "output_already_exists")
    evidence = read_parent(parent, expected_parent_plan, expected_parent_closure)
    require(output != Path(evidence["parent"]) and not output.is_relative_to(Path(evidence["parent"])), "output_inside_parent")
    additions = new_sources()
    cap = {"version": VERSION, "parent_plan_sha256": expected_parent_plan, "parent_closure_sha256": expected_parent_closure,
           "inherited": INHERITED, "inherited_wall_seconds": evidence["wall_seconds"], "total_limits": base.LIMITS,
           "remaining_opportunities": 64, "remaining_qwen_detector_opportunities": 43,
           "remaining_gliner_broad_infers": 10, "remaining_gliner_strict_gates": 11,
           "remaining_post_cap": 106, "remaining_infer_cap": 10,
           "remaining_schedule_sha256": base._digest(evidence["remaining"]),
           "failed_parent_schedule_index": 31, "failed_parent_slot_must_not_repeat": True,
           "automatic_outer_retries": 0, "additional_native_or_paid_calls": 0}
    plan = {"version": VERSION, "status": "planned_not_executed", "parent": evidence["parent"], "output": str(output),
            "parent_plan_sha256": expected_parent_plan, "parent_closure_sha256": expected_parent_closure,
            "parent_artifacts_sha256": evidence["hashes"], "parent_source_sha256": evidence["plan"]["source_sha256"],
            "continuation_source_sha256": additions, "preregistration_sha256": base.sha(prereg),
            "inherited": INHERITED, "remaining_schedule": evidence["remaining"], "cap": cap,
            "classification_amendment": "Post hoc execution-rule amendment: preserve verified two-generation output-validation failures as model_output_invalid; original statuses/errors stay visible. Unknown infrastructure errors stop.",
            "scoring_amendment": "model_output_invalid is unprocessable and never a correct negative/review; no accepted spans, positive FN retained. All 96 opportunities remain in denominator.",
            "reference_rule": "Hash/copy reference opaquely; parse only after all 96 merged predictions and capture bindings are closed.",
            "wall_scope": "Cumulative active execution wall time: inherited parent time plus continuation initialization/model-loop time. Offline implementation/analysis gap is separately outside active execution, not reset model budget."}
    output.mkdir(parents=True)
    archive = output / "implementation"
    for relative in {**evidence["plan"]["source_sha256"], **additions}:
        destination = archive / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    shutil.copy2(prereg, output / "preregistration.md")
    base.save_exclusive(output / "continuation_cap.json", cap)
    base.save_exclusive(output / "remaining_schedule.json", evidence["remaining"])
    plan.update(cap_file_sha256=base.sha(output / "continuation_cap.json"),
                remaining_schedule_file_sha256=base.sha(output / "remaining_schedule.json"))
    base.save_exclusive(output / "plan.json", plan)
    return {"status": "planned_not_executed", "plan_sha256": base.sha(output / "plan.json"),
            "model_calls": 0, "inherited": INHERITED, "remaining_opportunities": 64}


def verify_current(output, plan, *, check_parent=True):
    require(plan.get("version") == VERSION and plan.get("inherited") == INHERITED, "plan_contract_changed")
    require(base.source_hashes() == plan["parent_source_sha256"] and new_sources() == plan["continuation_source_sha256"],
            "source_changed")
    base.verify_implementation_archive(output, {**plan["parent_source_sha256"], **plan["continuation_source_sha256"]})
    require(base.sha(Path(output) / "preregistration.md") == plan["preregistration_sha256"]
            and base.sha(Path(output) / "continuation_cap.json") == plan["cap_file_sha256"]
            and read_json(Path(output) / "continuation_cap.json") == plan["cap"]
            and base.sha(Path(output) / "remaining_schedule.json") == plan["remaining_schedule_file_sha256"]
            and read_json(Path(output) / "remaining_schedule.json") == plan["remaining_schedule"], "frozen_sidecar_changed")
    if check_parent:
        require(parent_hashes(plan["parent"]) == plan["parent_artifacts_sha256"], "parent_artifacts_changed")
        base.verify_implementation_archive(plan["parent"], plan["parent_source_sha256"])


class InheritedBudget(base.Budget):
    def __init__(self, wall_seconds):
        super().__init__()
        self.continuation_started = self.started
        self.started -= wall_seconds
        self.posts, self.infers = 22, 6


def _empty_group():
    return {key: 0 for key in ("cells", "applicable_cells", "ok", "needs_review", "unsupported", "model_output_invalid",
            "decision_matches", "reference_review_cells", "reference_review_matches", "determinate_applicable_cells",
            "determinate_exact_matches", "tp", "fp", "fn")}


def score_merged(rows, reference, texts):
    """Score a copy; model-output failures are never semantic review successes."""
    scored = copy.deepcopy(rows)
    summary = base.score_rows([row for row in scored if row["status"] != OUTPUT_FAILURE], reference, texts)
    cases = {case["text_index"]: case for case in reference["cases"]}
    for group in summary.values():
        group[OUTPUT_FAILURE] = 0
    for row in scored:
        if row["status"] != OUTPUT_FAILURE:
            continue
        cell = row["cell"]
        expected = cases[cell["text_index"]]["expected"][cell["profile"]]
        spans = set()
        for finding in expected["spans"]:
            a, b, category = finding["start"], finding["end"], finding["category"]
            require(type(a) is int and type(b) is int and 0 <= a < b <= len(texts[cell["text_index"]])
                    and category == "CUSTOMER" and finding["text"] == texts[cell["text_index"]][a:b], "reference_span_invalid")
            spans.add((a, b, category))
        decision = expected["decision"]
        require(decision in {"sensitive", "not_sensitive", "needs_review"}, "reference_decision_invalid")
        determinate = decision != "needs_review"
        row["score"] = {"expected_decision": decision, "actual_decision": OUTPUT_FAILURE,
                        "decision_matches": False, "applicable": True,
                        "span_score": {"tp": 0, "fp": 0, "fn": len(spans)} if determinate else None,
                        "determinate_exact_match": False if determinate else None}
        group = summary.setdefault(cell["profile"] + "/" + cell["arm"], _empty_group())
        group["cells"] += 1
        group["applicable_cells"] += 1
        group[OUTPUT_FAILURE] += 1
        group["reference_review_cells"] += int(not determinate)
        group["determinate_applicable_cells"] += int(determinate)
        group["fn"] += len(spans) if determinate else 0
    for group in summary.values():
        group["processable_rate"] = group["ok"] / group["cells"]
        group["decision_match_rate"] = group["decision_matches"] / group["applicable_cells"] if group["applicable_cells"] else None
        group["determinate_exact_match_rate"] = group["determinate_exact_matches"] / group["determinate_applicable_cells"] if group["determinate_applicable_cells"] else None
        group["precision"] = group["tp"] / (group["tp"] + group["fp"]) if group["tp"] + group["fp"] else None
        group["recall"] = group["tp"] / (group["tp"] + group["fn"]) if group["tp"] + group["fn"] else None
        group["eligible_for_same_profile_ranking"] = bool(group["applicable_cells"])
    return scored, summary


def close_and_score(output, plan, plan_hash, rows, budget):
    output = Path(output)
    budget.check()
    verify_current(output, plan)
    require(len(rows) == 96 and [row["cell"] for row in rows] == base.make_schedule(), "prediction_inventory_incomplete")
    base.save_exclusive(output / "predictions.json", copy.deepcopy(rows))
    capture_hashes = {name: base.sha(output / name) for name in ("http_transport_capture.json", "ner_infer_capture.json")}
    closure = {"version": VERSION, "plan_sha256": plan_hash, "predictions_sha256": base.sha(output / "predictions.json"),
               "all_96_opportunities_closed": True, "completed_opportunities": 96, "inherited_opportunities": 32,
               "parent_artifacts_sha256": plan["parent_artifacts_sha256"], "continuation_captures_sha256": capture_hashes,
               "source_and_archives_verified": True, "reference_parsed": False,
               "qwen_post_attempts_cumulative": budget.posts, "gliner_infer_invocations_cumulative": budget.infers,
               "closed_at_unix_seconds": time.time()}
    base.save_exclusive(output / "prediction_phase_closed.json", closure)
    closure_hash = base.sha(output / "prediction_phase_closed.json")
    budget.check()
    parent = Path(plan["parent"])
    require(base.sha(parent / "evaluation.opaque.json") == plan["parent_artifacts_sha256"]["evaluation.opaque.json"], "reference_changed")
    # FIRST reference JSON parse, after all inherited+new observations close.
    reference = read_json(parent / "evaluation.opaque.json")
    require(reference["runtime_sha256"] == plan["parent_artifacts_sha256"]["runtime.json"], "reference_runtime_mismatch")
    texts = base.read_runtime(parent / "runtime.json")
    scored, summary = score_merged(rows, reference, texts)
    verify_current(output, plan)
    require(base.sha(output / "predictions.json") == closure["predictions_sha256"]
            and base.sha(output / "prediction_phase_closed.json") == closure_hash
            and all(base.sha(output / name) == value for name, value in capture_hashes.items()), "closed_evidence_changed")
    base.save_exclusive(output / "scored_rows.json", scored)
    return {"version": VERSION, "status": "complete_with_disclosed_execution_rule_amendment",
            "plan_sha256": plan_hash, "predictions_sha256": closure["predictions_sha256"],
            "prediction_phase_closed_sha256": closure_hash, "opportunities": 96, "inherited_opportunities": 32,
            "new_opportunities": 64, "qwen_post_attempts_inherited": 22, "qwen_post_attempts_new": budget.posts - 22,
            "qwen_post_attempts_cumulative": budget.posts, "gliner_infer_invocations_inherited": 6,
            "gliner_infer_invocations_new": budget.infers - 6, "gliner_infer_invocations_cumulative": budget.infers,
            "gliner_strict_infer_invocations": 0, "by_profile_arm": summary,
            "classification_amendment": plan["classification_amendment"], "parent_original_status_unchanged": "stopped",
            "neural_forward_count": "not_instrumented", "cloud_calls": 0, "paid_calls": 0,
            "native_client_calls": 0, "answer_model_calls": 0,
            "scope": "Same synthetic development probe with post hoc failure-preserving execution amendment; no new independent acceptance set or pure algorithm gain."}


def execute(output, expected_plan_sha256):
    output = Path(output).resolve()
    require(not (output / "execution.json").exists(), "execution_already_started")
    require(base.sha(output / "plan.json") == expected_plan_sha256, "plan_hash_mismatch")
    plan = read_json(output / "plan.json")
    verify_current(output, plan)
    evidence = read_parent(plan["parent"], plan["parent_plan_sha256"], plan["parent_closure_sha256"])
    require(evidence["remaining"] == plan["remaining_schedule"] and evidence["hashes"] == plan["parent_artifacts_sha256"], "parent_changed")
    budget = InheritedBudget(evidence["wall_seconds"])
    rows = copy.deepcopy(evidence["projected"])
    network = {"loopback_connect_attempts": 0, "blocked_connects": 0}
    base.install_network_guard(network)
    execution = {"version": VERSION, "status": "started", "plan_sha256": expected_plan_sha256,
                 "reference_parsed": False, "inherited": INHERITED}
    base.save_exclusive(output / "execution.json", execution)
    try:
        parent_plan = evidence["plan"]
        local = base.LocalSensitivityAgent({"timeout_seconds": parent_plan["qwen"]["timeout_seconds"]})
        transport = base.CapturedTransport(local._transport, budget, output)
        local.transport = transport
        health = local.health()
        require(health == evidence["detectors"]["qwen_health"]
                and base._digest(local.cache_identity()) == base._digest(evidence["detectors"]["qwen_identity"]), "qwen_identity_changed")
        budget.check()
        actual = base.LocalNerRuntime(parent_plan["assets"]["root"], threads=parent_plan["gliner"]["threads"])
        runtime = base.CapturedNer(actual, budget, output)
        ner = base.GlinerEntityAgent(runtime, approved_policies=[evidence["policies"][profile][base.ARMS[2]] for profile in base.PROFILES],
                                     splitter=parent_plan["gliner"]["splitter"], threshold=parent_plan["gliner"]["threshold"])
        require(base._digest(ner.cache_identity()) == base._digest(evidence["detectors"]["ner_identity"]), "ner_identity_changed")
        base.save_exclusive(output / "detectors.json", {"qwen_health": health, "qwen_identity": local.cache_identity(),
                            "ner_identity": ner.cache_identity(), "matched_parent_identities": True})
        for index, cell in enumerate(plan["remaining_schedule"], 32):
            budget.check()
            verify_current(output, plan)
            transport.cell = runtime.cell = cell
            detector = ner if cell["arm"] == base.ARMS[2] else local
            before = budget.infers if detector is ner else budget.posts
            response = detector(text=evidence["texts"][cell["text_index"]], source_id=base.SOURCE_ID,
                                policy=copy.deepcopy(evidence["policies"][cell["profile"]][cell["arm"]]), rule_findings=[])
            budget.check()
            observed = (budget.infers if detector is ner else budget.posts) - before
            original = base.observation_status(response, expected_unsupported=(detector is ner and cell["profile"] == base.STRICT_CUSTOMER_RELATION))
            row = {"cell": cell, "status": original, "response": response,
                   "qwen_post_attempts": observed if detector is local else 0,
                   "gliner_infer_invocations": observed if detector is ner else 0}
            status = classify(cell, response, transport.events, evidence["texts"][cell["text_index"]], evidence["policies"][cell["profile"]][cell["arm"]])
            rows.append(project_row(row, index=index, origin="continuation", status=status))
            base.save(output / "rows.json", rows)
            require(status != "engineering_error" and response.get("local_calls") == observed, "engineering_error_or_accounting_mismatch")
            base.exact_findings(response, evidence["texts"][cell["text_index"]])
            print(json.dumps({"completed": len(rows), "new": len(rows) - 32, **cell, "status": status,
                              "qwen_posts_cumulative": budget.posts, "ner_infers_cumulative": budget.infers}), flush=True)
        report = close_and_score(output, plan, expected_plan_sha256, rows, budget)
        report.update(network=network, cumulative_active_wall_seconds=time.monotonic() - budget.started)
        base.save_exclusive(output / "report.json", report)
        execution.update(status=report["status"], reference_parsed=True)
        return report
    except Exception as exc:
        execution.update(status="stopped", error_type=type(exc).__name__,
                         error_code=str(exc) if str(exc).startswith(("continuation_", "probe_")) else "continuation_execution_error")
        raise
    finally:
        execution.update(completed_opportunities=len(rows), new_opportunities=len(rows) - 32,
                         qwen_post_attempts_cumulative=budget.posts, gliner_infer_invocations_cumulative=budget.infers,
                         cumulative_active_wall_seconds=time.monotonic() - budget.started, network=network)
        base.save(output / "execution.json", execution)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--parent-run", type=Path, default=ROOT / "results/ontology_contract_probe_20261027_run_01")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prereg", type=Path, default=ROOT / "docs/共同敏感类别合同_失败保留与续跑预注册_2026-10-27.md")
    parser.add_argument("--expected-plan-sha256")
    args = parser.parse_args()
    if args.plan_only:
        result = plan_only(args.parent_run, args.output, args.prereg)
    else:
        if not args.expected_plan_sha256:
            parser.error("--execute requires --expected-plan-sha256")
        result = execute(args.output, args.expected_plan_sha256)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
