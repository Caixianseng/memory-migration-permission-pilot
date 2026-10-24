"""Assemble a local protocol-delivery hub and an aggregate-only public summary.

This script uses the Python standard library only. It never imports a model,
calls an API, changes a score, or substitutes zero for missing required evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
from pathlib import Path
import re

MEMORY_RUNS = ("development", "development_gliner_v2", "development_union", "heldout_gliner", "heldout_union")
HELDOUT_RUNS = ("heldout_gliner", "heldout_union")
PRIVATE_ARMS = ("model_build_migration", "coverage_migration", "coverage_intent_migration",
                "coverage_intent_generation", "coverage_intent_two_stage")
VERSION = "semantic_protocol_delivery_v1"
LEGACY_STORAGE_FIELDS = ("stored_record_json_bytes", "stored_source_copy_characters")
MEMORY_TABLE_FIELDS = ("legal_tasks", "correct", "ready", "build_successes", "build_stories", "supported_legal_tasks",
                       "true_model_unknown", "restoration_failure", "ready_with_masking_gaps", "extra_masked_characters",
                       "stored_characters", "stored_record_json_bytes", "stored_source_copy_characters", "unauthorized_output")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def integer(obj, key):
    value = obj[key]
    if type(value) is not int or value < 0:
        raise ValueError("invalid_nonnegative_count:" + key)
    return value


def status(passed):
    return "passed" if passed else "failed"


def require_files(memory_root, detection_root, tests_log):
    paths = [tests_log, memory_root / "final_heldout_freeze.json", memory_root / "value_validation_replay.json",
             memory_root / "value_validation_demo.json", memory_root / "delivery_integrity.json"]
    for run in MEMORY_RUNS:
        paths.extend(memory_root / run / name for name in
                     ("report.json", "plan.json", "runtime_identity.json", "network_audit.json"))
    for run in HELDOUT_RUNS:
        paths.extend(memory_root / run / name for name in
                     ("evidence_verification.json", "evidence_verification_release.json", "rows.json", "runtime.json"))
    for run in ("development", "heldout"):
        paths.extend(detection_root / run / name for name in ("report.json", "plan.json", "network_audit.json"))
    paths.append(detection_root / "development/accounting_recheck.json")
    for run in ("lifecycle", "lifecycle_timed"):
        paths.extend(memory_root / run / name for name in ("report.json", "plan.json", "runtime_identity.json", "network_audit.json"))
    paths.extend(memory_root / "ner_label_probe" / name for name in ("report.json", "plan.json", "verification.json"))
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        # This check precedes parsing any formal heldout content or scoring.
        raise FileNotFoundError("required_protocol_artifacts_missing:\n" + "\n".join(missing))
    return paths


def test_results(path):
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    matches = list(re.finditer(r"^Ran (\d+) tests? in ([0-9.]+)s\s*$", text, re.M))
    if not matches:
        raise ValueError("final_test_run_count_missing")
    match = matches[-1]
    tail = text[match.end():]
    ok = re.search(r"^OK(?: \(skipped=(\d+)\))?\s*$", tail, re.M)
    failed = re.search(r"^FAILED(?: \(([^\n]+)\))?\s*$", tail, re.M)
    if not ok and not failed:
        raise ValueError("final_test_run_not_terminal")
    return {"executed": int(match.group(1)), "wall_seconds": float(match.group(2)),
            "status": "passed" if ok else "failed", "skipped": int(ok.group(1) or 0) if ok else None,
            "failure_summary": failed.group(1) if failed else None, "log_sha256": sha(path)}


def network_summary(obj):
    blocked_keys = [key for key in obj if "blocked" in key and ("external" in key or "socket" in key)]
    if not blocked_keys:
        raise ValueError("network_audit_blocked_count_missing")
    blocked = sum(integer(obj, key) for key in blocked_keys)
    return {"status": status(blocked == 0), "blocked_external_attempts": blocked,
            "allowed_loopback_connections": obj.get("allowed_loopback_connections"),
            "scope": "Recorded process socket.connect audit; not a system-wide traffic proof."}


def verification_summary(obj):
    checks = obj["checks"]
    if not isinstance(checks, list) or not checks:
        raise ValueError("verification_checks_missing")
    passed = obj["status"] == "passed" and all(check["passed"] is True for check in checks)
    return {"status": status(passed), "checks": len(checks), "passed_checks": sum(check["passed"] is True for check in checks),
            "rows_verified": obj.get("rows_verified"), "verification_model_calls": integer(obj, "verification_model_calls")}


def validation_advisory(memory_root):
    """Aggregate the post-run annotation layer without exporting candidate values."""
    replay_path, demo_path = memory_root / "value_validation_replay.json", memory_root / "value_validation_demo.json"
    replay, demo = read(replay_path), read(demo_path)
    checks, sources = replay["checks"], replay["sources"]
    count = integer(replay, "detections_replayed")
    if (replay["status"] != "passed" or count != 600 or len(checks) != count or len(sources) != 2
            or sorted(integer(source, "rows") for source in sources) != [200, 400]
            or sum(integer(source, "rows") for source in sources) != count
            or not all(c["original_decisions_preserved"] is True and c["fixed_annotations_without_raw_values"] is True for c in checks)
            or not all(source["original_files_unchanged"] is True for source in sources)
            or integer(replay, "additional_model_calls") != 0 or replay["new_api_cost_cny"] != 0):
        raise ValueError("posthoc_value_validation_replay_failed")
    source_hashes = [{"detections": integer(source, "rows"), "runtime_sha256": source["runtime_sha256"],
                      "rows_sha256": source["rows_sha256"], "original_files_unchanged": True} for source in sources]
    annotation_counts = []
    for item in replay["annotation_counts"]:
        if any(not isinstance(item[key], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item[key])
               for key in ("category", "check", "state")):
            raise ValueError("unexpected_value_validation_annotation_enum")
        annotation_counts.append({key: item[key] for key in ("category", "check", "state")}
                                 | {"count": integer(item, "count")})
    fields = ("source_id", "start", "end", "category")
    candidate_keys = {tuple(item[key] for key in fields) for item in demo["findings"]}
    annotation_keys = {tuple(item[key] for key in fields) for item in demo["validation_annotations"]}
    if (demo["status"] != "ok" or len(demo["findings"]) != 4 or len(candidate_keys) != 4
            or len(demo["validation_annotations"]) != 4
            or candidate_keys != annotation_keys or integer(demo, "local_calls") != 0):
        raise ValueError("value_validation_demo_contract_failed")
    demo_states = {name: sum(a[name] == "invalid" for a in demo["validation_annotations"])
                   for name in ("format", "checksum", "calendar")}
    release = {}
    for run in HELDOUT_RUNS:
        path = memory_root / run / "evidence_verification_release.json"
        obj = read(path)
        checked = verification_summary(obj)
        if (checked["status"] != "passed" or checked["checks"] != 28
                or obj["additional_current_sources"] != ["value_validation.py"]
                or obj["declared_allowed_additions"] != ["value_validation.py"]
                or checked["verification_model_calls"] != 0):
            raise ValueError("executed_source_preservation_release_check_failed")
        release[run] = dict(checked, executed_sources_preserved=True,
                            complete_current_snapshot_identical=obj["current_snapshot_identical"],
                            only_postrun_added_module="value_validation.py", certificate_sha256=sha(path))
    module = Path(__file__).resolve().parents[1] / "memory_migration_study/value_validation.py"
    return {"status": "passed", "validation_version": replay["validation_version"], "module_sha256": sha(module),
            "replay": {"detections_replayed": count, "decision_preservation_checks_passed": count,
                       "annotation_no_raw_value_checks_passed": count, "source_hashes": source_hashes,
                       "annotation_counts": annotation_counts, "additional_model_calls": 0,
                       "report_sha256": sha(replay_path)},
            "demo": {"status": demo["status"], "candidate_count": 4, "annotated_candidate_count": len(annotation_keys),
                     "candidate_keys_retained": True, "invalid_annotation_counts": demo_states,
                     "additional_model_calls": 0, "report_sha256": sha(demo_path)},
            "executed_source_preservation": release,
            "scope": "Pure advisory post-run validation. It does not change status, findings, authorization or disclosure decisions; invalid checksum/calendar values remain sensitive candidates. This added layer did not participate in frozen neural decisions and does not improve or replace any neural score. Six hundred actual saved detections were replayed without model calls."}


def delivery_integrity(memory_root):
    path = memory_root / "delivery_integrity.json"
    receipt = read(path)
    if (receipt["ledger_unchanged"] is not True or receipt["historical_report_unchanged"] is not True
            or integer(receipt, "new_cloud_calls") != 0
            or ("new_api_cost_cny" in receipt and receipt["new_api_cost_cny"] != 0)):
        raise ValueError("history_or_budget_integrity_failed")
    hashes = {}
    for key, value in receipt.items():
        if key.endswith("_sha256"):
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                raise ValueError("invalid_integrity_hash")
            hashes[key] = value
    return {"status": "passed", "ledger_unchanged": True, "historical_report_unchanged": True,
            "new_cloud_calls": 0, "recorded_hashes": hashes, "receipt_sha256": sha(path)}


def memory_cost(report, identity):
    plain_ner = (isinstance(identity.get("detector"), dict)
                 and identity["detector"].get("runtime", {}).get("model_id", "").startswith("fastino/gliner")
                 and "members" not in identity["detector"])
    parts = {key: integer(report, key) for key in
             ("model_builder_generations", "query_intent_generations", "answer_generations",
              "coverage_builder_encoder_calls", "migration_encoder_calls")}
    resolution = None
    for key in ("coverage_builder_detector_generations", "migration_detector_generations"):
        if key in report:
            parts[key] = integer(report, key)
        elif plain_ner:
            # The earliest archived run predates these columns, but its trusted
            # saved detector identity proves a pure encoder with no LLM member.
            parts[key] = 0
            resolution = "Legacy absent generation columns resolved to zero from saved plain-GLiNER detector contract."
        else:
            raise ValueError("unresolved_memory_generation_count:" + key)
    generations = sum(parts[key] for key in ("model_builder_generations", "query_intent_generations", "answer_generations",
                                              "coverage_builder_detector_generations", "migration_detector_generations"))
    return {"local_generations": generations,
            "local_encoder_invocations": parts["coverage_builder_encoder_calls"] + parts["migration_encoder_calls"],
            "physical_components": parts, "legacy_column_resolution": resolution,
            "accounting_complete": report.get("detector_call_accounting_complete", plain_ner)}


def memory_metrics(report, run):
    """Only the first development predates these two storage measurements.

    Keep those unrecorded values as null. Every other table metric, including
    all storage fields in v2/union and heldout runs, remains strictly required.
    The original loaded report is never mutated.
    """
    metrics, unrecorded = copy.deepcopy(report["arms"]), set()
    for arm, values in metrics.items():
        for field in MEMORY_TABLE_FIELDS:
            if field not in values or values[field] is None:
                if run == "development" and field in LEGACY_STORAGE_FIELDS:
                    values[field] = None
                    unrecorded.add(field)
                else:
                    raise ValueError(f"required_memory_metric_missing:{run}:{arm}:{field}")
            else:
                integer(values, field)
    return metrics, sorted(unrecorded)


def safe_correct_by_arm(report, rows):
    result = {}
    for arm, metrics in report["arms"].items():
        selected = [r for r in rows if r["arm"] == arm and r["score"]["legal"]]
        if len(selected) != integer(metrics, "legal_tasks"):
            raise ValueError("heldout_legal_denominator_mismatch")
        raw = arm == "coverage_raw_local" or all(r.get("mode") == "raw" for r in selected)
        safe = None if raw else sum(r["score"]["correct"] and r.get("prepare_status") == "ok"
                                   and r.get("masking", {}).get("partial") == 0
                                   and r.get("masking", {}).get("unmasked") == 0 for r in selected)
        result[arm] = {"legal_tasks": len(selected), "correct": integer(metrics, "correct"),
                       "correct_with_complete_registered_masking": safe,
                       "raw_local_control_excluded_from_leakage": raw,
                       "scope": "Post-hoc descriptive intersection; all legal questions remain in denominator. No score is changed; registered spans are not all possible privacy."}
    return result


def pins(identity, plan):
    ner = identity.get("ner", identity)
    allowed = ("code_revision", "model_revision", "model_id", "files_sha256", "weights_sha256", "device", "threads", "dependencies")
    if not all(key in ner for key in ("code_revision", "model_revision", "model_id", "weights_sha256")):
        raise ValueError("model_pin_missing")
    config = plan["config"]
    return {"ner": {key: ner[key] for key in allowed if key in ner},
            "qwen": {"model": config["model"], "runtime": config["expected_version"], "digest": config["expected_digest"]}}


def data_and_code_hashes(plan):
    result = {key: value for key, value in plan.items() if key in
              ("runtime_sha256", "evaluation_sha256", "manifest_sha256", "script_sha256",
               "development_runtime_sha256", "selected_input_sha256")}
    source = plan.get("implementation_sha256", plan.get("package_sha256", {}))
    if source:
        result["package_files_sha256"] = {str(name).replace("\\", "/").split("/")[-1]: value for name, value in source.items()}
    return result


def no_cloud(report, *, cost_key="new_api_cost_cny"):
    if report["cloud_calls"] != 0 or report[cost_key] != 0:
        raise ValueError("unexpected_cloud_execution_in_local_protocol")


def lifecycle_summary(report, *, timed):
    cells = []
    expected = {(arm, n) for arm in ("migration", "migration_cached", "generation", "generation_cached") for n in (1, 3, 10)}
    if len(report["cells"]) != len(expected) or {(c["arm"], c["requested_repetitions"]) for c in report["cells"]} != expected:
        raise ValueError("lifecycle_condition_matrix_incomplete")
    for cell in report["cells"]:
        keys = ("arm", "requested_repetitions", "setup_status", "setup_encoder_calls", "migration_encoder_calls",
                "total_physical_encoder_calls", "prepare_calls_executed", "ready_transfers", "cache_hits", "reused_tokens")
        selected = {key: cell[key] for key in keys}
        if integer(cell, "setup_builder_model_calls") != 0:
            raise ValueError("lifecycle_unexpected_generator_setup")
        for key in ("setup_wall_seconds", "prepare_wall_seconds", "restore_instrument_wall_seconds", "cell_wall_seconds"):
            if timed:
                value = cell[key]
                if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                    raise ValueError("invalid_lifecycle_timing")
                selected[key] = value
        cells.append(selected)
    if (sum(c["prepare_calls_executed"] for c in cells) != integer(report, "executed_preparations")
            or sum(c["requested_repetitions"] for c in cells) != integer(report, "registered_preparations")
            or sum(c["total_physical_encoder_calls"] for c in cells) + integer(report["dynamic"], "total_physical_encoder_calls")
               != integer(report, "total_physical_encoder_calls")):
        raise ValueError("lifecycle_physical_total_mismatch")
    if timed:
        for key in ("model_loading_and_asset_validation_wall_seconds", "run_measured_wall_seconds"):
            if not isinstance(report[key], (int, float)) or isinstance(report[key], bool) or report[key] < 0:
                raise ValueError("required_lifecycle_run_timing_missing")
    return {"status": report["status"], "independent_source_stories": integer(report, "independent_source_stories"),
            "executed_preparations": integer(report, "executed_preparations"),
            "registered_preparations": integer(report, "registered_preparations"), "cells": cells,
            "dynamic_status": report["dynamic"]["status"],
            "total_physical_encoder_calls": integer(report, "total_physical_encoder_calls"),
            "local_generations": integer(report, "model_answer_calls"),
            "model_loading_and_asset_validation_wall_seconds": report.get("model_loading_and_asset_validation_wall_seconds"),
            "run_measured_wall_seconds": report.get("run_measured_wall_seconds"),
            "timing_recorded": timed, "scope": "One development story; actual 1/3/10 transfers and host lifecycle witnesses. Programmatic restoration probe, not task accuracy or native online revocation."}


def build_summary(memory_root, detection_root, tests_log):
    required = require_files(memory_root, detection_root, tests_log)
    tests = test_results(tests_log)
    advisory, history_integrity = validation_advisory(memory_root), delivery_integrity(memory_root)
    memory, evidence, networks, costs, hashes, source_pins = {}, {}, {}, [], {}, {}
    heldout_cards = []
    for run in MEMORY_RUNS:
        folder = memory_root / run
        report, plan, identity = read(folder / "report.json"), read(folder / "plan.json"), read(folder / "runtime_identity.json")
        no_cloud(report)
        metrics, unrecorded = memory_metrics(report, run)
        cost = memory_cost(report, identity)
        costs.append(dict(cost, run_id="memory/" + run, evidence_sha256=sha(folder / "report.json")))
        memory[run] = {"split": report["split"], "source_stories": integer(report, "source_stories"),
                       "template_families": integer(report, "template_families"), "arms": metrics,
                       "legacy_unrecorded_storage_fields": unrecorded,
                       "implementation_unchanged": report["implementation_unchanged"]}
        networks["memory/" + run] = network_summary(read(folder / "network_audit.json"))
        hashes["memory/" + run] = data_and_code_hashes(plan)
        source_pins["memory/" + run] = pins(identity, plan)
        if run in HELDOUT_RUNS:
            rows, runtime = read(folder / "rows.json"), read(folder / "runtime.json")
            expected = sum(len(story["tasks"]) for story in runtime) * len(report["arms"])
            if len(rows) != expected or len(runtime) != report["source_stories"]:
                raise ValueError("heldout_matrix_incomplete")
            evidence[run] = verification_summary(read(folder / "evidence_verification.json"))
            memory[run]["posthoc_correct_and_complete_masking"] = safe_correct_by_arm(report, rows)
            heldout_cards.append((run, rows, runtime))
    detection = {}
    for split in ("development", "heldout"):
        folder = detection_root / split
        original, plan = read(folder / "report.json"), read(folder / "plan.json")
        no_cloud(original)
        selected = original
        if split == "development":
            selected = read(folder / "accounting_recheck.json")
            if (selected["original_report_sha256"] != sha(folder / "report.json")
                    or selected["predictions_and_scores_unchanged"] is not True or selected["new_model_calls"] != 0):
                raise ValueError("development_cost_recheck_not_bound_to_original")
            generations, encoders = integer(selected, "qwen_generations_recomputed"), integer(selected, "encoder_invocations_recomputed")
            complete = selected["complete_reconstructed_call_accounting"]
        else:
            generations, encoders = integer(selected, "qwen_generations_reported"), integer(selected, "encoder_invocations_reported")
            complete = selected["complete_call_accounting"]
        costs.append({"run_id": "detection/" + split, "local_generations": generations, "local_encoder_invocations": encoders,
                      "accounting_complete": complete, "evidence_sha256": sha(folder / ("accounting_recheck.json" if split == "development" else "report.json"))})
        detection[split] = {"materials": integer(original, "material_count"), "arms": selected["arms"],
                            "implementation_unchanged": original["implementation_unchanged"],
                            "cost_basis": "independent_accounting_recheck" if split == "development" else "frozen_report",
                            "split_statistics": plan["split_statistics"]}
        networks["detection/" + split] = network_summary(read(folder / "network_audit.json"))
        hashes["detection/" + split] = data_and_code_hashes(plan)
    lifecycle = {}
    for run in ("lifecycle", "lifecycle_timed"):
        folder = memory_root / run
        report = read(folder / "report.json")
        no_cloud(report)
        detector_identity = read(folder / "runtime_identity.json")["detector"]
        if ("members" in detector_identity
                or not detector_identity.get("runtime", {}).get("model_id", "").startswith("fastino/gliner")):
            raise ValueError("lifecycle_encoder_only_contract_unproven")
        selected = lifecycle_summary(report, timed=run.endswith("_timed"))
        lifecycle[run] = selected
        costs.append({"run_id": run, "local_generations": selected["local_generations"],
                      "local_encoder_invocations": selected["total_physical_encoder_calls"],
                      "accounting_complete": True, "evidence_sha256": sha(folder / "report.json")})
        networks[run] = network_summary(read(folder / "network_audit.json"))
        hashes[run] = data_and_code_hashes(read(folder / "plan.json"))
    probe = read(memory_root / "ner_label_probe/report.json")
    no_cloud(probe, cost_key="api_cost_cny")
    probe_verification = verification_summary(read(memory_root / "ner_label_probe/verification.json"))
    costs.append({"run_id": "development_schema_probe", "local_generations": integer(probe, "qwen_calls"),
                  "local_encoder_invocations": integer(probe, "actual_local_encoder_invocations"),
                  "accounting_complete": probe_verification["status"] == "passed",
                  "evidence_sha256": sha(memory_root / "ner_label_probe/report.json")})
    networks["development_schema_probe"] = network_summary(probe["network_audit"])
    if len({c["run_id"] for c in costs}) != len(costs):
        raise ValueError("duplicate_physical_run_in_cost_ledger")
    detection_gates = {}
    for arm, metrics in detection["heldout"]["arms"].items():
        p, r = metrics["accepted"]["precision"], metrics["accepted"]["recall"]
        passed = p is not None and r is not None and p >= .90 and r >= .95
        no_review = metrics["needs_review"] == 0 and metrics["other_non_ok"] == 0
        detection_gates[arm] = {"precision": p, "recall": r, "precision90_recall95": status(passed),
                               "no_review_or_error": status(no_review), "combined_status": status(passed and no_review)}
    memory_gates = {}
    for run in HELDOUT_RUNS:
        memory_gates[run] = {arm: {"zero_registered_masking_gaps": status(m["ready_with_masking_gaps"] == 0),
                                   "zero_unauthorized_outputs": status(m["unauthorized_output"] == 0),
                                   "legal_correct": m["correct"], "legal_denominator": m["legal_tasks"]}
                            for arm, m in memory[run]["arms"].items() if arm in PRIVATE_ARMS}
    detector_accepted = any(g["combined_status"] == "passed" for g in detection_gates.values())
    integrity = {"engineering_tests": tests["status"],
                 "heldout_evidence": status(all(v["status"] == "passed" for v in evidence.values())),
                 "source_unchanged": status(all(r["implementation_unchanged"] is True for r in memory.values())
                                            and all(r["implementation_unchanged"] is True for r in detection.values())),
                 "physical_call_accounting": status(all(c["accounting_complete"] is True for c in costs)),
                 "network_audits": status(all(n["status"] == "passed" for n in networks.values())),
                 "lifecycle_witnesses": status(all(r["status"] == "passed" and r["dynamic_status"] == "passed" for r in lifecycle.values())),
                 "advisory_validation_and_source_preservation": advisory["status"],
                 "historical_results_and_budget": history_integrity["status"]}
    summary = {"version": VERSION, "title": "预设协议执行结果", "date": "2026-10-25",
        "execution": {"status": "completed" if all(v == "passed" for v in integrity.values()) else "completed_with_evidence_errors",
                       "integrity_checks": integrity, "required_artifacts": len(required),
                       "scope": "Pre-specified local implementation, controls and evaluation delivery; not completion of the full research roadmap or production capability."},
        "acceptance": {"detection_precision90_recall95_and_no_review": status(detector_accepted),
                       "detection_by_condition": detection_gates, "registered_memory_checks": memory_gates,
                       "legal_utility": "Descriptive results only; no new numeric utility threshold is invented after seeing heldout results.",
                       "overall_effect_acceptance": "failed" if not detector_accepted else "not_established",
                       "full_research_or_production_completed": False},
        "memory": memory, "detection": detection, "lifecycle": lifecycle,
        "evidence_verification": evidence, "probe_verification": probe_verification, "tests": tests,
        "value_validation_advisory": advisory, "delivery_integrity": history_integrity,
        "physical_run_costs": costs,
        "total_actual_local_generations": sum(c["local_generations"] for c in costs),
        "total_actual_local_encoder_invocations": sum(c["local_encoder_invocations"] for c in costs),
        "physical_call_accounting_complete": all(c["accounting_complete"] is True for c in costs),
        "cloud_calls": 0, "new_api_cost_cny": 0, "source_model_pins": source_pins, "data_and_code_hashes": hashes,
        "final_protocol_sha256": sha(memory_root / "final_heldout_freeze.json"),
        "network_audits": networks, "summarizer_sha256": sha(__file__),
        "limitations": [
            "Authored synthetic data; labels are programmatically checked, not independently human adjudicated or enterprise ground truth.",
            "Heldout memory: 16 stories from 8 bilingual template families, 64 legal tasks per condition; tasks/conditions are not independent stories.",
            "Heldout detection: 40 materials, only 20 positive registered spans, 3 template families and 18 private/public payload pairs; not 40 independent contents.",
            "Lossless source chunking stores more text and source copies; it is not semantic summarization or a new compression algorithm.",
            "Closed-set intent hints transmit semantic side information; registered-span masking does not prove protection from inference leakage.",
            "Raw local control uses synthetic plaintext and is excluded from masking-leak counts; never treat its utility as pseudonymized privacy success.",
            "Correct-and-completely-masked counts are post-hoc descriptive intersections with the full legal denominator, not altered correctness labels.",
            "Lifecycle is one-source, same-process host instrumentation; no native online revocation, arbitrary derived-memory policies or production security claim.",
            "Every actually executed development run, schema probe and both lifecycle runs is counted once; per-arm allocated builder/intent costs are not added to physical totals."]}
    return summary, heldout_cards


def esc(value):
    if value is None:
        value = "未测／不适用"
    return html.escape(str(value), quote=True)


def table(headers, rows):
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>' + esc(x) + '</th>' for x in headers) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join('<td>' + esc(x) + '</td>' for x in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def percent(value):
    return None if value is None else f"{100 * value:.2f}%"


def storage_cell(run, metrics, field):
    value = metrics[field]
    return "当时未记录" if run == "development" and field in LEGACY_STORAGE_FIELDS and value is None else value


def render(summary, cards):
    parts = ['<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;unsafe-inline&#39;; style-src &#39;unsafe-inline&#39;">',
        '<title>预设协议执行结果</title><style>body{font:15px/1.65 system-ui;margin:28px;background:#f5f7fb;color:#213047}h1,h2{color:#173d64}.notice{background:#fff0d2;border-left:5px solid #cf8a21;padding:14px}.scroll{overflow:auto}table{border-collapse:collapse;background:white;margin:14px 0;white-space:nowrap}td,th{border:1px solid #c5cfdd;padding:7px 10px}details{background:white;border:1px solid #cbd5e1;border-radius:6px;margin:10px 0;padding:12px}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef2f7;padding:10px}input,select{padding:9px;margin:5px;max-width:90vw}.meta{color:#52657b}.hidden{display:none}.failure{color:#9f2f25}section{margin:28px 0}</style>',
        '<h1>预设协议执行结果</h1><p>已完成预设本地实验与交付，执行完成和性能验收分开判断。本页保留开发、正式保留、失败及成本证据。</p>',
        '<p class="notice">效果验收状态：' + esc(summary["acceptance"]["overall_effect_acceptance"]) + '。检测目标为完整片段召回率≥95%、精确率≥90%，待审单列；绿色工程测试不能替代隐私或合法问答验收。完整科研路线和生产能力未宣称完成。</p>',
        '<p>全程新增云端调用0、API费用0元。实际本地生成 ' + esc(summary["total_actual_local_generations"]) + ' 次，编码 ' + esc(summary["total_actual_local_encoder_invocations"]) + ' 次；计算类型不视为等价成本。</p>',
        '<p>最终测试：' + esc(summary["tests"]["executed"]) + '项，状态' + esc(summary["tests"]["status"]) + '。<a href="summary.json">本地聚合JSON</a></p>',
        '<section><h2>开发与正式保留的完整问答对照</h2><p>开发8故事/4模板族、每条件32合法题；保留16故事/8模板族、每条件64合法题。所有问题留在分母。程序原文分块是更大存储强基线，不是语义摘要。</p>']
    memory_rows = []
    for run, report in summary["memory"].items():
        for arm, m in report["arms"].items():
            safe = report.get("posthoc_correct_and_complete_masking", {}).get(arm, {}).get("correct_with_complete_registered_masking")
            memory_rows.append([run, arm, f"{m['correct']}/{m['legal_tasks']}", safe, m["ready"],
                f"{m['build_successes']}/{m['build_stories']}", m["supported_legal_tasks"], m["true_model_unknown"], m["restoration_failure"],
                "本地明文参照" if arm == "coverage_raw_local" else m["ready_with_masking_gaps"], m["extra_masked_characters"],
                m["stored_characters"], storage_cell(run,m,"stored_record_json_bytes"),
                storage_cell(run,m,"stored_source_copy_characters"), m["unauthorized_output"]])
    parts.append(table(['实际run','条件','合法答对','答对且完整遮蔽*','可准备','构建成功/故事','必要事实保留题','模型UNKNOWN','恢复失败','有漏遮请求','额外遮蔽字符','存储文本字符','记录JSON字节','源副本文字','越权输出'], memory_rows))
    parts.append('<p class="meta">* 仅正式保留的私密条件统计，要求同一道题答对、prepare成功且注册片段partial=0/unmasked=0；仍以全部64合法题为分母。它是事后描述，未改变原分数。raw_local的明文只送本地模型，不算脱敏泄漏或隐私成功。</p></section>')
    parts.append('<section><h2>九类检测：接受预测与待审候选</h2><p>非ok结果在主指标中接受0预测、敏感真值保留为FN；候选结果另列。保留40材料仅20个敏感片段、3个模板族、18对同文本策略配对，不能当作40个独立故事。</p>')
    detection_rows = []
    category_rows = []
    for split, report in summary["detection"].items():
        for arm, m in report["arms"].items():
            p, r = m["accepted"]["precision"], m["accepted"]["recall"]
            gate = status(p is not None and r is not None and p >= .90 and r >= .95)
            detection_rows.append([split, arm, m["materials"], m["accepted"]["tp"], m["accepted"]["fp"], m["accepted"]["fn"], percent(p), percent(r),
                                   percent(m["validated_candidate"]["precision"]), percent(m["validated_candidate"]["recall"]), m["needs_review"], gate])
            if split == "heldout":
                for cat, scores in m["by_category"].items():
                    accepted = scores["accepted"]
                    category_rows.append([arm,cat,accepted["tp"],accepted["fp"],accepted["fn"],percent(accepted["precision"]),percent(accepted["recall"])])
    parts.append(table(['划分','条件','材料','TP','FP','FN','主精确率','主召回率','候选精确率','候选召回率','待审','95/90数值门槛'],detection_rows))
    parts.append('<details><summary>展开正式保留的九类别结果</summary>' + table(['条件','类别','TP','FP','FN','精确率','召回率'],category_rows) + '</details></section>')
    parts.append('<section><h2>真实1／3／10次迁移与耗时</h2><p>以下为单一开发故事的实际调用；程序恢复探针不是模型答题。旧未计时运行和新计时运行都实际发生，成本分别计一次。未测时间显示未测。</p>')
    lifecycle_rows=[]
    for run, report in summary["lifecycle"].items():
        for cell in sorted(report["cells"],key=lambda c:(c["arm"],c["requested_repetitions"])):
            lifecycle_rows.append([run,cell["arm"],cell["requested_repetitions"],cell["setup_encoder_calls"],cell["migration_encoder_calls"],cell["total_physical_encoder_calls"],cell["ready_transfers"],cell["cache_hits"],cell.get("setup_wall_seconds"),cell.get("prepare_wall_seconds"),cell.get("restore_instrument_wall_seconds"),cell.get("cell_wall_seconds")])
    parts.append(table(['实际run','方法','重复次数','构建编码','迁移编码','总编码','准备成功','缓存命中','构建秒','迁移API秒','程序恢复秒','单格累计秒'],lifecycle_rows))
    parts.append('<p>计时运行模型加载／资产校验：' + esc(summary["lifecycle"]["lifecycle_timed"]["model_loading_and_asset_validation_wall_seconds"]) + '秒；整次已测运行：' + esc(summary["lifecycle"]["lifecycle_timed"]["run_measured_wall_seconds"]) + '秒。单次本机观察，不作跨设备速度或吞吐泛化。</p></section>')
    parts.append('<section><h2>实际计算量账本</h2>' + table(['run（每项只计一次）','本地生成','本地编码','计量完整'],[[c["run_id"],c["local_generations"],c["local_encoder_invocations"],c["accounting_complete"]] for c in summary["physical_run_costs"]]) + '<p>开发检测使用独立accounting_recheck修正：375次生成、248次编码；原报告仍保留。条件分摊的构建/意图成本没有再次加入物理总数。</p></section>')
    advisory=summary['value_validation_advisory']
    parts.append('<section><h2>事后格式／校验位／日期注记与原执行源码保持</h2><p>新增纯建议性层在冻结神经模型判定之后运行；它不改status、findings或权限，不因校验位或日历无效放行，也不能声称改善神经模型分数。已对实际保存的 '+esc(advisory['replay']['detections_replayed'])+' 份检测结果单独重放，新增模型调用为0。</p>')
    parts.append(table(['核查项','状态／数量'],[['真实检测重放',advisory['replay']['detections_replayed']],['原判定保持检查通过',advisory['replay']['decision_preservation_checks_passed']],['演示候选全部保留',advisory['demo']['candidate_count']],['演示非法校验位注记',advisory['demo']['invalid_annotation_counts']['checksum']],['演示非法日期注记',advisory['demo']['invalid_annotation_counts']['calendar']],['费用账本保持',summary['delivery_integrity']['ledger_unchanged']],['历史报告保持',summary['delivery_integrity']['historical_report_unchanged']]]))
    parts.append(table(['正式variant','发布核验','通过检查','旧执行源码保持','唯一事后新增模块'],[[run,v['status'],f"{v['passed_checks']}/{v['checks']}",v['executed_sources_preserved'],v['only_postrun_added_module']] for run,v in advisory['executed_source_preservation'].items()])+'<p class="meta">完整当前快照与执行时快照不同，仅因为新增value_validation.py；两份发布核验证明原执行源未改。公开聚合只含状态、数量和哈希，不含演示原值、候选位置或恢复映射。</p></section>')
    parts.append('<section><h2>正式保留逐题：原文 → 实际模型输入 → 回答 → 恢复</h2><p>搜索故事、语言、条件、问题、原文或失败码；展开卡片可看完整实际outbound。固定意图hint若被加入，也原样显示。这里只包含自编合成文字，不保存恢复映射或密钥。</p><input id="search" type="search" placeholder="搜索问题、故事、条件、错误…"><select id="variant"><option value="">全部variant</option>' + ''.join('<option value="'+esc(run)+'">'+esc(run)+'</option>' for run,_,_ in cards) + '</select><span id="visible"></span>')
    for run, rows, runtime in cards:
        stories = {s["story_id"]:s for s in runtime}
        for row in rows:
            story=stories[row["story_id"]]
            task=next(t for t in story["tasks"] if t["task_id"]==row["task_id"])
            outbound=row.get("outbound")
            outbound_text=(json.dumps(outbound,ensure_ascii=False,indent=2) if outbound is not None else
                           "未执行模型调用" if row.get("answer_calls")==0 else "实际outbound未保存，不能用重构输入代替")
            title=f"{run} · {row['language']} · {row['story_id']} · {row['task_id']} · {row['arm']} · correct={row['score']['correct']}"
            state={key:row.get(key) for key in ('actor_id','build_status','prepare_status','prepare_error','module_authorization_error','intent_applied','intent_error','answer_status','answer_error','restoration_status','restoration_error','checks')}
            parts.append('<details class="case" data-variant="'+esc(run)+'"><summary>'+esc(title)+'</summary><p><strong>原问题</strong></p><pre>'+esc(task['query'])+'</pre><p><strong>源原文</strong></p><pre>'+esc(story['source']['text'])+'</pre><p><strong>实际outbound（包括真实hint）</strong></p><pre>'+esc(outbound_text)+'</pre><p><strong>模型原回答</strong></p><pre>'+esc(row.get('model_answer'))+'</pre><p><strong>最终恢复答案</strong></p><pre>'+esc(row.get('final_answer'))+'</pre><p><strong>构建、意图、权限与失败状态</strong></p><pre>'+esc(json.dumps(state,ensure_ascii=False,indent=2))+'</pre></details>')
    parts.append('</section><section><h2>证据范围与限制</h2><ul>'+''.join('<li>'+esc(item)+'</li>' for item in summary['limitations'])+'</ul></section>')
    parts.append('''<script>
const q=document.getElementById('search'),variant=document.getElementById('variant'),cards=[...document.querySelectorAll('.case')];
function filter(){const term=q.value.toLocaleLowerCase();let shown=0;for(const card of cards){const ok=(!variant.value||card.dataset.variant===variant.value)&&card.textContent.toLocaleLowerCase().includes(term);card.classList.toggle('hidden',!ok);shown+=ok?1:0;}document.getElementById('visible').textContent=` 显示 ${shown} / ${cards.length}`;}
q.addEventListener('input',filter);variant.addEventListener('change',filter);filter();
</script></html>''')
    return ''.join(parts)


def assert_aggregate_only(obj):
    forbidden = {"rows", "query", "text", "outbound", "mapping", "map", "key", "api_key", "authority", "record_store", "source_text"}
    def visit(value):
        if isinstance(value, dict):
            if forbidden.intersection(value):
                raise ValueError("raw_material_in_public_summary")
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str) and re.search(r"(?i)(?:[A-Z]:[/\\]|wxid_|xwechat_files|sk-[A-Za-z0-9]{24,})", value):
            raise ValueError("private_path_or_credential_in_public_summary")
    visit(obj)


def deliver(memory_root, detection_root, output, public_summary, tests_log=None):
    memory_root, detection_root, output, public_summary = map(Path,(memory_root,detection_root,output,public_summary))
    tests_log=Path(tests_log) if tests_log is not None else memory_root/'unittest_delivery.log'
    if output.exists() or public_summary.exists():
        raise FileExistsError("new_hub_and_public_summary_paths_required")
    summary,cards=build_summary(memory_root,detection_root,tests_log)
    assert_aggregate_only(summary)
    body=render(summary,cards)
    output.mkdir(parents=True,exist_ok=False)
    public_summary.parent.mkdir(parents=True,exist_ok=True)
    raw=json.dumps(summary,ensure_ascii=False,indent=2)+'\n'
    (output/'summary.json').write_text(raw,encoding='utf-8')
    public_summary.write_text(raw,encoding='utf-8')
    (output/'index.html').write_text(body,encoding='utf-8')
    return summary


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--memory-root',type=Path,default=Path('results/semantic_memory_v1'))
    parser.add_argument('--detection-root',type=Path,default=Path('results/semantic_detection_v1'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--public-summary',type=Path,default=Path('benchmarks/semantic_memory_delivery_20261025_summary.json'))
    parser.add_argument('--tests-log',type=Path)
    args=parser.parse_args()
    result=deliver(args.memory_root,args.detection_root,args.output,args.public_summary,args.tests_log)
    print(json.dumps({'execution':result['execution']['status'],'effect_acceptance':result['acceptance']['overall_effect_acceptance'],
                      'tests':result['tests'],'local_generations':result['total_actual_local_generations'],
                      'local_encoder_invocations':result['total_actual_local_encoder_invocations']},ensure_ascii=False))
