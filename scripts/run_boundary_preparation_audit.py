"""Replay frozen boundary findings through old/new local preparation, no models.

All material rows and masking footprints are fixed before evaluation labels are
parsed.  Witnesses are authored mechanism checks, not a detection/QA benchmark.
Restoration maps, token lookup entries and keys are never exported.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.privacy import (CATEGORIES, _digest, _sources, detect_sensitive,
    prepare_private_payload, restore_answer)
from memory_migration_study.privacy_egress import validate_outbound
from memory_migration_study.privacy_payload_eval import masking_intervals


VERSION = "boundary_preparation_replay_audit_v1"
ARMS = ("legacy_prepare", "boundary_prepare")
DEFAULT_EVALUATION = Path("results/semantic_detection_v1/development/evaluation.json")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")


def source_hashes(source):
    return {path.relative_to(source).as_posix(): sha(path) for path in sorted(source.rglob("*")) if path.is_file()}


def preparation_functions():
    from memory_migration_study.boundary_preparation import prepare_boundary_payload
    return {"legacy_prepare": prepare_private_payload, "boundary_prepare": prepare_boundary_payload}


def prepare_material(case, detection, arm, prepare):
    payload, policy = case["payload"], case["policy"]
    actor, request = "preparation-audit-owner", VERSION+":"+case["case_id"]+":"+arm
    memory_ids = {item["source_id"] for item in payload["memories"]}
    def authorizer(source_id, current_actor, version):
        return source_id in memory_ids and current_actor == actor and version == policy["version"]
    try:
        prepared = prepare(copy.deepcopy(payload), copy.deepcopy(detection), actor_id=actor,
            request_id=request, policy_version=policy["version"], sensitivity_policy=copy.deepcopy(policy),
            authorizer=authorizer)
    except Exception as exc:
        # Unexpected implementation errors remain explicit failed material rows;
        # do not expose exception strings which can contain source text.
        return {"case_id": case["case_id"], "language": case["language"], "template_family": case["template_family"],
            "arm": arm, "source_detection_sha256": _digest(detection), "detection_status": detection.get("status"),
            "prepare_status": "needs_review", "prepare_error": "preparation_exception",
            "egress": {"status": "blocked", "code": "preparation_exception"}, "prepared_payload": None,
            "mask_alignment_status": "not_ready", "mask_footprint": {}, "metadata": {},
            "audit_exception_type": type(exc).__name__}
    egress = validate_outbound(payload, prepared, detection, policy)
    row = {"case_id": case["case_id"], "language": case["language"], "template_family": case["template_family"],
           "arm": arm, "source_detection_sha256": _digest(detection), "detection_status": detection.get("status"),
           "prepare_status": prepared.get("status"), "prepare_error": prepared.get("error"), "egress": egress,
           "prepared_payload": copy.deepcopy(prepared.get("payload")), "mask_alignment_status": "not_ready",
           "mask_footprint": {}, "metadata": copy.deepcopy(prepared.get("metadata", {}))}
    if prepared.get("status") == "ok":
        try:
            pairs = [("__query__", payload["query"], prepared["payload"]["query"])]
            pairs.extend((original["source_id"], original["text"], transformed["text"])
                for original, transformed in zip(payload["memories"], prepared["payload"]["memories"], strict=True))
            row["mask_footprint"] = {sid: masking_intervals(raw, transformed, prepared["mapping"]._entries)
                                     for sid, raw, transformed in pairs}
            row["mask_alignment_status"] = "ok"
        except (TypeError, ValueError, KeyError, AttributeError):
            row["mask_alignment_status"] = "audit_failed"
            row["mask_footprint"] = {}
    # Do not return the opaque map or any entry/token-to-value lookup.
    prepared["mapping"] = None
    return row


def score_mask(row, gold):
    ready = (row["prepare_status"] == "ok" and row["egress"]["status"] == "ok"
             and row["mask_alignment_status"] == "ok")
    sensitive = {(span["source_id"], position) for span in gold["findings"]
                 for position in range(span["start"], span["end"])}
    masked = {(sid, position) for sid, intervals in row["mask_footprint"].items()
              for start, end in intervals for position in range(start, end)} if ready else set()
    complete = partial = uncovered = 0
    for span in gold["findings"]:
        target = {(span["source_id"], position) for position in range(span["start"], span["end"])}
        overlap = target & masked
        complete += overlap == target
        partial += bool(overlap) and overlap != target
        uncovered += not overlap
    return {"ready": ready, "gold_spans": len(gold["findings"]), "fully_masked_spans": complete,
            "partially_masked_spans": partial, "unmasked_or_not_ready_spans": uncovered,
            "masked_unprotected_characters": len(masked-sensitive) if ready else None,
            "all_reference_spans_masked_and_ready": ready and complete == len(gold["findings"])}


def validate_evaluation(runtime, gold):
    if not isinstance(gold, dict) or set(gold) != {case["case_id"] for case in runtime}:
        raise ValueError("evaluation_runtime_identity_mismatch")
    for case in runtime:
        reference, sources = gold[case["case_id"]], _sources(case["payload"])
        if not isinstance(reference, dict) or not isinstance(reference.get("findings"), list):
            raise ValueError("invalid_evaluation_findings")
        seen = set()
        for item in reference["findings"]:
            if not isinstance(item, dict):
                raise ValueError("invalid_evaluation_span")
            sid, start, end, category = (item.get(key) for key in ("source_id", "start", "end", "category"))
            if (sid not in sources or type(start) is not int or type(end) is not int
                    or not 0 <= start < end <= len(sources[sid]) or category not in CATEGORIES
                    or ("quote" in item and item["quote"] != sources[sid][start:end])):
                raise ValueError("invalid_evaluation_span")
            identity = (sid, start, end, category)
            if identity in seen:
                raise ValueError("duplicate_evaluation_span")
            seen.add(identity)


def witness_suite(functions):
    """Explicit query seed, then test real restore; no model or gold lookup."""
    policy = {"version": "query-key-witness-v1", "protected_categories": ["CUSTOMER"]}
    definitions = [
        ("query_key_only", [{"source_id": "key", "text": "客户：尚未填写"}],
         {"legacy_prepare": "ok", "boundary_prepare": "blocked"}),
        ("same_name_real_value", [{"source_id": "real", "text": "客户：客户"}],
         {"legacy_prepare": "ok", "boundary_prepare": "ok"}),
        ("independent_real_source", [{"source_id": "key", "text": "客户：尚未填写"},
                                      {"source_id": "real", "text": "客户：客户"}],
         {"legacy_prepare": "ok", "boundary_prepare": "ok"}),
    ]
    rows = []
    for case_id, memories, expected in definitions:
        payload = {"query": "客户", "memories": copy.deepcopy(memories)}
        def exact_query_seed(**kwargs):
            return {"status": "ok", "errors": [], "local_calls": 0, "elapsed_seconds": 0.0,
                "findings": [{"start": 0, "end": 2, "quote": "客户", "category": "CUSTOMER"}]
                            if kwargs["source_id"] == "__query__" else []}
        detection = detect_sensitive(payload, policy, agent=exact_query_seed, mode="agent")
        if detection["status"] != "ok" or detection["local_calls"] != 0:
            raise ValueError("witness_instrument_contract_failed")
        for arm, prepare in functions.items():
            actor, request = "witness-owner", VERSION+":"+case_id+":"+arm
            allowed = {item["source_id"] for item in memories}
            def authorizer(sid, current_actor, version):
                return sid in allowed and current_actor == actor and version == policy["version"]
            prepared = prepare(payload, detection, actor_id=actor, request_id=request,
                policy_version=policy["version"], sensitivity_policy=policy, authorizer=authorizer)
            egress = validate_outbound(payload, prepared, detection, policy)
            def restore_now():
                if prepared.get("status") != "ok" or egress["status"] != "ok":
                    return {"status": "blocked", "error": prepared.get("error") or egress.get("code"), "answer": None}
                return restore_answer(prepared["payload"]["query"], prepared["mapping"], actor_id=actor,
                    request_id=request, policy_version=policy["version"], sensitivity_policy=policy, authorizer=authorizer)
            initial = restore_now()
            observations = {"initial": {"status": initial["status"], "error": initial.get("error"),
                "answer_sha256": hashlib.sha256(initial["answer"].encode()).hexdigest() if initial.get("answer") else None}}
            expectations = {"initial": expected[arm]}
            if case_id == "independent_real_source":
                allowed.discard("key")
                key_revoked = restore_now()
                observations["key_only_source_revoked"] = {"status": key_revoked["status"], "error": key_revoked.get("error")}
                expectations["key_only_source_revoked"] = "ok" if arm == "boundary_prepare" else "blocked"
                allowed.discard("real")
                real_revoked = restore_now()
                observations["real_source_revoked"] = {"status": real_revoked["status"], "error": real_revoked.get("error")}
                expectations["real_source_revoked"] = "blocked"
            correct_value = initial.get("answer") == "客户" if expected[arm] == "ok" else initial.get("answer") is None
            rows.append({"case_id": case_id, "arm": arm, "payload": copy.deepcopy(payload),
                "prepare_status": prepared.get("status"), "prepare_error": prepared.get("error"), "egress": egress,
                "observations": observations, "expected_statuses": expectations,
                "expected_observations_met": correct_value and all(observations[name]["status"] == status
                    for name, status in expectations.items()),
                "boundary_preparation_metadata": copy.deepcopy(prepared.get("metadata", {}).get("boundary_preparation"))})
            prepared["mapping"] = None
    return {"kind": "authored_query_key_source_evidence_witnesses_not_a_benchmark",
            "rows": rows, "boundary_expectations_met": all(row["expected_observations_met"]
                for row in rows if row["arm"] == "boundary_prepare"),
            "legacy_query_key_only_allowed": any(row["case_id"] == "query_key_only" and row["arm"] == "legacy_prepare"
                and row["observations"]["initial"]["status"] == "ok" for row in rows),
            "additional_inference_calls": 0, "mapping_persisted": False}


def run(source, output, *, runtime_path=None, evaluation_path=DEFAULT_EVALUATION, expected_materials=80, progress=None):
    source, output = Path(source).resolve(), Path(output).resolve()
    runtime_path = Path(runtime_path).resolve() if runtime_path is not None else source/"runtime.json"
    evaluation_path = Path(evaluation_path).resolve()
    if output == source or output.is_relative_to(source):
        raise ValueError("output_must_not_modify_frozen_source")
    if type(expected_materials) is not int or expected_materials < 1:
        raise ValueError("invalid_expected_material_count")
    frozen_source = source_hashes(source)
    inputs_before = {"runtime": sha(runtime_path), "evaluation": sha(evaluation_path)}
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    source_runtime = source/"runtime.json"
    if source_runtime.is_file() and sha(source_runtime) != inputs_before["runtime"]:
        raise ValueError("runtime_differs_from_frozen_boundary_run")
    if not isinstance(runtime, list) or len(runtime) != expected_materials:
        raise ValueError("all_registered_materials_required")
    if len({case["case_id"] for case in runtime}) != len(runtime):
        raise ValueError("duplicate_runtime_identity")
    for case in runtime:
        if set(case) != {"case_id", "language", "template_family", "policy", "payload"}:
            raise ValueError("runtime_must_exclude_evaluation_labels")
        _sources(case["payload"])
    saved = json.loads((source/"rows.json").read_text(encoding="utf-8"))
    selected = [row for row in saved if row.get("arm") == "boundary_refined"]
    indexed = {row["case_id"]: row for row in selected}
    if len(indexed) != len(selected) or set(indexed) != {case["case_id"] for case in runtime}:
        raise ValueError("exactly_one_boundary_receipt_per_material_required")
    package = Path(__file__).resolve().parents[1]/"memory_migration_study"
    implementation = [*sorted(package.glob("*.py")), Path(__file__).resolve()]
    code_before = {str(path): sha(path) for path in implementation}
    functions = preparation_functions()
    output.mkdir(parents=True, exist_ok=False)
    archive = output/"implementation"
    archive.mkdir()
    for path in implementation:
        shutil.copy2(path, archive/path.name)
    save(output/"plan.json", {"version": VERSION, "arms": ARMS, "expected_materials": expected_materials,
        "source_sha256": frozen_source, "input_sha256": inputs_before, "implementation_sha256": code_before,
        "input_origin": "boundary_refined final host findings; no detector re-execution",
        "scope": "Exposed development replay plus authored mechanism witnesses. No new blind acceptance, detection improvement or downstream QA claim.",
        "new_inference_counts": {"local_encoder": 0, "local_generation": 0, "unknown": 0}, "cloud_calls": 0})
    shutil.copy2(runtime_path, output/"runtime.json")
    rows = []
    for case in runtime:
        detection = indexed[case["case_id"]]["detection"]
        for arm in ARMS:
            rows.append(prepare_material(case, detection, arm, functions[arm]))
        save(output/"rows.json", rows)
        if progress:
            progress({"prepared_materials": len(rows)//len(ARMS), "registered_materials": len(runtime)})
    witnesses = witness_suite(functions)
    save(output/"witnesses.json", witnesses)
    if (frozen_source != source_hashes(source) or inputs_before != {"runtime": sha(runtime_path), "evaluation": sha(evaluation_path)}
            or code_before != {str(path): sha(path) for path in implementation}):
        raise ValueError("frozen_inputs_or_implementation_changed")
    # Every preparation, actual payload footprint and witness is fixed first.
    gold = json.loads(evaluation_path.read_text(encoding="utf-8"))
    validate_evaluation(runtime, gold)
    for row in rows:
        row["mask_score"] = score_mask(row, gold[row["case_id"]])
    summary = {}
    for arm in ARMS:
        chosen = [row for row in rows if row["arm"] == arm]
        summary[arm] = {"registered_materials": len(chosen),
            "detection_non_ok": sum(row["detection_status"] != "ok" for row in chosen),
            "prepare_non_ok": sum(row["prepare_status"] != "ok" for row in chosen),
            "egress_non_ok": sum(row["egress"]["status"] != "ok" for row in chosen),
            "instrumentation_errors": sum(row["mask_alignment_status"] == "audit_failed" for row in chosen),
            "preparation_exceptions": sum("audit_exception_type" in row for row in chosen),
            "ready": sum(row["mask_score"]["ready"] for row in chosen),
            "masked_unprotected_characters": sum(row["mask_score"]["masked_unprotected_characters"] or 0 for row in chosen),
            **{key: sum(row["mask_score"][key] for row in chosen) for key in
               ("gold_spans", "fully_masked_spans", "partially_masked_spans", "unmasked_or_not_ready_spans")}}
    report = {"version": VERSION, "material_count": len(runtime), "arms": summary,
        "boundary_witness_expectations_met": witnesses["boundary_expectations_met"],
        "legacy_query_key_only_allowed": witnesses["legacy_query_key_only_allowed"],
        "new_inference_counts": {"local_encoder": 0, "local_generation": 0, "unknown": 0},
        "cloud_calls": 0, "new_api_cost_cny": 0, "source_unchanged": True, "implementation_unchanged": True,
        "mapping_persisted": False, "overall_effectiveness_acceptance": "not_established",
        "scope": "Reuses all frozen development findings. Scores actual prepared payloads after all processing. Non-ready materials retain their reference spans. Witnesses check source attribution only; no answer model, fresh detection, new holdout or semantic privacy guarantee."}
    save(output/"rows.json", rows)
    save(output/"report.json", report)
    return report


def install_no_network_guard(network):
    def audit(event, values):
        if event == "socket.connect":
            network["attempted_connections"] += 1
            network["blocked_connections"] += 1
            raise RuntimeError("preparation_audit_network_forbidden")
    sys.addaudithook(audit)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("results/acceptance_v2_research/boundary_fresh_v1"))
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--evaluation", type=Path, default=DEFAULT_EVALUATION)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    network = {"attempted_connections": 0, "blocked_connections": 0}
    install_no_network_guard(network)
    report = run(args.source, args.output, runtime_path=args.runtime, evaluation_path=args.evaluation,
                 progress=lambda item: print(json.dumps(item, ensure_ascii=False), flush=True))
    save(args.output/"network_audit.json", network)
    print(json.dumps(report, ensure_ascii=False), flush=True)
