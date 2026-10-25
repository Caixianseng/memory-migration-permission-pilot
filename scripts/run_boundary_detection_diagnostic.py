"""Full development detection + preparation + egress boundary diagnostic.

Saved mode replays host-validated GLiNER+rules findings, not raw NER predictions.
Fresh mode runs the pinned encoder once, shared by paired deterministic arms.
Neither mode provides independent blind acceptance on this exposed corpus.
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
from memory_migration_study.boundary_detector import refine_detection
from memory_migration_study.privacy import _digest, _policy, _sources, detect_sensitive, prepare_private_payload
from memory_migration_study.privacy_egress import validate_outbound
from memory_migration_study.privacy_payload_eval import masking_intervals
from scripts.run_semantic_detection_benchmark import CountingAgent, install_network_guard, score_detection, sum_counts

VERSION = "boundary_detection_diagnostic_v1"
ARMS = ("host_baseline", "rehost_noop", "boundary_refined")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")


def rehost(payload, policy, detection):
    if detection.get("status") != "ok":
        return copy.deepcopy(detection)
    sources = _sources(payload)
    normalized = _policy(policy)
    if (detection.get("payload_sha256") != _digest(payload)
            or detection.get("policy_sha256") != _digest(normalized)
            or detection.get("policy_id") != normalized["policy_id"]
            or detection.get("policy_version") != normalized["version"]
            or detection.get("protected_categories") != normalized["protected_categories"]
            or detection.get("errors") != [] or detection.get("local_calls_complete") is not True
            or type(detection.get("local_calls")) is not int or detection["local_calls"] < 0):
        failed = copy.deepcopy(detection)
        failed.update(status="needs_review", errors=["rehost_input_binding_or_accounting_invalid"])
        return failed
    def replay(**kwargs):
        return {"status": "ok", "local_calls": 0, "elapsed_seconds": 0.0, "errors": [],
                "findings": [{"start": f["start"], "end": f["end"], "category": f["category"],
                              "quote": sources[f["source_id"]][f["start"]:f["end"]]}
                             for f in detection["findings"] if f["source_id"] == kwargs["source_id"]]}
    result = detect_sensitive(payload, policy, mode="agent", agent=replay)
    # Preserve provenance/accounting of the actual baseline inference.
    result.update({k: copy.deepcopy(detection[k]) for k in
                  ("local_calls", "local_calls_complete", "agent_elapsed_seconds", "agent_observations")
                  if k in detection})
    return result


def mask_footprint(original, transformed, mapping):
    """Check the actual replacement stream and retain only original positions.

    Positions are research diagnostics, not the restoration table. Token values
    are used in process memory and are not copied into output. Ambiguous Unicode
    casefold lengths are explicitly an audit failure instead of guessed offsets.
    """
    return masking_intervals(original, transformed, mapping._entries)


def prepare_row(case, detection, arm):
    payload, policy = case["payload"], case["policy"]
    actor, request = "development-owner", VERSION+":"+case["case_id"]+":"+arm
    memory_ids = {m["source_id"] for m in payload["memories"]}
    def authorizer(sid, current_actor, version):
        return sid in memory_ids and current_actor == actor and version == policy["version"]
    prepared = prepare_private_payload(payload, detection, actor_id=actor, request_id=request,
        policy_version=policy["version"], sensitivity_policy=policy, authorizer=authorizer)
    egress = validate_outbound(payload, prepared, detection, policy)
    row = {"prepare_status": prepared["status"], "prepare_error": prepared["error"],
           "egress": egress, "prepared_payload": prepared["payload"],
           "replacement_count": prepared["metadata"].get("replacement_count"),
           "mask_alignment_status": "not_ready", "mask_footprint": {}}
    if prepared["status"] == "ok":
        try:
            pairs = [("__query__", payload["query"], prepared["payload"]["query"])]
            pairs += [(left["source_id"], left["text"], right["text"])
                      for left, right in zip(payload["memories"], prepared["payload"]["memories"])]
            row["mask_footprint"] = {sid: mask_footprint(raw, masked, prepared["mapping"])
                                     for sid, raw, masked in pairs}
            row["mask_alignment_status"] = "ok"
        except (KeyError, ValueError, TypeError):
            row["mask_alignment_status"] = "audit_failed"
            row["mask_footprint"] = {}
    # Mapping and its original value/token lookup are never serialized.
    return row


def score_mask(row, gold, payload):
    ready = (row["prepare_status"] == "ok" and row["egress"]["status"] == "ok"
             and row["mask_alignment_status"] == "ok")
    covered = partial = uncovered = 0
    all_sensitive = {(f["source_id"], pos) for f in gold["findings"] for pos in range(f["start"], f["end"])}
    all_masked = {(sid, pos) for sid, intervals in row["mask_footprint"].items()
                  for start, end in intervals for pos in range(start, end)} if ready else set()
    for item in gold["findings"]:
        target = set(range(item["start"], item["end"]))
        masked = {pos for start, end in row["mask_footprint"].get(item["source_id"], [])
                  for pos in range(start, end)} if ready else set()
        overlap = target & masked
        covered += overlap == target
        partial += bool(overlap) and overlap != target
        uncovered += not overlap
    return {"ready": ready, "gold_spans": len(gold["findings"]),
            "fully_masked_spans": covered, "partially_masked_spans": partial,
            "unmasked_or_not_ready_spans": uncovered,
            "masked_unprotected_characters": len(all_masked-all_sensitive) if ready else None,
            "all_reference_spans_masked_and_ready": ready and covered == len(gold["findings"])}


def run(source, output, *, fresh=False, model_root=Path(".runtime/github_ner"), progress=None, detector=None):
    source, output = Path(source), Path(output)
    files = {name: source/name for name in ("runtime.json", "rows.json", "evaluation.json")}
    before = {name: sha(path) for name, path in files.items()}
    runtime = json.loads(files["runtime.json"].read_text(encoding="utf-8"))
    saved = json.loads(files["rows.json"].read_text(encoding="utf-8"))
    index = {(row["case_id"], row["arm"]): row for row in saved}
    if len(index) != len(saved) or len({r["case_id"] for r in runtime}) != len(runtime):
        raise ValueError("duplicate_case_or_condition")
    for case in runtime:
        if set(case) != {"case_id", "language", "template_family", "policy", "payload"}:
            raise ValueError("runtime_must_exclude_gold")
        _sources(case["payload"])
        if (case["case_id"], "gliner_combined") not in index:
            raise ValueError("missing_saved_baseline")
    output.mkdir(parents=True, exist_ok=False)
    package = Path("memory_migration_study")
    implementation = [*sorted(package.glob("*.py")), Path(__file__), Path("scripts/run_semantic_detection_benchmark.py")]
    frozen = {str(path): sha(path) for path in implementation}
    archive = output/"implementation"
    archive.mkdir()
    for path in implementation:
        shutil.copy2(path, archive/path.name)
    save(output/"plan.json", {"version": VERSION, "arms": ARMS, "materials": len(runtime),
        "source_sha256": before, "implementation_sha256": frozen, "fresh_encoder": fresh,
        "targets": {"span_recall": .95, "span_precision": .90, "needs_review": 0},
        "inference": "Fresh: one encoder invocation per nonempty protected source (query and each memory separately), shared by paired deterministic stages. Saved: zero new inference; historical baseline counts are retained once per material, never summed across arms. No answer model.",
        "scope": "Exposed development/regression. Saved data contains host-validated GLiNER+rules final findings, not raw encoder predictions. Preparation and known-value egress guards are unchanged. No independent acceptance or end-task utility is established."})
    shutil.copy2(files["runtime.json"], output/"runtime.json")
    if fresh and detector is None:
        from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
        detector = GlinerEntityAgent(LocalNerRuntime(model_root), approved_policies=[r["policy"] for r in runtime],
                                     splitter="cjk_aware", threshold=.5)
        save(output/"detector_identity.json", detector.cache_identity())
    rows, new_counts = [], {"local_encoder": 0, "local_generation": 0}
    for case in runtime:
        old_row = index[(case["case_id"], "gliner_combined")]
        if fresh:
            observer = CountingAgent(detector, "local_encoder")
            base = detect_sensitive(case["payload"], case["policy"], mode="combined", agent=observer)
            accounting = observer.accounting(base)
            for kind in new_counts:
                new_counts[kind] += accounting["inference_counts"][kind]
        else:
            base, accounting = copy.deepcopy(old_row["detection"]), copy.deepcopy(old_row["accounting"])
        outputs = {"host_baseline": base, "rehost_noop": rehost(case["payload"], case["policy"], base),
                   "boundary_refined": refine_detection(case["payload"], case["policy"], base)}
        for arm, detection in outputs.items():
            rows.append({"case_id": case["case_id"], "language": case["language"], "arm": arm,
                         "detection": detection, "shared_baseline_accounting": accounting,
                         **prepare_row(case, detection, arm)})
        save(output/"rows.json", rows)
        if progress:
            progress({"completed_materials": len(rows)//3, "expected_materials": len(runtime),
                      "case_id": case["case_id"], "status": outputs["boundary_refined"]["status"]})
    if before != {name: sha(path) for name, path in files.items()} or frozen != {str(path): sha(path) for path in implementation}:
        raise ValueError("input_or_implementation_changed")
    # All detection, preparation and actual payload alignment is fixed before labels.
    gold = json.loads(files["evaluation.json"].read_text(encoding="utf-8"))
    if set(gold) != {r["case_id"] for r in runtime}:
        raise ValueError("gold_runtime_identity_mismatch")
    lookup = {r["case_id"]: r for r in runtime}
    for row in rows:
        case = lookup[row["case_id"]]
        row["score"] = score_detection(row["detection"], gold[row["case_id"]], case["payload"])
        row["mask_score"] = score_mask(row, gold[row["case_id"]], case["payload"])
    summary = {}
    for arm in ARMS:
        chosen = [row for row in rows if row["arm"] == arm]
        counts = sum_counts([row["score"]["accepted"] for row in chosen])
        summary[arm] = {**counts, "materials": len(chosen),
            "needs_review": sum(r["detection"]["status"] != "ok" for r in chosen),
            "ready": sum(r["mask_score"]["ready"] for r in chosen),
            "instrumentation_errors": sum(r["mask_alignment_status"] == "audit_failed" for r in chosen),
            "masked_unprotected_characters": sum(r["mask_score"]["masked_unprotected_characters"] or 0 for r in chosen),
            "complete_exact_materials": sum(r["score"]["accepted_complete_exact"] for r in chosen),
            **{key: sum(r["mask_score"][key] for r in chosen) for key in
               ("gold_spans", "fully_masked_spans", "partially_masked_spans", "unmasked_or_not_ready_spans")}}
        def grouped(items):
            return {"materials": len(items), **sum_counts([r["score"]["accepted"] for r in items]),
                    "ready": sum(r["mask_score"]["ready"] for r in items),
                    "needs_review": sum(r["detection"]["status"] != "ok" for r in items),
                    "fully_masked_spans": sum(r["mask_score"]["fully_masked_spans"] for r in items),
                    "gold_spans": sum(r["mask_score"]["gold_spans"] for r in items)}
        summary[arm]["by_language"] = {lang: grouped([r for r in chosen if r["language"] == lang]) for lang in ("zh", "en")}
        summary[arm]["by_policy_scope"] = {scope: grouped([r for r in chosen if bool(lookup[r["case_id"]]["policy"]["protected_categories"]) == private])
                                                    for scope, private in (("private", True), ("public", False))}
        summary[arm]["by_category"] = {cat: sum_counts([r["score"]["by_category"][cat]["accepted"] for r in chosen])
                                        for cat in chosen[0]["score"]["by_category"]} if chosen else {}
    same = 0
    for i in range(0, len(rows), 3):
        def keys(row):
            return row["detection"]["status"], {(f["source_id"], f["start"], f["end"], f["category"])
                                                  for f in row["detection"]["findings"]}
        same += keys(rows[i]) == keys(rows[i+1])
    report = {"version": VERSION, "arms": summary, "baseline_origin": "fresh_encoder" if fresh else "saved_host_findings",
              "noop_equal_materials": same, "material_count": len(runtime), "new_inference_counts": new_counts,
              "cloud_calls": 0, "api_cost_cny": 0, "source_unchanged": True, "implementation_unchanged": True,
              "baseline_call_accounting_complete": all(r["shared_baseline_accounting"]["complete"] for r in rows[::3]),
              "historical_encoder_calls_referenced_once": 0 if fresh else sum(index[(r["case_id"], "gliner_combined")]["encoder_invocations"] for r in runtime),
              "overall_effectiveness_acceptance": "not_established",
              "scope": "Full detection/preparation/known-value egress development diagnostic; no new blind data, no downstream answer results. Gold-spans-not-ready remains in denominator. Footprints reveal positions; prepared synthetic payloads may reveal relationships."}
    save(output/"rows.json", rows)
    save(output/"report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("results/semantic_detection_v1/development"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--model-root", type=Path, default=Path(".runtime/github_ner"))
    args = parser.parse_args()
    network = {"allowed_loopback_connections": 0, "blocked_external_connections": 0}
    install_network_guard(network)
    report = run(args.source, args.output, fresh=args.fresh, model_root=args.model_root,
                 progress=lambda item: print(json.dumps(item, ensure_ascii=False), flush=True))
    save(args.output/"network_audit.json", network)
    print(json.dumps(report, ensure_ascii=False), flush=True)
