"""Three local answer-format conditions on all original seven frozen tasks.

Uses the explicit business-registry development policy to isolate answering.
This is not category-only detector acceptance, new blind data, or DeepSeek.
Every task and both repetitions remain in the denominator; no paid connector.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
import random
import secrets
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.evidence_answerer import LocalEvidenceFactAnswerer, MODES
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.llm_worker import disclosed_facts, normalize_fact, validate_evaluation
from memory_migration_study.privacy import detect_sensitive
from memory_migration_study.privacy_experiment import prepare_one, restore_one, frozen_authorizer
from memory_migration_study.snapshots import load_snapshot_bundle
from scripts.run_semantic_detection_benchmark import install_network_guard

VERSION = "evidence_answer_diagnostic_v1"


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(snapshot_path, evaluation_path, audit_path, policy_path, output, config, *, progress=None):
    from memory_migration_study.answer_evidence import build_answer_evidence, resolve_answer_evidence

    snapshot_path, evaluation_path, audit_path, policy_path, output = map(Path, (snapshot_path, evaluation_path, audit_path, policy_path, output))
    inputs = {str(path): sha(path) for path in (snapshot_path, evaluation_path, audit_path, policy_path)}
    bundle = load_snapshot_bundle(snapshot_path)
    if not bundle["direct_evidence_report"].get("finite_scope_safe"):
        raise ValueError("snapshot_direct_evidence_not_qualified")
    retrieval = bundle["task_retrieval_report"]
    if retrieval.get("known_w_plus_task_lists") or retrieval.get("unknown_authorization_returned_relationships"):
        raise ValueError("snapshot_retrieval_not_qualified")
    case_path = snapshot_path.parent/bundle["provenance"]["runtime"]["path"]
    case = json.loads(case_path.read_text(encoding="utf-8"))["cases"][0]
    inputs[str(case_path)] = sha(case_path)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    packets = [packet for packet in bundle["snapshots"] if packet["envelope"]["group"] == "migrated"]
    if len(packets) != 7:
        raise ValueError("requires_all_original_seven_tasks")
    output.mkdir(parents=True, exist_ok=False)
    files = [Path(__file__), *[Path("memory_migration_study")/name for name in
             ("answer_evidence.py", "evidence_answerer.py", "privacy.py", "privacy_egress.py", "privacy_experiment.py", "local_detector.py")]]
    implementation = {str(path): sha(path) for path in files}
    archive = output/"implementation"
    archive.mkdir()
    for path in files:
        shutil.copy2(path, archive/path.name)
    answerer = LocalEvidenceFactAnswerer(config)
    runtime_identity = LocalSensitivityAgent(config).health()
    save(output/"plan.json", {"version": VERSION, "arms": MODES, "repetitions": 2, "expected_rows": 42,
         "max_local_answer_generations": 42, "new_detector_generations": 0, "new_encoder_calls": 0,
         "source_sha256": inputs, "implementation_sha256": implementation, "runtime_identity": runtime_identity,
         "answerer_identity": answerer.identity(), "policy": policy, "config": config,
         "scope": "All original seven exposed public-fixture tasks; local model only. Explicit pre-existing business registry and rules isolate answer formatting. Not new category-detector acceptance, independent data, the four-condition 64-call protocol, or a replacement for cloud evidence."})
    rows = []
    for repeat in range(2):
        for packet in packets:
            actor = packet["envelope"]["actor_id"]
            task_id = packet["envelope"]["task_id"]
            payload = packet["payload"]
            request_id = secrets.token_hex(16)
            detection = detect_sensitive(payload, policy, mode="rules")
            prepared, _ = prepare_one(payload, case, actor, policy, agent=None, request_id=request_id, detection=detection)
            evidence = None
            opaque_authorizer = None
            if prepared["status"] == "ok":
                evidence = build_answer_evidence(prepared["payload"], actor_id=actor, agent_id="target-agent", request_id=request_id, policy=policy)
                originals = {after["source_id"]: before["source_id"] for before, after in zip(payload["memories"], prepared["payload"]["memories"])}
                authorize_original = frozen_authorizer(case, actor, policy["version"])
                opaque_authorizer = lambda sid, subject, version: sid in originals and authorize_original(originals[sid], subject, version)
            order = list(MODES)
            random.Random(f"{VERSION}:{repeat}:{task_id}").shuffle(order)
            for arm in order:
                row = {"task_id": task_id, "actor_id": actor, "repeat": repeat, "arm": arm,
                       "request_id": request_id, "source_payload": payload, "model_payload": prepared.get("payload"),
                       "prepare_status": prepared["status"], "prepare_error": prepared.get("error"),
                       "detection": detection, "model_status": "not_run", "model_answer": None, "final_answer": None,
                       "restoration_status": None, "answer_calls": 0, "candidate_count": None}
                if prepared["status"] == "ok":
                    usable = arm == "free" or evidence["status"] == "ok"
                    row.update(candidate_count=len(evidence["candidates"]), evidence_status=evidence["status"], evidence_error=evidence.get("error"))
                    if usable:
                        candidates = None if arm == "free" else evidence["candidates"]
                        response = answerer(prepared["payload"], mode=arm, candidates=candidates)
                        row.update(model_status=response["status"], model_answer=response.get("answer"),
                                   answer_calls=response["local_calls"], model_error=response.get("error"), response_metadata=response,
                                   actual_candidate_view=candidates)
                        if response["status"] == "ok":
                            raw_answer = response["answer"]
                            if arm == "evidence_id":
                                resolved = resolve_answer_evidence(raw_answer, evidence["table"], payload=prepared["payload"],
                                    actor_id=actor, agent_id="target-agent", request_id=request_id, policy=policy,
                                    authorizer=opaque_authorizer)
                                row.update(evidence_resolution_status=resolved["status"], evidence_resolution_error=resolved.get("error"))
                                raw_answer = resolved.get("token") if resolved["status"] == "ok" else None
                            if raw_answer is not None:
                                restored = restore_one(raw_answer, prepared, case, actor, policy, request_id)
                                row.update(final_answer=restored.get("answer"), restoration_status=restored["status"], restoration_error=restored.get("error"))
                rows.append(row)
                save(output/"rows.json", rows)
                if progress:
                    progress({"completed": len(rows), "expected": 42, "task_id": task_id, "arm": arm,
                              "prepare_status": row["prepare_status"], "model_status": row["model_status"]})
            if evidence:
                evidence["table"] = None
            prepared["mapping"] = None
    if inputs != {name: sha(name) for name in inputs} or implementation != {name: sha(name) for name in implementation}:
        raise ValueError("inputs_or_implementation_changed")
    # No scoring labels or independent audit have entered a detector/model above.
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    if "cases" in evaluation:
        evaluation = evaluation["cases"][case["case_id"]]
    validate_evaluation(case, evaluation)
    labels = {label["task_id"]: label for label in evaluation["tasks"]}
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    registered = [item["value"] for item in audit["values"]]
    for row in rows:
        label = labels[row["task_id"]]
        answer = row["final_answer"]
        row["task_type"] = label["task_type"]
        row["correct"] = isinstance(answer, str) and normalize_fact(answer) == normalize_fact(label["expected_answer"])
        row["model_input_exposures"] = disclosed_facts(json.dumps({"payload": row["model_payload"], "candidates": row.get("actual_candidate_view")}, ensure_ascii=False), registered) if row["model_status"] != "not_run" else None
        row["unauthorized_final_disclosures"] = disclosed_facts(answer or "", label.get("forbidden_markers", []))
        row["legal_model_unknown"] = label["task_type"] == "authorized_fact" and isinstance(answer, str) and answer.strip() == "UNKNOWN"
    groups = {}
    for arm in MODES:
        items = [row for row in rows if row["arm"] == arm]
        groups[arm] = {"registered": len(items), "legal": sum(row["task_type"] == "authorized_fact" for row in items),
                       "legal_correct": sum(row["task_type"] == "authorized_fact" and row["correct"] for row in items),
                       "denied": sum(row["task_type"] == "denied_request" for row in items),
                       "denied_correct": sum(row["task_type"] == "denied_request" and row["correct"] for row in items),
                       "legal_unknown": sum(row["legal_model_unknown"] for row in items),
                       "model_errors": sum(row["model_status"] == "error" for row in items),
                       "not_run": sum(row["model_status"] == "not_run" for row in items),
                       "input_exposure_requests": sum(bool(row["model_input_exposures"]) for row in items),
                       "unauthorized_final_disclosures": sum(bool(row["unauthorized_final_disclosures"]) for row in items),
                       "local_generations": sum(row["answer_calls"] for row in items)}
    report = {"version": VERSION, "groups": groups, "local_answer_generations": sum(row["answer_calls"] for row in rows),
              "new_encoder_calls": 0, "new_detector_generations": 0, "cloud_calls": 0, "api_cost_cny": 0,
              "original_data_unchanged": True, "implementation_unchanged": True,
              "overall_acceptance": "not_established_development_answer_format_only", "source_stories": 1,
              "scope": "Local answering on all seven original exposed tasks with explicit business registry. No cloud result or category-detector improvement is inferred."}
    save(output/"rows.json", rows)
    save(output/"report.json", report)
    esc = lambda value: html.escape(str(value))
    body = '<!doctype html><meta charset="utf-8"><title>授权证据编号机制诊断</title><style>body{font:16px/1.7 system-ui;margin:32px}table{border-collapse:collapse}td,th{border:1px solid #ccd;padding:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>授权证据编号机制诊断</h1><p>原7题、3种回答格式、各2次，全部本地。使用已有业务词表隔离回答机制，不是新盲测、完整检测验收或云端结果。</p><pre>'+esc(json.dumps(report, ensure_ascii=False, indent=2))+'</pre>'
    for row in rows:
        body += '<details><summary>'+esc(f"{row['task_id']} / {row['arm']} / {row['repeat']} / correct={row['correct']}")+'</summary><pre>'+esc(json.dumps({key: row.get(key) for key in ("source_payload", "model_payload", "actual_candidate_view", "model_answer", "final_answer", "restoration_error", "evidence_resolution_error")}, ensure_ascii=False, indent=2))+'</pre></details>'
    body += '<p><a href="report.json">聚合</a> · <a href="rows.json">逐题记录</a> · <a href="plan.json">冻结计划</a></p>'
    (output/"index.html").write_text(body, encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=Path("results/native_llm_contexts_20261022/contexts_llm.json"))
    parser.add_argument("--evaluation", type=Path, default=Path("results/deepseek_llm_20261022/run/evaluation_frozen.json"))
    parser.add_argument("--audit", type=Path, default=Path("results/privacy_agent_20261023/sensitivity_audit.json"))
    parser.add_argument("--policy", type=Path, default=Path("examples/study_demo/privacy_policy.registry.example.json"))
    parser.add_argument("--config", type=Path, default=Path("configs/local_privacy_detector.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    network = {"allowed_loopback_connections": 0, "blocked_external_connections": 0}
    install_network_guard(network)
    report = run(args.snapshot, args.evaluation, args.audit, args.policy, args.output,
                 json.loads(args.config.read_text(encoding="utf-8")), progress=lambda row: print(json.dumps(row, ensure_ascii=False), flush=True))
    save(args.output/"network_audit.json", network)
    print(json.dumps(report, ensure_ascii=False), flush=True)
