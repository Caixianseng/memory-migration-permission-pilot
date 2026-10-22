"""Reproducible author-created reference demonstrations and portable reports."""
from __future__ import annotations

import copy
import hashlib
import html
import json
import uuid
from pathlib import Path

from .backend import ReferenceAPI
from .evidence import evaluate, probe
from .policy import make_plan
from .tasks import run_tasks, score_runs, validate_runtime


def save_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def write_report(output: Path, report: dict):
    output = Path(output)
    save_json(output / "report.json", report)
    rows = []
    for result in report.get("results", []):
        direct = result["direct"]
        metrics = result.get("tasks", {}).get("instrumentation_metrics")
        values = [result["case_id"], result["condition"], result.get("artificial_fault", "none"), direct["backend_kind"],
                  direct["known_w_plus"], direct["known_w_minus"], direct["unknown_count"], direct["finite_scope_safe"],
                  metrics.get("complete_mean_loss") if metrics else None]
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in values) + "</tr>")
    if not rows:
        rows.append("<tr><td colspan='9'>" + html.escape(str(report.get("native_status", "See JSON report"))) + "</td></tr>")
    body = """<!doctype html><html lang="zh"><meta charset="utf-8"><title>记忆迁移有限域报告</title>
<style>body{font:16px system-ui;margin:2rem;max-width:1400px}table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:.5rem}p{max-width:1000px}</style>
<h1>记忆迁移有限域报告</h1><p>自编样例仅检验仪器。reference_backend不是产品原生结果；离线回答器结果不是真实LLM实证。read/list分别计关系，跨入口可达性只作诊断。未知不判通过。</p>
<table><thead><tr><th>故事</th><th>条件</th><th>人工故障</th><th>后端</th><th>W+</th><th>W−</th><th>未知</th><th>有限域安全</th><th>离线配对损失</th></tr></thead><tbody>""" + "".join(rows) + "</tbody></table><p>完整原始证据、manifest与逐任务结果见同目录report.json与evidence/。未覆盖语义推断披露、生产发布、动态撤权或全空间安全。</p></html>"
    (output / "report.html").write_text(body, encoding="utf-8")


def run_demo(output: Path, *, seed=42, diagnostics=False, runtime_path=None, evaluation_path=None,
             legacy_project=None, answerer=None) -> dict:
    answerer_kind = getattr(answerer, "kind", "unknown") if answerer is not None else "deterministic_instrumentation"
    instrumentation = answerer_kind == "deterministic_instrumentation"
    examples = Path(__file__).resolve().parents[1] / "examples/study_demo"
    runtime_path = Path(runtime_path or examples / "runtime.json")
    evaluation_path = Path(evaluation_path or examples / "evaluation.json")
    runtime = json.loads(runtime_path.read_text(encoding="utf-8-sig"))
    validate_runtime(runtime)
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8-sig"))
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    execution_id = str(uuid.uuid4())
    results = []
    for case in runtime["cases"]:
        conditions = ["source_keep", "source_export_roundtrip", "target_equivalent", "exact_groups", "reader_copies", "reject_all"]
        if diagnostics:
            conditions += ["partial", "error_body_leak", "extra_copy_leak", "missing_probe"]
        for condition in conditions:
            working_case = copy.deepcopy(case)
            source = condition in {"source_keep", "source_export_roundtrip"}
            if source:
                working_case["actor_mapping"] = {a["actor_id"]: a["actor_id"] for a in case["actors"]}
                working_case["reference_scope"] = "source_policy_control"
                for record in working_case["records"]:
                    record["recipient_readers"] = copy.deepcopy(record.get("source_readers"))
                    record["target_readers"] = copy.deepcopy(record.get("source_readers"))
            method = condition if condition in {"exact_groups", "reader_copies", "reject_all", "partial"} else "exact_groups"
            namespace = f"study-{execution_id}/{case['case_id']}/{condition}"
            plan = make_plan(working_case, method, namespace, source_only=source, keep_source=condition == "source_keep")
            plan["reference_scope"] = "source_policy_control" if source else "common_authorization"
            fault = "none"
            artificial = condition in {"partial", "error_body_leak", "extra_copy_leak", "missing_probe"}
            if condition == "error_body_leak":
                fault = condition
            if condition == "extra_copy_leak":
                record = next(r for r in case["records"] if len(r["source_readers"]) == 1)
                broad_readers = [a["actor_id"] for a in case["actors"]]
                artificial_container = namespace + "/artificial-broad-group"
                obj = {"source_id": record["source_id"], "target_id": namespace + "/artificial-broad-copy",
                       "text": record["text"], "readers": broad_readers, "container_id": artificial_container}
                plan["objects"].append(obj)
                plan["object_mapping"][record["source_id"]].append(obj["target_id"])
                plan["containers"].append({"container_id": artificial_container, "readers": broad_readers,
                                           "target_ids": [obj["target_id"]]})
            with ReferenceAPI(working_case, plan, fault=fault) as backend:
                evidence = probe(working_case, plan, backend.adapter)
                evidence["artificial_fault"] = condition if artificial else "none"
                if condition == "missing_probe":
                    for index, observation in enumerate(evidence["observations"]):
                        if observation["endpoint"] == "read":
                            del evidence["observations"][index]
                            break
                direct = evaluate(evidence)
                task_result = None
                # Source controls measure source relationships; target task loss is paired only within target conditions.
                if not source:
                    task_run = run_tasks(working_case, plan, backend.adapter, seed=seed, answerer=answerer)
                    task_result = dict(score_runs(task_run, evaluation["cases"][case["case_id"]]), run=task_run)
            from .legacy import check_with_legacy
            legacy = check_with_legacy(working_case, plan, legacy_project)
            evidence_file = f"evidence/{case['case_id']}__{condition}.json"
            save_json(output / evidence_file, evidence)
            results.append({"case_id": case["case_id"], "condition": condition, "artificial_fault": condition if artificial else "none",
                            "direct": direct, "tasks": task_result or {}, "legacy_model_check": legacy,
                            "evidence_file": evidence_file, "plan": plan})
    manifest = {"schema_version": 1, "implementation_version": "0.1.0", "seed": seed, "execution_id": execution_id,
                "independent_stories": len(runtime["cases"]), "input_files": [{"path": str(p.resolve()), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in (runtime_path, evaluation_path)],
                "actual_runs": ["reference_backend_http", "operation_specific_differential", "paired_fresh_session_tasks", "legacy_model_projection" if legacy_project else "legacy_not_configured"],
                "not_run": ["native_products", "paid_model_calls"] if instrumentation else ["native_products"],
                "not_implemented": ["semantic_or_inference_disclosure", "dynamic_revocation", "production_publish_or_cleanup", "distributed_commit", "new_optimization_algorithm"],
                "native_status": "not_configured", "answerer_kind": answerer_kind,
                "remote_model_calls": 0 if instrumentation else "see_model_ledger",
                "paid_model_status": "not_run" if instrumentation else "see_model_ledger",
                "real_llm_metrics": None if instrumentation else "per_condition", "diagnostics_enabled": diagnostics,
                "qualification": "author_created_instrumentation_cases_only", "statistical_intervals": None}
    report = {"manifest": manifest, "results": results}
    write_report(output, report)
    return report
