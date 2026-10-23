"""Free local preparation and restoration instrumentation for verified snapshots."""
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
import uuid

from .llm_worker import disclosed_facts
from .privacy_egress import TOKEN
from .privacy_experiment import (_validate_sensitivity_audit, digest, make_agent,
                                 prepare_one, restore_one)
from .runner import save_json
from .snapshots import load_snapshot_bundle


def run_local_privacy_check(*, snapshot_path, policy, detector_config, output,
                            sensitivity_audit=None, agent=None, progress=None, reuse_detection_report=None):
    snapshot_path, output = Path(snapshot_path), Path(output)
    bundle = load_snapshot_bundle(snapshot_path)
    if (not bundle["direct_evidence_report"].get("finite_scope_safe")
            or bundle["task_retrieval_report"]["known_w_plus_task_lists"]
            or bundle["task_retrieval_report"]["unknown_authorization_returned_relationships"]):
        raise ValueError("native_authorization_not_qualified")
    case = json.loads((snapshot_path.parent / bundle["provenance"]["runtime"]["path"]).read_text(encoding="utf-8"))["cases"][0]
    audit = _validate_sensitivity_audit(sensitivity_audit, case, policy)
    cached = None
    if reuse_detection_report is not None:
        previous = json.loads(Path(reuse_detection_report).read_text(encoding="utf-8"))
        if (previous["snapshot_sha256"] != hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
                or previous["policy_sha256"] != digest(policy) or previous["detector_config"] != detector_config
                or any(previous["implementation_sha256"].get(name) != hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                       for name in ("privacy.py", "local_detector.py"))):
            raise ValueError("stale_local_detection_report")
        cached = {digest(row["source_payload"]): row["detection"] for row in previous["rows"]}
        from .privacy import _digest as privacy_digest, _policy
        for row in previous["rows"]:
            result = row["detection"]
            if (not isinstance(result, dict) or not result
                    or result.get("status") not in {"ok", "needs_review"}
                    or result.get("payload_sha256") != privacy_digest(row["source_payload"])
                    or result.get("policy_sha256") != privacy_digest(_policy(policy))):
                raise ValueError("invalid_cached_local_detection")
    output.mkdir(parents=True, exist_ok=False)
    agent = agent or make_agent(detector_config)
    packets = [p for p in bundle["snapshots"] if p["envelope"]["group"] == "migrated"]
    rows = []
    for index, packet in enumerate(packets):
        source, env = packet["payload"], packet["envelope"]
        request = str(uuid.uuid4())
        if cached is not None and digest(source) not in cached:
            raise ValueError("cached_local_payload_missing")
        prepared, detection = prepare_one(source, case, env["actor_id"], policy, agent=agent, request_id=request,
                                          detection=cached[digest(source)] if cached is not None else None)
        row = {"task_id": env["task_id"], "actor_id": env["actor_id"], "request_id": request,
               "source_payload": source, "source_payload_sha256": digest(source),
               "model_payload": prepared["payload"], "status": prepared["status"], "error": prepared.get("error"),
               "detection": detection, "egress": prepared.get("egress"), "token_checks": [],
               "remaining_audit_values": None, "task_correctness": None, "cloud_answer": None}
        if prepared["status"] == "ok":
            if audit is not None:
                row["remaining_audit_values"] = disclosed_facts(json.dumps(prepared["payload"], ensure_ascii=False),
                                                                [item["value"] for item in audit["values"]])
            memory_tokens = set(TOKEN.findall(json.dumps(prepared["payload"]["memories"])))
            query_tokens = set(TOKEN.findall(prepared["payload"]["query"]))
            for token in sorted(memory_tokens | query_tokens):
                restored = restore_one(token, prepared, case, env["actor_id"], policy, request)
                expected = "ok" if token in memory_tokens else "blocked"
                row["token_checks"].append({"token": token, "expected_status": expected,
                                            "status": restored["status"], "error": restored.get("error"),
                                            "restored_value_sha256": hashlib.sha256(restored["answer"].encode()).hexdigest()
                                                if restored["answer"] is not None else None,
                                            "passed": restored["status"] == expected})
        prepared["mapping"] = None
        rows.append(row)
        save_json(output / "responses.json", {"rows": rows})
        if progress:
            progress({"processed": index + 1, "expected": len(packets), "status": row["status"]})
    ready = [r for r in rows if r["status"] == "ok"]
    checks = [check for r in rows for check in r["token_checks"]]
    report = {"schema_version": 2, "kind": "local_preparation_and_token_instrumentation",
              "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
              "policy_sha256": digest(policy), "policy": policy, "detector_config": detector_config,
              "sensitivity_audit_sha256": digest(audit) if audit is not None else None,
              "registered_tasks": len(rows), "ready_tasks": len(ready), "blocked_tasks": len(rows) - len(ready),
              "audited_ready_tasks": sum(r["remaining_audit_values"] is not None for r in ready),
              "registered_value_residual_requests": sum(bool(r["remaining_audit_values"]) for r in ready) if audit is not None else None,
              "token_checks_passed": sum(c["passed"] for c in checks), "token_checks_total": len(checks),
              "remote_model_calls": 0, "new_api_cost_cny": "0", "task_correctness": None,
              "detector_execution": "cached_only_no_new_detector_calls" if cached is not None else "fresh_local_inference",
              "reused_detection_report_sha256": hashlib.sha256(Path(reuse_detection_report).read_bytes()).hexdigest()
                  if reuse_detection_report is not None else None,
              "mapping_persisted": False, "report_contains_local_originals": True,
              "mapping_scope": "Opaque object not serialized; original inputs are shown locally; token checks store value hashes only.",
              "authorization_scope": "frozen_snapshot_only",
              "scope": "Development regression; audit scoring only; token replay is not a model answer or a novel-story evaluation.",
              "implementation_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")},
              "rows": rows}
    save_json(output / "report.json", report)
    esc = lambda value: html.escape(str(value))
    table = []
    for row in rows:
        table.append("<tr>" + "".join("<td><pre>" + esc(v) + "</pre></td>" for v in
            (row["task_id"], row["status"], json.dumps(row["source_payload"], ensure_ascii=False),
             json.dumps(row["model_payload"], ensure_ascii=False), row["remaining_audit_values"],
             json.dumps(row["token_checks"], ensure_ascii=False))) + "</tr>")
    (output / "index.html").write_text('<!doctype html><html lang="zh"><meta charset="utf-8"><title>本地外发与恢复检查</title>'
        '<style>body{font:15px/1.7 system-ui;margin:24px}table{border-collapse:collapse}td,th{padding:10px;border:1px solid #ccc;vertical-align:top}pre{white-space:pre-wrap;word-break:break-word;max-width:400px}</style>'
        '<h1>本地外发与恢复检查（零付费）</h1><p>可准备任务：' + esc(len(ready)) + '/' + esc(len(rows)) +
        '；有注册原值残留/已审计输入：' +
        (esc(report["registered_value_residual_requests"]) + '/' + esc(report["audited_ready_tasks"]) if audit is not None else '未审计') +
        '；代号自检通过：' + esc(report["token_checks_passed"]) + '/' + esc(len(checks)) +
        '。</p><p>本轮没有调用云端。代号自检不是模型答题；词表条件是旧故事开发回归，不能作为新故事泛化成绩。原文和恢复结果在本地报告中。</p>'
        '<table><tr><th>任务</th><th>状态</th><th>本地原文</th><th>拟外发内容</th><th>独立审计残留</th><th>代号自检</th></tr>' +
        ''.join(table) + '</table><p><a href="report.json">完整JSON</a></p></html>', encoding="utf-8")
    return report
