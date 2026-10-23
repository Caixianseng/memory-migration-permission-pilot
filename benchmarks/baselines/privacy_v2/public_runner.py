"""Offline public-content pilot with an explicit controlled-policy boundary."""
from __future__ import annotations

from collections import Counter
import html
import json
from pathlib import Path

from .runner import run_demo, save_json, write_report


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _write_index(output, summary):
    counts = summary["counts"]
    rows = []
    for condition in summary["conditions"]:
        values = [condition["condition"], condition["known_w_plus"], condition["known_w_minus"],
                  condition["unknown_count"], condition["finite_scope_safe"],
                  condition["authorized_fact_mean_loss"]]
        rows.append("<tr>" + "".join("<td>" + html.escape(str(v)) + "</td>" for v in values) + "</tr>")
    links = "".join('<li><a href="' + html.escape(path, quote=True) + '">' + html.escape(name) + '</a></li>'
                    for name, path in summary["artifacts"].items())
    body = """<!doctype html><html lang="zh"><meta charset="utf-8">
<title>公开内容受控策略离线试验</title>
<style>body{font:16px system-ui;margin:2rem;max-width:1100px}table{border-collapse:collapse}th,td{border:1px solid #bbb;padding:.5rem}</style>
<h1>公开内容受控策略离线试验</h1>
<p>公开对话提供原文；读取规则由研究控制者另行声明。本次运行只验证本地 HTTP 参考后端、权限证据及任务评分管线。
未重新运行 Mem0、Cognee 或 Open WebUI，未调用真实大模型；离线回答器得分仅为仪器指标，自然业务授权资格仍为 0。</p>
""" + (f"<p>公开 episode：{counts['public_episodes']}；独立故事：{counts['independent_stories']}；"
       f"受控记忆：{counts['controlled_memories']}；预登记任务：{counts['tasks']}"
       f"（合法事实任务 {counts['authorized_fact_tasks']}，拒绝任务 {counts['denied_request_tasks']}）。"
       "条件、副本、重复请求与任务不增加独立故事数。</p>") + """
<table><thead><tr><th>条件</th><th>W+</th><th>W−</th><th>未知</th><th>有限域安全</th><th>合法事实离线平均损失</th></tr></thead><tbody>
""" + "".join(rows) + "</tbody></table><p>源端两组仅检查源读取关系；目标条件用同一检索管线进行参照／迁移／无记忆配对。拒绝任务单独评分。</p><ul>" + links + "</ul></html>"
    (output / "index.html").write_text(body, encoding="utf-8")


def run_public_pilot(legacy_project: Path, output: Path, *, seed=42) -> dict:
    """Prepare a traceable fixture, then run only the local reference study."""
    # Lazy import lets unrelated commands work while this optional fixture is absent.
    from .public_fixture import SpanInstrumentationAnswerer, prepare_controlled_fixture

    legacy_project, output = Path(legacy_project).resolve(), Path(output).resolve()
    if not legacy_project.is_dir():
        raise ValueError("legacy_project must be an existing restored project directory")
    output.mkdir(parents=True, exist_ok=False)
    fixture = output / "fixture"
    prepare_controlled_fixture(legacy_project, fixture)
    runtime_path, evaluation_path = fixture / "runtime.json", fixture / "evaluation.json"
    runtime, evaluation = _load(runtime_path), _load(evaluation_path)
    provenance = _load(fixture / "provenance.json")
    public_episode_ids = [provenance["episode_id"]]
    answerer = SpanInstrumentationAnswerer()
    if answerer.kind != "deterministic_instrumentation":
        raise ValueError("public-pilot requires the offline instrumentation answerer")
    report = run_demo(output / "reference_run", seed=seed, runtime_path=runtime_path,
                      evaluation_path=evaluation_path, legacy_project=legacy_project, answerer=answerer)
    report["manifest"].update(qualification="public_content_administrator_declared_controlled_policy_only",
                              source_fixture_provenance=str((fixture / "provenance.json").resolve()),
                              natural_authorization_qualification=0)
    write_report(output / "reference_run", report)
    labels = [task for case in evaluation["cases"].values() for task in case["tasks"]]
    types = Counter(task.get("task_type", "unclassified") for task in labels)
    conditions = []
    for result in report["results"]:
        direct = result["direct"]
        metrics = result.get("tasks", {}).get("instrumentation_metrics")
        conditions.append({"case_id": result["case_id"], "condition": result["condition"],
                           "known_w_plus": direct["known_w_plus"], "known_w_minus": direct["known_w_minus"],
                           "unknown_count": direct["unknown_count"], "finite_scope_safe": direct["finite_scope_safe"],
                           "authorized_fact_mean_loss": metrics.get("authorized_fact_complete_mean_loss") if metrics else None,
                           "instrumentation_metrics": metrics})
    summary = {"schema_version": 1, "seed": seed, "status": "completed",
               "qualification": "public_content_administrator_declared_controlled_policy_only",
               "backend_kind": "reference_backend", "native_execution_performed": False,
               "native_status": "not_run", "remote_model_calls": 0, "paid_model_status": "not_run",
               "answerer_kind": answerer.kind, "real_llm_metrics": None,
               "natural_authorization_qualification": 0, "human_review": None,
               "public_episode_ids": public_episode_ids,
               "counts": {"public_episodes": len(public_episode_ids), "independent_stories": len(runtime["cases"]),
                          "controlled_memories": sum(len(case["records"]) for case in runtime["cases"]),
                          "tasks": len(labels), "authorized_fact_tasks": types["authorized_fact"],
                          "denied_request_tasks": types["denied_request"]},
               "conditions": conditions, "source_provenance": provenance, "reference_manifest": report["manifest"],
               "artifacts": {"runtime": "fixture/runtime.json", "evaluation": "fixture/evaluation.json",
                             "provenance": "fixture/provenance.json", "reference_report": "reference_run/report.json"}}
    save_json(output / "summary.json", summary)
    _write_index(output, summary)
    return summary
