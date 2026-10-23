"""Render local evidence and export aggregate-only, publishable benchmark metrics."""
import argparse
import html
import json
from pathlib import Path


def build(root, public_summary):
    read = lambda p: json.loads(p.read_text(encoding="utf-8"))
    comp = root / "comparison_run"
    plan = read(comp / "plan.json")
    esc = lambda x: html.escape(str(x))
    table, payload_table, summaries = [], [], {}
    for label, title in (("baseline", "第二版"), ("current", "第三版")):
        detection = read(comp / f"{label}_detection.json")
        payload = read(comp / f"{label}_payloads.json")
        selected = [r for r in detection["summaries"] if r["split"] == "heldout" and r["language"] == "all"]
        flow = next(r for r in payload["summaries"] if r["split"] == "heldout")
        flow = dict(flow, ready_cases_without_gold_masking_gaps=flow["ready_cases"] - flow["ready_cases_with_incomplete_masking"])
        summaries[label] = {"detector_heldout": selected, "detector_gate": detection["heldout_gate"],
                            "payload_heldout": flow, "provenance": detection["basis"]["provenance"],
                            "detector_sha256": detection["basis"]["detector_sha256"],
                            "local_agent_sha256": detection["basis"]["local_agent_sha256"]}
        for row in selected:
            percent = lambda key: "未定义" if row[key] is None else f"{row[key]:.2%}"
            table.append("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in
                (title, row["mode"], percent("precision"), percent("recall"), percent("character_recall"),
                 f"{row['needs_review']}/{row['cases']}", row["fp"], row["fn"])) + "</tr>")
        payload_table.append("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in
            (title, f"{flow['ready_cases']}/{flow['registered_cases']}", flow["blocked_cases"],
             f"{flow['ready_cases_without_gold_masking_gaps']}/{flow['registered_cases']}",
             f"{flow['ready_cases_with_incomplete_masking']}/{flow['ready_cases']}",
             f"{flow['complete_masked_spans']}/{flow['ready_gold_spans']}", flow["partial_masked_spans"],
             flow["unmasked_spans"], flow["masked_unprotected_characters"], flow["instrumentation_errors"])) + "</tr>")
    regression = read(root / "category_only/report.json")
    summary = {"schema_version": 3, "release_status": "experimental_below_acceptance_gate",
        "promotion_decision": "Do not promote as a validated privacy pipeline; mixed detection change and worse ready-payload coverage.",
        "dataset": "examples/privacy_eval_v3_final", "synthetic": True,
        "human_review": None, "case_count": plan["corpus_manifest"]["case_count"],
        "heldout_cases": plan["corpus_manifest"]["expected_heldout_cases"],
        "corpus_runtime_sha256": plan["corpus_manifest"]["runtime_sha256"],
        "corpus_evaluation_sha256": plan["corpus_manifest"]["evaluation_sha256"],
        "results": summaries, "new_cloud_calls": 0, "new_api_cost_cny": "0", "llm_task_correctness": None,
        "old_story_regression": {k: regression[k] for k in ("registered_tasks", "ready_tasks", "blocked_tasks", "registered_value_residual_requests", "token_checks_passed", "token_checks_total")},
        "limits": ["Same fresh corpus, single frozen run per implementation; no statistical significance claim.",
                   "Gold is scoring-only. Actual masking coverage includes request-local propagation, not semantic anonymization.",
                   "Ready-only masking counts retain blocked-case denominator. No new cloud question answering or live revocation tested.",
                   "Full local reports contain original public/synthetic text and are excluded from Git."]}
    public_summary.parent.mkdir(parents=True, exist_ok=True)
    public_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    gate = summaries["current"]["detector_gate"]["passed"]
    result = "达到本次合成检测开发门槛" if gate else "检测门槛仍未通过"
    (root / "index.html").write_text(f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>本地隐私处理第三版</title>
<style>body{{margin:0;background:#f5f7fb;color:#24344b;font:16px/1.7 system-ui}}main{{max-width:1400px;margin:auto;padding:30px}}.notice{{padding:18px;background:#fff1d8;border-left:5px solid #b5801c}}
table{{border-collapse:collapse;background:white;width:100%}}th,td{{padding:10px;border:1px solid #d9e1eb;text-align:left}}th{{background:#e9f0fa}}.scroll{{overflow:auto}}section{{margin:26px 0}}a{{color:#155ca4}}</style>
<main><h1>本地敏感检测与假名化：第三版紧凑候选</h1><div class="notice">{esc(result)}。仅作为实验候选发布，未晋升为已验证方案。完整片段召回略增，但精确率和实际遮蔽覆盖退化。本次独立材料{plan['corpus_manifest']['case_count']}条，保留材料{plan['corpus_manifest']['expected_heldout_cases']}条；本轮没有云端调用，不能把本地恢复自检当作模型答题成绩。</div>
<section><h2>同一批新保留材料：检测</h2><p>两个版本在相同模型权重、冻结语料与统一评分器下比较。完整片段要求类别、来源和边界都正确；字符覆盖另列。新材料没有业务词表，仍为未人工复核的合成材料。</p>
<div class="scroll"><table><tr><th>版本</th><th>方式</th><th>精确率</th><th>召回率</th><th>字符召回</th><th>待审</th><th>FP</th><th>FN</th></tr>{''.join(table)}</table></div></section>
<section><h2>真正准备后的输入：完整实体是否遮蔽</h2><p>直接核对实际替换区间，计入跨问题和记忆的同步遮蔽。评分标签在转换完成后才计分，不提供给检测器。阻断与未知保留分母，不算脱敏成功；合成owner只允许访问本病例的来源ID。</p>
<div class="scroll"><table><tr><th>版本</th><th>准备成功/总数</th><th>阻断</th><th>可准备且无金标遮蔽缺口/总数</th><th>仍有不完整遮蔽/已准备</th><th>完全遮蔽片段/已准备金标</th><th>部分遮蔽</th><th>未遮蔽</th><th>额外遮蔽字符</th><th>仪器错误</th></tr>{''.join(payload_table)}</table></div>
<p>“无金标遮蔽缺口”包含没有敏感金标的病例，只说明注册金标覆盖，不证明无未知敏感信息。</p>
<p>“额外遮蔽字符”是可用性风险代理，不能代替问答正确率。原值被替换仍可能留下关系、长度或推断线索。</p></section>
<section><h2>旧7题本地回归（无业务词表）</h2><p>可准备 {regression['ready_tasks']}/{regression['registered_tasks']}，阻断 {regression['blocked_tasks']}；已审计输入中注册原值残留 {regression['registered_value_residual_requests']}/{regression['audited_ready_tasks']}；代号自检 {regression['token_checks_passed']}/{regression['token_checks_total']}。</p>
<p><a href="category_only/index.html">逐条拟外发文本与自检证据</a>。这是已知公开故事的开发回归，未重新调用云端模型。</p></section>
<p><a href="comparison_run/current_detection.json">第三版检测JSON</a> · <a href="comparison_run/current_payloads.json">实际遮蔽JSON</a> · <a href="comparison_run/plan.json">冻结清单</a> · <a href="unittest_final.log">工程测试</a> · <a href="final_integrity.json">归档与历史结果核验</a></p>
<p>完整报告保存在本机，公开仓库仅包含自编材料、代码和聚合结果。当前不证明全面隐私、原生在线撤权或论文创新。</p></main></html>''', encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--public-summary", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.root, args.public_summary)
    print(json.dumps({"gate": result["results"]["current"]["detector_gate"], "summary": str(args.public_summary)}, ensure_ascii=False))
