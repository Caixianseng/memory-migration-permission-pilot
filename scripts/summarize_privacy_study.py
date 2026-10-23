"""Render the local public-fixture evidence; never calls a model or loads a key."""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path


def build(root: Path):
    read = lambda path: json.loads((root / path).read_text(encoding="utf-8"))
    detection = read("detection_full.json")
    ablation = read("ablation/report.json")
    esc = lambda value: html.escape(str(value))
    names = {"rules": "规则", "agent": "本地Agent", "combined": "规则＋本地Agent"}
    detection_rows = []
    for row in detection["summaries"]:
        if row["language"] == "all" and row["split"] == "heldout":
            detection_rows.append("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in
                (names[row["mode"]], f"{row['precision']:.2%}", f"{row['recall']:.2%}",
                 f"{row['needs_review']}/{row['cases']}", row["fp"], row["fn"])) + "</tr>")
    group_rows = []
    group_names = {"A": "原提示＋原文", "B": "修正提示＋原文", "C": "原提示＋代号", "D": "修正提示＋代号",
                   "N1": "原提示＋无记忆", "N2": "修正提示＋无记忆"}
    for name, row in ablation["groups"].items():
        legal, denied = (row["by_type"][key] for key in ("authorized_fact", "denied_request"))
        group_rows.append("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in
            (group_names[name], f"{legal['correct']}/{legal['registered']}",
             f"{denied['correct']}/{denied['registered']}" if denied["registered"] else "—",
             legal["supported_abstentions"], row["privacy_blocked"],
             f"{row['registered_fact_input_exposure_requests']}/{row['input_exposure_evaluated_requests']}",
             f"{row['final_registered_disclosure_requests']}/{row['final_disclosure_evaluated_requests']}")) + "</tr>")
    examples = [r for r in ablation["rows"] if r["condition"] == "D" and r["repeat"] == 0 and r["task_type"] == "authorized_fact"]
    cards = []
    for row in examples:
        stages = [("本机原文（公开实验材料）", row["source_payload"]), ("云端收到的内容", row["model_payload"]),
                  ("云端回答", row["cloud_answer"]), ("本机恢复结果", row["final_answer"])]
        cards.append("<details><summary>" + esc(row["task_id"]) + " · " + esc(row["status"]) + "</summary><div class='grid'>" +
            "".join("<section><h3>" + esc(label) + "</h3><pre>" + esc(json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, dict) else value) +
                    "</pre></section>" for label, value in stages) + "</div></details>")
    gate = "达到本次开发目标" if detection["heldout_gate"]["passed"] else "未达到检测验收目标，不能据此放行真实私密数据"
    private_rows = [r for r in ablation["rows"] if r["condition"] in {"C", "D"}]
    remaining = sorted({value for r in private_rows for value in (r["input_registered_facts"] or [])})
    restored_correct = sum(r["condition"] == "D" and r["normalized_correct"] == 1 and
                           isinstance(r["cloud_answer"], str) and r["cloud_answer"].startswith("[PVT_") for r in private_rows)
    body = f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>本地隐私处理 · 实验结果</title><style>
body{{margin:0;background:#f4f7fb;color:#213047;font:16px/1.65 system-ui}}main{{max-width:1300px;margin:auto;padding:30px}}
h1{{font-size:30px;margin-bottom:8px}}h2{{margin-top:30px}}.notice{{background:#fff2da;border-left:5px solid #bd7d16;padding:16px}}
.stats,.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}}section,.stat,details{{background:white;padding:18px;border:1px solid #dce5ef;border-radius:10px;margin:12px 0}}
strong{{font-size:23px}}table{{border-collapse:collapse;width:100%;background:white}}td,th{{padding:12px;border:1px solid #dce5ef;text-align:left}}th{{background:#e9f0f8}}
.table{{overflow:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}}a{{color:#125ca4}}summary{{cursor:pointer;font-weight:600}}
</style><main><p>2026-10-23 · 冻结快照 · 受控研究原型</p><h1>本地 Agent 检测与可恢复脱敏</h1>
<p>原值留在本机，云端处理代号，本机核验权限后恢复。所有本轮实验原文均为公开或自编合成材料。</p>
<div class="notice">{esc(gate)}。合法问答效果与检测质量分别判断；假名化仍保留关系及推断线索。</div>
<div class="stats"><div class="stat">检测材料<br><strong>120 条</strong><br>80开发＋40保留；中英文各60</div>
<div class="stat">本轮云端请求<br><strong>{ablation['model_calls']} 次</strong><br>最多64次；失败不自动重试</div>
<div class="stat">本轮用量估算<br><strong>¥{esc(ablation['estimated_cost_cny'])}</strong><br>硬上限¥0.50；未核验供应商逐请求账单</div></div>
<h2>1. 检测是否可靠：40条保留材料</h2><p>目标：召回率≥95%，精确率≥90%。类别与片段边界完全匹配；重叠短片段也会产生FP，不能把FP比例直接解释为不相关内容被遮蔽比例。</p>
<div class="table"><table><tr><th>方法</th><th>精确率</th><th>召回率</th><th>待审</th><th>FP</th><th>FN</th></tr>{''.join(detection_rows)}</table></div>
<p><a href="detection_full.json">完整检测证据</a> · <a href="detection_failure_analysis.md">失败原因分析</a></p>
<h2>2. 合法回答是否改善：固定7题</h2><p>每条件重复两次。原文A/B仅为公开材料对照；“输入含原值”包括独立注册的项目、客户、预算、日期和来源ID。检测/恢复阻断不算模型拒答。</p>
<div class="table"><table><tr><th>条件</th><th>合法正确</th><th>应拒正确</th><th>有事实仍UNKNOWN</th><th>隐私阻断</th><th>输入含原值/已审计</th><th>最终越权披露/已审计</th></tr>{''.join(group_rows)}</table></div>
<p>问答开发门槛：{esc(ablation['utility_gate'])}。即使该门槛通过，也不能替代检测保留集验收。</p>
<div class="notice">脱敏条件中仍出现的注册原值：{esc('、'.join(remaining) or '无已发现残留')}。D条件实际正确恢复代号{restored_correct}次，其他原值正确回答不等于代号恢复成功。完整漏检计数见<a href="ablation_failure_analysis.json">回答失败分析</a>。</div>
<h2>3. 看一次信息如何流动</h2>{''.join(cards)}
<h2>证据与复现</h2><p><a href="ablation/index.html">全部逐次对照</a> · <a href="ablation/report.json">回答实验JSON</a> · <a href="runtime_receipt.json">版本与摘要</a> · <a href="runtime_probe.json">GPU实测</a> · <a href="unittest_pre_cloud.log">208项工程测试</a></p>
<p>当前一个公开故事，冻结权限；未验证原生在线撤权、长摘要、数值运算、跨用户共享或语义推断隐私。检测材料是AI自编模板，尚无人工标注复核。无记忆正确率为0是信息不足对照，不等于误拒。</p>
<p>此HTML特意显示本机公开原文和恢复结果，不能将它当作可公开发布的脱敏附件。</p></main></html>"""
    (root / "index.html").write_text(body, encoding="utf-8")
    return root / "index.html"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    print(build(parser.parse_args().root).resolve())
