"""Render local-only v1/v2 comparisons without contacting any model."""
import argparse
import html
import json
from pathlib import Path


def build(root):
    read = lambda path: json.loads((root / path).read_text(encoding="utf-8"))
    esc = lambda value: html.escape(str(value))
    reports = {v: read(f"comparison/{v}_detection.json") for v in ("v1", "v2")}
    metrics = []
    names = {"rules": "规则", "agent": "本地Agent", "combined": "独立联合"}
    for version, report in reports.items():
        for row in report["summaries"]:
            if row["split"] == "heldout" and row["language"] == "all":
                percent = lambda key: "未定义" if row[key] is None else f"{row[key]:.2%}"
                metrics.append("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in
                    (version, names[row["mode"]] if version == "v2" else row["mode"], percent("precision"), percent("recall"),
                     percent("character_recall"), f"{row['needs_review']}/{row['cases']}", row["fp"], row["fn"])) + "</tr>")
    regression = []
    examples = []
    for name, title in (("category_guarded", "仅类别策略＋边界阻断"), ("registry_guarded", "显式业务词表（开发条件）")):
        report = read(f"{name}/report.json")
        regression.append("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in
            (title, f"{report['ready_tasks']}/{report['registered_tasks']}",
             f"{report['registered_value_residual_requests']}/{report['audited_ready_tasks']}",
             f"{report['token_checks_passed']}/{report['token_checks_total']}")) + "</tr>")
        if name == "registry_guarded":
            for row in report["rows"]:
                if row["task_id"] in {"owner_maple_customer", "owner_maple_budget"}:
                    examples.append("<details><summary>" + esc(row["task_id"]) + "</summary><div class='grid'><section><h3>本地原文</h3><pre>" +
                        esc(json.dumps(row["source_payload"], ensure_ascii=False, indent=2)) + "</pre></section><section><h3>拟外发内容（本轮未发送）</h3><pre>" +
                        esc(json.dumps(row["model_payload"], ensure_ascii=False, indent=2)) + "</pre></section></div></details>")
    gate = reports["v2"]["heldout_gate"]["passed"]
    result = "通过本次合成开发验收" if gate else "尚未通过新保留集检测验收"
    (root / "index.html").write_text(f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>本地隐私检测第二版</title><style>body{{background:#f3f6fb;color:#25354b;font:16px/1.7 system-ui;margin:0}}main{{max-width:1200px;padding:32px;margin:auto}}
.notice{{background:#fff2d9;padding:18px;border-left:5px solid #bb821e}}table{{border-collapse:collapse;background:white;width:100%}}td,th{{padding:11px;border:1px solid #d6e0ed;text-align:left}}
th{{background:#e9f1fa}}.table{{overflow:auto}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}}section,details{{background:white;border:1px solid #dae1eb;padding:16px;margin:18px 0;border-radius:10px}}
pre{{white-space:pre-wrap;word-break:break-word;font-size:13px}}a{{color:#1260a2}}</style><main>
<p>2026-10-23 · 零新增云端调用</p><h1>本地敏感检测：第二版进展</h1><div class="notice">{esc(result)}。本轮只评价本地检测、拟外发输入和代号恢复自检；下游大模型问答效果尚未复测。</div>
<p>新材料共96条，中英文各48；开发集和保留集各48。两个版本在同一批材料上串行运行，模型权重相同，旧版本取自上一轮归档。所有新材料均无业务词表，评分标签只留在评分器中。合成材料尚无人工复核。</p>
<h2>同一批新材料：48条保留集</h2><p>类别和完整片段边界都正确才算命中；字符覆盖补充说明遮蔽范围。待审与错误保留分母，不能当作正确拒答。验收门槛：召回率≥95%、精确率≥90%，全部48条完成且无待审/错误。</p>
<div class="table"><table><tr><th>版本</th><th>方法</th><th>精确率</th><th>召回率</th><th>字符召回率</th><th>待审</th><th>FP</th><th>FN</th></tr>{''.join(metrics)}</table></div>
<p><a href="comparison/v1_detection.json">v1检测证据</a> · <a href="comparison/v2_detection.json">v2检测证据</a> · <a href="comparison/comparison_plan.json">运行前冻结清单</a></p>
<h2>旧7题回归：拟外发与代号恢复</h2><p>本轮没有云端回答，代号自检不等于任务正确率。业务词表是经营方预先登记的本地配置，此处根据已知公开故事构造，仅作工程回归；不能作为新名称泛化成绩。</p>
<div class="table"><table><tr><th>条件</th><th>已准备/注册任务</th><th>输入残留/已审计</th><th>代号自检通过/总数</th></tr>{''.join(regression)}</table></div>
<p>类别条件中出现“代号＋实体后缀”的请求会被阻断，不计成功脱敏。原始检测结果被复用，没有追加调参推理。阻断前记录保留在<a href="category_only/index.html">早期回归</a>。</p>
<p><a href="category_guarded/index.html">仅类别策略逐项检查</a> · <a href="registry_guarded/index.html">业务词表逐项检查</a></p>{''.join(examples)}
<h2>实现与边界</h2><p>可信策略进入system消息，原文不能自称公开来取消策略；规则与模型独立检测后合并；完整策略及输入摘要绑定映射，外发前检查已知残留和代号来源。</p>
<p>未登记且未识别的语义秘密仍可能漏过；假名化仍保留关联线索。本轮不是原生在线撤权、完整隐私证明或论文创新证明。原始材料与恢复结果显示在本地报告中。</p>
<p><a href="unittest_final_v2_2.log">完整工程测试</a> · <a href="final_integrity_check.json">历史结果与账本核验</a> · <a href="fresh_failure_analysis.md">新保留集失败分析</a> · <a href="../privacy_agent_20261023/index.html">上一轮原始结果</a></p></main></html>''', encoding="utf-8")
    return root / "index.html"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    print(build(parser.parse_args().root).resolve())
