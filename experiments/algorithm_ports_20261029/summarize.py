"""Render a local report from closed result artifacts; never run experiments."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "results/algorithm_ports_20261029"


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--acorn-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--document", type=Path, required=True)
    args = parser.parse_args()
    score = load(BASE / "ltt_run01/scores.json")
    bf = load(BASE / "bf_run01/stage_summary.json")
    bf_host = load(BASE / "bf_handoff01/integration.json")
    acorn = load(args.acorn_review)
    assert acorn["stage_closed"] is True and bf_host["status"] == "passed"
    assert bf["bounded_comparison"]["all_materialized_and_delivery_sets_equal"]
    assert len(score["rows"]) == 80
    ledger = load(ROOT / "results/qoder_harness_plan_20261029/resource_ledger.json")
    assert ledger["actual"]["generation"] == 200
    assert ledger["actual"]["cloud"] == ledger["actual"]["paid_cost"] == 0
    args.output.mkdir(parents=True, exist_ok=False)
    selected = score["heldout_selected_result"]
    other = score["heldout_all_legal_baseline"]
    reduction = 100 * (1 - selected["prompt_tokens_total"] / other["prompt_tokens_total"])
    scenarios = bf["bounded_comparison"]["scenario_measurements"]
    mid = scenarios[-1]
    ltt_rows = []
    for config in ("top1", "all_legal"):
        for split in ("calibration", "check"):
            row = score["summary"][config][split]
            ltt_rows.append([config, split, str(row["tasks"] - row["failures"]) + "/" + str(row["tasks"]),
                str(row["legal_tasks"]) , str(row["legal_refusals"]), str(row["processing_failures"]),
                str(row["prompt_tokens_total"])])
    bf_rows = [[r["scenario"], str(r["states"]), str(r["rules"]),
                f'{r["bf_workload_total_ms"]:.3f}', f'{r["indexed_queue_workload_total_ms"]:.3f}']
               for r in scenarios]

    def md_table(headers, rows):
        return "| " + " | ".join(headers) + " |\n| " + " | ".join(["---"] * len(headers)) + " |\n" + "\n".join(
            "| " + " | ".join(map(str, row)) + " |" for row in rows)

    def html_table(headers, rows):
        return "<div class='scroll'><table><thead><tr>" + "".join("<th>" + html.escape(h) + "</th>" for h in headers) + \
            "</tr></thead><tbody>" + "".join("<tr>" + "".join("<td>" + html.escape(str(c)) + "</td>" for c in r) + "</tr>" for r in rows) + "</tbody></table></div>"

    overview = [["LTT：离线配置验收", "选择top1；检查两组均8/8", "保留简单top1强基线，未证明LTT提高正确率"],
                ["B/F：依赖增量维护", "29/29机械状态一致，当前比队列重算慢", "本轮不建议替换重算基线"],
                ["ACORN：过滤向量检索", acorn["headline"], acorn["decision"]]]
    ltt_headers = ["配置", "分组", "正确/总题", "合法题数", "合法UNKNOWN", "处理失败", "输入token合计"]
    bf_headers = ["场景", "状态", "规则", "B/F工作总时ms", "索引队列重算ms"]
    evidence = ["ltt_run01/scores.json", "ltt_run01/analysis/score_scope_audit.md",
                "bf_run01/stage_summary.md", "bf_run01/benchmark_attempt01/results.json",
                "bf_handoff01/integration.json", *acorn["evidence"]]
    inventory = []
    for relative in evidence:
        path = BASE / relative
        assert path.is_file(), relative
        inventory.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    flow = "身份与签名核验 → 当前读取＋传播授权 → 合法候选检索 → 请求级代号化 → 本地模型 → 当前权限复核 → 恢复交付"
    md = f"""# 三项算法逐项移植与效果评估

日期：2026-10-29。项目主线仍是 **Agent记忆安全迁移与权限保持**。本轮按LTT→B/F→ACORN分别运行，代码位于 `experiments/algorithm_ports_20261029/`；没有把组合效果归给单一算法。

## 1. 实际结论

{md_table(["算法与位置", "观察结果", "当前判断"], overview)}

## 2. 接入位置

{flow}

LTT在离线校准阶段选择检索配置；ACORN产生符合宿主掩码的检索候选；B/F维护明确来源依赖的派生物有效状态。三个方法都不能创建读取、传播或恢复权限。最终检查仍由项目既有接口执行。本轮是受控宿主链路，没有运行Qoder/Harness真实客户端的新实验。

## 3. LTT：少取必要合法记忆

新生成40个受控故事：32个校准、8个预留检查，两种固定配置共80次正式本地请求。`top1`先按固定词法相关性取一条合法记忆，`all_legal`使用全部合法记忆。每题答案来自明确结构化事实与授权策略。

{md_table(ltt_headers, ltt_rows)}

校准时top1的p值0.03434，通过预先设定的0.05门限；all_legal的p值0.15642，没有通过。选择仅用校准损失。检查集两组都8/8，其中合法题各4道，合法UNKNOWN各0；top1输入token合计{selected['prompt_tokens_total']}，all_legal为{other['prompt_tokens_total']}，少{reduction:.1f}%。输入内容字节少20%。输入token采用模型返回统计，不能据此推出同等比例的费用或时延下降。

all_legal的唯一校准错误是代号无法恢复，计入处理失败，未冒充拒答。80份捕获输入的事后精确字符串扫描未发现登记合成敏感原值。LTT的α=0.1约束此生成器上的无条件任务失败风险，δ=0.1为家族错误概率设置；它们不是允许隐私泄露的阈值。校准中包含18道应UNKNOWN的题，合法回答的条件风险未单独校准。

**解释：** 现有简单top1已经达到同样的检查成绩，LTT提供配置验收程序，没有证明比top1强基线更准确。40个故事使用同一事实模板，不能外推到自然语义、否定关系或真实业务。评分时两组参考同时解封，选参代码只用校准损失；不宣称检查参考在选定前仍物理盲化。记录的逐位置时延不是完整端到端时延。

## 4. B/F：撤权后保留真正独立的支持

B/F先向后检查是否还有支持，再向前传播失效；本轮只接受可信宿主明确声明的有限正向ground规则。规则体中的多个条件为AND，同一结论的多条规则为OR。两个相同文本不自动成为独立来源。

14项定向测试首轮通过。29个机械状态与独立全扫、索引队列重算两种参照一致；87份引擎观察不等于87个独立病例。

{md_table(bf_headers, bf_rows)}

每个图只做预先登记的单遍计时，总工作时含初始化、维护、共同最终门、状态哈希和机械新包准备；不包含真实客户端鉴权、网络和完整迁移成本。中图本次B/F约为队列重算的{mid['bf_workload_total_ms'] / mid['indexed_queue_workload_total_ms']:.2f}倍；这不是稳定速度估计，但不支持当前成本收益。内存测量也没有显示优势。

另通过7阶段真实项目接口小实验：撤A后其两个同祖先副本和AND派生物失效，独立B支持仍可用新包交接；旧包被阻断；撤B后全部无权；向算法图强行插回B，也不能越过当前宿主授权。这是受控接口验证，不是自然语言来源独立性识别或原生在线授权系统。

## 5. ACORN：权限过滤下的向量检索

{acorn['description']}

{md_table(acorn['headers'], acorn['rows'])}

{acorn['interpretation']}

{acorn['integration']}

## 6. 交付、失败与资源

LTT数学17项、跨接口9项、B/F14项定向测试共40项已通过；另有B/F状态对照和宿主集成，以及ACORN独立证据，不能累加为同一成功率。

本轮修复了新桥接层的一处对象绑定缺口：分别合法的读取记录和迁移包不能拼接授权，恢复时须再次核对对象、来源、内容与request ID。复现与修复后的回归测试均保留。一次预检中模型省略代号括号，因原提示同时要求“原样”和“不含标点”，在正式预测前修正提示，未放宽恢复器；4次预检全部计费计数，正式80次不重试。ACORN构建和首轮结果的兼容处理见其证据文件。

沿用的2026-10-29计划账本累计：NER60/100、生成200/200，其中本次移植新增4次预检＋80次正式生成；该账本内云端0、付费0、自动重试0，不覆盖项目更早的DeepSeek实验。生成预算已满，后续模型实验需另行安排。Ollama进程已清理，端口11435未监听。本轮没有重新评价敏感检测漏检率，不能声称三个算法减少了NER漏检。

## 7. 下一步选择

优先保留当前核权、独立传播授权、代号恢复和简单检索/重算。只有真实负载或更丰富任务证明简单基线不足时，才考虑进一步替换。当前获得了可运行的适配、正负结果和研究边界，尚未建立新算法优势或论文创新结论。

## 8. 来源与证据

- [LTT论文](https://arxiv.org/abs/2110.01052)：本轮使用精确Bernoulli检验和Bonferroni校正的有限配置选择。
- [B/F原论文](https://www.cs.ox.ac.uk/people/ian.horrocks/Publications/download/2015/MNPH15b.pdf)：本轮是有限正向ground规则的独立Python移植。
- [ACORN论文](https://arxiv.org/abs/2403.04871)、[固定作者代码](https://github.com/guestrin-lab/ACORN/tree/c259f11cdbec880671658eaa0d8747e2cc9de79d)：本轮固定实现与兼容处理见证据。

"""
    md += "\n".join("- [" + item["path"].split("algorithm_ports_20261029/")[-1] + "](" + Path(item["path"]).as_uri() + ")；SHA256 `" + item["sha256"] + "`" for item in inventory) + "\n"
    # The HTML is standalone: no scripts, external fonts or web dependency.
    page = """<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>算法逐项移植与效果评估</title><style>body{margin:0;background:#f3f6fb;color:#18253a;font:16px/1.75 'Microsoft YaHei',sans-serif}main{max-width:1120px;margin:auto;padding:36px 24px}h1{font-size:30px}h2{margin-top:38px}section{background:white;border:1px solid #dce4ee;border-radius:14px;padding:24px;margin:20px 0}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border-bottom:1px solid #dce4ee;padding:12px;text-align:left}th{background:#edf3fb}.flow{padding:20px;background:#e8f0ff;border-radius:10px;font-weight:600}.small{color:#52627a;font-size:14px}a{color:#1757ad}li{overflow-wrap:anywhere}.badge{display:inline-block;padding:4px 14px;background:#e5f4ec;color:#165535;border-radius:20px}</style><main>"""
    page += "<p class='badge'>2026-10-29 · 逐项执行，保留负结果</p><h1>记忆安全迁移：三项算法实测</h1><p>主线仍是Agent记忆安全迁移与权限保持。算法分别用于配置验收、依赖维护和过滤检索。</p>"
    page += "<section>" + html_table(["方法", "观察结果", "当前判断"], overview) + "</section><div class='flow'>" + html.escape(flow) + "</div>"
    page += "<section><h2>LTT：简单top1基线已经很强</h2>" + html_table(ltt_headers, ltt_rows) + f"<p>检查集两组均8/8，合法题各4道。top1输入token少{reduction:.1f}%，未证明LTT比固定top1更准确。</p><p class='small'>40个受控故事，80次正式请求；不是敏感检测、自然语义或真实客户端效果证明。</p></section>"
    page += "<section><h2>B/F：正确性通过，当前没有成本收益</h2>" + html_table(bf_headers, bf_rows) + "<p>29/29机械状态与两种参照一致，14项测试及7阶段宿主接口验证通过。单遍测量，保留比优化重算更慢的结果。</p></section>"
    page += "<section><h2>ACORN：过滤检索</h2><p>" + html.escape(acorn["description"]) + "</p>" + html_table(acorn["headers"], acorn["rows"]) + "<p>" + html.escape(acorn["interpretation"]) + "</p><p>" + html.escape(acorn["integration"]) + "</p></section>"
    page += "<section><h2>如何使用这些结果</h2><p>三种方法都不能赋予权限；读取、传播和恢复仍经过当前授权。保留简单强基线，有证据再替换。尚无自然语义、原生多Agent或论文创新结论。</p><p>本轮新增84次本地生成，累计生成200/200；云端、付费、自动重试均0。局部耗时、机械状态和注册字符串检查分别解释。</p><p><a href='report.md'>完整报告与方法边界</a></p><ul>"
    page += "".join("<li><a href='" + html.escape(Path(item["path"]).as_uri(), quote=True) + "'>" + html.escape(item["path"].split("algorithm_ports_20261029/")[-1]) + "</a></li>" for item in inventory)
    page += "</ul></section></main></html>"
    (args.output / "report.md").write_text(md, encoding="utf-8")
    (args.output / "index.html").write_text(page, encoding="utf-8")
    (args.output / "evidence.json").write_text(json.dumps({"files": inventory, "model_actual": ledger["actual"],
        "report_generation_model_calls": 0}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.document.exists():
        old = args.document.read_text(encoding="utf-8")
        assert old.startswith("# 算法逐项移植与效果评估"), "refuse to replace unrelated document"
        (args.output / "interim_report_before_completion.md").write_text(old, encoding="utf-8")
    # Local links in the repository-facing Markdown are absolute file links.
    for item in inventory:
        md = md.replace(Path(item["path"]).as_uri(), str(Path(item["path"])).replace("\\", "/"))
    args.document.parent.mkdir(parents=True, exist_ok=True)
    args.document.write_text(md, encoding="utf-8")
    print(json.dumps({"status": "rendered", "output": str(args.output), "evidence_files": len(inventory), "model_calls": 0}))


if __name__ == "__main__":
    main()
