"""Render the closed 16-call source-context diagnostic without answer access.

No inference, account query or reference parsing occurs here. Public Markdown
contains aggregate outcomes and quota deltas. Synthetic replies are shown only
in the local HTML, separate from the earlier 32-call client comparison.
"""
from __future__ import annotations

import argparse
from collections import Counter
from decimal import Decimal, InvalidOperation
import hashlib
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_NAME = "期刊方法适配与来源上下文优化结果_2026-10-30.md"
ARMS = ("fragment", "context")
LABELS = {"fragment": "保护后事实片段（移去主体标题）",
          "context": "获准原文标题＋相同保护事实"}


def _regular(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("missing_or_linked_report_input:" + path.name)
    return path


def _load(path):
    return json.loads(_regular(path).read_text(encoding="utf-8"))


def _sha(path):
    return hashlib.sha256(_regular(path).read_bytes()).hexdigest()


def _escape(value):
    return html.escape(str(value)) if value is not None else "无/未测"


def _fraction(a, b):
    return f"{a}/{b}" if b else "未测"


def _number(value):
    try:
        n = Decimal(str(value))
        return format(n, "f") if n.is_finite() else "未核实"
    except (InvalidOperation, TypeError, ValueError):
        return "未核实"


def _closed_inputs(run):
    # Neither plan nor scores are loaded until raw predictions are closed and
    # their digest matches the closure. No answer-reference path is accessed.
    closure = _load(run / "prediction_phase_closed.json")
    if closure.get("all_slots_closed") is not True:
        raise ValueError("prediction_phase_not_closed")
    raw = _regular(run / "predictions.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != closure.get("predictions_sha256"):
        raise ValueError("closed_prediction_hash_mismatch")
    predictions = json.loads(raw)
    if (not isinstance(predictions, list) or len(predictions) != 16
            or len({(r["task_id"], r["arm"]) for r in predictions}) != 16
            or {r["arm"] for r in predictions} != set(ARMS)):
        raise ValueError("complete_16_slot_matrix_required")
    tasks = {(r["case_id"], r["task_id"]) for r in predictions}
    if len(tasks) != 8 or len({r["case_id"] for r in predictions}) != 2:
        raise ValueError("frozen_story_task_inventory_changed")
    if any(sum(r["case_id"] == c and r["task_id"] == t for r in predictions) != 2 for c, t in tasks):
        raise ValueError("incomplete_context_pair")
    scores = _load(run / "scoring_summary.json")
    if (scores.get("predictions_sha256") != digest
            or scores.get("reference_read_after_closure") is not True):
        raise ValueError("scoring_not_bound_to_closed_predictions")
    scored = scores.get("scored_rows")
    if (not isinstance(scored, list) or len(scored) != 16
            or {(r["task_id"], r["arm"]) for r in scored}
            != {(r["task_id"], r["arm"]) for r in predictions}):
        raise ValueError("scoring_slot_inventory_changed")
    return closure, predictions, scores, _load(run / "plan.json"), _load(run / "accounting.json")


def _arm_results(scored, arm):
    rows = [r for r in scored if r["arm"] == arm]
    legal = [r for r in rows if r["task_kind"] == "legal"]
    failures = {"client_failure", "not_run", "processing_failure"}
    legal_classes = Counter(r["classification"] for r in legal)
    controls = {}
    for kind in ("forbidden", "missing"):
        subset = [r for r in rows if r["task_kind"] == kind]
        controls[kind] = {"planned": len(subset), "correct": sum(r["correct"] is True for r in subset),
            "unknown_observed": sum(r.get("final_answer") == "UNKNOWN" for r in subset),
            "failures": sum(r["classification"] in failures for r in subset)}
    return {"slots": len(rows), "legal_planned": len(legal),
        "legal_correct": sum(r["correct"] is True for r in legal),
        "legal_raw_unknown": sum(r.get("raw_answer") == "UNKNOWN" for r in legal),
        "legal_final_unknown": sum(r["classification"] == "legal_unknown" for r in legal),
        "legal_raw_explicit_refusal": sum(r.get("raw_explicit_refusal") is True for r in legal),
        "legal_wrong": legal_classes["wrong"],
        "legal_client_failure_or_not_run": legal_classes["client_failure"] + legal_classes["not_run"],
        "legal_processing_failure": legal_classes["processing_failure"],
        "all_failures": sum(r["classification"] in failures for r in rows),
        "registered_raw_disclosure": sum(r.get("registered_raw_disclosure") is True for r in rows),
        "registered_raw_observed": sum(type(r.get("registered_raw_disclosure")) is bool for r in rows),
        "withheld_raw_disclosure": sum(r.get("withheld_raw_disclosure") is True for r in rows),
        "withheld_raw_observed": sum(type(r.get("withheld_raw_disclosure")) is bool for r in rows),
        "input_context_bytes": sum(r.get("context_bytes", 0) for r in rows),
        "controls": controls}


def _evidence(run, plan, predictions):
    source_ids, fact_ids = set(), set()
    hosts = []
    for path in sorted(run.glob("*_host_evidence.json")):
        row = _load(path)
        hosts.append({"file": path.name, "sha256": _sha(path),
            "ordinary_context_byte_equal": row.get("ordinary_context_byte_equal") is True,
            "mapping_persisted": row.get("restoration_mapping_persisted")})
        for record in row.get("records", []):
            source_id = (record.get("source") or {}).get("source_id")
            if source_id:
                source_ids.add(source_id)
        fact_ids.update(row.get("selected_fact_ids", []))
        for excluded in row.get("excluded", []):
            if excluded.get("fact_id"):
                fact_ids.add(excluded["fact_id"])
            if excluded.get("source_id"):
                source_ids.add(excluded["source_id"])
    slots = {s["slot_id"]: s for s in plan["slots"]}
    bindings = 0
    model_ids = set()
    for row in predictions:
        slot = slots[row["slot_id"]]
        receipt = row.get("receipt") or {}
        memory = Path(slot["workspace"]) / "AGENTS.md"
        bindings += bool(memory.is_file() and _sha(memory) == slot["memory_sha256"]
                         and receipt.get("agent_memory_file_sha256") == slot["memory_sha256"])
        model_ids.update(v for v in receipt.get("reported_model_ids") or [] if isinstance(v, str))
    optional = run / "independent_verification.json"
    verification = None
    if optional.is_file() and not optional.is_symlink():
        # Raw audit files remain local. Do not copy their arbitrary contents or
        # any possible account values into public documentation.
        row = _load(optional)
        verification = {"file": optional.name, "sha256": _sha(optional),
            "status": row.get("status") or ("passed" if row.get("all_passed") is True
                else "failed" if row.get("all_passed") is False else "unresolved"),
            "checks_total": row.get("checks_total"), "passed": row.get("passed"), "available": True}
    return {"source_objects": len(source_ids), "fact_objects": len(fact_ids),
        "host_evidence_files": len(hosts), "host_evidence": hosts,
        "ordinary_byte_equal_cases": sum(r["ordinary_context_byte_equal"] for r in hosts),
        "qoder_file_binding_verified": bindings, "qoder_native_loading_event_proven": False,
        "reported_model_ids": sorted(model_ids), "optional_independent_verification": verification}


def render(run_dir):
    run = Path(run_dir).resolve()
    closure, predictions, score, plan, accounting = _closed_inputs(run)
    scored = score["scored_rows"]
    arms = {arm: _arm_results(scored, arm) for arm in ARMS}
    evidence = _evidence(run, plan, predictions)
    f, c = arms["fragment"], arms["context"]
    correct_delta = c["legal_correct"] - f["legal_correct"]
    unknown_delta = c["legal_final_unknown"] - f["legal_final_unknown"]
    executed = closure.get("client_attempts")
    states = Counter(r.get("client_status") for r in predictions)
    pair_rows = score.get("paired_legal") or []
    pair_counts = Counter((r.get("fragment_correct"), r.get("context_correct")) for r in pair_rows)
    if correct_delta > 0:
        verdict = f"在这批预先构造的来源绑定诊断材料上，保留获准原文标题后，合法题正确数增加{correct_delta}题。"
    elif correct_delta < 0:
        verdict = f"在这批诊断材料上，保留获准原文标题后，合法题正确数反而减少{-correct_delta}题，未观察到效用改善。"
    else:
        verdict = "在这批诊断材料上，两种视图的合法题正确数相同，未观察到正确数改善。"
    if states["ok"] != 16:
        verdict += " 本轮存在未执行或客户端失败位置，不能声称16次响应均成功。"
    failures = [r for r in predictions if r.get("client_status") != "ok" or r.get("processing_error")]
    failure_text = ("；".join(f"{r['slot_id']}：{r.get('processing_error') or r.get('client_status')}"
                             for r in failures) if failures else "本批未记录客户端或恢复处理失败。")
    forbidden_failures = sum(a["controls"]["forbidden"]["planned"]
                             - a["controls"]["forbidden"]["correct"] for a in arms.values())
    forbidden_note = (f"本批权限排除题有{forbidden_failures}个位置未正确返回UNKNOWN。即使没有披露登记的禁出原值，"
        "回答仍可能发生事实选择或来源归因错误；不能仅用精确原值披露为0认定控制题通过。"
        if forbidden_failures else "本批权限排除题的正确UNKNOWN与合法题单列，不扩大为一般授权安全证明。")
    if (f["controls"]["forbidden"]["planned"] == 1
            and f["controls"]["forbidden"]["correct"] == 0
            and c["controls"]["forbidden"]["correct"] == 1
            and f["withheld_raw_disclosure"] == 0):
        forbidden_note += ("本次封存回复的错误表现为：片段组把另一来源的已获准值回答给了该问题，"
            "保留标题后返回UNKNOWN。该现象属于来源主体丢失后的错误归属，"
            "没有据此记录为真正禁出原值或邮箱的披露；具体合成回复仅列在本地明细中。")
    metric_rows = "\n".join(
        f"| {LABELS[arm]} | {_fraction(a['legal_correct'], a['legal_planned'])} | "
        f"{a['legal_raw_unknown']} | {a['legal_raw_explicit_refusal']} | {a['legal_wrong']} | "
        f"{a['legal_client_failure_or_not_run']} | {a['legal_processing_failure']} |"
        for arm, a in arms.items())
    control_rows = "\n".join(
        f"| {LABELS[arm]} | {'权限排除' if kind == 'forbidden' else '事实缺失'} | "
        f"{_fraction(a['controls'][kind]['correct'], a['controls'][kind]['planned'])} | "
        f"{a['controls'][kind]['unknown_observed']} | {a['controls'][kind]['failures']} |"
        for arm, a in arms.items() for kind in ("forbidden", "missing"))
    credit_delta = accounting.get("qoder_credit_difference_observed")
    installed = plan.get("installed") or {}
    model_display = installed.get("model", "DeepSeek-Flash")
    opaque_ids = ", ".join(evidence["reported_model_ids"]) or "未提供"
    title = "期刊方法适配与来源上下文优化结果"
    md = f"""# {title}

日期：2026-10-30。{verdict}但候选保护视图与普通完整授权上下文基线字节等价，因此本轮没有证明新算法优于强基线。它验证的是来源主体在原文投影中是否需要被保留，以及这项保留能否在既有权限检查下执行。

**这批材料刻意设置双主体竞争，fragment删去消歧所需的来源标题，证据不足以唯一回答；context增加了已经获准的来源信息。两组的信息量不同，正确数变化不能解释为同信息条件下的算法超越或一般成功率提升。**

## 本轮范围与旧结果分开

本次新增实际Qoder尝试{executed}次，关闭16个预定位置，成功客户端回执{states['ok']}/16、错误{states['error']}、未执行{states['not_run']}。材料为{score.get('stories')}个新合成故事、{evidence['source_objects']}个源对象、{evidence['fact_objects']}条事实、{score.get('unique_tasks')}道不同题，每题比较fragment/context两种视图。每组预声明含{f['legal_planned']}道合法题、{f['controls']['forbidden']['planned']}道权限排除题和{f['controls']['missing']['planned']}道缺失事实题。

这是独立于前一次32次Qoder/Harness实验的新批次；旧结果和原件未覆盖。本批只调用Qoder，没有新增Harness、检测器或原始模型API推理。16个位置不是16个独立故事，也不能与旧32次合成48个独立病例。

## 优化怎样适配现有项目

原始来源中，标题或对象名称负责说明后续事实属于谁。fragment视图只保留保护后的事实片段，诊断性地移去这些主体标题；context视图另外保留已经分别获准读取、迁出和复制的确切原文标题，并与同一来源的相同保护事实绑定。标题通过原文半开区间和来源对象登记，不能从用户问题中补写主体，也不能因标题文本相同就推断来源独立。

```mermaid
flowchart TD
    A[来源原文与可信权限] --> B[分别检查标题和事实的权限]
    B --> C[确切原文与敏感位置绑定]
    C --> D[完整受保护准备记录]
    D --> E[fragment 仅事实片段]
    D --> F[context 获准原文标题与相同事实]
    F --> G[普通完整授权上下文基线 字节等价]
    E --> H[独立Qoder会话]
    F --> I[独立Qoder会话]
    H --> J[完整标题与事实再次核权后恢复]
    I --> J
    J --> K[关闭预测后评分与披露审计]
```

两组都保留同一套完整标题与事实准备记录作为恢复依据。调用前与恢复时检查当前授权、签名包、原文绑定及请求/工作区能力，UNKNOWN同样经过完整检查；没有只持有一个代号就跳过标题或其他记录核权的恢复捷径。恢复映射仅保留在内存中，没有落盘。

## 合法题效果与弃答

| 视图 | 正确/计划合法题 | 原始UNKNOWN | 原始明确拒绝短语 | 答错 | 客户端失败或未执行 | 恢复/处理失败 |
|---|---:|---:|---:|---:|---:|---:|
{metric_rows}

正确数差为context减fragment：{correct_delta:+d}题；最终合法UNKNOWN数差为{unknown_delta:+d}题。{len(pair_rows)}道合法配对中，两组均对{pair_counts[(True, True)]}题，仅context对{pair_counts[(False, True)]}题，仅fragment对{pair_counts[(True, False)]}题，两组均未成功{pair_counts[(False, False)]}题。这里的“未成功”仍包含表中独立列出的运行或处理失败。

**fragment的主体证据被诊断性地移去，UNKNOWN不能直接叫作安全误拒。** 它可能是对不完整或无法绑定来源的证据的合理弃答。明确拒绝只按冻结的原始短语规则统计，不等于人工语义裁决；恢复失败不会删除已经观察到的原始回复。该材料专门暴露来源绑定问题，不能代表日常任务分布，也不能以题面给出的对象名称替代来源证据。

## 权限排除与事实缺失

| 视图 | 控制类型 | 正确/计划数 | 最终UNKNOWN | 客户端或处理失败 |
|---|---|---:|---:|---:|
{control_rows}

这些控制题与合法题分开，不能把权限排除题返回UNKNOWN纳入合法误拒率。{forbidden_note}失败记录：{failure_text}

## 强基线与论文贡献裁决

普通基线是从同一获准安全输入中，按明确的位置关系连接确切原文标题与事实。候选上下文投影与该普通完整授权上下文逐字节等价；共有{evidence['ordinary_byte_equal_cases']}/{evidence['host_evidence_files']}份逐题宿主证据登记这项等价。两者共享context组的{c['slots']}个相应调用结果，不另跑一批同输入，也不把共享结果当作第二组独立实验。

因此，context相对fragment的任何改善都不能证明候选超过普通完整上下文或构成新算法。若本轮没有改善，同样保留负结果。当前较明确的工程价值是：在确切摘录迁移时避免把“有值但不知道属于谁”的记忆交给下游，同时对标题和事实共同保持授权检查。进一步论文贡献仍需真实失败机制、独立材料和强基线不足证据，不能靠改名、增加模块或扩大平台数量替代。

## 期刊方法的角色与来源

| 来源 | 本项目借鉴 | 本轮未声称完成 |
|---|---|---|
| FACPL权限框架 | 明确权限合同、条件缺失与执行义务，独立检查实际判决 | 完整FACPL语言、Java工具链、SMT证明或一般安全证明 |
| DLM信息传播模型 | 明确来源下保持限制，标题与事实分别获准，变换不能自行放宽权限 | Jif全程序检查、任意摘要依赖推断或通用端到端信息流保证 |
| Anthropic Contextual Retrieval | 避免分块或摘录丢失理解所需的来源上下文 | LLM生成分块说明、contextual embeddings、BM25检索或重排效果复现 |

FACPL将授权语义、义务和策略分析纳入严格定义的框架，本项目只做受限方法适配。[作者技术报告](https://arxiv.org/abs/1612.09339)。DLM研究不同主体约束下的数据传播与有授权的限制放宽，本轮仅保留明确原文及其已登记权限。[作者论文](https://www.cs.cornell.edu/andru/papers/iflow-tosem.pdf)。Anthropic方法将来源上下文用于检索，本轮仅使用确定性的获准原文标题连接，没有移植其完整检索流程，也没有运行新的上下文生成模型。[官方说明](https://www.anthropic.com/research/contextual-retrieval)。

FACPL与DLM在这里服务于安全合同和验证；上下文保留是效用适配。两类工作不能互相替代贡献证据。

## 披露、加载与执行边界

fragment组可观察原始回复中的注册敏感值披露为{f['registered_raw_disclosure']}/{f['registered_raw_observed']}，权限排除值披露为{f['withheld_raw_disclosure']}/{f['withheld_raw_observed']}；context组分别为{c['registered_raw_disclosure']}/{c['registered_raw_observed']}和{c['withheld_raw_disclosure']}/{c['withheld_raw_observed']}。原始审计在恢复前进行，无回复位置不计为已证明零泄漏。这只检查登记精确原值，不能证明无改写、推断或未知敏感实体披露。

Qoder固定显式选择器为`{model_display}`；返回的模型标识为`{opaque_ids}`。这类不透明返回标识不能用于证明后端固定修订。文件SHA-256与包装器输入绑定合格{evidence['qoder_file_binding_verified']}/16；Qoder未提供Harness同等级的原生instruction加载事件，证据是文件字节、固定加载配置和客户端回执，不能仅由答对倒推加载已获直接证明。

标题与事实的当前授权仍由本地主机执行；静态AGENTS.md本身不提供原生逐次ACL或即时撤权。各位置用新工作区与新进程，同题两组采用预声明交替顺序。整批不进行自动重试、不开放工具，输出最多64 token。原始宿主记录可在临时密钥销毁后核对一致性，但不能冒称事后重新执行了当时的密码学鉴权。

## 调用、输入与费用

fragment组计划{f['slots']}次、context组计划{c['slots']}次；实际总尝试{executed}次。输入说明文件总字节数分别为{f['input_context_bytes']}与{c['input_context_bytes']}，这是本机上下文文件大小，不等于云端总token或隐含系统提示长度。

Qoder账户前后观察到的Credits差额为{_number(credit_delta)}；仅用现有额度，没有充值。该差额不是独立供应商账单，0差额也不能单独证明所有未来调用免费。账户原始快照只留本机，公开文档不贴账户剩余额度、充值余额或参考答案。Harness新增调用为{accounting.get('new_harness_calls')}，新本地检测器调用为0，旧200次本地生成账本没有被重置。

## 验证记录与后续范围

本轮相关源码20项测试实际通过。首次预检出现15项失败、2项通过，定位为broker双actor合同与本批Qoder目标身份的接口不匹配；修复后测试通过。这是调用前工程接口问题，没有计作模型失败或用修改评分真值处理。本批使用合成控制标签，人工语义复核和真实检测效果仍未成立。

后续若要扩大实验，应保持来源依赖和授权可验证，使用新故事检验自然任务中这种缺失实际出现的频率，并继续比较普通完整授权上下文。当前不扩展为自由摘要、跨源语义依赖发现或新权限优化算法，也不把本轮16次与旧32次合并成通用成功率。

## 可核对文件

- [上下文投影与共同核权](../experiments/context_closure_20261030/context_projection.py)、[冻结执行器](../experiments/context_closure_20261030/run_probe.py)、[关闭后评分器](../experiments/context_closure_20261030/score_probe.py)。
- [期刊方法结合实施与验证](期刊方法结合实施与验证_2026-10-30.md)。
- [前一批32次真实客户端对照](Qoder到Harness_32次真实客户端对照结果_2026-10-30.md)，结果和原始工件保持分开。
- 本机原始目录`{run.name}`中的plan.json、predictions.json、prediction_phase_closed.json、scoring_summary.json、accounting.json及逐题host_evidence；本地HTML另外展示16行合成回复。

预测SHA-256：`{closure['predictions_sha256']}`。评分在整批预测关闭并核对该哈希后进行，参考未进入模型上下文；报告生成器不读取原始评分参考。本轮不自动上传原始结果或更改旧报告。
"""
    independent = evidence["optional_independent_verification"]
    if independent:
        md += f"\n本机另存独立核验文件independent_verification.json，状态为`{independent.get('status')}`；其SHA-256为`{independent['sha256']}`。具体检查范围以该文件为准，不能将文件存在本身当作所有性质已证明。\n"
    summary = {"date": "2026-10-30", "run_name": run.name,
        "stories": score.get("stories"), "source_objects": evidence["source_objects"],
        "fact_objects": evidence["fact_objects"], "unique_tasks": score.get("unique_tasks"),
        "closed_slots": len(predictions), "actual_client_attempts": executed,
        "client_status": dict(states), "arms": arms, "legal_correct_delta": correct_delta,
        "legal_final_unknown_delta": unknown_delta,
        "paired_counts": {"both_correct": pair_counts[(True, True)],
            "context_only_correct": pair_counts[(False, True)],
            "fragment_only_correct": pair_counts[(True, False)],
            "neither_successful": pair_counts[(False, False)]},
        "evidence": evidence, "qoder_credit_difference_observed": credit_delta,
        "new_harness_calls": accounting.get("new_harness_calls"), "new_detector_calls": 0,
        "supplier_bill_verified": False, "ordinary_complete_context_equivalent":
            evidence["ordinary_byte_equal_cases"] == evidence["host_evidence_files"]
            and evidence["host_evidence_files"] == 8,
        "novel_algorithm_advantage_established": False, "human_semantic_review": None,
        "predictions_sha256": closure["predictions_sha256"],
        "scoring_summary_sha256": _sha(run / "scoring_summary.json"),
        "reference_values_opened_by_renderer": False}
    (run / "report.md").write_text(md, encoding="utf-8")
    (ROOT / "docs" / DOC_NAME).write_text(md, encoding="utf-8")
    (run / "report_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    metric_html = "".join(
        f"<tr><td>{_escape(LABELS[arm])}</td><td>{_fraction(a['legal_correct'],a['legal_planned'])}</td>"
        f"<td>{a['legal_raw_unknown']}</td><td>{a['legal_raw_explicit_refusal']}</td>"
        f"<td>{a['legal_wrong']}</td><td>{a['legal_client_failure_or_not_run']}</td>"
        f"<td>{a['legal_processing_failure']}</td></tr>" for arm,a in arms.items())
    detail_html = "".join(
        f"<tr><td>{_escape(r['slot_id'])}</td><td>{_escape(r['task_kind'])}</td>"
        f"<td>{_escape(r.get('raw_answer'))}</td><td>{_escape(r.get('final_answer'))}</td>"
        f"<td>{_escape(r['classification'])}</td><td>{_escape(r.get('processing_error'))}</td>"
        f"<td>{_escape(r.get('registered_raw_disclosure'))} / {_escape(r.get('withheld_raw_disclosure'))}</td></tr>"
        for r in scored)
    page = f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>*{{box-sizing:border-box}}body{{margin:0;background:#f0f4f8;color:#183044;font:16px/1.75 "Microsoft YaHei",sans-serif}}main{{max-width:1200px;margin:28px auto;background:white;padding:32px;border-radius:14px}}h1{{font-size:28px}}h2{{font-size:21px;margin-top:30px}}.cards,.flow{{display:flex;flex-wrap:wrap;gap:12px}}.cards div,.flow span{{background:#e6f1f8;padding:14px;border-radius:8px;flex:1;min-width:150px}}.notice{{border-left:4px solid #c58a25;padding:14px;background:#fff5e4}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{border:1px solid #ccd7e0;padding:10px;vertical-align:middle;text-align:left;overflow-wrap:anywhere}}th{{background:#e6eef5}}.scroll{{overflow:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f9;padding:18px;font:14px/1.8 "Microsoft YaHei",sans-serif}}details{{margin-top:24px}}.muted{{color:#5b7180}}</style>
<main><h1>{title}</h1><p class="muted">2026-10-30 · 新增Qoder有界诊断 · 与旧32次分开</p>
<div class="cards"><div>{executed}次实际尝试<br>2故事 / 8题 / 16位置</div><div>事实片段合法题<br>{_fraction(f['legal_correct'],f['legal_planned'])}正确</div><div>获准上下文合法题<br>{_fraction(c['legal_correct'],c['legal_planned'])}正确</div><div>相对普通完整上下文<br>字节等价，无新算法优势</div></div>
<p class="notice">{html.escape(verdict)} fragment移去了主体证据，UNKNOWN不能直接叫作安全误拒。该批是机制诊断材料，不代表自然任务分布。</p>
<h2>本轮处理流程</h2><div class="flow"><span>原文标题与事实分别核权 →</span><span>同一完整安全准备 →</span><span>片段 / 获准标题对照 →</span><span>完整现时核权恢复与封存评分</span></div>
<h2>共同合法任务</h2><div class="scroll"><table><tr><th>视图</th><th>正确/计划题</th><th>原始UNKNOWN</th><th>原始明确拒绝</th><th>答错</th><th>客户端失败/未执行</th><th>处理失败</th></tr>{metric_html}</table></div>
<p>候选与普通完整授权标题基线共享context组{c['slots']}次调用。没有额外第三组独立结果，也没有复现embedding、BM25或LLM生成上下文流程。</p>
<h2>执行与用量边界</h2><p>文件绑定{evidence['qoder_file_binding_verified']}/16，Qoder无原生加载事件证明。Credits观察差额{_number(credit_delta)}；账户余额不展示。没有新增Harness、检测器或自动重试；注册值披露审计与最终恢复分开。</p>
<details><summary>16个位置的本地合成回复</summary><div class="scroll"><table><tr><th>位置</th><th>题型</th><th>原始回复</th><th>最终恢复</th><th>评分状态</th><th>处理错误</th><th>注册敏感 / 排除值原始披露</th></tr>{detail_html}</table></div></details>
<details><summary>方法来源、完整结果和论文边界</summary><pre>{html.escape(md)}</pre></details></main></html>"""
    (run / "index.html").write_text(page, encoding="utf-8")
    return {"document": str(ROOT / "docs" / DOC_NAME), "html": str(run / "index.html"),
        "summary": str(run / "report_summary.json"), "closed_prediction_hash_verified": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(render(args.run_dir), ensure_ascii=False))


if __name__ == "__main__":
    main()
