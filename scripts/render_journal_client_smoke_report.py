"""Render closed native-client evidence without opening answer references.

The public Markdown contains aggregate synthetic-study results and spending
deltas only. Raw synthetic replies are shown only in the local HTML. This
module never starts a client, queries an account or parses scoring references.
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
DOC_NAME = "Qoder到Harness_32次真实客户端对照结果_2026-10-30.md"
LABELS = {
    "A": "Qoder 源端获准原文",
    "B": "Qoder 源端保护视图",
    "C": "Harness 迁入相同保护视图",
    "D": "Harness 无记忆对照",
}


def _json(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("missing_or_linked_report_input:" + path.name)
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _safe(value):
    return html.escape(str(value)) if value is not None else "未测/无"


def _fraction(n, d):
    return f"{n}/{d}" if d else "未测"


def _decimal(value):
    try:
        parsed = Decimal(str(value))
        return parsed if parsed.is_finite() else None
    except (InvalidOperation, ValueError, TypeError):
        return None


def _number(value):
    parsed = _decimal(value)
    return format(parsed, "f") if parsed is not None else "未核实"


def _account_delta(run):
    """Return deltas, never copy absolute wallet or credit balances to reports."""
    checkpoints = [_json(p) for p in sorted(run.glob("account_checkpoint_*.json"))]
    checkpoints.sort(key=lambda row: (row.get("ordinal", -1),
                                    row.get("snapshot", {}).get("checked_at_utc", "")))
    first = checkpoints[0] if checkpoints else {}
    last = checkpoints[-1] if checkpoints else {}
    q0 = _decimal(first.get("snapshot", {}).get("qoder", {}).get("quota_remaining_credits"))
    q1 = _decimal(last.get("snapshot", {}).get("qoder", {}).get("quota_remaining_credits"))
    credit_delta = q0 - q1 if q0 is not None and q1 is not None else None
    return {
        "qoder_credit_consumption_observed": str(credit_delta) if credit_delta is not None else None,
        "checkpoint_count": len(checkpoints),
        "first_observation_utc": first.get("snapshot", {}).get("checked_at_utc"),
        "last_observation_utc": last.get("snapshot", {}).get("checked_at_utc"),
        "wallet_delta_cny": last.get("observed_wallet_delta_cny"),
        "absolute_balances_in_report": False,
    }


def _load_closed(run):
    # Closure and prediction integrity are checked before ANY other result data.
    closure = _json(run / "prediction_phase_closed.json")
    if closure.get("all_slots_closed") is not True:
        raise ValueError("prediction_phase_not_closed")
    raw = (run / "predictions.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != closure.get("predictions_sha256"):
        raise ValueError("prediction_hash_mismatch")
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 32:
        raise ValueError("all_32_closed_slots_required")
    cells = {(row["case_id"], row["task_id"], row["condition"]) for row in rows}
    if len(cells) != 32:
        raise ValueError("duplicate_prediction_cells")
    score = _json(run / "scoring_summary.json")
    if score.get("predictions_sha256") != digest:
        raise ValueError("score_prediction_binding_mismatch")
    if score.get("reference_read_after_prediction_closure") is not True:
        raise ValueError("score_reference_phase_unverified")
    scored = score.get("scored_rows")
    if not isinstance(scored, list) or len(scored) != 32:
        raise ValueError("all_32_scores_required")
    scored_cells = {(row["case_id"], row["task_id"], row["condition"]) for row in scored}
    if cells != scored_cells:
        raise ValueError("score_cell_binding_mismatch")
    return closure, rows, score, _json(run / "plan.json"), _json(run / "accounting_summary.json")


def _common_rows(scored):
    by_task = {}
    for row in scored:
        by_task.setdefault((row["case_id"], row["task_id"]), {})[row["condition"]] = row
    keys = [key for key, arms in by_task.items() if all(
        condition in arms and arms[condition].get("task_kind") == "legal"
        and arms[condition].get("evaluation_role") == "legal_available"
        for condition in ("A", "B", "C"))]
    return {condition: [by_task[key][condition] for key in keys]
            for condition in ("A", "B", "C", "D")}


def _performance(rows):
    counts = Counter(row.get("outcome") for row in rows)
    return {
        "tasks": len(rows),
        "correct": sum(row.get("correct") is True for row in rows),
        "raw_unknown": sum(row.get("raw_unknown_abstention") is True for row in rows),
        "raw_explicit_refusal": sum(row.get("raw_explicit_refusal") is True for row in rows),
        "wrong_answer": counts["wrong_answer"],
        "client_failure_or_not_run": counts["client_failure"] + counts["client_not_run"],
        "processing_failure": counts["processing_failure"],
        "unresolved": counts["reference_condition_unresolved"],
    }


def _loading(run, plan, rows):
    slots = {slot["slot_id"]: slot for slot in plan["slots"]}
    harness_native, qoder_file, guard_valid, credential_clean = 0, 0, 0, 0
    failures = []
    for row in rows:
        slot = slots[row["slot_id"]]
        receipt = row.get("receipt") or {}
        memory_path = Path(slot["workspace"]) / "AGENTS.md"
        file_valid = (memory_path.is_file() and _sha(memory_path) == slot["memory_sha256"]
                      and receipt.get("agent_memory_file_sha256") == slot["memory_sha256"])
        if row["client"] == "qoder":
            qoder_file += bool(file_valid)
            continue
        expected = memory_path.read_text(encoding="utf-8") if memory_path.is_file() else ""
        sha1 = hashlib.sha1(expected.encode("utf-8")).hexdigest()
        valid_baseline = False
        for baseline in receipt.get("native_instruction_baselines") or []:
            source = baseline.get("source") or {}
            rendered = "".join(block.get("text", "") for block in baseline.get("content") or []
                               if block.get("type") == "text")
            valid_change = any(item.get("digest") == sha1 and str(item.get("path", ""))
                               .replace("\\", "/").endswith("AGENTS.md")
                               for item in source.get("changes") or [])
            valid_baseline |= (source.get("kind") == "agent-instructions" and source.get("baseline") is True
                               and bool(expected) and expected.strip() in rendered and valid_change)
        loaded = file_valid and receipt.get("native_instruction_loaded") is True and valid_baseline
        harness_native += bool(loaded)
        counts = receipt.get("guard_counts") or {}
        guard_valid += all(counts.get(k) == 1 for k in
                           ("agent_attempt_count", "stream_attempt_count", "allowed_stream_count"))
        credential_clean += (receipt.get("credentials_source_unchanged") is True
                             and receipt.get("temporary_credentials_removed") is True)
        if not loaded:
            failures.append(row["slot_id"])
    by_task = {}
    for slot in plan["slots"]:
        by_task.setdefault(slot["task_id"], {})[slot["condition"]] = slot
    byte_pairs = sum(arms["B"]["memory_sha256"] == arms["C"]["memory_sha256"]
                     and arms["B"]["prompt"] == arms["C"]["prompt"] for arms in by_task.values())
    return {"harness_native_loading_verified": harness_native,
            "harness_planned": sum(row["client"] == "harness" for row in rows),
            "qoder_file_binding_verified": qoder_file,
            "qoder_planned": sum(row["client"] == "qoder" for row in rows),
            "harness_single_stream_guard_verified": guard_valid,
            "harness_credentials_unchanged_and_temp_removed": credential_clean,
            "protected_byte_identical_pairs": byte_pairs, "protected_pairs": len(by_task),
            "failed_harness_loading_slots": failures,
            "qoder_native_loading_event_proof": False}


def render(run_dir):
    run = Path(run_dir).resolve()
    closure, predictions, score, plan, accounting = _load_closed(run)
    scored = score["scored_rows"]
    perf = {arm: _performance(rows) for arm, rows in _common_rows(scored).items()}
    loading = _loading(run, plan, predictions)
    deltas = _account_delta(run)
    status = Counter(row.get("client_status") for row in predictions)
    scoped = [row for row in predictions if row["condition"] in {"B", "C", "D"}]
    pi_leak = sum(row.get("registered_leak") is True for row in scoped)
    pi_observed = sum(type(row.get("registered_leak")) is bool for row in scoped)
    unauthed = sum(row.get("unauthorized_raw_disclosure") is True for row in scoped)
    unauthed_observed = sum(type(row.get("unauthorized_raw_disclosure")) is bool for row in scoped)
    raw_audit_complete = sum(row.get("raw_audit", "").startswith("registered exact values")
                             for row in predictions)
    attempts = closure.get("client_attempts")
    common_count = score["common_legal_task_count"]
    c = perf["C"]
    d_source_match = sum(row.get("source_reference_match") is True for row in _common_rows(scored)["D"])
    # Data-driven headline: do not turn errors or unknowns into a success claim.
    if c["correct"] == c["tasks"] and c["tasks"]:
        conclusion = f"本批迁入Harness的共同合法题为{c['correct']}/{c['tasks']}正确，未观察到这些题的回答损失。"
    else:
        conclusion = f"本批迁入Harness的共同合法题为{c['correct']}/{c['tasks']}正确，失败与弃答需按下表分别解释。"
    if attempts != 32 or status["ok"] != 32:
        conclusion += " 本轮并未形成32份全部成功的客户端响应，未执行及失败位置保留在分母中。"
    if pi_leak or unauthed:
        conclusion += " 原始输出发现注册值披露，不能因本地拦截而判为无披露。"
    title = "Qoder到Harness的32次真实客户端对照结果"
    table = "\n".join(
        f"| {arm} {LABELS[arm]} | {_fraction(perf[arm]['correct'], perf[arm]['tasks'])} | "
        f"{perf[arm]['raw_unknown']} | {perf[arm]['raw_explicit_refusal']} | "
        f"{perf[arm]['wrong_answer']} | {perf[arm]['client_failure_or_not_run']} | "
        f"{perf[arm]['processing_failure']} | {perf[arm]['unresolved']} |"
        for arm in ("A", "B", "C"))
    controls = []
    for arm in ("A", "B", "C", "D"):
        rows = [row for row in scored if row["condition"] == arm]
        for role, label in (("missing_fact", "事实缺失"), ("withheld_fact", "迁出权限排除"),
                            ("no_memory_control", "无记忆对照")):
            subset = [row for row in rows if row["evaluation_role"] == role]
            if subset:
                n = sum(row.get("control_unknown_correct") is True for row in subset)
                failure = sum(row.get("outcome") in {"client_failure", "client_not_run", "processing_failure"}
                              for row in subset)
                controls.append(f"| {arm} | {label} | {_fraction(n, len(subset))} | {failure} |")
    extra = [row for row in scored if row["condition"] == "A" and row["task_kind"] == "forbidden"
             and row["evaluation_role"] == "legal_available"]
    extra_correct = sum(row.get("correct") is True for row in extra)
    all_failures = [row for row in predictions if row.get("client_status") != "ok" or row.get("processing_error")]
    failure_summary = ("；".join(f"{row['slot_id']}：{row.get('processing_error') or row.get('client_status')}"
                                  for row in all_failures) if all_failures else "本批未记录客户端或恢复处理失败。")
    qdelta = deltas["qoder_credit_consumption_observed"]
    wallet_delta = accounting.get("observed_wallet_delta_cny", deltas["wallet_delta_cny"])
    reserved = accounting.get("reserved_engineering_budget_cny")
    approved = accounting.get("approved_limit_cny")
    actual_by_client = closure.get("per_client", {})
    qoder_model_ids = sorted({model for row in predictions if row.get("client") == "qoder"
        for model in (row.get("receipt") or {}).get("reported_model_ids", [])})
    summary = {
        "date": "2026-10-30", "run_dir": run.name, "client_attempts": attempts,
        "closed_slots": len(predictions), "successful_client_responses": status["ok"],
        "independent_stories": score["story_count"], "unique_tasks": score["unique_tasks"],
        "common_legal_tasks": common_count, "common_legal": perf,
        "D_common_source_answer_matches": d_source_match,
        "raw_registered_disclosure": {"count": pi_leak, "observed": pi_observed},
        "raw_unauthorized_disclosure": {"count": unauthed, "observed": unauthed_observed},
        "raw_audited_responses": raw_audit_complete, "loading": loading,
        "accounting_deltas": deltas, "wallet_delta_cny": wallet_delta,
        "reserved_engineering_budget_cny": reserved, "supplier_bill_verified": False,
        "novel_algorithm_advantage_established": False, "real_detector_effectiveness_measured": False,
        "human_semantic_review": None, "predictions_sha256": closure["predictions_sha256"],
        "actual_by_client": actual_by_client, "qoder_reported_model_ids": qoder_model_ids,
        "scoring_summary_sha256": _sha(run / "scoring_summary.json"),
    }
    md = f"""# {title}

日期：2026-10-30。{conclusion}本轮回答的是在限定授权、确切原文与单事实任务下，保护后的记忆交给另一客户端是否仍可使用，以及合法题是否出现弃答或明确拒绝。它不验证任意Agent原生权限互通或一般隐私安全。

## 实际运行和分母

本轮关闭{len(predictions)}个预定位置，实际客户端尝试{attempts}次，其中Qoder实际{actual_by_client.get('qoder', 0)}次，Harness实际{actual_by_client.get('harness', 0)}次。成功客户端回执{status['ok']}/{len(predictions)}；未执行{status['not_run']}，客户端错误{status['error']}。材料为{score['story_count']}个AI辅助合成故事、{score['unique_tasks']}道不同题，四条件各一次；不是32个独立故事。共同合法题共{common_count}道，人工语义复核为null。

| 条件 | 实际客户端 | 记忆输入 |
|---|---|---|
| A | Qoder | 源端获准原文 |
| B | Qoder | 源端保护视图 |
| C | DeepSeek Harness | 与B相同的迁入保护视图 |
| D | DeepSeek Harness | 无迁入记忆，使用中性非空说明文件 |

每个位置使用新工作区、进程和会话；工作区含独立.git边界。每题B/C属于一个逻辑交接事务，在该事务内共用同一保护文本；两端各用绑定Agent、工作区、条件和题目的单次宿主能力票据，不跨题或用户复用恢复映射。实际保护输入配对字节相同{loading['protected_byte_identical_pairs']}/{loading['protected_pairs']}。

## 迁移后的回答效果和合法问题拒答

下表仅比较A/B/C都获准且有证据的共同合法题。正确依据冻结的精确参考，失败留在计划分母。UNKNOWN是弃答；不能仅凭它推断模型是在进行隐私拒绝。明确拒绝只按事先声明的原始回复短语规则识别，未作人工语义裁决。

| 条件 | 正确/计划合法题 | 原始UNKNOWN | 原始明确拒绝 | 答错 | 客户端失败或未执行 | 恢复/处理失败 | 参考未解决 |
|---|---:|---:|---:|---:|---:|---:|---:|
{table}

D组在这{common_count}道题中，返回源事实答案的数量为{d_source_match}/{common_count}。这是记忆效用诊断；D没有证据，不能把其UNKNOWN当作合法题误拒。C相对D的配对结果见本机scoring_summary.json。

来源可读但禁止迁出的额外问题在A组仍可合法回答，单独为{_fraction(extra_correct, len(extra))}正确；B/C排除该事实后，UNKNOWN属于权限/证据边界，不进入合法误拒分母。因此这个故事的A→B差异包含授权选择，不能纯归因于脱敏；B→C差异也包括客户端系统提示、工具配置与运行环境。

## 缺失事实及权限控制题

| 条件 | 任务类别 | 正确UNKNOWN/计划数 | 客户端或处理失败 |
|---|---|---:|---:|
{chr(10).join(controls)}

原始拒绝文本与最终处理状态分层保留。例如拒绝长句被单值恢复合同阻断时，仍统计原始明确拒绝，最终结果记作处理失败；不能把失败包装成正常业务拒绝。失败记录：{failure_summary}

## 保护与加载证据

B/C/D原始回复中，注册敏感原值披露为{pi_leak}/{pi_observed}份可观察回复；另行审计禁止交付但未列为PII的登记值，原始披露为{unauthed}/{unauthed_observed}。原始审计在恢复前完成；有回复而本地恢复失败时，仍保留披露证据。无回复的位置不冒充零泄漏。上述只覆盖登记精确值，不证明无改写、推断或未知实体泄漏。

Harness原生instruction baseline结合内容、文件路径、SHA-1加载摘要与文件SHA-256，合格{loading['harness_native_loading_verified']}/{loading['harness_planned']}；单流守卫合格{loading['harness_single_stream_guard_verified']}/{loading['harness_planned']}。Qoder合格文件绑定{loading['qoder_file_binding_verified']}/{loading['qoder_planned']}，证据是固定加载配置和文件哈希，未提供同等级原生加载事件，不能由答对倒推已直接证明加载。

权限仍由本地宿主现时核权与单次恢复门禁执行。静态AGENTS.md不提供客户端原生逐次ACL或即时撤权；已读明文不能靠事后撤权让客户端遗忘。本轮没有开放自由工具或跨机器原子撤权。

## 用量和费用

本次计划最多32次，输出每次64 token，工具0、自动重试0；没有新本地检测器调用或额外原始API推理。Qoder账户前后观察到的Credits消耗差额为{_number(qdelta)}；未充值或购买额度。Harness观察到的钱包余额差额为{_number(wallet_delta)}元，已授权本轮限额为{_number(approved)}元，工程预算累计预留为{_number(reserved)}元。

钱包差额可能包含结算滞后或账号并发使用，不是本项目独立供应商账单；工程预留不是实际消费，也不是供应商原子金额上限。旧原生客户端费用未补成已核实数字，项目历史累计费用仍不能据此认定已核清。公开报告不展示账户充值或赠送余额；原始本机核账快照保留。

## 研究结论和边界

本轮建立的是限定案例上的真实客户端效用证据。实际使用合成控制标签，未启用真实检测器，因而不能声称降低了敏感检测漏检率。当前结果也没有比较新算法与完整强基线的增量，不足以成立论文创新。两端显式选择Flash模型，但选择器相同不保证隐藏提示或后端模型修订完全一致。Qoder回执中的模型标识为{json.dumps(qoder_model_ids, ensure_ascii=False)}，属于不透明标识，不能据此证明与Harness底层模型版本相同。

合法题UNKNOWN率、明确拒绝率、答错及接口失败应分别解释。只有2个故事的小型资格测试，即使全对也不能外推一般成功率接近100%；后续扩展需要新独立故事与冻结对照。

## 工程和前序依据

- [本轮执行器](../experiments/journal_methods_20261030/client_smoke.py)、[封存后评分器](../experiments/journal_methods_20261030/client_smoke_score.py)、[只读核账器](../experiments/journal_methods_20261030/account_budget_probe.py)。
- [期刊方法结合实施与验证](期刊方法结合实施与验证_2026-10-30.md)。
- [前次真实Qoder/Harness验证](DeepSeek_Harness与Qoder_当前代码验证结果_2026-10-27.md)，该批结果与本轮分开计数。
- [Harness官方模型计费条款](https://www.deepseek.com/harness/terms-of-use/)、[DeepSeek模型价格](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/)、[Qoder Credits与价格](https://docs.qoder.com/account/pricing)。价格适用日期为预算核查记录时点。

本机原始目录：`{run.name}`。关键文件为plan.json、predictions.json、prediction_phase_closed.json、scoring_summary.json及accounting_summary.json。预测SHA-256为`{closure['predictions_sha256']}`；评分只在预测关闭并核对该哈希后进行，参考答案未进入客户端上下文。恢复映射未落盘。原始运行与本地明细未自动上传GitHub。
"""
    doc = ROOT / "docs" / DOC_NAME
    doc.write_text(md, encoding="utf-8")
    (run / "report.md").write_text(md, encoding="utf-8")
    (run / "report_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    table_html = "".join(
        f"<tr><td>{_safe(arm+' '+LABELS[arm])}</td><td>{_fraction(perf[arm]['correct'], perf[arm]['tasks'])}</td>"
        f"<td>{perf[arm]['raw_unknown']}</td><td>{perf[arm]['raw_explicit_refusal']}</td>"
        f"<td>{perf[arm]['wrong_answer']}</td><td>{perf[arm]['client_failure_or_not_run']}</td>"
        f"<td>{perf[arm]['processing_failure']}</td></tr>" for arm in ("A", "B", "C"))
    score_index = {row["slot_id"]: row for row in scored}
    detail_html = "".join(
        f"<tr><td>{_safe(row['slot_id'])}</td><td>{_safe(row['client'])}</td>"
        f"<td>{_safe(row.get('raw_answer'))}</td><td>{_safe(row.get('final_answer'))}</td>"
        f"<td>{_safe(score_index[row['slot_id']]['outcome'])}</td>"
        f"<td>{_safe(row.get('processing_error'))}</td>"
        f"<td>{_safe(row.get('registered_leak'))} / {_safe(row.get('unauthorized_raw_disclosure'))}</td></tr>"
        for row in predictions)
    page = f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f0f4f8;color:#172d40;font:16px/1.7 "Microsoft YaHei",sans-serif}}main{{max-width:1220px;margin:28px auto;background:white;padding:32px;border-radius:14px}}h1{{font-size:28px}}h2{{margin-top:30px;font-size:21px}}.cards,.flow{{display:flex;flex-wrap:wrap;gap:12px}}.cards div,.flow span{{background:#e7f1f9;border-radius:8px;padding:14px;flex:1;min-width:150px}}.notice{{padding:15px;border-left:4px solid #d59a30;background:#fff5e4}}.scroll{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #ccd8e2;padding:10px;text-align:left;vertical-align:middle;overflow-wrap:anywhere}}th{{background:#e7eff6}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f9;padding:20px;font:14px/1.8 "Microsoft YaHei",sans-serif}}details{{margin-top:24px}}.muted{{color:#586f80}}
</style><main><h1>{title}</h1><p class="muted">2026-10-30 · 真实客户端四条件 · 合成研究控制</p>
<div class="cards"><div>{attempts}次实际尝试<br>{score['story_count']}故事 / {score['unique_tasks']}题</div><div>迁入共同合法题<br>{_fraction(c['correct'],c['tasks'])}正确</div><div>迁入合法题原始弃答<br>{c['raw_unknown']}个UNKNOWN</div><div>迁入合法题原始明确拒绝<br>{c['raw_explicit_refusal']}个短语命中</div></div>
<p class="notice">{html.escape(conclusion)} 这些是小型资格结果，不能外推一般成功率或敏感检测能力。</p>
<h2>输入与检查流程</h2><div class="flow"><span>冻结合成原文与授权 →</span><span>A原文 / B源保护 →</span><span>C迁入相同保护 / D无记忆 →</span><span>原始审计、核权、恢复与封存</span></div>
<h2>共同合法题</h2><div class="scroll"><table><tr><th>条件</th><th>正确/计划题</th><th>UNKNOWN</th><th>明确拒绝</th><th>答错</th><th>客户端失败/未执行</th><th>处理失败</th></tr>{table_html}</table></div>
<p>D组源事实答案匹配{d_source_match}/{common_count}。A的额外源私有问题单列，不把B/C权限排除当误拒。明确拒绝为原始短语检查，UNKNOWN为弃答。</p>
<h2>预算与披露观察</h2><p>Qoder Credits消耗差额：{_number(qdelta)}。Harness钱包观察差额：{_number(wallet_delta)}元；工程预留：{_number(reserved)}元。钱包差额不是独立账单，预留不是实际费用。注册敏感值原始披露{pi_leak}/{pi_observed}；未获交付许可值原始披露{unauthed}/{unauthed_observed}。</p>
<details><summary>32个位置的本地原始与最终回复</summary><p>仅含本批合成材料的回答。处理失败不会删除原始披露证据；未观察到回复时标记未测。</p><div class="scroll"><table><tr><th>位置</th><th>客户端</th><th>原始回复</th><th>最终恢复</th><th>评分状态</th><th>处理错误</th><th>敏感值 / 权限外原始披露</th></tr>{detail_html}</table></div></details>
<details><summary>详细说明与研究边界</summary><pre>{html.escape(md)}</pre></details></main></html>"""
    (run / "index.html").write_text(page, encoding="utf-8")
    return {"document": str(doc), "html": str(run / "index.html"),
            "summary": str(run / "report_summary.json"), "closed_prediction_hash_verified": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(render(args.run_dir), ensure_ascii=False))


if __name__ == "__main__":
    main()
