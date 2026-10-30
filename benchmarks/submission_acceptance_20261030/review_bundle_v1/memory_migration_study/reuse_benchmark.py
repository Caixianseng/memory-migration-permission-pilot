"""Reproducible role-cover and cache comparisons, with explicitly bounded claims."""
from __future__ import annotations

import copy
import hashlib
import html
import json
from pathlib import Path
import random
import re
import secrets
import time

from .backend import ReferenceAPI
from .detection_cache import DetectionCache, detector_revision
from .evidence import evaluate, probe
from .local_detector import LocalSensitivityAgent
from .memory_generation_experiment import LocalFactAnswerer
from .memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from .plan_verifier import verify_plan
from .policy import make_plan
from .privacy import _digest, _sources, detect_sensitive
from .privacy_payload_eval import masking_intervals
from .tasks import validate_runtime

ARMS = {"migration": ("migration", False), "migration_cached": ("migration", True),
        "generation": ("generation", False), "generation_cached": ("generation", True)}


def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8"))


def role_cases():
    """Mechanism fixtures, not sampled enterprise policies."""
    specifications = [
        ("overlap", [["a", "b"], ["b", "c"], ["a", "b", "c"]], {}),
        ("expensive_copies", [["a", "b"], ["b", "c"], ["a", "b", "c"]], {"container_cost": 1, "object_cost": 8}),
        ("noncopyable", [["a", "b"], ["b", "c"], ["a", "b", "c"]], {}),
        ("implicit_owner", [["a", "b"], ["b", "c"], ["a", "b", "c"]], {"implicit_readers": ["a"]}),
        ("restricted_groups", [["a", "b"], ["b", "c"], ["a", "b", "c"]],
         {"allowed_reader_sets": [["a", "b"], ["b", "c"]]}),
        ("unknown_policy", [["a", "b"], ["b", "c"], ["a", "b", "c"]], {}),
        ("disjoint", [["a"], ["b"], ["c"]], {}),
        ("uniform", [["a", "b", "c"]] * 3, {}),
    ]
    cases = []
    for name, groups, options in specifications:
        case = {"case_id": name,
                "actors": [{"actor_id": a, "user_id": "user-" + a, "agent_id": "agent-" + a} for a in "abc"],
                "actor_mapping": {a: "target-" + a for a in "abc"},
                "records": [{"source_id": f"m{i}", "text": f"Synthetic {name} independent source fact {i}.",
                             "source_readers": g, "recipient_readers": g, "target_readers": g,
                             "export_allowed": True, "copy_allowed": True} for i, g in enumerate(groups)]}
        if name == "noncopyable":
            case["records"][2]["copy_allowed"] = False
        if name == "unknown_policy":
            case["records"][1]["target_readers"] = None
        cases.append((case, options))
    return cases


def run_role_comparison(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for case, options in role_cases():
        for method in ("exact_groups", "reader_copies", "role_cover"):
            run = f"reuse/{case['case_id']}/{method}/{secrets.token_hex(8)}"
            plan = make_plan(case, method, run, planner_options=options if method == "role_cover" else None)
            constraints = {k: options[k] for k in ("implicit_readers", "allowed_reader_sets") if k in options}
            model = verify_plan(case, plan, **constraints)
            direct = None
            # Invalid target configurations never reach the deployment adapter.
            # Unknown SOURCE relationships still get a diagnostic HTTP probe;
            # they remain unknown and cannot qualify the overall plan as safe.
            if not model["added"] and not model["structural_errors"]:
                with ReferenceAPI(case, plan) as backend:
                    evidence = probe(case, plan, backend.adapter)
                    direct = evaluate(evidence)
                save(output / "evidence" / f"{case['case_id']}__{method}.json", evidence)
            cc, oc = options.get("container_cost", 4), options.get("object_cost", 1)
            rows.append({"case_id": case["case_id"], "method": method, "options": options,
                         "model": model, "direct": direct, "plan": plan,
                         "weighted_cost": cc * len(plan["containers"]) + oc * len(plan["objects"]),
                         "deploy_status": "reference_http_probed" if direct is not None else "blocked_by_preflight"})
    report = {"kind": "synthetic_target_contract_reference_http", "cases": len(role_cases()), "rows": rows,
              "native_product_runs": 0, "cloud_calls": 0,
              "scope": "Weighted configuration cost; finite-domain oracle plus independent read/list probes. No semantic task quality or native product claim."}
    save(output / "report.json", report)
    return report


def cache_fixture():
    """Fresh, authored exact-source memories. Gold lives in a separate structure.

    This isolates reuse on already-built memories. It does not rerun or improve
    the earlier extractive memory builder or reuse its heldout evaluation set.
    """
    stories = [
        ("en_1", "The customer is Alder Lantern Works. The delivery status is received.",
         "Who is the customer?", "What is the delivery status?", "Alder Lantern Works", "received"),
        ("en_2", "The customer is Willow Kestrel Cooperative. The review status is approved.",
         "Who is the customer?", "What is the review status?", "Willow Kestrel Cooperative", "approved"),
        ("zh_1", "客户名称：云帆陶艺合作社。交付状态：已签收。", "客户名称是什么？", "交付状态是什么？", "云帆陶艺合作社", "已签收"),
        ("zh_2", "客户名称：星桥植材联合社。审核状态：已通过。", "客户名称是什么？", "审核状态是什么？", "星桥植材联合社", "已通过"),
    ]
    runtime, gold = [], {}
    for sid, text, private_query, public_query, private_answer, public_answer in stories:
        tasks = [{"task_id": "private_first", "query": private_query, "actor_id": "owner"},
                 {"task_id": "public", "query": public_query, "actor_id": "owner"},
                 {"task_id": "private_repeat", "query": private_query, "actor_id": "owner"},
                 {"task_id": "outsider", "query": private_query, "actor_id": "outsider"}]
        runtime.append({"story_id": sid, "source": {"source_id": sid, "text": text}, "tasks": tasks,
                        "policy": {"version": "synthetic-customer-policy-1", "protected_categories": ["CUSTOMER"],
                                   "instructions": "Customer organization names are sensitive. Status words are not customer names."}})
        gold[sid] = {"answers": {"private_first": private_answer, "public": public_answer, "private_repeat": private_answer},
                     "sensitive_spans": [{"start": text.index(private_answer), "end": text.index(private_answer) + len(private_answer)}]}
    return runtime, gold


def score_cached_task(row, gold):
    expected = gold["answers"].get(row["task_id"])
    legal = row["actor_id"] == "owner"
    actual = row.get("final_answer")
    return {"legal": legal, "correct": bool(expected is not None and actual is not None and actual.casefold() == expected.casefold()),
            "preprocessing_block": legal and row["prepare_status"] != "ok",
            "model_unknown": legal and row.get("model_answer", "").strip().casefold() == "unknown",
            "restoration_failure": legal and row.get("restoration_status") == "blocked",
            "unauthorized_output": not legal and (row["prepare_status"] == "ok" or bool(actual)),
            "outsider_blocked_before_model": not legal and row["prepare_status"] == "blocked" and row["answer_calls"] == 0}


def masking_score(prepared, spans, text):
    if prepared["status"] != "ok":
        return {"ready": False, "incomplete_memory_spans": None, "extra_masked_memory_characters": None}
    before = prepared["original_payload"]["memories"][0]
    after = prepared["payload"]["memories"][0]
    covered = {p for a, b in masking_intervals(before["text"], after["text"], prepared["mapping"]._entries) for p in range(a, b)}
    gold = {p for s in spans for p in range(s["start"], s["end"])}
    residual_query = [text[s["start"]:s["end"]] for s in spans
                      if text[s["start"]:s["end"]].casefold() in prepared["payload"]["query"].casefold()]
    return {"ready": True, "incomplete_memory_spans": sum(not set(range(s["start"], s["end"])) <= covered for s in spans),
            "extra_masked_memory_characters": len(covered - gold), "registered_query_residuals": len(residual_query)}


def summarize_cache(rows, setup):
    results = {}
    for arm in ARMS:
        items = [r for r in rows if r["arm"] == arm]
        legal = [r for r in items if r["score"]["legal"]]
        ready = [r for r in legal if r["prepare_status"] == "ok"]
        creation_calls = sum(s["local_calls"] for s in setup) if arm.startswith("generation") else 0
        results[arm] = {"legal_tasks": len(legal), "legal_correct": sum(r["score"]["correct"] for r in legal),
                        "ready_tasks": len(ready), "preprocessing_blocks": sum(r["score"]["preprocessing_block"] for r in legal),
                        "true_model_unknown": sum(r["score"]["model_unknown"] for r in legal),
                        "restoration_failures": sum(r["score"]["restoration_failure"] for r in legal),
                        "ready_with_masking_gaps": sum(bool(r["masking"]["incomplete_memory_spans"]) for r in ready),
                        "extra_masked_memory_characters": sum(r["masking"]["extra_masked_memory_characters"] for r in ready),
                        "unauthorized_outputs": sum(r["score"]["unauthorized_output"] for r in items),
                        "outsider_blocks": sum(r["score"]["outsider_blocked_before_model"] for r in items),
                        "migration_detector_calls": sum(r["detector_calls"] for r in items),
                        "generation_label_calls_allocated": creation_calls,
                        "total_detector_calls_with_creation": creation_calls + sum(r["detector_calls"] for r in items),
                        "answer_calls": sum(r["answer_calls"] for r in items),
                        "cache_hits": sum(r.get("cache", {}).get("hits", 0) for r in items)}
    return results


def run_cache_comparison(output, config, *, detector=None, answerer=None, progress=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    runtime, evaluation = cache_fixture()
    validate_runtime(runtime)
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")}
    save(output / "runtime.json", runtime)
    save(output / "evaluation.json", evaluation)
    save(output / "plan.json", {"arms": ARMS, "independent_stories": 4,
                               "runtime_sha256": _digest(runtime), "evaluation_sha256": _digest(evaluation),
                               "implementation_sha256": hashes, "config": config, "cloud_calls": 0,
                               "scope": "Mechanism benchmark; new synthetic exact-source memories. No extraction/heldout-generalization claim.",
                               "creation_cost": "Generation labels are measured once per story and allocated to each generation arm. Shared physical setup counted once in actual run totals."})
    detector = detector or LocalSensitivityAgent(config)
    if hasattr(detector, "health"):
        detector.health()
    answerer = answerer or LocalFactAnswerer(config)
    rows, setups = [], []
    for story in runtime:
        source, policy = story["source"], story["policy"]
        authority = MemoryLabelAuthority(secrets.token_bytes(32))
        # Annotation at construction uses the local detector, never evaluation.
        construction_revision = detector_revision(detector)
        build_detection = detect_sensitive({"query": "", "memories": [source]}, policy, agent=detector)
        ready_label = build_detection["status"] == "ok" and construction_revision == detector_revision(detector)
        setup = {"story_id": story["story_id"], "status": build_detection["status"],
                 "local_calls": build_detection["local_calls"], "detection": build_detection}
        setups.append(setup)
        fact = {"text": source["text"], "source_start": 0, "source_end": len(source["text"]),
                "findings": [{k: f[k] for k in ("start", "end", "category")} for f in build_detection["findings"]] if ready_label else []}
        record = authority.build_record(source, fact, policy, owner_id="owner", readers=["owner"],
                                        agent_id="source-agent", allowed_agent_ids=["target-agent"],
                                        builder_version="exact_source_fixture_v1", detector_version=construction_revision)
        if not ready_label:
            # Missing annotation must force normal fallback; never sign failure
            # as a successful empty label. Source/access still remain verifiable.
            record.pop("label")
            record.pop("label_signature")
        caches = {arm: DetectionCache(ttl_seconds=3600) for arm, (_, enabled) in ARMS.items() if enabled}
        for task_index, task in enumerate(story["tasks"]):
            order = list(ARMS)
            random.Random(story["story_id"] + str(task_index)).shuffle(order)
            for arm in order:
                mode, enabled = ARMS[arm]
                request = secrets.token_hex(16)
                started = time.monotonic()
                prepared = prepare_labeled_transfer([record], task["query"], policy, authority=authority,
                    actor_id=task["actor_id"], agent_id="target-agent", request_id=request, mode=mode, agent=detector,
                    detection_cache=caches.get(arm) if enabled else None,
                    label_requirements={"expected_builder_version": "exact_source_fixture_v1", "expected_detector_version": detector_revision(detector)})
                row = {"story_id": story["story_id"], "task_id": task["task_id"], "actor_id": task["actor_id"],
                       "arm": arm, "prepare_status": prepared["status"], "prepare_error": prepared.get("error"),
                       "detector_calls": prepared["local_calls"], "cache": prepared["metadata"].get("detection_cache", {}),
                       "detection": prepared.get("detection"), "payload": prepared.get("payload"),
                       "answer_calls": 0, "model_answer": "", "final_answer": None, "restoration_status": None}
                if prepared["status"] == "ok":
                    response = answerer(prepared["payload"])
                    row.update(answer_calls=response["local_calls"], model_answer=response.get("answer") or "",
                               answer_status=response["status"], answer_error=response.get("error"))
                    if response["status"] == "ok":
                        restored = restore_labeled_answer(response["answer"], prepared, [record], policy,
                            authority=authority, actor_id=task["actor_id"], agent_id="target-agent", request_id=request)
                        row.update(restoration_status=restored["status"], restoration_error=restored.get("error"),
                                   final_answer=restored["answer"])
                row["elapsed_seconds"] = round(time.monotonic() - started, 6)
                # Evaluation labels enter ONLY here, after all model calls and
                # transformations. No scorer output feeds a later request.
                gold = evaluation[story["story_id"]]
                row["masking"] = masking_score(prepared, gold["sensitive_spans"], source["text"])
                row["score"] = score_cached_task(row, gold)
                prepared["mapping"] = None
                rows.append(row)
                save(output / "rows.json", rows)
                save(output / "setup.json", setups)
                if progress:
                    progress({"completed": len(rows), "expected": len(runtime) * 4 * len(ARMS),
                              "story": story["story_id"], "arm": arm, "status": row["prepare_status"]})
    final_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")}
    report = {"kind": "local_cache_mechanism_comparison", "independent_stories": 4,
              "implementation_unchanged": hashes == final_hashes, "arms": summarize_cache(rows, setups),
              "actual_local_calls": sum(s["local_calls"] for s in setups) + sum(r["detector_calls"] + r["answer_calls"] for r in rows),
              "actual_creation_calls": sum(s["local_calls"] for s in setups), "cloud_calls": 0, "new_api_cost_cny": 0,
              "rows": rows, "setups": setups, "cache_contains_restoration_mapping": False,
              "scope": "Synthetic mechanism regression on 4 exact-source memories; 3 legal queries/story including one repeat. Not independent clinical/business data, not semantic safety proof, no new heldout quality claim."}
    save(output / "report.json", report)
    return report


def render_report(output, role_report, cache_report=None):
    output = Path(output)
    esc = lambda x: html.escape(str(x))
    def table(headers, values):
        return "<table><thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr></thead><tbody>" + "".join(
            "<tr>" + "".join(f"<td>{esc(v)}</td>" for v in row) + "</tr>" for row in values) + "</tbody></table>"
    role_table = table(["场景", "方法", "容器", "对象副本", "加权成本", "新增授权", "合法关系缺失", "目标配置检查", "HTTP检查"],
                       [(r["case_id"], r["method"], r["model"]["container_count"], r["model"]["object_count"], r["weighted_cost"],
                         len(r["model"]["added"]), len(r["model"]["missing"]), ", ".join(r["model"]["structural_errors"]) or "通过结构检查",
                         "未部署" if r["direct"] is None else f"W+={r['direct']['known_w_plus']}, W−={r['direct']['known_w_minus']}, unknown={r['direct']['unknown_count']}")
                        for r in role_report["rows"]])
    cache_body = "<p>未运行真实本地模型对照。</p>"
    if cache_report:
        cache_body = table(["方法", "合法答对", "可准备", "模型UNKNOWN", "恢复失败", "漏遮请求/可准备", "迁移检测调用", "含构建检测调用", "越权输出"],
            [(arm, f"{v['legal_correct']}/{v['legal_tasks']}", v['ready_tasks'], v['true_model_unknown'], v['restoration_failures'],
              f"{v['ready_with_masking_gaps']}/{v['ready_tasks']}", v['migration_detector_calls'], v['total_detector_calls_with_creation'],
              v['unauthorized_outputs']) for arm, v in cache_report["arms"].items()])
        cache_body += f"<p>实际本地调用 {cache_report['actual_local_calls']} 次；云端调用 0；新增API费用 0元。构建标注实际只运行一次，比较各方法时分别分摊其成本，不能将分摊数再次相加当作实际账单。</p>"
    body = '<!doctype html><html lang="zh"><meta charset="utf-8"><title>已有算法适配与效果核对</title>'
    body += '<style>body{font:16px/1.7 system-ui;margin:32px;color:#243447;background:#f7f9fc}main{max-width:1500px;margin:auto}h1,h2{color:#16486b}table{background:white;border-collapse:collapse;display:block;overflow-x:auto}td,th{padding:9px;border:1px solid #ccd7e3;white-space:nowrap}p{max-width:1100px}.note{background:#fff4d9;padding:16px;border-left:4px solid #cd9324}a{color:#005c9b}</style><main>'
    body += '<h1>已有算法适配与效果核对 · 2026-10-25</h1><p>两条优化线：带复制成本和目标权限限制的角色覆盖；内容、策略、检测器与主体绑定的检测缓存。均为已有方法的项目适配，不据此认定论文创新。</p>'
    body += '<h2>权限配置：容器少不等于总成本低</h2><p>默认示例权重为每容器4、每对象1，属于可配置实验单位，不是实际费用。隐含所有者和允许读者组是显式声明的合成目标契约。配置预检拒绝的方案不会发送到后端。缺失和未知不被掩盖。</p>' + role_table
    body += '<h2>隐私链：与正确缓存比较</h2><p>migration=每次检测；migration_cached=每次重新核权但复用有效检测；generation=构建时标注；generation_cached=构建标注加检测缓存。4条新合成记忆，原文直接保留；构建标注由真实本地检测器完成。本对照隔离复用机制，未重新评估上游事实提取。</p>' + cache_body
    body += '<p class="note">节省调用不代表漏检或误拒降低。缓存会保留成功检测中的漏检，策略变化、版本变化和到期后必须重检；标签和缓存都不是授权。合法任务质量、恢复失败与漏遮单列。这里是参考HTTP服务和小规模本地模型结果，尚未证明真实产品部署或普遍隐私安全。</p>'
    body += '<p><a href="roles/report.json">权限完整证据</a> · <a href="cache/report.json">缓存完整证据</a> · <a href="summary.json">聚合结果</a></p></main></html>'
    (output / "index.html").write_text(body, encoding="utf-8")


def summary(role_report, cache_report=None):
    return {"schema_version": 1, "date": "2026-10-25", "role_cases": role_report["cases"],
            "roles": [{"case_id": r["case_id"], "method": r["method"], "weighted_cost": r["weighted_cost"],
                       "containers": r["model"]["container_count"], "objects": r["model"]["object_count"],
                       "added": len(r["model"]["added"]), "missing": len(r["model"]["missing"]),
                       "unknown": len(r["model"]["unknown_reference"]), "model_errors": r["model"]["structural_errors"],
                       "deploy_status": r["deploy_status"],
                       "http_w_plus": r["direct"]["known_w_plus"] if r["direct"] is not None else None,
                       "http_w_minus": r["direct"]["known_w_minus"] if r["direct"] is not None else None,
                       "http_unknown": r["direct"]["unknown_count"] if r["direct"] is not None else None,
                       "optimality": r["plan"].get("planner", {}).get("optimality")} for r in role_report["rows"]],
            "cache": {k: v for k, v in cache_report.items() if k not in {"rows", "setups"}} if cache_report else None,
            "claims": {"new_algorithm": False, "native_product_tested": False, "semantic_quality_improvement_established": False},
            "new_api_cost_cny": 0, "cloud_calls": 0}
