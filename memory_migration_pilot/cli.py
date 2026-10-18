"""Run a reproducible, offline pilot and write a self-contained Chinese report."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import platform
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from .core import (
    LocalAPI, ReferenceStore, collect_source_truth, content_hash, default_mapping,
    make_plan, run_budget_audit, run_full_audit,
)
from .data import discover_data_root, load_bundle


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
                             for k, v in row.items()})


def compact_audit(audit: dict) -> dict:
    return {k: v for k, v in audit.items() if k != "observations"}


def stage_check(api: LocalAPI, actors: list[str], mapping: dict, records: list[dict]) -> bool:
    for actor in actors:
        status, data = api.request(mapping[actor], "list")
        if status != 200 or data.get("items") != []:
            return False
        if records and api.request(mapping[actor], "read", records[0]["id"])[0] != 404:
            return False
    return True


def run_dataset(bundle: dict, out: Path, quota: int, budgets: list[int], seed: int) -> dict:
    out.mkdir()
    records = bundle["records"]
    subjects = bundle["subjects"]
    if not records:
        raise ValueError("No eligible records; inspect the data qualification audit")
    outsider = "__pilot_outsider__"
    if outsider in subjects:
        raise ValueError("reserved outsider identity already exists")
    actors = subjects + [outsider]
    mapping = default_mapping(subjects)
    audit_mapping = {**mapping, outsider: "target_lab|" + outsider}
    target_actors = list(audit_mapping.values())
    write_json(out / "data_audit.json", bundle["audit"])
    write_json(out / "controlled_policy.json", {
        "policy_version": "static-v1", "policy_origin": bundle["policy_origin"],
        "is_original_benchmark_acl": False, "subjects": subjects, "outsider": outsider,
        "identity_mapping": mapping,
        "records": [{"id": r["id"], "allowed_users": r["allowed_users"],
                     "content_sha256": content_hash(r["text"]), "source_ref": r["source_ref"]}
                    for r in records],
    })
    write_json(out / "input_manifest.json", bundle["input_files"])
    src = ReferenceStore(out / "source.sqlite3", "source", "source_lab")
    src.seed_source(records)
    try:
        with LocalAPI(src, actors) as source_api:
            truth, source_evidence = collect_source_truth(source_api, actors, records)
            source_calls = source_api.calls
            invalid_status, _ = source_api.raw_request("/memories", None)
            override_status, _ = source_api.raw_request("/memories?user_id=" + subjects[0], source_api.tokens[outsider])
            if invalid_status != 401 or override_status != 400:
                raise RuntimeError("reference authentication calibration failed")
            auth_calls = source_api.calls - source_calls
        write_json(out / "source_execution.json", {
            "source_read_list_matrix_verified": True, "api_calls": source_calls,
            "principals": source_evidence, "anonymous_http_status": invalid_status,
            "identity_override_http_status": override_status, "auth_probe_api_calls": auth_calls,
        })
        k1 = []
        for scenario, cap in (("unrestricted", None), ("synthetic_quota", quota)):
            for method in ("acl_grouping", "per_item_reject", "selective_groups"):
                name = f"{scenario}_{method}"
                plan = make_plan(records, subjects, method, cap, mapping)
                write_json(out / f"plan_{name}.json", plan)
                target = ReferenceStore(out / f"target_{name}.sqlite3", "target", name)
                preview = ReferenceStore(out / f"preview_{name}.sqlite3", "target", name)
                try:
                    manifest = target.stage_target(records, plan)
                    with LocalAPI(target, target_actors) as target_api:
                        staged_hidden = stage_check(target_api, actors, audit_mapping, records)
                        stage_calls = target_api.calls
                        if not staged_hidden:
                            raise RuntimeError("staged records exposed before publication")
                        # An isolated copy runs the same reference implementation.
                        # It is not a second independent product or proof of a
                        # vendor's concurrent publication protocol.
                        with target.lock, preview.lock:
                            target.conn.backup(preview.conn)
                            preview.expected_binding = target.expected_binding
                        preview.publish(manifest)
                        with LocalAPI(preview, target_actors) as validation_api:
                            audit = run_full_audit(validation_api, actors, records, audit_mapping, truth)
                            validation_calls = validation_api.calls
                        safe = audit["status"] == "no_counterexample_in_finite_domain" and audit["content_errors"] == 0
                        admitted = safe and bool(plan["retained_ids"])
                        if admitted:
                            target.publish(manifest)
                        post_calls = 0
                        post_ok = None
                        if admitted:
                            post_ok = True
                            for actor in actors:
                                status, data = target_api.request(audit_mapping[actor], "list")
                                post_calls += 1
                                expected = {i for i in plan["retained_ids"] if truth[(actor, i)]}
                                post_ok &= status == 200 and {x["id"] for x in data.get("items", [])} == expected
                            if not post_ok:
                                raise RuntimeError("published list differs from accepted reference configuration")
                    retained = len(plan["retained_ids"])
                    row = {
                        "scenario": scenario, "scenario_kind": "local_reference" if cap is None else "synthetic_resource_stress",
                        "method": method, "plan_state": plan["state"],
                        "records_total": len(records), "records_retained": retained,
                        "content_retention": retained / len(records),
                        "datasets_used": len(plan["containers"]), "max_datasets": cap,
                        "legal_access_retention": audit["legal_access_retention"],
                        "unauthorized_disclosures": audit["unauthorized_disclosures"],
                        "unauthorized_denominator": audit["total_unauthorized_cells"],
                        "indeterminate_requests": audit["indeterminate_requests"],
                        "staged_hidden": staged_hidden, "admission_check_passed": safe, "admitted": admitted,
                        "post_publication_list_matches": post_ok,
                        "stage_probe_api_calls": stage_calls, "validation_api_calls": validation_calls,
                        "post_publication_api_calls": post_calls, "audit_status": audit["status"],
                    }
                    k1.append(row)
                    write_json(out / f"execution_{name}.json", {"summary": row, "manifest": manifest,
                                                               "audit": compact_audit(audit)})
                    write_csv(out / f"matrix_{name}.csv", audit["observations"],
                              ["user", "operation", "memory_id", "http_status", "known", "checked_ids",
                               "returned_ids", "violations", "content_errors"])
                finally:
                    preview.close()
                    target.close()
        k2 = []
        oracle_summaries = []
        full_plan = make_plan(records, subjects, "acl_grouping", mapping=mapping)
        for fault in ("none", "list_acl_bypass"):
            diagnostic = ReferenceStore(out / f"diagnostic_{fault}.sqlite3", "target", "diagnostic_" + fault, fault)
            try:
                manifest = diagnostic.stage_target(records, full_plan)
                diagnostic.publish(manifest)
                with LocalAPI(diagnostic, target_actors) as api:
                    for strategy in ("fixed", "random", "rule_coverage", "read_only", "migration_relation", "enumerate"):
                        for budget in budgets:
                            before = api.calls
                            result = run_budget_audit(api, actors, records, audit_mapping, truth, strategy, budget, seed)
                            if api.calls - before != result["actual_api_calls"]:
                                raise RuntimeError("probe budget accounting mismatch")
                            row = {k: v for k, v in result.items() if k != "history"}
                            row["fault"] = fault
                            row["scenario_kind"] = "local_clean_control" if fault == "none" else "injected_fault_only"
                            k2.append(row)
                            write_csv(out / f"probes_{fault}_{strategy}_{budget}.csv", result["history"],
                                      ["user", "operation", "memory_id", "http_status", "known", "checked_ids",
                                       "returned_ids", "violations", "content_errors"])
                    # Offline oracle is called AFTER budgeted selectors; its cost
                    # is separately recorded and its results never guide them.
                    before_oracle = api.calls
                    oracle = run_full_audit(api, actors, records, audit_mapping, truth)
                    oracle_summaries.append({"fault": fault, "diagnostic_only": True,
                                             **compact_audit(oracle), "oracle_api_calls": api.calls - before_oracle})
                    write_json(out / f"oracle_{fault}.json", compact_audit(oracle))
            finally:
                diagnostic.close()
        write_csv(out / "k1_results.csv", k1, list(k1[0]))
        write_csv(out / "k2_results.csv", k2, list(k2[0]))
        result = {
            "dataset": bundle["audit"].get("dataset"), "policy_origin": bundle["policy_origin"],
            "selected_records": len(records), "registered_subjects": len(subjects),
            "source_api_calls": source_calls, "authentication_probe_api_calls": auth_calls,
            "k1": k1, "k2": k2, "k2_oracles": oracle_summaries,
            "vendor_migration_tested": False, "original_benchmark_score": None,
            "new_algorithm_advantage": None, "semantic_privacy_score": None,
        }
        result["total_counted_http_calls"] = source_calls + auth_calls + sum(
            r["stage_probe_api_calls"] + r["validation_api_calls"] + r["post_publication_api_calls"] for r in k1
        ) + sum(r["actual_api_calls"] for r in k2) + sum(r["oracle_api_calls"] for r in oracle_summaries)
        write_json(out / "summary.json", result)
        return result
    finally:
        src.close()


def percent(value) -> str:
    return "未知/不适用" if value is None else f"{value:.1%}"


def html_report(summary: dict) -> str:
    e = lambda x: html.escape(str(x))
    sections = []
    for dataset in summary["datasets"]:
        rows = "".join(
            f"<tr><td>{e(r['scenario'])}</td><td>{e(r['method'])}</td><td>{e(r['plan_state'])}</td>"
            f"<td>{r['records_retained']}/{r['records_total']}</td><td>{percent(r['legal_access_retention'])}</td>"
            f"<td>{r['unauthorized_disclosures']}/{r['unauthorized_denominator']}</td><td>{r['datasets_used']}</td></tr>"
            for r in dataset["k1"])
        budget_rows = "".join(
            f"<tr><td>{e(r['fault'])}</td><td>{e(r['strategy'])}</td><td>{r['actual_api_calls']}</td>"
            f"<td>{e('预算内未发现' if r['first_counterexample_cost'] is None else r['first_counterexample_cost'])}</td><td>{percent(r['unknown_cell_fraction'])}</td>"
            f"<td>{e(r['status'])}</td></tr>" for r in dataset["k2"])
        sections.append(f"""<section><h2>{e(dataset['dataset'])}</h2>
        <p>选取 {dataset['selected_records']} 条记忆，{dataset['registered_subjects']} 个登记主体，另测一个无权限主体。
        源端与目标端请求均经过本地 HTTP Bearer 认证及 SQLite 权限执行。</p>
        <h3>K1 权限适配与功能保留</h3><table><tr><th>条件</th><th>基线</th><th>状态</th><th>保留条目</th>
        <th>合法访问保留</th><th>越权/未授权单元</th><th>容器数</th></tr>{rows}</table>
        <p>unrestricted 无资源上限；synthetic_quota 是人为配额压力条件，不是厂商限制。selective_groups 是简单价值排序，不是新算法。
        无限制时正确 ACL 分组可以解决当前静态模型，本程序不会制造“本方法优越”的结论。</p>
        <h3>K2 同预算跨接口测试</h3><table><tr><th>诊断条件</th><th>选测规则</th><th>实际API调用</th>
        <th>首次反例成本</th><th>未知单元比例</th><th>结果</th></tr>{budget_rows}</table>
        <p>list_acl_bypass 是我们故意注入的列表权限旁路，用来验证测试器。它不是真实产品漏洞。
        全量 oracle 单独计费且在预算测试后运行；一次 list 即使返回多条记录也只消耗一次请求。
        unknown 表示预算或观察不足，不能解读为安全。仅针对该定制故障的表现不能证明选择器优越。</p></section>""")
    return """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
    <title>记忆迁移权限保持 本地测试报告</title><style>
    body{font-family:system-ui,'Microsoft YaHei',sans-serif;max-width:1250px;margin:35px auto;padding:0 24px;color:#172337;background:#f5f7fa}
    section{background:white;padding:20px 24px;margin:22px 0;border-radius:12px;border:1px solid #dde3ec}
    table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:8px;border-bottom:1px solid #dde3ec;text-align:left}
    th{background:#edf2f7}p,li{line-height:1.8}.notice{border-left:5px solid #b77618;background:#fff5df;padding:14px 20px}
    code{background:#e9eef4;padding:2px 5px}h1{font-size:27px}h2{font-size:22px}
    </style><h1>Agent 记忆迁移权限保持 本地测试</h1>
    <div class="notice">本报告来自自建参考后端，未测试 Mem0、Letta、Cognee 或 Zep。
    公开数据只提供内容；ACL 是公开说明的受控配置。未调用大模型、未产生 API 费用。
    结果不是原始 GateMem 成绩，也不能证明新算法有效或真实产品存在漏洞。</div>
    <p>当前范围：静态策略、完整记忆、已知 ID 读取和列表。搜索、上下文装配、动态撤销和语义隐私评价未实现。</p>
    """ + "".join(sections) + """<section><h2>怎样理解结果</h2><ul>
    <li>零越权要与合法访问保留率一起看；全部阻断通常也没有越权。</li>
    <li>条目数不是独立安全事件数；重复请求和同一 episode 的多条记录也不是独立实验。</li>
    <li>每个数据子目录的 controlled_policy.json 说明实际施加的权限与来源。</li>
    <li>data_audit.json、input_manifest.json、matrix_*.csv 和 probes_*.csv 可用于复查。</li>
    <li>本地暂存、隔离副本验收和发布后列表复查只证明本参考程序的有限域行为，不证明厂商发布协议。</li>
    </ul></section></html>"""


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Offline controlled ACL migration pilot (no model/API fees)")
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--dataset", choices=["all", "synthetic", "gatemem"], default="all")
    parser.add_argument("--limit", type=int, default=60, help="records per dataset; 0 means all")
    parser.add_argument("--episodes-per-domain", type=int, default=1, help="GateMem episodes per domain; 0 means all")
    parser.add_argument("--quota", type=int, default=2, help="simulated stress quota, not a vendor limit")
    parser.add_argument("--budgets", nargs="+", type=int, default=[0, 8, 20])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--groups", type=Path)
    parser.add_argument("--output", type=Path, help="new output directory; existing paths are not overwritten")
    args = parser.parse_args(argv)
    if args.limit < 0 or args.episodes_per_domain < 0 or args.quota < 0 or any(b < 0 for b in args.budgets):
        parser.error("limits and budgets must be nonnegative")
    project = Path(__file__).resolve().parents[1]
    data_root = args.data_root.resolve() if args.data_root else discover_data_root(project)
    groups = (args.groups or project / "configs" / "pilot_groups.json").resolve()
    out = args.output.resolve() if args.output else project / "results" / (
        datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6])
    out.mkdir(parents=True, exist_ok=False)
    start = time.perf_counter()
    result = {
        "schema_version": "0.1", "status": "running", "experiment_kind": "local_reference_only",
        "created_at": datetime.now().astimezone().isoformat(), "python": sys.version,
        "platform": platform.platform(), "data_root": str(data_root),
        "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "model_calls": 0, "paid_api_calls": 0, "datasets": [],
        "source_code_sha256": {str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted((project / "memory_migration_pilot").glob("*.py"))},
        "not_implemented": ["vendor_backends", "search", "context", "K3_dynamic_revocation", "K4_information_flow", "LLM_semantic_judge"],
    }
    qualifications = []
    public_root = data_root / "benchmarks" / "migration_public_2026-10-18"
    for name, path, reason in (
        ("PrivacyLens", public_root / "privacylens/raw/data/main_data.json",
         "内容与传播规范需要资格审核；本程序不自动把敏感标签转换成read ACL。"),
        ("AgentLeak", public_root / "agentleak/raw/agentleak_data/datasets/scenarios_full_1000.jsonl",
         "渠道与字段允许集未完成语义映射；本程序不将其当成原生用户ACL。"),
    ):
        item = {"dataset": name, "path": str(path), "integrated_into_acl_test": False, "reason": reason}
        if path.is_file():
            if path.suffix == ".jsonl":
                with path.open(encoding="utf-8-sig") as handle:
                    count = sum(bool(line.strip()) for line in handle)
            else:
                value = json.loads(path.read_text(encoding="utf-8-sig"))
                count = len(value) if isinstance(value, list) else None
            item.update({"present": True, "records_observed": count,
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        else:
            item["present"] = False
        qualifications.append(item)
    result["auxiliary_data_qualification"] = qualifications
    write_json(out / "data_qualification.json", qualifications)
    write_json(out / "run_manifest.json", result)
    try:
        for dataset in (["gatemem", "synthetic"] if args.dataset == "all" else [args.dataset]):
            print(f"[{dataset}] loading local data and executing controlled read/list checks...", flush=True)
            bundle = load_bundle(data_root, dataset, args.limit, args.seed, groups,
                                 episodes_per_domain=args.episodes_per_domain)
            dataset_result = run_dataset(bundle, out / dataset, args.quota, sorted(set(args.budgets)), args.seed)
            for source_file in bundle["input_files"]:
                if hashlib.sha256(Path(source_file["path"]).read_bytes()).hexdigest() != source_file["sha256"]:
                    raise RuntimeError("input file changed during experiment: " + source_file["path"])
            dataset_result["input_integrity_unchanged"] = True
            write_json(out / dataset / "summary.json", dataset_result)
            result["datasets"].append(dataset_result)
        result["status"] = "completed"
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        write_json(out / "run_manifest.json", result)
        print(f"FAILED; inspect {out / 'run_manifest.json'}", file=sys.stderr)
        raise
    finally:
        result["elapsed_seconds"] = time.perf_counter() - start
        write_json(out / "run_manifest.json", result)
    write_json(out / "summary.json", result)
    (out / "report.html").write_text(html_report(result), encoding="utf-8")
    print(f"Completed: {out / 'report.html'}", flush=True)
    for d in result["datasets"]:
        clean = [r for r in d["k1"] if r["scenario"] == "unrestricted"]
        print(f"  {d['dataset']}: {d['selected_records']} records; unrestricted "
              f"disclosures={sum(r['unauthorized_disclosures'] for r in clean)}; "
              f"HTTP calls={d['total_counted_http_calls']}", flush=True)
    return 0
