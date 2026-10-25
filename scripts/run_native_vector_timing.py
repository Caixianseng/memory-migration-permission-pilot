"""Bounded same-text immediate/delay native diagnostic; no repair or retries."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from scripts.run_native_exact_fact_bridge import WorkerRPC, archive_code, file_sha256, verify_sha_table, check_semantic_row
from scripts.probe_native_vector_null_target import load_fixture

VERSION = "same_geometry_native_timing_pairs_v1"
QUERY = "Customer service and delivery status."


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8", newline="\n")


def schedule():
    return [{"pair":p,"actor":("assistant","owner","outsider")[p % 3],"arms":
             ["immediate","delay500"] if p % 2 == 0 else ["delay500","immediate"]} for p in range(6)]


def qualify_observation(query, writes, final, fixture):
    actor = query["actor"]
    owned = {r["target_id"]: r["native_item"] for r in writes if r["actor"] == actor}
    semantic = check_semantic_row(query["semantic_row"], expected_ids=set(owned), listed_rows=owned,
                                  source_canary="NEVER-SENT-SOURCE-CANARY")
    trace, timing = query["trace"], final["timing"]
    input_sha = [hashlib.sha256((r["path"].strip("/")+"\n"+r["text"]).encode()).hexdigest() for r in fixture]
    instrumentation = (len(trace) == timing["search_calls"] == timing["query_attempts"] == 1 and
        len(timing["upserts"]) == 6 and query["embedding_delta"] == 1 and final["native_embedding_function_invocations"] == 7 and
        [h for r in timing["upserts"] for h in r["text_sha256"]] == input_sha and
        all(r["original_calls"] == 1 and r.get("returned") is True for r in timing["upserts"]) and
        not timing["observer_errors"] and final["generation_attempts"] == 0 and
        all(e.get("allowed") is True for e in final["network_events"]))
    if len(trace) == 1:
        row = trace[0]
        instrumentation = instrumentation and row["actor"] == actor and row["original_calls"] == 1 and row["trace_restored"] is True and row["limit"] == 100 and row["filter"] is None and row["query_vectors"]["shape"] == [1,384] and row["query_vectors"]["finite"] is True
    if query["arm"] == "delay500":
        instrumentation = instrumentation and query["http_started_ns"]-query["scheduled_ns"] >= 500_000_000
    null = query["semantic_row"]["status"] == 200 and query["semantic_row"]["native_raw_body"] == "null"
    foreign = False
    value = query["semantic_row"].get("vector_result")
    if isinstance(value,dict):
        ids = {i for group in value.get("ids",[]) for i in group}
        foreign = bool(ids - set(owned))
    return {"semantic_complete":bool(semantic),"instrumentation_complete":bool(instrumentation),
            "null":null,"foreign_id":foreign,"passed":bool(semantic and instrumentation),
            "exception_events":sum(len(r["exception_events"]) for r in trace)}


def run(output, *, python, legacy, fixture_report, execute=False):
    output = Path(output).resolve(); legacy = Path(legacy).resolve(); fixture_report = Path(fixture_report).resolve()
    if output.exists() or not output.is_relative_to((PROJECT/"results").resolve()):
        raise ValueError("new_workspace_results_required")
    fixture = load_fixture(fixture_report)
    source = [PROJECT/"scripts"/name for name in ("run_native_vector_timing.py","native_vector_timing_worker.py",
        "native_exact_fact_target.py","native_exact_fact_common.py","native_vector_trace_only_worker.py",
        "native_vector_null_target_worker.py","probe_native_vector_null_target.py","probe_native_vector_null.py","run_native_exact_fact_bridge.py")]
    source += [PROJECT/"memory_migration_study"/name for name in ("native_webui.py","__init__.py")]
    source += [legacy/"scripts"/name for name in ("qualify_migration.py","openwebui_migration_probe.py")]
    hashes = {str(p.resolve()):file_sha256(p) for p in source}
    old_plan = json.loads(fixture_report.with_name("plan.json").read_bytes())
    assets = old_plan["asset_sha256"]
    if verify_sha_table(assets)["status"] != "passed":
        raise ValueError("native_assets_differ_from_original_failure")
    output.mkdir(parents=True)
    archive = archive_code(source, hashes, output)
    plan = {"version":VERSION,"fixture_report_sha256":file_sha256(fixture_report),"fixture":fixture,
        "code_sha256":hashes,"code_archive":archive,"asset_sha256":assets,"schedule":schedule(),
        "max_queries":12,"max_writes":72,"max_embeddings":84,"generations":0,"cloud_calls":0,
        "query":QUERY,"k":100,"threshold":0,"extra_count_get":0,"retries":0,"fallback":False,
        "stop_rule":"finish one matched arm after first ordinary failure then stop; immediate stop for scope/security/asset/network failure",
        "scope":"isolated target-only same-text paired diagnosis; not full migration acceptance or a repair"}
    save(output/"plan.json", plan)
    if not execute:
        return {"status":"plan_only","model_calls":0,"max_queries":12}
    rows=[];stopped=None;alignments=[]
    for pair in schedule():
        failed_pair=False
        for arm in pair["arms"]:
            cell = output/f"pair_{pair['pair']}_{arm}";cell.mkdir()
            worker=None;writes=[];query=None;final={};error=None;runtime=None
            try:
                if verify_sha_table(hashes)["status"] != "passed":
                    raise ValueError("frozen_code_changed")
                worker=WorkerRPC(python,PROJECT/"scripts/native_vector_timing_worker.py",
                    ["--state",cell/"state","--assets",legacy/"runtime_assets","--legacy-project",legacy],timeout=300)
                runtime=worker.call("init",{})
                for item in fixture:
                    written=worker.call("timing_add",deepcopy(item))
                    if any(written[k]!=item[k] for k in item):raise ValueError("frozen_write_changed")
                    writes.append(written)
                query=worker.call("timing_query",{"pair":pair["pair"],"actor":pair["actor"],"arm":arm})
            except Exception as exc:
                error={"class":type(exc).__name__,"code":str(exc) if type(exc) is ValueError else "native_worker_failure"}
            finally:
                if worker is not None:
                    try:final=worker.call("close",{})
                    except Exception:final={"close_error":True}
                    save(cell/"rpc_receipts.json",worker.calls);worker.terminate()
            row={"pair":pair["pair"],"actor":pair["actor"],"arm":arm,"runtime":runtime,"writes":writes,"query":query,"final":final,"error":error}
            if query is not None and "timing" in final:
                row["score"]=qualify_observation(query,writes,final,fixture)
            else:row["score"]={"passed":False,"instrumentation_complete":False,"foreign_id":False}
            save(cell/"observation.json",row);rows.append(row);save(output/"rows.json",rows)
            print(json.dumps({"completed":len(rows),"pair":pair["pair"],"arm":arm,"score":row["score"]}),flush=True)
            if not row["score"]["instrumentation_complete"] or row["score"]["foreign_id"]:
                stopped="scope_security_or_instrumentation_failure";break
            if not row["score"]["passed"]:failed_pair=True
        paired=[r for r in rows if r["pair"]==pair["pair"]]
        if len(paired)==2 and all(r["score"]["instrumentation_complete"] for r in paired):
            left,right=paired
            vector_hashes=lambda row: [x["vectors"]["sha256"] for x in row["final"]["timing"]["upserts"]]
            matched=(vector_hashes(left)==vector_hashes(right) and
                     left["query"]["trace"][0]["query_vectors"]==right["query"]["trace"][0]["query_vectors"] and
                     set(left["runtime"]["native_user_ids"].values()).isdisjoint(right["runtime"]["native_user_ids"].values()))
            alignments.append({"pair":pair["pair"],"all_six_write_vectors_and_query_identical":matched,"fresh_native_users":True})
            save(output/"pair_alignment.json",alignments)
            if not matched:stopped="paired_vectors_or_independent_users_mismatch"
        if stopped or failed_pair:
            stopped=stopped or "ordinary_failure_pair_completed";break
    post={"code":verify_sha_table(hashes),"assets":verify_sha_table(assets)}
    report={"version":VERSION,"rows":len(rows),"queries":sum(r["query"] is not None for r in rows),
        "passed":sum(r["score"]["passed"] for r in rows),"stop_reason":stopped,
        "embeddings":sum(r["final"].get("native_embedding_function_invocations",0) for r in rows),
        "generations":0,"cloud_calls":0,"new_api_cost_cny":0,"postflight":post,
        "pair_alignment":alignments,
        "interpretation":"not_reproduced_in_12_fixed_queries" if len(rows)==12 and all(r["score"]["passed"] for r in rows) and len(alignments)==6 and all(a["all_six_write_vectors_and_query_identical"] for a in alignments) else "failure_observed_or_run_incomplete",
        "original_v3_failure_closed":False}
    save(output/"report.json",report)
    return report


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--execute",action="store_true")
    parser.add_argument("--python",type=Path,default=PROJECT/".venv-native-webui/Scripts/python.exe")
    parser.add_argument("--legacy",type=Path,default=PROJECT/"memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
    parser.add_argument("--fixture-report",type=Path,default=PROJECT/"results/native_exact_fact_bridge_20261025_v3/report.json")
    args=parser.parse_args()
    result=run(args.output,python=args.python,legacy=args.legacy,fixture_report=args.fixture_report,execute=args.execute)
    print(json.dumps(result,ensure_ascii=False))
