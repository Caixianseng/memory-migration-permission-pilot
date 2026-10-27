"""Freeze/replay the old six-text complete target lifecycle once, no line trace."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Optional

PROJECT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(PROJECT))
from scripts import run_native_exact_fact_bridge as bridge
from scripts.native_vector_metadata_worker import CHROMA_SHA,SNAPSHOTS,instrument_search

VERSION="fixed_old_lifecycle_metadata_observer_no_trace_v1"
OLD_REPORT_SHA="d0879b96e57580e5f74fb2b5a8a3d072e33d3dab93fe6accfce39a2786cece52"
TARGET_SHA="be7d8b422cdad86aba795bde5d168dd159acd033d4a1a9cbc9b0803759e1f5c2"
BRIDGE_SHA="5e607b8614f1e7d0d2d8632eac3b66bff8eb9eb8a97f49c0b500ac4bca20218b"
COMMANDS=("init","snapshot","add","add","add","add_residents","snapshot","snapshot","snapshot","delete","delete","snapshot","snapshot","report","close")


def require(value,code):
    if not value:raise ValueError(code)


def save(path,value):
    with Path(path).open("x",encoding="utf-8",newline="\n") as stream:json.dump(value,stream,ensure_ascii=False,indent=2,allow_nan=False);stream.write("\n")


def freeze_fixture(report):
    calls=report["target_rpc_receipts"];require(tuple(r["command"] for r in calls)==COMMANDS,"old_rpc_sequence_changed")
    writes=[];old_to_logical={}
    for logical,call in zip(("main-owner","main-assistant","valid-assistant"),calls[2:5]):
        writes.append({"logical_id":logical,**deepcopy(call["input"])});old_to_logical[call["result"]["target_id"]]=logical
    residents=calls[5]["result"]["residents"]
    require(residents==report["resident_controls"] and [r["actor"] for r in residents]==list(bridge.ACTORS),"old_residents_changed")
    for item in residents:
        logical="resident-"+item["actor"];old_to_logical[item["target_id"]]=logical
        writes.append({"logical_id":logical,"actor":item["actor"],"text":item["content"],"path":item["path"]})
    require(len(old_to_logical)==6 and all(isinstance(r["text"],str) and r["text"] for r in writes),"old_writes_invalid")
    require(report["trusted_fixture"]["source_only_canary"] not in json.dumps(writes),"source_canary_in_target_fixture")
    schedule=[];previous=None;snapshot=0
    for call in calls:
        data=deepcopy(call["input"])
        if call["command"]=="snapshot":
            data["target_ids"]=[old_to_logical[x] for x in data["target_ids"]];snapshot+=1
        if call["command"]=="delete":data["target_id"]=old_to_logical[data["target_id"]]
        require(previous is None or 0<=call["started_ns"]-previous<1_000_000_000,"old_rpc_gap_out_of_scope")
        schedule.append({"command":call["command"],"input":data,"gap_ns":0 if previous is None else call["started_ns"]-previous,
            "snapshot_name":SNAPSHOTS[snapshot-1] if call["command"]=="snapshot" else None})
        previous=call["finished_ns"]
    require(snapshot==6 and [r["input"] for r in schedule if r["command"]=="delete"]==[
        {"actor":"owner","target_id":"main-owner"},{"actor":"assistant","target_id":"main-assistant"}],"old_lifecycle_changed")
    return {"schema":VERSION+"_fixture","writes":writes,"schedule":schedule,"source_canary_included":False}


def plan_only(output,*,python,legacy,fixture_report):
    output=Path(output).resolve();legacy=Path(legacy).resolve();fixture_report=Path(fixture_report).resolve();python=Path(python).resolve()
    require(output.is_relative_to(PROJECT/"results") and not output.exists(),"new_results_directory_required")
    require(bridge.file_sha256(fixture_report)==OLD_REPORT_SHA,"old_report_changed")
    require(bridge.file_sha256(PROJECT/"scripts/native_exact_fact_target.py")==TARGET_SHA
        and bridge.file_sha256(PROJECT/"scripts/run_native_exact_fact_bridge.py")==BRIDGE_SHA,"original_control_flow_changed")
    fixture=freeze_fixture(json.loads(fixture_report.read_bytes()));old_plan_path=fixture_report.with_name("plan.json")
    old_plan=json.loads(old_plan_path.read_bytes());assets=old_plan["asset_sha256"]
    require(bridge.verify_sha_table(assets)["status"]=="passed","old_native_assets_changed")
    chroma=python.parent.parent/"Lib/site-packages/open_webui/retrieval/vector/dbs/chroma.py"
    require(bridge.file_sha256(chroma)==CHROMA_SHA,"fixed_chroma_changed")
    _,ast_receipt=instrument_search(chroma.read_bytes().decode("utf-8"),str(chroma),
        {"Optional":Optional,"SearchResult":type("SearchResult",(),{})},lambda error:None,CHROMA_SHA)
    sources=[Path(__file__),PROJECT/"scripts/native_vector_metadata_worker.py",PROJECT/"scripts/native_exact_fact_target.py",
        PROJECT/"scripts/native_exact_fact_common.py",PROJECT/"scripts/run_native_exact_fact_bridge.py",chroma]
    sources+=sorted((PROJECT/"memory_migration_study").glob("*.py"))
    sources+=[legacy/"scripts"/n for n in ("qualify_migration.py","openwebui_migration_probe.py")]
    hashes={str(p.resolve()):bridge.file_sha256(p) for p in sources};output.mkdir(parents=True)
    archive=bridge.archive_code(sources,hashes,output);save(output/"fixture.json",fixture)
    plan={"version":VERSION,"output":str(output),"python":str(python),"legacy":str(legacy),"fixture_report":str(fixture_report),
        "fixture_report_sha256":OLD_REPORT_SHA,"old_plan_sha256":bridge.file_sha256(old_plan_path),"fixture_sha256":bridge.file_sha256(output/"fixture.json"),
        "code_sha256":hashes,"code_archive":archive,"asset_sha256":assets,"chroma_sha256":CHROMA_SHA,"ast_preflight":ast_receipt,
        "one_arm_only":"A","max_native_http":164,"max_searches":15,"max_snapshots":6,"max_deletions":2,"max_embeddings":21,
        "generation_cap":0,"cloud_cap":0,"retry_cap":0,"extra_native_reads":0,"sys_settrace":False,
        "query":bridge.SEMANTIC_QUERY,"k":100,"threshold_changed":False,"source_sdk_started":False,
        "schedule_gaps":"old target RPC finish-to-next-start intervals; not historical CPU scheduling",
        "stop_rule":"ordinary null retained and complete planned lifecycle; stop for foreign disclosure/auth/backend/observer/network/assets failure",
        "scope":"target-only metadata-observer AST variant, not full migration acceptance; all green is only not reproduced"}
    save(output/"plan.json",plan);return plan


def validate_plan(path):
    path=Path(path).resolve();plan=json.loads(path.read_bytes());output=Path(plan["output"])
    require(path==output/"plan.json" and output.is_relative_to(PROJECT/"results") and plan["version"]==VERSION,"plan_location_invalid")
    require(bridge.file_sha256(output/"fixture.json")==plan["fixture_sha256"] and bridge.file_sha256(plan["fixture_report"])==OLD_REPORT_SHA
        and bridge.file_sha256(Path(plan["fixture_report"]).with_name("plan.json"))==plan["old_plan_sha256"],"fixture_binding_changed")
    require(json.loads((output/"fixture.json").read_bytes())==freeze_fixture(json.loads(Path(plan["fixture_report"]).read_bytes())),"fixture_not_old_exact_sequence")
    require(bridge.verify_sha_table(plan["code_sha256"])["status"]==bridge.verify_sha_table(plan["asset_sha256"])["status"]=="passed","frozen_source_or_assets_changed")
    require(bridge.verify_sha_table({str(output/r["archive_path"]):r["sha256"] for r in plan["code_archive"].values()})["status"]=="passed","frozen_archive_changed")
    return plan


def validate_snapshot_security(snapshot,expected):
    for row in snapshot["rows"]:
        require(row["status"] not in {401,403} and row["status"]<500,"native_auth_or_backend_failure")
        value=row.get("vector_result") if row["operation"]=="semantic" else row.get("items")
        if isinstance(value,dict) and row["operation"]=="semantic":ids={x for group in value.get("ids",[]) for x in group}
        elif isinstance(value,list):ids={x["id"] for x in value if isinstance(x,dict) and "id" in x}
        else:ids=set()
        require(ids<=expected[row["actor"]],"foreign_native_id_observed")


def replay(target,fixture,*,sleep=time.sleep,records=None):
    mapping={};expected={a:set() for a in bridge.ACTORS};texts={};snapshots={};checks=[];deletions=[]
    records=records if records is not None else {}
    records.update(snapshots=snapshots,checks=checks,deletions=deletions,mapping=mapping)
    for step in fixture["schedule"]:
        sleep(step["gap_ns"]/1_000_000_000);data=deepcopy(step["input"]);command=step["command"]
        if command=="snapshot":data["target_ids"]=[mapping[x] for x in data["target_ids"]]
        if command=="delete":data["target_id"]=mapping[data["target_id"]]
        result=target.call(command,data)
        if command=="add":
            item=fixture["writes"][len(mapping)];rid=result["target_id"]
            require(result["actor"]==item["actor"] and result["content"]==item["text"] and rid not in texts,"native_write_binding_invalid")
            mapping[item["logical_id"]]=rid;expected[item["actor"]].add(rid);texts[rid]=item["text"]
        if command=="add_residents":
            require(len(result["residents"])==3,"resident_count_changed")
            for item,row in zip(fixture["writes"][3:],result["residents"]):
                require(all(row[k]==item[k if k!="content" else "text"] for k in ("actor","content","path")) and row["target_id"] not in texts,"resident_binding_changed")
                mapping[item["logical_id"]]=row["target_id"];expected[item["actor"]].add(row["target_id"]);texts[row["target_id"]]=item["text"]
        if command=="delete":
            require(result.get("status")==200 and result.get("deleted") is True and result.get("target_id")==data["target_id"]
                and result.get("actor")==data["actor"],"native_delete_failed")
            expected[data["actor"]].remove(data["target_id"]);deletions.append(result)
        if command=="snapshot":
            snapshots[step["snapshot_name"]]=result;validate_snapshot_security(result,expected)
            checks.append({"stage":step["snapshot_name"],"passed":bridge.check_snapshot(result,deepcopy(expected),source_canary="NEVER-SENT-SOURCE-CANARY",
                expected_text=texts if texts else None,known_ids=list(mapping.values()))})
        if command=="close":records["final"]=result;return records
    raise ValueError("missing_planned_close")


def execute(path,*,factory=bridge.WorkerRPC):
    plan=validate_plan(path);output=Path(plan["output"]);require(not (output/"execution_started.json").exists(),"one_arm_no_retry")
    save(output/"execution_started.json",{"plan_sha256":bridge.file_sha256(path),"one_arm":"A"})
    target=None;result={};error=None
    try:
        target=factory(Path(plan["python"]),PROJECT/"scripts/native_vector_metadata_worker.py",["--state",output/"target_state",
            "--assets",Path(plan["legacy"])/"runtime_assets","--legacy-project",plan["legacy"],"--fixture",output/"fixture.json","--fixture-sha",plan["fixture_sha256"]],timeout=300)
        result=replay(target,json.loads((output/"fixture.json").read_bytes()),records=result)
    except Exception as exc:error={"class":type(exc).__name__,"code":str(exc) if type(exc) is ValueError else "native_worker_or_protocol_failed"}
    finally:
        if target is not None:
            if not target.calls or target.calls[-1]["command"]!="close":
                try:result["final"]=target.call("close",{})
                except Exception:result["close_error"]=True
            save(output/"rpc_receipts.json",target.calls);target.terminate()
    final=result.get("final",{});observed=final.get("metadata_only",{});rows=observed.get("observations",[])
    post={"code":bridge.verify_sha_table(plan["code_sha256"]),"assets":bridge.verify_sha_table(plan["asset_sha256"])}
    instrumentation=(error is None and len(result.get("snapshots",{}))==6 and len(result.get("deletions",[]))==2
        and len(final.get("native_requests",[]))==164 and final.get("native_embedding_function_invocations")==21
        and observed.get("snapshot_calls")==6 and observed.get("search_calls")==len(rows)==15 and not observed.get("observer_errors") and observed.get("observer_failure") is False
        and all(r.get("variant_calls")==1 and r.get("literal_original_function_calls")==0
            and r.get("trace_disabled_before") and r.get("trace_disabled_after") for r in rows)
        and final.get("generation_attempts")==0 and all(e.get("allowed") is True for e in final.get("network_events",[]))
        and all(x["status"]=="passed" for x in post.values()))
    nulls=[{"stage":stage,"actor":r["actor"]} for stage,s in result.get("snapshots",{}).items() for r in s["rows"]
        if r["operation"]=="semantic" and r["status"]==200 and r.get("native_raw_body")=="null"]
    report={"version":VERSION,"error":error,**result,"instrumentation_complete":bool(instrumentation),"null_http_events":nulls,
        "exception_events":sum(len(r.get("exception_events",[])) for r in rows),"postflight":post,"generation_calls":0,"cloud_calls":0,
        "original_v3_failure_closed":False,"source_sdk_started":False,
        "interpretation":"not_reproduced_in_one_fixed_complete_lifecycle" if instrumentation and not nulls and all(c["passed"] for c in result["checks"]) else "failure_observed_or_run_incomplete"}
    save(output/"report.json",report);return report


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only",action="store_true");mode.add_argument("--execute",action="store_true")
    parser.add_argument("--output",type=Path);parser.add_argument("--approved-plan",type=Path)
    parser.add_argument("--python",type=Path,default=PROJECT/".venv-native-webui/Scripts/python.exe")
    parser.add_argument("--legacy",type=Path,default=PROJECT/"memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
    parser.add_argument("--fixture-report",type=Path,default=PROJECT/"results/native_exact_fact_bridge_20261025_v3/report.json")
    args=parser.parse_args()
    if args.plan_only:
        require(args.output is not None and args.approved_plan is None,"plan_arguments_invalid")
        plan_only(args.output,python=args.python,legacy=args.legacy,fixture_report=args.fixture_report)
        print(json.dumps({"status":"plan_only_zero_native_embedding","one_arm":"A"}))
    else:
        require(args.approved_plan is not None and args.output is None,"execution_arguments_invalid")
        r=execute(args.approved_plan);print(json.dumps({k:r[k] for k in ("instrumentation_complete","exception_events","null_http_events","interpretation","original_v3_failure_closed")}))
        raise SystemExit(0 if r["instrumentation_complete"] else 1)
