"""At most sixteen native HTTP requests: identity readiness, not migration."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.run_native_exact_fact_bridge import WorkerRPC, verify_sha_table

WHEEL_SHA256="aaef9fdc02f542b1d125cde21759dde2fac56355d8928e39c734e7b5c6705eca"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path,value):
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+"\n",encoding="utf-8",newline="\n")


def qualify(runtime,final):
    ids=runtime.get("identities",{}) if isinstance(runtime,dict) else {}
    requests=final.get("native_requests",[])
    expected={"owner","assistant","outsider"}
    checks={"three_ordinary_independent_users":set(ids)==expected and len({v["id"] for v in ids.values()})==3 and
             all(v.get("is_superuser") is False for v in ids.values()),
            "physical_http_cap":len(requests)==10 and len(requests)<=16,
            "zero_inference":final.get("generation_attempts")==final.get("embedding_attempts")==0,
            "no_blocked_network":all(x.get("allowed") is True for x in final.get("network_events",[])),
            "redacted_client_credentials":final.get("client_credential_values_persisted") is False,
            "no_datasets_or_facts":not final.get("datasets") and not final.get("facts"),
            "fixed_wheel":runtime.get("wheel_sha256")==WHEEL_SHA256 if isinstance(runtime,dict) else False}
    return checks


def run(output,*,python,wheel,legacy):
    output=Path(output).resolve();wheel=Path(wheel).resolve();legacy=Path(legacy).resolve()
    if output.exists() or not output.is_relative_to((ROOT/"results").resolve()):
        raise ValueError("new_workspace_results_required")
    if sha(wheel)!=WHEEL_SHA256:raise ValueError("cognee_wheel_not_official_fixed_file")
    temp_root=Path(tempfile.gettempdir()).resolve()
    state=temp_root/("agent_memory_cognee_qual_"+uuid.uuid4().hex)
    if not str(state).isascii() or state.parent!=temp_root or state.exists():
        raise ValueError("new_ascii_system_temp_child_required")
    source=[ROOT/"scripts"/n for n in ("run_cognee_identity_qualification.py","native_cognee_policy_worker.py",
                "native_exact_fact_common.py","run_native_exact_fact_bridge.py")]
    source.append(legacy/"scripts/cognee_local_migration_probe.py")
    hashes={str(p.resolve()):sha(p) for p in source}
    output.mkdir(parents=True)
    for index,path in enumerate(source):
        (output/f"source_{index}_{path.name}").write_bytes(path.read_bytes())
    plan={"version":"cognee_native_identity_qualification_v1","wheel_sha256":WHEEL_SHA256,
          "python":str(Path(python).resolve()),"state":str(state),"code_sha256":hashes,
          "max_native_http_requests":16,"expected_setup_requests":10,"max_model_calls":0,
          "source_policy_projection_performed":False,"datasets_created":0,"facts_migrated":0,
          "scope":"new isolated native identity/application readiness only; policy matrix remains unverified"}
    save(output/"plan.json",plan)
    runtime=None;final={};worker=None;failure=None
    try:
        worker=WorkerRPC(python,ROOT/"scripts/native_cognee_policy_worker.py",["--state",state,"--wheel",wheel,
            "--legacy-project",legacy,"--http-cap","16"],timeout=180)
        runtime=worker.call("init",{})
    except Exception as error:
        failure={"class":type(error).__name__,"code":"native_identity_init_failed"}
    finally:
        if worker is not None:
            try:final=worker.call("close",{})
            except Exception as error:final["close_error"]={"class":type(error).__name__}
            save(output/"rpc_receipts.json",worker.calls)
            worker.terminate()
    checks=qualify(runtime,final)
    postflight=verify_sha_table(hashes)
    passed=failure is None and all(checks.values()) and postflight["status"]=="passed"
    report={"version":plan["version"],"status":"qualified" if passed else "not_qualified",
            "runtime":runtime,"final":final,"failure":failure,"checks":checks,"postflight":postflight,
            "new_model_calls":0,"paid_api_calls":0,"source_policy_projection_performed":False,
            "all_projection_matrix_entries_remain_unverified":True,"scope":plan["scope"]}
    save(output/"report.json",report)
    return report


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--python",type=Path,default=ROOT/".venv-native-cognee/Scripts/python.exe")
    parser.add_argument("--wheel",type=Path,default=ROOT/".runtime/native_cognee_wheel/cognee-1.6.5-py3-none-any.whl")
    parser.add_argument("--legacy",type=Path,default=ROOT/"memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
    args=parser.parse_args()
    result=run(args.output,python=args.python,wheel=args.wheel,legacy=args.legacy)
    print(json.dumps({k:result[k] for k in ("status","failure","checks","postflight","scope")},ensure_ascii=False))
    raise SystemExit(0 if result["status"]=="qualified" else 1)
