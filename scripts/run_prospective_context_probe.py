"""Frozen prospective synthetic comparison: plain versus source-only routing."""
from copy import deepcopy
import argparse
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_candidate_context_probe as common
from scripts import run_native_span_attribute_probe as assets
from memory_migration_study import occurrence_routing as routing
from memory_migration_study.ner_detector import LocalNerRuntime, MODEL_ID, MODEL_REVISION, CODE_REVISION
from memory_migration_study.sensitivity_contract import bind_category_contract

base, scoring, redaction, batch = common.base, common.scoring, common.redaction, common.batch
save, sha, require = base.save, base.sha, base.require
ARMS = ("plain", "conditional")
VERSION = "prospective_context_probe_v1"
METHOD = ROOT / "results/prospective_context_20261027/method_freeze.json"
METHOD_SHA = "172248b1d9bac8cf7b96d2f494bfaf1da70f98cf238da4b1173701fbe19c512a"
PREREG = "docs/新材料条件标记_前瞻检验预注册_2026-10-27.md"
LIMITS = {"texts": 24, "rows": 48, "ner_proposal_attempts": 24, "generation_posts": 48,
          "wall_seconds": 1800, "cloud_calls": 0, "native_writes": 0, "repairs": 0}


def policy():
    return bind_category_contract({"version": VERSION, "policy_id": VERSION,
        "protected_categories": ["CUSTOMER"], "max_text_chars": 6000,
        "instructions": base.relation.BUSINESS_SCOPE, "entity_registry": []}, base.PROFILE)


def check_method():
    require(sha(METHOD) == METHOD_SHA, "method_freeze_changed")
    frozen = json.loads(METHOD.read_text(encoding="utf-8"))
    require(all(sha(ROOT/name) == digest for name,digest in frozen["files"].items()), "frozen_method_changed")
    return frozen


def read_runtime(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    require(data.get("schema_version") == "relation_occurrence_probe_runtime_v1"
        and type(data.get("texts")) is list and len(data["texts"]) == 24
        and all(type(text) is str and 0 < len(text) <= 6000 and text.strip() for text in data["texts"])
        and len(set(data["texts"])) == 24, "runtime_invalid")
    return data["texts"]


def manifest():
    paths = list((ROOT/"memory_migration_study").glob("*.py")) + [Path(__file__)]
    paths += [ROOT/name for name in ("scripts/run_candidate_context_probe.py", "scripts/run_relation_event_probe.py",
        "scripts/relation_probe_scoring.py", "scripts/relation_redaction_audit.py", "scripts/run_boundary_preparation_audit.py",
        "scripts/run_native_span_attribute_probe.py", "scripts/native_span_attribute_scoring.py",
        "tests/test_prospective_context_probe.py", "tests/test_occurrence_routing.py",
        "tests/test_candidate_context_batch.py", PREREG)]
    return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(paths)}


def freeze(output, materials):
    check_method()
    require(output.is_relative_to(ROOT/"results") and not output.exists(), "output_scope_or_exists")
    read_runtime(materials/"runtime.json")
    asset = {"assets_root":str(ROOT/".runtime/github_ner")}
    assets.verify_assets(asset)
    asset["asset_receipt_sha256"] = sha(Path(asset["assets_root"])/"receipt.json")
    files = manifest(); output.mkdir(parents=True)
    for name in files:
        dest=output/"implementation"/name; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/name,dest)
    for name in ("runtime.json", "evaluation.opaque.json"): shutil.copyfile(materials/name,output/name)
    authoring_hash=None
    if (materials/"authoring.json").is_file():
        shutil.copyfile(materials/"authoring.json",output/"authoring.opaque.json")
        authoring_hash=sha(output/"authoring.opaque.json")
    value={"version":VERSION,"limits":LIMITS,"options":base.OPTIONS,"method_freeze_sha256":METHOD_SHA,
        "sources":files,"runtime_sha256":sha(output/"runtime.json"),"reference_sha256":sha(output/"evaluation.opaque.json"),"authoring_sha256":authoring_hash,
        "policy":policy(),"batch_spec":batch.compiled_spec(),"routing_version":routing.VERSION,
        "model":base.MODEL,"model_digest":base.DIGEST,"ollama":base.OLLAMA_VERSION,**asset,
        "ner_model":MODEL_ID,"ner_revision":MODEL_REVISION,"ner_code_revision":CODE_REVISION,
        "reference_parsed":False,"scope":"24 newly authored synthetic texts; not real-world holdout or independent human annotation.",
        "failure_contract":"No truncated source/candidates. Ineligible pool or either required context blocks both arms. Plain routes share one observation.",
        "acceptance":"Both known exact and known prepared nondecreasing, at least one improves; all unknown review; no prepared incomplete sensitive span."}
    save(output/"plan.json",value)
    return {"status":"frozen","plan_sha256":sha(output/"plan.json"),"new_model_calls":0}


def verify(output, expected):
    check_method(); require(sha(output/"plan.json")==expected,"plan_changed")
    plan=json.loads((output/"plan.json").read_text(encoding="utf-8"))
    require(plan["sources"]==manifest() and plan["limits"]==LIMITS and plan["options"]==base.OPTIONS
        and plan["policy"]==policy() and plan["batch_spec"]==batch.compiled_spec()
        and plan["routing_version"]==routing.VERSION,"contract_changed")
    for name,digest in plan["sources"].items():require(sha(output/"implementation"/name)==digest,"archive_changed")
    require(sha(output/"runtime.json")==plan["runtime_sha256"] and sha(output/"evaluation.opaque.json")==plan["reference_sha256"],"material_changed")
    if plan["authoring_sha256"] is not None:
        require(sha(output/"authoring.opaque.json")==plan["authoring_sha256"],"authoring_record_changed")
    require(sha(Path(plan["assets_root"])/"receipt.json")==plan["asset_receipt_sha256"],"asset_receipt_changed")
    return plan,read_runtime(output/"runtime.json")


class BoundedClient(base.Client):
    """Separate 48-attempt budget; the old 24-attempt client stays unchanged."""
    def __call__(self, method, path, body=None):
        require(not self.closed and time.monotonic()-self.started < LIMITS["wall_seconds"],"client_closed_or_wall_budget")
        require((method=="GET" and path in {"/api/version","/api/tags"} and body is None)
            or (method=="POST" and path=="/api/chat"),"transport_route_forbidden")
        if method=="POST":
            require(self.posts<LIMITS["generation_posts"] and body["model"]==base.MODEL and body["options"]==base.OPTIONS,"generation_budget_or_identity")
            self.posts+=1
        event={"method":method,"path":path,"body":deepcopy(body),"raw_response":None,"error_type":None}
        self.events.append(event)
        try:
            event["raw_response"]=self.exchange(method,path,body)
            return base._strict_json(event["raw_response"])
        except Exception as error:
            event["error_type"]=type(error).__name__; raise
        finally:
            save(self.output/("transport_%03d.json"%len(self.events)),event)


def schedule(text, pool):
    """Only source candidates route, with common eligibility for paired arms."""
    try:
        route=routing.select_context_mode(text,pool)
        modes=("plain","marked") if route["mode"]=="marked" else ("plain",)
        requests,checks={},{}
        for mode in modes:
            req=batch.build_request(text,pool,mode=mode); checks[mode]=req["preflight"]
            requests[mode]={"model":base.MODEL,"messages":req["messages"],"format":req["schema"],
                "stream":False,"keep_alive":"30m","options":deepcopy(base.OPTIONS)}
        if not all(check["fits"] for check in checks.values()):
            return {"status":"coverage_review","reason":"request_context_budget_exceeded","route":route,"checks":checks,"requests":{}}
        return {"status":"ok","reason":None,"route":route,"checks":checks,"requests":requests}
    except (ValueError,KeyError,TypeError) as error:
        coverage=pool.get("error_kind")=="coverage" or getattr(error,"kind",None)=="coverage"
        return {"status":"coverage_review" if coverage else "engineering_error",
            "reason":str(error),"route":None,"checks":{},"requests":{}}


def observe_pair(text, pool, client, *, reverse=False):
    selected=schedule(text,pool); results={}
    if selected["status"]!="ok":
        response=base.failure_response("input_budget_exceeded" if selected["status"]=="coverage_review" else "invalid_input_or_policy")
        for arm in ARMS:
            results[arm]={"status":selected["status"],"response":deepcopy(response),"raw_response":None,
                "input_mode":None,"physical_generation_calls":0,"shared_from":None}
        return selected,results
    modes=list(selected["requests"])
    if reverse:modes.reverse()
    observed={}
    for mode in modes:
        before=client.posts
        status,response,raw=common.observe(text,pool,mode,selected["requests"][mode],client)
        require(client.posts-before==1,"physical_post_mismatch")
        observed[mode]={"status":status,"response":response,"raw_response":raw,"input_mode":mode,
            "physical_generation_calls":1,"shared_from":None}
    results["plain"]=deepcopy(observed["plain"])
    mode=selected["route"]["mode"]
    results["conditional"]=deepcopy(observed[mode])
    if mode=="plain":results["conditional"].update(physical_generation_calls=0,shared_from="plain")
    return selected,results


def score_rows(rows, reference, texts):
    require(len(texts)==24 and len(rows)==48 and all(type(r.get("cell",{}).get("text_index")) is int for r in rows)
        and {(r["cell"]["text_index"],r["cell"]["profile"],r["cell"]["arm"]) for r in rows}
        == {(i,base.PROFILE,a) for i in range(24) for a in ARMS},"prediction_grid_incomplete")
    refs=scoring._validate_reference(reference,texts); groups={}; scored=[]
    for row in deepcopy(rows):
        i,arm=row["cell"]["text_index"],row["cell"]["arm"]; text=texts[i]; truth=refs[i]["expected"][base.PROFILE]
        predicted=scoring._validate_status(row,text); sent,payload=scoring._validate_preparation(row,text)
        trace=row["redaction_trace"]
        require(trace["response_sha256"]==scoring._hash(row["response"])
            and trace["frozen_preparation_sha256"]==scoring._hash(row["preparation"]),"trace_binding_changed")
        mask=redaction.score_observation(text,trace,truth); require(mask["ready"]==sent,"mask_ready_changed")
        known=truth["decision"]!="needs_review"; gold=scoring._spans(truth["spans"],text,reference=True)
        actual=("sensitive" if predicted else "not_sensitive") if row["status"]=="ok" else row["status"]
        values={"cells":1,"known":int(known),"known_exact":int(known and sent and actual==truth["decision"] and predicted==gold),
            "known_prepared":int(known and sent),"prepared":int(sent),"unknown":int(not known),
            "unknown_review":int(not known and row["status"]=="needs_review"),"unknown_negative":int(not known and actual=="not_sensitive"),
            "tp":len(predicted&gold) if known else 0,"fp":len(predicted-gold) if known else 0,"fn":len(gold-predicted) if known else 0,
            "reference_spans":len(gold),"fully_masked_spans":mask["fully_masked_spans"] or 0,
            "partially_masked_spans":mask["partially_masked_spans"] or 0,
            "prepared_incomplete_spans":((mask["partially_masked_spans"] or 0)+(mask["unmasked_spans"] or 0)) if sent and known else 0,
            "allowed_fact_retained":int(sent and any(refs[i]["allowed_fact"]["text"] in s for s in payload))}
        row["score"]={**values,"mask":mask};scored.append(row)
        group=groups.setdefault(arm,{**{k:0 for k in values},"statuses":{}})
        for key,value in values.items():group[key]+=value
        group["statuses"][row["status"]]=group["statuses"].get(row["status"],0)+1
    for group in groups.values():
        group["precision"]=group["tp"]/(group["tp"]+group["fp"]) if group["tp"]+group["fp"] else None
        group["recall"]=group["tp"]/(group["tp"]+group["fn"]) if group["tp"]+group["fn"] else None
    a,b=groups["plain"],groups["conditional"]
    gate=(b["known_exact"]>=a["known_exact"] and b["known_prepared"]>=a["known_prepared"]
        and (b["known_exact"]>a["known_exact"] or b["known_prepared"]>a["known_prepared"])
        and b["unknown_review"]==b["unknown"] and b["prepared_incomplete_spans"]==0)
    return {"rows":scored,"by_arm":groups,"advance_gate_passed":gate}


def execute(output, expected):
    plan,texts=verify(output,expected)
    save(output/"execution_started.json",{"plan_sha256":expected,"reference_parsed":False})
    client=BoundedClient(output); rows=[]; pools=[]; schedules=[]; captures=[]
    state={"status":"started","reference_parsed":False}; network={"loopback_connects":0,"blocked_connects":0}
    runtime=None; active={"text_index":None}
    def guard(event,args):
        if event=="socket.connect":
            if not isinstance(args[1],tuple) or args[1][:2]!=("127.0.0.1",11435):
                network["blocked_connects"]+=1;raise RuntimeError("external_network_forbidden")
            network["loopback_connects"]+=1
    sys.addaudithook(guard)
    def budget():require(time.monotonic()-client.started<LIMITS["wall_seconds"],"wall_budget_exceeded")
    def capture(event):
        item={"text_index":active["text_index"],"event":deepcopy(event)};captures.append(item)
        save(output/("ner_capture_%02d.json"%len(captures)),item);budget()
    try:
        assets.verify_assets(plan);budget()
        import torch
        torch.set_num_threads(2);torch.manual_seed(42)
        if torch.get_num_interop_threads()!=2:torch.set_num_interop_threads(2)
        ner=LocalNerRuntime(plan["assets_root"],threads=2)
        runtime=base.relation.GlinerOccurrenceRuntime(ner,max_proposals=24,max_classifications=0,on_capture=capture)
        local=base.LocalSensitivityAgent(transport=client)
        save(output/"identities.json",{"qwen":local.health(),"ner":ner.identity})
        for i,text in enumerate(texts):
            budget();verify(output,expected);active["text_index"]=i
            pool=base.relation.propose(text,runtime=runtime);pools.append(pool);save(output/("pool_%02d.json"%i),pool)
            counts=runtime.snapshot_counts()
            require(counts=={"proposal_infer_invocations":i+1,"classification_extract_invocations":0} and len(captures)==i+1,"ner_proposal_accounting")
            selected,pair=observe_pair(text,pool,client,reverse=bool(i%2));schedules.append(selected)
            save(output/("schedule_%02d.json"%i),selected)
            for arm in ARMS:
                row={"cell":{"text_index":i,"profile":base.PROFILE,"arm":arm},"pool_sha256":pool["pool_sha256"],**pair[arm]}
                row["preparation"]=scoring.prepare_observation(text,plan["policy"],row["response"])
                row["redaction_trace"]=redaction.audit_observation(text,plan["policy"],row)
                rows.append(row);save(output/("row_%02d.json"%len(rows)),row)
            print(json.dumps({"texts_completed":i+1,"rows":len(rows),"generation_posts":client.posts}),flush=True)
        require(client.posts==sum(row["physical_generation_calls"] for row in rows)<=48,"physical_generation_accounting")
        local.health();client.closed=True;budget();assets.verify_assets(plan)
        require(network["blocked_connects"]==0,"blocked_network_attempt")
        save(output/"predictions.json",rows);save(output/"pools.json",pools);save(output/"schedules.json",schedules);verify(output,expected)
        files={p.name:sha(p) for pattern in ("transport_*.json","ner_capture_*.json") for p in sorted(output.glob(pattern))}
        closure={"plan_sha256":expected,"reference_parsed":False,"rows":48,"generation_posts":client.posts,
            "ner_counts":runtime.snapshot_counts(),"network":network,"capture_sha256":files,
            "predictions_sha256":sha(output/"predictions.json"),"pools_sha256":sha(output/"pools.json"),"schedules_sha256":sha(output/"schedules.json")}
        save(output/"prediction_phase_closed.json",closure)
        reference=json.loads((output/"evaluation.opaque.json").read_text(encoding="utf-8"));state["reference_parsed"]=True
        results=score_rows(rows,reference,texts);save(output/"scored_rows.json",results["rows"]);verify(output,expected)
        for name,key in (("predictions.json","predictions_sha256"),("pools.json","pools_sha256"),("schedules.json","schedules_sha256")):
            require(sha(output/name)==closure[key],"closed_predictions_changed")
        require(all(sha(output/name)==digest for name,digest in files.items()),"closed_captures_changed")
        posts=[event for event in client.events if event["method"]=="POST"]
        decoded=[base._strict_json(event["raw_response"]) for event in posts]
        report={"version":VERSION,"status":"complete","by_arm":results["by_arm"],"advance_gate_passed":results["advance_gate_passed"],
            "rows":48,"unique_synthetic_texts":24,"generation_posts":client.posts,"ner_counts":runtime.snapshot_counts(),
            "shared_plain_rows":sum(row["shared_from"]=="plain" for row in rows),
            "route_marked_documents":sum(s["status"]=="ok" and s["route"]["mode"]=="marked" for s in schedules),
            "physical_prompt_tokens":sum(raw["prompt_eval_count"] for raw in decoded),"physical_output_tokens":sum(raw["eval_count"] for raw in decoded),
            "cloud_calls":0,"native_writes":0,"repairs":0,"network":network,"plan_sha256":expected,
            "closure_sha256":sha(output/"prediction_phase_closed.json"),"scope":plan["scope"]}
        save(output/"report.json",report);state["status"]="complete";return report
    except Exception as error:
        state.update(status="stopped",error_type=type(error).__name__,error=str(error));raise
    finally:
        state.update(rows=len(rows),generation_posts=client.posts,ner_counts=runtime.snapshot_counts() if runtime else None,
                     network=network,wall_seconds=time.monotonic()-client.started)
        save(output/"execution_final.json",state)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--materials",type=Path);parser.add_argument("--expected-plan-sha")
    mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument("--plan-only",action="store_true");mode.add_argument("--execute",action="store_true")
    args=parser.parse_args();output=args.output.resolve()
    require(not args.plan_only or args.materials is not None,"materials_required")
    result=freeze(output,args.materials.resolve()) if args.plan_only else execute(output,args.expected_plan_sha)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":main()
