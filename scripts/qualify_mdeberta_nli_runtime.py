"""Pinned offline NLI runtime qualification, never a privacy effectiveness test.

Plan/host code is stdlib-only. ML imports occur solely in the explicit worker.
The worker receives three fixed public text pairs, never their expected labels.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
import email.parser
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import traceback


ROOT = Path(__file__).resolve().parents[1]
VERSION = "mdeberta_nli_runtime_qualification_v1"
MODEL_ID = "MoritzLaurer/mDeBERTa-v3-base-mnli-xnli"
REVISION = "8adb042d524ecd5c26d3e3ba0e3fbcf7e2d0864c"
MANIFEST = "configs/mdeberta_nli_assets_v1.json"
ASSETS = ".runtime/mdeberta_nli/"+REVISION
PYTHON = ".venv-native-webui/Scripts/python.exe"
COMMON = "scripts/native_exact_fact_common.py"
SELF = "scripts/qualify_mdeberta_nli_runtime.py"
LABELS = {"entailment": 0, "neutral": 1, "contradiction": 2}
FILES = (
    ("config.json",1066,"4e4430c95100d613df80fa01276f231931e1b535557cf62fbb3cc50323e50cca"),
    ("tokenizer_config.json",1256,"df9fd3a4482cc4a866788244824573fab8e74dadd1609d4f0e5997f9e96921dc"),
    ("special_tokens_map.json",286,"9463f61e1b109a8eb4688b829260d7c6b1e6dff04c98ff7269bb89e2b92369b9"),
    ("added_tokens.json",23,"fb697283833d25e2c711f1bc37730ecd8b20f4bd5f015db1d84aefe0adc9155a"),
    ("spm.model",4305025,"13c8d666d62a7bc4ac8f040aab68e942c861f93303156cc28f5c7e885d86d6e3"),
    ("tokenizer.json",16331396,"3aca3ce69a0a35aeb144a52c4f1d41c4246b8785f8f398315cc8fb6b24057810"),
    ("model.safetensors",557652046,"65af59b1ff4450b09ecbf13ca35c840dbf038b26ff8e10e5ea89ca724828ed1e"),
    ("README.md",6514,"c6cc8ca44d55e6ff3dd75672c8fcc41c22ca18b551aa52fb5d611d720a5f966b"),
)
PAIRS = (
    {"pair_id":"P1","premise":"A person is reading a book.","hypothesis":"Someone is reading."},
    {"pair_id":"P2","premise":"这扇门是打开的。","hypothesis":"这扇门没有打开。"},
    {"pair_id":"P3","premise":"A person is reading a book.","hypothesis":"The person is a doctor."},
)
RUNTIME = {"device":"cpu","dtype":"float32","threads":2,"interop_threads":2,"batch_size":1,
    "max_positions":512,"max_top_classifier_forwards":3,"truncation":False,"eval":True,
    "inference_mode":True,"local_files_only":True,"trust_remote_code":False,"token":False,
    "device_map":None,"use_safetensors":True,"generation_cap":0,"cloud_cap":0,"timeout_seconds":180}
DISTRIBUTIONS = ("torch","transformers","tokenizers","safetensors","sentencepiece","protobuf","numpy")
RUNTIME_SOURCES = ("transformers/models/deberta_v2/modeling_deberta_v2.py",
                   "transformers/models/deberta_v2/configuration_deberta_v2.py",
                   "transformers/models/auto/modeling_auto.py", "transformers/models/auto/tokenization_auto.py")


def require(value, code):
    if not value:
        raise ValueError(code)


def encoded(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+"\n").encode("utf-8")


def loads(raw):
    def pairs(items):
        obj={}
        for key,value in items:
            require(key not in obj,"duplicate_json_key");obj[key]=value
        return obj
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):digest.update(block)
    return digest.hexdigest()


def scoped(path, parent):
    p=Path(path).absolute();base=Path(parent).absolute()
    require(p.is_relative_to(base) and p.resolve(strict=False)==p and not p.is_symlink(),"path_scope_or_link_invalid")
    return p


def save(path,value):
    with Path(path).open("xb") as stream:stream.write(encoded(value))


def runtime_metadata():
    site=ROOT/".venv-native-webui/Lib/site-packages"
    found={}
    for path in site.glob("*.dist-info/METADATA"):
        msg=email.parser.BytesParser().parsebytes(path.read_bytes(),headersonly=True)
        name=msg.get("Name","").lower().replace("_","-")
        if name in DISTRIBUTIONS:
            require(name not in found,"duplicate_distribution")
            found[name]={"version":msg["Version"],"metadata_file":path.relative_to(ROOT).as_posix(),"sha256":sha(path)}
    require(set(found)==set(DISTRIBUTIONS),"runtime_distribution_missing")
    return found


def build_plan(output):
    output=scoped(output,ROOT/"results")
    manifest_path=scoped(ROOT/MANIFEST,ROOT)
    manifest=loads(manifest_path.read_bytes())
    expected=[{"name":n,"size":s,"sha256":h} for n,s,h in FILES]
    require(manifest["model_id"]==MODEL_ID and manifest["revision"]==REVISION
        and manifest["files"]==expected and manifest["declared_label2id"]==LABELS
        and manifest["declared_max_positions"]==512,"fixed_asset_manifest_mismatch")
    require(manifest["total_bytes_including_model_card"]==sum(s for _,s,_ in FILES),"fixed_asset_total_mismatch")
    for row in expected:
        path=scoped(ROOT/ASSETS/row["name"],ROOT/ASSETS)
        require(path.is_file() and path.stat().st_size==row["size"] and sha(path)==row["sha256"],"asset_integrity_failed")
    config=loads((ROOT/ASSETS/"config.json").read_bytes())
    require(config["label2id"]==LABELS and config["id2label"]=={str(v):k for k,v in LABELS.items()}
        and config["architectures"]==["DebertaV2ForSequenceClassification"] and config["max_position_embeddings"]==512,
        "classifier_config_mismatch")
    python=scoped(ROOT/PYTHON,ROOT/".venv-native-webui")
    source_paths=[SELF,COMMON,MANIFEST,".venv-native-webui/pyvenv.cfg",PYTHON]
    source_paths.extend(".venv-native-webui/Lib/site-packages/"+name for name in RUNTIME_SOURCES)
    frozen={name:sha(scoped(ROOT/name,ROOT)) for name in source_paths}
    return {"schema":VERSION,"model_id":MODEL_ID,"revision":REVISION,"assets":expected,
        "asset_root":ASSETS,"asset_manifest":MANIFEST,"runtime":deepcopy(RUNTIME),
        "runtime_distributions":runtime_metadata(),"implementation_sha256":frozen,
        "python":PYTHON,"output":output.relative_to(ROOT).as_posix(),"pairs":deepcopy(list(PAIRS)),
        "scope":"Three fixed public pairs, runtime only, no privacy or paper acceptance, defaults unchanged."}


def plan_only(output):
    plan=build_plan(output);destination=ROOT/plan["output"]
    require(not destination.exists(),"new_output_directory_required")
    destination.mkdir(parents=True)
    for name in (SELF,COMMON,MANIFEST):
        target=destination/"frozen_source"/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as stream:stream.write((ROOT/name).read_bytes())
    save(destination/"plan.json",plan)
    return plan


def approved_plan(path):
    path=scoped(path,ROOT/"results");raw=path.read_bytes();plan=loads(raw)
    require(path==ROOT/plan["output"]/"plan.json","approved_plan_location_mismatch")
    require(raw==encoded(build_plan(ROOT/plan["output"])),"approved_plan_or_runtime_changed")
    for name in (SELF,COMMON,MANIFEST):
        require(sha(path.parent/"frozen_source"/name)==plan["implementation_sha256"][name],"source_snapshot_changed")
    return plan,hashlib.sha256(raw).hexdigest()


def child_environment(home):
    # Only selected OS values are read. In particular, never inspect HF tokens,
    # API keys, inherited user cache/profile values or any native auth store.
    keep=("SYSTEMROOT","WINDIR","COMSPEC","PATH","PATHEXT","TEMP","TMP","NUMBER_OF_PROCESSORS","PROCESSOR_ARCHITECTURE")
    env={k:os.environ[k] for k in keep if k in os.environ}
    home=str(home)
    env.update({k:home for k in ("TEMP","TMP","HOME","USERPROFILE","APPDATA","LOCALAPPDATA","XDG_CACHE_HOME","HF_HOME",
        "HUGGINGFACE_HUB_CACHE","TRANSFORMERS_CACHE")})
    env.update({"HF_TOKEN_PATH":str(Path(home)/"unused_token"),"HF_HUB_OFFLINE":"1","TRANSFORMERS_OFFLINE":"1",
        "HF_HUB_DISABLE_TELEMETRY":"1","HF_HUB_DISABLE_IMPLICIT_TOKEN":"1","PYTHON_DOTENV_DISABLED":"1",
        "PYTHONNOUSERSITE":"1","PYTHONDONTWRITEBYTECODE":"1","DO_NOT_TRACK":"1","USE_TF":"0","USE_FLAX":"0",
        "TOKENIZERS_PARALLELISM":"false","OMP_NUM_THREADS":"2","MKL_NUM_THREADS":"2","CUDA_VISIBLE_DEVICES":""})
    return env


def worker_job(plan,plan_hash):
    return {"schema":VERSION+"_worker","plan_sha256":plan_hash,"plan":deepcopy(plan)}


class ForwardBudget:
    """Wrap the actual top-level classifier method before model loading."""
    def __init__(self,klass):
        self.klass=klass;self.model=None;self.phase="loading";self.attempts=0;self.actual=0;self.blocked=0
    def __enter__(self):
        self.original=self.klass.forward;budget=self
        def forward(model,*args,**kwargs):
            budget.attempts+=1
            if budget.phase!="inference" or model is not budget.model or budget.actual>=3:
                budget.blocked+=1;raise RuntimeError("classifier_forward_cap_or_stage_violation")
            budget.actual+=1
            return budget.original(model,*args,**kwargs)
        self.klass.forward=forward
        return self
    def __exit__(self,*_):self.klass.forward=self.original
    def accounting(self):
        return {"top_classifier_entry_attempts":self.attempts,"actual_top_classifier_forwards":self.actual,
                "blocked_forward_entries":self.blocked}


def run_pairs(tokenize,forward,start_inference):
    """Tokenize all pairs in full before allowing any forward; pure fake seam."""
    prepared=[]
    for pair in PAIRS:
        tokens=tokenize(pair["premise"],pair["hypothesis"])
        require(isinstance(tokens,dict) and set(tokens)<={"input_ids","attention_mask","token_type_ids"}
            and {"input_ids","attention_mask"}<=set(tokens),"tokenizer_output_invalid")
        n=len(tokens["input_ids"])
        require(0<n<=512,"full_pair_token_budget_exceeded")
        require(all(isinstance(v,list) and len(v)==n and all(type(x) is int for x in v) for v in tokens.values()),"tokenizer_shape_invalid")
        require(all(x>=0 for x in tokens["input_ids"]),"token_id_invalid")
        prepared.append((pair,tokens))
    start_inference()
    rows=[]
    for pair,tokens in prepared:
        output=forward(tokens)
        require(isinstance(output,dict) and set(output)=={"logits","shape","dtype","device"},"logit_fields_invalid")
        logits=output["logits"]
        require(output["shape"]==[1,3] and output["dtype"]=="float32" and output["device"]=="cpu"
            and isinstance(logits,list) and len(logits)==3
            and all(type(x) in (int,float) and math.isfinite(x) for x in logits),"logit_contract_invalid")
        index=max(range(3),key=lambda i:logits[i])
        rows.append({"pair_id":pair["pair_id"],"pair_sha256":hashlib.sha256(encoded(pair)).hexdigest(),
            "input_token_count":len(tokens["input_ids"]),"encoded_inputs":tokens,"encoded_input_sha256":hashlib.sha256(encoded(tokens)).hexdigest(),
            **output,"predicted_id":index,"predicted_label":next(k for k,v in LABELS.items() if v==index)})
    return rows


def load_common():
    spec=importlib.util.spec_from_file_location("nli_qualification_common",ROOT/COMMON)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class WorkerGuard:
    """Python audit guard, not an OS sandbox against hostile native code."""
    def __init__(self,common,job_path,output):
        self.network=common.NetworkGuard();self.denied=[]
        self.read_files={(ROOT/SELF).resolve(),(ROOT/COMMON).resolve(),(ROOT/MANIFEST).resolve(),job_path.resolve()}
        self.read_files.update((ROOT/ASSETS/n).resolve() for n,_,_ in FILES)
        self.read_files.add((output/"plan.json").resolve())
        self.read_files.update((output/"frozen_source"/n).resolve() for n in (SELF,COMMON,MANIFEST))
        self.read_roots=[Path(sys.prefix).resolve(),Path(sys.base_prefix,"Lib").resolve(),Path(sys.base_prefix,"DLLs").resolve()]
        self.write_root=(output/"child_home").resolve();self.output=output.resolve()
    def __call__(self,event,args):
        if event in {"subprocess.Popen","os.system","os.exec","os.posix_spawn"}:
            self.denied.append({"event":event,"code":"worker_process_forbidden"});raise PermissionError("worker_process_forbidden")
        if event=="open" and args and isinstance(args[0],(str,bytes,os.PathLike)):
            path=Path(os.fsdecode(args[0])).resolve(strict=False)
            if path.name.casefold() in {".env",".netrc","_netrc","token","tokens.json","stored_tokens","credentials","auth.json",".webui_secret_key"}:
                self.denied.append({"event":"open","code":"credential_file_forbidden"});raise PermissionError("credential_file_forbidden")
            mode=args[1] if len(args)>1 else None;flags=args[2] if len(args)>2 else 0
            write=(isinstance(mode,str) and any(c in mode for c in "wax+")) or (isinstance(flags,int) and bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)))
            if write:
                allowed=path.is_relative_to(self.write_root) or path in {self.output/"worker_predictions.json"}
            else:
                allowed=path in self.read_files or any(path.is_relative_to(p) for p in self.read_roots) or path.is_relative_to(self.write_root)
            if not allowed:
                self.denied.append({"event":"open","code":"worker_file_scope_forbidden"});raise PermissionError("worker_file_scope_forbidden")
        self.network(event,args)
    def accounting(self):
        blocked=[e for e in self.network.events if e.get("allowed") is False]
        return {"blocked_attempts":len(blocked)+len(self.denied),"scope_denials":deepcopy(self.denied),
            "network_denials":len(blocked),"application_network_requests":0,
            "internal_socket_events":[{k:e[k] for k in ("event","allowed","kind") if k in e} for e in self.network.events if e.get("allowed") is True],
            "scope":"Python audit hooks and offline flags, not an OS sandbox."}


def worker(path):
    path=scoped(path,ROOT/"results");job=loads(path.read_bytes());plan=job.get("plan",{})
    output=scoped(ROOT/plan["output"],ROOT/"results")
    require(path==output/"worker_job.json" and set(job)=={"schema","plan_sha256","plan"}
        and job["schema"]==VERSION+"_worker" and plan.get("pairs")==list(PAIRS),"worker_job_invalid")
    actual,plan_hash=approved_plan(output/"plan.json")
    require(encoded(actual)==encoded(plan) and job["plan_sha256"]==plan_hash,"worker_plan_binding_failed")
    home=output/"child_home";home.mkdir(exist_ok=False)
    env=child_environment(home);os.environ.clear();os.environ.update(env);sys.dont_write_bytecode=True
    common=load_common();guard=WorkerGuard(common,path,output);sys.addaudithook(guard)
    result={"schema":VERSION+"_worker_predictions","plan_sha256":plan_hash,"status":"error","rows":[],
        "runtime_qualified":False,"stage":"imports","model_loads":0,"generation_calls":0,"cloud_calls":0,
        "top_classifier_entry_attempts":0,"actual_top_classifier_forwards":0,"blocked_forward_entries":0}
    budget=None;discard=io.StringIO()
    try:
        with redirect_stdout(discard),redirect_stderr(discard):
            import torch
            import transformers
            from transformers import AutoModelForSequenceClassification, AutoTokenizer, DebertaV2ForSequenceClassification
            torch.set_num_threads(2);torch.set_num_interop_threads(2)
            result["runtime_versions"]={"torch":str(torch.__version__),"transformers":transformers.__version__,"python":sys.version.split()[0]}
            result["stage"]="tokenizer_load"
            directory=str(ROOT/ASSETS)
            tokenizer=AutoTokenizer.from_pretrained(directory,local_files_only=True,trust_remote_code=False,token=False)
            with ForwardBudget(DebertaV2ForSequenceClassification) as budget:
                result["stage"]="model_load"
                model=AutoModelForSequenceClassification.from_pretrained(directory,local_files_only=True,
                    trust_remote_code=False,token=False,use_safetensors=True,dtype=torch.float32,device_map=None,attn_implementation="eager")
                result["model_loads"]=1
                require(type(model) is DebertaV2ForSequenceClassification,"classifier_type_mismatch")
                model.to(device=torch.device("cpu"),dtype=torch.float32);model.eval()
                require(model.config.label2id==LABELS and model.config.id2label=={v:k for k,v in LABELS.items()}
                    and model.config.max_position_embeddings==512,"loaded_config_mismatch")
                require(all(p.device.type=="cpu" and (not p.is_floating_point() or p.dtype==torch.float32) for p in model.parameters()),"model_device_dtype_mismatch")
                require(not model.training and torch.get_num_threads()==2 and torch.get_num_interop_threads()==2,"runtime_mode_mismatch")
                result["model_metadata"]={"class":type(model).__name__,"device":"cpu","floating_dtype":"float32",
                    "eval":not model.training,"threads":torch.get_num_threads(),"interop_threads":torch.get_num_interop_threads()}
                budget.model=model;budget.phase="tokenizing";result["stage"]="full_pair_preflight"
                def tokenize(premise,hypothesis):
                    return dict(tokenizer(premise,hypothesis,add_special_tokens=True,padding=False,truncation=False,return_attention_mask=True))
                def start():budget.phase="inference";result["stage"]="three_public_forwards"
                def forward(tokens):
                    inputs={k:torch.tensor([v],device="cpu",dtype=torch.long) for k,v in tokens.items()}
                    with torch.inference_mode():logits=model(**inputs).logits
                    return {"logits":logits.detach().cpu().tolist()[0],"shape":list(logits.shape),
                        "dtype":str(logits.dtype).removeprefix("torch."),"device":logits.device.type}
                result["rows"]=run_pairs(tokenize,forward,start)
            require(budget.actual==3 and budget.attempts==3 and budget.blocked==0,"forward_accounting_failed")
            require(guard.accounting()["blocked_attempts"]==0,"guard_attempts_observed")
            result.update(status="runtime_qualified",runtime_qualified=True,stage="complete")
    except Exception as error:
        result.update(error_type=type(error).__name__,error_code="offline_runtime_qualification_failed",
            error_frames=[{"file":Path(f.filename).name,"line":f.lineno,"function":f.name} for f in traceback.extract_tb(error.__traceback__)[-4:]])
    if budget is not None:result.update(budget.accounting())
    result["guard"]=guard.accounting();result["suppressed_diagnostic_characters"]=discard.tell()
    result["method_acceptance"]=False
    save(output/"worker_predictions.json",result)
    print(json.dumps({"status":result["status"],"actual_top_classifier_forwards":result["actual_top_classifier_forwards"]}))
    return 0 if result["runtime_qualified"] else 1


def score_closed(output,closed):
    """Host-only: decode predictions and access expected labels after closure."""
    phase=output/"prediction_phase_closed.json"
    require(phase.is_file() and phase.read_bytes()==encoded(closed),"prediction_phase_not_sealed")
    require(closed.get("closed") is True and sha(output/"worker_predictions.json")==closed["prediction_sha256"],"predictions_not_closed")
    raw=loads((output/"worker_predictions.json").read_bytes())
    require(raw.get("plan_sha256")==closed["plan_sha256"],"prediction_plan_binding_failed")
    if raw.get("runtime_qualified") is True:
        require(raw.get("status")=="runtime_qualified" and raw.get("model_loads")==1
            and raw.get("actual_top_classifier_forwards")==raw.get("top_classifier_entry_attempts")==3
            and raw.get("blocked_forward_entries")==raw.get("generation_calls")==raw.get("cloud_calls")==0
            and raw.get("guard",{}).get("blocked_attempts")==0 and len(raw.get("rows",[]))==3,
            "runtime_receipt_contract_failed")
        for row,pair in zip(raw["rows"],PAIRS):
            tokens=row["encoded_inputs"];logits=row["logits"]
            require(row["pair_id"]==pair["pair_id"] and row["pair_sha256"]==hashlib.sha256(encoded(pair)).hexdigest()
                and row["encoded_input_sha256"]==hashlib.sha256(encoded(tokens)).hexdigest()
                and 0<row["input_token_count"]==len(tokens["input_ids"])<=512
                and row["shape"]==[1,3] and all(type(x) is int for x in row["shape"])
                and row["dtype"]=="float32" and row["device"]=="cpu" and len(logits)==3
                and all(type(x) in (int,float) and math.isfinite(x) for x in logits)
                and row["predicted_id"]==max(range(3),key=lambda i:logits[i])
                and row["predicted_label"]==next(k for k,v in LABELS.items() if v==row["predicted_id"]),
                "runtime_prediction_shape_or_binding_failed")
    expected=("entailment","contradiction","neutral")
    rows=raw.get("rows",[])
    smoke=[]
    if len(rows)==3:
        for row,pair,label in zip(rows,PAIRS,expected):
            require(row["pair_id"]==pair["pair_id"],"prediction_pair_mismatch")
            smoke.append({"pair_id":pair["pair_id"],"predicted":row["predicted_label"],"expected":label,"correct":row["predicted_label"]==label})
    return {"schema":VERSION+"_report","runtime_qualified":raw.get("runtime_qualified") is True,
        "worker_status":raw.get("status"),"actual_top_classifier_forwards":raw.get("actual_top_classifier_forwards"),
        "smoke_rows":smoke,"smoke_correct":sum(r["correct"] for r in smoke) if smoke else None,
        "smoke_denominator":3,"generation_calls":raw.get("generation_calls"),"cloud_calls":raw.get("cloud_calls"),
        "native_operations":0,"default_changed":False,"method_acceptance":False,
        "scope":"Runtime qualification and public semantic smoke are separate; no privacy P/R or paper acceptance."}


def execute(path):
    plan,plan_hash=approved_plan(path);output=ROOT/plan["output"]
    for name in ("worker_job.json","worker_predictions.json","prediction_phase_closed.json","report.json","process_receipt.json"):
        require(not (output/name).exists(),"execution_already_started_no_automatic_retry")
    save(output/"worker_job.json",worker_job(plan,plan_hash))
    command=[str(ROOT/PYTHON),"-I","-B",str(ROOT/SELF),"--worker-job",str(output/"worker_job.json")]
    process=subprocess.Popen(command,cwd=ROOT,env=child_environment(output/"child_home"),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        stdout,stderr=process.communicate(timeout=RUNTIME["timeout_seconds"])
    except subprocess.TimeoutExpired:
        process.kill();stdout,stderr=process.communicate()
    save(output/"process_receipt.json",{"returncode":process.returncode,"stdout_bytes":len(stdout),"stderr_bytes":len(stderr),
        "stdout_sha256":hashlib.sha256(stdout).hexdigest(),"stderr_sha256":hashlib.sha256(stderr).hexdigest(),"raw_output_not_persisted":True})
    predictions=output/"worker_predictions.json"
    closed={"closed":predictions.is_file(),"prediction_sha256":sha(predictions) if predictions.is_file() else None,
            "plan_sha256":plan_hash,"returncode":process.returncode}
    save(output/"prediction_phase_closed.json",closed)
    if closed["closed"]:
        report=score_closed(output,closed)
    else:
        report={"schema":VERSION+"_report","runtime_qualified":False,"worker_status":"worker_failed_before_predictions",
                "actual_top_classifier_forwards":None,"smoke_rows":[],"smoke_correct":None,"smoke_denominator":3,
                "default_changed":False,"method_acceptance":False,"native_operations":0}
    report["source_assets_runtime_unchanged"]=encoded(build_plan(output))==encoded(plan)
    report["runtime_qualified"]=report["runtime_qualified"] and process.returncode==0 and report["source_assets_runtime_unchanged"]
    save(output/"report.json",report)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only",action="store_true");mode.add_argument("--execute",action="store_true")
    mode.add_argument("--worker-job",type=Path,help=argparse.SUPPRESS)
    parser.add_argument("--output",type=Path);parser.add_argument("--approved-plan",type=Path)
    args=parser.parse_args()
    if args.worker_job:
        require(args.output is None and args.approved_plan is None,"worker_cli_invalid")
        return worker(args.worker_job)
    if args.plan_only:
        require(args.output is not None and args.approved_plan is None,"plan_cli_invalid")
        plan=plan_only(args.output)
        print(json.dumps({"status":"plan_only_zero_load_forward","plan":plan["output"]+"/plan.json","pairs":3}))
        return 0
    require(args.approved_plan is not None and args.output is None,"execute_cli_invalid")
    result=execute(args.approved_plan)
    print(json.dumps({"runtime_qualified":result["runtime_qualified"],"actual_top_classifier_forwards":result["actual_top_classifier_forwards"],"smoke_correct":result["smoke_correct"]}))
    return 0 if result["runtime_qualified"] else 1


if __name__=="__main__":
    try:raise SystemExit(main())
    except (OSError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({"status":"qualification_failed","error_type":type(error).__name__,"code":"plan_or_worker_protocol_failed"}))
        raise SystemExit(1) from None
