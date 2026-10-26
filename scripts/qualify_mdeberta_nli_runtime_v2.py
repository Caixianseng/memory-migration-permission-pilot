"""Thin v2 qualification: exact stdlib ZIP probes and verified loading metadata.

The frozen v1 supplies the three public pairs, forward budget and closed scoring.
No ML imports occur in this host wrapper or its plan-only path.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
SELF=Path(__file__).resolve()
BASE="scripts/qualify_mdeberta_nli_runtime.py"
BASE_SHA="37bb3e61bd70bd681a13fb0a74b6d5ca48e50bafcc3d0524c446bebe8f4963a1"
VERSION="mdeberta_nli_runtime_qualification_v2"
BUFFER_KEY="deberta.embeddings.position_ids"
IDENTITY_CODE='''import hashlib,json,pathlib,sys
p=pathlib.Path(sys.base_prefix)/("python%d%d.zip"%sys.version_info[:2])
paths=[pathlib.Path(x).resolve() for x in sys.path if x]
exists=p.is_file()
print(json.dumps({"executable":str(pathlib.Path(sys.executable).resolve()),"version":sys.version.split()[0],"base_prefix":str(pathlib.Path(sys.base_prefix).resolve()),"major_minor":list(sys.version_info[:2]),"stdlib_zip":str(p.resolve()),"zip_in_sys_path":p.resolve() in paths,"zip_exists":exists,"zip_size":p.stat().st_size if exists else None,"zip_sha256":hashlib.sha256(p.read_bytes()).hexdigest() if exists else None}))
'''


def require(condition,code):
    if not condition:raise ValueError(code)


def validate_identity(identity,python_path):
    require(set(identity)=={"executable","version","base_prefix","major_minor","stdlib_zip","zip_in_sys_path","zip_exists","zip_size","zip_sha256"},"python_identity_fields_invalid")
    require(Path(identity["executable"]).resolve()==Path(python_path).resolve(),"fixed_interpreter_mismatch")
    major,minor=identity["major_minor"]
    expected=Path(identity["base_prefix"])/f"python{major}{minor}.zip"
    require(major==3 and minor==12 and identity["version"].startswith("3.12.")
        and identity["zip_in_sys_path"] is True and Path(identity["stdlib_zip"]).resolve()==expected.resolve(),"stdlib_zip_identity_invalid")
    require(type(identity["zip_exists"]) is bool and ((identity["zip_exists"] and type(identity["zip_size"]) is int
        and isinstance(identity["zip_sha256"],str) and len(identity["zip_sha256"])==64)
        or (not identity["zip_exists"] and identity["zip_size"] is None and identity["zip_sha256"] is None)),"stdlib_zip_integrity_invalid")
    return identity


def python_identity(q,output):
    target=ROOT/q.PYTHON
    if Path(sys.executable).resolve()==target.resolve():
        archive=Path(sys.base_prefix)/f"python{sys.version_info.major}{sys.version_info.minor}.zip"
        exists=archive.is_file()
        identity={"executable":str(Path(sys.executable).resolve()),"version":sys.version.split()[0],
            "base_prefix":str(Path(sys.base_prefix).resolve()),"major_minor":list(sys.version_info[:2]),
            "stdlib_zip":str(archive.resolve()),"zip_in_sys_path":archive.resolve() in [Path(x).resolve() for x in sys.path if x],
            "zip_exists":exists,"zip_size":archive.stat().st_size if exists else None,"zip_sha256":q.sha(archive) if exists else None}
    else:
        process=subprocess.run([str(target),"-I","-B","-c",IDENTITY_CODE],cwd=ROOT,
            env=q.child_environment(output/"child_home"),capture_output=True,timeout=30)
        require(process.returncode==0,"interpreter_metadata_failed")
        identity=q.loads(process.stdout)
    return validate_identity(identity,target)


def validate_loading(model,info):
    require(isinstance(info,dict),"loading_info_invalid")
    for name in ("missing_keys","unexpected_keys","mismatched_keys","error_msgs"):
        require(isinstance(info.get(name),list),"loading_info_fields_invalid")
    require(not info["missing_keys"] and not info["mismatched_keys"] and not info["error_msgs"],"weight_loading_incomplete")
    unexpected=info["unexpected_keys"]
    require(all(isinstance(k,str) for k in unexpected) and len(unexpected)==len(set(unexpected))
        and set(unexpected)<={BUFFER_KEY},"unexpected_weight_key")
    config=model.config;emb=model.deberta.embeddings;buffer=emb.position_ids
    require(config.position_biased_input is False and config.max_position_embeddings==512
        and emb.position_biased_input is False and emb.position_embeddings is None,"position_buffer_config_invalid")
    require("position_ids" in emb._non_persistent_buffers_set and emb._buffers.get("position_ids") is buffer
        and BUFFER_KEY not in model.state_dict(),"position_buffer_persistence_invalid")
    require(list(buffer.shape)==[1,512] and str(buffer.dtype)=="torch.int64" and buffer.device.type=="cpu"
        and buffer.requires_grad is False and buffer.tolist()==[list(range(512))],"position_buffer_content_invalid")
    return {"accepted":True,"missing_keys":[],"mismatched_keys":[],"error_msgs_count":0,
        "unexpected_keys":list(unexpected),"verified_nonpersistent_buffer":{"key":BUFFER_KEY,"shape":[1,512],
        "dtype":"int64","device":"cpu","values":"arange(512)","persistent":False,"position_biased_input":False},
        "additional_loading_info_fields":sorted(set(info)-{"missing_keys","unexpected_keys","mismatched_keys","error_msgs"})}


def install(q,trace):
    old_build=q.build_plan;old_plan=q.plan_only;old_approved=q.approved_plan;old_save=q.save;old_score=q.score_closed
    q.VERSION=VERSION;q.SELF=SELF.relative_to(ROOT).as_posix()
    def build(output):
        require(q.sha(ROOT/BASE)==BASE_SHA,"frozen_v1_changed")
        plan=old_build(output);identity=python_identity(q,output);trace["python_identity"]=identity
        plan["implementation_sha256"][BASE]=BASE_SHA
        plan["python_identity"]=identity
        plan["v2_loading_contract"]={"output_loading_info":True,"missing_keys":[],"mismatched_keys":[],"error_msgs":[],
            "only_optional_unexpected_key":BUFFER_KEY,"buffer_persistent":False,"buffer_values":"arange(512)","position_biased_input":False}
        return plan
    def plan_only(output):
        plan=old_plan(output);target=ROOT/plan["output"]/"frozen_source"/BASE;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((ROOT/BASE).read_bytes());return plan
    def approved(path):
        result=old_approved(path);require(q.sha(Path(path).parent/"frozen_source"/BASE)==BASE_SHA,"frozen_v1_snapshot_changed");return result
    def save(path,value):
        if isinstance(value,dict) and value.get("schema")==VERSION+"_worker_predictions":
            value={**value,"qualification_v2":deepcopy(trace)}
        old_save(path,value)
    def score(output,closed):
        report=old_score(output,closed);raw=q.loads((output/"worker_predictions.json").read_bytes());detail=raw.get("qualification_v2",{})
        if raw.get("runtime_qualified") is True:require(detail.get("weight_loading",{}).get("accepted") is True,"v2_loading_not_verified")
        report["qualification_v2"]=detail;return report
    class Guard(q.WorkerGuard):
        def __init__(self,common,job_path,output):
            super().__init__(common,job_path,output)
            self.read_files.update({(ROOT/BASE).resolve(),(output/"frozen_source"/BASE).resolve()})
            self.zip=Path(trace["python_identity"]["stdlib_zip"]).resolve();self.probes=[]
        def __call__(self,event,args):
            if event=="open" and args and isinstance(args[0],(str,bytes,os.PathLike)):
                mode=args[1] if len(args)>1 else None;flags=args[2] if len(args)>2 else 0
                write=(isinstance(mode,str) and any(c in mode for c in "wax+")) or (isinstance(flags,int) and bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)))
                if not write and Path(os.fsdecode(args[0])).resolve(strict=False)==self.zip:
                    self.probes.append({"event":"open","path":str(self.zip),"mode":mode,"flags":flags,"read_only":True})
                    self.network(event,args);return
            return super().__call__(event,args)
        def accounting(self):
            return {**super().accounting(),"stdlib_zip_read_only_probes":deepcopy(self.probes)}
    class Budget(q.ForwardBudget):
        def __enter__(self):
            super().__enter__();self.auto=sys.modules["transformers"].AutoModelForSequenceClassification
            self.local="from_pretrained" in self.auto.__dict__;self.descriptor=self.auto.__dict__.get("from_pretrained");original=self.auto.from_pretrained
            def load(cls,*args,**kwargs):
                kwargs=dict(kwargs);kwargs["output_loading_info"]=True;model,info=original(*args,**kwargs)
                trace["weight_loading"]={"accepted":False,"loading_info_received":isinstance(info,dict)}
                if isinstance(info,dict):
                    for name in ("missing_keys","unexpected_keys","mismatched_keys"):
                        values=info.get(name,[])
                        trace["weight_loading"][name]=[x if isinstance(x,str) else x[0] for x in values] if isinstance(values,list) else None
                    trace["weight_loading"]["error_msgs_count"]=len(info["error_msgs"]) if isinstance(info.get("error_msgs"),list) else None
                try:trace["weight_loading"]=validate_loading(model,info)
                except ValueError as error:
                    trace["weight_loading"]["validation_error"]=str(error);raise
                return model
            self.auto.from_pretrained=classmethod(load);return self
        def __exit__(self,*args):
            if self.local:self.auto.from_pretrained=self.descriptor
            else:delattr(self.auto,"from_pretrained")
            return super().__exit__(*args)
    q.build_plan=build;q.plan_only=plan_only;q.approved_plan=approved;q.save=save;q.score_closed=score
    q.WorkerGuard=Guard;q.ForwardBudget=Budget
    return q


def load_qualifier():
    require(hashlib.sha256((ROOT/BASE).read_bytes()).hexdigest()==BASE_SHA,"frozen_v1_changed")
    spec=importlib.util.spec_from_file_location("frozen_nli_v1_for_v2",ROOT/BASE)
    q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
    return install(q,{"schema":VERSION,"weight_loading":None})


if __name__=="__main__":
    try:raise SystemExit(load_qualifier().main())
    except (OSError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({"status":"qualification_failed","error_type":type(error).__name__,"code":"v2_plan_or_worker_protocol_failed"}))
        raise SystemExit(1) from None
