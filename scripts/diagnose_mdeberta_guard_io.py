"""Thin diagnostic of the frozen qualifier; zero classifier forward, no repair."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
SELF=Path(__file__).resolve()
QUALIFIER=ROOT/"scripts/qualify_mdeberta_nli_runtime.py"
QUALIFIER_SHA="37bb3e61bd70bd681a13fb0a74b6d5ca48e50bafcc3d0524c446bebe8f4963a1"
VERSION="mdeberta_guard_io_diagnostic_v1"


def load_qualifier():
    if hashlib.sha256(QUALIFIER.read_bytes()).hexdigest()!=QUALIFIER_SHA:raise ValueError("frozen_qualifier_changed")
    spec=importlib.util.spec_from_file_location("frozen_nli_qualification",QUALIFIER)
    q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
    return q


def loading_summary(info):
    result={}
    for name in ("missing_keys","unexpected_keys","mismatched_keys"):
        values=info.get(name,[])
        result[name]={"count":len(values),"keys":[v if isinstance(v,str) else v[0] for v in values]}
    result["error_msgs_count"]=len(info.get("error_msgs",[]))
    result["additional_info_fields"]=sorted(set(info)-{"missing_keys","unexpected_keys","mismatched_keys","error_msgs"})
    return result


def wrappers(q,trace):
    class DiagnosticGuard(q.WorkerGuard):
        def __call__(self,event,args):
            if event=="open" and args and isinstance(args[0],(str,bytes,os.PathLike)):
                path=Path(os.fsdecode(args[0]));mode=args[1];flags=args[2]
                write=(isinstance(mode,str) and any(c in mode for c in "wax+")) or bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
                if not write and path.resolve(strict=False)==SELF:
                    self.network(event,args);return  # Own code only, never a read-scope expansion elsewhere.
            try:
                return super().__call__(event,args)
            except PermissionError:
                if event=="open" and args and isinstance(args[0],(str,bytes,os.PathLike)):
                    frames=[];frame=sys._getframe(1);stage="unknown"
                    while frame is not None:
                        if len(frames)<6:frames.append({"file":frame.f_code.co_filename,"line":frame.f_lineno,"function":frame.f_code.co_name})
                        if frame.f_code.co_filename==str(QUALIFIER) and frame.f_code.co_name=="worker":
                            result=frame.f_locals.get("result")
                            if isinstance(result,dict):stage=result.get("stage","unknown")
                        frame=frame.f_back
                    trace["denied_opens"].append({"path":os.fsdecode(args[0]),"mode":args[1] if isinstance(args[1],str) else None,
                        "flags":args[2],"stage":stage,"callers":frames})
                raise

    class DiagnosticBudget(q.ForwardBudget):
        def __enter__(self):
            self.original=self.klass.forward;budget=self
            def stop(model,*args,**kwargs):
                budget.attempts+=1;budget.blocked+=1
                trace["blocked_classifier_entries"]+=1
                raise RuntimeError("diagnostic_zero_forward_stop")
            self.klass.forward=stop
            self.auto=sys.modules["transformers"].AutoModelForSequenceClassification
            self.had_local="from_pretrained" in self.auto.__dict__
            self.descriptor=self.auto.__dict__.get("from_pretrained")
            original=self.auto.from_pretrained
            def load(cls,*args,**kwargs):
                kwargs=dict(kwargs);kwargs["output_loading_info"]=True
                model,info=original(*args,**kwargs)  # Real model and real loader information.
                trace["loading_info"]=loading_summary(info)
                trace["loaded_class"]=type(model).__name__
                return model
            self.auto.from_pretrained=classmethod(load)
            return self
        def __exit__(self,*_):
            self.klass.forward=self.original
            if self.had_local:self.auto.from_pretrained=self.descriptor
            else:delattr(self.auto,"from_pretrained")
            trace["actual_top_classifier_forwards"]=self.actual
    return DiagnosticGuard,DiagnosticBudget


def binding(q,output,base):
    _,base_sha=q.approved_plan(base);_,inner_sha=q.approved_plan(output/"plan.json")
    return {"schema":VERSION,"output":output.relative_to(ROOT).as_posix(),"base_plan":base.relative_to(ROOT).as_posix(),
        "base_plan_sha256":base_sha,"qualifier_plan_sha256":inner_sha,"frozen_qualifier_sha256":QUALIFIER_SHA,
        "diagnostic_source_sha256":q.sha(SELF),"classifier_forward_cap":0,"output_loading_info":True,
        "extra_read_only_code":SELF.relative_to(ROOT).as_posix(),"runtime_qualified":False,
        "scope":"Diagnostic only. No guard relaxation, method repair, new questions or additional inference."}


def validate(q,path):
    path=q.scoped(path,ROOT/"results");raw=path.read_bytes();plan=q.loads(raw)
    output=q.scoped(ROOT/plan["output"],ROOT/"results");base=q.scoped(ROOT/plan["base_plan"],ROOT/"results")
    q.require(path==output/"diagnostic_plan.json" and raw==q.encoded(binding(q,output,base)),"diagnostic_plan_changed")
    q.require(q.sha(output/"diagnostic_source.py")==plan["diagnostic_source_sha256"],"diagnostic_source_snapshot_changed")
    return plan,output


def worker(q,path):
    _,output=validate(q,path)
    trace={"schema":VERSION,"runtime_qualified":False,"diagnostic_only":True,"denied_opens":[],
        "loading_info":None,"loaded_class":None,"blocked_classifier_entries":0,"actual_top_classifier_forwards":0}
    q.WorkerGuard,q.ForwardBudget=wrappers(q,trace)
    code=q.worker(output/"worker_job.json")
    trace["frozen_worker_exit_code"]=code
    trace["status"]="diagnostic_finished_zero_forward" if trace["actual_top_classifier_forwards"]==0 else "diagnostic_cap_failure"
    q.save(output/"child_home/guard_io_diagnostic.json",trace)
    print(json.dumps({"status":trace["status"],"denied_opens":len(trace["denied_opens"]),"actual_top_classifier_forwards":trace["actual_top_classifier_forwards"]}))
    return 0 if trace["actual_top_classifier_forwards"]==0 else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__);modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan-only",action="store_true");modes.add_argument("--execute",action="store_true")
    modes.add_argument("--worker-plan",type=Path,help=argparse.SUPPRESS)
    parser.add_argument("--output",type=Path);parser.add_argument("--base-plan",type=Path)
    parser.add_argument("--approved-plan",type=Path);args=parser.parse_args();q=load_qualifier()
    if args.worker_plan:return worker(q,args.worker_plan)
    if args.plan_only:
        q.require(args.output is not None and args.base_plan is not None and args.approved_plan is None,"plan_arguments_required")
        output=q.scoped(args.output,ROOT/"results");base=q.scoped(args.base_plan,ROOT/"results")
        q.approved_plan(base);q.plan_only(output)
        with (output/"diagnostic_source.py").open("xb") as f:f.write(SELF.read_bytes())
        q.save(output/"diagnostic_plan.json",binding(q,output,base))
        print(json.dumps({"status":"diagnostic_plan_only","classifier_forward_cap":0}));return 0
    q.require(args.approved_plan is not None and args.output is None and args.base_plan is None,"approved_plan_required")
    _,output=validate(q,args.approved_plan)
    q.require(not (output/"worker_job.json").exists(),"diagnostic_already_started_no_retry")
    inner,inner_sha=q.approved_plan(output/"plan.json");q.save(output/"worker_job.json",q.worker_job(inner,inner_sha))
    command=[str(ROOT/q.PYTHON),"-I","-B",str(SELF),"--worker-plan",str(args.approved_plan.absolute())]
    process=subprocess.run(command,cwd=ROOT,env=q.child_environment(output/"child_home"),capture_output=True,timeout=180)
    q.save(output/"diagnostic_process.json",{"returncode":process.returncode,"stdout_sha256":hashlib.sha256(process.stdout).hexdigest(),
        "stderr_sha256":hashlib.sha256(process.stderr).hexdigest(),"raw_output_not_persisted":True,"runtime_qualified":False})
    print(json.dumps({"status":"diagnostic_child_finished","returncode":process.returncode,"runtime_qualified":False}))
    return process.returncode


if __name__=="__main__":
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status":"diagnostic_failed","error_type":type(error).__name__,"runtime_qualified":False}))
        raise SystemExit(1) from None
