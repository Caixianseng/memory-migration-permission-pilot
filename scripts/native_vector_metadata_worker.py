"""One metadata-observer variant of pinned Chroma search; never enables tracing."""
from __future__ import annotations
import argparse
import ast
from copy import deepcopy
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import sys
import threading
import time
import types

if __package__:
    from .native_exact_fact_target import TargetWorker
    from .native_exact_fact_common import serve_commands
else:
    from native_exact_fact_target import TargetWorker
    from native_exact_fact_common import serve_commands

CHROMA_SHA="825f745d2fba2a8c295ad3acca00893309184208230333bc4246dcaceaf236f9"
SNAPSHOTS=("before_writes","before_revoke","export_disabled_existing_copies_retained",
    "revoked_before_target_cleanup","after_cleanup","after_old_job_replay")
HOOK="__native_metadata_exception_observer__"


def require(value,code):
    if not value:raise ValueError(code)


def exception_metadata(error):
    message=str(error).encode("utf-8",errors="replace");lower=message.decode("utf-8",errors="replace").lower()
    markers={"contiguous_2d_results":"contiguous 2d array","plan_execution":"error executing plan",
        "index_id_lookup":"error finding id","native_panic":"panic","database_locked":"database is locked",
        "dimension_mismatch":"embedding dimension","collection_missing":"collection does not exist"}
    frames=[];tb=error.__traceback__
    while tb is not None:
        frames.append({"file":tb.tb_frame.f_code.co_filename,"line":tb.tb_lineno,"function":tb.tb_frame.f_code.co_name});tb=tb.tb_next
    return {"class":type(error).__module__+"."+type(error).__name__,"message_sha256":hashlib.sha256(message).hexdigest(),
        "message_bytes":len(message),"known_message_markers":[k for k,v in markers.items() if v in lower],"stack":frames[-12:]}


def instrument_search(source,filename,namespace,observer,expected_sha):
    """Only one AST statement is added inside the original catch; normal AST is identical."""
    require(hashlib.sha256(source.encode("utf-8")).hexdigest()==expected_sha,"chroma_source_hash_changed")
    tree=ast.parse(source,filename=filename)
    classes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="ChromaClient"]
    require(len(classes)==1,"chroma_class_shape_changed")
    functions=[n for n in classes[0].body if isinstance(n,ast.FunctionDef) and n.name=="search"]
    require(len(functions)==1,"chroma_search_shape_changed")
    original=functions[0];target=deepcopy(original)
    require(not target.decorator_list and len(target.body)==1 and isinstance(target.body[0],ast.Try),"chroma_search_try_shape_changed")
    attempt=target.body[0]
    require(len(attempt.handlers)==1 and not attempt.orelse and not attempt.finalbody,"chroma_search_handler_shape_changed")
    handler=attempt.handlers[0]
    require(isinstance(handler.type,ast.Name) and handler.type.id=="Exception" and handler.name=="e"
        and len(handler.body)==1 and isinstance(handler.body[0],ast.Return)
        and isinstance(handler.body[0].value,ast.Constant) and handler.body[0].value.value is None,"chroma_search_catch_changed")
    require(isinstance(attempt.body[-1],ast.Return) and isinstance(attempt.body[-1].value,ast.Constant)
        and attempt.body[-1].value.value is None and HOOK not in namespace,"chroma_search_none_or_hook_changed")
    statement=ast.Expr(ast.Call(func=ast.Name(id=HOOK,ctx=ast.Load()),args=[ast.Name(id="e",ctx=ast.Load())],keywords=[]))
    ast.copy_location(statement,handler.body[0]);handler.body.insert(0,statement);ast.fix_missing_locations(target)
    recovered=deepcopy(target);del recovered.body[0].handlers[0].body[0]
    require(ast.dump(recovered,include_attributes=False)==ast.dump(original,include_attributes=False),"normal_path_ast_changed")
    scope=dict(namespace);scope[HOOK]=observer
    exec(compile(ast.Module(body=[target],type_ignores=[]),filename,"exec"),scope)
    receipt={"original_source_sha256":expected_sha,"original_search_ast_sha256":hashlib.sha256(ast.dump(original,include_attributes=False).encode()).hexdigest(),
        "observed_search_ast_sha256":hashlib.sha256(ast.dump(target,include_attributes=False).encode()).hexdigest(),
        "normal_path_ast_preserved":True,"added_statements":1,"added_statement_scope":"except Exception as e before original return None",
        "original_first_line":original.lineno,"observation_variant":True,"original_function_object_called":False,"vendor_file_written":False}
    return scope["search"],receipt


class MetadataSearch:
    def __init__(self,original,identities,stage_provider,*,source=None,filename=None,expected_sha=CHROMA_SHA):
        self.calls=[];self.observer_errors=[];self.local=threading.local();self.stage=stage_provider
        self.actors={"user-memory-"+identifier:actor for actor,identifier in identities.items()};self.signature=inspect.signature(original)
        path=Path(filename or original.__code__.co_filename)
        raw=path.read_bytes() if source is None else source.encode("utf-8")
        require(hashlib.sha256(raw).hexdigest()==expected_sha,"chroma_original_bytes_changed")
        function,self.receipt=instrument_search(raw.decode("utf-8"),str(path),original.__func__.__globals__,self.observe,expected_sha)
        require(original.__func__.__closure__ is None and original.__code__.co_firstlineno==self.receipt["original_first_line"],"chroma_original_function_changed")
        self.observed=types.MethodType(function,original.__self__)
    def observe(self,error):
        try:self.local.row["exception_events"].append(exception_metadata(error))
        except BaseException:
            self.observer_errors.append("metadata_observer_failed");raise RuntimeError("metadata_observer_failed") from None
    def __call__(self,*args,**kwargs):
        require(sys.gettrace() is None,"trace_must_be_disabled")
        require(len(self.calls)<15,"search_budget_exceeded")
        params=self.signature.bind(*args,**kwargs);params.apply_defaults();params=params.arguments
        actor=self.actors.get(params["collection_name"])
        require(actor is not None and params["limit"]==100 and params["filter"] is None,"search_scope_changed")
        row={"stage":deepcopy(self.stage()),"actor":actor,"collection_name":params["collection_name"],"started_ns":time.perf_counter_ns(),
            "exception_events":[],"variant_calls":1,"literal_original_function_calls":0,"trace_disabled_before":True}
        self.local.row=row
        try:
            value=self.observed(*args,**kwargs)
            row["return_kind"]="none" if value is None else type(value).__name__
            row["none_reason"]=("caught_exception" if row["exception_events"] else "non_exception_branch") if value is None else None
            return value
        except BaseException as error:
            row["outward_exception"]=exception_metadata(error);raise
        finally:
            row["finished_ns"]=time.perf_counter_ns();row["trace_disabled_after"]=sys.gettrace() is None
            self.calls.append(row);del self.local.row


class MetadataTargetWorker(TargetWorker):
    def __init__(self,*,fixture,fixture_sha,**kwargs):
        raw=Path(fixture).read_bytes();require(hashlib.sha256(raw).hexdigest()==fixture_sha,"frozen_fixture_changed")
        self.fixture=json.loads(raw);self.snapshot_ordinal=0;self.residents_added=False;self.command_index=0
        super().__init__(**kwargs)
    def initialize(self,data):
        require(sys.gettrace() is None and threading.gettrace() is None,"trace_must_be_disabled")
        result=super().initialize(data)
        require(importlib.metadata.version("chromadb")=="1.5.9","chroma_version_changed")
        from open_webui.retrieval.vector.factory import get_vector_db_client
        backend=get_vector_db_client()
        require(type(backend).__module__=="open_webui.retrieval.vector.dbs.chroma" and type(backend).__name__=="ChromaClient","native_backend_changed")
        def stage():return {"snapshot_ordinal":self.snapshot_ordinal,"snapshot_name":SNAPSHOTS[self.snapshot_ordinal-1],"native_request_index":len(self.recorder.requests)}
        self.metadata_search=MetadataSearch(backend.search,result["native_user_ids"],stage)
        backend.search=self.metadata_search;result["metadata_observer"]=deepcopy(self.metadata_search.receipt)
        return result
    def __call__(self,command,data):
        require(sys.gettrace() is None,"trace_must_be_disabled")
        require(command=="close" or (self.command_index<len(self.fixture["schedule"])
            and command==self.fixture["schedule"][self.command_index]["command"]),"frozen_command_sequence_changed")
        self.command_index+=1
        if command=="add":
            item=self.fixture["writes"][self.command_index-3]
            require(data=={k:item[k] for k in ("actor","text","path")},"frozen_write_payload_changed")
        if command=="add_residents":
            require(data=={} and not self.residents_added,"fixed_resident_scope_invalid");self.residents_added=True
            from memory_migration_study.native_webui import _insert_memory
            rows=[]
            for item in self.fixture["writes"][3:]:
                rid=_insert_memory(self.recorder,item["actor"],self.identities[item["actor"]]["id"],item["text"],item["path"])
                rows.append({"target_id":rid,"actor":item["actor"],"content":item["text"],"path":item["path"]})
            return {"residents":rows}
        if command=="snapshot":
            require(self.snapshot_ordinal<6,"snapshot_budget_exceeded");self.snapshot_ordinal+=1
        value=super().__call__(command,data)
        require(self.embedding_invocations<=21,"embedding_budget_exceeded")
        return value
    def summary(self):
        result=super().summary()
        if hasattr(self,"metadata_search"):
            result["metadata_only"]={"snapshot_calls":self.snapshot_ordinal,"search_calls":len(self.metadata_search.calls),
                "observations":deepcopy(self.metadata_search.calls),"observer_errors":list(self.metadata_search.observer_errors),
                "implementation":deepcopy(self.metadata_search.receipt),"extra_native_reads":0,"sys_settrace_used":False}
        return result


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for name in ("state","assets","legacy-project","fixture"):parser.add_argument("--"+name,required=True,type=Path)
    parser.add_argument("--fixture-sha",required=True);args=parser.parse_args()
    serve_commands(MetadataTargetWorker(state=args.state,assets=args.assets,legacy_project=args.legacy_project,fixture=args.fixture,fixture_sha=args.fixture_sha))
