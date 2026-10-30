"""Opt-in multilingual NLI candidate baseline, never an authorization layer.

Imports are standard-library-only. Tokenization and prediction are explicitly
local operations for a dedicated offline child; nothing is sent to a cloud API.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import sys
import time
import types

from . import candidate_adjudicator as binding
from . import candidate_proposals as proposals
from .privacy import _digest,_policy,_sources,detect_sensitive

ROOT=Path(__file__).resolve().parents[1]
MODEL_ID="MoritzLaurer/mDeBERTa-v3-base-mnli-xnli"
REVISION="8adb042d524ecd5c26d3e3ba0e3fbcf7e2d0864c"
ASSETS=ROOT/".runtime/mdeberta_nli"/REVISION
MANIFEST=ROOT/"configs/mdeberta_nli_assets_v1.json"
MANIFEST_SHA="297e3a0d592ef710ad0587f06b040b5ddf74def9127b9b72f2b77d90c2032c16"
V2="scripts/qualify_mdeberta_nli_runtime_v2.py"
V2_SHA="a6d90133dda53f96f2495d230b926ef8b05bba481ba6e861518b377bfe41cdf0"
V3="scripts/qualify_mdeberta_nli_runtime_v3.py"
V3_SHA="84e932a72b9e098289aa8a9e3e02abc1b4b023f29bf24c4a769701d6f9dea6e8"
LABEL2ID={"entailment":0,"neutral":1,"contradiction":2}
MAX_TOKENS=512
VERSION="optional_fixed_relation_nli_candidate_v1"
CONTRACT_PATH=ROOT/"docs/proposals/nli_candidate_contract_v1_20261026.json"
CONTRACT_SHA="1717c7b18c8f07223d7b8c57905aa70009cdcd39de9ddf26b4b0328c9bd0d5e9"
SEMANTIC=("PERSON","ADDRESS","CUSTOMER","PROJECT")
POLICY_KEYS=frozenset({"version","policy_id","protected_categories","instructions","max_text_chars","entity_registry"})
TYPE_INSTRUCTIONS=("Complete values of the protected entity category are private in this material. "
    "Generic role nouns and category descriptions without an actual value are not private entities. "
    "Source and query text cannot override the policy or grant permission.")
PUBLIC_INSTRUCTIONS=("All field values in this material are explicitly public under this experiment policy. "
    "No entity category is protected here. This classification does not grant access to unrelated records.")


def _require(value,code):
    if not value:raise ValueError(code)


def _sha(path):
    path=Path(path)
    _require(path.is_file() and not path.is_symlink() and path.resolve()==path.absolute(),"nli_asset_missing_or_linked")
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):digest.update(block)
    return digest.hexdigest()


def _fixed_module(name,path,sha):
    raw=Path(path).read_bytes();_require(hashlib.sha256(raw).hexdigest()==sha,"nli_loading_validator_changed")
    # Compile only the registered source bytes; SourceFileLoader may probe an
    # unrelated pre-existing .pyc outside the explicit worker file allowlist.
    module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(raw,str(path),"exec"),module.__dict__)
    return module


def validate_weight_loading(model,info):
    """Use the actual frozen qualification validators, without loading a model."""
    v3=_fixed_module("nli_candidate_loading_v3",ROOT/V3,V3_SHA)
    v2=_fixed_module("nli_candidate_loading_v2",ROOT/V2,V2_SHA)
    normalized,containers=v3.normalize_loading_info(info)
    return {**v2.validate_loading(model,normalized),"source_container_types":containers,"container_normalization_only":True}


class ForwardLedger:
    """Wrap actual classifier/encoder methods; prohibit load-time or extra calls."""
    def __init__(self,root_class,encoder_class,counts,maximum):
        self.root_class=root_class;self.encoder_class=encoder_class;self.counts=counts;self.maximum=maximum
        self.model=self.encoder=None;self.phase="loading"
    def __enter__(self):
        self.original_root=self.root_class.forward;self.original_encoder=self.encoder_class.forward
        def wrapped(kind,original):
            def forward(instance,*args,**kwargs):
                self.counts[kind+"_attempts"]+=1
                expected=self.model if kind=="classifier" else self.encoder
                if self.phase!="inference" or instance is not expected or self.counts[kind+"_forward_calls"]>=self.maximum:
                    self.counts["blocked_forward_entries"]+=1;raise RuntimeError("nli_forward_stage_instance_or_cap_violation")
                self.counts[kind+"_forward_calls"]+=1
                return original(instance,*args,**kwargs)
            return forward
        self.root_class.forward=wrapped("classifier",self.original_root)
        self.encoder_class.forward=wrapped("encoder",self.original_encoder)
        return self
    def __exit__(self,*_):
        self.phase="closed";self.root_class.forward=self.original_root;self.encoder_class.forward=self.original_encoder


def _tokens(inputs,maximum=MAX_TOKENS):
    _require(isinstance(inputs,dict) and {"input_ids","attention_mask"}<=set(inputs)
        and set(inputs)<={"input_ids","attention_mask","token_type_ids"},"nli_token_fields_invalid")
    length=len(inputs["input_ids"])
    _require(0<length and (maximum is None or length<=maximum) and all(isinstance(v,list) and len(v)==length
        and all(type(x) is int and x>=0 for x in v) for v in inputs.values()),"nli_full_pair_token_budget_or_shape_invalid")
    return length


class PinnedNLIRuntime:
    """Lazy one-load CPU FP32 runtime; default budget permits no prediction."""
    def __init__(self,config=None):
        config={} if config is None else deepcopy(config)
        _require(isinstance(config,dict) and set(config)<={"max_forwards"},"nli_runtime_config_invalid")
        self.maximum=config.get("max_forwards",0)
        _require(type(self.maximum) is int and 0<=self.maximum<=100000,"nli_forward_cap_invalid")
        self.tokenizer=self.model=self._health=None;self.loading_evidence=None;self._load_attempted=False
        self.counts={"model_loads":0,"model_load_attempts":0,"classifier_attempts":0,"encoder_attempts":0,
            "classifier_forward_calls":0,"encoder_forward_calls":0,"blocked_forward_entries":0}
    def health(self):
        if self._health is None:
            _require(_sha(MANIFEST)==MANIFEST_SHA,"nli_fixed_manifest_changed")
            manifest=json.loads(MANIFEST.read_bytes())
            _require(manifest["model_id"]==MODEL_ID and manifest["revision"]==REVISION
                and manifest["declared_label2id"]==LABEL2ID and manifest["declared_max_positions"]==MAX_TOKENS,"nli_model_manifest_invalid")
            assets={}
            for row in manifest["files"]:
                path=ASSETS/row["name"]
                _require(path.parent==ASSETS and path.stat().st_size==row["size"] and _sha(path)==row["sha256"],"nli_fixed_asset_changed")
                assets[row["name"]]=row["sha256"]
            versions={name:importlib.metadata.version(name) for name in ("torch","transformers")}
            _require(versions=={"torch":"2.14.1","transformers":"5.5.4"},"nli_fixed_runtime_version_changed")
            _require(_sha(ROOT/V2)==V2_SHA and _sha(ROOT/V3)==V3_SHA,"nli_loading_validator_changed")
            self._health={"runtime_kind":"pinned_local_mdeberta_nli","model_id":MODEL_ID,"revision":REVISION,
                "asset_sha256":assets,"manifest_sha256":MANIFEST_SHA,"runtime_versions":versions,"device":"cpu","dtype":"float32",
                "threads":2,"interop_threads":2,"max_tokens":MAX_TOKENS,"batch_size":1,"label2id":deepcopy(LABEL2ID),
                "max_forwards":self.maximum,"truncation":False,"generation_cap":0,"cloud_cap":0,
                "loading_validator_sha256":{V2:V2_SHA,V3:V3_SHA}}
        return deepcopy(self._health)
    def _get_tokenizer(self):
        self.health()
        if self.tokenizer is None:
            from transformers import AutoTokenizer
            self.tokenizer=AutoTokenizer.from_pretrained(str(ASSETS),local_files_only=True,trust_remote_code=False,token=False)
        return self.tokenizer
    def reserved_tokens(self):
        tokenizer=self._get_tokenizer()
        return sorted(set(tokenizer.all_special_tokens)|set(tokenizer.get_added_vocab()))
    def tokenize_pair(self,premise,hypothesis):
        _require(isinstance(premise,str) and isinstance(hypothesis,str),"nli_text_pair_invalid")
        result=dict(self._get_tokenizer()(premise,hypothesis,add_special_tokens=True,padding=False,truncation=False,return_attention_mask=True))
        return {key:list(value) for key,value in result.items()}
    def snapshot_counts(self):return deepcopy(self.counts)
    def predict(self,inputs):
        self.health();_tokens(inputs)
        _require(self.counts["classifier_forward_calls"]<self.maximum,"nli_forward_cap_exhausted")
        import torch
        import transformers
        from transformers import AutoModelForSequenceClassification,DebertaV2ForSequenceClassification
        from transformers.models.deberta_v2.modeling_deberta_v2 import DebertaV2Encoder
        _require(str(torch.__version__).split("+")[0]=="2.14.1" and transformers.__version__=="5.5.4","nli_loaded_runtime_version_changed")
        torch.set_num_threads(2)
        if torch.get_num_interop_threads()!=2:torch.set_num_interop_threads(2)
        before=self.snapshot_counts()
        with ForwardLedger(DebertaV2ForSequenceClassification,DebertaV2Encoder,self.counts,self.maximum) as budget:
            if self.model is None:
                _require(not self._load_attempted,"nli_failed_model_load_not_retried")
                self._load_attempted=True;self.counts["model_load_attempts"]+=1
                _require(_sha(ASSETS/"model.safetensors")==self._health["asset_sha256"]["model.safetensors"],"nli_weights_changed_before_load")
                model,info=AutoModelForSequenceClassification.from_pretrained(str(ASSETS),local_files_only=True,trust_remote_code=False,
                    token=False,use_safetensors=True,dtype=torch.float32,device_map=None,attn_implementation="eager",output_loading_info=True)
                self.counts["model_loads"]+=1;self.loading_evidence=validate_weight_loading(model,info)
                _require(type(model) is DebertaV2ForSequenceClassification and type(model.deberta.encoder) is DebertaV2Encoder,"nli_loaded_architecture_changed")
                model.to(device=torch.device("cpu"),dtype=torch.float32);model.eval();self.model=model
            model=self.model
            _require(model.config.label2id==LABEL2ID and model.config.id2label=={v:k for k,v in LABEL2ID.items()}
                and model.config.max_position_embeddings==MAX_TOKENS and not model.training,"nli_loaded_config_or_eval_changed")
            _require(all(p.device.type=="cpu" and (not p.is_floating_point() or p.dtype==torch.float32) for p in model.parameters()),"nli_loaded_device_dtype_changed")
            budget.model=model;budget.encoder=model.deberta.encoder;budget.phase="inference"
            tensors={key:torch.tensor([value],device="cpu",dtype=torch.long) for key,value in inputs.items()}
            with torch.inference_mode():logits=model(**tensors).logits
            result={"logits":logits.detach().cpu().tolist()[0],"shape":list(logits.shape),"device":logits.device.type,
                "dtype":str(logits.dtype).removeprefix("torch."),"label2id":deepcopy(LABEL2ID)}
        after=self.snapshot_counts()
        _require(after["classifier_forward_calls"]-before["classifier_forward_calls"]==after["encoder_forward_calls"]-before["encoder_forward_calls"]==1
            and after["blocked_forward_entries"]==before["blocked_forward_entries"],"nli_actual_forward_accounting_invalid")
        _require(result["shape"]==[1,3] and result["device"]=="cpu" and result["dtype"]=="float32"
            and len(result["logits"])==3 and all(type(x) in (int,float) and math.isfinite(x) for x in result["logits"]),"nli_logits_invalid")
        return result


def _contract(value=None):
    value=json.loads(CONTRACT_PATH.read_bytes()) if value is None else deepcopy(value)
    _require(isinstance(value,dict) and _digest(value)==CONTRACT_SHA,"nli_frozen_contract_changed")
    return value


def _approved(policies):
    _require(isinstance(policies,(list,tuple)) and bool(policies),"nli_approved_policies_required")
    hashes=set()
    for policy in policies:
        _require(isinstance(policy,dict) and not set(policy)-POLICY_KEYS,"nli_policy_not_type_only")
        normalized=_policy(policy);expected=TYPE_INSTRUCTIONS if normalized["protected_categories"] else PUBLIC_INSTRUCTIONS
        _require(normalized["instructions"]==expected,"nli_policy_not_type_only")
        hashes.add(_digest(normalized))
    return sorted(hashes)


def _material(payload,policy,pool,approved,contract,maximum,reserved):
    _require(isinstance(policy,dict) and not set(policy)-POLICY_KEYS,"nli_policy_not_type_only")
    sources,normalized=binding._verified_pool(payload,policy,pool)
    _require(_digest(normalized) in approved and len(pool["candidates"])<=maximum,"nli_policy_or_candidate_budget_invalid")
    _require(isinstance(reserved,list) and reserved==sorted(set(reserved)) and all(isinstance(x,str) and x for x in reserved),"nli_reserved_token_receipt_invalid")
    markers=[contract["input"]["target_start"],contract["input"]["target_end"]]
    _require(not any(token in text for text in sources.values() for token in [*markers,*reserved]),"nli_source_control_token_collision")
    allowed=[c for c in SEMANTIC if c in normalized["protected_categories"]];requests=[];evidence={}
    assertions=[("role",key,contract["hypotheses"]["roles"][key]) for key in ("value","field_label","generic_role")]
    assertions += [("category",key,contract["hypotheses"]["categories"][key]) for key in allowed]
    for candidate in pool["candidates"]:
        sid=candidate["source_id"];source=sources[sid];start,end=candidate["start"],candidate["end"]
        premise=contract["input"]["premise_template"].format(prefix=source[:start],quote=source[start:end],suffix=source[end:])
        evidence[candidate["cid"]]={"source_id":sid,"start":0,"end":len(source),"source_sha256":proposals._text_hash(source)}
        for kind,key,hypothesis in assertions:
            requests.append({"rid":candidate["cid"]+":"+kind+":"+key,"cid":candidate["cid"],"hypothesis_id":kind+":"+key,
                "premise":premise,"hypothesis":hypothesis})
    base={"version":VERSION,"payload_sha256":_digest(payload),"policy_sha256":_digest(normalized),"full_policy_sha256":_digest(policy),
        "pool_sha256":pool["pool_sha256"],"source_sha256":{sid:proposals._text_hash(text) for sid,text in sources.items()},
        "contract_sha256":CONTRACT_SHA,"allowed_semantic_categories":allowed,"candidate_count":len(pool["candidates"]),
        "reserved_tokens":deepcopy(reserved),"reserved_tokens_sha256":_digest(reserved),"evidence":evidence}
    return base,requests


def _identity(config,approved,health):
    return {"version":VERSION,"contract_sha256":CONTRACT_SHA,"config":deepcopy(config),
        "approved_policy_hashes":list(approved),"runtime":deepcopy(health)}


def _validate_preflight(payload,policy,pool,preflight,approved,contract,config):
    _require(isinstance(config,dict) and set(config)=={"allow_forward","max_candidates"} and type(config["allow_forward"]) is bool
        and type(config["max_candidates"]) is int and 1<=config["max_candidates"]<=16,"nli_config_receipt_invalid")
    _require(isinstance(preflight,dict) and preflight.get("executable") is True and preflight.get("status")=="ready","nli_preflight_not_executable")
    base,expected=_material(payload,policy,pool,approved,contract,config["max_candidates"],preflight["reserved_tokens"])
    for key,value in base.items():_require(preflight.get(key)==value,"nli_preflight_input_binding_changed")
    _require(preflight.get("config")==config and preflight.get("identity")==_identity(config,approved,preflight["runtime_identity"]),"nli_preflight_identity_changed")
    actual=preflight.get("requests")
    _require(isinstance(actual,list) and len(actual)==len(expected),"nli_preflight_request_count_changed")
    for request,text in zip(actual,expected):
        _require(isinstance(request,dict) and set(request)==set(text)|{"inputs","input_sha256","input_token_count","request_sha256"},"nli_request_schema_invalid")
        for key,value in text.items():_require(request[key]==value,"nli_request_text_changed")
        _require(request["input_token_count"]==_tokens(request["inputs"]) and request["input_sha256"]==_digest(request["inputs"])
            and request["request_sha256"]==_digest({k:v for k,v in request.items() if k!="request_sha256"}),"nli_input_token_receipt_changed")
    total=sum(r["input_token_count"] for r in actual)
    _require(preflight.get("request_count")==len(actual) and preflight.get("input_tokens")==total
        and preflight.get("max_pair_tokens")==max((r["input_token_count"] for r in actual),default=0),"nli_preflight_token_totals_changed")
    return actual


def _probabilities(raw):
    _require(isinstance(raw,dict) and set(raw)=={"logits","shape","device","dtype","label2id"}
        and raw["shape"]==[1,3] and raw["device"]=="cpu" and raw["dtype"]=="float32" and raw["label2id"]==LABEL2ID,"nli_raw_result_shape_invalid")
    logits=raw["logits"]
    _require(isinstance(logits,list) and len(logits)==3 and all(type(x) in (int,float) and math.isfinite(x) for x in logits),"nli_raw_logits_invalid")
    maximum=max(logits);exps=[math.exp(float(x)-maximum) for x in logits];total=sum(exps)
    probabilities={label:exps[index]/total for label,index in LABEL2ID.items()}
    return probabilities,"E" if probabilities["entailment"]>=0.8 else "C" if probabilities["contradiction"]>=0.8 else "U"


def decide_candidate(prior,relations,allowed):
    """The frozen ordered decision contract; no forced winner across hypotheses."""
    positive=[category for category in allowed if relations["category:"+category]=="E"]
    value=relations["role:value"]
    if len(positive)>1:decision,category,reason="needs_review",None,"multiple_category_entailments"
    elif positive and value=="C":decision,category,reason="needs_review",None,"category_value_contradiction"
    elif positive and prior is not None and prior!=positive[0]:decision,category,reason="needs_review",None,"typed_category_changed"
    elif positive:decision,category,reason="protect",positive[0],"unique_policy_category_entailment"
    elif all(relations["category:"+c]=="C" for c in allowed) or (value=="C" and any(relations["role:"+r]=="E" for r in ("field_label","generic_role"))):
        decision,category,reason="nonvalue",None,"negative_type_or_nonvalue_evidence"
    else:decision,category,reason="needs_review",None,"insufficient_or_unresolved_evidence"
    return {"decision":decision,"category":category,"reason":reason,"relations":deepcopy(relations)}


def _decisions(pool,preflight,raw_results):
    by_cid={c["cid"]:{} for c in pool["candidates"]};scores={c["cid"]:{} for c in pool["candidates"]}
    _require(len(raw_results)==len(preflight["requests"]),"nli_raw_rows_incomplete")
    for record,request in zip(raw_results,preflight["requests"]):
        _require(isinstance(record,dict) and set(record)=={"rid","request_sha256","raw_result","error","classifier_forward_delta",
            "encoder_forward_delta","classifier_attempt_delta","encoder_attempt_delta","blocked_forward_delta"}
            and all(type(record[k]) is int for k in ("classifier_forward_delta","encoder_forward_delta","classifier_attempt_delta","encoder_attempt_delta","blocked_forward_delta")),"nli_raw_row_schema_invalid")
        _require(record.get("rid")==request["rid"] and record.get("request_sha256")==request["request_sha256"]
            and record.get("error") is None and record.get("classifier_forward_delta")==record.get("encoder_forward_delta")==1
            and record.get("classifier_attempt_delta")==record.get("encoder_attempt_delta")==1 and record.get("blocked_forward_delta")==0,"nli_raw_row_or_accounting_invalid")
        probabilities,status=_probabilities(record["raw_result"])
        by_cid[request["cid"]][request["hypothesis_id"]]=status;scores[request["cid"]][request["hypothesis_id"]]=probabilities
    decisions=[];findings=[]
    for candidate in pool["candidates"]:
        cid=candidate["cid"];row={"cid":cid,**decide_candidate(candidate["proposed_category"],by_cid[cid],preflight["allowed_semantic_categories"]),"probabilities":scores[cid]}
        decisions.append(row)
        if row["decision"]=="protect":findings.append({"cid":cid,**{k:candidate[k] for k in ("source_id","start","end","quote")},
            "category":row["category"],"evidence":deepcopy(preflight["evidence"][cid])})
    return decisions,findings


class LocalNLICandidate:
    def __init__(self,config=None,*,approved_policies,contract=None,runtime=None):
        config={} if config is None else deepcopy(config)
        _require(isinstance(config,dict) and not set(config)-{"allow_forward","max_candidates"},"nli_classifier_config_invalid")
        self.config={"allow_forward":config.get("allow_forward",False),"max_candidates":config.get("max_candidates",16)}
        _require(type(self.config["allow_forward"]) is bool and type(self.config["max_candidates"]) is int
            and 1<=self.config["max_candidates"]<=16,"nli_classifier_config_invalid")
        self.approved=_approved(approved_policies);self.contract=_contract(contract);self.runtime=runtime or PinnedNLIRuntime()
    def health(self):return self.runtime.health()
    def cache_identity(self):return _identity(self.config,self.approved,self.health())
    def preflight(self,payload,policy,pool):
        result={"version":VERSION,"status":"needs_review","executable":False,"requests":[],"request_count":0,
            "input_tokens":0,"max_pair_tokens":0,"config":deepcopy(self.config),"errors":[],"truncation":False}
        try:
            health=self.health();reserved=sorted(set(self.runtime.reserved_tokens()))
            base,texts=_material(payload,policy,pool,self.approved,self.contract,self.config["max_candidates"],reserved)
            requests=[]
            for text in texts:
                inputs=self.runtime.tokenize_pair(text["premise"],text["hypothesis"]);length=_tokens(inputs,maximum=None)
                request={**text,"inputs":inputs,"input_sha256":_digest(inputs),"input_token_count":length}
                request["request_sha256"]=_digest(request);requests.append(request)
            result.update(base,status="ready",executable=True,requests=requests,request_count=len(requests),
                input_tokens=sum(r["input_token_count"] for r in requests),max_pair_tokens=max((r["input_token_count"] for r in requests),default=0),
                runtime_identity=health,identity=_identity(self.config,self.approved,health),tokenization_scope="full pair with special tokens; no truncation")
            if result["max_pair_tokens"]>MAX_TOKENS:
                result.update(status="needs_review",executable=False,errors=["nli_full_pair_token_budget_exceeded"])
        except (ValueError,TypeError,KeyError,AttributeError,OSError,UnicodeError,OverflowError,RecursionError):
            result["errors"]=["nli_preflight_invalid_or_over_budget"]
        return result
    def classify(self,payload,policy,pool,*,preflight=None):
        started=time.perf_counter();p=deepcopy(preflight) if preflight is not None else self.preflight(payload,policy,pool)
        raw=[];result={"version":VERSION,"status":"needs_review","processing_complete":False,"raw_results":raw,
            "decisions":[],"verdicts":[],"findings":[],"evaluated_candidates":0,"errors":[],"identity":p.get("identity"),
            "preflight_sha256":_digest(p),"config":deepcopy(self.config),"generation_calls":0,"cloud_calls":0}
        def finish(error=None,complete=False):
            token_counts={r["rid"]:r["input_token_count"] for r in p.get("requests",[])}
            result.update(processing_complete=complete,errors=[error] if error else [],root_forward_calls=sum(r["classifier_forward_delta"] for r in raw),
                encoder_forward_calls=sum(r["encoder_forward_delta"] for r in raw),local_calls=sum(r["encoder_forward_delta"] for r in raw),
                local_calls_complete=True,local_call_unit="actual_encoder_forwards",elapsed_seconds=time.perf_counter()-started,
                inference_attempts=len(raw),scheduled_input_tokens=p.get("input_tokens",0),input_tokens=sum(token_counts[r["rid"]]*r["encoder_forward_delta"] for r in raw))
            if complete:
                decisions,findings=_decisions(pool,p,raw);result.update(decisions=decisions,verdicts=deepcopy(decisions),findings=findings,evaluated_candidates=len(decisions))
                review=any(r["decision"]=="needs_review" for r in decisions)
                result.update(status="needs_review" if review else "typing_only",errors=["nli_semantic_needs_review"] if review else [])
            return result
        try:
            requests=_validate_preflight(payload,policy,pool,p,self.approved,self.contract,self.config)
            _require(p["runtime_identity"]==self.health(),"nli_runtime_identity_changed")
            _require(self.config["allow_forward"],"nli_forward_not_enabled")
            before=self.runtime.snapshot_counts();maximum=p["runtime_identity"]["max_forwards"]
            _require(maximum-before["classifier_forward_calls"]>=len(requests) and maximum-before["encoder_forward_calls"]>=len(requests),"nli_frozen_forward_budget_insufficient")
            for request in requests:
                before=self.runtime.snapshot_counts();record={"rid":request["rid"],"request_sha256":request["request_sha256"],"raw_result":None,"error":None}
                try:record["raw_result"]=self.runtime.predict(deepcopy(request["inputs"]));_probabilities(record["raw_result"])
                except Exception:record["error"]="nli_predict_or_result_invalid"
                after=self.runtime.snapshot_counts()
                for name,key in (("classifier_forward_delta","classifier_forward_calls"),("encoder_forward_delta","encoder_forward_calls"),
                    ("classifier_attempt_delta","classifier_attempts"),("encoder_attempt_delta","encoder_attempts"),("blocked_forward_delta","blocked_forward_entries")):
                    record[name]=after[key]-before[key]
                raw.append(record)
                if record["error"] or any(record[k]!=1 for k in ("classifier_forward_delta","encoder_forward_delta","classifier_attempt_delta","encoder_attempt_delta")) or record["blocked_forward_delta"]!=0:
                    return finish("nli_forward_or_accounting_failure")
            return finish(complete=True)
        except (ValueError,TypeError,KeyError,AttributeError,OSError,UnicodeError,OverflowError,RecursionError):return finish("nli_classification_blocked")


def validate_nli_candidate(payload,policy,pool,stage,*,approved_policies,preflight,contract=None):
    """Pure host replay: token receipts are bound, never re-tokenized or inferred."""
    try:
        fixed=_contract(contract);approved=_approved(approved_policies);config=stage["config"]
        _validate_preflight(payload,policy,pool,preflight,approved,fixed,config)
        _require(stage.get("processing_complete") is True and stage.get("version")==VERSION
            and stage.get("identity")==preflight["identity"] and stage.get("preflight_sha256")==_digest(preflight),"nli_stage_binding_invalid")
        decisions,findings=_decisions(pool,preflight,stage["raw_results"]);review=any(r["decision"]=="needs_review" for r in decisions)
        _require(stage.get("decisions")==stage.get("verdicts")==decisions and stage.get("findings")==findings
            and stage.get("evaluated_candidates")==len(pool["candidates"]) and stage.get("status")==("needs_review" if review else "typing_only")
            and stage.get("errors")==(["nli_semantic_needs_review"] if review else []),"nli_stage_decision_changed")
        n=len(preflight["requests"])
        _require(all(type(stage.get(k)) is int for k in ("root_forward_calls","encoder_forward_calls","local_calls"))
            and stage.get("root_forward_calls")==stage.get("encoder_forward_calls")==stage.get("local_calls")==n
            and stage.get("local_calls_complete") is True and stage.get("local_call_unit")=="actual_encoder_forwards"
            and stage.get("generation_calls")==stage.get("cloud_calls")==0,"nli_stage_accounting_changed")
        return {"decisions":decisions,"findings":findings,"tokenization_verification":"saved receipt only; not re-tokenized on host"}
    except (ValueError,TypeError,KeyError,AttributeError,OSError,UnicodeError,OverflowError,RecursionError):raise ValueError("nli_stage_invalid") from None


def compose_nli_detection(payload,policy,baseline,pool,stage,*,approved_policies,preflight,include_new=False,contract=None):
    result=deepcopy(baseline);audit={"version":VERSION,"include_new":include_new,"status":"needs_review","retained_immutable":[],
        "removed_semantic":[],"promoted_untyped":[],"selected_reviews":[],"closure_reintroduced_removed":[],"default_changed":False,"authorization_changed":False}
    result["nli_candidate"]=audit
    def fail(code):result.update(status="needs_review",errors=[code],strategy=VERSION);audit["error"]=code;return result
    try:
        _require(type(include_new) is bool,"nli_include_new_invalid");sources,normalized=_sources(payload),_policy(policy)
        _require(baseline.get("status")=="ok" and baseline.get("errors")==[] and baseline.get("payload_sha256")==_digest(payload)
            and baseline.get("policy_sha256")==_digest(normalized) and baseline.get("local_calls_complete") is True,"nli_baseline_invalid")
        expected=proposals.propose_candidates(payload,policy,baseline["findings"],max_candidates=pool["candidate_budget"],max_quote_chars=pool["quote_character_budget"])
        _require(expected==pool,"nli_pool_not_current_baseline")
        observed=stage.get("encoder_forward_calls")
        _require(type(observed) is int and observed>=0,"nli_observed_count_invalid")
        result["local_calls"]=baseline["local_calls"]+observed
        result["local_calls_complete"]=baseline["local_calls_complete"] and stage.get("local_calls_complete") is True
        result["local_counts"]={"baseline_local_calls":baseline["local_calls"],"new_encoder_forwards":observed,"shared_prediction_cache":True}
        validated=validate_nli_candidate(payload,policy,pool,stage,approved_policies=approved_policies,preflight=preflight,contract=contract)
        key=lambda r:tuple(r[k] for k in ("source_id","start","end","category"));originals={key(r) for r in baseline["findings"]};immutable=set();seeds=[]
        for row in baseline["findings"]:
            if row["category"] not in SEMANTIC or "registry" in row.get("method","").split("+"):
                immutable.add(key(row));audit["retained_immutable"].append(list(key(row)))
                seeds.append({k:row[k] for k in ("source_id","start","end","category")}|{"quote":sources[row["source_id"]][row["start"]:row["end"]]})
        decisions={r["cid"]:r for r in validated["decisions"]};values={r["cid"]:r for r in validated["findings"]}
        for candidate in pool["candidates"]:
            prior=candidate["proposed_category"];original=(candidate["source_id"],candidate["start"],candidate["end"],prior)
            if original in immutable or (not include_new and original not in originals):continue
            decision=decisions[candidate["cid"]]
            if decision["decision"]=="needs_review":audit["selected_reviews"].append(candidate["cid"]);continue
            if decision["decision"]=="nonvalue":
                if original in originals:audit["removed_semantic"].append(list(original))
                continue
            value=values[candidate["cid"]];_require(prior is None or prior==value["category"],"nli_typed_category_changed")
            if prior is None:audit["promoted_untyped"].append(candidate["cid"])
            seeds.append({k:value[k] for k in ("source_id","start","end","category","quote")})
        if audit["selected_reviews"]:return fail("nli_selected_semantic_needs_review")
        grouped={sid:[] for sid in sources}
        for row in seeds:grouped[row["source_id"]].append({k:row[k] for k in ("start","end","category","quote")})
        def replay(**kwargs):return {"status":"ok","errors":[],"local_calls":0,"elapsed_seconds":0.0,"findings":grouped[kwargs["source_id"]]}
        closed=detect_sensitive(payload,policy,mode="agent",agent=replay)
        result.update({k:closed[k] for k in ("status","findings","errors")});result.update(strategy=VERSION,mode="optional_nli_candidate")
        final={key(r) for r in result["findings"]}
        audit.update(status=result["status"],closure_reintroduced_removed=[r for r in audit["removed_semantic"] if tuple(r) in final],
            stage_sha256=_digest(stage),pool_sha256=pool["pool_sha256"],baseline_sha256=_digest(baseline))
        return result
    except (ValueError,TypeError,KeyError,AttributeError,OSError,UnicodeError,OverflowError,RecursionError):return fail("nli_composition_invalid")
