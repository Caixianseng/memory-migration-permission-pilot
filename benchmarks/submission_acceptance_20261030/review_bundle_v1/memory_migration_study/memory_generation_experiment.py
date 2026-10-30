"""Paired local memory-generation study; evaluation labels enter scoring only."""
from __future__ import annotations

import copy
import hashlib
import html
import json
from pathlib import Path
import random
import re
import secrets
import time
import uuid

from .budget import MEMORY_PROMPTS
from .local_detector import LocalSensitivityAgent, MODEL
from .memory_builder import LocalMemoryBuilder
from .memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from .privacy import _digest, _sources
from .privacy_payload_eval import masking_intervals

MODES = ("migration", "generation", "two_stage", "raw_reference")
ANSWER_PROMPT = MEMORY_PROMPTS["memory_fact_query_v2"]
STUDY_VERSION = "memory_generation_paired_local_v1"


def save(path, value):
    Path(path).write_bytes(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8"))


class LocalFactAnswerer:
    """Actual local task-model calls, with no reference answers or policy labels."""
    def __init__(self, config=None, *, transport=None):
        self.client = LocalSensitivityAgent(config, transport=transport)

    def __call__(self, payload):
        started = time.monotonic()
        try:
            _sources(payload)
        except (ValueError, TypeError):
            return {"status": "error", "answer": None, "local_calls": 0, "error": "invalid_answer_payload"}
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(content.encode()) + len(ANSWER_PROMPT.encode()) + 320 + 64 > 4096:
            return {"status": "error", "answer": None, "local_calls": 0, "error": "answer_input_budget_exceeded"}
        try:
            response = self.client.transport("POST", "/api/chat", {
                "model": MODEL, "messages": [{"role": "system", "content": ANSWER_PROMPT},
                                               {"role": "user", "content": content}],
                "stream": False, "keep_alive": "30m",
                "options": {"num_ctx": 4096, "num_predict": 64, "temperature": 0, "seed": 42}})
            message = response.get("message", {})
            if (response.get("model") != MODEL or response.get("done") is not True
                    or response.get("done_reason") != "stop" or message.get("thinking")
                    or message.get("tool_calls") or not isinstance(message.get("content"), str)
                    or not message["content"].strip()):
                raise ValueError("invalid_answer_envelope")
            return {"status": "ok", "answer": message["content"].strip(), "error": None,
                    "local_calls": 1, "elapsed_seconds": round(time.monotonic()-started, 6)}
        except Exception:
            return {"status": "error", "answer": None, "local_calls": 1, "error": "local_answer_failed",
                    "elapsed_seconds": round(time.monotonic()-started, 6)}


def score_task(row, label):
    """No model, builder, migration or authorization call occurs in this function."""
    answer = row.get("final_answer")
    supported = row.get("required_fact_in_generated_memory")
    is_unknown = isinstance(answer, str) and answer.strip().casefold() == "unknown"
    return {"correct": answer is not None and answer.strip().casefold() == label["expected_answer"].strip().casefold(),
            "authorized": label["authorized"],
            "processing_blocked": row["status"] == "blocked" and row.get("model_status") is None,
            "model_refusal_with_fact": bool(label["authorized"] and supported and row.get("model_status") == "ok" and is_unknown),
            "authorized_no_answer": bool(label["authorized"] and (answer is None or is_unknown)),
            "restore_failed": row.get("restoration_status") == "blocked"}


def score_masking(case, labels, records, prepared):
    """Score after transformation; missing extraction is distinct from masking."""
    source_gold = {(p) for s in labels["sensitive_spans"] for p in range(s["start"], s["end"])}
    retained = {p for r in records for p in range(r["source_start"], r["source_end"])}
    original_span_sets=[set(range(s['start'],s['end'])) for s in labels['sensitive_spans']]
    out = {"source_sensitive_characters": len(source_gold), "retained_sensitive_characters": len(source_gold & retained),
           "missing_extraction_sensitive_characters": len(source_gold-retained), "ready": False,
           "fully_retained_source_spans":sum(chars<=retained for chars in original_span_sets),
           "partially_retained_source_spans":sum(bool(chars & retained) and not chars<=retained for chars in original_span_sets),
           "missing_source_spans":sum(not chars & retained for chars in original_span_sets),
           "retained_gold_spans": 0, "complete": None, "partial": None, "unmasked": None, "extra_masked_characters": None}
    if prepared.get("status") != "ok":
        return out
    original = prepared["original_payload"]
    mapping = prepared["mapping"]
    covered, sensitive = set(), set()
    for before, after in zip(original["memories"], prepared["payload"]["memories"]):
        rid = before["source_id"]
        covered |= {(rid, p) for a, b in masking_intervals(before["text"], after["text"], mapping._entries) for p in range(a,b)}
    # Query-sensitive repeats of source values also count, independently of detection.
    query = original["query"]
    covered |= {("__query__", p) for a,b in masking_intervals(query, prepared["payload"]["query"], mapping._entries) for p in range(a,b)}
    spans=[]
    for s in labels["sensitive_spans"]:
        for r in records:
            a,b=max(s["start"],r["source_start"]),min(s["end"],r["source_end"])
            if a < b:
                spans.append(({(r["record_id"],p-r["source_start"]) for p in range(a,b)}, a!=s['start'] or b!=s['end']))
        value=case["source"]["text"][s["start"]:s["end"]]
        for m in re.finditer(re.escape(value),query,re.I):
            chars={("__query__",p) for p in range(m.start(),m.end())}
            if (chars,False) not in spans: spans.append((chars,False))
    complete=partial=unmasked=0
    for chars,truncated in spans:
        sensitive |= chars
        if chars <= covered and not truncated: complete+=1
        elif chars & covered: partial+=1
        else: unmasked+=1
    return dict(out,ready=True,retained_gold_spans=len(spans),complete=complete,partial=partial,unmasked=unmasked,
                extra_masked_characters=len(covered-sensitive))


def summarize(rows, builds):
    summaries=[]
    for split in ("all","dev","heldout"):
        for mode in MODES:
            selected=[r for r in rows if r["mode"]==mode and (split=="all" or r["split"]==split)]
            authorized=[r for r in selected if r["score"]["authorized"]]
            supported=[r for r in authorized if r["required_fact_in_generated_memory"]]
            ready=[r for r in selected if r.get("masking",{}).get("ready")]
            deny=[r for r in selected if not r["score"]["authorized"]]
            summaries.append({"split":split,"mode":mode,"registered_tasks":len(selected),
                "authorized_tasks":len(authorized),"authorized_correct":sum(r["score"]["correct"] for r in authorized),
                "authorized_no_answer":sum(r["score"]["authorized_no_answer"] for r in authorized),
                "supported_authorized_tasks":len(supported),
                "model_refusal_with_fact":sum(r["score"]["model_refusal_with_fact"] for r in selected),
                "processing_blocked_authorized":sum(r["score"]["processing_blocked"] for r in authorized),
                "processing_blocked_with_fact":sum(r["score"]["processing_blocked"] for r in supported),
                "restore_failed":sum(r["score"]["restore_failed"] for r in selected),
                "denied_tasks":len(deny),"denied_correctly_blocked":sum(r["status"]=="blocked" and r["error"]=="authorization_denied" for r in deny),
                "module_denied_tasks":sum(r.get("module_authorization_denied",False) for r in deny),
                "denied_received_answer":sum(r.get("final_answer") not in (None,"UNKNOWN") for r in deny),
                "ready_masked_requests":len(ready),
                "ready_with_masking_gaps":sum(r["masking"]["partial"]+r["masking"]["unmasked"]>0 for r in ready),
                "complete_masked_spans":sum(r["masking"]["complete"] for r in ready),
                "partial_masked_spans":sum(r["masking"]["partial"] for r in ready),
                "unmasked_spans":sum(r["masking"]["unmasked"] for r in ready),
                "extra_masked_characters":sum(r["masking"]["extra_masked_characters"] for r in ready),
                "source_sensitive_characters":sum(r.get("masking",{}).get("source_sensitive_characters",0) for r in selected),
                "retained_sensitive_characters":sum(r.get("masking",{}).get("retained_sensitive_characters",0) for r in selected),
                "missing_extraction_sensitive_characters":sum(r.get("masking",{}).get("missing_extraction_sensitive_characters",0) for r in selected),
                "migration_detector_calls":sum(r.get("detector_calls",0) for r in selected),
                "task_model_calls":sum(r.get("answer_calls",0) for r in selected),
                "migration_seconds":round(sum(r.get("migration_seconds",0) for r in selected),6),
                "fallback_requests":sum(any(x.get("fallback_reason") for x in r.get("checks",[])) for r in selected)})
    extraction=[]
    for case_id in dict.fromkeys(r['case_id'] for r in rows):
        scored=next((r for r in rows if r['case_id']==case_id and r.get('masking')),None)
        if scored and 'fully_retained_source_spans' in scored['masking']:
            extraction.append({'case_id':case_id,'split':scored['split'],**{k:scored['masking'][k] for k in
                ('source_sensitive_characters','retained_sensitive_characters','missing_extraction_sensitive_characters',
                 'fully_retained_source_spans','partially_retained_source_spans','missing_source_spans')}})
    return {"summaries":summaries,"extraction_per_story":extraction,"build_cases":len(builds),"build_successes":sum(b["status"]=="ok" for b in builds),
            "builder_calls":sum(b["local_calls"] for b in builds),"builder_seconds":round(sum(b.get("elapsed_seconds",0) for b in builds),6),
            "new_cloud_calls":0,"new_api_cost_cny":"0","mapping_persisted":False,
            "limits":["Synthetic, not independently human annotated; controlled local authority and frozen source, not native online revocation.",
                      "Actual task answers use the pinned local model, not a cloud provider; no cloud utility claim.",
                      "Conditions share one extractive memory build. A discards its labels; generation cost is reported separately for all conditions.",
                      "Masking gold spans are projected onto retained text; extraction loss is separate and never a privacy gain.",
                      "One serial run; request nonce and model variance can affect task answers; no significance claim."]}


def run_study(corpus, output, config, *, splits=("dev","heldout"), builder=None, detector=None, answerer=None):
    corpus,output=Path(corpus),Path(output)
    runtime=json.loads((corpus/"runtime.json").read_text(encoding="utf-8"))
    evaluation=json.loads((corpus/"evaluation.json").read_text(encoding="utf-8"))
    manifest=json.loads((corpus/'manifest.json').read_text(encoding='utf-8'))
    for name in ('runtime','evaluation'):
        if hashlib.sha256((corpus/(name+'.json')).read_bytes()).hexdigest()!=manifest['raw_sha256'][name]:
            raise ValueError('frozen_corpus_changed')
    if _digest(runtime)!=manifest['canonical_sha256']['runtime'] or _digest(evaluation)!=manifest['canonical_sha256']['evaluation']:
        raise ValueError('frozen_corpus_semantics_changed')
    labels={x["case_id"]:x for x in evaluation["cases"]}
    output.mkdir(parents=True,exist_ok=False)
    package=Path(__file__).parent
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    archive=output/'implementation'
    archive.mkdir()
    for p in package.glob('*.py'):
        (archive/p.name).write_bytes(p.read_bytes())
    save(output/"plan.json",{"study_version":STUDY_VERSION,"runtime_sha256":_digest(runtime),"evaluation_sha256":_digest(evaluation),
        "implementation_sha256":hashes,"splits":list(splits),"modes":MODES,"ordering_seed":20261024,
        "answer_prompt_sha256":hashlib.sha256(ANSWER_PROMPT.encode()).hexdigest(),"max_answer_calls":len(runtime["cases"])*8,
        "fixed_local_model":MODEL,"no_heldout_retuning":True,"new_cloud_calls":0})
    builder=builder or LocalMemoryBuilder(config)
    detector=detector or LocalSensitivityAgent(config)
    answerer=answerer or LocalFactAnswerer(config)
    authority=MemoryLabelAuthority(secrets.token_bytes(32))
    rows,builds=[],[]
    record_store=[]
    order=random.Random(20261024)
    for case in runtime["cases"]:
        if case["split"] not in splits: continue
        source,policy=case["source"],case["policy"]
        build=builder(text=source["text"],source_id=source["source_id"],policy=policy)
        builds.append(dict(build,case_id=case["case_id"],split=case["split"]))
        records=[]
        if build["status"]=="ok":
            for fact in build["facts"]:
                records.append(authority.build_record(source,fact,policy,owner_id=case["owner_id"],readers=case["readers"],
                    agent_id="builder_"+case["owner_agent_id"], allowed_agent_ids=["builder_"+case["owner_agent_id"],case["owner_agent_id"]],
                    builder_version=build["builder_version"]))
        record_store.append({"case_id":case["case_id"],"records":records})
        # JSON roundtrip exercises a real local store boundary without exporting a signing key.
        save(output/"record_store.json",record_store)
        records=json.loads(json.dumps(records))
        for task in case["tasks"]:
            modes=list(MODES);order.shuffle(modes)
            task_label=next(t for t in labels[case["case_id"]]["tasks"] if t["task_id"]==task["task_id"])
            for mode in modes:
                row={"case_id":case["case_id"],"task_id":task["task_id"],"split":case["split"],"mode":mode,
                     "status":"blocked","error":None,"model_status":None,"final_answer":None,"detector_calls":0,"answer_calls":0}
                # Evaluation support is scored here, but never supplies facts to a production module.
                needed=task_label.get("required_quote")
                row["required_fact_in_generated_memory"]=bool(needed and any(needed in r["text"] for r in records))
                if mode!='raw_reference':
                    row['masking']=score_masking(case,labels[case['case_id']],records,{'status':'blocked'})
                allowed=task["actor_id"] in case["readers"] and task["agent_id"]==case["owner_agent_id"]
                if not allowed:
                    row.update(error="authorization_denied",final_answer="UNKNOWN")
                    if mode!='raw_reference' and records:
                        denied=prepare_labeled_transfer(records,task['query'],policy,authority=authority,
                            actor_id=task['actor_id'],agent_id=task['agent_id'],request_id=str(uuid.uuid4()),mode=mode,agent=detector)
                        row['module_denied_tasks']=denied.get('error')
                        row['module_authorization_denied']=denied['status']=='blocked' and denied.get('error')=='principal_not_authorized'
                        row['detector_calls']=denied.get('local_calls',0)
                        if denied['status']=='ok':
                            row.update(status='error',error='unauthorized_module_accepted',final_answer=None)
                        denied['mapping']=None
                elif build["status"]!="ok" or not records:
                    row["error"]="memory_build_unavailable"
                elif mode=="raw_reference":
                    payload={"query":task["query"],"memories":[{"source_id":r["record_id"],"text":r["text"]} for r in records]}
                    answer=answerer(payload)
                    row.update(status=answer["status"],error=answer.get("error"),model_status=answer["status"],
                               final_answer=answer["answer"],model_answer=answer["answer"],answer_calls=answer["local_calls"])
                else:
                    start=time.monotonic()
                    request_id=str(uuid.uuid4())
                    prepared=prepare_labeled_transfer(records,task["query"],policy,authority=authority,
                        actor_id=task["actor_id"],agent_id=task["agent_id"],request_id=request_id,mode=mode,agent=detector)
                    row.update(migration_seconds=round(time.monotonic()-start,6),error=prepared.get("error"),
                               detector_calls=prepared.get("local_calls",0),checks=prepared.get("checks",[]))
                    row["masking"]=score_masking(case,labels[case["case_id"]],records,prepared)
                    if prepared["status"]=="ok":
                        row["outbound"]=prepared["payload"]
                        answer=answerer(prepared["payload"])
                        row.update(model_status=answer["status"],model_answer=answer["answer"],answer_calls=answer["local_calls"])
                        if answer["status"]=="ok":
                            restored=restore_labeled_answer(answer["answer"],prepared,records,policy,authority=authority,
                                actor_id=task["actor_id"],agent_id=task["agent_id"],request_id=request_id)
                            row.update(status="ok" if restored["status"]=="ok" else "blocked",restoration_status=restored["status"],
                                       final_answer=restored.get("answer"),error=restored.get("error"))
                        else: row.update(status="error",error=answer.get("error"))
                    prepared["mapping"]=None
                row["score"]=score_task(row,task_label)
                rows.append(row)
                save(output/"rows.json",rows)
        save(output/"builds.json",builds)
        print(json.dumps({"completed_case":case["case_id"],"split":case["split"],"build_status":build["status"],"facts":len(records),"rows":len(rows)},ensure_ascii=False),flush=True)
    if any(hashlib.sha256((package/name).read_bytes()).hexdigest()!=h for name,h in hashes.items()):
        raise ValueError("implementation_changed_during_study")
    report=summarize(rows,builds)
    report.update(study_version=STUDY_VERSION,runtime_sha256=_digest(runtime),evaluation_sha256=_digest(evaluation))
    report['total_actual_local_generation_calls']=report['builder_calls']+sum(r.get('detector_calls',0)+r.get('answer_calls',0) for r in rows)
    report['agent_identity_scope']='Two trusted host-simulated roles in one process: local builder -> receiving Agent; not native cross-platform Agent integration.'
    report['repeat_cost_projections']=[{'mode':s['mode'],'batch_repetitions':n,
        'projected_local_calls_build_plus_migration':report['builder_calls']+n*s['migration_detector_calls'],
        'projected_seconds_build_plus_migration':round(report['builder_seconds']+n*s['migration_seconds'],6),
        'scope':'Arithmetic projection of observed batch, including blocked cases, not fresh repeated inference or a dynamic-policy experiment.'}
        for s in report['summaries'] if s['split']=='all' and s['mode']!='raw_reference' for n in (1,3,10)]
    save(output/"report.json",report)
    return report


def render_report(output, report):
    output=Path(output)
    rows=[]
    for r in report["summaries"]:
        if r["split"] not in {"heldout","all"}:continue
        values=[r[k] for k in ("split","mode","registered_tasks","authorized_correct","authorized_tasks","model_refusal_with_fact",
            "processing_blocked_authorized","ready_masked_requests","ready_with_masking_gaps","complete_masked_spans","partial_masked_spans","unmasked_spans","extra_masked_characters","migration_detector_calls","task_model_calls")]
        rows.append('<tr>'+''.join('<td>'+html.escape(str(v))+'</td>' for v in values)+'</tr>')
    header=['范围','条件','总任务','合法答对','合法总数','有事实模型拒答','合法处理阻断','可准备','仍有遮蔽缺口','完整片段','部分片段','漏遮片段','额外遮蔽字符','迁移检测调用','回答调用']
    body='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>生成时隐私标注对照</title><style>body{font:16px/1.7 system-ui;margin:2rem}table{border-collapse:collapse}td,th{padding:8px;border:1px solid #bbb}.scroll{overflow:auto}</style><h1>生成时隐私标注与迁移校验：实际本地模型对照</h1><p>migration：迁移时完整检测；generation：生成标签验签＋问题检测；two_stage：标签＋迁移时完整检测；raw_reference：授权明文参照（本地合成材料）。</p><p>标签经过本地存储往返，HMAC密钥与恢复映射不写入报告。全部回答均来自真实本地模型；阻断、模型UNKNOWN和恢复失败分别统计。新云端调用0、API费用0元。</p><div class="scroll"><table><tr>'+''.join('<th>'+h+'</th>' for h in header)+'</tr>'+''.join(rows)+'</table></div><p>仅统计已准备输入的遮蔽时，必须同时查看阻断分母。原始事实抽取缺失另列于builds.json和逐项记录，不能算作成功保护。原值替换不等于全面匿名化。</p><ul>'+''.join('<li>'+html.escape(s)+'</li>' for s in report['limits'])+'</ul><p><a href="report.json">聚合JSON</a> · <a href="rows.json">逐项实际输入与回答</a> · <a href="builds.json">生成事实</a> · <a href="plan.json">冻结计划</a></p></html>'
    (output/'index.html').write_text(body,encoding='utf-8')
