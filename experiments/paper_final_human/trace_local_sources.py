"""Read only controlled source results and Host DB metadata for C attribution.

No credentials, native account/session trees or database writes are accessed.
"""
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research_paper_v1/paper_final/evidence/ai_evaluation'
LOCAL=ROOT/'results/persistent_exchange_v1'
PUBLIC=ROOT/'benchmarks/persistent_exchange_v1_public_20261105'


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    spec=importlib.util.spec_from_file_location('AI_assess',Path(__file__).with_name('ai_assess.py'));a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
    cards=json.loads((OUT/'Ccards.json').read_text(encoding='utf-8'))
    # Current C causes may already have been resolved; retain the first grouping.
    initial_cards=OUT/'Ccards_before_local_trace.json'
    if not initial_cards.exists():initial_cards.write_text(json.dumps(cards,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    else:cards=json.loads(initial_cards.read_text(encoding='utf-8'))
    public_records=json.loads((PUBLIC/'records.public.json').read_text(encoding='utf-8'))
    local_records=json.loads((LOCAL/'main_records.json').read_text(encoding='utf-8'))
    attempts={r['attempt_id']:r for r in json.loads((PUBLIC/'source_attempts.public.json').read_text(encoding='utf-8'))}
    public_by={(r['case_id'],r['direction'],r['arm']):r for r in public_records}
    local_by={(r['case_id'],r['direction'],r['arm']):r for r in local_records}
    item_data=json.loads((ROOT/'research_paper_v1/paper_final/evidence/human/items.blinded.json').read_text(encoding='utf-8'))
    item_refs={x['item_id']:x for x in item_data['items']}
    receipt={'schema':'local-source-attribution-v1','date_local':'2026-11-06','scope':'Controlled source result.json/memory.json, explicit protocol-failure summaries/partial source output and Host SQLite tables, all read-only; no account metadata, credentials or native hidden sessions.','input_hashes':{},'items':[],'conditions':[]}
    hashes={};cache={}
    for group in cards:
        c=group['condition'];condition=(c['case_id'],c['direction'],c['arm']);rec=public_by[condition];native=local_by[condition]
        sender='A' if c['direction']=='A_to_B' else 'B'
        dbpath=LOCAL/'cases'/c['case_id']/f'{sender}.sqlite'
        before=sha(dbpath);con=sqlite3.connect(dbpath.resolve().as_uri()+'?mode=ro',uri=True);con.row_factory=sqlite3.Row
        tables=[r['name'] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        db_metadata={}
        for table in ('memories','node_provenance'):
            if table in tables:
                db_metadata[table]=[dict(r) for r in con.execute('SELECT * FROM '+table)]
        con.close();assert sha(dbpath)==before;hashes[str(dbpath.relative_to(ROOT))]=before
        job_candidates=[]
        for attempt_id in rec['source_jobs']:
            pub=attempts[attempt_id]
            folder=LOCAL/'source_jobs'/pub['case_id']/pub['agent']/pub['phase']/pub['group']
            candidates=[folder/'result.json']
            if folder.exists():
                candidates.extend(folder.glob('attempt*/result.json'))
                candidates.extend(folder.glob('recovery*/result.json'))
            match=None;result=None
            for path in candidates:
                if not path.exists():continue
                content=json.loads(path.read_text(encoding='utf-8-sig'))
                if content.get('memory')==pub.get('memory') and set(content.get('source_ids',[]))==set(pub.get('source_ids',[])):
                    match=path;result=content;break
            if match:
                hashes[str(match.relative_to(ROOT))]=sha(match)
                memory=str(result.get('memory') or '')
                failure=match.parent/'native_protocol_failed.json'
                fail_summary={}
                if failure.exists():
                    failure_data=json.loads(failure.read_text(encoding='utf-8-sig'));hashes[str(failure.relative_to(ROOT))]=sha(failure)
                    # Preserve field names and selected coarse reasons, not private transports.
                    fail_summary={k:v for k,v in failure_data.items() if k in {'status','reason','error','message','scope','source_protocol_conformance','source_attempt_status','protocol_issues','protocol_failure_action'}}
                partial='';partial_path=match.parent/'failed_completion_audit.json';partial_hash_ok=False
                if partial_path.exists():
                    partial_data=json.loads(partial_path.read_text(encoding='utf-8-sig'));partial=str(partial_data.get('partial_model_output') or '');hashes[str(partial_path.relative_to(ROOT))]=sha(partial_path)
                    expected=result.get('evidence',{}).get('partial_output_sha256');partial_hash_ok=bool(expected and hashlib.sha256(partial.encode()).hexdigest()==expected)
                outside='';outside_path=None;missing_path=match.parent/'native_missing_output_closed.json'
                if missing_path.exists():
                    missing_data=json.loads(missing_path.read_text(encoding='utf-8-sig'));hashes[str(missing_path.relative_to(ROOT))]=sha(missing_path)
                    for name in missing_data.get('observed_Write_tool_paths',[]):
                        path=Path(name).resolve()
                        if path.name=='memory.json' and path.is_relative_to(Path('D:/agent安全论文').resolve()) and path.exists():
                            outside_data=json.loads(path.read_text(encoding='utf-8-sig'));outside=str(outside_data.get('memory') or '');outside_path=str(path);hashes[outside_path]=sha(path)
                job_candidates.append({'attempt_id':attempt_id,'public_status':pub['source_attempt_status'],'usable':pub['usable_generated_memory'],'effective':pub['effective_for_study'],'source_ids':pub['source_ids'],'memory':memory,'partial_output':partial,'partial_output_sha_matches':partial_hash_ok,'partial_audit_path':str(partial_path.relative_to(ROOT)) if partial_path.exists() else None,'outside_declared_memory':outside,'outside_declared_path':outside_path,'missing_output_audit_path':str(missing_path.relative_to(ROOT)) if missing_path.exists() else None,'group':pub['group'],'phase':pub['phase'],'agent':pub['agent'],'local_path':str(match.relative_to(ROOT)),'local_sha256':sha(match),'public_memory_sha_matches':hashlib.sha256(memory.encode()).hexdigest()==pub['memory_text_sha256'],'local_protocol_failure_file':str(failure.relative_to(ROOT)) if failure.exists() else None,'protocol_failure_summary':fail_summary})
            else:job_candidates.append({'attempt_id':attempt_id,'match':'not_located_in_safe_source_result_paths','public_status':pub['source_attempt_status'],'usable':pub['usable_generated_memory'],'effective':pub['effective_for_study'],'source_ids':pub['source_ids'],'memory':str(pub.get('memory') or ''),'local_path':None})
        rejected=native.get('delivery',{}).get('source_protocol_rejected_memory_keys',[])
        received_path=LOCAL/'receiver_jobs'/c['case_id']/c['direction']/c['arm']/'retrieved_memory.json'
        retrieved=json.loads(received_path.read_text(encoding='utf-8-sig'))
        hashes[str(received_path.relative_to(ROOT))]=sha(received_path)
        for job in job_candidates:
            job['sender_memory_keys']=[r['memory_key'] for r in db_metadata.get('memories',[]) if r['content']==job.get('memory')]
            job['host_rejected_keys_matched']=sorted(set(job['sender_memory_keys']) & set(rejected))
            job['closed_artifact_sentinel_matched']=f"FAILED-{job.get('agent')}-{job.get('group')}-{job.get('phase')}" in rejected
        # DB metadata is restricted to case-owned material and used to tie artifact text.
        metadata_text=json.dumps(db_metadata,ensure_ascii=False)
        condition_result={'condition':c,'receiver_memory_bytes':len(rec['received_memory'].encode()),'public_and_local_received_memory_equal':rec['received_memory']==retrieved['memory'],'receiver_readback_sha256':sha(received_path),'receiver_content_sha256':hashlib.sha256(retrieved['memory'].encode()).hexdigest(),'local_delivery_keys':list(native.get('delivery',{})),'rejected_memory_keys':rejected,'source_jobs':[{k:v for k,v in job.items() if k not in {'memory','source_ids','partial_output','outside_declared_memory'}} for job in job_candidates],'sender_db_path':str(dbpath.relative_to(ROOT)),'sender_db_tables':tables,'source_result_db_content_links':[{ 'attempt_id':job['attempt_id'],'text_present_in_sender_db':bool(job.get('sender_memory_keys'))} for job in job_candidates]}
        receipt['conditions'].append(condition_result)
        for item in group['items']:
            required=item['ground_truth']['required_values'];missing=[v for v in required if a.canonical(v) not in a.canonical(rec['received_memory'])]
            # If receiver received the fact but omitted it, classify a downstream omission.
            fact_details=[]
            for value in missing:
                contains=[job for job in job_candidates if a.canonical(value) in a.canonical(job.get('memory',''))]
                rejected_contains=[job for job in contains if not job['usable'] and job['effective'] and job.get('host_rejected_keys_matched')]
                safe_contains=[job for job in contains if job['usable'] and job['effective']]
                partial_contains=[job for job in job_candidates if a.canonical(value) in a.canonical(job.get('partial_output','')) and job.get('partial_output_sha_matches') and job.get('closed_artifact_sentinel_matched')]
                outside_contains=[job for job in job_candidates if a.canonical(value) in a.canonical(job.get('outside_declared_memory','')) and job.get('closed_artifact_sentinel_matched')]
                fact_details.append({'value':value,'present_in_received_memory':False,'rejected_artifacts_with_value':[job['attempt_id'] for job in rejected_contains],'usable_artifacts_with_value':[job['attempt_id'] for job in safe_contains],'local_paths_with_value':[job['local_path'] for job in contains if job['local_path']],'host_filter_mechanism_observed':bool(rejected_contains),'partial_output_closed_with_value':[job['attempt_id'] for job in partial_contains],'outside_path_closed_with_value':[job['attempt_id'] for job in outside_contains],'all_source_results_missing_value':not contains})
            located=all(any(job.get('local_path') and job.get('public_memory_sha_matches') for job in job_candidates if job['attempt_id'] in detail['rejected_artifacts_with_value']) for detail in fact_details) if fact_details else False
            resolved=bool(missing) and len(fact_details)==len(missing) and all(d['host_filter_mechanism_observed'] for d in fact_details) and located and condition_result['public_and_local_received_memory_equal']
            partial_resolved=bool(missing) and all(d['partial_output_closed_with_value'] for d in fact_details)
            outside_resolved=bool(missing) and all(d['outside_path_closed_with_value'] for d in fact_details)
            decision='resolved_observed_delivery_filter_loss' if resolved else ('resolved_partial_output_closed' if partial_resolved else ('resolved_wrong_path_artifact_closed' if outside_resolved else ('resolved_receiver_omission_despite_fact_in_memory' if not missing else 'multiple_or_unresolved_causes')))
            frozen=item_refs[item['case_id']];permission=item['permissions_at_time']
            receipt['items'].append({'item_id':item['case_id'],'condition':c,'question':item['original_input']['question'],'answer':item['agent_original_answer'],'required_values':required,'frozen_primary_eligible':frozen['primary_eligible'],'reference_supports_currently_authorized':all(permission[s]=='ALLOW' for s in frozen['reference_support_ids']),'missing_values_from_receiver':missing,'missing_fact_details':fact_details,'decision':decision,'interpretation':'Specific required value existed in a hash-matched source output/partial output or identified wrong-path artifact, but was absent after documented nonconformance closure/filtering. Operational delivery-chain loss established, not receiver/Host-authorization failure or counterfactual proof of a unique cause.' if (resolved or partial_resolved or outside_resolved) else ('Required values already present in readback; downstream answer omitted them, despite unrelated upstream nonconformance.' if not missing else 'Partial/truncated source output itself lacks the needed fact; content omission versus truncation cannot be uniquely separated.'),'extra_evidence_paths':[job['local_path'] for job in job_candidates if job.get('local_path')]+[job['partial_audit_path'] for job in job_candidates if job.get('partial_audit_path')]+[job['outside_declared_path'] for job in job_candidates if job.get('outside_declared_path')]+[str(dbpath.relative_to(ROOT)),str(received_path.relative_to(ROOT))]})
    for path,expected in hashes.items():assert sha(ROOT/path)==expected,path
    receipt['input_hashes']=hashes
    receipt['summary']={kind:sum(x['decision']==kind for x in receipt['items']) for kind in sorted({x['decision'] for x in receipt['items']})}
    receipt['original_files_unchanged']=True
    (OUT/'local_source_trace.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'summary':receipt['summary'],'conditions':len(receipt['conditions']),'read_safe_files':len(hashes),'original_files_unchanged':True,'first_three_cards':receipt['items'][:2]},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
