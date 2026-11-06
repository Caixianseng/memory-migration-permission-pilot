"""Read-only accounting for controlled exact-original real receiver jobs."""
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/exact_original_live'
DATA=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/dataset'


def load(path):return json.loads(path.read_text(encoding='utf8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def audit():
    projects=load(DATA/'projects.json');manifest=load(OUT/'execute_manifest.json')
    rows=[];models=Counter();sessions=[];errors=[];blocked=[];recovered=[]
    for cell in sorted(p for p in OUT.iterdir()if p.is_dir()and p.name.startswith('LIVE-')):
        if not(cell/'complete.json').exists():
            failure=cell/'blocked.json'if(cell/'blocked.json').exists()else cell/'local_exception.json'
            blocked.append({'cell':cell.name,'failure':load(failure)if failure.exists()else'pending'})
            continue
        complete=load(cell/'complete.json');project=projects[complete['project_id']]
        if complete.get('completed_via_safe_precreation_retry'):
            recovered.append({'cell':cell.name,'original_failure_retained':(cell/'blocked.json').exists(),
               'proof':str((cell/'safe_precreation_retry_check.json').relative_to(ROOT)),
               'new_inference_path':str((cell/'receiver_raw_safe_precreation_retry_01').relative_to(ROOT))})
        allowed=set(project['permission_timeline'][1]['receiver_allowed_source_ids'])
        expected='\n\n'.join(s['text']for s in project['sources']if s['source_id']in allowed)
        readback=load(cell/'readback.json');records=load(cell/'evaluation_records.json');record=records[0]
        packet=load(cell/'persistent/legal_raw.packet.json');denied=load(cell/'persistent/all_packet_rejection.json')
        request=load(cell/'receiver_request.json');contract=load(cell/'receiver_raw/contract.json')
        kinds=[memory['kind']for memory in packet['memories']]
        tests={'exact_readback_bytes':readback['memory'].encode('utf8')==expected.encode('utf8'),
          'all_packet_rejected':denied['status']=='rejected'and denied['actual_receiver_batches']==0,
          'every_memory_kind_raw':all(k=='raw'for k in kinds),
          'only_legal_sources':{s['source_id']for s in packet['sources']}==allowed,
          'independent_process_readback':readback['read_in_separate_process'],
          'input_request_hash':contract['prompt_sha256']==record['recipient_input_sha256'],
          'raw_only':contract['scenarios']==['raw'],'source_not_model_generated':record['source_type']=='controlled_exact_original'and not record['source_model_invoked'],
          'gold_fields_not_sent':not any(k in request['prompt']for k in ('expected_answer','withheld_reference_value','minimal_support_sets'))}
        dbfile=cell/'persistent/receiver.sqlite';before=sha(dbfile)
        db=sqlite3.connect(dbfile.resolve().as_uri()+'?mode=ro',uri=True)
        try:
            tests['single_legal_batch']=db.execute('SELECT count(*) FROM batches').fetchone()[0]==1
            tests['sqlite_quick_check']=db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        finally:db.close()
        tests['db_read_only_hash_unchanged']=before==sha(dbfile)
        failed=[key for key,ok in tests.items()if not ok]
        if failed:errors.append({'cell':cell.name,'failed_checks':failed})
        meta=complete['metadata'];models[str(meta.get('model'))]+=1
        if meta.get('session_id'):sessions.append(meta['session_id'])
        rows.append({'cell':cell.name,'project_id':complete['project_id'],'direction':complete['direction'],
          'repeat_index':complete['repeat_index'],'source_type':'controlled_exact_original',
          'receiver_platform':record['receiver_platform'],'actual_model':meta.get('model'),
          'answer_fields':len(record['answers'])if isinstance(record.get('answers'),dict)else None,
          'readback_sha256':readback['memory_sha256'],'prompt_sha256':record['recipient_input_sha256'],
          'sdk_observed_physical_requests':meta.get('physical_supplier_calls'),
          'sdk_estimated_cost_cny':meta.get('estimated_cost_cny'),'actual_invoice_cost_cny':meta.get('actual_cost_cny'),
          'checks':tests})
    script=ROOT/'experiments/paper_live_v2/exact_original_live.py'
    result={'schema':'controlled-exact-original-real-receiver-audit-v1','checked_utc':datetime.now(timezone.utc).isoformat(),
      'expected_jobs':manifest['expected_receiver_jobs'],'completed_jobs':len(rows),'blocked_or_pending':blocked,
      'project_count_completed':len({r['project_id']for r in rows}),
      'directions':dict(Counter(r['direction']for r in rows)),
      'receiver_platforms':dict(Counter(r['receiver_platform']for r in rows)),
      'first_attempt_completed_jobs':len(rows)-len(recovered),'safe_precreation_retry_recoveries':recovered,
      'outer_attempts_including_known_zero_send_failure':len(rows)+len(recovered),
      'actual_models':dict(models),'source_model_calls':0,'human_review_completed':False,
      'observed_workbuddy_unique_sessions':len(set(sessions)),'observed_workbuddy_sessions':len(sessions),
      'runner_matches_execute_manifest':sha(script)==manifest['script_sha256'],
      'errors':errors,'cells':rows,
      'cost_scope':'SDK physical counts/estimate only where observed; native supplier calls and invoice charges unknown',
      'sample_unit':'10 controlled project clusters; direction/repetition/question nested; not 60 independent projects'}
    (OUT/'audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items()if k!='cells'},ensure_ascii=False,indent=2))
    return result


if __name__=='__main__':audit()
