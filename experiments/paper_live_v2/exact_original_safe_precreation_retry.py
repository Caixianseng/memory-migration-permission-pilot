"""One separately authorized fresh-session retry of a proven no-send failure.

Reads only the failed job's own registration/history. Never resends to the old
UUID, never edits its frozen intent/result, never retries a possibly sent prompt.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from experiments.paper_live_v2 import exact_original_live as exact
from experiments.paper_live_v2 import live_runtime as runtime


def inspect_owned(cell):
    input_path=cell/'receiver_raw/native/input.json'
    envelope_path=cell/'receiver_raw/native/envelope.json'
    job=runtime.load(input_path);envelope=runtime.load(envelope_path);native=envelope['nativeExecution']
    if not(native.get('stage')=='creating_fresh_session'and native.get('modelPromptsSubmitted')==0 and native.get('promptSendAttempted')is False):
        raise RuntimeError('not_a_proven_pre_send_failure_no_retry')
    config=Path(job['workbuddyConfigDir']);db=sqlite3.connect((config/'workbuddy.db').resolve().as_uri()+'?mode=ro',uri=True)
    db.row_factory=sqlite3.Row
    try:
        db.execute('PRAGMA query_only=ON')
        registrations=[dict(r)for r in db.execute('SELECT id,cwd,model,status,is_playground,deleted_at FROM sessions WHERE id=? OR cwd=?',(job['sessionId'],job['workspace']))]
    finally:db.close()
    histories=[];errors=[]
    for directory in (config/'projects').iterdir():
        try:
            if not directory.is_dir():continue
            candidate=directory/(job['sessionId']+'.jsonl')
            if candidate.exists():
                raw=candidate.read_bytes();rows=[json.loads(line)for line in raw.decode('utf8').splitlines()if line.strip()]
                histories.append({'path':str(candidate),'sha256':hashlib.sha256(raw).hexdigest(),'rows':len(rows),
                    'user_message_count':sum(r.get('type')=='message'and r.get('role')=='user'for r in rows)})
        except OSError as exc:errors.append({'directory':directory.name,'error':type(exc).__name__})
    user_count=sum(h['user_message_count']for h in histories)
    if errors or user_count or len(histories)>1:raise RuntimeError('own_history_not_proven_zero_user_messages')
    if any(r['id']!=job['sessionId']or str(Path(r['cwd']).resolve())!=str(Path(job['workspace']).resolve())for r in registrations):
        raise RuntimeError('native_registration_identity_conflict')
    return {'schema':'safe-precreation-retry-owned-evidence-v1','checked_utc':datetime.now(timezone.utc).isoformat(),
      'original_session_id':job['sessionId'],'original_workspace':job['workspace'],'native_stage':native['stage'],
      'prompt_send_attempted':False,'model_prompts_submitted':0,'registration_metadata':registrations,
      'own_history_files':histories,'observed_own_user_message_count':user_count,'directory_read_errors':errors,
      'no_history_file_is_distinct_from_global_observation':'combined with pre-send execution trace; not proof of all hidden provider behavior',
      'original_input_sha256':hashlib.sha256(input_path.read_bytes()).hexdigest(),
      'original_envelope_sha256':hashlib.sha256(envelope_path.read_bytes()).hexdigest(),
      'action_authorized_by_root':'one new-session safe_precreation_retry; preserve first failure; do not resend original UUID'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--cell',default='LIVE-P09.B_to_A.r1');parser.add_argument('--execute-real',action='store_true');args=parser.parse_args()
    cell=exact.OUT/args.cell
    check=inspect_owned(cell)
    proof=cell/'safe_precreation_retry_check.json'
    if not proof.exists():runtime.save(proof,check)
    if not args.execute_real:
        print(json.dumps(check,ensure_ascii=False,indent=2));return
    if(cell/'complete.json').exists():
        print(json.dumps({'status':'already_effectively_complete','new_calls':0}));return
    pid,direction,repetition=args.cell.split('.');repeat_index=int(repetition[1:])
    if direction!='B_to_A':raise RuntimeError('this_recovery_is_for_workbuddy_no_send_only')
    request=runtime.load(cell/'receiver_request.json');payload=runtime.load(cell/'readback.json')
    recovered_dir=cell/'receiver_raw_safe_precreation_retry_01'
    result=runtime.infer('hy3',request['prompt'],recovered_dir,'target',scenarios=('raw',))
    if result['status']!='ok':
        print(json.dumps({'status':'recovery_failed_closed','error':result.get('error'),'automatic_retry':False}));return
    new_session=result['metadata'].get('session_id')
    if not new_session or new_session==check['original_session_id']:raise RuntimeError('fresh_recovery_session_not_verified')
    record={'project_id':pid,'direction':direction,'repeat_index':repeat_index,'scenario':'raw','phase':'exact_original_raw',
      'method':'exact_original_memory_transfer','equivalent_methods':['exact_original_memory_transfer'],
      'source_type':'controlled_exact_original','source_output_origin':'controlled_exact_original',
      'source_platform':'controlled_exact_original','source_model_invoked':False,'source_model_calls':0,
      'receiver_type':'real_commercial','receiver_platform':'hy3','receiver_model_metadata':result['metadata'],
      'answers':result['parsed']['scenarios']['raw']['answers'],'status':'ok','source_memory':payload['memory'],
      'source_memory_sha256':payload['memory_sha256'],'recipient_input_sha256':runtime.sha(request['prompt']),
      'receiver_inference_seconds':result['inference_wall_seconds'],'human_confirmed':False,
      'host_owned_raw_readback':True,'gold_in_context':False,
      'recovery':{'type':'safe_precreation_retry','original_session_id':check['original_session_id'],
        'fresh_session_id':new_session,'original_failure_preserved':True,'original_model_prompts_submitted':0,
        'check_path':str(proof),'inference_path':str(recovered_dir)}}
    runtime.save(recovered_dir/'effective_evaluation_records.json',[record])
    runtime.save(cell/'evaluation_records.json',[record])
    summary={'status':'completed','project_id':pid,'direction':direction,'repeat_index':repeat_index,
      'source_type':'controlled_exact_original','receiver_type':'real_commercial','source_model_calls':0,
      'recipient_inference_jobs':1,'scenario_count':1,'answer_fields':len(record['answers']),
      'metadata':result['metadata'],'completed_via_safe_precreation_retry':True,
      'first_attempt_completed':False,'first_failure_path':str(cell/'blocked.json'),
      'original_session_not_reused':True,'outer_attempts':2}
    runtime.save(cell/'complete.json',summary)
    print(json.dumps({k:v for k,v in summary.items()if k!='metadata'},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
