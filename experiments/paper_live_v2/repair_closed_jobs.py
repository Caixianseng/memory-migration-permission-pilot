"""Resume only terminal cases; retain failures and never replay unknown calls."""
import argparse,hashlib,json,time
from pathlib import Path
from .live_runtime import OUT,ROOT,load,save,infer
from .recover_records import recover
from . import live_study

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--execute-known-zero-retries',action='store_true');args=ap.parse_args()
    root=OUT/'raw_experiment_data/qualification_isolated_v1';rows=[]
    for case in sorted(root.iterdir()):
        if not case.name.startswith('LIVE-') or not (case/'blocked.json').exists() or (case/'complete.json').exists():continue
        for job in list(case.iterdir()):
            if not (job/'result.json').exists() or load(job/'result.json').get('status')!='failed':continue
            cp=load(job/'contract.json');role=cp['role'];scenarios=cp['scenarios']
            if (job/'local_parse_recovery.json').exists():continue
            rr=recover(job,role,scenarios)
            if rr is not None:
                save(job/'local_parse_recovery.json',rr);rows.append({'job':str(job),'action':'local_lossless_parse','new_calls':0});continue
            native_file=job/'native/envelope.json'
            if cp['platform']=='hy3' and native_file.exists():
                env=load(native_file);execution=env.get('nativeExecution') or {}
                if (execution.get('modelPromptsSubmitted')==0 and execution.get('promptSendAttempted') is False
                        and execution.get('stage')=='creating_fresh_session'):
                    input_job=load(job/'native/input.json');sid=input_job['sessionId']
                    db=__import__('sqlite3').connect('file:[USER_HOME]/.workbuddy/workbuddy.db?mode=ro',uri=True)
                    try:registered=db.execute('SELECT id,cwd,model,status FROM sessions WHERE id=?',(sid,)).fetchall()
                    finally:db.close()
                    histories=list(Path('[USER_HOME]/.workbuddy/projects').glob('*/'+sid+'.jsonl'))
                    user_count=0
                    for h in histories:
                        for line in h.read_bytes().splitlines():
                            record=json.loads(line)
                            if record.get('type')=='message' and record.get('role')=='user':user_count+=1
                    if user_count:continue
                    inspection={'original_envelope_sha256':hashlib.sha256(native_file.read_bytes()).hexdigest(),
                        'original_session_id':sid,'registered_own_session_metadata':registered,'own_history_files':len(histories),
                        'own_user_message_count':0,'original_prompt_send_attempted':False,'original_model_prompts_submitted':0,
                        'source_of_zero_send':'verified helper returned before sendMessage branch; original native records read only',
                        'old_session_reused_for_send':False,'observed_unix':time.time()}
                    if not (job/'precreation_failure_inspection.json').exists():save(job/'precreation_failure_inspection.json',inspection)
                    if args.execute_known_zero_retries:
                        rr=infer('hy3',cp['prompt'],job/'safe_precreation_retry',role,scenarios=scenarios)
                        rows.append({'job':str(job),'action':'fresh_reserved_session_after_verified_zero_prompt','status':rr['status']})
            pointer=load(job/'sdk_ledger_pointer.json') if (job/'sdk_ledger_pointer.json').exists() else None
            ledger=Path(pointer['path']) if pointer else job/'sdk.private';sdk=ledger/'job-inference'
            if cp['platform']=='flash' and (sdk/'guard.json').exists() and (sdk/'account_metadata.private.json').exists():
                guard=load(sdk/'guard.json');metadata=load(sdk/'account_metadata.private.json')
                if (guard.get('agent_attempt_count')==guard.get('stream_attempt_count')==guard.get('allowed_stream_count')==0
                        and metadata.get('model_requests')==0 and metadata.get('status')=='unavailable'):
                    inspection={'original_guard_sha256':hashlib.sha256((sdk/'guard.json').read_bytes()).hexdigest(),
                        'original_receipt_sha256':hashlib.sha256((sdk/'receipt.json').read_bytes()).hexdigest(),
                        'account_stage':metadata.get('stage'),'model_requests':0,'allowed_stream_count':0,
                        'original_failure_preserved':True,'reason':'transient official account metadata; no model dispatch',
                        'account_readiness_preflight':'preflight/harness_account_readiness_after_failure.json'}
                    if not (job/'account_predispatch_failure_inspection.json').exists():save(job/'account_predispatch_failure_inspection.json',inspection)
                    if args.execute_known_zero_retries:
                        rr=infer('flash',cp['prompt'],job/'safe_predispatch_retry',role,scenarios=scenarios)
                        rows.append({'job':str(job),'action':'fresh_sdk_after_guard_proved_zero_model_requests','status':rr['status']})
            if cp['platform']=='flash' and (sdk/'receipt.json').exists() and not (sdk/'runtime.json').exists() and not (sdk/'guard.json').exists() and not (sdk/'response.json').exists():
                credential_destination=sdk/'home.private/.credentials.yaml'
                # The frozen SDK function persists runtime.json BEFORE creating
                # the only model-capable child process. No runtime receipt plus
                # this reproduced >259-character path is a pre-dispatch failure.
                if len(str(credential_destination.resolve()))<=259:continue
                inspection={'original_receipt_sha256':hashlib.sha256((sdk/'receipt.json').read_bytes()).hexdigest(),
                    'original_error':load(sdk/'receipt.json')['error'],'destination_path_characters':len(str(credential_destination.resolve())),
                    'sdk_runtime_file_missing':True,'sdk_guard_file_missing':True,'sdk_response_missing':True,
                    'ordering_evidence':'sdk_adapter._exchange writes runtime.json before subprocess.Popen and any session/prompt',
                    'physical_requests_in_original_attempt_from_trusted_ordering':0,
                    'original_failure_preserved':True,'observed_unix':time.time()}
                if not (job/'predispatch_failure_inspection.json').exists():save(job/'predispatch_failure_inspection.json',inspection)
                if args.execute_known_zero_retries:
                    rr=infer('flash',cp['prompt'],job/'safe_predispatch_retry',role,scenarios=scenarios)
                    rows.append({'job':str(job),'action':'new_short_path_attempt_after_proven_zero_request','status':rr['status']})
        pid,direction,repeat=case.name.split('.')
        # run_case uses cached verified inference, persisted effects and readback.
        result=live_study.run_case(pid,direction,int(repeat[1:]))
        rows.append({'case':case.name,'resumed_status':result['status'],'error':result.get('error')})
    dest=root/('recovery_pass_'+str(time.time_ns())+'.json');save(dest,rows)
    print(json.dumps({'receipt':str(dest),'operations':rows},ensure_ascii=False),flush=True)
if __name__=='__main__':main()
