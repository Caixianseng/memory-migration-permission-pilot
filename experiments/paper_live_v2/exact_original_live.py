"""Exact controlled source text -> persistent Host -> fresh real receiver QA.

No source-model generation occurs. Default preparation does not call a model;
real inference requires --execute-real and the parent's scheduling instruction.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from experiments.paper_live_v2 import dataset_gold as data
from experiments.paper_live_v2 import live_runtime as runtime
from experiments.persistent_exchange_v1 import store
from experiments.paper_final_v1 import durable_delivery

OUT=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/exact_original_live'
SDK_ROOT=ROOT/'.tmp/eosdk'


def digest(value):
    raw=value if isinstance(value,bytes)else json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf8')
    return hashlib.sha256(raw).hexdigest()


def readback(cell):
    request=runtime.load(cell/'readback_request.json')
    receiver=store.AgentStore(cell/'persistent/receiver.sqlite',request['recipient_id'])
    try:result=receiver.retrieve(request['batch_id'])
    finally:receiver.close()
    if result['memory'].encode('utf8')!=request['expected_legal_raw_utf8'].encode('utf8'):
        raise RuntimeError('exact_original_bytes_changed_on_readback')
    runtime.save(cell/'readback.json',{'memory':result['memory'],'memory_sha256':digest(result['memory'].encode('utf8')),
       'source_type':'controlled_exact_original','receiver_type':'real_commercial',
       'query_receipt':result['query_receipt'],'read_in_separate_process':True,'closed_and_reopened':True})


def prepare_case(pid,direction,repeat_index):
    project=data.load_project(pid)
    source_hash=digest(project)
    cell=OUT/f'{pid}.{direction}.r{repeat_index}';cell.mkdir(parents=True,exist_ok=True)
    contract={'project_id':pid,'direction':direction,'repeat_index':repeat_index,
      'project_data_sha256':source_hash,'representation':'exact_original_memory_transfer',
      'source_type':'controlled_exact_original','source_model_invoked':False,'scenarios':['raw'],
      'receiver_type':'real_commercial','gold_in_model_context':False}
    existing=cell/'prepared.json'
    if existing.exists():
        previous=runtime.load(existing)
        if previous['contract']!=contract:raise RuntimeError('prepared_exact_original_contract_changed')
        return cell,project,runtime.load(cell/'readback.json')
    if (cell/'prepare_intent.json').exists():
        raise RuntimeError('partial_exact_original_preparation_requires_audit_not_automatic_overwrite')
    runtime.save(cell/'prepare_intent.json',{'contract':contract,'unix':time.time()})
    persistent=cell/'persistent';persistent.mkdir()
    sender_id,recipient_id=('A','B')if direction=='A_to_B'else('B','A')
    sender=store.AgentStore(persistent/'sender.sqlite',sender_id)
    receiver=store.AgentStore(persistent/'receiver.sqlite',recipient_id)
    policy=store.TrustedPolicy(persistent/'authority.sqlite')
    try:
        originals=[];all_memory_ids=[];by_source={}
        for index,source in enumerate(project['sources']):
            originals.append(sender.add_original(source['source_id'],source['text']))
            mid=f'exact-raw-{index:02d}';all_memory_ids.append(mid);by_source[source['source_id']]=mid
            sender.add_memory(mid,source['text'],source_ids=[source['source_id']],kind='raw',
                              provenance={'generator':'controlled_exact_original','attempt_id':f'{pid}-{direction}-r{repeat_index}'})
        policy.register_sources(originals)
        all_ids=[source['source_id']for source in project['sources']]
        policy.set_permissions(recipient_id,all_ids)
        all_packet=store.export_package(sender,policy,recipient_id,all_memory_ids,batch_id='exact-all-before-revoke')
        runtime.save(persistent/'all_before_revocation.packet.json',all_packet)
        epoch_before=policy.epoch
        allowed=project['permission_timeline'][1]['receiver_allowed_source_ids']
        policy.set_permissions(recipient_id,allowed)
        runtime.save(persistent/'permission_events.json',{'initial_epoch':epoch_before,'revocation_epoch':policy.epoch,
           'initial_allowed_source_ids':all_ids,'allowed_source_ids':allowed,'revoked_source_ids':sorted(set(all_ids)-set(allowed)),
           'before_receiver_first_commit':True,'source_generation':'none; exact controlled source bytes'})
        try:
            durable_delivery.deliver(receiver,policy,all_packet)
        except store.StoreError as exc:denied={'status':'rejected','reason':str(exc),'actual_receiver_batches':receiver.db.execute('SELECT count(*) FROM batches').fetchone()[0]}
        else:raise RuntimeError('restricted_full_original_packet_was_not_rejected')
        if denied['actual_receiver_batches']!=0:raise RuntimeError('forbidden_packet_persisted_before_rejection')
        runtime.save(persistent/'all_packet_rejection.json',denied)
        safe_sources=[s for s in project['sources']if s['source_id']in set(allowed)]
        safe_ids=[by_source[s['source_id']]for s in safe_sources]
        packet=store.export_package(sender,policy,recipient_id,safe_ids,batch_id='exact-legal-raw')
        runtime.save(persistent/'legal_raw.packet.json',packet)
        receipt=durable_delivery.deliver(receiver,policy,packet)
        runtime.save(persistent/'legal_raw.commit_receipt.json',receipt)
        expected='\n\n'.join(source['text']for source in safe_sources)
    finally:sender.close();receiver.close();policy.close()
    runtime.save(cell/'readback_request.json',{'recipient_id':recipient_id,'batch_id':'exact-legal-raw','expected_legal_raw_utf8':expected})
    result=subprocess.run([sys.executable,'-B','-X','utf8','-m','experiments.paper_live_v2.exact_original_live',
                           '--readback',str(cell)],cwd=ROOT,capture_output=True,text=True,encoding='utf8',timeout=60)
    runtime.save(cell/'readback_process.json',{'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
    if result.returncode:raise RuntimeError('exact_original_independent_readback_failed')
    payload=runtime.load(cell/'readback.json')
    if payload['memory'].encode('utf8')!=expected.encode('utf8'):raise RuntimeError('not_exact_original_source_text')
    runtime.save(existing,{'contract':contract,'memory_sha256':payload['memory_sha256'],
                          'all_packet_rejected_before_commit':True,'legal_raw_committed':True,
                          'source_model_calls':0,'recipient_model_calls':0,'status':'host_prepared_only'})
    return cell,project,payload


def run_case(pid,direction,repeat_index,execute_real=False,sdk_root=SDK_ROOT):
    cell,project,payload=prepare_case(pid,direction,repeat_index)
    if not execute_real:return {'status':'prepared','project_id':pid,'direction':direction,'repeat_index':repeat_index,'commercial_calls':0}
    completed=cell/'complete.json'
    if completed.exists():return runtime.load(completed)
    receiver_platform='flash'if direction=='A_to_B'else'hy3'
    request=data.receiver_request(pid,direction,repeat_index,{'raw':payload['memory']},scenarios=('raw',))
    # The common projection includes public question text only. These scoring
    # field names must never appear in the model-facing serialized request.
    if any(key in request['prompt']for key in ('expected_answer','withheld_reference_value','minimal_support_sets')):
        raise RuntimeError('gold_field_detected_in_receiver_context')
    runtime.save(cell/'receiver_request.json',request)if not(cell/'receiver_request.json').exists()else None
    token=hashlib.sha256(f'exact-raw:{pid}:{direction}:r{repeat_index}'.encode('ascii')).hexdigest()[:12]
    short_ledger=Path(sdk_root)/token
    kwargs={'scenarios':('raw',)}
    if receiver_platform=='flash':
        if 'sdk_ledger_dir'not in inspect.signature(runtime.infer).parameters:
            raise RuntimeError('runtime_short_sdk_ledger_parameter_not_yet_available')
        kwargs['sdk_ledger_dir']=short_ledger
    result=runtime.infer(receiver_platform,request['prompt'],cell/'receiver_raw','target',**kwargs)
    if result['status']!='ok':
        blocked={'status':'blocked','project_id':pid,'direction':direction,'repeat_index':repeat_index,
                 'source_type':'controlled_exact_original','receiver_type':'real_commercial','error':result.get('error'),
                 'automatic_retry':False,'source_model_calls':0,'recipient_result':str(cell/'receiver_raw/result.json')}
        if not(cell/'blocked.json').exists():runtime.save(cell/'blocked.json',blocked)
        return blocked
    answers=result['parsed']['scenarios']['raw']['answers']
    record={'project_id':pid,'direction':direction,'repeat_index':repeat_index,'scenario':'raw',
       'phase':'exact_original_raw','method':'exact_original_memory_transfer','equivalent_methods':['exact_original_memory_transfer'],
       'source_type':'controlled_exact_original','source_output_origin':'controlled_exact_original',
       'source_platform':'controlled_exact_original','source_model_invoked':False,'source_model_calls':0,
       'receiver_type':'real_commercial','receiver_platform':receiver_platform,'receiver_model_metadata':result['metadata'],
       'answers':answers,'status':'ok','source_memory':payload['memory'],'source_memory_sha256':payload['memory_sha256'],
       'recipient_input_sha256':runtime.sha(request['prompt']),'receiver_inference_seconds':result['inference_wall_seconds'],
       'human_confirmed':False,'host_owned_raw_readback':True,'gold_in_context':False}
    runtime.save(cell/'evaluation_records.json',[record])
    summary={'status':'completed','project_id':pid,'direction':direction,'repeat_index':repeat_index,
       'source_type':'controlled_exact_original','receiver_type':'real_commercial','source_model_calls':0,
       'recipient_inference_jobs':1,'scenario_count':1,'answer_fields':len(answers),'metadata':result['metadata']}
    runtime.save(completed,summary)
    print(json.dumps({k:summary[k]for k in ('status','project_id','direction','repeat_index')},ensure_ascii=False),flush=True)
    return summary


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--execute-real',action='store_true')
    parser.add_argument('--projects',nargs='*');parser.add_argument('--repeats',type=int,nargs='*',default=[0,1,2])
    parser.add_argument('--workers',type=int,default=1);parser.add_argument('--sdk-root',type=Path,default=SDK_ROOT)
    parser.add_argument('--readback',type=Path);args=parser.parse_args()
    if args.readback:return readback(args.readback)
    projects=args.projects or list(runtime.load(data.OUT/'projects.json'))
    jobs=[(pid,direction,r)for pid in projects for r in args.repeats for direction in data.DIRECTIONS]
    if any(r not in (0,1,2)for r in args.repeats):raise SystemExit('repeat index outside fixed design')
    manifest={'schema':'controlled-exact-original-real-receiver-reference-v1','source_type':'controlled_exact_original',
       'receiver_type':'real_commercial','source_model_calls':0,'expected_receiver_jobs':len(jobs),
       'scenario_count':1,'scenarios':['raw'],'project_ids':projects,'directions':list(data.DIRECTIONS),
       'repeats':args.repeats,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
       'execution_mode':'execute_real'if args.execute_real else'host_preparation_only',
       'full_design':len(projects)==10 and args.repeats==[0,1,2],
       'retries':'no automatic model dispatch retry; infer reserves each job once',
       'scope':'exact original controlled source facts, not model-generated raw restatement'}
    OUT.mkdir(parents=True,exist_ok=True)
    label='execute_manifest.json'if args.execute_real else'prepare_manifest.json'
    if not(OUT/label).exists():runtime.save(OUT/label,manifest)
    elif runtime.load(OUT/label)!=manifest:raise RuntimeError('exact_original_run_manifest_changed')
    def safe_case(job):
        try:return run_case(*job,args.execute_real,args.sdk_root)
        except Exception as exc:
            pid,direction,r=job;cell=OUT/f'{pid}.{direction}.r{r}';cell.mkdir(parents=True,exist_ok=True)
            blocked={'status':'blocked','project_id':pid,'direction':direction,'repeat_index':r,
                     'source_type':'controlled_exact_original','receiver_type':'real_commercial',
                     'error':str(exc),'error_type':type(exc).__name__,'automatic_retry':False,
                     'source_model_calls':0,'unix':time.time()}
            error_path=cell/'local_exception.json'
            if not error_path.exists():runtime.save(error_path,blocked)
            print(json.dumps(blocked,ensure_ascii=False),flush=True)
            return blocked
    with ThreadPoolExecutor(max_workers=args.workers)as pool:
        futures=[pool.submit(safe_case,job)for job in jobs]
        results=[future.result()for future in as_completed(futures)]
    print(json.dumps({'jobs':len(results),'completed':sum(r['status']=='completed'for r in results),
       'prepared_only':sum(r['status']=='prepared'for r in results),'blocked':sum(r['status']=='blocked'for r in results),
       'source_model_calls':0,'real_calls_authorized_mode':args.execute_real},ensure_ascii=False),flush=True)


if __name__=='__main__':main()
