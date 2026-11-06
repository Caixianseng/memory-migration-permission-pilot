"""Real generated artifacts -> five persistent handoffs -> real recipient QA.

The Host owns SQLite; commercial models are fresh zero-tool inference sessions.
Equal verified recipient inputs share one model answer, never extra sample n.
"""
from __future__ import annotations
import argparse,json,sqlite3,subprocess,time,traceback
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from . import dataset_gold as data
from .live_runtime import OUT,ROOT,infer,save,load,sha
from experiments.persistent_exchange_v1 import store
from experiments.paper_final_v1 import durable_delivery

SCENARIOS=data.SCENARIOS
METHODS=('A_file','B_static_hash','C_dynamic_precheck','D_transaction','E_host')
RUN_ID='qualification_isolated_v1'
def persist_case(case,project,direction,r,initial,legal,source_meta):
    path=case/'persistent';resuming=path.exists();path.mkdir(exist_ok=True)
    sender_id,recipient_id=('A','B') if direction=='A_to_B' else ('B','A')
    sender=store.AgentStore(path/'sender.sqlite',sender_id);policy=store.TrustedPolicy(path/'authority.sqlite')
    originals=[sender.add_original(s['source_id'],s['text']) for s in project['sources']]
    all_ids=[s['source_id'] for s in originals]
    if not resuming:
        policy.register_sources(originals)
        policy.set_permissions(recipient_id,all_ids)
    else:
        # Only the source-generation failure before the first effect is resumable
        # here. Never reset grants or create a fresh authority on a partial run.
        if not (path/'permission_events.json').exists():raise RuntimeError('partial_host_state_not_resumable')
    receipts=[];packets={};receivers={}
    # Actual generated initial artifacts conservatively depend on ALL seen input.
    for scenario in SCENARIOS:
        sender.add_memory(scenario+'-initial',initial[scenario],source_ids=all_ids,
                          provenance={'execution':'real_model','observed_input_scope':'all_supplied_sources'})
    for method in ('D_transaction','E_host'):
        receivers[method]=store.AgentStore(path/(method+'.sqlite'),recipient_id)
        if resuming and receivers[method].db.execute('SELECT COUNT(*) FROM batches').fetchone()[0]:
            raise RuntimeError('partial_host_effect_requires_separate_recovery')
        for scenario in SCENARIOS:
            batch=method+'-'+scenario+'-initial'
            if not resuming:
                packets[method,scenario]=store.export_package(sender,policy,recipient_id,[scenario+'-initial'],batch_id=batch)
            else:
                seal=policy.db.execute('SELECT * FROM seals WHERE batch_id=?',(batch,)).fetchone()
                if seal is None or seal['consumed_by'] is not None:raise RuntimeError('original_seal_not_resumable')
                artifact=sender.get_memory(scenario+'-initial')
                packet={'schema':store.SCHEMA,'import_id':seal['import_id'],'nonce':seal['nonce'],
                    'batch_id':batch,'sender_id':sender_id,'recipient_id':recipient_id,'epoch':seal['epoch'],
                    'memories':[artifact],'lineage':store._lineage(sender,[artifact]),'sources':artifact['dependencies']}
                packet['content_sha256']=store.digest(packet)
                if packet['content_sha256']!=seal['packet_sha256']:raise RuntimeError('reconstructed_original_packet_not_identical')
                packets[method,scenario]=packet
    safe_ids=project['permission_timeline'][1]['receiver_allowed_source_ids']
    old_epoch=policy.epoch
    if not resuming:policy.set_permissions(recipient_id,safe_ids)
    new_epoch=policy.epoch
    if resuming:
        recorded=load(path/'permission_events.json')
        grants=[row[0] for row in policy.db.execute('SELECT source_id FROM grants WHERE recipient_id=? ORDER BY source_id',(recipient_id,))]
        if grants!=sorted(safe_ids) or new_epoch!=recorded['revocation_epoch']:raise RuntimeError('resume_current_authority_changed')
        if not (path/'resume_original_authority.json').exists():save(path/'resume_original_authority.json',{
            'original_authority_reused':True,'grants_reset':False,'prior_receiver_effects':0,
            'original_packet_digest_matched_durable_seal':True,'epoch':new_epoch})
    else:save(path/'permission_events.json',{'after_real_generation':True,'before_first_delivery':True,
          'initial_epoch':old_epoch,'revocation_epoch':new_epoch,'initial_allowed':all_ids,
          'current_allowed':safe_ids,'revoked':sorted(set(all_ids)-set(safe_ids)),
          'source_execution':source_meta})
    # The actual SQLite revocation above precedes the legal-source invocation.
    if callable(legal):legal=legal()
    actual={}
    for phase,texts,scope in (('initial',initial,all_ids),('legal_successor',legal,safe_ids)):
        if phase=='legal_successor':
            for scenario in SCENARIOS:
                sender.add_memory(scenario+'-legal',texts[scenario],source_ids=safe_ids,
                                  provenance={'execution':'real_model_on_authorized_sources'})
        for method in METHODS:
            arm=path/method;arm.mkdir(exist_ok=True)
            for scenario in SCENARIOS:
                t=time.perf_counter();accepted=False;error=None;batch=None
                try:
                    if method in ('A_file','B_static_hash'):
                        # B validates initial, static grant snapshot and content hash.
                        if method=='B_static_hash':
                            assert set(scope)<=set(all_ids)
                            save(arm/f'{phase}.{scenario}.integrity.json',{'sha256':sha(texts[scenario]),'static_grant_ids':all_ids})
                        (arm/f'{phase}.{scenario}.txt').write_text(texts[scenario],encoding='utf-8')
                        accepted=True
                    elif method=='C_dynamic_precheck':
                        artifact=sender.get_memory(scenario+('-initial' if phase=='initial' else '-legal'))
                        policy.validate_dependencies(recipient_id,artifact['dependencies'],expected_epoch=policy.epoch)
                        # Nonatomic disk write intentionally retained, same as CPU baseline.
                        (arm/f'{phase}.{scenario}.txt').write_text(texts[scenario],encoding='utf-8');accepted=True
                    else:
                        if phase=='initial':packet=packets[method,scenario]
                        else:packet=store.export_package(sender,policy,recipient_id,[scenario+'-legal'],batch_id=method+'-'+scenario+'-legal')
                        batch=packet['batch_id'];save(arm/f'{phase}.{scenario}.packet.json',packet)
                        receipt=durable_delivery.deliver(receivers[method],policy,packet)
                        save(arm/f'{phase}.{scenario}.receipt.json',receipt);accepted=True
                except store.StoreError as e:error=str(e)
                record={'project_id':project['project_id'],'direction':direction,'repeat_index':r,
                    'scenario':scenario,'method':method,'phase':phase,'accepted':accepted,
                    'error':error,'batch_id':batch,'host_processing_ms':(time.perf_counter()-t)*1000,
                    'dependency_scope':scope,'policy_epoch':policy.epoch,
                    'contains_revoked_scope':bool(set(scope)-set(safe_ids)),
                    'source_type':'real_commercial_model_generated','delivery_storage':'Host-owned files/SQLite'}
                receipts.append(record)
    sender.close();policy.close()
    for receiver in receivers.values():receiver.close()
    # Close/reopen in a separate process before supplying any QA input.
    request={'path':str(path),'recipient_id':recipient_id,'scenarios':list(SCENARIOS)}
    save(path/'readback_request.json',request)
    p=subprocess.run(['D:/python3.11/python.exe','-m','experiments.paper_live_v2.live_study',
                      '--readback',str(path/'readback_request.json')],cwd=ROOT,capture_output=True,text=True,encoding='utf-8',timeout=60)
    save(path/'readback_process.json',{'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    if p.returncode:raise RuntimeError('persistent_readback_failed')
    actual=load(path/'readback.json')
    save(case/'delivery_records.json',receipts)
    return actual,receipts

def readback(request_path):
    req=load(request_path);p=Path(req['path']);out={'initial':{},'legal_successor':{}}
    for phase in out:
        for method in METHODS:
            texts={}
            for scenario in req['scenarios']:
                if method in ('D_transaction','E_host'):
                    db=store.AgentStore(p/(method+'.sqlite'),req['recipient_id'])
                    try:
                        batch=method+'-'+scenario+('-initial' if phase=='initial' else '-legal')
                        exists=db.db.execute('SELECT 1 FROM batches WHERE batch_id=?',(batch,)).fetchone()
                        if exists:texts[scenario]=db.retrieve(batch)['memory']
                    finally:db.close()
                else:
                    f=p/method/f'{phase}.{scenario}.txt'
                    if f.exists():texts[scenario]=f.read_text(encoding='utf-8')
            out[phase][method]=texts
    save(p/'readback.json',out)

def run_case(pid,direction,r):
    case=OUT/'raw_experiment_data'/RUN_ID/f'{pid}.{direction}.r{r}'
    case.mkdir(parents=True,exist_ok=True)
    if (case/'complete.json').exists():return load(case/'complete.json')
    try:
        src,dst=('hy3','flash') if direction=='A_to_B' else ('flash','hy3')
        generated={};source_meta={}
        def generate_phase(phase):
            req=data.source_request(pid,direction,r,phase)
            # Same compact contract on both platforms; source IDs remain assertions.
            prompt=req['prompt']+'\n执行补充：每种 memory_text 务必保留输入全部关键事实和推导结果，尽量在250汉字内；claims统一返回空数组[]，实际输入来源由Host独立记录。不输出额外键。'
            result=infer(src,prompt,case/('source_'+phase),'source')
            if result['status']!='ok':raise RuntimeError('source_failed:'+result.get('error','unknown'))
            generated[phase]={s:result['parsed']['scenarios'][s]['memory_text'] for s in SCENARIOS}
            if not all(isinstance(t,str) and t.strip() for t in generated[phase].values()):raise ValueError('empty_generated_memory')
            source_meta[phase]=result['metadata']
            return generated[phase]
        generate_phase('initial_generation')
        # Permissions are applied to the already-generated initial artifact. The
        # successor was generated with disjoint fresh native/SDK context and only
        # currently authorized inputs, never by redacting the unsafe prose.
        if (case/'persistent/readback.json').exists() and (case/'delivery_records.json').exists():
            # Existing persistent effects are read; they are never recommitted
            # merely to finish a locally failed model-output parser.
            generate_phase('legal_rebuild')
            actual=load(case/'persistent/readback.json');receipts=load(case/'delivery_records.json')
        else:
            actual,receipts=persist_case(case,data.load_project(pid),direction,r,
                generated['initial_generation'],lambda:generate_phase('legal_rebuild'),source_meta)
        if actual['initial']['A_file']!=actual['initial']['B_static_hash']:raise RuntimeError('unsafe_baseline_readback_diverged')
        if any(actual['initial'][m] for m in METHODS[2:]):raise RuntimeError('unexpected_protected_initial_persistence')
        if any(actual['legal_successor'][m]!=actual['legal_successor']['E_host'] for m in METHODS):raise RuntimeError('legal_readback_diverged')
        answers=[]
        for phase,representative,equivalent in (('initial','A_file',['A_file','B_static_hash']),
                ('legal_successor','E_host',list(METHODS))):
            for scenario in SCENARIOS:
                req=data.receiver_request(pid,direction,r,actual[phase][representative],scenarios=(scenario,))
                result=infer(dst,req['prompt'],case/('receiver_'+phase+'_'+scenario),'target',scenarios=(scenario,))
                if result['status']!='ok':raise RuntimeError('receiver_failed:'+result.get('error','unknown'))
                answers.append({'project_id':pid,'direction':direction,'repeat_index':r,'scenario':scenario,
                    'run_id':RUN_ID,'source_model_metadata':source_meta,
                    'phase':phase,'answers':result['parsed']['scenarios'][scenario]['answers'],
                    'status':'ok','source_memory':actual[phase][representative][scenario],
                    'source_platform':src,'receiver_platform':dst,'receiver_model_metadata':result['metadata'],
                    'equivalent_methods':equivalent,'inference_reused_for_identical_verified_input':True,
                    'source_output_origin':'real_commercial_model','human_confirmed':False,
                    'recipient_input_sha256':sha(req['prompt']),'receiver_inference_seconds':result['inference_wall_seconds']})
        save(case/'evaluation_records.json',answers)
        result={'status':'completed','project_id':pid,'direction':direction,'repeat_index':r,
                'source_model':source_meta,'recipient_answer_rows':len(answers),'delivery_rows':len(receipts),
                'commercial_inference_jobs':8,'safe_successor_model_generated':True,
                'raw_definition':'model-generated factual restatement; exact original source transfer is a separate deterministic reference',
                'host_controls_persistence':True,'native_model_direct_sqlite_access':False}
        save(case/'complete.json',result)
    except Exception as e:
        result={'status':'blocked','project_id':pid,'direction':direction,'repeat_index':r,
                'error':str(e),'type':type(e).__name__,'time_unix':time.time()}
        f=case/'blocked.json'
        if not f.exists():save(f,result)
    print(json.dumps({k:result[k] for k in ('status','project_id','direction','repeat_index','error') if k in result},ensure_ascii=False),flush=True)
    return result

def main():
    global RUN_ID
    a=argparse.ArgumentParser();a.add_argument('--readback',type=Path);a.add_argument('--run-id',default=RUN_ID);a.add_argument('--projects',nargs='*');a.add_argument('--repeats',nargs='*',type=int,default=[0,1,2]);a.add_argument('--workers',type=int,default=4);args=a.parse_args()
    if args.readback:return readback(args.readback)
    RUN_ID=args.run_id
    projects=args.projects or list(load(data.OUT/'projects.json'))
    jobs=[(p,d,r) for p in projects for r in args.repeats for d in data.DIRECTIONS]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures=[pool.submit(run_case,*j) for j in jobs]
        results=[f.result() for f in as_completed(futures)]
    print(json.dumps({'finished':len(results),'completed':sum(x['status']=='completed' for x in results),'blocked':sum(x['status']=='blocked' for x in results)},ensure_ascii=False),flush=True)
if __name__=='__main__':main()
