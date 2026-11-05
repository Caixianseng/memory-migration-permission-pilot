"""Resumable, bounded real bidirectional persistent-memory experiment.

Only model_runtime calls produce derived prose. SQLite operations are trusted
controller actions. Existing successful artifacts are immutable; unresolved
model attempts stop instead of being silently replaced.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import time
import traceback

from .model_runtime import generate_memory, write_json, digest, REPO
from .prepare_data import source_projection, permission_event, receiver_questions, direction_agents
from .store import AgentStore, TrustedPolicy, export_package, import_package, StoreError
from .source_registry import resolve_source_result, source_attempt_paths

HERE=Path(__file__).resolve().parent
DEFAULT_ROOT=REPO/'results/persistent_exchange_v1'
PLATFORMS={'A':'hy3','B':'flash'}
ARMS=('raw','whole_drop','full_rebuild','selective')


def load(path):return json.loads(Path(path).read_bytes())


def snapshot(path,body):
    """Atomic replace only for explicit progress files, never model artifacts."""
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(body,ensure_ascii=False,indent=2),encoding='utf-8')
    tmp.replace(path)


def material():
    cases=[json.loads(x)for x in (HERE/'data/cases.public.jsonl').read_text(encoding='utf-8').splitlines()]
    contract=load(HERE/'data/contract.json')
    for name,expected in contract['artifact_sha256'].items():
        if digest((HERE/'data'/name).read_bytes())!=expected:raise RuntimeError('frozen_material_changed:'+name)
    return cases,contract


def source_jobs(root,cases,phase):
    jobs=[]
    for case in cases:
        for agent in ('A','B'):
            full=[s['source_id']for s in case['agents'][agent]['sources']]
            groups=[('whole',full,2048)]+[('chunk'+str(i),ids,1024)for i,ids in enumerate(case['chunks'][agent])]
            direction=agent+'_to_'+('B'if agent=='A'else'A')
            allowed=set(permission_event(case,direction)['allowed'])
            for group,ids,budget in groups:
                if phase=='repair':
                    if set(ids)<=allowed:continue
                    ids=[sid for sid in ids if sid in allowed]
                    if not ids:continue
                job_dir=root/'source_jobs'/case['case_id']/agent/phase/group
                jobs.append({'case_id':case['case_id'],'agent':agent,'platform':PLATFORMS[agent],
                    'phase':phase,'group':group,'source_ids':ids,'sources':source_projection(case,agent,ids)['sources'],
                    'budget':budget,'job_dir':str(job_dir)})
    return jobs


def execute_source(job):
    folder=Path(job['job_dir']);result=folder/'result.json'
    if result.exists():
        old=load(result)
        if old['source_ids']!=job['source_ids']:raise RuntimeError('completed_source_input_changed')
        return old
    began=time.monotonic()
    memory,evidence=generate_memory(job['platform'],job['sources'],folder,max_output_tokens=job['budget'])
    value={k:v for k,v in job.items()if k!='sources'}
    value.update(memory=memory,evidence=evidence,wall_ms=(time.monotonic()-began)*1000)
    write_json(result,value)
    return value


def source_phase(root,cases,phase,workers):
    jobs=source_jobs(root,cases,phase)
    state={'phase':phase,'planned':len(jobs),'finished':0,'failed':0,'errors':[]}
    progress=root/(phase+'_progress.json');snapshot(progress,state)
    errors=[]
    with ThreadPoolExecutor(max_workers=workers)as pool:
        futures={pool.submit(execute_source,job):job for job in jobs}
        for future in as_completed(futures):
            job=futures[future]
            try:
                future.result();state['finished']+=1
            except Exception as exc:
                code=str(exc)
                # Only controlled exception codes reach progress; do not dump CLI stderr/credentials.
                state['failed']+=1;state['errors'].append({'case_id':job['case_id'],'agent':job['agent'],
                    'group':job['group'],'job_dir':job['job_dir'],'error':code[:250]})
                errors.append(job['job_dir'])
            snapshot(progress,state)
            print(json.dumps({'phase':phase,'finished':state['finished'],'failed':state['failed'],
                              'planned':state['planned']},ensure_ascii=False),flush=True)
    if errors:raise RuntimeError('unresolved_source_jobs:'+str(len(errors)))


def prepare_origins(root,cases):
    for case in cases:
        case_dir=root/'cases'/case['case_id'];case_dir.mkdir(parents=True,exist_ok=True)
        policy=TrustedPolicy(case_dir/'policy.sqlite')
        for agent in ('A','B'):
            store=AgentStore(case_dir/(agent+'.sqlite'),agent)
            records=[store.add_original(s['source_id'],s['text'],s['version'],s['origin'])for s in case['agents'][agent]['sources']]
            policy.register_sources(records);store.close()
        if not(case_dir/'t0.json').exists():
            ids=[s['source_id']for a in ('A','B')for s in case['agents'][a]['sources']]
            policy.set_permissions('A',ids);policy.set_permissions('B',ids)
            write_json(case_dir/'t0.json',{'epoch':policy.epoch,'initial_grants':'both all originals'})
        policy.close()


def store_generated(root,case,agent,phase,group,ids):
    cell=root/'source_jobs'/case['case_id']/agent/phase/group
    selected_file=resolve_source_result(cell)
    result=load(selected_file)
    if result['memory']is None and(cell/'provider_quota_evidence.json').exists():
        raise RuntimeError('unresolved_source_provider_quota_not_algorithm_zero')
    if set(result['source_ids'])!=set(ids):raise RuntimeError('generation_dependency_binding_changed')
    if result['memory']is None:
        if result['evidence'].get('source_protocol_conformance')is not False:raise RuntimeError('missing_source_without_closed_failure')
        return {'kind':'failed_source','memory_key':'FAILED-'+agent+'-'+group+'-'+phase,
                'memory_id':group+'-'+phase,'generated_memory_exists':False}
    store=AgentStore(root/'cases'/case['case_id']/(agent+'.sqlite'),agent)
    artifact=store.add_memory(group+'-'+phase,result['memory'],ids,provenance={
        'generator':PLATFORMS[agent],'model':PLATFORMS[agent],'evidence_hash':digest(json.dumps(result['evidence'],sort_keys=True,ensure_ascii=False))})
    store.close();return artifact


def withdraw(root,cases):
    for case in cases:
        case_dir=root/'cases'/case['case_id'];path=case_dir/'withdrawal.json'
        policy=TrustedPolicy(case_dir/'policy.sqlite')
        if not path.exists():
            for direction in ('A_to_B','B_to_A'):
                sender,recipient=direction_agents(direction);event=permission_event(case,direction)
                own=[s['source_id']for s in case['agents'][recipient]['sources']]
                policy.set_permissions(recipient,own+event['allowed'])
            write_json(path,{'epoch':policy.epoch,'events':[permission_event(case,d)for d in ('A_to_B','B_to_A')]})
        elif load(path)['epoch']!=policy.epoch:raise RuntimeError('postwithdrawal_policy_changed')
        policy.close()


def source_deliverable(result,job_dir):
    if result['evidence'].get('source_protocol_conformance',True)is False:return False
    if result['platform']!='hy3':return True
    job_dir=Path(job_dir);audit_file=job_dir/'native_source_shell_scope_audit.json'
    if not audit_file.exists():raise RuntimeError('native_source_shell_scope_audit_required_before_delivery')
    audit=load(audit_file);evidence=result['evidence']
    if not(audit.get('schema')=='native-source-shell-scope-audit-v1'
           and audit.get('source_result_sha256')==digest((job_dir/'result.json').read_bytes())
           and audit.get('session_id')==evidence['session_id']
           and audit.get('task_id')==evidence['task_id']
           and audit.get('artifact_sha256')==evidence['artifact_sha256']
           and type(audit.get('protocol_conformance'))is bool):
        raise RuntimeError('native_source_shell_scope_audit_binding_invalid')
    return audit['protocol_conformance']


def deliver(root,cases):
    manifest_path=root/'manifest.json'
    if manifest_path.exists():return load(manifest_path)
    withdraw(root,cases)
    records=[];case_metadata=[]
    for case in cases:
        case_dir=root/'cases'/case['case_id'];policy=TrustedPolicy(case_dir/'policy.sqlite')
        artifacts={}
        for agent in ('A','B'):
            full=[s['source_id']for s in case['agents'][agent]['sources']]
            artifacts[agent]={'whole':store_generated(root,case,agent,'initial','whole',full),'chunks':[]}
            for i,ids in enumerate(case['chunks'][agent]):
                artifacts[agent]['chunks'].append(store_generated(root,case,agent,'initial','chunk'+str(i),ids))
        case_metadata.append({'case_id':case['case_id'],'case_dir':str(case_dir),'policy_epoch':policy.epoch,
                              'origins':case['agents'],'artifacts':artifacts})
        for direction in ('A_to_B','B_to_A'):
            agent,recipient=direction_agents(direction);event=permission_event(case,direction)
            allowed=set(event['allowed']);all_ids=[s['source_id']for s in case['agents'][agent]['sources']]
            whole=artifacts[agent]['whole'];chunks=artifacts[agent]['chunks']
            rebuild=whole if set(all_ids)<=allowed else store_generated(root,case,agent,'repair','whole',event['allowed'])
            selective=[]
            for i,ids in enumerate(case['chunks'][agent]):
                legal=[sid for sid in ids if sid in allowed]
                if not legal:continue
                selective.append(chunks[i]if set(ids)<=allowed else store_generated(root,case,agent,'repair','chunk'+str(i),legal))
            sender=AgentStore(case_dir/(agent+'.sqlite'),agent)
            raw=[]
            for original in case['agents'][agent]['sources']:
                if original['source_id']in allowed:
                    raw.append(sender.add_memory('raw-'+original['source_id'],original['text'],[original['source_id']],kind='raw'))
            method_artifacts={'raw':raw,'whole_drop':[whole]if set(all_ids)<=allowed else[],
                              'full_rebuild':[rebuild],'selective':selective}
            for arm,selected in method_artifacts.items():
                rejected=[];usable=[]
                for artifact in selected:
                    if artifact['kind']=='failed_source':rejected.append(artifact['memory_key']);continue
                    if artifact['kind']=='raw':usable.append(artifact);continue
                    group,phase=artifact['memory_id'].rsplit('-',1)
                    source_dir=root/'source_jobs'/case['case_id']/agent/phase/group
                    selected_file=resolve_source_result(source_dir)
                    result=load(selected_file)
                    if source_deliverable(result,selected_file.parent):usable.append(artifact)
                    else:rejected.append(artifact['memory_key'])
                selected=usable
                folder=root/'receiver_jobs'/case['case_id']/direction/arm
                folder.mkdir(parents=True,exist_ok=True);delivery_file=folder/'delivery.json'
                batch_id=case['case_id']+'-'+direction+'-'+arm
                dependencies=[dep for a in selected for dep in a['dependencies']]
                policy.check_dependencies(recipient,dependencies)
                if delivery_file.exists():
                    delivery=load(delivery_file)
                else:
                    began=time.monotonic()
                    packet=export_package(sender,policy,recipient,[a['memory_key']for a in selected],batch_id=batch_id)
                    packet_file=folder/'transport.packet.json';write_json(packet_file,packet)
                    receiver=AgentStore(folder/'receiver.sqlite',recipient)
                    for s in case['agents'][recipient]['sources']:
                        receiver.add_original(s['source_id'],s['text'],s['version'],s['origin'])
                    receipt=import_package(receiver,policy,load(packet_file));receiver.close()
                    reopened=AgentStore(folder/'receiver.sqlite',recipient)
                    retrieved=reopened.retrieve(batch_id);reopened.close()
                    expected='\n\n'.join(a['content']for a in selected)
                    if retrieved['memory']!=expected:raise RuntimeError('post_close_reopen_memory_changed')
                    delivery={'receipt':receipt,'receiver_db':str(folder/'receiver.sqlite'),'batch_id':batch_id,
                        'policy_db':str(policy.path),'policy_epoch':policy.epoch,
                        'packet_path':str(packet_file),'packet_file_sha256':digest(packet_file.read_bytes()),
                        'packet_bytes':packet_file.stat().st_size,'content_bytes':len(expected.encode('utf-8')),
                        'memory_keys':[a['memory_key']for a in selected],'dependencies':dependencies,
                        'source_protocol_rejected_memory_keys':rejected,'source_protocol_clean':not rejected,
                        'reopened_content_sha256':digest(expected),'close_reopen_verified':True,
                        'export_import_reopen_ms':(time.monotonic()-began)*1000}
                    write_json(delivery_file,delivery)
                initial_groups=[]if arm=='raw'else(['whole']if arm in ('whole_drop','full_rebuild')else['chunk0','chunk1'])
                repair_groups=[]
                if arm=='full_rebuild'and set(all_ids)-allowed:repair_groups=['whole']
                if arm=='selective':repair_groups=['chunk'+str(i)for i,ids in enumerate(case['chunks'][agent])if set(ids)-allowed and set(ids)&allowed]
                jobs=[str(path)for phase,groups in (('initial',initial_groups),('repair',repair_groups))for group in groups
                      for path in source_attempt_paths(root/'source_jobs'/case['case_id']/agent/phase/group)]
                records.append({'case_id':case['case_id'],'direction':direction,'arm':arm,
                    'recipient':recipient,'receiver_platform':PLATFORMS[recipient],'job_dir':str(folder),
                    'delivery':delivery,'source_jobs':jobs,'timings':{'delivery_ms':delivery['export_import_reopen_ms']}})
            sender.close()
        policy.close()
    manifest={'schema':'persistent-exchange-run-v1','root':str(root),'cases':case_metadata,
              'main_records':records,'source_physical_results':sorted({str(path)for job in source_jobs(root,cases,'initial')+source_jobs(root,cases,'repair')
                  for path in source_attempt_paths(Path(job['job_dir']))}),
              'first_delivery_boundary':'receiver SQLite import commit','main_invocations_planned':len(records)}
    write_json(manifest_path,manifest);return manifest


def execute_receiver(record,evaluation):
    from .receiver_dispatch import answer_receiver
    folder=Path(record['job_dir']);path=folder/'scored_input.json'
    if path.exists():return load(path)
    delivery=record['delivery'];policy=TrustedPolicy(delivery['policy_db'])
    policy.check_dependencies(record['recipient'],delivery['dependencies'],delivery['policy_epoch']);policy.close()
    answers,evidence=answer_receiver(record['receiver_platform'],delivery['receiver_db'],delivery['batch_id'],
        receiver_questions(evaluation,record['case_id'],record['direction']),folder)
    completed={**record,'answers':answers,'receiver_evidence':evidence}
    write_json(path,completed);return completed


def receiver_phase(root,manifest,workers):
    evaluation=load(HERE/'data/evaluation_only.json');jobs=manifest['main_records']
    state={'phase':'receiver','planned':len(jobs),'finished':0,'failed':0,'errors':[]};records=[]
    with ThreadPoolExecutor(max_workers=workers)as pool:
        futures={pool.submit(execute_receiver,job,evaluation):job for job in jobs}
        for future in as_completed(futures):
            job=futures[future]
            try:records.append(future.result());state['finished']+=1
            except Exception as exc:
                state['failed']+=1;state['errors'].append({'job_dir':job['job_dir'],'error':str(exc)[:250]})
            snapshot(root/'receiver_progress.json',state)
            print(json.dumps(state|{'errors':[]}),flush=True)
    if state['failed']:raise RuntimeError('unresolved_receiver_jobs:'+str(state['failed']))
    records.sort(key=lambda r:(r['case_id'],r['direction'],r['arm']))
    write_json(root/'main_records.json',records)
    return records


def freeze(root,contract):
    path=root/'execution_freeze.json'
    files=['model_runtime.py','run_study.py','store.py','read_receiver.py']
    body={'contract_sha256':digest((HERE/'data/contract.json').read_bytes()),
          'source_runtime_sha256':{name:digest((HERE/name).read_bytes())for name in files},
          'source_model_assignment':PLATFORMS,'workers':4,'zero_model_outcomes_used_for_design':True,
          'scope':'source-generation and gateway frozen before main model calls; receiver and analysis separately sealed before their calls'}
    if path.exists():
        old=load(path)
        if old!=body:
            cursor=old
            amendments=[load(p)for p in root.glob('execution_amendment_*.json')]
            for _ in range(len(amendments)):
                matches=[a for a in amendments if a['before']==cursor]
                if not matches:break
                if len(matches)!=1:raise RuntimeError('ambiguous_execution_amendment_chain')
                cursor=matches[0]['after']
                if cursor==body:break
            if cursor!=body:raise RuntimeError('unapproved_frozen_execution_change')
    else:write_json(path,body)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=('initial','repair','deliver','receiver','analyze','all'),required=True)
    parser.add_argument('--root',type=Path,default=DEFAULT_ROOT);parser.add_argument('--workers',type=int,default=4)
    args=parser.parse_args();root=args.root.resolve();root.mkdir(parents=True,exist_ok=True)
    cases,contract=material();freeze(root,contract)
    if args.phase in ('initial','all'):prepare_origins(root,cases);source_phase(root,cases,'initial',args.workers)
    if args.phase in ('repair','all'):withdraw(root,cases);source_phase(root,cases,'repair',args.workers)
    if args.phase in ('deliver','all'):deliver(root,cases)
    if args.phase in ('receiver','all'):
        receiver_phase(root,load(root/'manifest.json'),args.workers)
    if args.phase in ('analyze','all'):
        from .evaluate import evaluate
        result=evaluate(load(root/'main_records.json'),load(HERE/'data/evaluation_only.json'))
        write_json(root/'evaluation.json',result)
    print(json.dumps({'status':'phase_complete','phase':args.phase}),flush=True)


if __name__=='__main__':main()
