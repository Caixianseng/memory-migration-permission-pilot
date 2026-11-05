"""Bounded real factorial confirmation on first four reserved Hotpot questions.

All 17 arms and all three policy states retained. No automatic retry. Neither
answers nor support annotations are read by the executing controller.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import secrets
import time

from .fusion_pipeline import ARMS, FusionPipeline
from .reranker_runtime import TinyBERTReranker
from .context_adapter import deliver
from .run_offline import CONFIG, hashes as module_hashes
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, save
from experiments.revocation_grouping_v1.lifecycle_runner import target_messages
from experiments.revocation_grouping_v1.sdk_adapter import FlashSDKClient, usage_costs
from experiments.revocation_prefix_v1.cache_qualification import native_isolation

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashes():
    return {**module_hashes(),'run_native.py':sha(__file__),
        'sdk_adapter.py':sha(REPO/'experiments/revocation_grouping_v1/sdk_adapter.py'),
        'guard.mjs':sha(REPO/'experiments/revocation_grouping_v1/dsh_group_guard.mjs'),
        'model_manifest':sha(HERE/'reranker_assets/manifest.json')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case-count',type=int,default=4,choices=[1,2,3,4])
    args=parser.parse_args()
    output=args.output.absolute()
    if output.exists():
        raise ValueError('fresh_output_required_no_resume_or_retry')
    data=HERE/'data_hotpot'
    cases=[json.loads(line) for line in (data/'cases.public.jsonl').read_text(encoding='utf-8').splitlines()]
    cases=[case for case in cases if case['split']=='reserved'][:args.case_count]
    schedules=json.loads((data/'schedules.json').read_text(encoding='utf-8'))
    target_prompt=json.loads((REPO/'experiments/revocation_grouping_v1/workload_contract_long.json').read_text())['target_prompt']
    seed=2026110545
    rng=random.Random(seed)
    plans=[]
    for case in cases:
        orders=[]
        for event in schedules[case['case_id']]:
            arms=list(ARMS)
            rng.shuffle(arms)
            orders.append({'event':event,'arm_order':arms})
        plans.append({'case_id':case['case_id'],'events':orders,
            'nonces':{arm:secrets.token_hex(32) for arm in ARMS}})
    frozen=hashes()
    output.mkdir(parents=True,exist_ok=False)
    save(output/'manifest.json',{'stage':'exploratory_native_integration_confirmation',
        'case_selection':'first four lexicographic reserved IDs, fixed before reserved outcomes',
        'cases':cases,'plans':plans,'arms':ARMS,'config':CONFIG,'seed':seed,'code_hashes':frozen,
        'data_hashes':{name:sha(data/name) for name in ('cases.public.jsonl','evaluation_only.json','schedules.json')},
        'max_calls':len(cases)*3*len(ARMS),'max_output_tokens':384,'budget_cap_cny_per_case':'3',
        'target_prompt':target_prompt,'all_initial_and_priming_calls_counted':True,
        'automatic_retry':False,'cost_is_supplier_bill':False,
        'human_review':None,'independent_units':'Hotpot questions; three policy states are repeated observations'})
    safe=FlashSDKClient(output/'metadata.private',budget_cap_cny='.5',max_jobs=1).preflight()
    save(output/'metadata_safe.json',safe)
    status={'status':'running','attempted':0,'completed':0,'max_calls':len(cases)*3*len(ARMS),
            'automatic_retry':False,'cost_is_supplier_bill':False}
    counter=0
    setup_started=time.perf_counter()
    try:
        with TinyBERTReranker() as ranker:
            save(output/'local_ranker_setup.json',{'wall_ms':(time.perf_counter()-setup_started)*1000,
                  'shared_service_startup_not_charged_to_supplier':True})
            for case,plan in zip(cases,plans):
                case_root=output/case['case_id']
                client=FlashSDKClient(case_root/'sdk.private',budget_cap_cny='3',max_jobs=3*len(ARMS))
                hosts={arm:LifecycleHost(case['sources'],case_root/'hosts'/arm) for arm in ARMS}
                pipelines={arm:FusionPipeline(case,arm,hosts[arm],ranker=ranker,retrieval_config=CONFIG) for arm in ARMS}
                try:
                    for step,entry in enumerate(plan['events']):
                        event=entry['event']
                        for arm in entry['arm_order']:
                            if hashes()!=frozen:
                                raise ValueError('frozen_code_or_weights_manifest_changed')
                            counter+=1
                            host=hosts[arm]
                            host.set_permissions(event['allowed'])
                            prepared,trace=pipelines[arm].prepare()
                            messages=target_messages(prepared.context,[{'question_id':case['case_id'],
                                'question':case['question']}],{'target_prompt':target_prompt})
                            messages[0]['content']=f'Qualification tag: {plan["nonces"][arm]}\n'+messages[0]['content']
                            row={'call_index':counter,'case_id':case['case_id'],'question_id':case['case_id'],
                                'arm':arm,'time':event['time'],'step':step,'allowed':event['allowed'],
                                'selected':list(prepared.source_ids),'context':prepared.context,
                                'context_sha256':prepared.context_sha256,'source_bytes':prepared.source_bytes,
                                'messages':messages,'trace':trace,'host_root':str(host.root),
                                'receipt':None,'output':None,'status':'pending'}
                            save(output/'inputs'/f'{counter:04d}.json',row)
                            def send():
                                status['attempted']+=1
                                return client.generate(messages,f'fusion-{counter:04d}',384,'target')
                            started=time.perf_counter()
                            try:
                                answer=deliver(prepared,host,messages,send)
                                row.update(status='completed',output=answer['output'],receipt=answer['receipt'],
                                           target_wall_ms=(time.perf_counter()-started)*1000)
                                tokens,peak,cache=usage_costs(answer['receipt']['usage'])
                                row.update(tokens=tokens,estimated_peak_cost_cny=str(peak),
                                    estimated_cache_aware_peak_cost_cny=str(cache) if cache is not None else None,
                                    cost_is_supplier_bill=False)
                                if step==0:
                                    row['initial_cache_isolation']=native_isolation(answer['receipt'],messages,plan['nonces'][arm])
                                status['completed']+=1
                            except BaseException as error:
                                row.update(status='failed_no_retry',failure_class=type(error).__name__)
                                raise
                            finally:
                                save(output/'rows'/f'{counter:04d}.json',row)
                            save(output/'progress'/f'{counter:04d}.json',status)
                            print(json.dumps({'completed':status['completed'],'max_calls':status['max_calls'],
                                'case_id':case['case_id'],'arm':arm,'time':event['time']}),flush=True)
                finally:
                    for pipeline in pipelines.values():
                        pipeline.close()
        status['status']='completed'
    except BaseException as error:
        status.update(status='failed_no_retry',failure_class=type(error).__name__)
        raise
    finally:
        save(output/'status.json',status)
    print(json.dumps(status))


if __name__=='__main__':
    main()
