"""Registered factorial pilot: all arms and every case retained, zero LLM calls."""
import argparse
import hashlib
import json
from pathlib import Path
import time
from dataclasses import asdict

from .fusion_pipeline import ARMS, FusionPipeline
from .reranker_runtime import TinyBERTReranker
from .context_adapter import deliver
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, save, digest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CONFIG = {'stages': [2,4,8], 'candidate_k': 20, 'score_threshold': .5,
          'min_relevant_sources': 2, 'lexical_coverage_threshold': .65,
          'require_distinct_parents': 2,
          'threshold_provenance': 'a_priori_fixed_before_new_Hotpot_outcomes_no_gold_calibration'}
CODE = ('fusion_pipeline.py','context_adapter.py','support_index.py','retrieval_assurance.py','reranker_runtime.py','bridge_repair.py','run_offline.py')


def hashes():
    return {name: hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in CODE}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', choices=['development','reserved'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists():
        raise ValueError('fresh_output_required_no_selective_resume')
    data = HERE/'data_hotpot'
    cases = [json.loads(line) for line in (data/'cases.public.jsonl').read_text(encoding='utf-8').splitlines()]
    cases = [case for case in cases if case['split']==args.split]
    evaluation = json.loads((data/'evaluation_only.json').read_text(encoding='utf-8'))
    schedules = json.loads((data/'schedules.json').read_text(encoding='utf-8'))
    output.mkdir(parents=True)
    frozen = hashes()
    save(output/'contract.json', {'split': args.split,'case_ids':[c['case_id'] for c in cases],
        'arms': ARMS, 'retrieval_config': CONFIG,'code':frozen,
        'data':{name:hashlib.sha256((data/name).read_bytes()).hexdigest() for name in
                ('cases.public.jsonl','evaluation_only.json','schedules.json')},
        'model_calls':0,'unsafe_payloads_sent':0,'human_gold_new_permission_views':None,
        'support_annotations_are_not_exhaustive':True,
        'independent_units':'original Hotpot question; three permission states are repeated observations'})
    rows = []
    started = time.perf_counter()
    with TinyBERTReranker() as ranker:
        for case_index, case in enumerate(cases):
            for arm in ARMS:
                host = LifecycleHost(case['sources'], output/'hosts'/case['case_id']/arm)
                pipeline = FusionPipeline(case,arm,host,ranker=ranker,retrieval_config=CONFIG)
                try:
                    for event in schedules[case['case_id']]:
                        if hashes()!=frozen:
                            raise ValueError('frozen_module_changed')
                        host.set_permissions(event['allowed'])
                        prepared, trace = pipeline.prepare()
                        messages = [{'role':'system','content':'Use only the supplied memory.'},
                            {'role':'user','content':json.dumps({'memory':prepared.context,
                              'questions':[{'question_id':case['case_id'],'question':case['question']}]})}]
                        calls = []
                        def local_commit():
                            calls.append(1)
                            return {'output':'{}','receipt':{'instrument_only':True,'physical_request_count':0}}
                        deliver(prepared,host,messages,local_commit)
                        if len(calls)!=1 or set(prepared.source_ids)-set(event['allowed']):
                            raise AssertionError('payload_authorization_or_commit_failed')
                        required = set(evaluation[case['case_id']]['support_ids'])
                        visible = set(prepared.source_ids)
                        allowed = set(event['allowed'])
                        # This is annotation coverage, not an answer oracle or
                        # proof that missing annotated support is unanswerable.
                        row = {'case_id':case['case_id'],'arm':arm,'time':event['time'],
                            'allowed':event['allowed'],'selected':list(prepared.source_ids),
                            'context':prepared.context,'context_sha256':prepared.context_sha256,
                            'source_bytes':prepared.source_bytes,'context_bytes':len(prepared.context.encode()),
                            'all_annotated_support_currently_allowed':required<=allowed,
                            'complete_annotated_support_retrieved':required<=visible,
                            'original_annotated_support_recall':len(required&visible)/len(required) if required else None,
                            'current_annotated_support_recall':len(required&allowed&visible)/len(required&allowed) if required&allowed else None,
                            'forbidden_source_ids':sorted(visible-allowed),'trace':trace,
                            'model_calls':0,'commit_gate_passed':True}
                        save(output/'rows'/f'{len(rows):05d}.json',row)
                        rows.append(row)
                finally:
                    pipeline.close()
            print(json.dumps({'completed_cases':case_index+1,'total':len(cases),'rows':len(rows)}),flush=True)
    aggregate = {}
    for arm in ARMS:
        subset = [r for r in rows if r['arm']==arm]
        eligible = [r for r in subset if r['all_annotated_support_currently_allowed']]
        aggregate[arm] = {'observations':len(subset),'eligible_annotated_support_views':len(eligible),
            'complete_support_views':sum(r['complete_annotated_support_retrieved'] for r in eligible),
            'source_bytes':sum(r['source_bytes'] for r in subset),
            'context_bytes':sum(r['context_bytes'] for r in subset),
            'forbidden_payloads':sum(bool(r['forbidden_source_ids']) for r in subset),
            'prepare_ms':sum(r['trace']['total_prepare_ms'] for r in subset),
            'initialization_ms':sum(next(r['trace']['initialization_ms'] for r in subset if r['case_id']==cid)
                                    for cid in {r['case_id'] for r in subset}),
            'reranker_calls':sum(r['trace']['retrieval'].get('ranker_call_count',0) for r in subset),
            'cache_reuses':sum(r['trace']['cache_reuse'] is not None for r in subset)}
    summary = {'status':'completed','split':args.split,'cases':len(cases),'rows':len(rows),
        'aggregate':aggregate,'elapsed_seconds':time.perf_counter()-started,'model_calls':0,
        'measurement':'offline current-authorization and annotated-support coverage, not model answer quality or supplier fee'}
    save(output/'summary.json',summary)
    print(json.dumps(summary,ensure_ascii=False))


if __name__=='__main__':
    main()
