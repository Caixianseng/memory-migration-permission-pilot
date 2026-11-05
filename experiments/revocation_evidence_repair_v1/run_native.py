"""Frozen five-arm first-delivery evidence-packet experiment; no gold lookup.

Initial packet/query construction is local and fully timed. Each real answer
uses a fresh SDK receiver session. Future permission events stay in scheduler
code, outside the pipeline. No retries or automatic failed-job recovery.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import secrets
import time

from .pipeline import RepairPipeline, ARMS
from experiments.memory_module_fusion_v1.context_adapter import deliver
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, save
from experiments.revocation_grouping_v1.lifecycle_runner import target_messages
from experiments.revocation_grouping_v1.sdk_adapter import FlashSDKClient, usage_costs
from experiments.revocation_prefix_v1.cache_qualification import native_isolation

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def code_hashes():
    own = ('run_native.py', 'pipeline.py', 'retrieval.py', 'prepare_data.py')
    paths = [HERE/name for name in own]
    paths += [REPO/'experiments/memory_module_fusion_v1'/name for name in ('context_adapter.py','strong_controls.py')]
    paths += [REPO/'experiments/revocation_grouping_v1'/name for name in
              ('lifecycle_host.py','lifecycle_runner.py','retrieval_baseline.py','sdk_adapter.py','dsh_group_guard.mjs')]
    paths += [REPO/'experiments/permission_context_v1/authorized_expansion.py']
    return {str(path.relative_to(REPO)): sha(path) for path in paths}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data', type=Path, required=True)
    p.add_argument('--lock', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--case-count', type=int, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise ValueError('fresh_run_required_no_retry_or_resume')
    lock = json.loads(a.lock.read_bytes())
    cases = [json.loads(line) for line in (a.data/'cases.public.jsonl').read_bytes().splitlines() if line.strip()]
    if not 1 <= a.case_count <= len(cases):
        raise ValueError('invalid_fixed_case_count')
    cases = cases[:a.case_count]
    schedules = json.loads((a.data/'schedules.json').read_bytes())
    config = lock['retrieval_config']
    prompt = lock['target_prompt']
    if tuple(lock['arms']) != tuple(ARMS):
        raise ValueError('arm_lock_mismatch')
    frozen = code_hashes()
    # Hashing this separate evaluation file does not reveal its answers/supports.
    data_hashes = {name: sha(a.data/name) for name in ('cases.public.jsonl','schedules.json','evaluation_only.json')}
    rng = random.Random(2026110587)
    plans = []
    for case in cases:
        order = []
        for event in schedules[case['case_id']]:
            arms = list(ARMS)
            rng.shuffle(arms)
            order.append({'event': event, 'arms': arms})
        plans.append({'case_id': case['case_id'], 'events': order,
            'nonces': {arm: secrets.token_hex(32) for arm in ARMS}})
    out = a.output.absolute()
    out.mkdir(parents=True)
    max_calls = sum(len(e['arms']) for q in plans for e in q['events'])
    save(out/'manifest.json', {'stage': lock['stage'], 'cases': cases, 'plans': plans,
        'arms': ARMS, 'config': config, 'target_prompt': prompt, 'lock_sha256': sha(a.lock),
        'data_hashes': data_hashes, 'code_hashes': frozen, 'max_calls': max_calls,
        'max_output_tokens': 384, 'budget_cap_cny_per_case': '2',
        'automatic_retry': False, 'all_initial_builds_and_priming_counted': True,
        'initial_build_is_extractive_local_not_LLM_summary': True,
        'independent_units': 'original questions; permission states repeated within question',
        'new_receiver': 'fresh native SDK session for each call; no recall of previously sent plaintext claimed',
        'cost_is_supplier_bill': False, 'human_review': None})
    for name in ('run_native.py','pipeline.py','retrieval.py'):
        (out/(name+'.snapshot')).write_bytes((HERE/name).read_bytes())
    status = {'status': 'running', 'registered': 0, 'attempted': 0, 'completed': 0,
              'max_calls': max_calls, 'automatic_retry': False}
    save(out/'metadata_safe.json', FlashSDKClient(out/'metadata.private', budget_cap_cny='.5', max_jobs=1).preflight())
    try:
        for case, plan in zip(cases, plans):
            base = out/case['case_id']
            client = FlashSDKClient(base/'sdk.private', budget_cap_cny='2', max_jobs=15)
            hosts = {arm: LifecycleHost(case['sources'], base/'hosts'/arm) for arm in ARMS}
            pipes = {arm: RepairPipeline(case, arm, hosts[arm], config=config) for arm in ARMS}
            initial = {}
            try:
                for arm in ARMS:
                    hosts[arm].set_permissions([s['source_id'] for s in case['sources']])
                    start = time.perf_counter()
                    initial[arm] = pipes[arm].initialize()
                    initial[arm]['initialization_ms'] = (time.perf_counter()-start)*1000
                    save(base/'initial'/f'{arm}.json', initial[arm])
                for step, entry in enumerate(plan['events']):
                    event = entry['event']
                    for arm in entry['arms']:
                        if code_hashes() != frozen:
                            raise ValueError('frozen_experiment_code_changed')
                        host = hosts[arm]
                        host.set_permissions(event['allowed'])
                        prepared, trace = pipes[arm].prepare()
                        shown = list(dict.fromkeys(s.source_id for s in prepared.span_witnesses))
                        messages = target_messages(prepared.context, [{'question_id': case['case_id'],
                            'question': case['question']}], {'target_prompt': prompt})
                        messages[0]['content'] = f'Qualification tag: {plan["nonces"][arm]}\n'+messages[0]['content']
                        status['registered'] += 1
                        idx = status['registered']
                        row = {'call_index': idx, 'case_id': case['case_id'], 'question_id': case['case_id'],
                            'arm': arm, 'time': event['time'], 'step': step, 'allowed': event['allowed'],
                            'selected': list(prepared.source_ids), 'presented_source_ids': shown,
                            'context': prepared.context, 'context_sha256': prepared.context_sha256,
                            'source_bytes': prepared.source_bytes, 'messages': messages,
                            'host_root': str(host.root), 'prepared': asdict(prepared), 'trace': trace,
                            'initial_build_trace': initial[arm] if step == 0 else {},
                            'receipt': None, 'output': None, 'status': 'pending'}
                        save(out/'inputs'/f'{idx:04d}.json', row)
                        def send():
                            status['attempted'] += 1
                            return client.generate(messages, f'repair-{idx:04d}', 384, 'target')
                        start = time.perf_counter()
                        try:
                            answer = deliver(prepared, host, messages, send)
                            tokens, peak, cached = usage_costs(answer['receipt']['usage'])
                            row.update(status='completed', output=answer['output'], receipt=answer['receipt'],
                                target_wall_ms=(time.perf_counter()-start)*1000, tokens=tokens,
                                estimated_peak_cost_cny=str(peak),
                                estimated_cache_aware_peak_cost_cny=str(cached) if cached is not None else None,
                                cost_is_supplier_bill=False)
                            if step == 0:
                                row['initial_cache_isolation'] = native_isolation(answer['receipt'], messages, plan['nonces'][arm])
                            status['completed'] += 1
                        except BaseException as error:
                            row.update(status='failed_no_retry', failure_class=type(error).__name__)
                            raise
                        finally:
                            save(out/'rows'/f'{idx:04d}.json', row)
                        save(out/'progress'/f'{idx:04d}.json', status)
                        print(json.dumps({'completed': status['completed'], 'max_calls': max_calls,
                            'case_id': case['case_id'], 'arm': arm, 'time': event['time']}), flush=True)
            finally:
                for pipe in pipes.values():
                    pipe.close()
        status['status'] = 'completed'
    except BaseException as error:
        status.update(status='failed_no_retry', failure_class=type(error).__name__)
        raise
    finally:
        save(out/'status.json', status)


if __name__ == '__main__':
    main()
