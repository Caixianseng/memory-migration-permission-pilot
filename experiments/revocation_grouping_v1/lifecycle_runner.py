"""Paired, chronological development screen. No automatic retry or resume.

Source jobs with identical legal input/configuration are physically shared.
Every method is charged once for each artifact it uses, independently of which
method first caused that physical request. Targets are never shared.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import json
import math
from pathlib import Path
import random
import time

from .group_planner import plan
from .lifecycle_host import LifecycleHost, canonical, digest, save
from .rebuild_cache import RebuildCache

HERE = Path(__file__).resolve().parent


def history_for(sources, seed, expected_deliveries=3):
    if type(expected_deliveries) is not int or expected_deliveries < 1:
        raise ValueError('positive_integer_expected_deliveries_required')
    rng = random.Random(seed)
    ids = [s['source_id'] for s in sources]
    masks = []
    # Independent synthetic training draws, never extracted from test events.
    for _ in range(24):
        if rng.random() < .65:
            start = rng.randrange(0, len(ids), 2)
            masks.append(ids[start:start + 2])
        else:
            masks.append([sid for sid in ids if rng.random() < .25])
    return {'masks': masks, 'expected_changes': 4, 'expected_deliveries': expected_deliveries,
            'provenance': 'controlled-training-simulation', 'seed': seed}


def schedule_for(sources, kind, seed):
    rng = random.Random(seed)
    ids = [s['source_id'] for s in sources]
    if kind == 'coordinated':
        revoked = set(ids[:4])
    elif kind == 'independent':
        revoked = set(rng.sample(ids, 4)) | {ids[0]}
    elif kind == 'distribution_shift':
        revoked = set(ids[::2])
    else:
        raise ValueError('unknown_event_distribution')
    return [
        {'time': 0, 'kind': 'initial', 'allowed': ids},
        {'time': 1, 'kind': 'single_revocation', 'allowed': [s for s in ids if s != ids[0]]},
        {'time': 2, 'kind': kind, 'allowed': [s for s in ids if s not in revoked]},
        {'time': 3, 'kind': 'reauthorize', 'allowed': [s for s in ids if s not in revoked or s in ids[:2]]},
        {'time': 4, 'kind': 'new_revocation', 'allowed': [s for s in ids if (s not in revoked or s in ids[:2]) and s != ids[-1]]},
    ]


def expanded_schedule(base_events, repeats=1):
    """Repeated deliveries are ticks, not additional permission changes."""
    if type(repeats) is not int or repeats < 1:
        raise ValueError('positive_integer_repeat_deliveries_required')
    if repeats == 1:
        return base_events
    return [{**deepcopy(event), 'time': event['time'] * repeats + batch,
             'policy_time': event['time'], 'query_batch': batch}
            for event in base_events for batch in range(repeats)]


def questions_at_time(spec, timepoint):
    """Keep references on the evaluation side; target_messages strips them."""
    if isinstance(spec, list):
        return spec
    if not isinstance(spec, dict) or not isinstance(spec.get('questions'), list):
        raise ValueError('invalid_question_specification')
    questions = spec['questions']
    if 'question_schedule' not in spec:
        return questions
    schedule = spec['question_schedule']
    if not isinstance(schedule, dict):
        raise ValueError('invalid_question_schedule')
    by_id = {}
    for question in questions:
        qid = question.get('question_id', question.get('id'))
        if not isinstance(qid, str) or not qid or qid in by_id:
            raise ValueError('scheduled_questions_require_unique_explicit_ids')
        by_id[qid] = question
    selected = schedule.get(str(timepoint))
    if (not isinstance(selected, list) or len(selected) != 3 or any(not isinstance(qid, str) for qid in selected)
            or len(set(selected)) != 3 or any(qid not in by_id for qid in selected)):
        raise ValueError('each_scored_tick_requires_three_known_unique_question_ids')
    return [by_id[qid] for qid in selected]


def source_messages(sources, contract):
    return [{'role': 'system', 'content': contract['source_prompt']},
            {'role': 'user', 'content': json.dumps({'maximum_words': output_limit(sources) // 2,
                'sources': [{'source_id': s['source_id'], 'text': s['text']} for s in sources]}, ensure_ascii=False)}]


def public_question(q, index):
    return {'question_id': q.get('question_id', q.get('id', f'Q{index+1}')),
            'question': q.get('question', q.get('text'))}


def target_messages(memory, questions, contract):
    return [{'role': 'system', 'content': contract['target_prompt']},
            {'role': 'user', 'content': json.dumps({'memory': memory, 'questions': [
                public_question(q, i) for i, q in enumerate(questions)]}, ensure_ascii=False)}]


def retrieved_sources(sources, questions, contract):
    from .retrieval_baseline import select
    texts = [public_question(q, i)['question'] for i, q in enumerate(questions)]
    strategy = contract.get('retrieval_strategy', 'sum')
    if strategy == 'sum':
        return select(sources, texts, top_k=contract['retrieval_top_k'])
    if strategy != 'per_question_top2_union':
        raise ValueError('unknown_retrieval_strategy')
    selected = {}
    for text in texts:
        for source in select(sources, [text], top_k=2):
            selected[source['source_id']] = source
    return [selected[sid] for sid in sorted(selected)]


def output_limit(sources):
    size = sum(len(s['text'].encode('utf-8')) for s in sources)
    return min(2048, max(256, math.ceil(size / 3 * .4 + 32)))


def update(path, value):
    temp = Path(str(path) + '.tmp')
    temp.write_bytes(canonical(value))
    temp.replace(path)


class FixtureClient:
    """Transport fixture ONLY; never generates an effectiveness result."""
    def __init__(self):
        self.jobs = 0

    def generate(self, messages, job_id, max_tokens, role):
        self.jobs += 1
        output = messages[-1]['content'] if role == 'source' else '{}'
        return {'output': output, 'receipt': {'request_id': job_id, 'instrument_only': True,
                'estimated_peak_cost_cny': None, 'physical_request_count': 0,
                'request_sha256': digest(messages), 'response_sha256': digest(output.encode())}}


def run(cases, questions_by_case, contract, output, client, *, instrument_only=False):
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    save(output / 'frozen_contract.json', contract)
    save(output / 'frozen_cases.json', cases)
    save(output / 'evaluation_only.json', questions_by_case)
    save(output / 'code_manifest.json', {p.name: digest(p.read_bytes()) for p in sorted(HERE.iterdir())
                                        if p.suffix in ('.py', '.mjs', '.json') and p.is_file()})
    summary = {'schema': 'grouping-lifecycle-results-v1', 'instrument_only': instrument_only,
               'status': 'running', 'human_gold': None, 'rows': [], 'cases': [],
               'started_unix': time.time(), 'contract_sha256': digest(contract)}
    cache = RebuildCache(output / 'cache')
    job_count = 0

    def invoke(messages, role, cap):
        nonlocal job_count
        job_count += 1
        result = client.generate(messages, f'group-{job_count:04d}', cap, role)
        if not isinstance(result, dict) or not isinstance(result.get('output'), str) or not isinstance(result.get('receipt'), dict):
            raise ValueError('invalid_model_receipt')
        save(output / 'calls' / f'{job_count:04d}.json', {
            'role': role, 'messages': messages, 'result': result, 'max_tokens': cap})
        return result

    try:
        for index, case in enumerate(cases):
            sequence_index = index + int(contract.get('case_offset', 0))
            case_id, sources = case['case_id'], case['sources']
            question_spec = questions_by_case[case_id]
            scheduled_questions = {tick: questions_at_time(question_spec, tick)
                                   for tick in contract['events']['scoring_times']}
            if len(sources) != 8:
                raise ValueError('eight_sources_required')
            kind = case.get('event_distribution', contract['events']['sequence_types'][sequence_index % 3])
            history = history_for(sources, contract['history']['seed'] + sequence_index,
                                  contract['planner'].get('expected_deliveries', 3))
            repeats = contract.get('repeat_deliveries_per_policy_state', 1)
            events = expanded_schedule(schedule_for(sources, kind, contract['events']['seed'] + sequence_index), repeats)
            case_root = output / case_id
            case_root.mkdir()
            save(case_root / 'training_history.json', history)
            save(case_root / 'events_frozen_before_models.json', events)
            state = {}
            for method in contract['methods']:
                host = LifecycleHost(sources, case_root / method / 'host')
                current = host.allowed_sources()
                cfg = {**contract['planner'], 'method': method}
                partition = {'method': method, 'groups': [], 'planning_ms': 0} if method in ('raw', 'retrieval') else plan(current, history, cfg)
                save(case_root / method / 'initial_plan.json', partition)
                state[method] = {'host': host, 'plan': partition, 'source_receipts': {}, 'target_receipts': [],
                                 'known_artifacts': {}, 'cache_hits': 0, 'source_requests_attributed': 0}

            for event in events:
                order = list(contract['methods'])
                random.Random(20261104 + index * 10 + event['time']).shuffle(order)
                for method in order:
                    item = state[method]
                    host = item['host']
                    if repeats == 1 or event['query_batch'] == 0:
                        host.set_permissions(event['allowed'])
                    else:
                        if sorted(s['source_id'] for s in host.allowed_sources()) != sorted(event['allowed']):
                            raise ValueError('repeated_tick_permission_state_mismatch')
                        host.log('policy_state_reused', {'time': event['time'], 'policy_time': event['policy_time'],
                                                        'query_batch': event['query_batch']})
                    # Check previously generated objects under current grants.
                    for artifact in item['known_artifacts'].values():
                        try:
                            host.authorize(artifact['source_ids'], 'old-artifact')
                            allowed = True
                        except ValueError:
                            allowed = False
                        host.log('old_artifact_check', {'artifact': artifact['artifact_id'], 'allowed': allowed,
                                                        'sources': artifact['source_ids']})
                    if event['time'] not in contract['events']['scoring_times']:
                        continue  # no demand: lazy rebuild performs no model call
                    questions = scheduled_questions[event['time']]
                    current = host.allowed_sources()
                    by_id = {s['source_id']: s for s in current}
                    if method in ('raw', 'retrieval'):
                        selected = current
                        if method == 'retrieval':
                            selected = retrieved_sources(current, questions, contract)
                        memory = '\n\n'.join(s['source_id'] + '\n' + s['text'] for s in selected)
                        dependencies = [s['source_id'] for s in selected]
                        artifacts = []
                    else:
                        texts, dependencies, artifacts = [], [], []
                        for initial_group in item['plan']['groups']:
                            group = [by_id[sid] for sid in initial_group if sid in by_id]
                            if not group:
                                continue
                            cap = output_limit(group)
                            transform = {'schema': 'flash-memory-v1', 'prompt': contract['source_prompt'],
                                         'model': 'deepseek-flash', 'thinking': 'off', 'max_tokens': cap,
                                         'permission_reuse': 'recheck_current_dependencies'}
                            artifact = cache.lookup(group, transform)
                            if artifact is None:
                                messages = source_messages(group, contract)
                                result = host.generate(group, messages, lambda: invoke(messages, 'source', cap))
                                artifact = cache.store(group, transform, result['output'], result['receipt'])
                            else:
                                item['cache_hits'] += 1
                                host.log('legal_cache_reused', {'artifact': artifact['artifact_id'],
                                                             'sources': artifact['source_ids']})
                            receipt = artifact['receipt']
                            item['source_receipts'][receipt['request_id']] = receipt
                            item['known_artifacts'][artifact['artifact_id']] = artifact
                            texts.append(artifact['text'])
                            dependencies.extend(artifact['source_ids'])
                            artifacts.append(artifact['artifact_id'])
                        memory = '\n\n'.join(texts)
                    messages = target_messages(memory, questions, contract)
                    result = host.deliver(memory, dependencies, messages,
                        lambda: invoke(messages, 'target', contract['target_max_output_tokens']))
                    item['target_receipts'].append(result['receipt'])
                    row = {'case_id': case_id, 'method': method, 'time': event['time'],
                           'event_distribution': kind, 'allowed': sorted(by_id),
                           'dependencies': sorted(set(dependencies)), 'artifacts': artifacts,
                           'memory_sha256': digest(memory.encode()), 'memory_utf8_bytes': len(memory.encode()),
                           'answer': result['output'], 'target_receipt': result['receipt'],
                           'human_score': None}
                    if repeats > 1:
                        row.update(policy_time=event['policy_time'], query_batch=event['query_batch'],
                                   question_ids=[public_question(q, i)['question_id'] for i, q in enumerate(questions)])
                    summary['rows'].append(row)
                    save(case_root / method / f't{event["time"]}.json', row)
                    update(output / 'summary.json', summary)
            for method, item in state.items():
                source_receipts = list(item['source_receipts'].values())
                receipts = source_receipts + item['target_receipts']
                costs = [r.get('estimated_peak_cost_cny') for r in receipts]
                summary['cases'].append({'case_id': case_id, 'method': method,
                    'source_job_ids': list(item['source_receipts']), 'source_jobs_attributed': len(source_receipts),
                    'target_jobs': len(item['target_receipts']), 'cache_hits': item['cache_hits'],
                    'planning_ms': item['plan']['planning_ms'],
                    'full_lifecycle_peak_cny': sum(float(v) for v in costs) if all(v is not None for v in costs) else None})
        summary['status'] = 'completed'
    except BaseException as error:
        summary['status'] = 'failed_no_automatic_retry'
        summary['failure_class'] = type(error).__name__
        # Fixed local error codes only; provider diagnostics may contain secrets.
        summary['failure_code'] = getattr(error, 'code', 'inspect_private_failure_record')
        raise
    finally:
        summary['physical_jobs'] = job_count
        summary['finished_unix'] = time.time()
        update(output / 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--questions', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--backend', choices=['fixture', 'sdk'], required=True)
    parser.add_argument('--split', default='development')
    parser.add_argument('--contract', type=Path, default=HERE / 'workload_contract.json')
    args = parser.parse_args()
    raw = args.cases.read_text(encoding='utf-8')
    cases = [json.loads(line) for line in raw.splitlines() if line.strip()] if args.cases.suffix == '.jsonl' else json.loads(raw)
    cases = cases.get('cases', cases) if isinstance(cases, dict) else cases
    cases = [c for c in cases if c.get('split', 'development') == args.split]
    if not cases:
        raise ValueError('no_cases_selected')
    questions = json.loads(args.questions.read_text(encoding='utf-8'))
    contract = json.loads(args.contract.read_text(encoding='utf-8'))
    if args.backend == 'fixture':
        client = FixtureClient()
    else:
        from .sdk_adapter import FlashSDKClient
        client = FlashSDKClient(args.output.parent / (args.output.name + '-private-sdk'),
                                budget_cap_cny=contract.get('run_budget_cap_cny', contract['budget']['development_cap_cny']),
                                max_jobs=contract.get('run_max_jobs', 160))
    result = run(cases, questions, contract, args.output, client, instrument_only=args.backend == 'fixture')
    print(json.dumps({'status': result['status'], 'physical_jobs': result['physical_jobs'],
                      'instrument_only': result['instrument_only']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
