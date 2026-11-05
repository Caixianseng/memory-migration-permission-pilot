"""Twelve-call bounded 64-source native bridge; no retries or resumptions."""
import json
from pathlib import Path
import random

from .scale_permission_runner import run, digest, save

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUTPUT = REPO / 'results/revocation_prefix_v1/quotient-native64-20261105-v1'


def main():
    if OUTPUT.exists():
        raise ValueError('fresh_output_required')
    paths = {'cases': HERE / 'data_scale64/cases.jsonl',
        'questions': HERE / 'data_scale64/questions.json',
        'old_question_rotation': HERE / 'data_reserved/questions_reserved.json',
        'contract': REPO / 'experiments/revocation_grouping_v1/workload_contract_long.json'}
    raw = {k: p.read_bytes() for k, p in paths.items()}
    cases = [json.loads(line) for line in raw['cases'].decode('utf-8').splitlines() if line.strip()]
    if len(cases) != 1 or len(cases[0]['sources']) != 64:
        raise ValueError('fixed_64_full_exchange_case_required')
    case = cases[0]
    spec = json.loads(raw['questions'])[case['case_id']]
    old_rotation = json.loads(raw['old_question_rotation'])
    ids = [s['source_id'] for s in case['sources']]
    if ids != [f'M{i:03d}' for i in range(1, 65)]:
        raise ValueError('chronological_source_ID_mapping_changed')
    groups = [ids[i:i+8] for i in range(0, 64, 8)]
    rng, state, history = random.Random(2026110523), set(ids), []
    # Prior simulated permissions, not model-cache prefetches or future events.
    for _ in range(128):
        before = sorted(state)
        operator = rng.choices([None, 0, 1, 6, 7], weights=[2, 1, 1, 3, 3])[0]
        if operator is not None:
            state.symmetric_difference_update(groups[operator])
        history.append({'before': before, 'after': sorted(state)})
    denied = [[], [0], [0, 7], [6, 7], [6, 7], []]
    schedule = []
    for step, denied_groups in enumerate(denied):
        blocked = {s for g in denied_groups for s in groups[g]}
        persona = f'personamem-long-{8 + step % 2:03d}'
        question_ids = old_rotation[persona]['question_schedule'][str((step // 2) % 4)]
        schedule.append({'time': step, 'allowed': [s for s in ids if s not in blocked],
                         'question_ids': question_ids})
    config = {'forecast_model': 'joint_delta', 'next_cost_weight': 1.0,
        'max_signature_groups': 12, 'max_explicit_forecast_states': 256,
        'arm_policies': {'quotient': {'method': 'quotient_two_step'},
                         'greedy': {'method': 'quotient_cache_greedy'}}}
    inputs = {k: {'path': str(paths[k]), 'sha256': digest(body)} for k, body in raw.items()}
    inputs['driver'] = {'path': str(Path(__file__)), 'sha256': digest(Path(__file__).read_bytes())}
    # Base runner freezes case, code, current-only planner inputs, complete
    # chronology, 12-call/2-CNY cap and all per-arm initial costs before dispatch.
    result = run(case, spec, schedule, history, OUTPUT, arms=['quotient', 'greedy'],
        config=config, budget_cap_cny='2', max_jobs=12,
        target_prompt=json.loads(raw['contract'])['target_prompt'], input_files=inputs)
    print(json.dumps({k: result[k] for k in ('status', 'model_calls_attempted', 'arm_totals',
          'physical_totals', 'isolation_review_required')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
