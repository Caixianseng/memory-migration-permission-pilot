"""Question-paired descriptive analysis of every frozen offline fusion arm.

The three permission states are repeated observations, not independent units.
This post-outcome analysis retains all arms, all states, initialization and local
preparation costs. Bytes are retrieval volume, never inferred supplier tokens or
fees. Pointwise cluster-bootstrap intervals are exploratory, not a simultaneous
multiple-comparison significance claim. No model or embedding calls occur.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import platform
import random

BOOTSTRAP_SEED = 2026110551
BOOTSTRAP_DRAWS = 5000
METRICS = ('eligible_support_complete_rate', 'lifecycle_source_bytes',
           'lifecycle_context_bytes', 'prepare_ms', 'initialization_ms',
           'lifecycle_cpu_ms', 'ranker_calls', 'cache_reuses')


def _mean(values):
    return sum(values) / len(values) if values else None


def _percentile(values, p):
    values = sorted(values)
    index = (len(values) - 1) * p
    low = int(index)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (index - low)


def paired_effect(candidate, control, samples):
    differences = [candidate[i] - control[i] for i in range(len(candidate))]
    distribution = [sum(differences[i] for i in sample) / len(sample) for sample in samples]
    return {'independent_question_clusters': len(differences), 'candidate_mean': _mean(candidate),
        'control_mean': _mean(control), 'paired_mean_difference_candidate_minus_control': _mean(differences),
        'pointwise_95pct_question_bootstrap_interval': [_percentile(distribution, .025), _percentile(distribution, .975)],
        'candidate_higher_questions': sum(d > 1e-12 for d in differences),
        'candidate_lower_questions': sum(d < -1e-12 for d in differences),
        'tied_questions': sum(abs(d) <= 1e-12 for d in differences),
        'per_question_differences': differences}


def analyze(rows, contract, *, bootstrap_draws=BOOTSTRAP_DRAWS):
    case_ids, arms = contract['case_ids'], contract['arms']
    by_cell = {}
    for row in rows:
        cell = row['case_id'], row['arm'], row['time']
        if cell in by_cell:
            raise ValueError('duplicate_offline_cell')
        by_cell[cell] = row
    event_times = {cid: sorted({r['time'] for r in rows if r['case_id'] == cid}) for cid in case_ids}
    expected = {(cid, arm, t) for cid in case_ids for arm in arms for t in event_times[cid]}
    if not all(len(event_times[cid]) == 3 for cid in case_ids) or set(by_cell) != expected:
        raise ValueError('complete_registered_three_state_matrix_required')
    # Eligibility is policy/gold dependent, never allowed to vary with the arm.
    for cid in case_ids:
        for t in event_times[cid]:
            reference = by_cell[cid, arms[0], t]
            if any(set(by_cell[cid, arm, t]['allowed']) != set(reference['allowed'])
                   or by_cell[cid, arm, t]['all_annotated_support_currently_allowed'] != reference['all_annotated_support_currently_allowed']
                   for arm in arms):
                raise ValueError('paired_arms_policy_or_eligibility_mismatch')
    rng = random.Random(BOOTSTRAP_SEED)
    samples = [[rng.randrange(len(case_ids)) for _ in case_ids] for _ in range(bootstrap_draws)]
    by_arm, summaries = {}, {}
    safety = []
    for arm in arms:
        questions = []
        for cid in case_ids:
            trajectory = [by_cell[cid, arm, t] for t in event_times[cid]]
            eligible = [row for row in trajectory if row['all_annotated_support_currently_allowed']]
            init = trajectory[0]['trace']['initialization_ms']
            if any(row['trace']['initialization_ms'] != init for row in trajectory):
                raise ValueError('initialization_measurement_changed_within_pipeline')
            prepare = sum(row['trace']['total_prepare_ms'] for row in trajectory)
            point = {'case_id': cid, 'repeated_policy_states': len(trajectory), 'eligible_views': len(eligible),
                'eligible_support_complete_rate': _mean([float(r['complete_annotated_support_retrieved']) for r in eligible]),
                'lifecycle_source_bytes': sum(r['source_bytes'] for r in trajectory),
                'lifecycle_context_bytes': sum(r['context_bytes'] for r in trajectory),
                'prepare_ms': prepare, 'initialization_ms': init, 'lifecycle_cpu_ms': prepare + init,
                'ranker_calls': sum(r['trace']['retrieval'].get('ranker_call_count', 0) for r in trajectory),
                'cache_reuses': sum(r['trace']['cache_reuse'] is not None for r in trajectory)}
            if point['eligible_support_complete_rate'] is None:
                raise ValueError('question_without_any_eligible_view')
            questions.append(point)
            for row in trajectory:
                forbidden = sorted(set(row['selected']) - set(row['allowed']))
                if forbidden or row.get('forbidden_source_ids') or row.get('commit_gate_passed') is not True:
                    safety.append({'case_id': cid, 'arm': arm, 'time': row['time'], 'forbidden': forbidden})
        by_arm[arm] = questions
        arm_rows = [row for row in rows if row['arm'] == arm]
        eligible_rows = [row for row in arm_rows if row['all_annotated_support_currently_allowed']]
        summaries[arm] = {'independent_questions': len(questions), 'observations': len(arm_rows),
            'eligible_observations': len(eligible_rows),
            'complete_support_eligible_observations': sum(r['complete_annotated_support_retrieved'] for r in eligible_rows),
            'question_macro_eligible_support_complete_rate': _mean([p['eligible_support_complete_rate'] for p in questions]),
            **{key + '_total': sum(p[key] for p in questions) for key in METRICS if key != 'eligible_support_complete_rate'}}

    def contrast(candidate, control):
        result = {key: paired_effect([p[key] for p in by_arm[candidate]], [p[key] for p in by_arm[control]], samples)
                  for key in METRICS}
        candidate_bytes = summaries[candidate]['lifecycle_source_bytes_total']
        control_bytes = summaries[control]['lifecycle_source_bytes_total']
        return {'candidate': candidate, 'control': control, 'metrics': result,
                'total_source_byte_reduction_fraction': 1-candidate_bytes/control_bytes if control_bytes else None}

    factorial = {}
    for feature, position in [('hierarchy', 1), ('proof', 3), ('rerank', 5)]:
        pairs = []
        for arm in arms:
            if len(arm) == 6 and arm[0] == 'h' and arm[position] == '0':
                positive = arm[:position] + '1' + arm[position + 1:]
                if positive in by_arm:
                    pairs.append((positive, arm))
        if not pairs:
            continue
        effects = {}
        for metric in METRICS:
            positive_values = [_mean([by_arm[pos][i][metric] for pos, _ in pairs]) for i in range(len(case_ids))]
            negative_values = [_mean([by_arm[neg][i][metric] for _, neg in pairs]) for i in range(len(case_ids))]
            effects[metric] = paired_effect(positive_values, negative_values, samples)
        factorial[feature] = {'conditional_pairs': [list(pair) for pair in pairs], 'averaged_main_effect': effects,
            'conditional_effects': [contrast(*pair) for pair in pairs]}

    proof_identity = []
    for h in (0, 1):
        for r in (0, 1):
            pos, neg = f'h{h}p1r{r}', f'h{h}p0r{r}'
            if pos not in by_arm or neg not in by_arm:
                continue
            equal_context, equal_ids, mismatches = 0, 0, []
            for cid in case_ids:
                for t in event_times[cid]:
                    a, b = by_cell[cid, pos, t], by_cell[cid, neg, t]
                    equal_context += a['context'] == b['context']
                    equal_ids += a['selected'] == b['selected']
                    if a['context'] != b['context']:
                        mismatches.append({'case_id': cid, 'time': t, 'proof_ids': a['selected'], 'no_proof_ids': b['selected']})
            proof_identity.append({'proof_arm': pos, 'no_proof_arm': neg, 'paired_views': len(case_ids)*3,
                'exact_context_equal_views': equal_context, 'ordered_source_ids_equal_views': equal_ids, 'mismatches': mismatches})
    contrasts = []
    for candidate, control in [('bm25_bridge', 'h0p0r0'), ('hierarchy_bridge', 'h1p0r0'),
                               ('assurance_bridge', 'h0p0r1'), ('fusion_bridge', 'h1p1r1')]:
        if candidate in by_arm and control in by_arm:
            contrasts.append(contrast(candidate, control))
    strong_controls = ('raw', 'fixed_rerank', 'adaptive_bm25', 'neighbor', 'parent_bm25',
                       'bm25_bridge', 'hierarchy_bridge', 'assurance_bridge')
    for candidate in ('h1p1r1', 'fusion_bridge'):
        if candidate in by_arm:
            contrasts.extend(contrast(candidate, control) for control in strong_controls if control in by_arm)
    return {'summary': {'status': 'completed', 'analysis_is_exploratory_post_outcome': True,
        'independent_unit': 'original Hotpot question', 'independent_questions': len(case_ids),
        'all_observations': len(rows), 'policy_states_per_question_arm': 3, 'no_observation_exclusions': True,
        'complete_registered_matrix': True, 'supplier_calls': 0, 'supplier_fee_estimated_from_bytes': False,
        'bootstrap': {'method': 'paired question-cluster percentile bootstrap', 'draws': bootstrap_draws,
                      'seed': BOOTSTRAP_SEED, 'coverage': .95, 'intervals': 'pointwise, not multiplicity adjusted',
                      'p_values_or_significance_claims': False},
        'local_timing_includes_initialization_once_plus_all_three_prepare_calls': True,
        'shared_ranker_startup': 'not per-arm; retain upstream elapsed_seconds separately',
        'forbidden_or_uncommitted_payload_observations': safety, 'arms': summaries,
        'python_version': platform.python_version()},
        'question_metrics': by_arm, 'factorial': factorial, 'proof_output_identity': proof_identity,
        'paired_contrasts': contrasts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('fresh_analysis_output_required')
    contract = json.loads((args.records/'contract.json').read_bytes())
    rows = [json.loads(file.read_bytes()) for file in sorted((args.records/'rows').glob('*.json'))]
    result = analyze(rows, contract)
    args.output.mkdir(parents=True)
    provenance = {'input_contract_sha256': hashlib.sha256((args.records/'contract.json').read_bytes()).hexdigest(),
        'rows_sha256': {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in sorted((args.records/'rows').glob('*.json'))},
        'analysis_code_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'upstream_summary_unchanged': json.loads((args.records/'summary.json').read_bytes())}
    for name, value in {**result, 'provenance': provenance}.items():
        (args.output/(name+'.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    print(json.dumps(result['summary'], ensure_ascii=False, allow_nan=False))


if __name__ == '__main__':
    main()
