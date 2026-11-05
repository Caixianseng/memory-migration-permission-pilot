"""Read-only 204+24 native comparison, retaining official unadjusted metrics.

Only explicitly named run manifests, original rows, native/host artifacts and
evaluation labels are read. Independent-review packets/labels are never read.
All 12 calls per arm enter lifecycle usage, costs and latency, including first
calls and policy views outside the primary answer subset. No model API calls.
"""
import argparse
from collections import Counter, defaultdict
from decimal import Decimal
import hashlib
from itertools import product
import json
from pathlib import Path

from .eval_fusion import evaluate_rows
from .summarize_offline import paired_effect

HERE = Path(__file__).resolve().parent
CLASSIC_CONTROLS = ('h0p0r0', 'h1p0r0', 'fixed_rerank', 'adaptive_bm25', 'neighbor',
                    'parent_bm25', 'bm25_bridge', 'hierarchy_bridge',
                    'authorized_parent_bm25_top3', 'authorized_parent_bm25_top4')
FULL_FUSION_ARMS = ('h1p1r1', 'fusion_bridge')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_run(root):
    root = Path(root).resolve()
    manifest = json.loads((root/'manifest.json').read_bytes())
    status = json.loads((root/'status.json').read_bytes())
    files = sorted((root/'rows').glob('*.json'))
    rows = [json.loads(file.read_bytes()) for file in files]
    if (status.get('status') != 'completed' or status['completed'] != manifest['max_calls']
            or status['attempted'] != manifest['max_calls'] or len(rows) != manifest['max_calls']
            or any(row.get('status') != 'completed' for row in rows)):
        raise ValueError('complete_successful_registered_run_required')
    expected = {(plan['case_id'], arm, entry['event']['time']) for plan in manifest['plans']
                for entry in plan['events'] for arm in manifest['arms']}
    actual = [(row['case_id'], row['arm'], row['time']) for row in rows]
    if len(set(actual)) != len(actual) or set(actual) != expected:
        raise ValueError('run_matrix_not_exactly_manifest_cells')
    nonces = []
    plans = {plan['case_id']: plan for plan in manifest['plans']}
    for plan in plans.values():
        nonces.extend(plan['nonces'].values())
    if len(set(nonces)) != len(nonces) or len(set(map(len, nonces))) != 1:
        raise ValueError('nonunique_or_unequal_length_nonces')
    for row in rows:
        plan = plans[row['case_id']]
        nonce = plan['nonces'][row['arm']]
        system = row['messages'][0]['content']
        event = [entry['event'] for entry in plan['events'] if entry['event']['time'] == row['time']]
        if system.count(nonce) != 1 or not system.startswith('Qualification tag: '+nonce+'\n'):
            raise ValueError('case_arm_fixed_system_start_nonce_binding_failed')
        if len(event) != 1 or set(event[0]['allowed']) != set(row['allowed']):
            raise ValueError('actual_policy_not_equal_to_manifest')
    initial = [row for row in rows if row['step'] == 0]
    if len(initial) != len(manifest['cases'])*len(manifest['arms']):
        raise ValueError('all_initial_calls_must_be_retained')
    scope = {'full_run_complete': True, 'expected_rows': manifest['max_calls'], 'observed_rows': len(rows),
        'independent_question_clusters': len(manifest['cases']), 'arms': manifest['arms'],
        'case_arm_initial_calls': len(initial),
        'initial_cache_read_tokens': [row['initial_cache_isolation']['initial_cache_read_tokens'] for row in initial],
        'initial_flag_counts': dict(Counter(row['initial_cache_isolation']['status'] for row in initial)),
        'unique_equal_length_fixed_case_arm_nonces': True,
        'lifecycle_estimated_cold_peak_cost_cny': str(sum((Decimal(row['receipt']['estimated_peak_cost_cny']) for row in rows), Decimal(0))),
        'lifecycle_estimated_native_cache_aware_peak_cost_cny': str(sum((Decimal(row['receipt']['estimated_cache_aware_peak_cost_cny']) for row in rows), Decimal(0))),
        'all_initial_and_priming_calls_counted': True, 'cost_is_supplier_bill': False}
    provenance = {'root': str(root), 'manifest_sha256': sha(root/'manifest.json'),
        'status_sha256': sha(root/'status.json'), 'input_rows_sha256': {file.name: sha(file) for file in files}}
    return rows, manifest, scope, provenance, nonces


def _mean(values):
    return sum(values) / len(values) if values else None


def compare(rows, evaluation_result, case_ids):
    scored = {(row['case_id'], row['arm'], row['time']): row for row in evaluation_result['rows']}
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['arm'], row['case_id']].append(row)
    per_question, table, raw_latency = {}, [], []
    for arm, aggregate in evaluation_result['summary']['arms'].items():
        points = []
        for cid in case_ids:
            trajectory = sorted(grouped[arm, cid], key=lambda row: row['time'])
            eligible = [scored[cid, arm, row['time']] for row in trajectory if scored[cid, arm, row['time']]['primary_eligible']]
            init = trajectory[0]['trace']['initialization_ms']
            if len(trajectory) != 3 or any(row['trace']['initialization_ms'] != init for row in trajectory):
                raise ValueError('three_state_initialization_binding_failed')
            if not eligible:
                raise ValueError('question_has_no_primary_eligible_view')
            prepare = sum(row['trace']['total_prepare_ms'] for row in trajectory)
            point = {'case_id': cid, 'calls': 3, 'primary_eligible_views': len(eligible),
                'official_primary_em': _mean([row['answer']['em'] for row in eligible]),
                'official_primary_f1': _mean([row['answer']['f1'] for row in eligible]),
                'cold_peak_cny': float(sum((Decimal(row['receipt']['estimated_peak_cost_cny']) for row in trajectory), Decimal(0))),
                'native_cache_aware_peak_cny': float(sum((Decimal(row['receipt']['estimated_cache_aware_peak_cost_cny']) for row in trajectory), Decimal(0))),
                'initialization_ms': init, 'prepare_ms': prepare, 'local_initialization_plus_prepare_ms': init+prepare,
                'target_wall_ms': sum(row['target_wall_ms'] for row in trajectory),
                'native_latency_seconds': sum(row['receipt']['latency_seconds'] for row in trajectory)}
            points.append(point)
            for row in trajectory:
                raw_latency.append({'case_id': cid, 'arm': arm, 'time': row['time'],
                    'target_wall_ms': row['target_wall_ms'], 'native_latency_seconds': row['receipt']['latency_seconds'],
                    'initialization_ms_recorded_for_pipeline': row['trace']['initialization_ms'],
                    'prepare_ms': row['trace']['total_prepare_ms']})
        per_question[arm] = points
        table.append({'arm': arm, 'calls': aggregate['observations'], 'independent_questions': len(points),
            'primary_eligible_views': aggregate['primary_eligible_views'],
            'official_primary_view_em': aggregate['primary_answer_em'],
            'official_primary_view_f1': aggregate['primary_answer_f1'],
            'official_primary_question_macro_em': aggregate['primary_question_macro_em'],
            'official_primary_question_macro_f1': aggregate['primary_question_macro_f1'],
            'eligible_complete_annotated_support_views': aggregate['primary_complete_annotated_support_views'],
            'estimated_cold_peak_cny': aggregate['estimated_peak_cost_cny_observed'],
            'estimated_native_cache_aware_peak_cny': aggregate['estimated_cache_aware_peak_cost_cny_observed'],
            'native_tokens': aggregate['native_tokens'],
            'initialization_ms_total': sum(p['initialization_ms'] for p in points),
            'prepare_ms_total': sum(p['prepare_ms'] for p in points),
            'local_initialization_plus_prepare_ms_total': sum(p['local_initialization_plus_prepare_ms'] for p in points),
            'target_wall_ms_total': sum(p['target_wall_ms'] for p in points),
            'native_latency_seconds_total': sum(p['native_latency_seconds'] for p in points),
            'all_first_and_regrant_calls_in_costs': True, 'cost_is_supplier_bill': False})
    by_arm = {row['arm']: row for row in table}
    def best(arms):
        # This is an openly post-outcome summary, not tuning or a new algorithm.
        return sorted(arms, key=lambda arm: (-by_arm[arm]['official_primary_question_macro_f1'],
            -by_arm[arm]['official_primary_question_macro_em'],
            Decimal(by_arm[arm]['estimated_native_cache_aware_peak_cny']), arm))[0]
    selected = {'raw': 'raw', 'highest_observed_classic_control': best([arm for arm in CLASSIC_CONTROLS if arm in by_arm]),
        'highest_observed_non_full_fusion': best([arm for arm in by_arm if arm not in FULL_FUSION_ARMS and arm != 'raw']),
        'highest_observed_full_fusion': best([arm for arm in FULL_FUSION_ARMS if arm in by_arm])}
    samples = list(product(range(len(case_ids)), repeat=len(case_ids)))
    pairs = {(arm, 'raw') for arm in by_arm if arm != 'raw'}
    fusion = selected['highest_observed_full_fusion']
    pairs |= {(fusion, selected['highest_observed_classic_control']), (fusion, selected['highest_observed_non_full_fusion'])}
    contrasts = []
    for candidate, control in sorted(pairs):
        metrics = {}
        for key in ('official_primary_em', 'official_primary_f1', 'cold_peak_cny',
                    'native_cache_aware_peak_cny', 'local_initialization_plus_prepare_ms',
                    'target_wall_ms', 'native_latency_seconds'):
            metrics[key] = paired_effect([point[key] for point in per_question[candidate]],
                [point[key] for point in per_question[control]], samples)
        contrasts.append({'candidate': candidate, 'control': control, 'metrics': metrics})
    return {'table': table, 'per_question': per_question, 'latency_rows': raw_latency,
        'selected_descriptive_comparison': {'selection': selected,
            'selection_rule': 'observed primary question-macro official F1 desc, then EM desc, cache-aware cost asc, arm name',
            'posthoc_selection_is_not_confirmation_or_tuning': True,
            'classic_control_definition': list(CLASSIC_CONTROLS), 'full_fusion_definition': list(FULL_FUSION_ARMS),
            'table': [{**by_arm[arm], 'comparison_role': role} for role, arm in selected.items()]},
        'paired_contrasts': contrasts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main-run', type=Path, required=True)
    parser.add_argument('--strong-run', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evaluation', type=Path, default=HERE/'data_hotpot/evaluation_only.json')
    parser.add_argument('--schedules', type=Path, default=HERE/'data_hotpot/schedules.json')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('fresh_combined_analysis_required')
    main_rows, main_manifest, main_scope, main_provenance, main_nonces = read_run(args.main_run)
    strong_rows, strong_manifest, strong_scope, strong_provenance, strong_nonces = read_run(args.strong_run)
    if main_manifest['cases'] != strong_manifest['cases'] or main_manifest['data_hashes'] != strong_manifest['data_hashes']:
        raise ValueError('runs_must_share_identical_original_case_bodies_and_policy_data')
    if set(main_manifest['arms']) & set(strong_manifest['arms']):
        raise ValueError('overlapping_arms_cannot_be_selectively_replaced')
    if len(set(main_nonces+strong_nonces)) != len(main_nonces+strong_nonces):
        raise ValueError('cross_run_nonce_collision')
    if (sha(args.evaluation) != main_manifest['data_hashes']['evaluation_only.json']
            or sha(args.schedules) != main_manifest['data_hashes']['schedules.json']):
        raise ValueError('evaluation_or_schedule_hash_not_frozen_input')
    rows = main_rows+strong_rows
    root = args.main_run.resolve().parent
    if args.strong_run.resolve().parent != root:
        raise ValueError('run_artifacts_must_share_results_parent')
    result = evaluate_rows(rows, json.loads(args.evaluation.read_bytes()), cases=main_manifest['cases'],
                           schedules=json.loads(args.schedules.read_bytes()), artifacts_root=root)
    if any(row['audit_status'] != 'verified' for row in result['rows']):
        raise ValueError('strict_actual_payload_host_native_audit_failed')
    case_ids = [case['case_id'] for case in main_manifest['cases']]
    if len(case_ids) != 4 or len(result['summary']['arms']) != 19 or len(rows) != 228:
        raise ValueError('registered_four_question_nineteen_arm_228_call_matrix_required')
    if result['summary']['observed_matrix_missing_cells']:
        raise ValueError('combined_matrix_incomplete')
    comparison = compare(rows, result, case_ids)
    summary = {'status': 'completed', 'full_two_run_lifecycle_complete': True,
        'strict_audit_status_counts': dict(Counter(row['audit_status'] for row in result['rows'])),
        'rows': len(rows), 'arms': 19, 'calls_per_arm': 12, 'independent_question_clusters': 4,
        'primary_eligible_views_per_arm': {arm: value['primary_eligible_views'] for arm, value in result['summary']['arms'].items()},
        'first_calls_retained': len(main_nonces+strong_nonces), 'cross_run_nonces_distinct': True,
        'all_initial_cache_read_tokens_zero': all(value == 0 for scope in (main_scope, strong_scope) for value in scope['initial_cache_read_tokens']),
        'total_estimated_cold_peak_cost_cny': str(sum((Decimal(row['receipt']['estimated_peak_cost_cny']) for row in rows), Decimal(0))),
        'total_estimated_native_cache_aware_peak_cost_cny': str(sum((Decimal(row['receipt']['estimated_cache_aware_peak_cost_cny']) for row in rows), Decimal(0))),
        'cost_is_supplier_bill': False, 'all_initialization_and_prepare_measurements_retained': True,
        'local_timers_measure_wall_time_not_process_cpu_utilization': True,
        'local_host_constructor_and_preflight_not_per_arm_instrumented': True,
        'shared_ranker_startup': json.loads((args.main_run/'local_ranker_setup.json').read_bytes()),
        'official_metric_rule': result['summary']['official_answer_metric_source'],
        'official_aliases_or_gold_answers_changed': False, 'case_exclusions_due_to_short_format_gold': [],
        'known_scoring_issue': 'Original short-format gold can penalize a longer answer or name/date variant. Official EM/F1 remain unadjusted; no adjudication files read or adjusted semantic score inferred here.',
        'missing_annotated_support_is_not_a_proof_of_unanswerability': True,
        'bootstrap': {'unit': 'paired original question, all repeated policy states retained inside question',
            'independent_questions': 4, 'resamples': 4**4, 'enumeration': 'all ordered empirical question-bootstrap resamples',
            'interval': 'pointwise percentile 95%; exploratory, not multiplicity/selection adjusted',
            'no_stable_superiority_claim': True},
        'sequential_runs_are_not_a_single_interleaved_19_arm_randomized_run': True,
        'independent_ai_review_packets_or_labels_read': False, 'analysis_model_api_calls': 0}
    provenance = {'main': main_provenance, 'strong': strong_provenance,
        'evaluation_sha256': sha(args.evaluation), 'schedules_sha256': sha(args.schedules),
        'analysis_code_sha256': sha(__file__), 'evaluator_code_sha256': sha(HERE/'eval_fusion.py')}
    args.output.mkdir(parents=True)
    for name, value in {'summary': summary, **comparison, 'rows_evaluated': result['rows'],
                         'official_aggregate': result['summary'], 'run_scopes': [main_scope, strong_scope], 'provenance': provenance}.items():
        (args.output/(name+'.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    # Complete the strict standalone followup scope without changing raw rows.
    scope_file = args.strong_run/'analysis-all/scope.json'
    if scope_file.exists():
        raise ValueError('strong_subrun_scope_must_be_fresh')
    scope_file.write_text(json.dumps(strong_scope, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'summary': summary, 'selected': comparison['selected_descriptive_comparison']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
