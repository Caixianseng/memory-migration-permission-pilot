"""Frozen three-regime native bridge: 96 calls maximum, no retries."""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path

from .permission_runner import run, digest, save, code_manifest
from experiments.revocation_grouping_v1.sdk_adapter import FlashSDKClient

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUTPUT = REPO / 'results/revocation_prefix_v1/exact-native-20261105-v1'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--continue-completed-batch', action='store_true',
        help='Skip only proven completed runs; refuse any incomplete/unknown request. Never retry a call.')
    args = parser.parse_args()
    continuing = args.continue_completed_batch
    if OUTPUT.exists() and not continuing:
        raise ValueError('fresh_batch_required_no_retry_or_resume')
    inputs = {
        'cases': HERE / 'data_reserved/cases.jsonl',
        'questions': HERE / 'data_reserved/questions_reserved.json',
        'trace': HERE / 'exact_screen_v1/frozen_cases.json',
        'contract': REPO / 'experiments/revocation_grouping_v1/workload_contract_long.json'}
    raw = {key: path.read_bytes() for key, path in inputs.items()}
    cases = {c['case_id']: c for c in (json.loads(line) for line in raw['cases'].decode('utf-8').splitlines())}
    questions, traces = json.loads(raw['questions']), json.loads(raw['trace'])
    prompt = json.loads(raw['contract'])['target_prompt']
    config = {'forecast_model': 'independent_status_marginal', 'next_cost_weight': 1.0,
        'risk_cut_threshold': .75, 'arm_policies': {
            'exact': {'method': 'exact_two_step'}, 'greedy': {'method': 'cache_greedy_forecast_tail'}}}
    selected = [('coordinated-00', 'personamem-long-008'),
                ('independent-00', 'personamem-long-009'), ('ood-00', 'personamem-long-008')]
    plans = []
    for trace_id, case_id in selected:
        trace = next(c for c in traces if c['case_id'] == trace_id)
        spec = questions[case_id]
        schedule = [{'time': t, 'allowed': state,
                     'question_ids': spec['question_schedule'][str(t % 4)]}
                    for t, state in enumerate(trace['test_states'])]
        plans.append({'trace_id': trace_id, 'case_id': case_id, 'case': cases[case_id],
                      'questions': spec, 'events': schedule, 'history': trace['training_transitions']})
    if not continuing:
        OUTPUT.mkdir(parents=True, exist_ok=False)
    manifest = {'stage': 'bounded_native_bridge_exploratory', 'created_utc': datetime.now(timezone.utc).isoformat(),
        'selected_first_replicate_of_each_registered_regime': selected,
        'selection_did_not_use_per_trace_effects': True,
        'permission_traces_previously_proxy_evaluated': True, 'unseen_permission_claim': False,
        'public_content_previously_downloaded_not_used_in_native_calls': True,
        'independent_content_clusters': 2, 'permission_trace_count': 3,
        'arms': ['exact', 'greedy'], 'config': config,
        'max_calls': 96, 'budget_cap_cny_per_run': '2', 'budget_cap_cny_batch_maximum': '6',
        'all_initial_priming_calls_counted': True, 'automatic_retry': False,
        'input_files': {k: {'path': str(inputs[k]), 'sha256': digest(body)} for k, body in raw.items()},
        'code_manifest': code_manifest(), 'batch_driver_sha256': digest(Path(__file__).read_bytes()),
        'new_exact_solver_cost_gain_cannot_be_inferred_from_shared_old_heuristic_orders': True,
        'human_gold': None}
    completed = []
    if continuing:
        previous = json.loads((OUTPUT / 'batch_manifest.json').read_text(encoding='utf-8'))
        frozen_plans = json.loads((OUTPUT / 'frozen_plans.json').read_text(encoding='utf-8'))
        if (previous['input_files'] != manifest['input_files'] or previous['code_manifest'] != code_manifest()
                or previous['config'] != config or digest(frozen_plans) != digest(plans)):
            raise ValueError('continuation_frozen_code_or_inputs_changed')
        for plan in plans:
            run_dir = OUTPUT / plan['trace_id']
            if not run_dir.exists():
                continue
            summary = json.loads((run_dir / 'summary.json').read_text(encoding='utf-8'))
            calls = list((run_dir / 'calls').glob('*.json'))
            outputs = [path for path in calls if not path.name.endswith('.input.json')]
            if (summary['status'] != 'completed' or summary['model_calls_attempted'] != 32
                    or len(summary['rows']) != 32 or len(outputs) != 32 or len(calls) != 64
                    or any(r['receipt']['status'] != 'ok' or r['receipt']['physical_request_count'] != 1
                           for r in summary['rows'])):
                raise ValueError('incomplete_or_unknown_prior_run_must_never_be_retried')
            completed.append(plan['trace_id'])
        save(OUTPUT / 'continuation_001.json', {'skip_completed_only': completed,
            'no_model_request_retried': True, 'frozen_code_manifest': code_manifest(),
            'reason': 'batch-only immutable status filename collision after first run completed',
            'new_batch_driver_sha256': digest(Path(__file__).read_bytes())})
    else:
        save(OUTPUT / 'batch_manifest.json', manifest)
        save(OUTPUT / 'frozen_plans.json', plans)
        # Official account metadata only; never submits a model prompt.
        metadata = FlashSDKClient(OUTPUT / 'metadata.private', budget_cap_cny=.5, max_jobs=1).preflight()
        save(OUTPUT / 'metadata_safe.json', metadata)
    status = {'status': 'running', 'runs': [], 'max_calls': 96, 'automatic_retry': False}
    progress = OUTPUT / ('progress_continuation_001' if continuing else 'progress_initial')
    progress.mkdir(exist_ok=False)
    save(progress / '000_initial.json', status)
    try:
        for index, plan in enumerate(plans):
            if plan['trace_id'] in completed:
                summary = json.loads((OUTPUT / plan['trace_id'] / 'summary.json').read_text(encoding='utf-8'))
                status['runs'].append({'trace_id': plan['trace_id'], 'case_id': plan['case_id'],
                    'status': 'completed_previously_not_retried', 'calls': 32, 'arm_totals': summary['arm_totals']})
                continue
            print(json.dumps({'starting': plan['trace_id'], 'native_calls': 32}), flush=True)
            summary = run(plan['case'], plan['questions'], plan['events'], plan['history'],
                OUTPUT / plan['trace_id'], arms=['exact', 'greedy'], config=config,
                budget_cap_cny='2', max_jobs=32, target_prompt=prompt,
                input_files=manifest['input_files'])
            status['runs'].append({'trace_id': plan['trace_id'], 'case_id': plan['case_id'],
                'status': summary['status'], 'calls': summary['model_calls_attempted'],
                'arm_totals': summary['arm_totals']})
            save(progress / f'{index + 1:03d}_run_completed.json', status)
            print(json.dumps(status['runs'][-1], ensure_ascii=False), flush=True)
        status['status'] = 'completed'
    except BaseException as error:
        status.update(status='failed_no_retry', error_class=type(error).__name__)
        raise
    finally:
        save(progress / '999_final.json', status)


if __name__ == '__main__':
    main()
