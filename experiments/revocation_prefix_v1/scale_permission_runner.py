"""Bounded 1..128-source paired quotient-solver native bridge.

Importing sends nothing. Each arm/event uses one fresh target SDK request,
including every initial/cache-priming request. No automatic retry or resume.
Future schedules and evaluator references never enter plan_layout inputs.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from decimal import Decimal
import json
import math
from pathlib import Path
import random
import re
import secrets
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, digest, save
from experiments.revocation_grouping_v1.lifecycle_runner import public_question, questions_at_time, target_messages
from experiments.revocation_grouping_v1.sdk_adapter import FlashSDKClient, SDKAdapterError, usage_costs
from experiments.revocation_prefix_v1 import planner
from experiments.revocation_prefix_v1 import exact_planner
from experiments.revocation_prefix_v1 import quotient_planner
from experiments.revocation_prefix_v1.cache_qualification import native_isolation, totals, update_summary

DEFAULT_CONFIG = {'min_conditional_samples': 2, 'next_cost_weight': 1.0,
                  'max_candidates': 192, 'max_observed_orders': 128, 'risk_cut_threshold': .75}
MAX_RUN_CALLS = 512
CODE_FILES = (Path(__file__), Path(planner.__file__), Path(exact_planner.__file__), Path(quotient_planner.__file__), Path(native_isolation.__code__.co_filename),
              REPO / 'experiments/revocation_grouping_v1/lifecycle_host.py',
              REPO / 'experiments/revocation_grouping_v1/lifecycle_runner.py',
              REPO / 'experiments/revocation_grouping_v1/sdk_adapter.py',
              REPO / 'experiments/revocation_grouping_v1/dsh_group_guard.mjs')


def code_manifest():
    return {str(path.relative_to(REPO)): digest(path.read_bytes()) for path in CODE_FILES}


IMPORT_CODE_HASHES = code_manifest()


def unique_ids(value, name, universe=None):
    if not isinstance(value, (list, tuple)) or any(not isinstance(sid, str) or not sid for sid in value):
        raise ValueError(name + '_must_be_source_id_list')
    if len(set(value)) != len(value) or (universe is not None and not set(value) <= set(universe)):
        raise ValueError(name + '_contains_duplicate_or_unknown_id')
    return list(value)


def source_binding(sources):
    result = {}
    for source in sources:
        sid, text, version = source['source_id'], source['text'], source.get('version', 1)
        if (not isinstance(sid, str) or not sid or sid in result or not isinstance(text, str) or not text
                or isinstance(version, bool) or not isinstance(version, (int, str)) or version == ''):
            raise ValueError('invalid_source_identity_text_or_version')
        result[sid] = {'version': version, 'text_sha256': digest(text.encode('utf-8')),
                       'text_utf8_bytes': len(text.encode('utf-8'))}
    if not 1 <= len(result) <= 128:
        raise ValueError('one_to_128_immutable_sources_required')
    return result


def validate_current(current, registry, allowed):
    records = {}
    for source in current:
        sid = source['source_id']
        if sid in records or sid not in registry or source.get('allow') is not True:
            raise ValueError('duplicate_unknown_or_forbidden_current_source')
        if source['text'] != registry[sid]['text'] or source.get('version', 1) != registry[sid].get('version', 1):
            raise ValueError('immutable_source_body_or_version_changed')
        records[sid] = source
    if set(records) != set(allowed):
        raise ValueError('host_current_permissions_do_not_match_frozen_event')
    return records


def render_current(current, order, registry, allowed):
    records = validate_current(current, registry, allowed)
    order = unique_ids(order, 'planner_order', records)
    if set(order) != set(records):
        raise ValueError('planner_order_must_include_all_current_sources_once')
    return '\n\n'.join(sid + '\n' + records[sid]['text'] for sid in order), order


def usable_completed_orders(observations, binding):
    """Only own successful dispatches in this immutable content/version scope."""
    result = []
    binding_hash = digest(binding)
    for row in observations:
        if row.get('source_binding_sha256') != binding_hash or row.get('source_binding') != binding:
            continue
        order = unique_ids(row['ordered_source_ids'], 'completed_order', binding)
        if row.get('completed') is True and row.get('physical_request_count') == 1:
            result.append(order)
    return result


def event_questions(spec, event):
    if 'question_ids' not in event:
        questions = questions_at_time(spec, event.get('question_time', event['time']))
    else:
        bank = spec if isinstance(spec, list) else spec['questions']
        by_id = {public_question(q, i)['question_id']: q for i, q in enumerate(bank)}
        if len(by_id) != len(bank):
            raise ValueError('question_bank_requires_unique_question_ids')
        ids = unique_ids(event['question_ids'], 'question_ids', by_id)
        questions = [by_id[qid] for qid in ids]
    if not 1 <= len(questions) <= 8 or any(not isinstance(public_question(q, i)['question'], str) for i, q in enumerate(questions)):
        raise ValueError('each_event_requires_one_to_eight_question_texts')
    return deepcopy(questions)


def support_labels(questions, allowed, universe):
    result, allowed = [], set(allowed)
    for i, question in enumerate(questions):
        support = question.get('support_sets')
        if support is None and 'support_source_ids' in question:
            support = [question['support_source_ids']]
        if support is not None:
            if not isinstance(support, list) or not support:
                raise ValueError('invalid_support_sets')
            support = [unique_ids(s, 'support_set', universe) for s in support]
            if any(not s for s in support):
                raise ValueError('nonempty_support_set_required')
        result.append({'question_id': public_question(question, i)['question_id'],
                       'support_sets': support, 'support_annotation_available': support is not None,
                       'expected_legally_answerable': any(set(s) <= allowed for s in support) if support is not None else None,
                       'currently_legal_complete_support_sets': [s for s in support if set(s) <= allowed] if support is not None else None,
                       'human_gold': None})
    return result


def arm_config(config, arm):
    """Resolve a frozen policy label without passing other arms to the planner."""
    result = deepcopy(config)
    policies = result.pop('arm_policies', {})
    policy = policies.get(arm, {'method': arm})
    if not isinstance(policy, dict) or set(policy) - {'method', 'forecast_model'}:
        raise ValueError('arm_policy_requires_only_method_and_optional_forecast_model')
    if policy.get('method') not in ('quotient_two_step', 'quotient_cache_greedy'):
        raise ValueError('unknown_arm_policy_method')
    return {**result, **policy}


def choose_layout(sources, history, cache, config):
    return quotient_planner.plan_layout(sources, history, cache, config)


def prepare(case, question_spec, schedule, history, arms, config, budget_cap_cny, max_jobs):
    case = deepcopy(case)
    binding = source_binding(case['sources'])
    registry = {source['source_id']: source for source in case['sources']}
    if not isinstance(case.get('case_id'), str) or not case['case_id']:
        raise ValueError('case_id_required')
    arms = unique_ids(arms, 'arms')
    if not arms:
        raise ValueError('at_least_one_arm_required')
    if any(re.fullmatch(r'[a-z0-9_]{1,64}', arm) is None for arm in arms):
        raise ValueError('arm_labels_must_be_safe_simple_identifiers')
    cap = Decimal(str(budget_cap_cny))
    if not cap.is_finite() or cap <= 0:
        raise ValueError('finite_positive_explicit_budget_cap_required')
    if not isinstance(schedule, list) or not schedule:
        raise ValueError('nonempty_schedule_list_required')
    if type(max_jobs) is not int or max_jobs != len(arms) * len(schedule) or not 1 <= max_jobs <= MAX_RUN_CALLS:
        raise ValueError('max_jobs_must_equal_arms_times_events_within_512')
    frozen_events, question_batches = [], []
    previous_time = -math.inf
    for original_event in schedule:
        if not isinstance(original_event, dict) or set(original_event) - {'time', 'allowed', 'question_ids', 'question_time', 'context'}:
            raise ValueError('unsupported_schedule_event_fields')
        event = deepcopy(original_event)
        timepoint = event.get('time')
        if type(timepoint) is not int or timepoint < 0 or timepoint <= previous_time:
            raise ValueError('strictly_increasing_nonnegative_integer_event_times_required')
        previous_time = timepoint
        event['allowed'] = unique_ids(event['allowed'], 'event_allowed', binding)
        question_batches.append(event_questions(question_spec, event))
        frozen_events.append(event)
    if not isinstance(history, list):
        raise ValueError('historical_transitions_list_required')
    for row in history:
        if not isinstance(row, dict) or set(row) - {'before', 'after', 'context'} or not {'before', 'after'} <= set(row):
            raise ValueError('history_must_only_contain_observed_before_after_optional_context')
        unique_ids(row['before'], 'history_before', binding)
        unique_ids(row['after'], 'history_after', binding)
    if not isinstance(config, dict) or set(config) - set(DEFAULT_CONFIG) - {'context', 'forecast_model', 'arm_policies', 'max_signature_groups', 'max_explicit_forecast_states'}:
        raise ValueError('only_explicit_planner_thresholds_and_optional_context_allowed')
    policies = config.get('arm_policies', {})
    if not isinstance(policies, dict) or set(policies) - set(arms):
        raise ValueError('arm_policies_must_map_registered_arms_only')
    cfg = {**DEFAULT_CONFIG, **deepcopy(config),
           'known_source_lengths_bytes': {sid: b['text_utf8_bytes'] for sid, b in binding.items()}}
    # Validate actual planner types/thresholds on the first legal view only.
    first = [{**registry[sid], 'allow': True} for sid in registry if sid in frozen_events[0]['allowed']]
    for arm in (arms if policies else arms[:1]):
        choose_layout(first, deepcopy(history), [], {**arm_config(cfg, arm),
                            **({'context': frozen_events[0]['context']} if 'context' in frozen_events[0] else {})})
    evaluation = [{'time': event['time'], 'questions': questions,
                   'expected_support': support_labels(questions, event['allowed'], binding)}
                  for event, questions in zip(frozen_events, question_batches)]
    # Canonical encoding also rejects nonfinite/nonserializable context metadata.
    digest({'events': frozen_events, 'history': history, 'config': cfg})
    return case, registry, binding, frozen_events, question_batches, deepcopy(history), arms, cfg, str(cap), evaluation


def run(case, question_spec, schedule, history, output, *, arms, config,
        budget_cap_cny, max_jobs, target_prompt, input_files=None,
        client=None, nonces=None, order_seed=None):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('fresh_output_directory_required_no_resume')
    if not isinstance(target_prompt, str) or not target_prompt:
        raise ValueError('fixed_target_prompt_required')
    case, registry, binding, events, batches, initial_history, arms, cfg, cap, evaluation = prepare(
        case, question_spec, schedule, history, arms, config, budget_cap_cny, max_jobs)
    nonces = {arm: secrets.token_hex(32) for arm in arms} if nonces is None else dict(nonces)
    if (set(nonces) != set(arms) or len(set(nonces.values())) != len(arms)
            or any(not isinstance(n, str) or len(n) != 64 or any(c not in '0123456789abcdef' for c in n) for n in nonces.values())):
        raise ValueError('distinct_equal_length_random_hex_nonces_required')
    seed = secrets.randbits(64) if order_seed is None else order_seed
    rng, step_orders = random.Random(seed), []
    for _ in events:
        order = list(arms)
        rng.shuffle(order)
        step_orders.append(order)
    hashes = code_manifest()
    if hashes != IMPORT_CODE_HASHES:
        raise ValueError('loaded_code_changed_restart_before_any_call')
    plan = {'schema': 'permission-prefix-real-paired-scale128-v1', 'case_id': case['case_id'],
            'materials_status': case.get('split', 'development_exposed_content_permission_events_may_be_new'),
            'not_unseen_content_or_independent_human_evidence': True,
            'input_files': input_files or {}, 'code_manifest': hashes, 'source_binding': binding,
            'source_binding_sha256': digest(binding), 'case_sha256': digest(case),
            'schedule': events, 'schedule_sha256': digest(events),
            'initial_history': initial_history, 'initial_history_sha256': digest(initial_history),
            'planner_config': cfg, 'arms': arms, 'step_arm_order': step_orders, 'arm_order_seed': seed,
            'nonces': nonces, 'nonce_placement': 'start_of_embedded_system_before_fixed_target_prompt',
            'target_prompt': target_prompt, 'target_max_output_tokens': 1024,
            'budget_cap_cny': cap, 'max_jobs': max_jobs,
            'history_update_rule': 'append_observed_previous_to_current_permission_transition_before_all_arms_at_each_event',
            'history_context_rule': 'context_observable_at_before_state',
            'cache_observation_rule': 'own_completed_successful_actual_orders_only_with_matching_text_version_binding',
            'all_initial_and_priming_calls_counted': True, 'automatic_retry': False,
            'cost_is_supplier_bill': False, 'human_gold': None}
    output.mkdir(parents=True, exist_ok=False)
    save(output / 'frozen_manifest.json', plan)
    save(output / 'frozen_case.json', case)
    save(output / 'evaluation_only.json', {'human_gold': None, 'events': evaluation})
    summary = {'schema': plan['schema'], 'status': 'running', 'case_id': case['case_id'],
               'instrument_only': bool(getattr(client, 'instrument_only', False)),
               'manifest_sha256': digest(plan), 'rows': [], 'model_calls_attempted': 0,
               'automatic_retry': False, 'cost_is_supplier_bill': False, 'human_gold': None,
               'materials_status': plan['materials_status']}
    update_summary(output, summary)
    try:
        if client is None:
            client = FlashSDKClient(output / 'sdk.private', budget_cap_cny=cap, max_jobs=max_jobs)
        hosts = {arm: LifecycleHost(case['sources'], output / arm / 'host') for arm in arms}
        observed = {arm: [] for arm in arms}
        past = deepcopy(initial_history)
        call_index = 0
        for step, event in enumerate(events):
            if step:
                previous = events[step - 1]
                transition = {'before': previous['allowed'], 'after': event['allowed']}
                if 'context' in previous or 'context' in cfg:
                    transition['context'] = previous.get('context', cfg.get('context'))
                past.append(deepcopy(transition))
            for arm in step_orders[step]:
                host = hosts[arm]
                host.set_permissions(event['allowed'])
                current = host.allowed_sources()
                validate_current(current, registry, event['allowed'])
                own_cache = usable_completed_orders(observed[arm], binding)
                live_cfg = arm_config(cfg, arm)
                if 'context' in event:
                    live_cfg['context'] = deepcopy(event['context'])
                layout = choose_layout(deepcopy(current), deepcopy(past), deepcopy(own_cache), live_cfg)
                memory, dependencies = render_current(current, layout['ordered_source_ids'], registry, event['allowed'])
                messages = target_messages(memory, batches[step], {'target_prompt': target_prompt})
                messages[0]['content'] = f'Qualification tag: {nonces[arm]}\n' + messages[0]['content']
                call_index += 1
                row = {'call_index': call_index, 'arm': arm, 'step': step, 'time': event['time'],
                       'nonce': nonces[arm], 'allowed': sorted(event['allowed']), 'dependencies': dependencies,
                       'permission_revision': host.revision, 'source_binding_sha256': digest(binding),
                       'memory_sha256': digest(memory.encode('utf-8')), 'memory_utf8_bytes': len(memory.encode('utf-8')),
                       'messages': messages, 'messages_sha256': digest(messages), 'max_tokens': 1024,
                       'planner_input_history': deepcopy(past), 'planner_input_observed_orders': own_cache,
                       'planner_input_config': live_cfg, 'layout': layout,
                       'all_current_allowed_sources_retained_verbatim': True}
                save(output / 'calls' / f'{call_index:04d}.input.json', row)

                def invoke():
                    if code_manifest() != hashes:
                        raise ValueError('frozen_code_changed_before_dispatch')
                    summary['model_calls_attempted'] += 1
                    update_summary(output, summary)
                    return client.generate(messages, f'permission-prefix-{call_index:04d}', 1024, 'target')

                answer = host.deliver(memory, dependencies, messages, invoke)
                receipt = answer['receipt']
                if receipt.get('status') != 'ok' or receipt.get('physical_request_count') != 1 or not isinstance(answer['output'], str):
                    raise ValueError('single_completed_native_receipt_and_text_required')
                tokens, peak, cache_peak = usage_costs(receipt['usage'])
                row.update(output=answer['output'], receipt=receipt, tokens=tokens,
                           estimated_peak_cost_cny=str(peak),
                           estimated_cache_aware_peak_cost_cny=str(cache_peak) if cache_peak is not None else None,
                           cost_is_supplier_bill=False)
                if step == 0:
                    row['initial_cache_isolation'] = native_isolation(receipt, messages, nonces[arm], instrument_only=summary['instrument_only'])
                save(output / 'calls' / f'{call_index:04d}.json', row)
                summary['rows'].append(row)
                observation = {'completed': True, 'physical_request_count': 1,
                               'case_id': case['case_id'], 'ordered_source_ids': dependencies,
                               'source_binding': deepcopy(binding), 'source_binding_sha256': digest(binding),
                               'request_id': receipt['request_id'], 'step': step}
                observed[arm].append(observation)
                host.log('completed_cache_order_observed', observation)
                summary['arm_totals'] = {name: totals([r for r in summary['rows'] if r['arm'] == name], len(events)) for name in arms}
                update_summary(output, summary)
        summary['status'] = 'completed'
        summary['full_lifecycle_cost_complete'] = True
        summary['isolation_review_required'] = any(
            r.get('initial_cache_isolation', {}).get('status', '').startswith('review_') for r in summary['rows'])
    except BaseException as error:
        summary.update(status='failed_no_automatic_retry', failure_class=type(error).__name__,
                       failure_code=str(error) if isinstance(error, SDKAdapterError) else 'inspect_local_failure_record',
                       full_lifecycle_cost_complete=False, unknown_or_failed_request_not_retried=True)
        raise
    finally:
        summary['arm_totals'] = {arm: totals([r for r in summary['rows'] if r['arm'] == arm], len(events)) for arm in arms}
        summary['physical_totals'] = totals(summary['rows'], max_jobs)
        update_summary(output, summary)
    return summary


def read_json_input(path, name, manifest):
    path = Path(path).absolute()
    raw = path.read_bytes()
    manifest[name] = {'path': str(path), 'sha256': digest(raw)}
    if path.suffix.lower() == '.jsonl':
        return [json.loads(line) for line in raw.decode('utf-8-sig').splitlines() if line.strip()]
    return json.loads(raw.decode('utf-8-sig'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cases', 'questions', 'schedule', 'history', 'config', 'contract', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--case-id', required=True)
    parser.add_argument('--arms', required=True, help='Comma-separated planner method names')
    parser.add_argument('--budget-cap-cny', required=True)
    parser.add_argument('--max-jobs', type=int, required=True)
    args = parser.parse_args()
    inputs = {}
    cases = read_json_input(args.cases, 'cases', inputs)
    cases = cases.get('cases', [cases]) if isinstance(cases, dict) else cases
    selected = [case for case in cases if case['case_id'] == args.case_id]
    if len(selected) != 1:
        raise ValueError('one_exact_case_id_required')
    questions = read_json_input(args.questions, 'questions', inputs)
    spec = questions.get(args.case_id, questions) if isinstance(questions, dict) else questions
    schedule = read_json_input(args.schedule, 'schedule', inputs)
    schedule = schedule.get('events', schedule) if isinstance(schedule, dict) else schedule
    history = read_json_input(args.history, 'history', inputs)
    history = history.get('transitions', history) if isinstance(history, dict) else history
    config = read_json_input(args.config, 'config', inputs)
    contract = read_json_input(args.contract, 'contract', inputs)
    summary = run(selected[0], spec, schedule, history, args.output,
                  arms=args.arms.split(','), config=config, budget_cap_cny=args.budget_cap_cny,
                  max_jobs=args.max_jobs, target_prompt=contract['target_prompt'], input_files=inputs)
    print(json.dumps({key: summary[key] for key in (
        'status', 'model_calls_attempted', 'arm_totals', 'physical_totals',
        'isolation_review_required', 'cost_is_supplier_bill', 'materials_status')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
