"""Six-call native-cache qualification on exposed development material.

This is a transport/cache feasibility check, not an algorithm-effect experiment.
No model call occurs on import. The CLI requires a fresh output directory and
never retries or resumes a failed/unknown request. Original inputs stay intact.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import random
import secrets
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, digest, save
from experiments.revocation_grouping_v1.lifecycle_runner import questions_at_time, target_messages
from experiments.revocation_grouping_v1.sdk_adapter import (
    FlashSDKClient, SDKAdapterError, dispatch_text, usage_costs,
)

OLD = REPO / 'experiments/revocation_grouping_v1'
CASE_ID = 'personamem-long-006'
SOURCE_IDS = tuple(f'S{i:02d}' for i in range(1, 9))
ARM_ORDERS = {'raw': SOURCE_IDS, 'stable_first': SOURCE_IDS[2:] + SOURCE_IDS[:2]}
PERMISSIONS = (SOURCE_IDS[:1] + SOURCE_IDS[2:], SOURCE_IDS[1:], SOURCE_IDS[1:])
NONCE_CHARS = 64
FIXED_WRAPPER_READ_ALERT_TOKENS = 512


def load_workload():
    paths = {'cases.jsonl': OLD / 'data_long_workload/cases.jsonl',
             'questions.json': OLD / 'data_long_workload/questions.json',
             'contract': OLD / 'workload_contract_long.json'}
    raw = {name: path.read_bytes() for name, path in paths.items()}
    contract = json.loads(raw['contract'])
    for name in ('cases.jsonl', 'questions.json'):
        if digest(raw[name]) != contract['data_files'][name]:
            raise ValueError('frozen_workload_hash_mismatch')
    cases = [json.loads(line) for line in raw['cases.jsonl'].decode('utf-8').splitlines() if line.strip()]
    matches = [case for case in cases if case['case_id'] == CASE_ID]
    if len(matches) != 1 or tuple(s['source_id'] for s in matches[0]['sources']) != SOURCE_IDS:
        raise ValueError('fixed_case_and_chronological_eight_sources_required')
    spec = json.loads(raw['questions.json'])[CASE_ID]
    batches = [questions_at_time(spec, step) for step in range(3)]
    return matches[0], batches, contract, {
        name: {'path': str(paths[name]), 'sha256': digest(body)} for name, body in raw.items()}


def render_allowed(current, frozen_order, registry, expected_allowed):
    """Validate an exact permutation and render only current verbatim sources."""
    if len(frozen_order) != len(registry) or set(frozen_order) != set(registry):
        raise ValueError('source_order_must_be_full_unique_permutation')
    by_id = {}
    for source in current:
        sid = source['source_id']
        if sid in by_id or sid not in registry or source.get('allow') is not True:
            raise ValueError('duplicate_unknown_or_forbidden_current_source')
        if source['text'] != registry[sid]['text'] or source.get('version', 1) != registry[sid].get('version', 1):
            raise ValueError('source_body_or_version_changed')
        by_id[sid] = source
    if set(by_id) != set(expected_allowed):
        raise ValueError('current_permission_set_mismatch')
    selected = [sid for sid in frozen_order if sid in by_id]
    memory = '\n\n'.join(sid + '\n' + by_id[sid]['text'] for sid in selected)
    if len(selected) != len(by_id) or set(selected) != set(expected_allowed):
        raise ValueError('rendered_source_set_mismatch')
    return memory, selected


def expected_support(questions, allowed):
    """Evaluator-only support labels; no reference answer enters the prompt."""
    allowed = set(allowed)
    result = []
    for question in questions:
        supports = question.get('support_sets', [question['support_source_ids']])
        if not supports or any(not support or not set(support) <= set(SOURCE_IDS) for support in supports):
            raise ValueError('invalid_question_support_annotation')
        result.append({'question_id': question['question_id'], 'support_sets': supports,
                       'currently_legal_complete_support_sets': [s for s in supports if set(s) <= allowed],
                       'expected_legally_answerable': any(set(s) <= allowed for s in supports),
                       'currently_missing_support_sources': sorted(set().union(*map(set, supports)) - allowed),
                       'human_gold': None})
    return result


def make_nonces():
    nonces = {arm: secrets.token_hex(NONCE_CHARS // 2) for arm in ARM_ORDERS}
    if len(set(nonces.values())) != len(nonces):
        return make_nonces()
    return nonces


def native_isolation(receipt, messages, nonce, *, instrument_only=False):
    """Initial READ is an observed diagnostic, never a theoretical cache hit.

    512 is a deliberately generous fixed-wrapper alert threshold, not a
    tokenizer result. Also expose actual pre-nonce native text bytes; unexpected
    wrapper growth or large initial reads require review rather than a pass.
    """
    result = {'initial_cache_read_tokens': receipt['usage'].get('cacheReadTokens', 0),
              'fixed_wrapper_read_alert_threshold_tokens': FIXED_WRAPPER_READ_ALERT_TOKENS,
              'threshold_is_exact_tokenization': False, 'isolation_proven': False}
    if instrument_only:
        return {**result, 'status': 'instrument_only_not_measured'}
    request = json.loads((Path(receipt['record_path']) / 'actual_request.json').read_bytes())
    expected = dispatch_text(messages)
    users = [piece['text'] for m in request['messages'] if m['role'] == 'user' for piece in m['content']]
    if len(users) != 2 or users[0] != expected or expected.count(nonce) != 1:
        raise ValueError('native_dispatch_or_nonce_binding_mismatch')
    before_nonce = 0
    found = False
    for message in request['messages']:
        for piece in message['content']:
            text = piece['text']
            if nonce in text:
                before_nonce += len(text.split(nonce, 1)[0].encode('utf-8'))
                found = True
                break
            before_nonce += len(text.encode('utf-8'))
        if found:
            break
    result['native_text_before_nonce_utf8_bytes'] = before_nonce
    result['status'] = ('review_unexpected_fixed_wrapper_growth' if before_nonce > 384 else
                        'review_excess_initial_cache_read' if result['initial_cache_read_tokens'] > FIXED_WRAPPER_READ_ALERT_TOKENS else
                        'no_excess_initial_cache_read_observed')
    return result


def update_summary(output, summary):
    # Preserve immutable checkpoints before refreshing the convenience index.
    # Avoid a filesystem rename requirement on managed Windows temp locations.
    summary['checkpoint'] = summary.get('checkpoint', 0) + 1
    save(output / 'progress' / f"{summary['checkpoint']:03d}.json", summary)
    with (output / 'summary.json').open('w', encoding='utf-8') as stream:
        json.dump(summary, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def totals(rows, expected_calls):
    cache_costs = [row['estimated_cache_aware_peak_cost_cny'] for row in rows]
    peak = str(sum((Decimal(row['estimated_peak_cost_cny']) for row in rows), Decimal(0)))
    cache_peak = (str(sum((Decimal(cost) for cost in cache_costs), Decimal(0)))
                  if all(cost is not None for cost in cache_costs) else None)
    complete = len(rows) == expected_calls
    return {'successful_calls': len(rows), 'full_lifecycle_cost_complete': complete,
            'tokens': {key: sum(row['tokens'][key] for row in rows) for key in (
                'input_uncached_tokens', 'cache_read_tokens', 'cache_write_tokens',
                'input_total_tokens', 'output_tokens', 'total_tokens')},
            'successful_receipted_peak_cost_cny': peak,
            'successful_receipted_cache_aware_peak_cost_cny': cache_peak,
            'full_lifecycle_peak_cost_cny': peak if complete else None,
            'full_lifecycle_cache_aware_peak_cost_cny': cache_peak if complete else None,
            'includes_initial_call_and_all_warmup': True, 'cost_is_supplier_bill': False}


def aggregate(rows):
    return {arm: totals([row for row in rows if row['arm'] == arm], 3) for arm in ARM_ORDERS}


def run(output, *, client=None, nonces=None, order_seed=None):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('fresh_output_directory_required_no_resume')
    case, batches, contract, inputs = load_workload()
    registry = {source['source_id']: source for source in case['sources']}
    nonces = make_nonces() if nonces is None else dict(nonces)
    if (set(nonces) != set(ARM_ORDERS) or len(set(nonces.values())) != 2
            or any(len(nonce) != NONCE_CHARS or any(c not in '0123456789abcdef' for c in nonce) for nonce in nonces.values())):
        raise ValueError('distinct_equal_length_hex_nonces_required')
    order_seed = secrets.randbits(64) if order_seed is None else order_seed
    rng = random.Random(order_seed)
    step_orders = []
    for _ in range(3):
        arms = list(ARM_ORDERS)
        rng.shuffle(arms)
        step_orders.append(arms)
    plan = {'schema': 'prefix-native-cache-qualification-v1', 'case_id': CASE_ID,
            'stage': 'exposed_development_cache_qualification_only', 'input_files': inputs,
            'nonces': nonces, 'nonce_placement': 'start_of_embedded_system_before_original_target_prompt',
            'arm_orders': ARM_ORDERS, 'step_arm_order': step_orders, 'arm_order_seed': order_seed,
            'permissions_by_step': PERMISSIONS, 'max_jobs': 6, 'budget_cap_cny': '0.5',
            'target_max_output_tokens': 1024, 'original_target_prompt': contract['target_prompt'],
            'question_ids_by_step': [[q['question_id'] for q in questions] for questions in batches],
            'original_source_order': SOURCE_IDS,
            'source_text_sha256': {sid: digest(source['text'].encode('utf-8')) for sid, source in registry.items()},
            'code_sha256': digest(Path(__file__).read_bytes()),
            'automatic_retry': False, 'human_gold': None, 'cost_is_supplier_bill': False,
            'fixed_wrapper_read_alert_threshold_tokens': FIXED_WRAPPER_READ_ALERT_TOKENS,
            'not_formal_algorithm_effect_evidence': True}
    output.mkdir(parents=True, exist_ok=False)
    save(output / 'qualification_plan.json', plan)
    save(output / 'evaluation_only.json', {'human_gold': None, 'expected_support_by_step': [
        expected_support(questions, allowed) for questions, allowed in zip(batches, PERMISSIONS)]})
    summary = {'schema': plan['schema'], 'status': 'running', 'case_id': CASE_ID,
               'instrument_only': bool(getattr(client, 'instrument_only', False)), 'rows': [],
               'model_calls_attempted': 0, 'automatic_retry': False, 'human_gold': None,
               'cost_is_supplier_bill': False, 'not_formal_algorithm_effect_evidence': True}
    update_summary(output, summary)
    try:
        if client is None:
            client = FlashSDKClient(output / 'sdk.private', budget_cap_cny=0.5, max_jobs=6)
        hosts = {arm: LifecycleHost(case['sources'], output / arm / 'host') for arm in ARM_ORDERS}
        call_index = 0
        for step, arms in enumerate(step_orders):
            for arm in arms:
                host = hosts[arm]
                if step < 2:
                    host.set_permissions(PERMISSIONS[step])
                else:
                    host.log('policy_state_reused', {'qualification_step': step, 'previous_step': 1})
                memory, dependencies = render_allowed(host.allowed_sources(), ARM_ORDERS[arm], registry, PERMISSIONS[step])
                messages = target_messages(memory, batches[step], contract)
                messages[0]['content'] = f'Qualification tag: {nonces[arm]}\n' + messages[0]['content']
                call_index += 1
                pending = {'call_index': call_index, 'arm': arm, 'step': step, 'nonce': nonces[arm],
                           'allowed': sorted(PERMISSIONS[step]), 'dependencies': dependencies,
                           'frozen_source_order': list(ARM_ORDERS[arm]), 'messages': messages,
                           'messages_sha256': digest(messages), 'memory_sha256': digest(memory.encode('utf-8')),
                           'memory_utf8_bytes': len(memory.encode('utf-8')), 'max_tokens': 1024,
                           'permission_revision': host.revision, 'all_allowed_original_text_retained': True}
                save(output / 'calls' / f'{call_index:03d}.input.json', pending)

                def invoke():
                    summary['model_calls_attempted'] += 1
                    update_summary(output, summary)
                    return client.generate(messages, f'prefix-qualification-{call_index:02d}', 1024, 'target')

                answer = host.deliver(memory, dependencies, messages, invoke)
                receipt = answer['receipt']
                if receipt.get('status') != 'ok' or receipt.get('physical_request_count') != 1:
                    raise ValueError('single_successful_native_receipt_required')
                tokens, peak, cache_peak = usage_costs(receipt['usage'])
                row = {**pending, 'output': answer['output'], 'receipt': receipt, 'tokens': tokens,
                       'estimated_peak_cost_cny': str(peak),
                       'estimated_cache_aware_peak_cost_cny': str(cache_peak) if cache_peak is not None else None,
                       'cost_is_supplier_bill': False}
                if step == 0:
                    row['initial_cache_isolation'] = native_isolation(receipt, messages, nonces[arm], instrument_only=summary['instrument_only'])
                save(output / 'calls' / f'{call_index:03d}.json', row)
                summary['rows'].append(row)
                summary['arm_totals'] = aggregate(summary['rows'])
                update_summary(output, summary)
        summary['status'] = 'completed'
        summary['full_lifecycle_cost_complete'] = True
        summary['isolation_review_required'] = any(
            row.get('initial_cache_isolation', {}).get('status', '').startswith('review_') for row in summary['rows'])
    except BaseException as error:
        summary['status'] = 'failed_no_automatic_retry'
        summary['failure_class'] = type(error).__name__
        summary['failure_code'] = str(error) if isinstance(error, SDKAdapterError) else 'inspect_local_failure_record'
        summary['full_lifecycle_cost_complete'] = False
        summary['unknown_or_failed_request_not_retried'] = True
        raise
    finally:
        summary['arm_totals'] = aggregate(summary['rows'])
        summary['physical_totals'] = totals(summary['rows'], 6)
        update_summary(output, summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    summary = run(args.output)
    print(json.dumps({key: summary[key] for key in (
        'status', 'model_calls_attempted', 'arm_totals', 'physical_totals', 'isolation_review_required',
        'cost_is_supplier_bill', 'not_formal_algorithm_effect_evidence')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
