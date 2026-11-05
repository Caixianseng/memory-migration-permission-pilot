"""Offline audit of permission_runner artifacts; importing never sends a request.

Uses recorded native request/guard/receipt evidence, not account/home files.
Costs are frozen-tariff estimates, never supplier invoices. QA is an AI-authored
lexical diagnostic, never human or semantic correctness. Original files stay intact.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from decimal import Decimal
from itertools import combinations
import json
import math
from pathlib import Path
import re
import sys
import unicodedata

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from experiments.revocation_grouping_v1.evaluate import (
    audit_native_call, digest, native_usage_totals, number, _host_events,
)

TOKEN_KEYS = ('input_uncached_tokens', 'cache_read_tokens', 'cache_write_tokens',
              'input_total_tokens', 'output_tokens', 'total_tokens')
SUPPORTED_RUN_SCHEMAS = frozenset({
    'permission-prefix-real-paired-development-v1',
    'permission-prefix-real-paired-scale128-v1',
})


def read(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('evidence_symlink_not_allowed')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def normalize(text):
    text = unicodedata.normalize('NFKC', str(text)).casefold()
    return ' '.join(text.replace('’', "'").replace('–', '-').replace('—', '-').split())


def question_diagnostics(output, questions, labels):
    """Tolerate one JSON code fence; missing/non-string answers remain explicit."""
    text, fenced = output.strip(), False
    match = re.fullmatch(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.I | re.S)
    if match:
        text, fenced = match.group(1).strip(), True
    duplicates = []

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    try:
        answers = json.loads(text, object_pairs_hook=object_pairs)
        if not isinstance(answers, dict):
            raise ValueError('not_object')
        parse_error = None
    except (ValueError, TypeError):
        answers, parse_error = {}, 'not_json_answer_object'
    by_label = {row['question_id']: row for row in labels}
    rows, counts = [], Counter()

    def phrase_hit(phrase, value):
        if isinstance(phrase, (list, tuple)):
            return any(phrase_hit(part, value) for part in phrase)
        return isinstance(phrase, str) and bool(phrase) and normalize(phrase) in normalize(value)

    for i, question in enumerate(questions):
        qid = question.get('question_id', question.get('id', f'Q{i + 1}'))
        present = qid in answers
        value = answers.get(qid)
        valid_string = isinstance(value, str) and bool(value.strip())
        unknown = valid_string and normalize(value).strip(' .!。！') == 'unknown'
        legally_answerable = by_label.get(qid, {}).get('expected_legally_answerable')
        phrases = question.get('required_phrases')
        if isinstance(phrases, str):
            phrases = [phrases]
        hit = (all(phrase_hit(p, value) for p in phrases)
               if valid_string and isinstance(phrases, list) and phrases else None)
        counts['question_count'] += 1
        counts['missing_answer_count'] += not present
        counts['invalid_or_empty_answer_count'] += present and not valid_string
        counts['unknown_answer_count'] += bool(unknown)
        if legally_answerable is True:
            counts['legally_answerable_count'] += 1
            counts['legal_nonunknown_string_count'] += valid_string and not unknown
            counts['legal_unexpected_unknown_count'] += bool(unknown)
            counts['legal_phrase_checkable_count'] += hit is not None
            counts['legal_required_phrase_hit_count'] += bool(hit and not unknown)
        elif legally_answerable is False:
            counts['unanswerable_control_count'] += 1
            counts['control_exact_unknown_count'] += bool(unknown)
            counts['control_nonunknown_string_count'] += valid_string and not unknown
        else:
            counts['unknown_support_annotation_count'] += 1
        rows.append({'question_id': qid, 'answer_present': present,
                     'nonempty_string': valid_string, 'answer': value,
                     'expected_legally_answerable': legally_answerable,
                     'exact_unknown_marker': bool(unknown), 'required_phrase_hit': hit,
                     'required_phrases_AI_authored': question.get('AI_authored'),
                     'semantic_correct': None, 'human_gold': None})
    expected = {row['question_id'] for row in rows}
    return {'diagnostic_only': True, 'is_semantic_or_human_score': False,
            'fenced_json_accepted_nonstrictly': fenced, 'parse_error': parse_error,
            'duplicate_answer_ids': duplicates, 'unexpected_answer_ids': sorted(set(answers) - expected),
            'exact_question_ids': parse_error is None and not duplicates and set(answers) == expected,
            'counts': dict(counts), 'questions': rows, 'human_gold': None}


def _policy(config, arm, event):
    cfg = {key: value for key, value in config.items() if key != 'arm_policies'}
    cfg.update(config.get('arm_policies', {}).get(arm, {'method': arm}))
    if 'context' in event:
        cfg['context'] = event['context']
    return cfg


def _initial_read(row, run_dir, instrument_only):
    if instrument_only:
        return {'review_required': True, 'status': 'instrument_only_not_measured',
                'isolation_proven': False}
    usage = native_usage_totals(row['receipt']['usage'])
    path = Path(row['receipt']['record_path']).resolve()
    path.relative_to((run_dir / 'sdk.private').resolve())
    request = read(path / 'actual_request.json')
    before, found = 0, False
    for message in request['messages']:
        for piece in message['content']:
            text = piece['text']
            if row['nonce'] in text:
                before += len(text.split(row['nonce'], 1)[0].encode('utf-8'))
                found = True
                break
            before += len(text.encode('utf-8'))
        if found:
            break
    status = ('review_nonce_missing' if not found else
              'review_unexpected_fixed_wrapper_growth' if before > 384 else
              'review_excess_initial_cache_read' if usage['cache_read_tokens'] > 512 else
              'no_excess_initial_cache_read_observed')
    return {'initial_cache_read_tokens': usage['cache_read_tokens'],
            'native_text_before_nonce_utf8_bytes': before, 'review_required': status.startswith('review_'),
            'status': status, 'isolation_proven': False,
            'fixed_wrapper_read_alert_threshold_tokens': 512,
            'threshold_is_exact_tokenization': False}


def _audit_hosts(run_dir, manifest, rows, errors, complete):
    for arm in manifest['arms']:
        path = run_dir / arm / 'host' / 'events.jsonl'
        if path.is_symlink():
            errors.append(f'host:{arm}:evidence_symlink_not_allowed')
            continue
        events, failures = _host_events(path)
        errors.extend(f'host:{arm}:{failure}' for failure in failures)
        own = [row for row in rows if row.get('arm') == arm]
        prepared, receipts, observations = [], [], []
        current = None
        for event in events:
            kind, data = event.get('kind'), event.get('data', {})
            if kind == 'permission_committed':
                current = data.get('allowed')
            elif kind == 'delivery_prepared':
                prepared.append((event, current))
            elif kind == 'delivery_receipt':
                receipts.append(event)
            elif kind == 'completed_cache_order_observed':
                observations.append(event)
        commits = {event.get('data', {}).get('prepared'): event for event in events
                   if event.get('kind') == 'delivery_committed'}
        if (len(prepared) < len(own) or len(receipts) != len(own) or len(observations) != len(own)
                or complete and len(prepared) != len(own)):
            errors.append(f'host:{arm}:delivery_or_cache_observation_count_mismatch')
        registered = events[0].get('data', {}).get('sources') if events else None
        expected_registered = {sid: binding['text_sha256'] for sid, binding in manifest['source_binding'].items()}
        if registered != expected_registered:
            errors.append(f'host:{arm}:registered_source_hash_mismatch')
        for index, row in enumerate(own):
            if index >= min(len(prepared), len(receipts), len(observations)):
                continue
            prep, allowed = prepared[index]
            receipt, observation = receipts[index], observations[index]['data']
            commit = commits.get(prep['hash'])
            if (allowed != sorted(row['allowed']) or prep.get('revision') != row['permission_revision']
                    or prep['data'].get('sources') != sorted(row['dependencies'])
                    or prep['data'].get('memory_sha256') != row['memory_sha256']
                    or prep['data'].get('messages_sha256') != row['messages_sha256']
                    or not commit or not prep['seq'] < commit['seq'] < receipt['seq']
                    or commit['data'].get('sources') != sorted(row['dependencies'])
                    or receipt['data'].get('prepared') != prep['hash']
                    or receipt['data'].get('receipt') != row['receipt']):
                errors.append(f"call:{row['call_index']}:host_authorization_or_delivery_binding_mismatch")
            if (observation.get('ordered_source_ids') != row['dependencies']
                    or observation.get('source_binding') != manifest['source_binding']
                    or observation.get('source_binding_sha256') != manifest['source_binding_sha256']
                    or observation.get('completed') is not True
                    or observation.get('physical_request_count') != 1
                    or observation.get('request_id') != row['receipt'].get('request_id')
                    or observation.get('step') != row['step']):
                errors.append(f"call:{row['call_index']}:host_own_cache_observation_mismatch")


def _arm_totals(rows, expected_count, eligible, instrument_only):
    native = [row for row in rows if row['native_verified'] is True]
    cost_ready = len(native) == expected_count and not instrument_only
    result = {'expected_model_calls': expected_count, 'completed_model_calls': len(rows),
              'native_verified_model_calls': len(native), 'comparison_eligible': eligible,
              'full_lifecycle_cost_complete': cost_ready,
              'source_text_utf8_bytes': sum(row['source_text_utf8_bytes'] for row in rows),
              'rendered_memory_utf8_bytes': sum(row['memory_utf8_bytes'] for row in rows),
              'planning_ms': sum(row['planning_ms'] for row in rows),
              'qa_counts': dict(sum((Counter(row['qa']['counts']) for row in rows), Counter())),
              'initial_read_review_required': any(row.get('initial_cache_review', {}).get('review_required') for row in rows),
              'tokens': {key: sum(row['tokens'][key] for row in native) for key in TOKEN_KEYS},
              'cost_is_supplier_bill': False, 'human_semantic_correctness': None}
    for name in ('cached_peak_cost_cny', 'no_cache_peak_cost_cny'):
        values = [number(row.get(name)) for row in native]
        partial = sum(values, Decimal(0)) if all(value is not None for value in values) else None
        result['verified_receipted_' + name] = str(partial) if partial is not None else None
        result['full_lifecycle_' + name] = str(partial) if cost_ready and partial is not None else None
    result['cache_hit_fraction'] = (result['tokens']['cache_read_tokens'] / result['tokens']['input_total_tokens']
                                    if result['tokens']['input_total_tokens'] else None)
    return result


def _pairs(arms):
    result = []
    for left, right in combinations(sorted(arms), 2):
        a, b = arms[left], arms[right]
        valid = a['comparison_eligible'] and b['comparison_eligible']
        row = {'left_arm': left, 'right_arm': right, 'comparison_eligible': valid,
               'initial_read_review_required': a['initial_read_review_required'] or b['initial_read_review_required']}
        for kind in ('cached', 'no_cache'):
            key = 'full_lifecycle_' + kind + '_peak_cost_cny'
            x, y = number(a.get(key)), number(b.get(key))
            ready = valid and x is not None and y is not None
            row[kind + '_right_minus_left_cny'] = str(y - x) if ready else None
            row[kind + '_right_saving_fraction_vs_left'] = float((x - y) / x) if ready and x else None
        result.append(row)
    return result


def analyze_run(directory):
    run_dir = Path(directory).resolve()
    manifest, case = read(run_dir / 'frozen_manifest.json'), read(run_dir / 'frozen_case.json')
    evaluation, summary = read(run_dir / 'evaluation_only.json'), read(run_dir / 'summary.json')
    errors, reviews = [], []
    if manifest.get('schema') not in SUPPORTED_RUN_SCHEMAS:
        raise ValueError('unsupported_real_run_schema')
    if len(set(manifest['arms'])) != len(manifest['arms']) or any(re.fullmatch(r'[a-z0-9_]{1,64}', arm) is None for arm in manifest['arms']):
        raise ValueError('unsafe_or_duplicate_arm')
    binding = {s['source_id']: {'version': s.get('version', 1), 'text_sha256': digest(s['text'].encode('utf-8')),
               'text_utf8_bytes': len(s['text'].encode('utf-8'))} for s in case['sources']}
    if len(binding) != len(case['sources']) or binding != manifest['source_binding']:
        errors.append('frozen_source_binding_mismatch')
    for field, value in (('source_binding_sha256', binding), ('case_sha256', case),
                         ('schedule_sha256', manifest['schedule']), ('initial_history_sha256', manifest['initial_history'])):
        if digest(value) != manifest.get(field):
            errors.append(field + '_mismatch')
    if summary.get('manifest_sha256') != digest(manifest) or summary.get('case_id') != case['case_id'] or manifest['case_id'] != case['case_id']:
        errors.append('manifest_or_case_summary_binding_mismatch')
    nonces = manifest['nonces']
    if (set(nonces) != set(manifest['arms']) or len(set(nonces.values())) != len(nonces)
            or any(re.fullmatch(r'[0-9a-f]{64}', nonce) is None for nonce in nonces.values())):
        errors.append('arm_nonce_scope_invalid')
    expected = [(step, arm) for step, arms in enumerate(manifest['step_arm_order']) for arm in arms]
    if (len(manifest['step_arm_order']) != len(manifest['schedule'])
            or any(sorted(arms) != sorted(manifest['arms']) for arms in manifest['step_arm_order'])
            or len(expected) != manifest['max_jobs']):
        errors.append('frozen_call_schedule_mismatch')
    call_paths = sorted(path for path in (run_dir / 'calls').glob('*.json') if not path.name.endswith('.input.json'))
    rows = [read(path) for path in call_paths]
    input_paths = sorted((run_dir / 'calls').glob('*.input.json'))
    if [row.get('call_index') for row in rows] != list(range(1, len(rows) + 1)):
        errors.append('completed_call_index_gap_or_duplicate')
    if any(path.name != f"{row.get('call_index'):04d}.json" for path, row in zip(call_paths, rows)):
        errors.append('call_filename_index_mismatch')
    if summary.get('rows') != rows:
        errors.append('summary_completed_rows_mismatch')
    attempted = summary.get('model_calls_attempted')
    complete = len(rows) == len(expected) and summary.get('status') == 'completed'
    if not complete:
        errors.append('incomplete_run_full_lifecycle_comparison_unavailable')
    if type(attempted) is not int or not len(rows) <= attempted <= len(input_paths) or attempted > len(expected):
        errors.append('attempted_calls_or_pending_inputs_mismatch')
    if complete and (attempted != len(expected) or len(input_paths) != len(expected)):
        errors.append('complete_run_call_count_mismatch')
    events = {event['time']: event for event in evaluation['events']}
    if len(events) != len(manifest['schedule']) or set(events) != {e['time'] for e in manifest['schedule']}:
        errors.append('evaluation_event_schedule_mismatch')
    registry = {s['source_id']: s for s in case['sources']}
    own_cache = defaultdict(list)
    history = list(manifest['initial_history'])
    histories = []
    for step, event in enumerate(manifest['schedule']):
        if step:
            previous = manifest['schedule'][step - 1]
            change = {'before': previous['allowed'], 'after': event['allowed']}
            if 'context' in previous or 'context' in manifest['planner_config']:
                change['context'] = previous.get('context', manifest['planner_config'].get('context'))
            history = history + [change]
        histories.append(list(history))
    request_ids, call_results = set(), []
    instrument = summary.get('instrument_only') is True
    for index, row in enumerate(rows):
        failures, arm, step = [], row['arm'], row['step']
        prefix = f"call:{row['call_index']}:"
        if index >= len(expected) or (step, arm) != expected[index]:
            failures.append('execution_order_mismatch')
        if arm not in manifest['arms'] or type(step) is not int or not 0 <= step < len(manifest['schedule']):
            raise ValueError(prefix + 'invalid_arm_or_step')
        event = manifest['schedule'][step]
        ev = events.get(event['time'], {'questions': [], 'expected_support': []})
        allowed, order = event['allowed'], row['dependencies']
        if (row.get('time') != event['time'] or row['allowed'] != sorted(allowed)
                or len(order) != len(set(order)) or set(order) != set(allowed)
                or row['layout'].get('ordered_source_ids') != order):
            failures.append('current_authorization_or_full_permutation_mismatch')
        if set(order) - set(registry):
            raise ValueError(prefix + 'unknown_source_dependency')
        memory = '\n\n'.join(sid + '\n' + registry[sid]['text'] for sid in order)
        public = [{'question_id': q.get('question_id', q.get('id', f'Q{i+1}')), 'question': q.get('question', q.get('text'))}
                  for i, q in enumerate(ev['questions'])]
        if 'question_ids' in event and event['question_ids'] != [q['question_id'] for q in public]:
            failures.append('frozen_event_question_selection_mismatch')
        if row.get('max_tokens') != manifest.get('target_max_output_tokens', 1024):
            failures.append('frozen_output_limit_mismatch')
        try:
            payload = json.loads(row['messages'][1]['content'])
            expected_system = f"Qualification tag: {nonces[arm]}\n" + manifest['target_prompt']
            valid_payload = (len(row['messages']) == 2 and row['messages'][0] == {'role': 'system', 'content': expected_system}
                             and row['messages'][1]['role'] == 'user' and payload == {'memory': memory, 'questions': public})
        except (ValueError, KeyError, TypeError, IndexError):
            valid_payload = False
        if (not valid_payload or row.get('nonce') != nonces[arm]
                or row.get('memory_sha256') != digest(memory.encode('utf-8'))
                or row.get('messages_sha256') != digest(row['messages'])
                or row.get('memory_utf8_bytes') != len(memory.encode('utf-8'))
                or row.get('source_binding_sha256') != digest(binding)
                or row.get('all_current_allowed_sources_retained_verbatim') is not True):
            failures.append('verbatim_memory_or_business_message_hash_mismatch')
        if row.get('planner_input_history') != histories[step]:
            failures.append('planner_history_not_causal_observed_prefix')
        if row.get('planner_input_observed_orders') != own_cache[arm]:
            failures.append('planner_cache_not_own_prior_completed_orders')
        if row.get('planner_input_config') != _policy(manifest['planner_config'], arm, event):
            failures.append('planner_policy_or_context_mismatch')
        if row.get('planner_input_config', {}).get('known_source_lengths_bytes') != {sid: x['text_utf8_bytes'] for sid, x in binding.items()}:
            failures.append('planner_known_source_lengths_mismatch')
        pending = read(run_dir / 'calls' / f"{row['call_index']:04d}.input.json")
        if any(row.get(key) != value for key, value in pending.items()):
            failures.append('pre_dispatch_input_snapshot_mismatch')
        labels = ev['expected_support']
        label_ids = [label['question_id'] for label in labels]
        if label_ids != [q['question_id'] for q in public]:
            failures.append('question_support_label_id_mismatch')
        for question, label in zip(ev['questions'], labels):
            supports = question.get('support_sets', [question['support_source_ids']] if 'support_source_ids' in question else None)
            legal = any(set(s) <= set(allowed) for s in supports) if supports is not None else None
            if (supports != label.get('support_sets') or label.get('expected_legally_answerable') is not legal
                    or supports is not None and any(not s or set(s) - set(registry) for s in supports)):
                failures.append('expected_legally_answerable_annotation_mismatch')
        receipt = row['receipt']
        rid = receipt.get('request_id')
        if not isinstance(rid, str) or not rid or rid in request_ids:
            failures.append('request_id_missing_or_reused')
        request_ids.add(rid)
        if receipt.get('status') != 'ok' or receipt.get('physical_request_count') != 1:
            failures.append('successful_single_native_request_required')
        native = audit_native_call({'result': {'receipt': receipt, 'output': row['output']},
                                    'messages': row['messages'], 'max_tokens': row['max_tokens']}, run_dir / 'sdk.private') if not instrument else {'native_verified': None, 'errors': [], 'cost': None}
        failures.extend(native.get('errors', []))
        if native.get('native_verified') is True:
            response = read(Path(receipt['record_path']) / 'response.json')
            if (response.get('last_terminal_reason') != {'kind': 'completed'}
                    or response.get('final_assistant_interrupted') is not False):
                failures.append('native_terminal_completion_mismatch')
                native['native_verified'] = False
        try:
            tokens = native_usage_totals(receipt['usage'])
            if any(row.get('tokens', {}).get(key) != value for key, value in tokens.items()):
                failures.append('row_native_usage_copy_mismatch')
        except ValueError as error:
            tokens = {key: 0 for key in TOKEN_KEYS}
            failures.append(str(error))
        no_cache, cached = native.get('cost'), native.get('cost_cache_peak')
        if not instrument and (number(row.get('estimated_peak_cost_cny')) != no_cache
                               or number(row.get('estimated_cache_aware_peak_cost_cny')) != cached):
            failures.append('row_lifecycle_cost_copy_mismatch')
        if tokens['cache_write_tokens']:
            reviews.append(prefix + 'cache_write_tariff_unknown_cached_cost_unavailable')
        planning = row['layout'].get('planning_ms')
        if isinstance(planning, bool) or not isinstance(planning, (int, float)) or not math.isfinite(planning) or planning < 0:
            failures.append('planning_time_invalid')
            planning = 0.0
        result = {'call_index': row['call_index'], 'step': step, 'time': row['time'], 'arm': arm,
                  'request_id': rid, 'errors': failures, 'native_verified': native.get('native_verified'),
                  'source_text_utf8_bytes': sum(binding[sid]['text_utf8_bytes'] for sid in order),
                  'memory_utf8_bytes': len(memory.encode('utf-8')), 'planning_ms': planning, 'tokens': tokens,
                  'cached_peak_cost_cny': str(cached) if cached is not None else None,
                  'no_cache_peak_cost_cny': str(no_cache) if no_cache is not None else None,
                  'qa': question_diagnostics(row['output'], ev['questions'], labels)}
        if step == 0:
            try:
                result['initial_cache_review'] = _initial_read(row, run_dir, instrument)
                stored = row.get('initial_cache_isolation', {})
                if not instrument and (stored.get('status') != result['initial_cache_review']['status']
                                       or stored.get('initial_cache_read_tokens') != tokens['cache_read_tokens']):
                    failures.append('initial_read_diagnostic_copy_mismatch')
            except (OSError, KeyError, ValueError, TypeError):
                failures.append('initial_native_read_review_unavailable')
                result['initial_cache_review'] = {'review_required': True, 'isolation_proven': False}
        errors.extend(prefix + error for error in failures)
        call_results.append(result)
        if receipt.get('status') == 'ok' and receipt.get('physical_request_count') == 1:
            own_cache[arm].append(order)
    _audit_hosts(run_dir, manifest, rows, errors, complete)
    # Denormalized summary totals are checked against receipts, never trusted as
    # the source of the analysis totals. Older fixtures may omit these indexes.
    groups = [('physical_totals', summary.get('physical_totals'), call_results, len(expected))]
    groups += [('arm_totals:' + arm, summary.get('arm_totals', {}).get(arm),
                [r for r in call_results if r['arm'] == arm], len(manifest['schedule'])) for arm in manifest['arms']]
    for name, recorded, selected, expected_count in groups:
        if recorded is None or instrument:
            continue
        if (recorded.get('successful_calls') != len(selected)
                or recorded.get('tokens') != {key: sum(r['tokens'][key] for r in selected) for key in TOKEN_KEYS}):
            errors.append(name + ':summary_call_or_usage_totals_mismatch')
        for key, field in (('no_cache_peak_cost_cny', 'full_lifecycle_peak_cost_cny'),
                           ('cached_peak_cost_cny', 'full_lifecycle_cache_aware_peak_cost_cny')):
            values = [number(r.get(key)) for r in selected]
            full = (sum(values, Decimal(0)) if len(selected) == expected_count and all(v is not None for v in values) else None)
            if number(recorded.get(field)) != full:
                errors.append(name + ':summary_full_lifecycle_cost_mismatch')
    errors = list(dict.fromkeys(errors))
    eligible = complete and not instrument and not errors
    arms = {arm: _arm_totals([row for row in call_results if row['arm'] == arm], len(manifest['schedule']), eligible, instrument)
            for arm in manifest['arms']}
    return {'schema': 'permission-prefix-real-analysis-v1', 'run_directory': str(run_dir), 'case_id': case['case_id'],
            'source_run_schema': manifest['schema'],
            'content_cluster_id': case.get('cluster_id', case['case_id']),
            'materials_status': manifest.get('materials_status'), 'instrument_only': instrument,
            'complete_planned_call_matrix': complete, 'analysis_integrity_ok': not errors,
            'comparison_eligible': eligible, 'errors': errors, 'reviews': reviews,
            'model_calls_attempted': attempted, 'expected_model_calls': len(expected),
            'completed_model_calls': len(rows), 'unreceipted_attempts': max(0, attempted - len(rows)) if type(attempted) is int else None,
            'arm_policies': {arm: _policy(manifest['planner_config'], arm, {}) for arm in manifest['arms']},
            'initial_cache_isolation_proven': False, 'all_calls_include_initial_and_priming': True,
            'authorization_audit_scope': 'recorded trusted serial Host and first dispatch, not malicious-host authenticity or retrospective erasure',
            'qa_is_nonstrict_lexical_diagnostic_only': True, 'human_gold': None,
            'arms': arms, 'paired_costs': _pairs(arms), 'calls': call_results,
            'frozen_artifact_hashes': {name: digest((run_dir / name).read_bytes()) for name in
                                      ('frozen_manifest.json', 'frozen_case.json', 'evaluation_only.json', 'summary.json')}}


def analyze_runs(directories):
    resolved = [str(Path(path).resolve()) for path in directories]
    if not resolved:
        raise ValueError('at_least_one_run_directory_required')
    if len(resolved) != len(set(resolved)):
        raise ValueError('duplicate_run_directory_would_double_count_costs')
    runs = []
    for directory in resolved:
        try:
            runs.append(analyze_run(directory))
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            runs.append({'run_directory': directory, 'comparison_eligible': False,
                         'errors': ['unreadable_or_malformed_run:' + type(error).__name__], 'arms': {}, 'paired_costs': []})
    arm_names = sorted(set().union(*(run['arms'] for run in runs)))
    aggregate = {}
    for arm in arm_names:
        instances = [run['arms'][arm] for run in runs if arm in run['arms']]
        ready = len(instances) == len(runs) and all(row['comparison_eligible'] for row in instances)
        entry = {'case_run_count': len(instances), 'comparison_eligible': ready,
                 'completed_model_calls': sum(row['completed_model_calls'] for row in instances),
                 'source_text_utf8_bytes': sum(row['source_text_utf8_bytes'] for row in instances),
                 'planning_ms': sum(row['planning_ms'] for row in instances),
                 'qa_counts': dict(sum((Counter(row['qa_counts']) for row in instances), Counter())),
                 'initial_read_review_required': any(row['initial_read_review_required'] for row in instances),
                 'tokens': {key: sum(row['tokens'][key] for row in instances) for key in TOKEN_KEYS}}
        for kind in ('cached', 'no_cache'):
            key = 'full_lifecycle_' + kind + '_peak_cost_cny'
            values = [number(row.get(key)) for row in instances]
            entry[key] = str(sum(values, Decimal(0))) if ready and all(v is not None for v in values) else None
        aggregate[arm] = entry
    cases = Counter(run.get('case_id') for run in runs if run.get('case_id'))
    clusters = Counter(run.get('content_cluster_id') for run in runs if run.get('content_cluster_id'))
    return {'schema': 'permission-prefix-real-multirun-analysis-v1', 'run_count': len(runs),
            'unique_case_count': len(cases), 'repeated_case_ids': {cid: count for cid, count in cases.items() if count > 1},
            'independent_content_cluster_count': len(clusters),
            'content_cluster_run_counts': dict(clusters),
            'all_runs_comparison_eligible': all(run['comparison_eligible'] for run in runs),
            'cost_is_supplier_bill': False, 'qa_is_semantic_or_human_score': False, 'human_gold': None,
            'runs': runs, 'aggregate_arms': aggregate, 'aggregate_paired_costs': _pairs(aggregate)}


def write_analysis(path, report):
    path = Path(path).absolute()
    for run in report['runs']:
        try:
            path.resolve().relative_to((Path(run['run_directory']) / 'calls').resolve())
        except ValueError:
            continue
        raise ValueError('analysis_output_must_not_be_in_original_calls')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=Path, nargs='+', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze_runs(args.runs)
    write_analysis(args.output, report)
    print(json.dumps({'output': str(args.output.absolute()), 'run_count': report['run_count'],
                      'all_runs_comparison_eligible': report['all_runs_comparison_eligible'],
                      'aggregate_arms': report['aggregate_arms']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
