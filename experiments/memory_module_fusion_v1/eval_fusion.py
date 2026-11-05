"""Read-only native outcome evaluator; never imports or starts a model client.

Answer normalization/EM/token F1 follow the official Hotpot evaluator at
https://github.com/hotpotqa/hotpot/blob/fa3a36370899e1d85822de61e58c85ea19993154/hotpot_evaluate_v1.py
(blob 50b0c2b2a123d183b65310debd35ba470c3a8104), including its categorical
yes/no/noanswer and empty-token behavior. No support-fact or joint answer score
is inferred from retrieval IDs. Missing annotations do not establish that an
answer is impossible under a changed permission view.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import string

from experiments.revocation_grouping_v1.sdk_adapter import usage_costs, dispatch_text

OFFICIAL_EVALUATOR = ('https://github.com/hotpotqa/hotpot/blob/'
    'fa3a36370899e1d85822de61e58c85ea19993154/hotpot_evaluate_v1.py')


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _hash(value):
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _text_hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def normalize_answer(answer):
    lowered = ''.join(ch for ch in answer.lower() if ch not in string.punctuation)
    return ' '.join(re.sub(r'\b(a|an|the)\b', ' ', lowered).split())


def answer_metrics(prediction, gold):
    pred, truth = normalize_answer(prediction), normalize_answer(gold)
    em = float(pred == truth)
    special = {'yes', 'no', 'noanswer'}
    if pred != truth and (pred in special or truth in special):
        return {'em': em, 'f1': 0., 'precision': 0., 'recall': 0.}
    p, g = pred.split(), truth.split()
    common = sum((Counter(p) & Counter(g)).values())
    if not common:
        return {'em': em, 'f1': 0., 'precision': 0., 'recall': 0.}
    precision, recall = common / len(p), common / len(g)
    return {'em': em, 'f1': 2 * precision * recall / (precision + recall),
            'precision': precision, 'recall': recall}


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value


def extract_answer(output, question_id):
    """One deterministic parse, without searching for a gold-favorable substring."""
    if not isinstance(output, str):
        return '', 'missing_or_nonstring_output'
    text = output.strip()
    wrapped = re.fullmatch(r'```(?:json)?\s*\n?(.*?)\n?```', text, flags=re.S)
    candidate = wrapped.group(1).strip() if wrapped else text
    try:
        obj = json.loads(candidate, object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        # A JSON-looking malformed result is a format failure, not a plain answer.
        return ('', 'invalid_answer_json') if candidate.startswith(('{', '[')) else (text, 'plain_text')
    if isinstance(obj, str):
        return obj, 'json_string'
    if not isinstance(obj, (dict, list)):
        # A bare year/quantity is a plain textual answer, even if JSON accepts it.
        return text, 'plain_text'
    if isinstance(obj, dict):
        if isinstance(obj.get('answer'), str):
            if 'question_id' in obj and obj['question_id'] != question_id:
                return '', 'wrong_question_id'
            return obj['answer'], 'answer_object'
        if isinstance(obj.get(question_id), str):
            return obj[question_id], 'question_mapping'
        obj = obj.get('answers', obj)
        if isinstance(obj, dict) and isinstance(obj.get(question_id), str):
            return obj[question_id], 'answers_mapping'
    if isinstance(obj, list):
        matches = [entry for entry in obj if isinstance(entry, dict)
                   and entry.get('question_id') == question_id]
        if len(matches) == 1 and isinstance(matches[0].get('answer'), str):
            return matches[0]['answer'], 'answers_list'
    return '', 'missing_or_ambiguous_answer'


def _artifact(path, root, filename=None):
    if root is None or not path:
        return None
    root = Path(root).resolve()
    target = Path(path)
    target = (target if target.is_absolute() else root / target).resolve()
    if filename:
        target /= filename
    if not target.is_relative_to(root):
        raise ValueError('artifact_path_outside_results_root')
    return target


def _prepared(row):
    return row.get('prepared') or row.get('trace', {}).get('prepared')


def audit_payload(row, case):
    issues, unknown = [], []
    allowed, selected = set(row['allowed']), row['selected']
    forbidden = sorted(set(selected) - allowed)
    if forbidden:
        issues.append('forbidden_delivery_dependencies')
    if len(set(selected)) != len(selected):
        issues.append('duplicate_selected_source_ids')
    if not isinstance(row.get('context'), str):
        return {'issues': issues + ['missing_context'], 'unverified': unknown,
                'forbidden_source_ids': forbidden, 'reconstructed': False}
    if row.get('context_sha256') not in (None, _text_hash(row['context'])):
        issues.append('context_hash_mismatch')
    if case is None:
        unknown.append('source_bodies_not_provided')
    else:
        sources = {s['source_id']: s for s in case['sources']}
        if (set(selected) | allowed) - sources.keys():
            issues.append('unknown_source_id')
        else:
            packet = _prepared(row)
            if packet is None:
                rebuilt = '\n\n'.join(sid + '\n' + sources[sid]['text'] for sid in selected)
                body_bytes = sum(len(sources[sid]['text'].encode('utf-8')) for sid in selected)
            else:
                if packet.get('source_ids') != selected:
                    issues.append('prepared_dependencies_differ_from_selected')
                witnesses = packet.get('witnesses', [])
                if [w.get('source_id') for w in witnesses] != selected:
                    issues.append('incomplete_full_source_witnesses')
                bindings = {w.get('source_id'): w for w in witnesses}
                for sid in selected:
                    source, witness = sources[sid], bindings.get(sid, {})
                    if (witness.get('version') != source.get('version', 1)
                            or witness.get('text_sha256') != _text_hash(source['text'])):
                        issues.append('full_source_version_or_hash_mismatch')
                pieces, body_bytes = [], 0
                for span in packet.get('span_witnesses', []):
                    sid, start, end = span.get('source_id'), span.get('start'), span.get('end')
                    if (sid not in selected or sid not in sources or type(start) is not int
                            or type(end) is not int or not 0 <= start < end <= len(sources[sid]['text'])):
                        issues.append('invalid_span_binding')
                        continue
                    original = sources[sid]['text'][start:end]
                    if (span.get('excerpt') != original or span.get('quote_sha256') != _text_hash(original)
                            or span.get('source_sha256') != _text_hash(sources[sid]['text'])
                            or span.get('version') != sources[sid].get('version', 1)
                            or span.get('permission_version') != bindings.get(sid, {}).get('permission_version')):
                        issues.append('nonoriginal_or_stale_span')
                    body_bytes += len(original.encode('utf-8'))
                    if packet.get('render_format') == 'full_sources_v1':
                        if start != 0 or end != len(sources[sid]['text']):
                            issues.append('partial_span_claimed_as_full_source')
                        pieces.append(sid + '\n' + original)
                    elif packet.get('render_format') == 'original_spans_v1':
                        pieces.append(json.dumps({'source_id': sid, 'char_start': start, 'char_end': end},
                            ensure_ascii=False, sort_keys=True) + '\n' + original)
                    else:
                        issues.append('unknown_span_render_format')
                rebuilt = '\n\n'.join(pieces)
                if packet.get('context') != row['context'] or packet.get('context_sha256') != _text_hash(row['context']):
                    issues.append('prepared_context_binding_mismatch')
                if packet.get('source_bytes') != body_bytes:
                    issues.append('prepared_source_byte_count_mismatch')
            if rebuilt != row['context']:
                issues.append('context_not_exactly_reconstructed_from_originals')
            if row.get('source_bytes') not in (None, body_bytes):
                issues.append('row_source_byte_count_mismatch')
    messages = row.get('messages')
    if messages is None:
        unknown.append('actual_business_messages_not_recorded')
    else:
        try:
            if (not isinstance(messages, list) or len(messages) != 2
                    or [m['role'] for m in messages] != ['system', 'user']
                    or any(set(m) != {'role', 'content'} for m in messages)):
                raise ValueError('invalid_messages')
            payload = json.loads(messages[1]['content'], object_pairs_hook=_unique_object)
            if set(payload) != {'memory', 'questions'} or payload['memory'] != row['context']:
                raise ValueError('unbound_context')
            expected_id = row.get('question_id', row['case_id'])
            if (not isinstance(payload['questions'], list) or len(payload['questions']) != 1
                    or set(payload['questions'][0]) != {'question_id', 'question'}
                    or payload['questions'][0]['question_id'] != expected_id
                    or (case is not None and payload['questions'][0]['question'] != case['question'])):
                raise ValueError('wrong_public_question')
        except (ValueError, KeyError, TypeError):
            issues.append('actual_messages_not_bound_to_context_and_public_question')
    return {'issues': sorted(set(issues)), 'unverified': unknown,
            'forbidden_source_ids': forbidden, 'reconstructed': not issues and case is not None}


def audit_native(row, artifacts_root=None):
    issues, unknown, tokens, costs = [], [], None, None
    receipt = row.get('receipt')
    if not isinstance(receipt, dict):
        return {'issues': [], 'unverified': ['missing_native_receipt'], 'tokens': None, 'costs': None}
    if receipt.get('status') != 'ok' or receipt.get('physical_request_count') != 1:
        issues.append('native_call_not_one_successful_request')
    try:
        tokens, peak, cache = usage_costs(receipt.get('usage'))
        for field in ('input_total_tokens', 'input_uncached_tokens', 'cache_read_tokens', 'cache_write_tokens', 'output_tokens'):
            if field in receipt and receipt[field] != tokens[field]:
                issues.append('receipt_native_usage_fields_disagree')
        for field, amount in (row.get('tokens') or {}).items():
            if field in tokens and amount != tokens[field]:
                issues.append('row_native_usage_fields_disagree')
        costs = {'estimated_peak_cost_cny': str(peak),
                 'estimated_cache_aware_peak_cost_cny': str(cache) if cache is not None else None,
                 'is_supplier_bill': False}
        for key in ('estimated_peak_cost_cny', 'estimated_cache_aware_peak_cost_cny'):
            if key in receipt and (None if receipt[key] is None else Decimal(str(receipt[key]))) != (None if costs[key] is None else Decimal(costs[key])):
                issues.append('receipt_cost_not_equal_to_frozen_sdk_estimate')
    except (RuntimeError, TypeError, ValueError, ArithmeticError):
        issues.append('invalid_or_missing_native_usage')
    if receipt.get('cost_is_supplier_bill') is not False:
        issues.append('receipt_does_not_mark_estimate_not_supplier_bill')
    output = row.get('output') if isinstance(row.get('output'), str) else ''
    if receipt.get('response_sha256') != _text_hash(output):
        issues.append('output_not_bound_to_native_receipt')
    messages = row.get('messages')
    expected_dispatch = None
    if messages is not None:
        if receipt.get('business_messages_sha256') != _hash(messages):
            issues.append('native_business_messages_hash_mismatch')
        try:
            expected_dispatch = dispatch_text(messages)
            if receipt.get('dispatch_sha256') != _text_hash(expected_dispatch):
                issues.append('native_dispatch_hash_mismatch')
        except (RuntimeError, ValueError, TypeError):
            issues.append('invalid_native_business_messages')
    else:
        unknown.append('native_dispatch_messages_missing')
    try:
        guard = row.get('guard')
        record = _artifact(receipt.get('record_path'), artifacts_root)
        if guard is None and record is not None:
            guard_file = record / 'guard.json'
            guard = json.loads(guard_file.read_bytes()) if guard_file.is_file() else None
        if guard is None:
            unknown.append('actual_request_guard_not_available')
        else:
            requests = guard.get('requests', [])
            if (guard.get('agent_attempt_count') != 1 or guard.get('stream_attempt_count') != 1
                    or guard.get('allowed_stream_count') != 1 or guard.get('reject_code') is not None
                    or len(requests) != 1):
                issues.append('actual_request_guard_not_single_allowed_stream')
            else:
                request = requests[0]
                if (request.get('bodyhash') != receipt.get('request_sha256')
                        or request.get('business_input_sha256') != receipt.get('dispatch_sha256')
                        or request.get('tools') != 0 or request.get('reasoningEffort') != 'off'
                        or request.get('user_text_blocks') != 2):
                    issues.append('actual_guard_request_binding_mismatch')
                actual_file = record / 'actual_request.json' if record is not None else None
                if actual_file is not None and actual_file.is_file():
                    raw = actual_file.read_bytes()
                    if _hash(raw) != request.get('bodyhash') or len(raw) != request.get('bytes'):
                        issues.append('saved_native_request_hash_or_size_mismatch')
                    actual = json.loads(raw)
                    user_blocks = [piece.get('text') for msg in actual.get('messages', [])
                        if msg.get('role') == 'user' for piece in msg.get('content', [])]
                    if (len(user_blocks) != 2 or any(not isinstance(x, str) for x in user_blocks)
                            or (expected_dispatch is not None and user_blocks[0] != expected_dispatch)
                            or _text_hash(user_blocks[1]) != request.get('runtime_context_sha256')):
                        issues.append('saved_native_request_business_or_runtime_mismatch')
                else:
                    unknown.append('actual_native_request_body_not_available')
    except (OSError, ValueError, TypeError, KeyError):
        issues.append('actual_guard_artifact_invalid_or_outside_results')
    return {'issues': sorted(set(issues)), 'unverified': unknown, 'tokens': tokens, 'costs': costs}


def audit_host(row, artifacts_root=None):
    issues, unknown = [], []
    try:
        path = _artifact(row.get('host_events_path'), artifacts_root)
        if path is None:
            path = _artifact(row.get('host_root'), artifacts_root, 'events.jsonl')
        if path is None or not path.is_file():
            return {'issues': [], 'unverified': ['actual_host_commit_log_not_available']}
        events = [json.loads(line) for line in path.read_bytes().splitlines()]
        previous, by_hash = '0' * 64, {}
        for seq, event in enumerate(events, 1):
            body = {key: value for key, value in event.items() if key != 'hash'}
            if event.get('previous') != previous or event.get('seq') != seq or event.get('hash') != _hash(body):
                issues.append('host_event_hash_chain_invalid')
            previous = event.get('hash')
            by_hash[previous] = event
        messages = row.get('messages')
        candidates = [event for event in events if event.get('kind') == 'delivery_prepared'
            and event['data'].get('sources') == sorted(row['selected'])
            and event['data'].get('memory_sha256') == _text_hash(row['context'])
            and (messages is None or event['data'].get('messages_sha256') == _hash(messages))]
        packet = _prepared(row)
        if packet is not None:
            candidates = [event for event in candidates if event['revision'] == packet['prepared_epoch']]
        success = False
        for event in candidates:
            linked = [other for other in events if other.get('data', {}).get('prepared') == event['hash']]
            committed = [other for other in linked if other['kind'] == 'delivery_committed']
            receipt_events = [other for other in linked if other['kind'] == 'delivery_receipt'
                              and other['data'].get('receipt') == row.get('receipt')]
            policies = [other for other in events if other['kind'] == 'permission_committed'
                        and other['revision'] == event['revision'] and other['seq'] < event['seq']]
            if (len(committed) == 1 and len(receipt_events) == 1 and len(policies) == 1
                    and event['seq'] < committed[0]['seq'] < receipt_events[0]['seq']
                    and committed[0]['revision'] == event['revision']
                    and set(policies[0]['data']['allowed']) == set(row['allowed'])):
                success = True
        if not success:
            issues.append('no_matching_actual_policy_commit_and_receipt')
    except (OSError, ValueError, TypeError, KeyError):
        issues.append('invalid_host_commit_artifact')
    return {'issues': sorted(set(issues)), 'unverified': unknown}


def evaluate_rows(rows, evaluation, *, cases=None, schedules=None, artifacts_root=None):
    cases = {case['case_id']: case for case in cases} if isinstance(cases, list) else (cases or {})
    seen, scored = set(), []
    for row in rows:
        cell = row['case_id'], row['arm'], row['time']
        if cell in seen:
            raise ValueError('duplicate_case_arm_time_no_selective_deduplication')
        seen.add(cell)
        gold = evaluation[row['case_id']]
        case = cases.get(row['case_id'])
        allowed, selected = set(row['allowed']), set(row['selected'])
        required = set(gold['support_ids'])
        prediction, parse = extract_answer(row.get('output'), row.get('question_id', row['case_id']))
        score = answer_metrics(prediction, gold['answer'])
        audits = {'payload': audit_payload(row, case), 'native': audit_native(row, artifacts_root),
                  'host': audit_host(row, artifacts_root)}
        if schedules is not None:
            expected = [event for event in schedules[row['case_id']] if event['time'] == row['time']]
            if len(expected) != 1 or set(expected[0]['allowed']) != allowed:
                audits['payload']['issues'].append('row_allowed_differs_from_frozen_schedule')
        issues = [f'{name}:{issue}' for name, audit in audits.items() for issue in audit['issues']]
        unknown = [f'{name}:{issue}' for name, audit in audits.items() for issue in audit['unverified']]
        status = 'failed' if issues else ('unverified' if unknown else 'verified')
        eligible = required <= allowed
        scored.append({'case_id': cell[0], 'arm': cell[1], 'time': cell[2], 'prediction': prediction,
            'answer_parse': parse, 'answer': score, 'primary_eligible': eligible,
            'all_granted': set(s['source_id'] for s in case['sources']) == allowed if case else None,
            'complete_annotated_support_retrieved': required <= selected,
            'current_annotated_support_recall': len(required & selected) / len(required) if required else None,
            'audit_status': status, 'issues': issues, 'unverified': unknown, 'audits': audits,
            'guarded_answer': {key: value if status == 'verified' else 0. for key, value in score.items()}})
    aggregates = {}
    for arm in sorted({row['arm'] for row in scored}):
        arm_rows = [row for row in scored if row['arm'] == arm]
        eligible = [row for row in arm_rows if row['primary_eligible']]
        by_case = defaultdict(list)
        for row in eligible:
            by_case[row['case_id']].append(row)
        def mean_score(key, subset, field='answer'):
            return sum(row[field][key] for row in subset) / len(subset) if subset else None
        token_rows = [row['audits']['native']['tokens'] for row in arm_rows if row['audits']['native']['tokens'] is not None]
        cost_rows = [row['audits']['native']['costs'] for row in arm_rows if row['audits']['native']['costs'] is not None]
        aggregates[arm] = {'observations': len(arm_rows), 'independent_question_clusters': len({r['case_id'] for r in arm_rows}),
            'primary_eligible_views': len(eligible), 'primary_answer_em': mean_score('em', eligible),
            'primary_answer_f1': mean_score('f1', eligible),
            'primary_guarded_em': mean_score('em', eligible, 'guarded_answer'),
            'primary_guarded_f1': mean_score('f1', eligible, 'guarded_answer'),
            'primary_question_macro_em': sum(mean_score('em', group) for group in by_case.values()) / len(by_case) if by_case else None,
            'primary_question_macro_f1': sum(mean_score('f1', group) for group in by_case.values()) / len(by_case) if by_case else None,
            'primary_complete_annotated_support_views': sum(row['complete_annotated_support_retrieved'] for row in eligible),
            'changed_views_without_all_annotated_support': len(arm_rows)-len(eligible),
            'audit_status_counts': dict(Counter(row['audit_status'] for row in arm_rows)),
            'native_usage_rows': len(token_rows),
            'native_tokens': {key: sum(row[key] for row in token_rows) for key in
                ('input_total_tokens', 'input_uncached_tokens', 'cache_read_tokens', 'cache_write_tokens', 'output_tokens', 'total_tokens')},
            'estimated_peak_cost_cny_observed': str(sum((Decimal(row['estimated_peak_cost_cny']) for row in cost_rows), Decimal(0))),
            'estimated_cache_aware_peak_cost_cny_observed': str(sum((Decimal(row['estimated_cache_aware_peak_cost_cny']) for row in cost_rows), Decimal(0)))
                if len(cost_rows) == len(arm_rows) and all(row['estimated_cache_aware_peak_cost_cny'] is not None for row in cost_rows) else None,
            'all_call_costs_accounted': len(cost_rows) == len(arm_rows), 'cost_is_supplier_bill': False}
    arms = {row['arm'] for row in scored}
    trajectory = {(row['case_id'], row['time']) for row in scored}
    missing = sorted([(*cell, arm) for cell in trajectory for arm in arms if (cell[0], arm, cell[1]) not in seen])
    return {'summary': {'rows': len(scored), 'arms': aggregates,
        'observed_matrix_missing_cells': missing, 'official_answer_metric_source': OFFICIAL_EVALUATOR,
        'primary_rule': 'all annotated support source IDs remain currently allowed; every eligible row retained',
        'changed_missing_support_views_are_not_declared_unanswerable': True,
        'guarded_scores_require_verified_payload_native_guard_and_host_commit': True,
        'no_support_fact_prediction_or_joint_score_claimed': True, 'model_calls_by_evaluator': 0}, 'rows': scored}


def _load_rows(path):
    path = Path(path)
    if path.is_dir():
        location = path / 'rows' if (path / 'rows').is_dir() else path
        return [json.loads(file.read_bytes()) for file in sorted(location.glob('*.json'))]
    if path.suffix == '.jsonl':
        return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]
    value = json.loads(path.read_bytes())
    return value if isinstance(value, list) else value['rows']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=Path, required=True)
    parser.add_argument('--evaluation', type=Path, required=True)
    parser.add_argument('--cases', type=Path)
    parser.add_argument('--schedules', type=Path)
    parser.add_argument('--artifacts-root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('fresh_evaluation_output_required')
    cases = [json.loads(line) for line in args.cases.read_bytes().splitlines() if line.strip()] if args.cases else None
    result = evaluate_rows(_load_rows(args.records), json.loads(args.evaluation.read_bytes()), cases=cases,
        schedules=json.loads(args.schedules.read_bytes()) if args.schedules else None,
        artifacts_root=args.artifacts_root)
    args.output.mkdir(parents=True)
    for name, value in result.items():
        (args.output / (name + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    print(json.dumps(result['summary'], ensure_ascii=False, allow_nan=False))


if __name__ == '__main__':
    main()
