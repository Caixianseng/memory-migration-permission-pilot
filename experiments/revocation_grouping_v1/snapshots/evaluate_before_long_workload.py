"""Independent offline replay of grouping inputs, authorization and full costs.

This evaluator reads recorded business requests and native SDK guard/receipt
files, never account metadata, credentials or a model. It checks consistency
under the experiment's trusted-serial-host assumption, not malicious-host
authenticity. Word/phrase matches are diagnostics, never semantic correctness.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import unicodedata

try:
    from .retrieval_baseline import select
except ImportError:
    from retrieval_baseline import select


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def read(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('evidence_symlink_not_allowed')
    return json.loads(path.read_text(encoding='utf-8'))


def number(value):
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return amount if amount.is_finite() and amount >= 0 else None


def safe_component(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,119}', value) or value in ('.', '..'):
        raise ValueError('unsafe_evidence_component')
    return value


def question_id(q, index):
    return q.get('question_id', q.get('id', f'Q{index + 1}'))


def public_questions(questions):
    return [{'question_id': question_id(q, i), 'question': q.get('question', q.get('text'))}
            for i, q in enumerate(questions)]


def normalized(text):
    return ' '.join(unicodedata.normalize('NFKC', str(text)).casefold().split())


def support_sets(q):
    alternatives = q.get('support_sets', q.get('alternative_support_sets'))
    if alternatives is not None:
        return [set(group) for group in alternatives]
    sources = q.get('support_source_ids', q.get('supporting_source_ids',
              q.get('source_ids', q.get('support_sources', q.get('source_id')))))
    if sources is None:
        return None
    if isinstance(sources, str):
        sources = [sources]
    if q.get('support_mode') == 'any':
        return [{sid} for sid in sources]
    return [set(sources)]


def evaluate_answer(output, questions, allowed, delivered, ai_scores=None):
    """Separate format/UNKNOWN checks from unmeasured semantic correctness."""
    parse_error = None
    try:
        answers = json.loads(output)
        if not isinstance(answers, dict):
            raise ValueError('answer_not_object')
    except (ValueError, TypeError):
        answers, parse_error = {}, 'not_plain_json_object'
    expected_ids = {question_id(q, i) for i, q in enumerate(questions)}
    exact_ids = parse_error is None and set(answers) == expected_ids
    result = []
    for i, q in enumerate(questions):
        qid = question_id(q, i)
        value = answers.get(qid)
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False) if value is not None else ''
        unknown = normalized(text).strip(' .。') == 'unknown'
        supports = support_sets(q)
        legal_support = None if supports is None else any(group and group <= set(allowed) for group in supports)
        delivered_support = None if supports is None else any(group and group <= set(delivered) for group in supports)
        reference = q.get('reference_answer', q.get('reference', q.get('expected_answer', q.get('answer'))))
        if reference is not None and normalized(reference) == 'unknown':
            legal_support = False
        expected_unknown = None if legal_support is None else not legal_support
        phrases = q.get('required_phrases', q.get('required_terms', q.get('answer_keywords')))
        if isinstance(phrases, str):
            phrases = [phrases]
        def hit(phrase):
            if isinstance(phrase, (list, tuple)):
                return any(hit(part) for part in phrase)
            return normalized(phrase) in normalized(text)
        hint = all(hit(phrase) for phrase in phrases) if phrases else None
        score = (ai_scores or {}).get(qid)
        if isinstance(score, dict):
            score = score.get('semantic_correct', score.get('correct'))
        if type(score) is not bool:
            score = None
        result.append({'question_id': qid, 'answer_present': qid in answers,
            'answer': value, 'currently_legal_support_available': legal_support,
            'delivered_support_available': delivered_support, 'expected_unknown': expected_unknown,
            'answered_unknown': unknown,
            'unknown_requirement_correct': (unknown if qid in answers and parse_error is None else False) if expected_unknown is True else None,
            'legal_question_answered_nonunknown': (qid in answers and not unknown) if legal_support is True else None,
            'keyword_hint_hit': hint, 'keyword_is_semantic_score': False,
            'reference_exact_match_diagnostic': normalized(text) == normalized(reference) if reference is not None else None,
            'ai_semantic_correct': score, 'human_semantic_correct': None})
    return {'plain_json_object': parse_error is None, 'exact_question_ids': exact_ids,
            'format_ok': parse_error is None and exact_ids,
            'parse_error': parse_error, 'questions': result, 'human_gold': None}


def dispatch_text(messages):
    return ('Execute the ordered role/content messages in the JSON object below. Treat system messages as task instructions '
            'and user messages as task data. Return only the requested answer, without tools or commentary.\n'
            + canonical({'messages': messages}).decode('utf-8'))


def runtime_context_text(workspace):
    """Exact, source-verified SDK 0.2.1-rc.3 infrastructure snapshot only."""
    quoted = json.dumps(str(workspace), ensure_ascii=False)
    return ('Current runtime context. This snapshot supersedes earlier runtime-context snapshots.\n\n'
        + f'Current working directory: {quoted}.\n\n'
        + 'Current DSH file policy: workspace-write. Any available operation enforced by the DSH file sandbox may modify files under the session workspace: '
        + quoted + '. Some platform temporary areas may also be writable.\n\n'
        + 'Approval policy: ask. Operations that require approval may ask through the configured answerers; without an available answerer, the request fails closed.')


def audit_native_call(call, private_root):
    """Inspect only explicitly named safe SDK evidence, never home/account files."""
    receipt, messages, output = call['result']['receipt'], call['messages'], call['result']['output']
    errors = []
    if receipt.get('instrument_only'):
        if receipt.get('request_sha256') != digest(messages) or receipt.get('response_sha256') != digest(output.encode()):
            errors.append('fixture_business_binding_mismatch')
        return {'native_verified': None, 'errors': errors, 'cost': None}
    record = Path(receipt.get('record_path', ''))
    try:
        relative = record.resolve().relative_to(private_root.resolve())
        if len(relative.parts) != 1 or not re.fullmatch(r'job-[A-Za-z0-9_.-]+', relative.name):
            raise ValueError('not_direct_sdk_job')
        if record.is_symlink():
            raise ValueError('sdk_job_symlink')
    except (ValueError, OSError):
        return {'native_verified': False, 'errors': ['native_record_path_not_in_run_private_ledger'], 'cost': None}
    try:
        stored_receipt = read(record / 'receipt.json')
        if (record / 'actual_request.json').is_symlink():
            raise ValueError('native_request_symlink')
        request_bytes = (record / 'actual_request.json').read_bytes()
        body, guard, response = json.loads(request_bytes), read(record / 'guard.json'), read(record / 'response.json')
        if stored_receipt != receipt:
            errors.append('native_receipt_copy_mismatch')
        if digest(request_bytes) != receipt.get('request_sha256'):
            errors.append('native_request_hash_mismatch')
        if receipt.get('business_messages_sha256') != digest(messages):
            errors.append('native_business_messages_hash_mismatch')
        if receipt.get('response_sha256') != digest(output.encode()) or response.get('final_assistant_text') != output:
            errors.append('native_response_binding_mismatch')
        prompt = dispatch_text(messages)
        runtime = runtime_context_text(record / 'workspace')
        user_pieces = []
        for message in body.get('messages', []):
            if message.get('role') not in ('system', 'user') or not isinstance(message.get('content'), list):
                errors.append('native_history_or_nontext_input')
                continue
            for piece in message['content']:
                if piece.get('type') != 'text' or not isinstance(piece.get('text'), str):
                    errors.append('native_history_or_nontext_input')
                elif message['role'] == 'user':
                    user_pieces.append(piece['text'])
        if user_pieces != [prompt, runtime] or receipt.get('dispatch_sha256') != digest(prompt.encode()):
            errors.append('native_actual_business_input_mismatch')
        if body.get('provider') != 'deepseek-account' or body.get('model') != 'deepseek-flash' or body.get('reasoningEffort') != 'off' or body.get('tools') not in (None, []):
            errors.append('native_route_or_tools_mismatch')
        if body.get('maxTokens') != call.get('max_tokens'):
            errors.append('native_output_limit_mismatch')
        if (guard.get('agent_attempt_count'), guard.get('stream_attempt_count'), guard.get('allowed_stream_count')) != (1, 1, 1) or guard.get('reject_code') is not None or len(guard.get('requests', [])) != 1:
            errors.append('native_request_count_not_one')
        elif (guard['requests'][0].get('bodyhash') != digest(request_bytes)
              or guard['requests'][0].get('business_input_sha256') != digest(prompt.encode())
              or guard['requests'][0].get('runtime_context_sha256') != digest(runtime.encode())
              or guard['requests'][0].get('user_text_blocks') != 2):
            errors.append('native_guard_input_binding_mismatch')
        usage_events = response.get('assistant_usage_events') or []
        usage = usage_events[0].get('usage', {}) if len(usage_events) == 1 else {}
        inputs = usage.get('inputTokens', usage.get('input_tokens', usage.get('prompt_tokens')))
        outputs = usage.get('outputTokens', usage.get('output_tokens', usage.get('completion_tokens')))
        if type(inputs) is not int or type(outputs) is not int or inputs < 1 or outputs < 1 or (inputs, outputs) != (receipt.get('input_tokens'), receipt.get('output_tokens')):
            errors.append('native_usage_receipt_mismatch')
            cost = None
        else:
            config = read(private_root / 'config.json')
            input_price, output_price = number(config.get('input_peak_cny_per_million')), number(config.get('output_peak_cny_per_million'))
            cost = None if input_price is None or output_price is None else (inputs * input_price + outputs * output_price) / Decimal(1_000_000)
            if cost != number(receipt.get('estimated_peak_cost_cny')):
                errors.append('native_cost_recalculation_mismatch')
        if receipt.get('status') != 'ok' or receipt.get('physical_request_count') != 1:
            errors.append('native_success_or_physical_count_mismatch')
        cached_peak = cached_offpeak = None
        hits = [usage[key] for key in ('cachedInputTokens', 'cacheReadInputTokens', 'cached_input_tokens',
                'cache_read_input_tokens', 'prompt_cache_hit_tokens') if key in usage]
        if (cost is not None and hits and all(type(value) is int and 0 <= value <= inputs for value in hits)
                and len(set(hits)) == 1):
            # Supplement the predeclared all-input peak upper bound with the
            # SDK's verified 2026-11-04 cache tariff; this is still an estimate.
            cached_peak = ((inputs - hits[0]) * input_price + hits[0] * Decimal('0.04')
                           + outputs * output_price) / Decimal(1_000_000)
            cached_offpeak = cached_peak / 2
            if ('cache_hit_input_tokens' in receipt and receipt['cache_hit_input_tokens'] != hits[0]
                    or 'estimated_cache_aware_peak_cost_cny' in receipt and number(receipt['estimated_cache_aware_peak_cost_cny']) != cached_peak
                    or 'estimated_cache_aware_offpeak_cost_cny' in receipt and number(receipt['estimated_cache_aware_offpeak_cost_cny']) != cached_offpeak):
                errors.append('native_cache_aware_cost_recalculation_mismatch')
        return {'native_verified': not errors, 'errors': errors, 'cost': cost,
                'cost_cache_peak': cached_peak, 'cost_cache_offpeak': cached_offpeak}
    except (OSError, ValueError, KeyError, TypeError):
        return {'native_verified': False, 'errors': errors + ['native_safe_evidence_missing_or_invalid'], 'cost': None}


def _host_events(path):
    events, errors, previous = [], [], '0' * 64
    try:
        for line in path.read_text(encoding='utf-8').splitlines():
            event = json.loads(line)
            checksum = event.get('hash')
            unsigned = {key: value for key, value in event.items() if key != 'hash'}
            if event.get('seq') != len(events) + 1 or event.get('previous') != previous or digest(unsigned) != checksum:
                errors.append('host_hash_chain_mismatch')
            previous = checksum
            events.append(event)
    except (OSError, ValueError, TypeError):
        errors.append('host_events_missing_or_invalid')
    return events, errors


def _ai_index(review):
    indexed = defaultdict(dict)
    if review is None:
        return indexed
    rows = review.get('rows', review) if isinstance(review, dict) else review
    if not isinstance(rows, list):
        raise ValueError('ai_review_requires_rows_list')
    for row in rows:
        key = (row['case_id'], row['method'], row['time'])
        indexed[key][row['question_id']] = row.get('semantic_correct', row.get('correct'))
    return indexed


def evaluate(run_root, questions=None, *, ai_review=None, write=True):
    root = Path(run_root).absolute()
    summary, contract, frozen = read(root / 'summary.json'), read(root / 'frozen_contract.json'), read(root / 'frozen_cases.json')
    if questions is None:
        questions = read(root / 'evaluation_only.json')
    elif isinstance(questions, (str, Path)):
        questions = read(questions)
    if isinstance(questions, dict) and isinstance(questions.get('cases'), dict):
        questions = questions['cases']
    questions = {key: value.get('questions', []) if isinstance(value, dict) else value for key, value in questions.items()}
    if isinstance(ai_review, (str, Path)):
        ai_review = read(ai_review)
    reviews = _ai_index(ai_review)
    issues, calls, call_audits = [], {}, {}
    private_root = root.parent / (root.name + '-private-sdk')
    if summary.get('contract_sha256') != digest(contract):
        issues.append({'code': 'frozen_contract_hash_mismatch'})
    for path in sorted((root / 'calls').glob('*.json')):
        call = read(path)
        rid = call.get('result', {}).get('receipt', {}).get('request_id')
        if not isinstance(rid, str) or not rid or rid in calls:
            issues.append({'code': 'missing_or_duplicate_physical_request_id', 'call_file': path.name})
            continue
        calls[rid] = call
        audit = audit_native_call(call, private_root)
        call_audits[rid] = audit
        for code in audit['errors']:
            issues.append({'code': code, 'request_id': rid})

    case_index = {case['case_id']: case for case in frozen}
    row_index, row_reports, method_reports, all_referenced = {}, [], [], set()
    for row in summary.get('rows', []):
        key = (row.get('case_id'), row.get('method'), row.get('time'))
        if key in row_index:
            issues.append({'code': 'duplicate_result_position', 'position': list(key)})
        row_index[key] = row
    for cid, case in case_index.items():
        safe_component(cid)
        sources = {s['source_id']: s for s in case['sources']}
        if len(sources) != len(case['sources']):
            raise ValueError('duplicate_frozen_source_id')
        try:
            events = read(root / cid / 'events_frozen_before_models.json')
        except (OSError, ValueError):
            events = []
            issues.append({'code': 'frozen_events_missing_or_invalid', 'case_id': cid})
        by_time = {event['time']: event for event in events}
        for method in contract['methods']:
            safe_component(method)
            base = root / cid / method
            history, host_errors = _host_events(base / 'host' / 'events.jsonl')
            local_errors = list(host_errors)
            hash_events = {event['hash']: event for event in history}
            permissions = [event for event in history if event['kind'] == 'permission_committed']
            for i, event in enumerate(permissions):
                if i >= len(events) or event['data'].get('allowed') != sorted(events[i]['allowed']):
                    local_errors.append('host_permissions_differ_from_frozen_events')
            registration = next((event for event in history if event['kind'] == 'registered'), None)
            if registration is None or registration['data'].get('sources') != {sid: digest(s['text'].encode()) for sid, s in sources.items()}:
                local_errors.append('host_registration_source_hash_mismatch')
            source_ids, target_ids = set(), set()
            artifacts = {}
            for event in history:
                data = event['data']
                if event['kind'] == 'generation_sealed':
                    rid = data.get('receipt', {}).get('request_id')
                    source_ids.add(rid)
                    try:
                        call = calls[rid]
                        registered = hash_events[data['input_event']]
                        grant = next(row for row in reversed(history) if row['kind'] == 'permission_committed' and row['seq'] < registered['seq'])
                        actual_sources = json.loads(call['messages'][1]['content'])['sources']
                        actual_ids = sorted(item['source_id'] for item in actual_sources)
                        if (call['role'] != 'source' or call['result']['receipt'] != data['receipt']
                                or digest(call['result']['output'].encode()) != data['output_sha256']
                                or registered['kind'] != 'generation_registered'
                                or registered['data']['messages_sha256'] != digest(call['messages'])
                                or actual_ids != data['sources'] or actual_ids != registered['data']['sources']
                                or not set(actual_ids) <= set(grant['data']['allowed'])
                                or event['revision'] != registered['revision']):
                            local_errors.append('generation_host_input_or_authorization_mismatch')
                        for item in actual_sources:
                            if item['text'] != sources[item['source_id']]['text']:
                                local_errors.append('generation_source_text_differs_from_frozen_source')
                    except (KeyError, TypeError, ValueError, StopIteration):
                        local_errors.append('generation_host_evidence_missing_or_invalid')
                elif event['kind'] == 'delivery_receipt':
                    target_ids.add(data.get('receipt', {}).get('request_id'))
                elif event['kind'] == 'delivery_outcome_unknown_no_retry':
                    local_errors.append('target_outcome_unknown_reservation_not_settled')
                elif event['kind'] == 'legal_cache_reused':
                    artifacts[data.get('artifact')] = None
            for timepoint in contract['events']['scoring_times']:
                key = (cid, method, timepoint)
                row = row_index.get(key)
                if row is None:
                    row_reports.append({'case_id': cid, 'method': method, 'time': timepoint, 'status': 'missing_or_failed', 'answer_evaluation': None})
                    local_errors.append('missing_planned_position')
                    continue
                for aid in row.get('artifacts', []):
                    artifacts[aid] = None
            for aid in list(artifacts):
                if not isinstance(aid, str) or not re.fullmatch(r'group-[a-f0-9]{64}', aid):
                    local_errors.append('invalid_artifact_id')
                    continue
                try:
                    artifact = read(root / 'cache' / (aid[6:] + '.json'))
                    unsigned = {key: value for key, value in artifact.items() if key != 'record_sha256'}
                    binding = artifact['binding']
                    if digest(unsigned) != artifact['record_sha256'] or digest(binding) != artifact['cache_key'] or artifact['cache_key'] != aid[6:] or artifact['artifact_id'] != aid:
                        raise ValueError('cache_record_or_key_hash_mismatch')
                    if digest(artifact['text'].encode()) != artifact['text_sha256'] or binding['dependencies'] != artifact['dependencies']:
                        raise ValueError('cache_body_or_dependencies_mismatch')
                    deps = artifact['dependencies']
                    if artifact['source_ids'] != sorted(dep['source_id'] for dep in deps):
                        raise ValueError('cache_source_ids_mismatch')
                    for dep in deps:
                        original = sources[dep['source_id']]
                        if dep['version'] != original.get('version', 1) or dep['text_sha256'] != digest(original['text'].encode()) or dep.get('permission_allowed') is not True:
                            raise ValueError('cache_source_binding_mismatch')
                    rid = artifact['receipt']['request_id']
                    source_ids.add(rid)
                    call = calls[rid]
                    source_payload = {}
                    if 'source_explicit_word_budget' in contract:
                        source_payload['maximum_words'] = call['max_tokens'] // 2
                    source_payload['sources'] = [{'source_id': sid, 'text': sources[sid]['text']} for sid in artifact['source_ids']]
                    expected_messages = [{'role': 'system', 'content': contract['source_prompt']},
                        {'role': 'user', 'content': json.dumps(source_payload, ensure_ascii=False)}]
                    if call['role'] != 'source' or call['messages'] != expected_messages or call['result']['output'] != artifact['text'] or call['result']['receipt'] != artifact['receipt']:
                        raise ValueError('actual_source_input_or_output_binding_mismatch')
                    transform = binding['transform_config']
                    if transform.get('prompt') != contract['source_prompt'] or transform.get('max_tokens') != call.get('max_tokens'):
                        raise ValueError('cache_transform_config_mismatch')
                    artifacts[aid] = artifact
                except (OSError, ValueError, TypeError, KeyError):
                    local_errors.append('artifact_missing_or_input_binding_invalid:' + str(aid))
            commits = {}
            for event in history:
                if event['kind'] == 'delivery_receipt':
                    rid = event['data'].get('receipt', {}).get('request_id')
                    commits[rid] = event
            for timepoint in contract['events']['scoring_times']:
                key = (cid, method, timepoint)
                row = row_index.get(key)
                if row is None:
                    continue
                errors = []
                allowed = sorted(by_time.get(timepoint, {}).get('allowed', []))
                if timepoint not in by_time:
                    errors.append('frozen_event_missing_for_position')
                if row.get('allowed') != allowed:
                    errors.append('row_permission_claim_mismatch')
                try:
                    if method in ('raw', 'retrieval'):
                        selected = [source for sid, source in sources.items() if sid in allowed]
                        if method == 'retrieval':
                            selected = select(selected, [q['question'] for q in public_questions(questions[cid])], top_k=contract['retrieval_top_k'])
                        memory = '\n\n'.join(source['source_id'] + '\n' + source['text'] for source in selected)
                        deps = sorted(source['source_id'] for source in selected)
                        if row.get('artifacts'):
                            errors.append('raw_or_retrieval_unexpected_generated_artifact')
                    else:
                        used = [artifacts[aid] for aid in row['artifacts']]
                        memory = '\n\n'.join(artifact['text'] for artifact in used)
                        deps = sorted({sid for artifact in used for sid in artifact['source_ids']})
                    if not set(deps) <= set(allowed):
                        errors.append('actual_delivered_dependencies_forbidden')
                    if row.get('dependencies') != deps or row.get('memory_sha256') != digest(memory.encode()) or row.get('memory_utf8_bytes') != len(memory.encode()):
                        errors.append('row_memory_or_dependency_binding_mismatch')
                    rid = row['target_receipt']['request_id']
                    target_ids.add(rid)
                    call = calls[rid]
                    messages = [{'role': 'system', 'content': contract['target_prompt']},
                        {'role': 'user', 'content': json.dumps({'memory': memory, 'questions': public_questions(questions[cid])}, ensure_ascii=False)}]
                    if call['role'] != 'target' or call['messages'] != messages or call['result']['output'] != row.get('answer') or call['result']['receipt'] != row['target_receipt']:
                        errors.append('actual_target_input_or_output_binding_mismatch')
                    received = commits[rid]
                    if received['data']['receipt'] != call['result']['receipt']:
                        errors.append('host_target_receipt_mismatch')
                    prepared = hash_events[received['data']['prepared']]
                    committed = next(event for event in history if event['kind'] == 'delivery_committed' and event['data'].get('prepared') == prepared['hash'])
                    current_grant = next(event for event in reversed(history) if event['kind'] == 'permission_committed' and event['seq'] < committed['seq'])
                    if prepared['data'].get('memory_sha256') != digest(memory.encode()) or prepared['data'].get('messages_sha256') != digest(messages) or prepared['data'].get('sources') != deps:
                        errors.append('host_prepared_payload_binding_mismatch')
                    if not prepared['seq'] < committed['seq'] < received['seq'] or prepared['revision'] != committed['revision'] or current_grant['data'].get('allowed') != allowed or not set(deps) <= set(current_grant['data']['allowed']):
                        errors.append('host_current_permission_or_commit_order_mismatch')
                    answer = evaluate_answer(call['result']['output'], questions[cid], allowed, deps, reviews.get(key))
                except (OSError, KeyError, TypeError, ValueError, StopIteration):
                    errors.append('row_evidence_missing_or_invalid')
                    answer = evaluate_answer(row.get('answer', ''), questions[cid], allowed, [], reviews.get(key))
                row_reports.append({'case_id': cid, 'method': method, 'time': timepoint,
                    'status': 'audited' if not errors else 'evidence_failed', 'current_allowed_independent': allowed,
                    'errors': errors, 'answer_evaluation': answer})
                local_errors.extend(errors)
            source_ids.discard(None)
            target_ids.discard(None)
            charged = source_ids | target_ids
            all_referenced.update(charged)
            for rid in charged:
                if rid not in call_audits:
                    local_errors.append('attributed_call_evidence_missing')
                else:
                    local_errors.extend(call_audits[rid]['errors'])
            if source_ids & target_ids:
                local_errors.append('one_request_attributed_as_source_and_target')
            costs = [call_audits.get(rid, {}).get('cost') for rid in charged]
            total = sum(costs, Decimal(0)) if costs and all(value is not None for value in costs) and not summary.get('instrument_only') else None
            if not charged and not summary.get('instrument_only'):
                total = Decimal(0)
            for rid in source_ids:
                if rid not in calls or calls[rid].get('role') != 'source':
                    local_errors.append('attributed_source_receipt_missing_or_wrong_role')
            for rid in target_ids:
                if rid not in calls or calls[rid].get('role') != 'target':
                    local_errors.append('attributed_target_receipt_missing_or_wrong_role')
            reported = next((item for item in summary.get('cases', []) if item.get('case_id') == cid and item.get('method') == method), None)
            if reported:
                reported_cost = number(reported.get('full_lifecycle_peak_cny'))
                # The runner serializes float sums; tolerate only their tiny
                # representation error, never omitted model requests/costs.
                cost_matches = (reported_cost is None and total is None) or (
                    reported_cost is not None and total is not None and abs(reported_cost - total) <= Decimal('0.000000000001'))
                if not cost_matches:
                    local_errors.append('summary_cost_does_not_match_independent_unique_receipts')
            own_rows = [row for row in row_reports if (row['case_id'], row['method']) == (cid, method)]
            scored = [q for row in own_rows if row.get('answer_evaluation') for q in row['answer_evaluation']['questions']]
            legal = [q for q in scored if q['currently_legal_support_available'] is True]
            ai_complete = bool(legal) and all(type(q['ai_semantic_correct']) is bool for q in legal)
            cost_complete = (total is not None and len(own_rows) == len(contract['events']['scoring_times'])
                             and not any(row['status'] == 'missing_or_failed' for row in own_rows)
                             and 'target_outcome_unknown_reservation_not_settled' not in local_errors)
            cache_costs = [call_audits.get(rid, {}).get('cost_cache_peak') for rid in charged]
            cached_total = sum(cache_costs, Decimal(0)) if cost_complete and cache_costs and all(value is not None for value in cache_costs) else None
            method_reports.append({'case_id': cid, 'method': method,
                'event_distribution': case.get('event_distribution', next((row.get('event_distribution') for row in summary.get('rows', []) if row.get('case_id') == cid), 'unknown')),
                'source_request_ids_charged_once': sorted(source_ids), 'target_request_ids': sorted(target_ids),
                'source_jobs_attributed': len(source_ids), 'target_jobs': len(target_ids),
                'full_lifecycle_peak_cny': float(total) if cost_complete else None,
                'observed_receipted_peak_cny': float(total) if total is not None else None,
                'full_lifecycle_cost_complete': cost_complete,
                'full_lifecycle_cache_aware_peak_cny': float(cached_total) if cached_total is not None else None,
                'full_lifecycle_cache_aware_offpeak_cny': float(cached_total / 2) if cached_total is not None else None,
                'audit_ok': not local_errors, 'errors': sorted(set(local_errors)),
                'format_ok_count': sum(row.get('answer_evaluation', {}).get('format_ok', False) for row in own_rows if row.get('answer_evaluation')),
                'legally_answerable_question_count': len(legal),
                'legal_nonunknown_answers': sum(q['legal_question_answered_nonunknown'] for q in legal),
                'required_unknown_count': sum(q['expected_unknown'] is True for q in scored),
                'required_unknown_correct': sum(q['unknown_requirement_correct'] is True for q in scored),
                'ai_supported_answer_completeness': sum(q['ai_semantic_correct'] for q in legal) / len(legal) if ai_complete else None,
                'human_supported_answer_completeness': None, 'human_gold': None})
            for code in sorted(set(local_errors)):
                issues.append({'code': code, 'case_id': cid, 'method': method})
    extra_rows = set(row_index) - {(cid, method, time) for cid in case_index for method in contract['methods'] for time in contract['events']['scoring_times']}
    if extra_rows:
        issues.append({'code': 'unplanned_summary_result_positions', 'positions': [list(key) for key in sorted(extra_rows)]})
    unattributed = set(calls) - all_referenced
    if unattributed:
        issues.append({'code': 'unattributed_physical_calls', 'request_ids': sorted(unattributed)})
    ledger_pending, ledger_success_ids = [], set()
    if private_root.exists():
        for job in sorted(private_root.glob('job-*')):
            receipt_path, reservation_path = job / 'receipt.json', job / 'reservation.json'
            receipt = read(receipt_path) if receipt_path.exists() else {}
            if receipt.get('status') == 'ok':
                ledger_success_ids.add(receipt.get('request_id'))
            else:
                reservation = read(reservation_path) if reservation_path.exists() else {}
                ledger_pending.append({'job': job.name, 'reservation_cny': reservation.get('reservation_cny'),
                                       'outcome': 'failed_or_unknown_reservation_retained'})
        if ledger_success_ids != set(calls):
            issues.append({'code': 'successful_private_ledger_and_saved_calls_differ'})
    paired = []
    strongest = []
    for cid in case_index:
        candidates = {item['method']: item for item in method_reports if item['case_id'] == cid}
        joint = candidates.get('joint')
        if not joint:
            continue
        audited_baselines = [item for method, item in candidates.items() if method != 'joint'
            and item['audit_ok'] and item['full_lifecycle_cost_complete']
            and item['full_lifecycle_peak_cny'] is not None]
        cheapest = min(audited_baselines, key=lambda item: (item['full_lifecycle_peak_cny'], item['method'])) if audited_baselines else None
        quality_matched = [item for item in audited_baselines
            if item['ai_supported_answer_completeness'] is not None and joint['ai_supported_answer_completeness'] is not None
            and item['ai_supported_answer_completeness'] >= joint['ai_supported_answer_completeness'] - .05]
        matched = min(quality_matched, key=lambda item: (item['full_lifecycle_peak_cny'], item['method'])) if quality_matched else None
        strongest.append({'case_id': cid,
            'cheapest_audited_baseline': cheapest['method'] if cheapest else None,
            'cheapest_baseline_peak_cny': cheapest['full_lifecycle_peak_cny'] if cheapest else None,
            'cost_only_is_not_quality_qualified': True,
            'cheapest_AI_quality_matched_baseline': matched['method'] if matched else None,
            'AI_quality_match_is_not_human_gold': True})
        for method, baseline in candidates.items():
            if method == 'joint':
                continue
            jcost, bcost = joint['full_lifecycle_peak_cny'], baseline['full_lifecycle_peak_cny']
            comparable = (summary.get('status') == 'completed' and joint['full_lifecycle_cost_complete']
                          and baseline['full_lifecycle_cost_complete'] and joint['audit_ok'] and baseline['audit_ok'])
            relative = (bcost - jcost) / bcost if comparable and jcost is not None and bcost not in (None, 0) else None
            jq, bq = joint['ai_supported_answer_completeness'], baseline['ai_supported_answer_completeness']
            jc, bc = joint['full_lifecycle_cache_aware_peak_cny'], baseline['full_lifecycle_cache_aware_peak_cny']
            paired.append({'case_id': cid, 'baseline': method, 'event_distribution': joint['event_distribution'],
                'joint_peak_cny': jcost, 'baseline_peak_cny': bcost,
                'cost_reduction_fraction': relative, 'ai_quality_difference_pp': (jq - bq) * 100 if jq is not None and bq is not None else None,
                'cache_aware_peak_cost_reduction_fraction': (bc - jc) / bc if comparable and jc is not None and bc not in (None, 0) else None,
                'human_quality_difference_pp': None})
    physical_costs = [audit['cost'] for audit in call_audits.values()]
    physical_total = sum(physical_costs, Decimal(0)) if physical_costs and all(value is not None for value in physical_costs) else None
    cached_physical = [audit.get('cost_cache_peak') for audit in call_audits.values()]
    cached_physical_total = sum(cached_physical, Decimal(0)) if cached_physical and all(value is not None for value in cached_physical) else None
    failure = None if summary.get('status') == 'completed' else {'status': summary.get('status'), 'failure_class': summary.get('failure_class'), 'failure_code': summary.get('failure_code')}
    report = {'schema': 'grouping-independent-evaluation-v1', 'run_status': summary.get('status'),
        'instrument_only': summary.get('instrument_only', False), 'human_gold': None,
        'audit_ok': not issues, 'issues': issues, 'failure_retained': failure,
        'native_input_binding_verified_count': sum(a['native_verified'] is True for a in call_audits.values()),
        'saved_physical_calls': len(calls), 'native_pending_or_failed_jobs': ledger_pending,
        'physical_successful_peak_cny': float(physical_total) if physical_total is not None else None,
        'physical_successful_cache_aware_peak_cny': float(cached_physical_total) if cached_physical_total is not None else None,
        'cache_aware_cost_note': 'Supplementary estimates only when raw native usage reports cache hits; missing cache accounting stays null. Offpeak estimate is one-half the verified peak tariff, not a supplier bill.',
        'cost_is_supplier_bill': False, 'method_case_results': method_reports,
        'positions': row_reports, 'story_paired_comparisons': paired,
        'strongest_simple_baselines': strongest,
        'unmeasured': ['independent human semantic correctness', 'supplier actual bill', 'monetized local CPU/planning cost'],
        'exploratory_continuation': {'cost_reduction_minimum': .2, 'quality_drop_maximum_pp': 5,
            'workload_classes_required': 2,
            'status': 'not_assessable_without_complete_semantic_review' if not ai_review else 'inspect_paired_results_with_AI_review_only',
            'advantage_proven': False},
        'limitations': [f"{len({item['case_id'] for item in method_reports})} persona clusters in this run are exploratory, not general effectiveness evidence.",
            'Hashes and guard records prove consistency under the trusted host contract, not malicious-host authenticity.',
            'Keyword/exact-phrase diagnostics are not semantic correctness; missing phrases never count automatically as wrong.',
            'Counterfactual method costs charge shared source receipts independently; physical wallet spend is reported separately.']}
    if write:
        (root / 'independent_evaluation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (root / 'effect_report.md').write_text(markdown(report), encoding='utf-8')
    return report


def markdown(report):
    rows = ['# D1 联合分组：独立离线复算', '',
        f"运行状态：`{report['run_status']}`；记录一致性核查：`{report['audit_ok']}`。",
        '本报告仅使用已存档请求、回执、来源与宿主事件，不调用模型。人工语义金标仍为 null。', '',
        '| 故事 | 方法 | 来源请求（独立归属） | 目标请求 | 完整模型费用上界/元 | 缓存感知峰价/元 | 核查 |',
        '|---|---|---:|---:|---:|---:|---|']
    for item in report['method_case_results']:
        cost = item['full_lifecycle_peak_cny']
        cached = item['full_lifecycle_cache_aware_peak_cny']
        rows.append(f"| {item['case_id']} | {item['method']} | {item['source_jobs_attributed']} | {item['target_jobs']} | {cost if cost is not None else '未测/未结'} | {cached if cached is not None else '未测'} | {item['audit_ok']} |")
    rows += ['', '费用包含每方法使用的唯一来源生成/重建回执和目标请求；共享来源物理调用只发生一次，每个方法单独承担其完整归属。费用为保守价格复算，不是供应商账单。只有原始usage提供缓存命中时才补算缓存感知峰/谷价，缺失时保持未测；不可把统一无缓存上界冒称实际费用。', '',
        '| 故事 | 简单基线 | D1相对节省 | AI合法完成度差/百分点 |', '|---|---|---:|---:|']
    for pair in report['story_paired_comparisons']:
        saving, quality = pair['cost_reduction_fraction'], pair['ai_quality_difference_pp']
        rows.append(f"| {pair['case_id']} | {pair['baseline']} | {saving:.1%} | {quality if quality is not None else '未测'} |" if saving is not None else f"| {pair['case_id']} | {pair['baseline']} | 未测 | 未测 |")
    rows += ['', '关键词命中和严格原文匹配只作线索；它们不会被转换为语义正确率。UNKNOWN 需求按冻结支持来源与当前合法集合独立检查。', '',
        f"本轮包含 {len({item['case_id'] for item in report['method_case_results']})} 个故事簇，按故事配对报告。是否继续扩样，应结合完整原文、普通检索及最强分组基线的成本与任务质量共同判断；成本下降20%、合法完成度下降不超过5个百分点是探索筛选阈值。工程核查、词法命中或少数故事的差异均不自动证明一般算法优势。", '']
    if report['failure_retained'] or report['native_pending_or_failed_jobs']:
        rows += ['运行失败、未结预约和缺失位置均保留，未被补成成功结果。', '']
    if report['issues']:
        rows += [f"核查发现 {len(report['issues'])} 项问题，见 independent_evaluation.json；带问题的结果不能作为安全或效果成立的证据。", '']
    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--questions', type=Path)
    parser.add_argument('--ai-review', type=Path)
    args = parser.parse_args()
    report = evaluate(args.run, args.questions, ai_review=args.ai_review)
    print(json.dumps({'run_status': report['run_status'], 'audit_ok': report['audit_ok'],
                      'saved_physical_calls': report['saved_physical_calls'], 'advantage_proven': False}))


if __name__ == '__main__':
    main()
