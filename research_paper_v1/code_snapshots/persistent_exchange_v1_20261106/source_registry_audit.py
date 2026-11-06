"""Read-only verification of a historical recovery followed by an unused turn.

Delivery continues to use the stricter source_registry API.  These audit-only
functions never select a later original artifact, create a registration, alter
evidence, or invoke a model.  An explicit bound event is required to inspect a
previously registered recovery after a separate native continuation wrote the
original output path.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re

from . import source_registry as registry

EVENT_NAME = 'late_original_artifact_event.json'
_NATIVE_PROJECTS = Path('[USER_HOME]/.workbuddy/projects').resolve()
_CONTINUE_QUERY_SHA = 'bb760742029a76fa050cf9aefa30e70d923f65b1684696a8498640df7071e4d3'


def _need(test, code):
    if not test:
        raise registry.SourceRegistryError('late_source_audit:'+code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _plain(value):
    value = str(value)
    return Path(value[4:] if value.startswith('\\\\?\\') else value).resolve()


def _io(path):
    # Windows extended paths change only filesystem I/O, never identity checks.
    text = str(path)
    return Path('\\\\?\\'+text) if os.name == 'nt' and len(text) >= 248 else path


def _same_path(value, expected):
    return isinstance(value, str) and _plain(value) == expected.resolve()


def _args(row):
    value = row.get('arguments')
    try:
        value = json.loads(value) if isinstance(value, str) else value
    except ValueError:
        value = None
    _need(isinstance(value, dict), 'native_tool_arguments_required')
    return value


def _time(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def _historical_pair(cell, event):
    """Recompute every existing receipt field; only old file absence is dated."""
    original_raw, original = registry._read(registry._local(cell, 'result.json'))
    identity = registry._identity(original)
    _need(original.get('memory') is None and original['evidence'].get('artifact_sha256') is None,
          'original_frozen_result_must_remain_no_output')
    _need(identity['platform'] == 'hy3', 'native_hy3_original_required')
    quota_raw, quota = registry._quota_binding(cell, original)
    replacement_path = registry._local(cell, 'quota_recovery_01/result.json')
    replacement_raw, replacement = registry._read(replacement_path)
    _need(registry._identity(replacement) == identity, 'replacement_identity_changed')
    old_input = registry._local(cell, 'sources.json').read_bytes()
    new_input = registry._local(cell, 'quota_recovery_01/sources.json').read_bytes()
    _need(old_input == new_input, 'source_projection_bytes_changed')
    try:
        actual_ids = [s['source_id'] for s in json.loads(old_input)['sources']]
    except (ValueError, KeyError, TypeError):
        raise registry.SourceRegistryError('late_source_audit:invalid_source_projection') from None
    _need(actual_ids == identity['source_ids'], 'source_projection_identity_changed')
    pair = {'original': original, 'replacement': replacement, 'quota': quota,
            'original_result_sha256': _sha(original_raw),
            'provider_quota_evidence_sha256': _sha(quota_raw),
            'replacement_result_sha256': _sha(replacement_raw),
            'sources_json_sha256': _sha(old_input), 'identity': identity,
            'replacement_file': replacement_path}
    receipt_file = registry._local(cell, registry.RECEIPT_NAME)
    receipt_raw, receipt = registry._read(receipt_file)
    _need(receipt == registry._receipt_value(cell, pair), 'historical_receipt_or_bound_evidence_changed')
    _need(event.get('frozen_recovery_receipt_sha256') == _sha(receipt_raw)
          and event.get('original_result_sha256') == pair['original_result_sha256']
          and event.get('original_sources_sha256') == pair['sources_json_sha256']
          and event.get('adopted_replacement_result_sha256') == pair['replacement_result_sha256'],
          'event_historical_hash_binding_changed')
    _need(_same_path(event.get('frozen_recovery_receipt_path'), receipt_file)
          and _same_path(event.get('adopted_replacement_result_path'), replacement_path),
          'event_historical_path_binding_changed')
    return pair, receipt_file


def _verified_late_event(cell):
    event_path = registry._local(cell, EVENT_NAME)
    event_raw, event = registry._read(event_path)
    _need(event.get('schema') == 'late-original-source-artifact-event-v1'
          and _same_path(event.get('source_cell'), cell), 'explicit_event_required')
    _need(event.get('late_artifact_adopted_for_study') is False
          and event.get('registered_replacement_selection_changed') is False
          and event.get('original_results_or_receipts_modified') is False
          and event.get('original_result_still_memory_none') is True
          and event.get('frozen_bindings_still_match') ==
              {'original_result': True, 'original_sources': True, 'replacement_result': True},
          'event_must_preserve_frozen_selection')
    pair, receipt_file = _historical_pair(cell, event)
    late = event.get('late_artifact') or {}
    late_file = registry._local(cell, 'memory.json')
    late_raw = late_file.read_bytes()
    _need(_same_path(late.get('path'), late_file) and late.get('sha256') == _sha(late_raw)
          and late.get('bytes') == len(late_raw), 'late_artifact_changed')
    receipt_mtime, late_mtime = receipt_file.stat().st_mtime, late_file.stat().st_mtime
    _need(abs(_time(event['recovery_receipt_filesystem_mtime_utc'])-receipt_mtime) < .001
          and abs(_time(late['filesystem_mtime_utc'])-late_mtime) < .001
          and abs(late['seconds_after_recovery_receipt_mtime']-(late_mtime-receipt_mtime)) < .001
          and late_mtime > receipt_mtime, 'late_artifact_chronology_changed')
    _, plan = registry._read(registry._local(cell, 'native_job.json'))
    sid = event.get('original_session_id')
    _need(sid == plan.get('sessionId') and event.get('original_task_id') == plan.get('taskId')
          == pair['quota']['source_job_id'], 'original_native_job_identity_changed')
    supplied_history = Path(event.get('own_native_history_path', ''))
    history = _plain(supplied_history)
    _need(not supplied_history.is_symlink() and history.name == str(sid)+'.jsonl'
          and history.is_relative_to(_NATIVE_PROJECTS)
          and not any(p.is_symlink() for p in (history, *history.parents) if p.is_relative_to(_NATIVE_PROJECTS)),
          'only_own_native_history_allowed')
    count = event.get('own_native_history_prefix_bytes')
    _need(type(count) is int and 0 < count <= 16*1024*1024, 'bounded_native_prefix_required')
    with _io(history).open('rb') as stream:
        raw = stream.read(count)
    lines = raw.splitlines(keepends=True)
    _need(len(raw) == count and _sha(raw) == event.get('own_native_history_prefix_sha256')
          and len(lines) == event.get('own_native_history_prefix_lines'), 'native_prefix_changed')
    try:
        rows = [json.loads(line) for line in lines]
    except ValueError:
        raise registry.SourceRegistryError('late_source_audit:invalid_native_prefix') from None
    turn = event.get('new_user_turn') or {}
    number = turn.get('line')
    _need(type(number) is int and 1 <= number <= len(rows), 'native_new_turn_line_required')
    user = rows[number-1]
    text = ''.join(b.get('text', '') for b in user.get('content', [])
                   if isinstance(b, dict) and b.get('type') in {'input_text', 'text'})
    queries = re.findall(r'<user_query>\s*(.*?)\s*</user_query>', text, re.S)
    query = queries[-1] if len(queries) == 1 else text
    _need(user.get('role') == 'user' and user.get('sessionId') == sid
          and user.get('providerData', {}).get('startsNewUserRequest') is True
          and user.get('timestamp') == turn.get('timestamp_ms')
          and user['timestamp']/1000 > receipt_mtime
          and turn.get('starts_new_user_request') is True
          and turn.get('query_classification') == 'official_rate_limit_continue_prompt'
          and turn.get('query_sha256') == _sha(query.encode()) == _CONTINUE_QUERY_SHA
          and turn.get('whole_user_text_sha256') == _sha(text.encode())
          and turn.get('queue_wake_marker_present') is False
          and 'CODEX_QUEUE_WAKE' not in text, 'native_new_turn_not_official_later_continuation')
    prefixes = b''
    old_prefix_found = False
    for line in lines[:number-1]:
        prefixes += line
        old_prefix_found |= _sha(prefixes) == pair['quota']['native_history_prefix_sha256']
    _need(old_prefix_found, 'original_quota_prefix_not_preserved_before_new_turn')
    _need(not any(r.get('role') == 'user' and r.get('providerData', {}).get('startsNewUserRequest') is True
                  for r in rows[number:]), 'additional_undeclared_user_turn')
    write = event.get('matching_native_write') or {}
    wn = write.get('line')
    _need(type(wn) is int and number < wn <= len(rows), 'native_write_line_required')
    row, arguments = rows[wn-1], _args(rows[wn-1])
    provider = row.get('providerData') or {}
    _need(row.get('type') == 'function_call' and row.get('name') == 'Write'
          and row.get('sessionId') == sid and row.get('timestamp') == write.get('timestamp_ms')
          and row['timestamp'] >= user['timestamp']
          and _same_path(arguments.get('file_path'), late_file)
          and _same_path(write.get('target_path'), late_file)
          and isinstance(arguments.get('content'), str)
          and arguments['content'].encode() == late_raw
          and write.get('content_sha256') == _sha(late_raw)
          and write.get('exact_current_file_bytes_match') is True
          and write.get('model') == provider.get('model') == 'hy3-x'
          and write.get('request_model_id') == provider.get('requestModelId') == 'hy3-x',
          'native_write_not_bound_to_unused_late_artifact')
    reads = event.get('new_turn_original_input_reads')
    _need(isinstance(reads, list) and bool(reads), 'original_input_read_evidence_required')
    for read in reads:
        rn = read.get('line')
        _need(type(rn) is int and number < rn < wn, 'native_read_order_changed')
        r = rows[rn-1]
        _need(r.get('name') == 'Read' and r.get('sessionId') == sid
              and r.get('timestamp') == read.get('timestamp_ms')
              and _same_path(read.get('business_path'), cell/'sources.json')
              and _same_path(_args(r).get('file_path'), cell/'sources.json'), 'native_original_input_read_changed')
    actual = sorted({r.get('providerData', {}).get('model') for r in rows[number-1:]
                     if r.get('providerData', {}).get('model')})
    requested = sorted({r.get('providerData', {}).get('requestModelId') for r in rows[number-1:]
                        if r.get('providerData', {}).get('requestModelId')})
    _need(actual == event.get('new_turn_actual_models') == ['hy3-x']
          and requested == event.get('new_turn_request_model_ids') == ['hy3-x'], 'late_native_model_binding_changed')
    expected_cost = {'input_tokens': None, 'native_additional_continuation_turns': 1,
        'native_turn_is_one_supplier_request': False, 'new_source_result_records': 0,
        'output_tokens': None, 'physical_supplier_calls': None, 'qualified_study_source_results': 0,
        'supplier_fee_cny': None}
    _need(event.get('extra_continuation_cost_evidence') == expected_cost, 'late_continuation_cost_unknown_must_not_be_zero')
    return event_path, event_raw, event, pair


def resolve_source_result_for_audit(cell_dir):
    cell = registry._cell(cell_dir)
    if not registry._local(cell, EVENT_NAME).exists():
        return registry.resolve_source_result(cell)
    _, _, _, pair = _verified_late_event(cell)
    return pair['replacement_file']


def source_attempt_paths_for_audit(cell_dir):
    cell = registry._cell(cell_dir)
    if not registry._local(cell, EVENT_NAME).exists():
        return registry.source_attempt_paths(cell)
    _verified_late_event(cell)
    paths = [registry._local(cell, 'result.json')]
    for folder in sorted(cell.glob('quota_recovery_*')):
        _need(folder.is_dir() and not folder.is_symlink(), 'invalid_recovery_directory')
        path = registry._local(cell, folder.name+'/result.json')
        if path.is_file():
            paths.append(path)
    return paths


def late_source_continuation_for_audit(cell_dir):
    """Return an extra cost-only observation, never a study source artifact."""
    cell = registry._cell(cell_dir)
    if not registry._local(cell, EVENT_NAME).exists():
        return None
    path, raw, event, pair = _verified_late_event(cell)
    return {'schema': 'late-source-native-continuation-audit-v1', 'event_path': str(path),
        'event_sha256': _sha(raw), 'experiment_identity': pair['identity'],
        'original_session_id': event['original_session_id'], 'original_task_id': event['original_task_id'],
        'actual_models': event['new_turn_actual_models'], 'request_model_ids': event['new_turn_request_model_ids'],
        'late_artifact_adopted_for_study': False, 'registered_replacement_selection_changed': False,
        **event['extra_continuation_cost_evidence']}


__all__ = ['resolve_source_result_for_audit', 'source_attempt_paths_for_audit',
           'late_source_continuation_for_audit']
