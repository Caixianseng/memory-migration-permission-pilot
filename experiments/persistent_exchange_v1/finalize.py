"""Independent local readback, input binding, identity and resource ledger audit.

Reads only frozen public materials and explicit outer job artifacts. Private SDK
homes, request directories and credentials are never opened. No inference runs.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sqlite3

from experiments.revocation_grouping_v1.sdk_adapter import usage_costs, dispatch_text
from .evaluate import (evaluate, is_unknown, value_present, _bootstrap,
                       _difference, _reduction, _mean, BOOTSTRAP_SEED)
from .prepare_data import permission_event, receiver_questions
from .read_receiver import read_batch, canonical
from .store import TrustedPolicy

HERE = Path(__file__).resolve().parent
ARMS = ('raw', 'whole_drop', 'full_rebuild', 'selective')
HY3_OFFICIAL_ROUTE_IDS = frozenset({'hy3', 'hy3-x'})


class FinalizeError(RuntimeError):
    pass


def _need(condition, code):
    if not condition:
        raise FinalizeError(code)


def _sha(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, bytes):
        value = canonical(value)
    return hashlib.sha256(value).hexdigest()


def _plain(value):
    """Normalize only the optional namespace prefix of the same Windows drive."""
    text = str(value)
    if text.startswith('\\\\?\\') and len(text) > 6 and text[5] == ':':
        text = text[4:]
    return Path(text)


def _resolved(value):
    return _plain(_plain(value).resolve())


def _path(root, value):
    """Resolve explicit artifacts inside this run and refuse private subtrees."""
    path = _plain(value)
    path = path if path.is_absolute() else root / path
    _need(not any(part.casefold() in {'sdk.private', 'home.private'} or 'credential' in part.casefold()
                  for part in path.parts), 'private_artifact_path_forbidden')
    _need(not path.is_symlink(), 'artifact_symlink_forbidden')
    path = _resolved(path)
    _need(path.is_relative_to(root), 'artifact_outside_result_root')
    _need(not any(part.casefold() in {'sdk.private', 'home.private'} or 'credential' in part.casefold()
                  for part in path.parts), 'resolved_private_artifact_path_forbidden')
    return path


def _load(path):
    return json.loads(Path(path).read_bytes())


def _save(path, value):
    _need(not path.is_symlink(), 'report_symlink_forbidden')
    temporary = path.with_suffix(path.suffix + '.tmp')
    _need(not temporary.is_symlink(), 'temporary_report_symlink_forbidden')
    temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False), encoding='utf-8')
    temporary.replace(path)


def _refs(dependencies):
    _need(isinstance(dependencies, list), 'dependency_list_required')
    result = set()
    for dependency in dependencies:
        _need(isinstance(dependency, dict) and set(dependency) == {'source_id', 'version', 'sha256', 'owner_id'},
              'complete_original_dependency_binding_required')
        result.add(tuple(dependency[key] for key in ('source_id', 'version', 'sha256', 'owner_id')))
    return result


def _original_refs(sources, owner):
    return [{'source_id': source['source_id'], 'version': source['version'],
             'sha256': _sha(source['text']), 'owner_id': owner} for source in sources]


def _hy3_routes(native):
    actual, requested = native.get('actual_models'), native.get('request_model_ids')
    _need(isinstance(actual, list) and bool(actual) and isinstance(requested, list) and bool(requested)
          and all(isinstance(value, str) and value in HY3_OFFICIAL_ROUTE_IDS for value in actual + requested),
          'hy3_actual_and_requested_model_mismatch')
    billing = native.get('billing_route_ids', requested)
    _need(isinstance(billing, list) and set(billing) == set(requested), 'hy3_billing_route_evidence_disagrees')
    _need(native.get('canonical_model_family', 'Hy3') == 'Hy3', 'hy3_canonical_family_evidence_disagrees')
    return {'canonical_model_family': 'Hy3', 'actual_models': list(actual),
            'request_model_ids': list(requested), 'billing_route_ids': list(billing),
            'route_ids_rewritten_to_family': False}


def _identity(evidence, platform, output, *, source=False, sources_raw=None):
    """Audit public evidence fields, not private provider histories or requests."""
    if platform == 'hy3':
        if not source and evidence.get('execution_mode') == 'controller_readback_native_paid_one_shot':
            envelope = evidence.get('native_paid_envelope') or {}
            routes = _hy3_routes({'actual_models': envelope.get('actualModels'),
                                   'request_model_ids': envelope.get('requestModelIds'),
                                   'billing_route_ids': envelope.get('requestModelIds')})
            _need(envelope.get('status') == 'verified_native_paid_one_shot'
                  and envelope.get('requestModelIds') == ['hy3-x']
                  and envelope.get('requestedModel') == 'hy3-x'
                  and envelope.get('mode') == 'ask' and envelope.get('tools') == ''
                  and envelope.get('nativeUserRequestCount') == 1 and envelope.get('toolCallCount') == 0
                  and envelope.get('nativeBusinessQueryMatchesSubmitted') is True
                  and evidence.get('actual_models') == envelope['actualModels']
                  and evidence.get('request_model_ids') == envelope['requestModelIds']
                  and evidence.get('billing_route_ids') == envelope['requestModelIds']
                  and evidence.get('workbuddy_fee_cny') is None and evidence.get('physical_supplier_calls') is None,
                  'paid_native_receiver_identity_evidence_mismatch')
            return {'platform': 'hy3', **routes, 'native_session_id': envelope['sessionId'],
                    'native_task_id': envelope['jobId'], 'native_tasks': 1,
                    'native_queue_submissions': 0, 'native_direct_session_submissions': 1,
                    'provider_identity_verified': True, 'physical_supplier_calls': None,
                    'supplier_fee_cny': None, 'token_usage': None,
                    'estimated_cold_peak_cny': None, 'estimated_cache_aware_peak_cny': None,
                    'native_tool_call_count': 0, 'native_user_request_count': 1,
                    'input_receipt_scope': 'controller fresh-process receiver DB readback plus one native paid zero-tool language turn; official user_query business binding verified, full upstream input and supplier request count not attested'}
        native = evidence if source else evidence.get('native_reader_audit', {})
        routes = _hy3_routes(native)
        supervisor_routes = None
        if not source:
            _need(evidence.get('actual_model') in HY3_OFFICIAL_ROUTE_IDS
                  and evidence.get('native_reader_command_verified') is True,
                  'hy3_receiver_native_reader_not_verified')
            base = evidence.get('native_evidence') or native
            if evidence.get('native_evidence') and any(key in base for key in ('actual_models', 'request_model_ids')):
                supervisor_routes = _hy3_routes(base)
        else:
            base = evidence
        session = native.get('session_id', base.get('session_id'))
        _need(isinstance(session, str) and bool(session), 'hy3_session_identity_missing')
        return {'platform': 'hy3', 'native_session_id': session,
                'native_task_id': base.get('task_id'), 'native_tasks': 1,
                **routes, 'supervisor_route_evidence': supervisor_routes,
                'outer_actual_model_claim': evidence.get('actual_model'),
                'native_queue_submissions': 1, 'provider_identity_verified': True,
                'physical_supplier_calls': None, 'supplier_fee_cny': None,
                'token_usage': None, 'estimated_cold_peak_cny': None,
                'estimated_cache_aware_peak_cny': None,
                'input_receipt_scope': 'outer native HY3 Read/Write audit; remote provider request bytes not observed'}
    _need(platform == 'flash', 'unknown_model_platform')
    receipt = evidence.get('receipt', {})
    truncated = source and receipt.get('status') == 'max_tokens_closed'
    _need(receipt.get('status') in ({'max_tokens_closed'} if truncated else {'ok'}) and receipt.get('actual_model') == 'deepseek-flash'
          and receipt.get('provider') == 'deepseek-account'
          and receipt.get('physical_request_count') == 1
          and (truncated or receipt.get('temporary_credentials_removed') is True),
          'flash_model_or_single_request_receipt_invalid')
    if truncated:
        _need(evidence.get('model_attempt_closed') is True and evidence.get('source_protocol_conformance') is False
              and evidence.get('guard_counts') == {'agent_attempt_count': 1, 'stream_attempt_count': 1, 'allowed_stream_count': 1}
              and receipt.get('completed') is False and receipt.get('original_failure_and_reservation_preserved') is True
              and receipt.get('automatic_retry') is False
              and evidence.get('original_terminal_reason') == {'kind': 'max-tokens'},
              'truncated_source_attempt_not_strictly_closed')
    if 'actual_model' in evidence:
        _need(evidence['actual_model'] == receipt['actual_model'], 'flash_outer_model_evidence_disagrees')
    _need(receipt.get('response_sha256') == _sha(output), 'flash_response_hash_mismatch')
    _need(receipt.get('cost_is_supplier_bill') is False, 'flash_estimate_mislabeled_as_bill')
    tokens, peak, cached = usage_costs(receipt.get('usage'))
    for key, value in tokens.items():
        if key in receipt:
            _need(receipt[key] == value, 'flash_usage_field_mismatch:' + key)
    for key, expected in (('estimated_peak_cost_cny', peak), ('estimated_cache_aware_peak_cost_cny', cached)):
        observed = receipt.get(key)
        _need((None if observed is None else Decimal(str(observed))) == expected,
              'flash_cost_estimate_mismatch:' + key)
    for key in ('request_sha256', 'dispatch_sha256', 'business_messages_sha256'):
        _need(isinstance(receipt.get(key), str) and len(receipt[key]) == 64,
              'flash_receipt_hash_missing:' + key)
    if source:
        messages = evidence.get('messages')
        _need(isinstance(messages, list) and len(messages) == 2
              and messages[0].get('role') == 'system' and messages[1].get('role') == 'user'
              and messages[1].get('content') == sources_raw.decode('utf-8'),
              'flash_source_business_input_not_exact_sources_file')
        _need(receipt['business_messages_sha256'] == _sha(messages)
              and receipt['dispatch_sha256'] == _sha(dispatch_text(messages)),
              'flash_source_business_or_dispatch_hash_mismatch')
        _need(evidence.get('input_sha256') == _sha(sources_raw), 'flash_source_input_file_hash_mismatch')
    else:
        _need(evidence.get('business_messages_sha256') == receipt['business_messages_sha256'],
              'flash_receiver_business_hash_mismatch')
    identity = ((receipt.get('request_sha256'), receipt.get('dispatch_sha256')) if truncated else
                (receipt.get('session_id'), receipt.get('request_id')))
    _need(all(isinstance(part, str) and part for part in identity), 'flash_request_identity_missing')
    return {'platform': 'flash', 'request_identity': list(identity),
            'native_tasks': 0, 'physical_supplier_calls': 1, 'supplier_fee_cny': None,
            'token_usage': tokens, 'estimated_cold_peak_cny': str(peak),
            'estimated_cache_aware_peak_cny': str(cached) if cached is not None else None,
            'input_receipt_scope': ('outer closed-completion guard/input/request/partial-response audit and hashes; private transport not re-read' if truncated else
                                   'outer exact sources/messages/dispatch/response hash binding; private transport not re-read' if source else
                                    'runtime receipt plus public questions/readback bindings; full receiver messages not exposed in outer artifact')}


def _planned_jobs(root, cases):
    jobs = {}
    for case in cases:
        for owner in ('A', 'B'):
            sources = case['agents'][owner]['sources']
            ids = [source['source_id'] for source in sources]
            allowed = set(permission_event(case, owner + '_to_' + ('B' if owner == 'A' else 'A'))['allowed'])
            groups = [('whole', ids)] + [('chunk' + str(i), group) for i, group in enumerate(case['chunks'][owner])]
            for phase in ('initial', 'repair'):
                for group, subset in groups:
                    if phase == 'repair':
                        if set(subset) <= allowed:
                            continue
                        subset = [sid for sid in subset if sid in allowed]
                        if not subset:
                            continue
                    path = root / 'source_jobs' / case['case_id'] / owner / phase / group / 'result.json'
                    jobs[path] = {'case_id': case['case_id'], 'agent': owner,
                                  'platform': 'hy3' if owner == 'A' else 'flash',
                                  'phase': phase, 'group': group, 'budget': 2048 if group == 'whole' else 1024,
                                  'source_ids': subset,
                                  'sources': [next(source for source in sources if source['source_id'] == sid) for sid in subset]}
    return jobs


def _source_scope(root, result_path, result):
    """Intersect immutable result status with the separately bound PS audit."""
    evidence = result.get('evidence', {})
    if evidence.get('source_protocol_conformance', True) is False:
        return False, None
    if result['platform'] != 'hy3':
        return True, None
    audit_path = _path(root, result_path.parent / 'native_source_shell_scope_audit.json')
    _need(audit_path.is_file(), 'native_source_shell_scope_audit_required')
    audit = _load(audit_path)
    _need(audit.get('schema') == 'native-source-shell-scope-audit-v1'
          and audit.get('source_result_sha256') == _sha(result_path.read_bytes())
          and audit.get('session_id') == evidence.get('session_id')
          and audit.get('task_id') == evidence.get('task_id')
          and audit.get('artifact_sha256') == evidence.get('artifact_sha256')
          and type(audit.get('protocol_conformance')) is bool,
          'native_source_shell_scope_audit_binding_invalid')
    return audit['protocol_conformance'], {
        'audit_file': str(audit_path), 'audit_sha256': _sha(audit_path.read_bytes()),
        'protocol_conformance': audit['protocol_conformance'],
        'issues': audit.get('issues', []), 'command_counts': audit.get('command_counts', {}),
        'full_remote_input_attestation': False,
        'scope': 'separately bound local native shell and explicit file-tool footprint; not complete remote model input attestation'}


def _closed_source(root, result_path, result, source_raw, late_audit=None):
    """Approve exclusion of a closed attempt, never its generated prose."""
    evidence, platform = result['evidence'], result['platform']
    _need(evidence.get('model_attempt_closed') is True and evidence.get('source_protocol_conformance') is False
          and evidence.get('artifact_sha256') is None, 'missing_source_not_explicitly_closed')
    if platform == 'hy3':
        if evidence.get('qualified_native_execution') is True:
            _need(evidence.get('runtime_source') == 'desktop_queue'
                  and evidence.get('native_task_submitted') is True
                  and evidence.get('declared_output_exists') is False
                  and evidence.get('protocol_issues') == ['source_output_written_outside_declared_directory']
                  and not _path(root, result_path.parent / 'memory.json').exists(),
                  'missing_native_output_not_explicitly_closed')
            observed = evidence.get('observed_Write_tool_paths')
            _need(isinstance(observed, list) and bool(observed)
                  and all(isinstance(path, str) for path in observed)
                  and any(_resolved(path) != result_path.parent/'memory.json' for path in observed),
                  'missing_native_output_wrong_write_path_not_observed')
            closed_path = _path(root, result_path.parent/'native_missing_output_closed.json')
            _need(_load(closed_path) == evidence, 'native_missing_output_closed_receipt_changed')
            _need(evidence.get('protocol_failure_action') == 'no artifact moved or copied; fail closed; no new prompt',
                  'missing_native_output_must_not_be_moved_or_regenerated')
            identity = _identity(evidence, 'hy3', None, source=True)
            return identity, 'missing_output_tool_protocol_closed', 0, _sha(closed_path.read_bytes())
        if evidence.get('native_task_submitted') is True:
            _need(evidence.get('native_queue_state') == 'blocked'
                  and evidence.get('provider_identity_verified') is False
                  and isinstance(evidence.get('actual_models'), list) and set(evidence['actual_models']) <= HY3_OFFICIAL_ROUTE_IDS
                  and isinstance(evidence.get('request_model_ids'), list) and set(evidence['request_model_ids']) <= HY3_OFFICIAL_ROUTE_IDS
                  and evidence.get('physical_supplier_calls') is None
                  and evidence.get('workbuddy_physical_supplier_calls') is None
                  and evidence.get('workbuddy_fee_cny') is None
                  and evidence.get('protocol_issues') == ['native_queue_terminal_blocked_without_generated_artifact']
                  and evidence.get('protocol_failure_action') == 'no verified source execution or memory; fail closed; preserve unknown usage; no replay',
                  'terminal_queue_failure_not_closed_with_unknown_execution')
            _need(not _path(root, result_path.parent / 'memory.json').exists() or late_audit is not None,
                  'terminal_queue_failure_has_memory_artifact')
            plan = _load(_path(root, result_path.parent / 'native_job.json'))
            submitted = _load(_path(root, result_path.parent / 'submission_intent.json'))
            _need(plan.get('taskId') == evidence.get('task_id') == submitted.get('task_id')
                  and plan.get('sessionId') == evidence.get('session_id')
                  and isinstance(evidence.get('native_history_prefix_sha256'), str)
                  and len(evidence['native_history_prefix_sha256']) == 64,
                  'terminal_queue_submission_identity_or_history_hash_mismatch')
            closed_path = _path(root, result_path.parent / 'native_terminal_closed.json')
            _need(_load(closed_path) == evidence, 'native_terminal_closed_receipt_changed')
            blocked_states = []
            for state_path in result_path.parent.glob('task_state_*.json'):
                state = _load(_path(root, state_path)).get('task', {})
                if state.get('state') == 'blocked' and state.get('taskId') == plan['taskId']:
                    blocked_states.append(state_path)
            _need(bool(blocked_states), 'terminal_queue_blocked_outer_state_missing')
            identity = {'platform': 'hy3', 'native_session_id': plan['sessionId'],
                        'native_task_id': plan['taskId'], 'native_tasks': 0,
                        'native_queue_submissions': 1, 'provider_identity_verified': False,
                        'actual_models': list(evidence['actual_models']),
                        'request_model_ids': list(evidence['request_model_ids']),
                        'billing_route_ids': list(evidence['request_model_ids']),
                        'canonical_model_family': 'Hy3',
                        'family_assignment_scope': 'requested/observed route metadata; no approved model execution',
                        'model_execution_count': None, 'physical_supplier_calls': None,
                        'supplier_fee_cny': None, 'token_usage': None,
                        'estimated_cold_peak_cny': None, 'estimated_cache_aware_peak_cny': None,
                        'input_receipt_scope': 'one queue submission ended blocked with no memory and no provider identity; actual model execution, requests, usage and fees remain unknown'}
            return identity, 'terminal_queue_no_artifact_closed', 0, _sha(closed_path.read_bytes())
        _need(evidence.get('model_prompts_submitted') == 0
              and evidence.get('actual_models') == [] and evidence.get('request_model_ids') == []
              and evidence.get('physical_supplier_calls') == 0
              and evidence.get('workbuddy_physical_supplier_calls') == 0,
              'native_pre_model_failure_does_not_prove_zero_submission')
        _need(not _path(root, result_path.parent / 'submission_intent.json').exists(),
              'native_zero_submission_failure_has_dispatch_intent')
        _need(not _path(root, result_path.parent / 'memory.json').exists(),
              'native_zero_submission_failure_has_generated_memory_artifact')
        created_path = _path(root, result_path.parent / 'created.json')
        created = _load(created_path)
        _need(created.get('modelPromptsSubmitted') == 0 and _sha(created_path.read_bytes()) == evidence.get('creation_sha256'),
              'native_zero_submission_creation_receipt_mismatch')
        closed_path = _path(root, result_path.parent / 'native_creation_closed.json')
        _need(_load(closed_path) == evidence, 'native_creation_closed_receipt_changed')
        identity = {'platform': 'hy3', 'native_session_id': None, 'native_task_id': None,
                    'native_tasks': 0, 'model_prompts_submitted': 0, 'physical_supplier_calls': 0,
                    'native_queue_submissions': 0, 'provider_identity_verified': False,
                    'supplier_fee_cny': None, 'token_usage': None,
                    'estimated_cold_peak_cny': None, 'estimated_cache_aware_peak_cny': None,
                    'input_receipt_scope': 'created.json proves zero model prompts and no submission intent; no generated memory'}
        return identity, 'pre_model_creation_closed', 0, _sha(closed_path.read_bytes())
    _need(platform == 'flash', 'closed_source_platform_unknown')
    audit_path = _path(root, result_path.parent / 'failed_completion_audit.json')
    closed = _load(audit_path)
    _need(closed.get('usable_generated_memory') is False and isinstance(closed.get('evidence'), dict),
          'closed_completion_audit_does_not_reject_memory')
    for key, value in closed['evidence'].items():
        _need(evidence.get(key) == value, 'closed_completion_outer_evidence_changed:' + key)
    _need(evidence.get('input_sha256') == _sha(source_raw), 'closed_completion_source_input_hash_mismatch')
    _need(evidence.get('protocol_failure_action') == 'fail closed; keep original reservation; no new request',
          'closed_completion_reservation_not_preserved')
    partial = closed.get('partial_model_output')
    if evidence.get('receipt', {}).get('status') == 'max_tokens_closed':
        _need(isinstance(partial, str) and evidence.get('partial_output_sha256') == _sha(partial)
              and isinstance(evidence.get('original_failed_receipt_sha256'), str)
              and len(evidence['original_failed_receipt_sha256']) == 64
              and evidence['original_failed_receipt_sha256'] == evidence['receipt'].get('original_failed_receipt_sha256'),
              'closed_completion_partial_or_original_failure_hash_mismatch')
        identity = _identity(evidence, platform, partial, source=True, sources_raw=source_raw)
        _need(0 < identity['token_usage']['output_tokens'] <= result.get('budget', 2048),
              'closed_completion_output_usage_exceeds_registered_budget')
        return identity, 'output_truncated_closed', len(partial.encode('utf-8')), _sha(audit_path.read_bytes())
    # A source with no approved output is still blocked if its supplier outcome
    # cannot be qualified. Preserve unknown usage/cost/request counts as unknown.
    _need(evidence.get('receipt', {}).get('status') == 'failed'
          and evidence.get('physical_supplier_calls') is None,
          'unqualified_closed_completion_evidence_invalid')
    identity = {'platform': 'flash', 'request_identity': None, 'native_tasks': 0,
                'physical_supplier_calls': None, 'supplier_fee_cny': None, 'token_usage': None,
                'estimated_cold_peak_cny': None, 'estimated_cache_aware_peak_cny': None,
                'input_receipt_scope': 'closed unapproved SDK failure; actual model, request count, usage and cost unqualified'}
    return identity, 'unqualified_sdk_failure_closed', len(partial.encode('utf-8')) if isinstance(partial, str) else 0, _sha(audit_path.read_bytes())


def _source(root, result_path, expected=None, *, late_audit=None):
    result_path = _path(root, result_path)
    result = _load(result_path)
    source_path = _path(root, result_path.parent / 'sources.json')
    source_raw = source_path.read_bytes()
    supplied = json.loads(source_raw)
    _need(result.get('memory') is None or isinstance(result.get('memory'), str) and bool(result['memory']),
          'source_memory_must_be_nonempty_text_or_explicit_closed_null')
    sources, parents = supplied.get('sources'), supplied.get('parent_memories')
    _need(isinstance(sources, list) and isinstance(parents, list), 'source_business_lists_missing')
    _need([source['source_id'] for source in sources] == result.get('source_ids'), 'source_actual_input_ids_mismatch')
    if expected is not None:
        _need(all(result.get(key) == value for key, value in expected.items() if key != 'sources'),
              'source_result_does_not_match_frozen_job')
        _need(sources == expected['sources'] and not parents, 'source_original_text_version_or_hidden_parent_mismatch')
    evidence = result.get('evidence', {})
    platform = result.get('platform')
    missing_memory = result.get('memory') is None
    attempt_status, partial_bytes, closed_audit_sha256 = 'success', 0, None
    if missing_memory:
        identity, attempt_status, partial_bytes, closed_audit_sha256 = _closed_source(root, result_path, result, source_raw, late_audit)
    else:
        _need(not (platform == 'flash' and evidence.get('model_attempt_closed') is True),
              'closed_partial_completion_cannot_be_usable_memory')
        identity = _identity(evidence, platform, result['memory'], source=True, sources_raw=source_raw)
    protocol_conformance, protocol_issues = True, []
    shell_scope_audit = None
    if missing_memory:
        protocol_conformance, protocol_issues = False, evidence.get('protocol_issues', [])
    elif platform == 'hy3':
        output_path = _path(root, evidence.get('artifact_path', result_path.parent / 'memory.json'))
        _need(output_path == result_path.parent / 'memory.json', 'native_source_output_path_mismatch')
        output_raw = output_path.read_bytes()
        _need(_sha(output_raw) == evidence.get('artifact_sha256')
              and _load(output_path) == {'memory': result['memory']}, 'native_source_write_artifact_binding_mismatch')
        # Failed native paths are evidence only. Never open an extra reported
        # Read/Write path, including a path outside this run or a private path.
        reads = {str(_resolved(path)) for path in evidence.get('explicit_Read_tool_paths', [])}
        writes = {str(_resolved(path)) for path in evidence.get('Write_tool_paths', [])}
        if not reads or reads - {str(source_path)}:
            protocol_issues.append('unexpected_explicit_native_business_read')
        if not writes or writes != {str(output_path)}:
            protocol_issues.append('unexpected_native_artifact_write')
        if 'controller_cancelled_for_source_input_boundary_violation' in evidence.get('protocol_issues', []):
            cancellation = _path(root, result_path.parent / 'controller_protocol_cancellation.json')
            _need(evidence.get('model_attempt_closed') is True
                  and evidence.get('remote_execution_stopped_verified') is False
                  and _sha(cancellation.read_bytes()) == evidence.get('controller_cancellation_sha256'),
                  'native_controller_cancellation_receipt_mismatch')
            protocol_issues.append('controller_cancelled_for_source_input_boundary_violation')
        protocol_conformance = not protocol_issues
        _need(evidence.get('source_protocol_conformance', True) == protocol_conformance,
              'native_source_protocol_declaration_mismatch')
        if not protocol_conformance:
            attempt_status = 'tool_protocol_failed_closed'
            _need(set(evidence.get('protocol_issues', [])) == set(protocol_issues),
                  'native_source_protocol_issues_mismatch')
            closed = _load(_path(root, result_path.parent / 'native_protocol_failed.json'))
            for field in ('task_id', 'session_id', 'artifact_sha256', 'actual_models', 'request_model_ids',
                          'explicit_Read_tool_paths', 'Write_tool_paths', 'source_protocol_conformance', 'protocol_issues'):
                _need(closed.get(field) == evidence.get(field), 'native_source_protocol_failure_receipt_changed:' + field)
            _need(closed.get('protocol_failure_action') == 'fail_closed_at_delivery; retain task and cost; no regeneration',
                  'native_source_protocol_failure_not_closed')
    if platform == 'hy3' and evidence.get('source_protocol_conformance', True) is not False:
        scope_conformance, shell_scope_audit = _source_scope(root, result_path, result)
        if not scope_conformance:
            protocol_conformance = False
            protocol_issues.append('native_source_shell_scope_audit_failed')
            attempt_status = 'tool_protocol_failed_closed'
    native_job = _path(root, result_path.parent / 'native_job.json')
    lifecycle_ms = (max(0, (result_path.stat().st_mtime - native_job.stat().st_mtime) * 1000)
                    if platform == 'hy3' and native_job.is_file() else None)
    return result, {
        'result_file': str(result_path), 'result_sha256': _sha(result_path.read_bytes()),
        'case_id': result.get('case_id'), 'agent': result.get('agent'),
        'kind': 'source', 'phase': result.get('phase'), 'group': result.get('group'),
        'platform': platform, 'original_input_source_count': len(sources),
        'original_input_characters': sum(len(source['text']) for source in sources),
        'parent_memory_count': len(parents),
        'parent_input_characters': sum(len(parent['content']) for parent in parents),
        'serialized_business_input_bytes': len(source_raw),
        'output_memory_bytes': len(result['memory'].encode('utf-8')) if not missing_memory else 0,
        'observed_partial_output_bytes_not_memory': partial_bytes,
        'source_attempt_status': attempt_status,
        'usable_generated_memory': not missing_memory and protocol_conformance,
        'closed_attempt_outer_audit_sha256': closed_audit_sha256,
        'late_continuation_audit': late_audit,
        'source_protocol_conformance': protocol_conformance, 'protocol_issues': protocol_issues,
        'native_source_shell_scope_audit': shell_scope_audit,
        'wall_ms': result.get('wall_ms') if platform == 'flash' else None,
        'observed_outer_invocation_wall_ms': result.get('wall_ms'),
        'wall_ms_scope': ('observed current supervision only; prior dispatch and resumed monitoring may be absent; complete generation duration unknown'
                          if platform == 'hy3' else 'outer SDK invocation wall; provider stream latency is reported separately'),
        'local_native_plan_file_to_result_file_elapsed_ms': lifecycle_ms,
        'local_file_elapsed_scope': 'native_job plan/result file mtime difference includes queue, creation and monitoring recovery; not pure model time or exact billed time',
        'flash_receipt_latency_ms': (evidence['receipt'].get('latency_seconds') * 1000
                                     if platform == 'flash' and isinstance(evidence['receipt'].get('latency_seconds'), (int, float)) else None),
        'identity': identity,
    }


def _selected(root, case, direction, arm, results, *, include_protocol=False, effective_paths=None, attempt_paths=None):
    owner = direction.split('_to_')[0]
    sources = case['agents'][owner]['sources']
    by_id = {source['source_id']: source for source in sources}
    allowed = set(permission_event(case, direction)['allowed'])
    full = [source['source_id'] for source in sources]
    selected, logical = [], []
    folder = root / 'source_jobs' / case['case_id'] / owner

    def job(phase, group):
        return folder / phase / group / 'result.json'

    if arm == 'raw':
        selected = [(source['text'], [source['source_id']], None) for source in sources if source['source_id'] in allowed]
    elif arm in ('whole_drop', 'full_rebuild'):
        logical = [job('initial', 'whole')]
        if set(full) <= allowed:
            selected = [(results[logical[0]]['memory'], full, logical[0])]
        elif arm == 'full_rebuild':
            logical.append(job('repair', 'whole'))
            selected = [(results[logical[-1]]['memory'], [sid for sid in full if sid in allowed], logical[-1])]
    elif arm == 'selective':
        logical = [job('initial', 'chunk' + str(i)) for i in range(2)]
        for i, group in enumerate(case['chunks'][owner]):
            legal = [sid for sid in group if sid in allowed]
            if not legal:
                continue
            path = job('initial' if set(group) <= allowed else 'repair', 'chunk' + str(i))
            if path not in logical:
                logical.append(path)
            selected.append((results[path]['memory'], legal, path))
    else:
        raise FinalizeError('unknown_main_arm')
    rejected_paths = [path for _, _, path in selected if path is not None
                      and not _source_scope(root, (effective_paths or {}).get(path, path), results[path])[0]]
    selected = [(text, ids, path) for text, ids, path in selected if path not in rejected_paths]
    refs = _original_refs([by_id[sid] for _, ids, _ in selected for sid in ids], owner)
    logical_refs = [attempt for path in logical for attempt in (attempt_paths or {}).get(path, [path])]
    base = ('\n\n'.join(text for text, _, _ in selected), refs, logical_refs)
    if not include_protocol:
        return base
    rejected_keys = [('FAILED-' + owner + '-' + path.parent.name + '-' + path.parent.parent.name
                      if results[path]['memory'] is None else
                      'mem-' + _sha({'origin_agent': owner, 'memory_id': path.parent.name + '-' + path.parent.parent.name,
                                    'version': 1})) for path in rejected_paths]
    return (*base, {'source_protocol_clean': not rejected_paths,
                    'source_protocol_rejected_memory_keys': rejected_keys,
                    'source_protocol_rejected_job_files': [str(path) for path in rejected_paths]})


def _current_policy_check(path, recipient, dependencies, epoch):
    policy = TrustedPolicy.__new__(TrustedPolicy)
    policy.path = path
    policy.db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, isolation_level=None)
    policy.db.row_factory = sqlite3.Row
    try:
        policy.db.execute('PRAGMA query_only=ON')
        _need(policy.epoch == epoch, 'current_policy_epoch_changed')
        policy.check_dependencies(recipient, dependencies, epoch)
    finally:
        policy.close()


def _receiver(root, record, allowed, *, expected_memory=None, expected_refs=None, effective_job_dir=None):
    delivery = record['delivery']
    database = _path(root, delivery['receiver_db'])
    policy_path = _path(root, delivery['policy_db'])
    _need(database.is_file() and policy_path.is_file(), 'receiver_or_policy_database_missing')
    reopened = read_batch(database, delivery['batch_id'])
    payload, receipt = reopened['payload'], reopened['receipt']
    evidence = record.get('receiver_evidence', {})
    original = evidence.get('reader_receipt', {})
    _need(original, 'receiver_original_read_receipt_missing')
    for key, value in receipt.items():
        if key != 'read_ms':
            _need(_sha(original.get(key)) == _sha(value), 'receiver_receipt_changed:' + key)
    _need(payload['recipient_id'] == record['recipient'] == receipt['recipient_id'], 'receiver_identity_mismatch')
    _need(_sha(payload['memory']) == delivery['reopened_content_sha256'], 'receiver_reopened_memory_hash_mismatch')
    _need(receipt['presented_memory_keys'] == delivery['memory_keys'], 'receiver_presented_memory_keys_mismatch')
    _need(receipt['import_epoch'] == delivery['policy_epoch'], 'receiver_import_epoch_mismatch')
    actual_refs = [dep for memory in receipt['records'] for dep in memory['dependencies']]
    _need(_refs(actual_refs) == _refs(delivery['dependencies']), 'receiver_dependency_closure_mismatch')
    _need({ref[0] for ref in _refs(actual_refs)} <= set(allowed), 'receiver_unauthorized_original_dependency')
    if expected_refs is not None:
        _need(_refs(actual_refs) == _refs(expected_refs), 'receiver_dependency_original_binding_not_frozen_inputs')
    if expected_memory is not None:
        _need(payload['memory'] == expected_memory, 'receiver_memory_not_selected_real_model_outputs_or_legal_raw')
    _current_policy_check(policy_path, record['recipient'], actual_refs, delivery['policy_epoch'])
    job_dir = _path(root, effective_job_dir or record['job_dir'])
    questions_path, answers_path = job_dir / 'questions.json', job_dir / 'answers.json'
    questions = _load(questions_path)
    answers_raw = answers_path.read_bytes()
    _need(_sha(questions) == evidence.get('questions_sha256'), 'receiver_public_questions_hash_mismatch')
    _need(_sha(answers_raw) == evidence.get('answers_sha256'), 'receiver_answer_artifact_hash_mismatch')
    if evidence.get('answers_schema_valid') is True:
        _need(json.loads(answers_raw) == record['answers'], 'receiver_answer_map_changed')
    else:
        _need(record['answers'] == {}, 'failed_answer_schema_must_keep_empty_scoring_map')
    if evidence.get('execution_mode') == 'controller_readback_native_paid_one_shot':
        from . import receiver_paid_runtime as paid
        child = job_dir/'native_paid_one_shot'
        envelope_path = _path(root, evidence['native_paid_envelope_path'])
        input_path = _path(root, evidence['native_paid_job_path'])
        _need(envelope_path == child/'envelope.json' and input_path == child/'job.json',
              'paid_native_receiver_job_paths_mismatch')
        _need(_sha(envelope_path.read_bytes()) == evidence['native_paid_envelope_sha256']
              and _sha(input_path.read_bytes()) == evidence['native_paid_job_sha256'],
              'paid_native_receiver_artifact_hash_mismatch')
        envelope, job = _load(envelope_path), _load(input_path)
        _need(envelope == evidence['native_paid_envelope'], 'paid_native_outer_envelope_changed')
        qualification = paid._qualification(_path(root, evidence['qualification']['path']))
        output = paid.verify_paid_envelope(envelope, job, input_path.read_bytes(), qualification)
        paid.verify_paid_history_prefix(envelope, job)
        _need(output.encode('utf-8') == answers_raw
              and job['businessInput'] == {'memory': payload['memory'], 'questions': questions}
              and job['instruction'] == paid.ANSWER_INSTRUCTIONS
              and job['softOutputCharacters'] == 4096,
              'paid_native_receiver_not_bound_to_reopened_memory_and_questions')
        process = _load(_path(root, job_dir/'paid_reader_process.json'))
        _need(process.get('returncode') == 0 and process.get('process_boundary') == 'fresh_python_process'
              and process.get('argv') == paid._reader_command(database, delivery['batch_id'], job_dir/'retrieved_memory.json'),
              'paid_native_receiver_reader_subprocess_evidence_invalid')
    identity = _identity(evidence, record['receiver_platform'], answers_raw, source=False)
    packet_path = _path(root, delivery['packet_path'])
    packet_bytes = packet_path.stat().st_size
    if 'packet_file_sha256' in delivery:
        _need(_sha(packet_path.read_bytes()) == delivery['packet_file_sha256'], 'transport_packet_file_hash_mismatch')
    content_bytes = len(payload['memory'].encode('utf-8'))
    for key, actual in (('packet_bytes', packet_bytes), ('content_bytes', content_bytes)):
        if key in delivery:
            _need(delivery[key] == actual, 'delivery_byte_count_mismatch:' + key)
    augmented = deepcopy(record)
    augmented['received_memory'] = payload['memory']
    augmented['delivery'].update(packet_bytes=packet_bytes, content_bytes=content_bytes)
    return augmented, {
        'kind': 'receiver', 'case_id': record['case_id'], 'direction': record['direction'], 'arm': record['arm'],
        'job_dir': str(job_dir), 'platform': record['receiver_platform'],
        'receipt_stable_fields_rechecked': True, 'original_dependencies_currently_authorized': True,
        'complete_original_dependency_count': len(_refs(actual_refs)),
        'rendered_memory_sha256': receipt['rendered_memory_sha256'],
        'packet_bytes': packet_bytes, 'output_memory_bytes': content_bytes,
        'delivery_ms': delivery.get('export_import_reopen_ms'), 'wall_ms': None,
        'questions': questions, 'identity': identity,
        'execution_mode': evidence.get('execution_mode', 'legacy_receiver_runtime'),
        'remote_provider_input_attestation': False,
    }


def _receiver_recovery(root, record, original_record, evaluation, manifest):
    """Pure verification of one authorized no-output provider-500 recovery."""
    base = _path(root, original_record['job_dir'])
    if 'effective_receiver_job_dir' not in record:
        _need('receiver_recovery_receipt_path' not in record and 'receiver_attempts' not in record,
              'partial_receiver_recovery_metadata_forbidden')
        return base, None, None
    from . import receiver_recovery as recovery
    retry = _path(root, record['effective_receiver_job_dir'])
    _need(retry == base/'provider_retry_01' and record['receiver_platform'] == 'hy3',
          'receiver_recovery_effective_directory_changed')
    receipt_path = _path(root, record['receiver_recovery_receipt_path'])
    receipt = _load(receipt_path)
    schema = receipt.get('schema')
    offline = schema == 'receiver-provider-recovery-offline-adoption-v1'
    _need(schema in {'receiver-provider-temporary-recovery-v1', 'receiver-provider-recovery-offline-adoption-v1'}
          and receipt.get('recovery_number') == 1
          and receipt.get('automatic_retry') is False and receipt.get('further_retry_authorized') is False
          and receipt.get('original_progress_overwritten') is False and receipt.get('original_inputs_modified') is False,
          'receiver_recovery_receipt_scope_invalid')
    _need(receipt_path == base/('receiver_recovery_offline_receipt.json' if offline else 'receiver_recovery_receipt.json'),
          'receiver_recovery_receipt_path_changed')
    original = recovery._original(root, original_record, evaluation)
    old_envelope = _load(base/'native_paid_one_shot/envelope.json')
    old_native = old_envelope.get('nativeExecution') or {}
    old_after = old_native.get('after') or {}
    errors = old_envelope.get('providerErrors') or []
    _need(not (base/'answers.json').exists() and not (base/'receiver_paid_verified.json').exists()
          and old_envelope.get('output') == '' and old_envelope.get('assistantCompletedMessages') == 0
          and any(error.get('code') == 11134 and error.get('httpStatus') == 500 for error in errors)
          and not any(error.get('httpStatus') == 429 or error.get('code') in (6004, 6020) for error in errors)
          and old_native.get('modelPromptsSubmitted') == 1 and old_native.get('status') == 'native_prompt_returned'
          and old_native.get('stopReason') in ('error', 'refusal') and old_after.get('status') == 'completed'
          and old_after.get('isProcessing') is False and old_after.get('model') == 'hy3-x',
          'receiver_recovery_requires_terminal_no_output_provider_500')
    new_bindings, schema_valid = recovery._new_proof(root, original, retry, record['answers'], record['receiver_evidence'])
    _need(receipt.get('original_bindings') == original['bindings']
          and receipt.get('new_verified_bindings') == new_bindings
          and receipt.get('delivery_sha256') == _sha(record['delivery'])
          and receipt.get('memory_sha256') == original['memory_sha256']
          and receipt.get('questions_sha256') == original['questions_sha256']
          and receipt.get('business_input_sha256') == original['business_input_sha256']
          and receipt.get('logical_snapshot_sha256') == original['logical_snapshot_sha256']
          and receipt.get('scored_input_sha256') == _sha(canonical(record)+b'\n')
          and _load(base/'scored_input.json') == record,
          'receiver_recovery_original_new_or_score_binding_changed')
    plan = _load(root/'receiver_recovery_plan.json')
    progress_file = root/'receiver_progress.first_pass.json'
    if not progress_file.exists():
        progress_file = root/'receiver_progress.json'
    progress = _load(progress_file)
    _need(plan.get('manifest_sha256') == _sha((root/'manifest.json').read_bytes())
          and plan.get('original_progress_sha256') == _sha(progress_file.read_bytes())
          and plan.get('evaluation_sha256') == _sha((HERE/'data/evaluation_only.json').read_bytes())
          and progress.get('planned') == len(manifest['main_records'])
          and progress.get('finished', 0)+progress.get('failed', 0) == len(manifest['main_records'])
          and any(item.get('cell_dir') == str(base) and item.get('bindings') == original['bindings']
                  for item in plan.get('candidates', [])), 'receiver_recovery_first_pass_plan_changed')
    first = recovery._attempt(base, 0)
    second = recovery._attempt(retry, 1, qualified=True, schema_valid=schema_valid)
    _need(_load(base/'original_receiver_failed_cost.json') == first,
          'receiver_recovery_original_failed_cost_changed')
    if offline:
        from .receiver_recovery_offline import _recheck
        recheck_path, _ = _recheck(root, original, retry, _load(retry/'receiver_paid_verified.json'))
        old_cost_path = retry/'receiver_attempt_cost.json'
        old_cost = recovery._attempt(retry, 1)
        failure_path = base/'receiver_recovery_failure.json'
        failure = _load(failure_path)
        _need(_load(old_cost_path) == old_cost and failure.get('receiver_attempts') == [first, old_cost]
              and failure.get('original_bindings') == original['bindings'],
              'receiver_recovery_old_failure_or_attempt_cost_changed')
        second.update(reclassificationOnly=True, newModelPromptsSubmitted=0,
            newNativeSessionsCreated=0, nativeChannelsCalled=[], original_attempt_cost_path=str(old_cost_path),
            original_attempt_cost_sha256=_sha(old_cost_path.read_bytes()),
            offline_recheck_receipt_path=str(recheck_path), offline_recheck_receipt_sha256=_sha(recheck_path.read_bytes()))
        cost_path = retry/'receiver_attempt_rechecked_cost.json'
        _need(_load(cost_path) == second
              and receipt.get('offline_recheck_receipt_sha256') == _sha(recheck_path.read_bytes())
              and receipt.get('original_failure_sha256') == _sha(failure_path.read_bytes())
              and receipt.get('old_attempt_cost_sha256') == _sha(old_cost_path.read_bytes())
              and receipt.get('rechecked_attempt_cost_sha256') == _sha(cost_path.read_bytes())
              and receipt.get('first_pass_progress_sha256') == _sha(progress_file.read_bytes())
              and receipt.get('newNativeChannels') == [] and receipt.get('newModelPromptsSubmitted') == 0
              and receipt.get('newNativeSessionsCreated') == 0 and receipt.get('reclassificationOnly') is True,
              'receiver_offline_adoption_binding_changed')
    else:
        _need(_load(retry/'receiver_attempt_cost.json') == second,
              'receiver_recovery_new_attempt_cost_changed')
    _need(record.get('receiver_attempts') == [first, second] and receipt.get('receiver_attempts') == [first, second],
          'receiver_recovery_attempts_not_exact_original_plus_one')
    failed_row = {'kind': 'receiver', 'case_id': record['case_id'], 'direction': record['direction'], 'arm': record['arm'],
        'platform': 'hy3', 'job_dir': str(base), 'receiver_attempt_outcome': 'terminal_no_output_provider_11134_HTTP500',
        'output_memory_bytes': len(original['memory'].encode('utf-8')), 'wall_ms': None,
        'identity': {'platform': 'hy3', 'native_session_id': first['native_session_id'],
            'native_task_id': first['native_task_id'], 'native_tasks': 0, 'native_queue_submissions': 0,
            'native_direct_session_submissions': 1, 'provider_identity_verified': False,
            'actual_models': first['actual_models'], 'request_model_ids': first['request_model_ids'],
            'billing_route_ids': first['request_model_ids'], 'canonical_model_family': 'Hy3',
            'physical_supplier_calls': None, 'supplier_fee_cny': None, 'token_usage': None,
            'estimated_cold_peak_cny': None, 'estimated_cache_aware_peak_cny': None,
            'input_receipt_scope': 'original terminal provider-500 native attempt; no complete answer; supplier requests and cost unknown'}}
    return retry, failed_row, {'receipt_file': str(receipt_path), 'receipt_sha256': _sha(receipt_path.read_bytes()),
        'schema': schema, 'original_job_dir': str(base), 'effective_job_dir': str(retry),
        'attempts': [first, second], 'original_failure_counted_once': True,
        'offline_recheck_counted_as_new_attempt': False}


def _aggregate(rows):
    flash = [row['identity'] for row in rows if row['platform'] == 'flash']
    qualified_flash = [row for row in flash if row['token_usage'] is not None]
    tokens = {key: sum(row['token_usage'][key] for row in qualified_flash) for key in
              ('input_total_tokens', 'input_uncached_tokens', 'cache_read_tokens', 'cache_write_tokens', 'output_tokens', 'total_tokens')}

    def known_sum(key, subset=rows):
        values = [row.get(key) for row in subset]
        return sum(values) if all(value is not None for value in values) else None

    cached_values = [row['estimated_cache_aware_peak_cny'] for row in flash]
    source_rows = [row for row in rows if row['kind'] == 'source']
    native_tasks = sum(row['identity']['native_tasks'] for row in rows if row['platform'] == 'hy3')
    queue_submissions = sum(row['identity'].get('native_queue_submissions', row['identity']['native_tasks'])
                            for row in rows if row['platform'] == 'hy3')
    qualified_queue_tasks = sum(row['identity']['native_tasks'] for row in rows if row['platform'] == 'hy3'
                                and row['identity'].get('native_queue_submissions', row['identity']['native_tasks']))
    direct_sessions = sum(row['identity'].get('native_direct_session_submissions', 0) for row in rows if row['platform'] == 'hy3')
    supplemental_turns = sum(row['identity'].get('native_existing_session_continuation_turns', 0) for row in rows if row['platform'] == 'hy3')
    flash_known_calls = sum(row['physical_supplier_calls'] for row in flash if row['physical_supplier_calls'] is not None)
    known_submissions = [(None if (row['identity'].get('native_queue_submissions', 0) or row['identity'].get('native_direct_session_submissions', 0))
                          and not row['identity'].get('provider_identity_verified', True)
                          else row['identity']['native_tasks']) if row['platform'] == 'hy3'
                         else row['identity']['physical_supplier_calls'] for row in rows]
    cold_values = [row['estimated_cold_peak_cny'] for row in flash]
    return {
        'artifact_count': len(rows), 'source_jobs': sum(row['kind'] == 'source' for row in rows),
        'logical_source_attempts': len(source_rows),
        'source_attempt_outcomes': dict(Counter(row['source_attempt_status'] for row in source_rows)),
        'successful_source_memory_jobs': sum(row['source_attempt_status'] == 'success' for row in source_rows),
        'receiver_jobs': sum(row['kind'] == 'receiver' for row in rows),
        'platform_jobs': dict(Counter(row['platform'] for row in rows)),
        'source_phase_jobs': dict(Counter(row.get('phase') or 'mechanism_source' for row in rows if row['kind'] == 'source')),
        'source_protocol_failed_jobs': sum(row.get('source_protocol_conformance') is False for row in rows if row['kind'] == 'source'),
        'native_source_shell_scope_failed_jobs': sum((row.get('native_source_shell_scope_audit') or {}).get('protocol_conformance') is False for row in source_rows),
        'hy3_native_tasks': native_tasks,
        'hy3_native_tasks_scope': 'qualified native HY3 executions only; excludes zero-prompt creation failures and blocked queue submissions without provider identity',
        'hy3_native_queue_submissions': queue_submissions,
        'hy3_native_direct_session_submissions': direct_sessions,
        'supplemental_existing_session_continuation_turns': supplemental_turns,
        'supplemental_continuation_input_volume_unknown_turns': supplemental_turns,
        'hy3_queue_submission_without_verified_model_execution': queue_submissions - qualified_queue_tasks,
        'hy3_pre_model_zero_submission_source_attempts': sum(row['source_attempt_status'] == 'pre_model_creation_closed' for row in source_rows),
        'known_model_calls_or_native_task_submissions': sum(value for value in known_submissions if value is not None),
        'model_submission_count_unknown_attempts': sum(value is None for value in known_submissions),
        'flash_physical_supplier_calls': flash_known_calls if all(row['physical_supplier_calls'] is not None for row in flash) else None,
        'flash_known_physical_supplier_calls': flash_known_calls,
        'flash_physical_request_count_unknown_attempts': sum(row['physical_supplier_calls'] is None for row in flash),
        'hy3_physical_supplier_calls': None if queue_submissions or native_tasks or direct_sessions or supplemental_turns else 0,
        'all_platform_physical_supplier_calls': None,
        'workbuddy_supplier_fee_cny': None, 'all_platform_supplier_fee_cny': None,
        'flash_native_tokens': tokens,
        'flash_native_tokens_scope': 'sum over qualified usage only; see unknown-usage count',
        'flash_usage_unknown_attempts': len(flash) - len(qualified_flash),
        'flash_estimated_cold_peak_cny_observed': str(sum((Decimal(value) for value in cold_values if value is not None), Decimal(0))),
        'flash_estimated_cold_peak_cny': (str(sum((Decimal(value) for value in cold_values), Decimal(0)))
                                           if all(value is not None for value in cold_values) else None),
        'flash_estimated_cache_aware_peak_cny': (str(sum((Decimal(value) for value in cached_values), Decimal(0)))
                                                if all(value is not None for value in cached_values) else None),
        'flash_estimates_are_supplier_bill': False,
        'original_input_source_count': sum(row.get('original_input_source_count', 0) for row in rows),
        'original_input_characters': sum(row.get('original_input_characters', 0) for row in rows),
        'parent_input_characters': sum(row.get('parent_input_characters', 0) for row in rows),
        'serialized_source_business_input_bytes': sum(row.get('serialized_business_input_bytes', 0) for row in rows),
        'source_output_memory_bytes': sum(row['output_memory_bytes'] for row in rows if row['kind'] == 'source'),
        'source_observed_partial_output_bytes_not_usable_memory': sum(row.get('observed_partial_output_bytes_not_memory', 0) for row in source_rows),
        'receiver_presented_memory_bytes': sum(row['output_memory_bytes'] for row in rows if row['kind'] == 'receiver'),
        'sum_source_job_wall_ms': known_sum('wall_ms', [row for row in rows if row['kind'] == 'source']),
        'source_wall_sum_is_parallel_elapsed_time': False,
        'receiver_wall_ms': None,
    }


def _clean_comparison(scored, audit_rows, logical_views):
    """Same clean case/direction pairs for all arms; no missing-view imputation."""
    audit_index = {(row['case_id'], row['direction'], row['arm']): row for row in audit_rows}
    pairs = sorted({(row['case_id'], row['direction']) for row in audit_rows})
    clean = [(case, direction) for case, direction in pairs if all(
        audit_index[(case, direction, arm)]['source_protocol_clean'] for arm in ARMS)]
    retained = set(clean)
    metrics = ('legal_utility', 'answer_completion_rate', 'content_bytes', 'packet_bytes',
               'logical_source_jobs', 'delivery_ms', 'source_supplied_original_characters', 'source_supplied_original_count')
    records = deepcopy(scored['per_record'])
    view_index = {(row['case_id'], row['direction'], row['arm']): row['resources'] for row in logical_views}
    for record in records:
        resources = view_index[(record['case_id'], record['direction'], record['arm'])]
        record['source_supplied_original_characters'] = resources['original_input_characters']
        record['source_supplied_original_count'] = resources['original_input_source_count']
    projects = sorted({case for case, _ in clean})
    per_project = []
    for case in projects:
        for arm in ARMS:
            rows = [row for row in records if row['case_id'] == case and row['arm'] == arm
                    and (case, row['direction']) in retained]
            per_project.append({'case_id': case, 'arm': arm, 'retained_directions': len(rows),
                                **{metric: _mean([row[metric] for row in rows])
                                   if all(row[metric] is not None for row in rows) else None for metric in metrics}})
    index = {(row['case_id'], row['arm']): row for row in per_project}
    contrasts = {}
    for reference in ('raw', 'full_rebuild'):
        contrasts['selective_vs_' + reference] = {}
        for metric in metrics:
            observations = [(index[(case, 'selective')][metric], index[(case, reference)][metric]) for case in projects]
            observations = [pair for pair in observations if all(value is not None for value in pair)]
            resource = metric not in ('legal_utility', 'answer_completion_rate')
            result = _bootstrap(observations, _reduction if resource else _difference, 5000, BOOTSTRAP_SEED)
            result['estimand'] = 'relative_reduction_of_project_means' if resource else 'mean_paired_project_difference'
            result['complete_retained_projects'] = len(observations) == len(projects)
            contrasts['selective_vs_' + reference][metric] = result
    return {'scope': 'supplementary comparison on case/direction pairs whose actually selected artifacts are source-protocol clean in all four arms; main 96 views remain unchanged',
            'selection_uses_receiver_answers': False, 'quality_or_resource_winner_selected': False,
            'paired_case_directions': [list(pair) for pair in clean], 'paired_direction_count': len(clean),
            'independent_project_clusters': len(projects), 'project_ids': projects,
            'excluded_case_directions': [list(pair) for pair in pairs if pair not in retained],
            'per_project': per_project, 'contrasts': contrasts,
            'weighting': 'same retained directions averaged within each project; projects weighted equally; paired project bootstrap',
            'complete_model_time_or_total_supplier_cost_comparison_available': False,
            'main_views_excluded_from_primary_analysis': 0}


def _no_identity_reuse(rows):
    identities = []
    for row in rows:
        ident = row['identity']
        if row['platform'] == 'hy3' and (ident['native_tasks'] or ident.get('native_queue_submissions', 0) or ident.get('native_direct_session_submissions', 0)):
            identities.append(('hy3', ident['native_session_id']))
        elif row['platform'] == 'flash' and ident['request_identity'] is not None:
            identities.append(('flash', *ident['request_identity']))
    _need(len(set(identities)) == len(identities), 'physical_native_job_identity_reused_across_artifacts')


def _require_resolved_provider_quota(root, source_paths, effective_paths=None):
    """A known unavailable provider view is missing data, not algorithm zero."""
    for path in source_paths:
        marker = _path(root, path.parent / 'provider_quota_evidence.json')
        if not marker.is_file():
            continue
        quota = _load(marker)
        known_quota = str(quota.get('error_code', quota.get('code', ''))) in {'6004', '6020'} or str(quota.get('http_status', '')) == '429'
        selected = (effective_paths or {}).get(path, path)
        if known_quota and (not selected.is_file() or _load(selected).get('memory') is None):
            raise FinalizeError('unresolved_source_provider_quota_not_algorithm_zero')


def _source_registry_maps(root, planned):
    from .source_registry_audit import (resolve_source_result_for_audit,
        source_attempt_paths_for_audit, late_source_continuation_for_audit)
    attempts, effective, late = {}, {}, {}
    for canonical_path in planned:
        cell = canonical_path.parent
        attempts[canonical_path] = [_path(root, path) for path in source_attempt_paths_for_audit(cell)]
        effective[canonical_path] = _path(root, resolve_source_result_for_audit(cell))
        _need(attempts[canonical_path][0] == canonical_path and effective[canonical_path] in attempts[canonical_path],
              'source_registry_attempt_or_effective_path_changed')
        extra = late_source_continuation_for_audit(cell)
        if extra is not None:
            late[canonical_path] = extra
    return attempts, effective, late


def _late_source_row(canonical_path, metadata):
    _need(metadata.get('late_artifact_adopted_for_study') is False
          and metadata.get('registered_replacement_selection_changed') is False
          and metadata.get('native_additional_continuation_turns') == 1,
          'late_source_output_cannot_change_study_selection')
    routes = _hy3_routes({'actual_models': metadata['actual_models'],
                          'request_model_ids': metadata['request_model_ids']})
    return {'kind': 'late_source_continuation', 'platform': 'hy3',
            'logical_source_cell': str(canonical_path.parent), 'late_source_event': metadata,
            'output_memory_bytes': None, 'wall_ms': None,
            'identity': {'platform': 'hy3', **routes,
                'native_session_id': metadata['original_session_id'],
                'native_task_id': metadata['original_task_id'], 'native_tasks': 0,
                'native_queue_submissions': 0, 'native_direct_session_submissions': 0,
                'native_existing_session_continuation_turns': 1,
                'registered_continuation_event_sha256': metadata['event_sha256'],
                'provider_identity_verified': True, 'physical_supplier_calls': None,
                'supplier_fee_cny': None, 'token_usage': None,
                'estimated_cold_peak_cny': None, 'estimated_cache_aware_peak_cny': None,
                'input_receipt_scope': 'separately audited late continuation; its body is quarantined and not used for study answers or selection'}}


def finalize(root):
    """Audit complete real artifacts, write two reports, and return the ledger.

    Raises FinalizeError on failed integrity checks. Does not infer, repair
    answers, read private SDK data, retry jobs, or modify any database content.
    """
    root = _resolved(root)
    _need(root.is_dir(), 'existing_result_root_required')
    manifest = _load(_path(root, root / 'manifest.json'))
    _need(_resolved(manifest['root']) == root, 'manifest_root_mismatch')
    records = _load(_path(root, root / 'main_records.json'))
    contract = _load(HERE / 'data/contract.json')
    for name, expected_hash in contract['artifact_sha256'].items():
        _need(_sha((HERE / 'data' / name).read_bytes()) == expected_hash, 'frozen_data_hash_changed:' + name)
    evaluation = _load(HERE / 'data/evaluation_only.json')
    cases = [json.loads(line) for line in (HERE / 'data/cases.public.jsonl').read_text(encoding='utf-8').splitlines()]
    case_index = {case['case_id']: case for case in cases}
    expected = _planned_jobs(root, cases)
    attempt_paths, effective_paths, late_metadata = _source_registry_maps(root, expected)
    _require_resolved_provider_quota(root, expected, effective_paths)
    expected_attempts = {attempt: (canonical_path, specification) for canonical_path, specification in expected.items()
                         for attempt in attempt_paths[canonical_path]}
    recorded_paths = [_path(root, path) for path in manifest['source_physical_results']]
    _need(len(set(recorded_paths)) == len(recorded_paths) and set(recorded_paths) == set(expected_attempts),
          'physical_source_manifest_does_not_match_frozen_plan')
    # This fixed-depth glob cannot enter sdk.private/home.private.
    discovered = {_resolved(path) for path in (root / 'source_jobs').glob('*/*/*/*/result.json')}
    discovered.update(_resolved(path) for path in (root/'source_jobs').glob('*/*/*/*/quota_recovery_*/result.json'))
    _need(discovered == set(expected_attempts), 'unexpected_or_missing_outer_source_result')
    physical_results, source_rows = {}, {}
    for path in sorted(expected_attempts):
        canonical_path, specification = expected_attempts[path]
        physical_results[path], source_rows[path] = _source(root, path, specification,
            late_audit=late_metadata.get(canonical_path) if path == canonical_path else None)
        source_rows[path].update(logical_source_cell=str(canonical_path.parent),
                                 effective_for_study=path == effective_paths[canonical_path])
    results = {path: physical_results[effective_paths[path]] for path in expected}
    late_rows = {str(path.parent): _late_source_row(path, metadata) for path, metadata in late_metadata.items()}
    manifest_index = {(row['case_id'], row['direction'], row['arm']): row for row in manifest['main_records']}
    _need(len(manifest_index) == len(manifest['main_records']), 'duplicate_main_manifest_record')
    _need(len(records) == len(manifest_index), 'completed_main_records_count_mismatch')
    augmented, receiver_rows, logical = [], [], {arm: [] for arm in ARMS}
    failed_receiver_rows, receiver_recoveries = [], []
    logical_views = []
    for record in records:
        key = (record['case_id'], record['direction'], record['arm'])
        _need(key in manifest_index, 'completed_record_not_in_manifest')
        planned_record = manifest_index[key]
        for field, value in planned_record.items():
            _need(record.get(field) == value, 'completed_record_manifest_field_changed:' + field)
        case = case_index[record['case_id']]
        memory, deps, paths, source_protocol = _selected(root, case, record['direction'], record['arm'], results,
            include_protocol=True, effective_paths=effective_paths, attempt_paths=attempt_paths)
        _need(record['delivery'].get('source_protocol_clean', True) == source_protocol['source_protocol_clean']
              and record['delivery'].get('source_protocol_rejected_memory_keys', []) == source_protocol['source_protocol_rejected_memory_keys'],
              'source_protocol_delivery_filter_declaration_mismatch')
        _need(not set(record['delivery']['memory_keys']) & set(source_protocol['source_protocol_rejected_memory_keys']),
              'failed_source_protocol_memory_was_exported')
        supplied_paths = [_path(root, path) for path in record['source_jobs']]
        _need(supplied_paths == paths, 'logical_method_job_references_not_frozen_plan')
        allowed = evaluation[record['case_id']][record['direction']]['event']['allowed']
        effective_receiver, failed_receiver, recovery_audit = _receiver_recovery(root, record, planned_record, evaluation, manifest)
        completed, audit = _receiver(root, record, allowed, expected_memory=memory, expected_refs=deps,
                                      effective_job_dir=effective_receiver)
        _need(audit['questions'] == receiver_questions(evaluation, record['case_id'], record['direction']),
              'receiver_public_questions_not_frozen_projection')
        audit.pop('questions')
        audit.update(source_protocol)
        augmented.append(completed)
        receiver_rows.append(audit)
        if failed_receiver is not None:
            failed_receiver_rows.append(failed_receiver)
            receiver_recoveries.append(recovery_audit)
        extra_cells = sorted({source_rows[path]['logical_source_cell'] for path in paths} & set(late_rows))
        view_jobs = ([source_rows[path] for path in paths] + [late_rows[cell] for cell in extra_cells]
                     + ([failed_receiver] if failed_receiver is not None else []) + [audit])
        logical[record['arm']].extend(view_jobs)
        logical_views.append({'case_id': record['case_id'], 'direction': record['direction'],
                              'arm': record['arm'], 'resources': _aggregate(view_jobs)})
    main_rows = list(source_rows.values()) + failed_receiver_rows + receiver_rows
    _no_identity_reuse(main_rows)
    scored = evaluate(augmented, evaluation)
    clean_comparison = _clean_comparison(scored, receiver_rows, logical_views)
    scored['source_protocol_clean_supplement'] = clean_comparison
    mechanisms = {'status': 'not_run', 'excluded_from_main': True}
    mechanism_file = _path(root, root / 'mechanisms/records.json')
    mechanism_rows = []
    if mechanism_file.exists():
        mechanism_records = _load(mechanism_file)
        _need({record['mechanism_id'] for record in mechanism_records} == set(evaluation['_mechanisms'])
              and len(mechanism_records) == len(evaluation['_mechanisms']), 'mechanism_records_incomplete_or_duplicate')
        probe_results = []
        specs = {spec['mechanism_id']: spec for spec in _load(HERE / 'data/mechanism_spec.json')['mechanisms']}
        all_originals = {source['source_id']: source for case in cases for agent in ('A', 'B') for source in case['agents'][agent]['sources']}
        for record in mechanism_records:
            mid = record['mechanism_id']
            spec = specs[mid]
            _need(record['case_id'] == spec['case_id'] and record['direction'] == 'B_to_A'
                  and record['receiver_platform'] == 'hy3', 'mechanism_case_or_model_assignment_changed')
            case = case_index[record['case_id']]
            marker = _load(_path(root, root / 'mechanisms' / mid / 'withdrawal.json'))
            own_A = [source['source_id'] for source in case['agents']['A']['sources']]
            _need(set(marker['allowed']) == set(own_A + spec['child_rebuild_inputs'][1:])
                  and set(marker['revoked']) == set(spec['withdraw_before_first_return'])
                  and marker['epoch'] == record['delivery']['policy_epoch'],
                  'mechanism_withdrawal_not_frozen_schedule')
            parent_record = next(main for main in augmented if main['case_id'] == record['case_id']
                                 and main['direction'] == 'A_to_B' and main['arm'] == 'full_rebuild')
            parent_input = [{'memory_key': parent_record['delivery']['memory_keys'][0],
                             'content': parent_record['received_memory']}]
            expected_paths = [root / 'mechanisms' / mid / 'source_jobs' / phase / 'result.json'
                              for phase in ('initial', 'rebuild')]
            _need([_path(root, path) for path in record['source_jobs']] == expected_paths,
                  'mechanism_source_job_refs_changed')
            source_results = []
            for index, path in enumerate(expected_paths):
                result, source_audit = _source(root, path)
                supplied = _load(_path(root, path.parent / 'sources.json'))
                source_ids = spec['child_inputs'][1:] if index == 0 else spec['child_rebuild_inputs'][1:]
                _need(result['platform'] == 'flash' and result['source_ids'] == source_ids
                      and supplied['sources'] == [all_originals[sid] for sid in source_ids]
                      and supplied['parent_memories'] == parent_input,
                      'mechanism_actual_inputs_not_frozen_sources_and_real_imported_parent')
                source_results.append(result)
                mechanism_rows.append(source_audit)
            legal_B = [all_originals[sid] for sid in spec['child_rebuild_inputs'][1:]]
            closure = parent_record['delivery']['dependencies'] + _original_refs(legal_B, 'B')
            actual, audit = _receiver(root, record, marker['allowed'],
                                      expected_memory=source_results[1]['memory'], expected_refs=closure)
            refs = evaluation['_mechanisms'][mid]['questions']
            _need(audit.pop('questions') == [{'question_id': q['question_id'], 'question': q['question']} for q in refs],
                  'mechanism_public_questions_not_frozen_projection')
            mechanism_rows.append(audit)
            checks = record['mechanism_evidence']
            initial_B = [all_originals[sid] for sid in spec['child_inputs'][1:]]
            _need(_refs(checks['old_child_dependencies']) == _refs(parent_record['delivery']['dependencies'] + _original_refs(initial_B, 'B'))
                  and _refs(checks['new_child_dependencies']) == _refs(closure),
                  'mechanism_flattened_parent_closure_mismatch')
            _need(checks['old_child_rejections']['export_blocked'] and checks['old_child_rejections']['import_blocked']
                  and checks['old_child_rejections']['no_partial_receiver_writes']
                  and checks['fresh_A_own_originals_only'] and checks['main_database_sha256_unchanged'],
                  'mechanism_gate_or_fresh_store_evidence_failed')
            probe_results.append({'mechanism_id': mid, 'legal_value_coverage': [
                all(value_present(value, actual['answers'].get(q['question_id'])) for value in q['required_values'])
                for q in refs if q['primary_eligible']],
                'unique_withheld_unknown': [is_unknown(actual['answers'].get(q['question_id'])) for q in refs
                                            if q['unique_value_abstention_provable_in_fixture']],
                'payload_surface_leaked_values': sum(value_present(value, actual['received_memory']) for q in refs
                    if q['unique_value_abstention_provable_in_fixture'] for value in q['required_values']),
                'old_child_export_and_import_blocked': True})
        _no_identity_reuse(main_rows + mechanism_rows)
        mechanisms = {'status': 'audited', 'excluded_from_main': True,
                      'probe_results': probe_results, 'physical_ledger': _aggregate(mechanism_rows), 'jobs': mechanism_rows}
    summary = {'schema': 'persistent-exchange-final-audit-ledger-v1', 'status': 'audited',
               'root': str(root), 'main_physical_ledger': _aggregate(main_rows),
               'study_boundaries': {
                   'initial_source_memory_timeline': 'actual source model text is first persisted in memory.json/result.json files; derived memories are registered in sender SQLite during deliver, after withdrawal/repair',
                   'initial_derived_sqlite_record_predates_withdrawal': False,
                   'source_input_route': 'controller projects frozen fixture originals into sources.json; owner SQLite stores the same originals and provenance binds IDs, versions and content hashes; source models read the projected file rather than retrieving originals with SQL',
                   'source_model_direct_sql_retrieval': False,
                   'receiver_input_route': 'experiment-owned receiver SQLite import is closed/reopened; Flash and paid zero-tool HY3 use controller-launched fresh Python read-only batch retrieval, while legacy HY3 evidence uses its native reader tool; record.execution_mode distinguishes these boundaries',
                   'withdrawal_boundary': 'after source text generation and file persistence, before first destination import/commit; does not establish that an initial derived SQLite row existed before withdrawal',
                   'product_memory_scope': 'explicit experiment-owned SQLite stores and exported text; no claim to migrate or erase private built-in WorkBuddy/Harness product memory',
                   'vendor_builtin_memory_migration_demonstrated': False,
                   'workbuddy_complete_remote_request_attestation': False,
                   'native_input_audit_scope': 'outer artifacts, explicit Read/Write/reader-tool evidence and available command-footprint audits; provider hidden prompts, opaque runtime context and complete remote request bytes are not attested',
                   'earlier_plaintext_disclosure_erasure_demonstrated': False},
               'main_logical_per_method_ledger': {arm: _aggregate(rows) for arm, rows in logical.items()},
               'main_logical_per_direction_method_views': logical_views,
               'source_recovery_registry': {'logical_source_cells': len(expected),
                    'physical_source_result_attempts': len(source_rows),
                    'registered_effective_recoveries': sum(path != effective_paths[path] for path in expected),
                    'effective_source_result_paths': {str(path): str(effective_paths[path]) for path in expected},
                    'late_continuation_events_separate_from_source_result_count': len(late_rows),
                    'late_output_used_for_quality_or_selection': False},
               'main_jobs': main_rows, 'mechanisms': mechanisms,
               'receiver_recovery_audit': {'adopted_recoveries': len(receiver_recoveries),
                    'original_failed_attempts_counted_separately': len(failed_receiver_rows),
                    'qualified_receiver_views': len(receiver_rows),
                    'physical_receiver_attempts': len(receiver_rows)+len(failed_receiver_rows),
                    'offline_recheck_new_model_prompts': 0, 'recoveries': receiver_recoveries},
               'supplemental_native_continuations': list(late_metadata.values()),
               'supplemental_native_continuation_ledger': _aggregate(list(late_rows.values())),
               'all_observed_activity_ledger': _aggregate(main_rows+list(late_rows.values())),
               'source_protocol_audit': {
                   'source_attempt_outcomes': dict(Counter(row['source_attempt_status'] for row in source_rows.values())),
                   'successful_approved_source_memory_count': sum(row['source_attempt_status'] == 'success' for row in source_rows.values()),
                   'closed_failed_source_attempt_count': sum(row['source_attempt_status'] != 'success' for row in source_rows.values()),
                   'bound_native_shell_scope_audits': sum(row['native_source_shell_scope_audit'] is not None for row in source_rows.values()),
                   'bound_native_shell_scope_failures': sum((row['native_source_shell_scope_audit'] or {}).get('protocol_conformance') is False for row in source_rows.values()),
                   'failed_physical_source_job_count': sum(row['source_attempt_status'] != 'success'
                       and (row['identity']['native_tasks'] if row['platform'] == 'hy3' else row['identity']['physical_supplier_calls']) == 1
                       for row in source_rows.values()),
                   'closed_failed_source_attempt_files': [str(path) for path, row in source_rows.items() if row['source_attempt_status'] != 'success'],
                   'failed_physical_source_job_files': [str(path) for path, row in source_rows.items() if row['source_attempt_status'] != 'success'
                       and (row['identity']['native_tasks'] if row['platform'] == 'hy3' else row['identity']['physical_supplier_calls']) == 1],
                   'arm_views_with_selected_source_protocol_rejections': sum(not row['source_protocol_clean'] for row in receiver_rows),
                   'arm_view_rejections_by_arm': {arm: sum(not row['source_protocol_clean'] for row in receiver_rows if row['arm'] == arm) for arm in ARMS},
                   'failed_selected_artifacts_filtered_before_export': True,
                   'retained_in_physical_and_logical_resource_ledgers': True,
                   'no_sample_replacement_or_new_generation_for_protocol_failure': True,
                   'main_record_count_retained': len(augmented)},
               'model_identity_scope': {
                   'hy3_verified_native_executions': sum(row['identity']['native_tasks'] for row in main_rows if row['platform'] == 'hy3'),
                   'hy3_native_queue_submissions': sum(row['identity'].get('native_queue_submissions', row['identity']['native_tasks'])
                                                       for row in main_rows if row['platform'] == 'hy3'),
                   'hy3_submitted_identity_rule': 'nonempty actual/request model ID arrays must contain only official hy3 or hy3-x; canonical family Hy3 is separate, original IDs are retained including mixed free/paid histories; zero-prompt and unidentified queue cases are separate',
                   'blocked_native_queue_scope': 'submitted queue task with no generated artifact and no provider identity is not a verified HY3 execution; request count, usage and fee unknown',
                   'flash_qualified_identity_rule': 'success and qualified max-token attempts have receipt.actual_model deepseek-flash; unqualified closed failures remain unknown',
                   'supplier_request_count_for_submitted_hy3_tasks': None},
               'source_protocol_clean_supplement': clean_comparison,
               'source_visibility': {
                   'condition_label_visible': True,
                   'actual_revoked_id_mask_and_questions_hidden': True,
                   'visibility_assertion_scope': 'provided source business inputs only; additional unapproved tool access is a protocol failure and its output is filtered',
                   'scope': 'sources.json exact frozen source projections; case IDs/native paths expose n and revocation-percentage condition labels; specific future withdrawn IDs, events, public receiver questions and gold are absent',
                   'future_all_metadata_blinded': False},
               'ledger_interpretation': {
                   'physical': 'each distinct finalized outer source attempt plus each receiver execution once; counters distinguish approved memory, truncation, tool failure, zero-model pre-creation failure and queue submission with unknown execution; no automatic retries',
                   'logical': 'each method charged its required initial/repair source jobs plus own receiver; shared whole generation can be charged to both whole_drop and full_rebuild',
                   'logical_arm_sums_are_physical_expenditure': False,
                   'hy3_task_count_is_physical_supplier_request_count': False,
                   'flash_usage': 'inputTokens is cache MISS; total input = MISS + cache READ + cache WRITE',
                   'unknown_workbuddy_fees_and_requests': None,
                   'money_estimates_are_supplier_bill': False,
                   'private_sdk_or_credentials_opened': False,
                   'path_normalization_scope': 'optional Windows drive namespace prefix only; same physical path, no file replacement or extra model dispatch',
                   'receiver_remote_input_attestation': False,
                   'aggregate_resource_winner_or_overall_advantage_claim': None,
                   'sum_job_wall_is_end_to_end_elapsed_time': False},
               'quality_summary': scored['summary'], 'quality_contrasts': scored['contrasts'],
               'independent_project_clusters': scored['independent_project_clusters']}
    _save(_path(root, root / 'audit_and_ledger.json'), summary)
    _save(_path(root, root / 'evaluation_with_payload.json'), scored)
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    args = parser.parse_args()
    summary = finalize(args.root)
    print(json.dumps({'status': summary['status'], 'main_jobs': summary['main_physical_ledger']['artifact_count'],
                      'mechanisms': summary['mechanisms']['status']}))
