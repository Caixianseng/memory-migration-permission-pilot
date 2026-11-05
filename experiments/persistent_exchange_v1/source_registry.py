"""Immutable, once-only adoption of a source attempt blocked by provider 429.

This module never dispatches a model, repairs a result, changes a budget, or
replaces original evidence. Only an explicit receipt selects quota_recovery_01.
Failed/unregistered recovery results remain in the physical-attempt ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

SCHEMA = 'source-provider-quota-recovery-v1'
IDENTITY = ('case_id', 'agent', 'platform', 'phase', 'group', 'budget', 'source_ids')
RECEIPT_NAME = 'source_recovery_receipt.json'
HY3_ROUTE_IDS = frozenset(('hy3', 'hy3-x'))


class SourceRegistryError(ValueError):
    pass


def _need(test, code):
    if not test:
        raise SourceRegistryError(code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _read(path):
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, ValueError, UnicodeError):
        raise SourceRegistryError('source_registry_file_missing_or_invalid:'+path.name) from None
    _need(isinstance(value, dict), 'source_registry_json_object_required:'+path.name)
    return raw, value


def _cell(cell_dir):
    supplied = str(cell_dir)
    if supplied.startswith('\\\\?\\'):
        supplied = supplied[4:]
    cell = Path(supplied).resolve()
    _need(not Path(supplied).is_symlink(), 'source_cell_symlink_not_allowed')
    return cell


def _local(cell, relative):
    candidate = cell/relative
    _need(not any(part.is_symlink() for part in (candidate, *candidate.parents)
                  if part == cell or part.is_relative_to(cell)), 'source_attempt_symlink_not_allowed')
    _need(candidate.resolve().is_relative_to(cell), 'source_attempt_outside_cell')
    return candidate


def _identity(result):
    _need(all(k in result for k in IDENTITY), 'source_attempt_identity_fields_required')
    value = {k: result[k] for k in IDENTITY}
    ids = value['source_ids']
    _need(isinstance(ids, list) and bool(ids) and all(isinstance(x, str) and x for x in ids)
          and len(set(ids)) == len(ids), 'source_attempt_unique_source_ids_required')
    _need(value['agent'] in ('A', 'B') and value['platform'] in ('hy3', 'flash')
          and value['phase'] in ('initial', 'repair')
          and value['group'] in ('whole', 'chunk0', 'chunk1')
          and type(value['budget']) is int and value['budget'] in (1024, 2048),
          'source_attempt_registered_identity_required')
    _need(isinstance(result.get('evidence'), dict), 'source_attempt_evidence_required')
    return value


def _quota_binding(cell, original):
    raw, quota = _read(_local(cell, 'provider_quota_evidence.json'))
    _need(quota.get('http_status') == 429 and type(quota.get('error_code')) is int,
          'explicit_provider_HTTP429_evidence_required')
    _need(isinstance(quota.get('native_history_prefix_sha256'), str)
          and re.fullmatch('[a-f0-9]{64}', quota['native_history_prefix_sha256']) is not None,
          'provider_quota_native_prefix_hash_required')
    task_id = quota.get('source_job_id')
    _need(isinstance(task_id, str) and task_id, 'provider_quota_source_job_id_required')
    bindings = []
    if isinstance(original['evidence'].get('task_id'), str):
        bindings.append(original['evidence']['task_id'])
    plan = _local(cell, 'native_job.json')
    if plan.exists():
        _, job = _read(plan)
        bindings.append(job.get('taskId'))
    _need(bool(bindings) and all(x == task_id for x in bindings),
          'provider_quota_evidence_belongs_to_another_job')
    return raw, quota


def _pair(cell):
    original_raw, original = _read(_local(cell, 'result.json'))
    original_identity = _identity(original)
    _need('memory' in original and original['memory'] is None,
          'recovery_for_existing_generated_memory_forbidden')
    _need(not _local(cell, 'memory.json').exists()
          and original['evidence'].get('artifact_sha256') is None,
          'recovery_for_existing_source_artifact_forbidden')
    quota_raw, quota = _quota_binding(cell, original)
    replacement_file = _local(cell, 'quota_recovery_01/result.json')
    replacement_raw, replacement = _read(replacement_file)
    _need(_identity(replacement) == original_identity,
          'recovery_source_ids_or_experiment_identity_changed')
    old_input = _local(cell, 'sources.json').read_bytes()
    new_input = _local(cell, 'quota_recovery_01/sources.json').read_bytes()
    _need(old_input == new_input, 'recovery_sources_json_bytes_changed')
    try:
        business = json.loads(old_input)
        actual_ids = [s['source_id'] for s in business['sources']]
    except (ValueError, KeyError, TypeError):
        raise SourceRegistryError('original_sources_json_contract_invalid') from None
    _need(actual_ids == original_identity['source_ids'], 'original_source_ids_do_not_match_actual_input')
    return {'original': original, 'replacement': replacement, 'quota': quota,
            'original_result_sha256': _sha(original_raw),
            'provider_quota_evidence_sha256': _sha(quota_raw),
            'replacement_result_sha256': _sha(replacement_raw),
            'sources_json_sha256': _sha(old_input),
            'identity': original_identity, 'replacement_file': replacement_file}


def _new_quota(cell, replacement):
    path = _local(cell, 'quota_recovery_01/provider_quota_evidence.json')
    if path.exists():
        _, value = _read(path)
        if value.get('http_status') == 429:
            return True
    evidence = replacement['evidence']
    candidates = [evidence, evidence.get('error'), evidence.get('provider_error')]
    candidates.extend(evidence.get('providerErrors', []) if isinstance(evidence.get('providerErrors'), list) else [])
    candidates.extend(evidence.get('provider_errors', []) if isinstance(evidence.get('provider_errors'), list) else [])
    return any(isinstance(value, dict) and any(value.get(k) == 429
               for k in ('http_status', 'httpStatus', 'status')) for value in candidates)


def _actual_output(cell, pair):
    replacement = pair['replacement']
    _need(not _new_quota(cell, replacement), 'recovery_again_rate_limited_pause_without_registration')
    memory = replacement.get('memory')
    _need(isinstance(memory, str) and bool(memory), 'recovery_has_no_actual_model_output')
    evidence = replacement['evidence']
    _need(type(evidence.get('source_protocol_conformance')) is bool,
          'recovery_explicit_source_protocol_outcome_required')
    if replacement['platform'] == 'hy3':
        _need(evidence.get('runtime_source') == 'desktop_queue',
              'recovery_must_use_original_normal_native_source_interface')
        _need(isinstance(evidence.get('actual_models'), list) and bool(evidence['actual_models'])
              and all(isinstance(x, str) and x for x in evidence['actual_models']),
              'recovery_actual_model_response_evidence_required')
        _need(set(evidence['actual_models']) <= HY3_ROUTE_IDS,
              'recovery_actual_model_outside_exact_Hy3_route_whitelist')
        requested = evidence.get('request_model_ids')
        _need(isinstance(requested, list) and bool(requested)
              and all(isinstance(x, str) for x in requested)
              and set(requested) <= HY3_ROUTE_IDS,
              'recovery_request_model_outside_exact_Hy3_route_whitelist')
        _need(evidence.get('canonical_model_family', 'Hy3') == 'Hy3',
              'recovery_canonical_model_family_mismatch')
        artifact_raw, artifact = _read(_local(cell, 'quota_recovery_01/memory.json'))
        _need(artifact == {'memory': memory} and evidence.get('artifact_sha256') == _sha(artifact_raw),
              'recovery_native_generated_artifact_binding_mismatch')
    else:
        _need(isinstance(evidence.get('actual_model'), str) and bool(evidence['actual_model'])
              and evidence.get('artifact_sha256') == _sha(memory.encode('utf-8')),
              'recovery_actual_model_response_evidence_required')
    return evidence['source_protocol_conformance']


def _receipt_value(cell, pair):
    conformance = _actual_output(cell, pair)
    return {'schema': SCHEMA, 'recovery_number': 1,
            'original_result_path': 'result.json',
            'original_result_sha256': pair['original_result_sha256'],
            'provider_quota_evidence_path': 'provider_quota_evidence.json',
            'provider_quota_evidence_sha256': pair['provider_quota_evidence_sha256'],
            'replacement_result_path': 'quota_recovery_01/result.json',
            'replacement_result_sha256': pair['replacement_result_sha256'],
            'original_sources_json_sha256': pair['sources_json_sha256'],
            'replacement_sources_json_sha256': pair['sources_json_sha256'],
            'experiment_identity': pair['identity'],
            'replacement_source_protocol_conformance': conformance,
            'response_model_binding': ({'canonical_model_family': 'Hy3',
                'raw_actual_models': pair['replacement']['evidence']['actual_models'],
                'raw_request_model_ids': pair['replacement']['evidence']['request_model_ids'],
                'exact_route_whitelist': sorted(HY3_ROUTE_IDS),
                'official_paid_alias': {'freeId': 'hy3', 'paidId': 'hy3-x', 'displayName': 'Hy3'}}
                if pair['replacement']['platform'] == 'hy3' else
                {'raw_actual_model': pair['replacement']['evidence']['actual_model']}),
            'adoption_outcome': 'usable_source_attempt' if conformance else 'final_protocol_failed_output_fail_closed',
            'original_evidence_preserved': True,
            'source_runtime_interface': 'original normal source interface; not receiver ask/one-shot',
            'all_attempts_required_in_physical_and_logical_cost_ledgers': True,
            'further_regeneration_authorized': False}


def _verified_receipt(cell):
    path = _local(cell, RECEIPT_NAME)
    _, saved = _read(path)
    expected = _receipt_value(cell, _pair(cell))
    _need(saved == expected, 'source_recovery_receipt_or_bound_evidence_changed')
    return saved


def resolve_source_result(cell_dir):
    """Select the unchanged original unless an exact immutable override exists."""
    cell = _cell(cell_dir)
    receipt = _local(cell, RECEIPT_NAME)
    if not receipt.exists():
        return _local(cell, 'result.json')
    _verified_receipt(cell)
    return _local(cell, 'quota_recovery_01/result.json')


def source_attempt_paths(cell_dir):
    """Count all existing recovery results, including paused/unregistered 429s.

    Adoption is restricted to recovery_01. Any other on-disk attempt remains
    visible to cost accounting rather than disappearing from the ledger.
    """
    cell = _cell(cell_dir)
    if _local(cell, RECEIPT_NAME).exists():
        _verified_receipt(cell)
    paths = [_local(cell, 'result.json')]
    if cell.is_dir():
        for folder in sorted(cell.glob('quota_recovery_*')):
            _need(folder.is_dir() and not folder.is_symlink(), 'invalid_source_attempt_directory')
            path = _local(cell, folder.name+'/result.json')
            if path.is_file():
                paths.append(path)
    return paths


def register_recovery(cell_dir, replacement_result_path):
    """Register at most one post-429 recovery, never rewrite model artifacts."""
    cell = _cell(cell_dir)
    expected_path = _local(cell, 'quota_recovery_01/result.json')
    supplied = str(replacement_result_path)
    if supplied.startswith('\\\\?\\'):
        supplied = supplied[4:]
    _need(Path(supplied).resolve() == expected_path.resolve(),
          'only_quota_recovery_01_may_be_registered')
    receipt_file = _local(cell, RECEIPT_NAME)
    if receipt_file.exists():
        return _verified_receipt(cell)
    receipt = _receipt_value(cell, _pair(cell))
    try:
        with receipt_file.open('xb') as stream:
            stream.write(_canonical(receipt)+b'\n')
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return _verified_receipt(cell)
    return receipt


__all__ = ['resolve_source_result', 'source_attempt_paths', 'register_recovery', 'SourceRegistryError']
