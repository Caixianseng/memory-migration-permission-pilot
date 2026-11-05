"""One bounded, explicitly evidenced recovery of provider-quota source cells.

Importing dispatches nothing. Calling run_quota_recovery is an operational
action: it uses the unchanged normal source interface, never receiver ask or a
one-shot prose substitute. Original attempts and all their bytes are retained.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import uuid

from .run_study import material, source_jobs, execute_source
from .source_registry import register_recovery, SourceRegistryError

SCHEMA = 'bounded-source-quota-recovery-plan-v1'
PLAN = 'quota_recovery_plan.json'
STOP = 'quota_recovery_STOPPED.json'
PROGRESS = 'quota_recovery_progress.json'
IDENTITY = ('case_id', 'agent', 'platform', 'phase', 'group', 'budget', 'source_ids')
HERE = Path(__file__).resolve().parent
_HEX = re.compile(r'^[a-f0-9]{64}$')


class QuotaRecoveryError(RuntimeError):
    """Stable controller error; no native command, credential or lease text."""


def _need(test, code):
    if not test:
        raise QuotaRecoveryError(code)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(path):
    _need(not path.is_symlink(), 'quota_recovery_symlink_file_forbidden')
    raw = path.read_bytes()
    return raw, json.loads(raw)


def _new(path, value):
    with path.open('xb') as stream:
        stream.write(_canonical(value)+b'\n')
        stream.flush()
        os.fsync(stream.fileno())


def _progress(root, value):
    target = root/PROGRESS
    temp = root/(PROGRESS+'.tmp')
    with temp.open('wb') as stream:
        stream.write(_canonical(value)+b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(target)


def _expected_source_bytes(job):
    return json.dumps({'sources': job['sources'], 'parent_memories': [],
                       'max_memory_characters': job['budget']*2,
                       'length_limit_scope': 'native soft instruction; SDK additionally enforces max output tokens'},
                      ensure_ascii=False, sort_keys=True, indent=2).encode('utf-8')


def _identity(value):
    return {key: value[key] for key in IDENTITY}


def _original_artifact_present(cell, original):
    if original.get('memory') is not None or (cell/'memory.json').exists():
        return True
    evidence = original.get('evidence', {})
    if evidence.get('artifact_sha256') is not None:
        return True
    for key in ('artifact_path', 'memory_path', 'memory_file', 'MemoryFile'):
        value = evidence.get(key, original.get(key))
        if isinstance(value, str) and value and Path(value).exists():
            return True
    return False


def _selection(root, jobs):
    selected = []
    for job in jobs:
        cell = Path(job['job_dir']).resolve()
        _need(cell.is_relative_to(root/'source_jobs'), 'quota_recovery_cell_outside_source_plan')
        if not (cell/'result.json').is_file() or not (cell/'provider_quota_evidence.json').is_file():
            continue
        original_raw, original = _read(cell/'result.json')
        if _original_artifact_present(cell, original):
            continue
        quota_raw, quota = _read(cell/'provider_quota_evidence.json')
        if quota.get('http_status') != 429:
            continue
        _need(job['platform'] == 'hy3' and job['agent'] == 'A', 'quota_recovery_requires_native_hy3_source')
        code = quota.get('error_code')
        _need(type(code) is int and ((code == 6004 and job['phase'] == 'repair')
                                    or (code == 6020 and job['phase'] == 'initial')),
              'quota_recovery_provider_code_or_phase_not_authorized')
        _need(_identity(original) == _identity(job), 'quota_recovery_original_identity_changed')
        _need(original.get('memory') is None and isinstance(original.get('evidence'), dict),
              'quota_recovery_closed_original_required')
        _need(original['evidence'].get('source_protocol_conformance') is False,
              'quota_recovery_original_failure_not_explicitly_closed')
        prefix = quota.get('native_history_prefix_sha256')
        _need(isinstance(prefix, str) and _HEX.fullmatch(prefix), 'quota_recovery_quota_prefix_binding_required')
        bindings = []
        if isinstance(original['evidence'].get('task_id'), str):
            bindings.append(original['evidence']['task_id'])
        native_path = cell/'native_job.json'
        native_hash = None
        if native_path.exists():
            native_raw, native = _read(native_path)
            bindings.append(native.get('taskId'))
            native_hash = _sha(native_raw)
        _need(bindings and all(x == quota.get('source_job_id') for x in bindings),
              'quota_recovery_quota_belongs_to_another_job')
        _need(not (cell/'sources.json').is_symlink(), 'quota_recovery_symlink_file_forbidden')
        source_bytes = (cell/'sources.json').read_bytes()
        _need(source_bytes == _expected_source_bytes(job), 'quota_recovery_frozen_source_input_changed')
        child = cell/'quota_recovery_01'
        _need(not child.is_symlink(), 'quota_recovery_child_symlink_forbidden')
        selected.append({'cell': cell, 'child': child, 'job': deepcopy(job),
                         'source_bytes': source_bytes,
                         'binding': {'cell_dir': str(cell), 'recovery_dir': str(child),
                            'identity': _identity(job), 'sources_sha256': _sha(_canonical(job['sources'])),
                            'original_result_sha256': _sha(original_raw),
                            'provider_quota_evidence_sha256': _sha(quota_raw),
                            'original_native_job_sha256': native_hash,
                            'original_sources_json_sha256': _sha(source_bytes)}})
    selected.sort(key=lambda row: str(row['cell']))
    _need(len(selected) <= 7, 'quota_recovery_maximum_authorized_cells_exceeded')
    return selected


def _has_429(value):
    if isinstance(value, dict):
        if any(str(value.get(key, '')) == '429' for key in ('http_status', 'httpStatus', 'status')):
            return True
        return any(_has_429(child) for child in value.values())
    return isinstance(value, list) and any(_has_429(child) for child in value)


def _child_quota(child, result=None):
    path = child/'provider_quota_evidence.json'
    try:
        if path.exists() and _has_429(_read(path)[1]):
            return True
    except (OSError, ValueError, QuotaRecoveryError):
        # A malformed audit file is an unknown outcome, never permission to
        # issue another prompt. Registration will reject it independently.
        pass
    return _has_429(result.get('evidence', {})) if isinstance(result, dict) else False


def run_quota_recovery(root, workers=2):
    """Return one outcome per eligible cell; pause prevents any later dispatch.

    A successful existing child is only verified/registered. An intent without
    a result is an unresolved attempt and is never automatically dispatched
    again. A STOP file requires external review; this function never clears it.
    """
    _need(type(workers) is int and 1 <= workers <= 2, 'quota_recovery_workers_must_be_one_or_two')
    supplied = str(root)
    if supplied.startswith('\\\\?\\'):
        supplied = supplied[4:]
    _need(not Path(supplied).is_symlink(), 'quota_recovery_root_symlink_forbidden')
    root = Path(supplied).resolve(strict=True)
    _need(root.is_dir(), 'quota_recovery_existing_root_required')
    lock = root/'quota_recovery_execution.lock'
    lock_bytes = _canonical({'pid': os.getpid(), 'nonce': uuid.uuid4().hex})
    try:
        with lock.open('xb') as stream:
            stream.write(lock_bytes)
    except FileExistsError:
        raise QuotaRecoveryError('quota_recovery_existing_lock_no_automatic_dispatch') from None
    try:
        cases, contract = material()
        jobs = source_jobs(root, cases, 'initial')+source_jobs(root, cases, 'repair')
        selected = _selection(root, jobs)
        parameters = {'workers': workers, 'maximum_recovery_attempts_per_cell': 1,
                      'recovery_directory': 'quota_recovery_01',
                      'interface': 'execute_source original normal-mode desktop_queue',
                      'pause_on_new_429_or_unknown_output': True}
        frozen = {'schema': SCHEMA, 'dataset_sha256': _sha(_canonical(cases)),
                  'dataset_contract_sha256': _sha(_canonical(contract)),
                  'source_plan_sha256': _sha(_canonical([{**_identity(job), 'sources': job['sources']}
                                                        for job in jobs])),
                  'parameters': parameters, 'parameters_sha256': _sha(_canonical(parameters)),
                  'runtime_sha256': {name: _sha((HERE/name).read_bytes()) for name in
                                     ('model_runtime.py', 'run_study.py', 'source_registry.py', 'run_quota_recovery.py')},
                  'eligible_cells': [row['binding'] for row in selected],
                  'source_questions_or_reference_answers_supplied': False,
                  'original_attempts_must_remain_in_cost_ledgers': True}
        plan_path = root/PLAN
        if plan_path.exists():
            _need(_read(plan_path)[1] == frozen, 'quota_recovery_frozen_plan_changed')
        else:
            _new(plan_path, frozen)
        _need(not (root/STOP).exists(), 'quota_recovery_paused_requires_external_review_no_auto_retry')
        stopped = threading.Event()
        stop_lock = threading.Lock()
        results = {}

        def pause(row, status, code):
            stopped.set()
            with stop_lock:
                if not (root/STOP).exists():
                    _new(root/STOP, {'schema': 'bounded-source-quota-recovery-stop-v1',
                         'cell_dir': str(row['cell']), 'status': status, 'error_code': code,
                         'automatic_retry': False, 'further_dispatch': False,
                         'inflight_attempts_may_only_be_harvested': True})

        def outcome(row, status, registered=False, **extra):
            return {'cell_dir': str(row['cell']), 'recovery_dir': str(row['child']),
                    'result_path': str(row['child']/'result.json') if (row['child']/'result.json').exists() else None,
                    'status': status, 'registered': registered, 'automatic_retry': False, **extra}

        def attempt(row):
            child, cell = row['child'], row['cell']
            try:
                # Recheck the frozen parent immediately before reserving this
                # child. No edited/future context can enter a source request.
                _need(_sha((cell/'result.json').read_bytes()) == row['binding']['original_result_sha256']
                      and _sha((cell/'provider_quota_evidence.json').read_bytes()) == row['binding']['provider_quota_evidence_sha256']
                      and (cell/'sources.json').read_bytes() == row['source_bytes'],
                      'quota_recovery_frozen_parent_binding_changed')
                _need(not _original_artifact_present(cell, _read(cell/'result.json')[1]),
                      'quota_recovery_original_artifact_appeared_no_dispatch')
                child.mkdir(exist_ok=True)
                source_file, result_file = child/'sources.json', child/'result.json'
                if source_file.exists():
                    _need(source_file.read_bytes() == row['source_bytes'], 'quota_recovery_child_input_bytes_changed')
                else:
                    with source_file.open('xb') as stream:
                        stream.write(row['source_bytes'])
                existing_result = result_file.exists()
                if existing_result:
                    result = _read(result_file)[1]
                else:
                    traces = ('recovery_attempt_intent.json', 'native_job.json', 'create.json', 'created.json',
                              'created.json.intent.json', 'submission_intent.json', 'memory.json',
                              'provider_quota_evidence.json', 'sdk.private')
                    _need(not any((child/name).exists() for name in traces),
                          'quota_recovery_unresolved_existing_child_no_retry')
                    if stopped.is_set():
                        return outcome(row, 'not_dispatched_after_pause')
                    _new(child/'recovery_attempt_intent.json', {
                         'schema': 'bounded-source-quota-recovery-attempt-v1',
                         'frozen_plan_sha256': _sha(plan_path.read_bytes()),
                         'original_binding': row['binding'], 'maximum_actual_attempts': 1,
                         'automatic_retry': False})
                    cloned = deepcopy(row['job'])
                    cloned['job_dir'] = str(child)
                    if stopped.is_set():
                        return outcome(row, 'not_dispatched_after_pause')
                    result = execute_source(cloned)
                _need(source_file.read_bytes() == row['source_bytes'], 'quota_recovery_source_input_changed_during_attempt')
                _need(result_file.exists() and _read(result_file)[1] == result,
                      'quota_recovery_normal_result_not_persisted')
                _need(_identity(result) == _identity(row['job']), 'quota_recovery_result_identity_changed')
                if _child_quota(child, result):
                    pause(row, 'paused_new_quota', 'provider_HTTP429_in_recovery')
                    return outcome(row, 'paused_new_quota')
                if not isinstance(result.get('memory'), str) or not result['memory']:
                    pause(row, 'paused_no_output', 'recovery_output_unknown_or_missing')
                    return outcome(row, 'paused_no_output')
                receipt = register_recovery(cell, result_file)
                conforms = receipt['replacement_source_protocol_conformance']
                return outcome(row, 'existing_registered' if existing_result else
                               'registered' if conforms else 'protocol_failed_registered', True,
                               source_protocol_conformance=conforms, scope_audit_required_before_delivery=True,
                               response_model_binding=receipt['response_model_binding'])
            except Exception as error:
                status = 'paused_new_quota' if _child_quota(child) else 'paused_execution_error'
                code = 'provider_HTTP429_in_recovery' if status == 'paused_new_quota' else 'recovery_attempt_unresolved_no_retry'
                pause(row, status, code)
                return outcome(row, status, exception_class=type(error).__name__)

        pending = list(selected)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            active = {}
            while pending or active:
                while pending and len(active) < workers and not stopped.is_set():
                    row = pending.pop(0)
                    active[pool.submit(attempt, row)] = row
                if not active:
                    break
                done, _ = wait(active, return_when=FIRST_COMPLETED)
                # Harvest every already-finished outcome before adding work;
                # workers set stopped themselves as soon as a failure is known.
                done |= {future for future in active if future.done()}
                for future in done:
                    row = active.pop(future)
                    results[str(row['cell'])] = future.result()
                _progress(root, {'schema': SCHEMA, 'status': 'paused' if stopped.is_set() else 'running',
                                 'planned': len(selected), 'results': [results[key] for key in sorted(results)]})
        for row in pending:
            results[str(row['cell'])] = outcome(row, 'not_dispatched_after_pause')
        ordered = [results[str(row['cell'])] for row in selected]
        _progress(root, {'schema': SCHEMA, 'status': 'paused' if stopped.is_set() else 'complete',
                         'planned': len(selected), 'results': ordered})
        return ordered
    finally:
        if lock.exists() and lock.read_bytes() == lock_bytes:
            lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=2)
    args = parser.parse_args()
    results = run_quota_recovery(args.root, args.workers)
    print(json.dumps({'planned': len(results), 'statuses': [r['status'] for r in results]}, ensure_ascii=False))


if __name__ == '__main__':
    main()
