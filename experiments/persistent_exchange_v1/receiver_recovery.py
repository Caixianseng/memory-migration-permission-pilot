"""One declared recovery for terminal provider-500 receiver turns with no text.

Only the root controller calls run_receiver_recovery after the full first pass.
This module never changes questions, memory, original envelopes or progress, and
never retries an incorrect answer, malformed existing response or unknown turn.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3

from .prepare_data import receiver_questions
from .read_receiver import read_batch, canonical
from .receiver_paid_runtime import answer_paid_hy3, DRIVER
from .receiver_runtime import _answers, _verify_readback
from .store import TrustedPolicy

HERE = Path(__file__).resolve().parent
ROUTES = {'hy3', 'hy3-x'}


class ReceiverRecoveryError(RuntimeError):
    pass


def _need(test, code):
    if not test:
        raise ReceiverRecoveryError(code)


def _sha(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _path(root, value):
    text = str(value)
    if text.startswith('\\\\?\\'):
        text = text[4:]
    supplied = Path(text)
    supplied = supplied if supplied.is_absolute() else root/supplied
    _need(not supplied.is_symlink(), 'receiver_recovery_symlink_forbidden')
    resolved = supplied.resolve()
    _need(resolved.is_relative_to(root), 'receiver_recovery_artifact_outside_run')
    _need(not any(x.casefold() in {'sdk.private', 'home.private'} or 'credential' in x.casefold()
                  for x in resolved.parts), 'receiver_recovery_private_artifact_forbidden')
    return resolved


def _load(path):
    try:
        return json.loads(Path(path).read_bytes())
    except (OSError, ValueError, UnicodeError):
        raise ReceiverRecoveryError('receiver_recovery_missing_or_invalid_file:'+Path(path).name) from None


def _once(path, value):
    raw = canonical(value)+b'\n'
    if path.exists():
        _need(path.read_bytes() == raw, 'receiver_recovery_frozen_output_changed:'+path.name)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _bindings(paths):
    try:
        return {str(p): {'bytes': p.stat().st_size, 'sha256': _sha(p.read_bytes())} for p in paths}
    except OSError:
        raise ReceiverRecoveryError('receiver_recovery_bound_file_missing_or_changed') from None


def _policy_check(root, record):
    # Reuse the exact authorization check without running the schema-creating
    # TrustedPolicy constructor on a main experiment authority.
    delivery = record['delivery']
    path = _path(root, delivery['policy_db'])
    policy = TrustedPolicy.__new__(TrustedPolicy)
    policy.path = path
    policy.db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, isolation_level=None)
    policy.db.row_factory = sqlite3.Row
    try:
        policy.db.execute('PRAGMA query_only=ON')
        policy.check_dependencies(record['recipient'], delivery['dependencies'], delivery['policy_epoch'])
    except Exception:
        raise ReceiverRecoveryError('receiver_recovery_current_permission_binding_changed') from None
    finally:
        policy.close()


def _is_candidate(base):
    if (base/'scored_input.json').exists() and not (base/'receiver_recovery_receipt.json').exists():
        return False
    envelope_file = base/'native_paid_one_shot'/'envelope.json'
    if not envelope_file.is_file():
        return False
    envelope = _load(envelope_file)
    native, errors = envelope.get('nativeExecution') or {}, envelope.get('providerErrors') or []
    if (base/'answers.json').exists() or (base/'receiver_paid_verified.json').exists():
        return False
    if envelope.get('assistantCompletedMessages') != 0 or envelope.get('output') != '':
        return False
    if any(e.get('httpStatus') == 429 or e.get('code') in (6004, 6020) for e in errors if isinstance(e, dict)):
        return False
    provider_500 = any(e.get('code') == 11134 and e.get('httpStatus') == 500
                       for e in errors if isinstance(e, dict))
    after = native.get('after') or {}
    return (provider_500 and native.get('status') == 'native_prompt_returned'
            and native.get('stopReason') in ('refusal', 'error')
            and native.get('modelPromptsSubmitted') == 1
            and after.get('status') == 'completed' and after.get('isProcessing') is False
            and after.get('model') == 'hy3-x' and after.get('mode') == 'ask' and after.get('tools') == '')


def _original(root, record, evaluation):
    base = _path(root, record['job_dir'])
    delivery, child = record['delivery'], base/'native_paid_one_shot'
    paths = [base/name for name in ('delivery.json', 'questions.json', 'receiver_paid_contract.json',
             'paid_dispatch_intent.json', 'retrieved_memory.json', 'retrieved_memory.json.receipt.json')]
    paths += [child/'job.json', child/'envelope.json']
    for path in paths:
        _path(root, path)
        _need(path.is_file(), 'receiver_recovery_original_binding_file_missing:'+path.name)
    _need(_load(base/'delivery.json') == delivery, 'receiver_recovery_manifest_delivery_changed')
    questions = receiver_questions(evaluation, record['case_id'], record['direction'])
    _need(_load(base/'questions.json') == questions, 'receiver_recovery_frozen_questions_changed')
    database = _path(root, delivery['receiver_db'])
    contract, job, envelope = (_load(base/'receiver_paid_contract.json'), _load(child/'job.json'),
                               _load(child/'envelope.json'))
    _need(contract.get('receiver_database') == str(database) and contract.get('batch_id') == delivery['batch_id']
          and contract.get('database_sha256') == _sha(database.read_bytes())
          and contract.get('questions') == questions and contract.get('model') == 'hy3-x'
          and contract.get('mode') == 'ask' and contract.get('tools') == '',
          'receiver_recovery_original_database_or_contract_changed')
    payload, reader_receipt = _verify_readback(database, delivery['batch_id'], base/'retrieved_memory.json')
    memory = payload['memory']
    _need(_sha(memory) == delivery['reopened_content_sha256'], 'receiver_recovery_imported_memory_changed')
    qualification = _path(root, contract['qualification']['path'])
    _need(_sha(qualification.read_bytes()) == contract['qualification']['sha256'],
          'receiver_recovery_qualification_changed')
    business = {'memory': memory, 'questions': questions}
    job_raw = (child/'job.json').read_bytes()
    intent = _load(base/'paid_dispatch_intent.json')
    _need(job.get('businessInput') == business and job.get('jobType') == 'receiver'
          and job.get('model') == 'hy3-x' and job.get('qualificationEnvelope') == str(qualification)
          and envelope.get('jobId') == job.get('jobId') and envelope.get('sessionId') == job.get('sessionId')
          and envelope.get('inputFileSha256') == _sha(job_raw)
          and envelope.get('businessInputSha256') == _sha(business)
          and intent.get('job_sha256') == _sha(job_raw)
          and intent.get('business_input_sha256') == _sha(business),
          'receiver_recovery_original_business_input_binding_changed')
    _need(contract.get('driver_sha256') == _sha(DRIVER.read_bytes()), 'receiver_recovery_original_driver_changed')
    _policy_check(root, record)
    paths += [database, _path(root, delivery['policy_db']), qualification]
    return {'base': base, 'database': database, 'questions': questions, 'memory': memory,
            'qualification': qualification, 'contract': contract, 'job': job, 'envelope': envelope,
            'bindings': _bindings(paths), 'business_input_sha256': _sha(business),
            'questions_sha256': _sha(questions), 'memory_sha256': _sha(memory),
            'logical_snapshot_sha256': reader_receipt['logical_snapshot_sha256']}


def _attempt(base, number, *, qualified=False, schema_valid=None):
    envelope_file, job_file = base/'native_paid_one_shot/envelope.json', base/'native_paid_one_shot/job.json'
    envelope = _load(envelope_file) if envelope_file.is_file() else {}
    native = envelope.get('nativeExecution') or {}
    prompts = native.get('modelPromptsSubmitted')
    errors = [{k: value.get(k) for k in ('code', 'httpStatus', 'resetIso')}
              for value in envelope.get('providerErrors', []) if isinstance(value, dict)]
    return {'schema': 'receiver-native-attempt-cost-evidence-v1', 'attempt': number, 'job_dir': str(base),
            'native_job_path': str(job_file), 'native_job_sha256': _sha(job_file.read_bytes()) if job_file.is_file() else None,
            'native_envelope_path': str(envelope_file),
            'native_envelope_sha256': _sha(envelope_file.read_bytes()) if envelope_file.is_file() else None,
            'native_session_id': envelope.get('sessionId'), 'native_task_id': envelope.get('jobId'),
            'native_direct_session_submissions': 1 if prompts == 1 else None,
            'qualified_native_turns': 1 if qualified else 0, 'answers_schema_valid': schema_valid,
            'provider_errors': errors, 'native_user_request_count': envelope.get('nativeUserRequestCount'),
            'actual_models': envelope.get('actualModels', []), 'request_model_ids': envelope.get('requestModelIds', []),
            'physical_supplier_calls': None, 'supplier_fee_cny': None, 'workbuddy_fee_cny': None,
            'input_tokens': None, 'output_tokens': None, 'automatic_retry': False,
            'native_turn_is_one_supplier_request': False}


def _new_proof(root, original, retry, answers, evidence):
    files = [retry/name for name in ('answers.json', 'questions.json', 'retrieved_memory.json',
             'retrieved_memory.json.receipt.json', 'receiver_paid_contract.json', 'receiver_paid_verified.json')]
    files += [retry/'native_paid_one_shot/job.json', retry/'native_paid_one_shot/envelope.json']
    _need(all(p.is_file() for p in files), 'receiver_recovery_new_verified_artifact_missing')
    for path in files:
        _path(root, path)
    raw, job_raw = (retry/'answers.json').read_bytes(), (retry/'native_paid_one_shot/job.json').read_bytes()
    job, envelope = _load(retry/'native_paid_one_shot/job.json'), _load(retry/'native_paid_one_shot/envelope.json')
    saved, contract = _load(retry/'receiver_paid_verified.json'), _load(retry/'receiver_paid_contract.json')
    _need(saved.get('answers') == answers and saved.get('evidence') == evidence
          and saved.get('contract_sha256') == _sha(contract), 'receiver_recovery_returned_cache_binding_changed')
    _need((retry/'questions.json').read_bytes() == (original['base']/'questions.json').read_bytes()
          and (retry/'retrieved_memory.json').read_bytes() == (original['base']/'retrieved_memory.json').read_bytes(),
          'receiver_recovery_memory_or_question_bytes_changed')
    _, reader_receipt = _verify_readback(original['database'], contract['batch_id'], retry/'retrieved_memory.json')
    _need(contract.get('receiver_database') == str(original['database'])
          and contract.get('batch_id') == original['contract']['batch_id']
          and contract.get('database_sha256') == original['contract']['database_sha256']
          and contract.get('questions') == original['questions']
          and contract.get('qualification') == original['contract']['qualification']
          and job.get('businessInput') == {'memory': original['memory'], 'questions': original['questions']}
          and job.get('instruction') == original['job']['instruction']
          and job.get('softOutputCharacters') == original['job']['softOutputCharacters']
          and job.get('qualificationEnvelope') == str(original['qualification']),
          'receiver_recovery_new_input_or_database_binding_changed')
    _need(envelope.get('status') == 'verified_native_paid_one_shot' and envelope.get('requestedModel') == 'hy3-x'
          and envelope.get('requestModelIds') == ['hy3-x'] and envelope.get('actualModels')
          and set(envelope['actualModels']) <= ROUTES and envelope.get('toolCallCount') == 0
          and envelope.get('nativeUserRequestCount') == 1 and envelope.get('nativeBusinessQueryMatchesSubmitted') is True
          and envelope.get('providerErrors') == [] and envelope.get('jobId') == job.get('jobId')
          and envelope.get('sessionId') == job.get('sessionId') != original['job']['sessionId']
          and envelope.get('inputFileSha256') == _sha(job_raw)
          and envelope.get('businessInputSha256') == original['business_input_sha256']
          and envelope.get('actualAssistantOutputSha256') == _sha(raw)
          and envelope.get('output', '').encode('utf-8') == raw,
          'receiver_recovery_new_native_envelope_not_verified')
    native = envelope.get('nativeExecution') or {}
    after = native.get('after') or {}
    _need(native.get('status') == 'native_prompt_returned' and native.get('stopReason') == 'end_turn'
          and native.get('modelPromptsSubmitted') == 1 and after.get('status') == 'completed'
          and after.get('isProcessing') is False and after.get('model') == 'hy3-x',
          'receiver_recovery_new_native_turn_not_complete')
    parsed, failure = _answers(raw, original['questions'])
    _need(parsed == answers and evidence.get('answers_schema_valid') == (failure is None)
          and evidence.get('answers_sha256') == _sha(raw) and evidence.get('reader_receipt') == reader_receipt
          and evidence.get('native_paid_envelope') == envelope
          and evidence.get('native_paid_envelope_sha256') == _sha((retry/'native_paid_one_shot/envelope.json').read_bytes())
          and evidence.get('native_paid_job_sha256') == _sha(job_raw)
          and evidence.get('actual_models') == envelope['actualModels']
          and evidence.get('request_model_ids') == envelope['requestModelIds']
          and evidence.get('workbuddy_fee_cny') is None and evidence.get('physical_supplier_calls') is None,
          'receiver_recovery_answer_or_resource_evidence_changed')
    return _bindings(files), failure is None


def _commit(root, record, original, answers, evidence):
    base, retry = original['base'], original['base']/'provider_retry_01'
    new_bindings, schema_valid = _new_proof(root, original, retry, answers, evidence)
    _need(_bindings([Path(p) for p in original['bindings']]) == original['bindings'],
          'receiver_recovery_original_artifact_changed_during_attempt')
    attempts = [_attempt(base, 0), _attempt(retry, 1, qualified=True, schema_valid=schema_valid)]
    _once(base/'original_receiver_failed_cost.json', attempts[0])
    _once(retry/'receiver_attempt_cost.json', attempts[1])
    receipt_file = base/'receiver_recovery_receipt.json'
    completed = {**record, 'answers': answers, 'receiver_evidence': evidence,
        'effective_receiver_job_dir': str(retry), 'receiver_recovery_receipt_path': str(receipt_file),
        'receiver_attempts': attempts}
    receipt = {'schema': 'receiver-provider-temporary-recovery-v1', 'recovery_number': 1,
        'original_job_dir': str(base), 'effective_receiver_job_dir': str(retry),
        'original_bindings': original['bindings'], 'new_verified_bindings': new_bindings,
        'delivery_sha256': _sha(record['delivery']), 'memory_sha256': original['memory_sha256'],
        'questions_sha256': original['questions_sha256'],
        'business_input_sha256': original['business_input_sha256'],
        'logical_snapshot_sha256': original['logical_snapshot_sha256'],
        'scored_input_sha256': _sha(canonical(completed)+b'\n'), 'receiver_attempts': attempts,
        'original_progress_overwritten': False, 'original_inputs_modified': False,
        'retry_reason': 'terminal provider 11134 HTTP500; no complete original assistant output',
        'wrong_answers_or_schema_failures_are_not_retry_reasons': True,
        'automatic_retry': False, 'further_retry_authorized': False}
    _once(receipt_file, receipt)
    _once(base/'scored_input.json', completed)
    return {'cell_dir': str(base), 'status': 'recovered' if schema_valid else 'format_failed_recovered',
        'registered': True, 'result_path': str(base/'scored_input.json'),
        'effective_receiver_job_dir': str(retry), 'automatic_retry': False}


def _failed(original, code):
    base, retry = original['base'], original['base']/'provider_retry_01'
    attempts = [_attempt(base, 0), _attempt(retry, 1)]
    _once(base/'original_receiver_failed_cost.json', attempts[0])
    _once(retry/'receiver_attempt_cost.json', attempts[1])
    failure = {'schema': 'receiver-provider-recovery-final-failure-v1', 'error_code': code[:200],
        'original_bindings': original['bindings'], 'receiver_attempts': attempts,
        'further_retry_authorized': False, 'automatic_retry': False}
    _once(base/'receiver_recovery_failure.json', failure)
    return {'cell_dir': str(base), 'status': 'failed_no_retry', 'registered': False, 'result_path': None,
        'effective_receiver_job_dir': str(retry), 'receiver_attempts': attempts, 'automatic_retry': False}


def run_receiver_recovery(root):
    """Recover eligible no-output provider failures once, after the first pass."""
    root = _path(Path(root).resolve(), Path(root).resolve())
    manifest_file, progress_file = root/'manifest.json', root/'receiver_progress.json'
    manifest, progress = _load(manifest_file), _load(progress_file)
    records = manifest['main_records']
    _need(progress.get('planned') == len(records)
          and progress.get('finished', 0)+progress.get('failed', 0) == len(records),
          'receiver_recovery_first_pass_not_finished')
    _need(Path(manifest['root']).resolve() == root, 'receiver_recovery_manifest_root_changed')
    evaluation_file = HERE/'data/evaluation_only.json'
    contract = _load(HERE/'data/contract.json')
    _need(_sha(evaluation_file.read_bytes()) == contract['artifact_sha256']['evaluation_only.json'],
          'receiver_recovery_frozen_evaluation_changed')
    evaluation, candidates = _load(evaluation_file), []
    for record in records:
        if record['receiver_platform'] == 'hy3' and _is_candidate(_path(root, record['job_dir'])):
            candidates.append((record, _original(root, record, evaluation)))
    plan = {'schema': 'receiver-temporary-provider-recovery-plan-v1',
        'manifest_sha256': _sha(manifest_file.read_bytes()), 'original_progress_sha256': _sha(progress_file.read_bytes()),
        'evaluation_sha256': _sha(evaluation_file.read_bytes()),
        'runtime_sha256': {'receiver_recovery.py': _sha(Path(__file__).read_bytes()),
                           'receiver_paid_runtime.py': _sha((HERE/'receiver_paid_runtime.py').read_bytes()),
                           'paid_native_driver': _sha(DRIVER.read_bytes())},
        'max_recoveries_per_cell': 1,
        'candidates': [{'cell_dir': str(o['base']), 'bindings': o['bindings']} for _, o in candidates]}
    _once(root/'receiver_recovery_plan.json', plan)
    outcomes = []
    for record, original in candidates:
        base, retry = original['base'], original['base']/'provider_retry_01'
        _once(base/'original_receiver_failed_cost.json', _attempt(base, 0))
        receipt_file = base/'receiver_recovery_receipt.json'
        if receipt_file.exists():
            receipt = _load(receipt_file)
            _need(receipt.get('original_bindings') == original['bindings']
                  and _bindings([Path(p) for p in receipt['new_verified_bindings']]) == receipt['new_verified_bindings'],
                  'receiver_recovery_registered_artifacts_changed')
            saved = _load(retry/'receiver_paid_verified.json')
            outcome = _commit(root, record, original, saved['answers'], saved['evidence'])
            outcome['status'] = 'existing_recovered'
            outcomes.append(outcome)
            continue
        failure_file = base/'receiver_recovery_failure.json'
        if failure_file.exists():
            previous = _load(failure_file)
            _need(previous['original_bindings'] == original['bindings'], 'receiver_recovery_failed_inputs_changed')
            outcomes.append(_failed(original, previous['error_code']))
            continue
        verified = retry/'receiver_paid_verified.json'
        if verified.exists():
            saved = _load(verified)
            outcomes.append(_commit(root, record, original, saved['answers'], saved['evidence']))
            continue
        intent = retry/'recovery_dispatch_intent.json'
        unknown_paths = (intent, retry/'paid_dispatch_intent.json',
            retry/'native_paid_one_shot/envelope.json', retry/'native_paid_one_shot/envelope.json.intent.json')
        if any(p.exists() for p in unknown_paths):
            outcomes.append(_failed(original, 'existing_unknown_or_failed_retry_no_replay'))
            continue
        retry.mkdir(parents=True, exist_ok=True)
        _once(intent, {'schema': 'receiver-recovery-dispatch-intent-v1', 'original_bindings': original['bindings'],
            'business_input_sha256': original['business_input_sha256'], 'database': str(original['database']),
            'batch_id': record['delivery']['batch_id'], 'automatic_retry': False})
        _policy_check(root, record)
        try:
            answers, evidence = answer_paid_hy3(original['database'], record['delivery']['batch_id'],
                original['questions'], retry, original['qualification'])
            outcomes.append(_commit(root, record, original, answers, evidence))
        except Exception as error:
            code = str(error)
            outcomes.append(_failed(original, code if code and len(code) <= 200 else 'recovery_execution_failed_no_retry'))
    return outcomes


__all__ = ['run_receiver_recovery', 'ReceiverRecoveryError']
