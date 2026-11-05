"""Adopt an existing completed retry after a local Windows path recheck.

This module has no dispatch path.  Original failed local verification records
remain immutable; the same native attempt receives a separate classification.
"""
from pathlib import Path

from .receiver_recovery import (HERE, ReceiverRecoveryError, _attempt, _bindings,
    _is_candidate, _load, _need, _new_proof, _once, _original, _path, _sha)
from .read_receiver import canonical


def _recheck(root, original, retry, saved):
    path = retry/'offline_recheck_receipt.json'
    receipt = _load(path)
    envelope_path = retry/'native_paid_one_shot/envelope.json'
    job_path = retry/'native_paid_one_shot/job.json'
    envelope = _load(envelope_path)
    _need(receipt.get('schema') == 'persistent-paid-receiver-offline-recheck-v1'
          and receipt.get('newNativeChannelsCalled') == []
          and receipt.get('newNativeChannels') == []
          and receipt.get('newModelPromptsSubmitted') == 0
          and receipt.get('newNativeSessionsCreated') == 0
          and receipt.get('originalNativeArtifactsModified') is False
          and receipt.get('nativeIdentityPathsRewritten') is False,
          'receiver_offline_recheck_must_submit_nothing')
    checks = {
        'originalEnvelopeSha256': _sha(envelope_path.read_bytes()),
        'nativeJobSha256': _sha(job_path.read_bytes()),
        'receiverDbSha256': _sha(original['database'].read_bytes()),
        'questionsSha256': original['questions_sha256'],
        'memorySha256': original['memory_sha256'],
        'businessInputSha256': original['business_input_sha256'],
        'qualificationEnvelopeSha256': original['contract']['qualification']['sha256'],
        'answersFileSha256': _sha((retry/'answers.json').read_bytes()),
        'verifiedCacheFileSha256': _sha((retry/'receiver_paid_verified.json').read_bytes()),
        'nativeHistoryPrefixSha256': envelope.get('nativeHistoryPrefixSha256'),
        'nativeHistoryPrefixBytes': envelope.get('nativeHistoryPrefixBytes'),
    }
    _need(all(receipt.get(key) == value for key, value in checks.items()),
          'receiver_offline_recheck_file_or_context_binding_changed')
    for key, expected in [('originalEnvelopePath', envelope_path), ('nativeJobPath', job_path),
            ('receiverDatabase', original['database']), ('answersPath', retry/'answers.json'),
            ('verifiedCachePath', retry/'receiver_paid_verified.json')]:
        _need(_path(root, receipt.get(key, '')) == expected,
              'receiver_offline_recheck_path_binding_changed')
    _need(receipt.get('batchId') == original['contract']['batch_id'],
          'receiver_offline_recheck_batch_changed')
    preserved = receipt.get('preservedMetadataBindings') or {}
    required = [original['base']/'receiver_recovery_failure.json',
                original['base']/'original_receiver_failed_cost.json', retry/'receiver_attempt_cost.json']
    _need(all(str(p) in preserved for p in required), 'receiver_offline_original_failure_binding_missing')
    bound_paths = [_path(root, name) for name in preserved]
    _need(_bindings(bound_paths) == preserved, 'receiver_offline_preserved_failure_or_cost_changed')
    return path, receipt


def register_verified_receiver_recovery(root, cell_dir):
    """Register one already executed retry, with zero native/model operations."""
    root = Path(root).resolve()
    base = _path(root, cell_dir)
    manifest_file = root/'manifest.json'
    manifest = _load(manifest_file)
    _need(Path(manifest['root']).resolve() == root, 'receiver_offline_manifest_root_changed')
    records = [r for r in manifest['main_records'] if _path(root, r['job_dir']) == base]
    _need(len(records) == 1 and records[0]['receiver_platform'] == 'hy3',
          'receiver_offline_unique_hy3_manifest_record_required')
    record, retry = records[0], base/'provider_retry_01'
    receipt_path = base/'receiver_recovery_offline_receipt.json'
    # A repeated adoption may already have scored_input; all original provider
    # eligibility and byte bindings remain checked through its immutable failure.
    _need(_is_candidate(base) or receipt_path.is_file(), 'receiver_offline_original_not_eligible')
    _need(not (base/'receiver_recovery_receipt.json').exists(), 'receiver_offline_prior_online_adoption_exists')
    _need(not (base/'scored_input.json').exists() or receipt_path.is_file(),
          'receiver_offline_unregistered_score_exists')
    evaluation_file = HERE/'data/evaluation_only.json'
    contract = _load(HERE/'data/contract.json')
    _need(_sha(evaluation_file.read_bytes()) == contract['artifact_sha256']['evaluation_only.json'],
          'receiver_offline_frozen_evaluation_changed')
    original = _original(root, record, _load(evaluation_file))
    plan = _load(root/'receiver_recovery_plan.json')
    progress_file = root/'receiver_progress.first_pass.json'
    if not progress_file.exists():
        progress_file = root/'receiver_progress.json'
    progress = _load(progress_file)
    _need(plan.get('manifest_sha256') == _sha(manifest_file.read_bytes())
          and plan.get('original_progress_sha256') == _sha(progress_file.read_bytes())
          and plan.get('evaluation_sha256') == _sha(evaluation_file.read_bytes())
          and progress.get('planned') == len(manifest['main_records'])
          and progress.get('finished', 0)+progress.get('failed', 0) == len(manifest['main_records'])
          and any(c.get('cell_dir') == str(base) and c.get('bindings') == original['bindings']
                  for c in plan.get('candidates', [])), 'receiver_offline_original_plan_changed')
    failure_path, old_cost_path = base/'receiver_recovery_failure.json', retry/'receiver_attempt_cost.json'
    failure, old_cost = _load(failure_path), _load(old_cost_path)
    _need(failure.get('schema') == 'receiver-provider-recovery-final-failure-v1'
          and failure.get('original_bindings') == original['bindings']
          and failure.get('automatic_retry') is False and failure.get('further_retry_authorized') is False
          and old_cost == _attempt(retry, 1)
          and failure.get('receiver_attempts') == [_attempt(base, 0), old_cost],
          'receiver_offline_preserved_attempt_binding_changed')
    saved = _load(retry/'receiver_paid_verified.json')
    answers, evidence = saved['answers'], saved['evidence']
    new_bindings, schema_valid = _new_proof(root, original, retry, answers, evidence)
    recheck_path, recheck = _recheck(root, original, retry, saved)
    _need(_bindings([Path(p) for p in original['bindings']]) == original['bindings'],
          'receiver_offline_original_changed_during_registration')
    reclassified_path = retry/'receiver_attempt_rechecked_cost.json'
    second = {**_attempt(retry, 1, qualified=True, schema_valid=schema_valid),
        'reclassificationOnly': True, 'newModelPromptsSubmitted': 0,
        'newNativeSessionsCreated': 0, 'nativeChannelsCalled': [],
        'original_attempt_cost_path': str(old_cost_path),
        'original_attempt_cost_sha256': _sha(old_cost_path.read_bytes()),
        'offline_recheck_receipt_path': str(recheck_path),
        'offline_recheck_receipt_sha256': _sha(recheck_path.read_bytes())}
    attempts = [_attempt(base, 0), second]
    completed = {**record, 'answers': answers, 'receiver_evidence': evidence,
        'effective_receiver_job_dir': str(retry), 'receiver_recovery_receipt_path': str(receipt_path),
        'receiver_attempts': attempts}
    receipt = {'schema': 'receiver-provider-recovery-offline-adoption-v1', 'recovery_number': 1,
        'original_job_dir': str(base), 'effective_receiver_job_dir': str(retry),
        'original_bindings': original['bindings'], 'new_verified_bindings': new_bindings,
        'delivery_sha256': _sha(record['delivery']), 'memory_sha256': original['memory_sha256'],
        'questions_sha256': original['questions_sha256'],
        'business_input_sha256': original['business_input_sha256'],
        'logical_snapshot_sha256': original['logical_snapshot_sha256'],
        'original_failure_path': str(failure_path), 'original_failure_sha256': _sha(failure_path.read_bytes()),
        'old_attempt_cost_path': str(old_cost_path), 'old_attempt_cost_sha256': _sha(old_cost_path.read_bytes()),
        'offline_recheck_receipt_path': str(recheck_path),
        'offline_recheck_receipt_sha256': _sha(recheck_path.read_bytes()),
        'rechecked_attempt_cost_path': str(reclassified_path),
        'rechecked_attempt_cost_sha256': _sha(canonical(second)+b'\n'),
        'first_pass_progress_path': str(progress_file), 'first_pass_progress_sha256': _sha(progress_file.read_bytes()),
        'scored_input_sha256': _sha(canonical(completed)+b'\n'), 'receiver_attempts': attempts,
        'newNativeChannels': [], 'newModelPromptsSubmitted': 0, 'newNativeSessionsCreated': 0,
        'reclassificationOnly': True, 'original_failure_and_cost_preserved': True,
        'original_progress_overwritten': False, 'original_inputs_modified': False,
        'automatic_retry': False, 'further_retry_authorized': False,
        'scope': 'local adoption of the already completed first controlled retry; no third model attempt'}
    _once(reclassified_path, second)
    _once(receipt_path, receipt)
    _once(base/'scored_input.json', completed)
    return receipt


__all__ = ['register_verified_receiver_recovery', 'ReceiverRecoveryError']
