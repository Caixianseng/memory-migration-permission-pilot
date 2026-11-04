"""Create this public projection from explicit, non-secret evidence paths.

Maintainer-only: archived results are intentionally absent from the public bundle.
Never opens account snapshots, settings, profiles, logs, headers or credentials.
Use reproduce.py to verify the already exported evidence, without these archives.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import shutil
import zipfile
from pathlib import Path


def sha(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def select(obj, keys):
    return {k: obj[k] for k in keys if k in obj}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-root', type=Path, required=True,
                        help='Repository containing the authorized frozen archives')
    args = parser.parse_args()
    root = args.archive_root.resolve()
    out = Path(__file__).resolve().parent
    base = root / 'results/revocation_rebuild_controlled_20261104'
    data = root / 'experiments/revocation_rebuild_controlled_20261104/data'

    def read(path):
        return json.loads(path.read_text(encoding='utf-8-sig'))

    def save(name, obj):
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf-8')

    aggregate = read(base / 'review/main_v2_cost_aggregate.json')
    formal = read(base / 'live_run02/formal_summary.json')
    semantic = read(base / 'review/semantic_review.json')
    security = read(base / 'review/security_review.json')
    external_security = read(base / 'review/external_security_review.json')
    materials = {'human_gold': None, 'provenance': read(data / 'data_manifest.json')['provenance']}
    for key, rel in [('formal_sources', 'source_only/sources.json'),
                     ('formal_questions', 'questions.json'),
                     ('formal_policy', 'policy_schedule.json'),
                     ('qualification_sources', 'qualification_fixture/source_only/sources.json'),
                     ('qualification_questions', 'qualification_fixture/questions.json'),
                     ('qualification_policy', 'qualification_fixture/policy_schedule.json')]:
        materials[key] = read(data / rel)
    save('materials.json', materials)

    # Exact SDK messages are retained once per job; repeated system text is shared.
    # Original message UUIDs are local request metadata, never account identities.
    templates = {}
    jobs = []

    def project_job(directory, metadata):
        receipt_path = directory / 'sdk/sdk_receipt.json'
        receipt = read(receipt_path)
        options = receipt['actual_options']
        messages = options['messages']
        system = messages[0]['content'][0]['text']
        template_id = sha(system)
        templates[template_id] = system
        user = messages[1]['content'][0]['text']
        job = {**metadata, **select(receipt, ['job_id', 'role', 'status', 'request_id',
               'sdk_stream_attempts', 'sdk_provider_dispatch_count', 'stop_reason', 'usage',
               'provider_actual_model', 'provider_response_id', 'system_fingerprint'])}
        job['settings'] = select(options, ['maxTokens', 'model', 'provider', 'reasoningEffort', 'tools'])
        job['system_template_id'] = template_id
        job['message_metadata'] = [select(m, ['id', 'role', 'source']) for m in messages]
        job['user_message'] = user
        job['user_message_sha256'] = sha(user)
        job['output'] = receipt['output']
        job['output_sha256'] = sha(receipt['output'])
        job['actual_options_sha256'] = receipt['actual_options_sha256']
        job['archive_sdk_receipt_sha256'] = sha(receipt_path.read_bytes())
        job['settlement'] = select(read(directory / 'settlement.json'), ['input_tokens',
            'output_tokens', 'peak_cost_upper_cny', 'reserved_cny', 'status', 'invoice_cny',
            'provider_physical_requests', 'receipt_sha256'])
        job['reservation'] = select(read(directory / 'reservation.json'), ['input_token_bound',
            'max_output_tokens', 'reserved_cny', 'role', 'raw_invoice_cny'])
        # Process termination is distinct from sealed successful SDK completion.
        job['process'] = select(read(directory / 'process.json'), ['returncode', 'exit_code',
            'parent_terminated_after_sealed_receipt', 'receipt_complete', 'timed_out'])
        jobs.append(job)
        return job

    for row in aggregate['jobs']:
        metadata = select(row, ['kind', 'story_id', 'method', 'artifact', 'view',
            'source_reused_by_branch_ids', 'source_cost_charged_once'])
        project_job(base / 'live_run02/budget' / ('job-' + row['job_id']), metadata)
    external_job = project_job(base / 'external_live02/target_budget/job-external-qual-target',
        {'kind': 'external_qualification', 'story_id': 'qualification_fixture', 'method': None,
         'artifact': None, 'view': 'revoke_critical'})
    groups = defaultdict(list)
    for job in jobs:
        groups[(job['kind'], job['story_id'], job['role'])].append(job)
    job_files = []
    for (kind, story, role), rows in sorted(groups.items()):
        chunks = [[]]
        for row in rows:
            candidate = chunks[-1] + [row]
            if len(json.dumps({'jobs': candidate}, ensure_ascii=False, indent=2).encode('utf-8')) > 48000:
                chunks.append([])
            chunks[-1].append(row)
        for number, chunk in enumerate(chunks, 1):
            name = f'sdk_jobs/{kind}_{story}_{role}_{number:02d}.json'
            save(name, {'jobs': chunk})
            job_files.append(name)
    save('sdk_jobs.json', {'schema': 'public-sdk-evidence-projection-v1',
                         'system_templates': templates, 'job_files': job_files})

    # Host packets / HMAC values and native logs are deliberately not exported.
    stories = []
    for story in formal['stories']:
        branches = []
        for branch_id, branch in story['branches'].items():
            row = {**branch, 'branch_id': branch_id}
            if branch['status'] == 'delivered':
                directory = base / 'live_run02/formal' / story['case_id'] / 'branches' / branch_id
                envelope = read(directory / 'delivery_prepared.json')['envelope']
                row['host_envelope'] = select(envelope, ['memory_hash', 'memory_sha256',
                    'artifact_ids', 'source_ids', 'output_hashes', 'policy_revision', 'recipient'])
                callback = read(directory / 'target_callback_receipt.json')
                row['sdk_job_id'] = callback['job_id']
                assert sha(json.loads(callback['actual_options']['messages'][1]['content'][0]['text'])['memory']) == row['memory_hash']
            branches.append(row)
        stories.append({'story_id': story['case_id'], 'source_calls': story['source_calls'],
                        'branches': branches})
    save('formal_delivery.json', {'schema': 'public-host-delivery-projection-v1', 'stories': stories})

    qkeys = ['answer_id', 'policy_legally_answerable', 'actual_delivery_memory_sufficient',
             'memory_support_kind', 'semantic_judgment', 'primary_semantic_credit',
             'legitimate_answer_credit', 'correct_missing_evidence_abstention', 'rationale',
             'unsupported_additional_assertions', 'negation_subject_or_condition_error',
             'calendar_or_quantity_error', 'revoked_value_disclosed', 'wording_reservation_ids']
    question_files = []
    for story in formal['stories']:
        name = f'ai_review/{story["case_id"]}.json'
        save(name, {'question_reviews': [select(row, qkeys) for row in semantic['question_reviews']
                                       if row['story_id'] == story['case_id']]})
        question_files.append(name)
    save('ai_review.json', {'schema': 'public-ai-review-projection-v1', 'human_gold': None,
        **select(semantic, ['status', 'human_review_completed', 'reviewer_disclosure', 'method',
                            'summary', 'per_method', 'reservations', 'limitations']),
        'question_files': question_files,
        'blocked_cells': [select(row, ['cell_id', 'status', 'reason', 'target_callback_invocations',
            'actual_target_output', 'synthetic_UNKNOWN_answers_created', 'legal_question_ids',
            'policy_missing_evidence_question_ids']) for row in semantic['blocked_cells']]})
    save('accounting_reference.json', {**select(aggregate, ['cost_basis', 'by_method', 'by_story',
        'formal_total', 'qualification_total', 'live_run02_combined_total', 'allocation']),
        'human_gold': None, 'scope': aggregate['scope']})
    save('security_review_summary.json', {
        'kind': 'archived_review_claims_not_full_native_reverification',
        'formal': select(security, ['schema', 'status', 'counts', 'limitations']),
        'external': select(external_security, ['schema', 'status', 'scope', 'event_chain',
            'limitations', 'old_M', 'rebuilt_R', 'source_reviews', 'target'])})

    external = select(read(base / 'external_live02/external_qualification_result.json'),
        ['schema', 'status', 'human_gold', 'independent_human_assessment', 'actual_answers',
         'deterministic_checks', 'old_M_rejected', 'hy3_logical_attempts', 'sdk_target_attempts',
         'hy3_cost_cny', 'provider_physical_requests', 'pool_with_main_experiment',
         'external_validation_only', 'algorithm_advantage'])
    external['sdk_job_id'] = external_job['job_id']
    external['hy3_sources'] = []
    for artifact in ['M', 'R']:
        directory = base / 'external_live02/host/generation' / artifact
        prompt = read(directory / 'adapter/prompt.json')
        observation = read(directory / 'adapter/observation.json')
        receipt = read(directory / 'adapter/receipt.json')
        output = (directory / 'adapter/output.txt').read_text(encoding='utf-8')
        external['hy3_sources'].append({'artifact': artifact,
            'input': read(directory / 'input.json'), 'submitted_prompt': prompt['prompt'],
            'submitted_prompt_sha256': prompt['sha256'], 'output': output,
            'observation': select(observation, ['input_sha256', 'output_sha256', 'source_ids',
                'model_id', 'trace_kind', 'new_native_session_created', 'opaque_provider_context_verified']),
            'receipt': select(receipt, ['schema', 'status', 'accepted', 'modelId', 'runtimeSource',
                'outputOrigin', 'savedBy', 'modelNativeFileWrite', 'queueTaskSubmissions',
                'nativePromptSubmissions', 'providerModelCalls', 'actualCostCny',
                'automaticRetryAllowed', 'opaqueProviderContextInspected', 'outputSha256']),
            'native_reply_proof_summary': select(read(directory / 'adapter/native_reply_proof.json'),
                ['assistantStepSeq', 'transcriptSha256', 'submittedPromptSha256', 'promptOccurrences',
                 'visibleFunctionCallCount', 'zeroVisibleToolsVerified', 'sameConversationRequest',
                 'modelId', 'outputSha256', 'rowCount', 'evidenceScope', 'hiddenProviderContextVerified',
                 'nativeIdleVerified', 'nativeIdlenessObservedTwice', 'stableSnapshotCount', 'stabilityWindowMs'])})
    external['sdk_qualification'] = read(base / 'live_run02/qualification/qualification_result.json')
    save('qualification.json', external)

    blind = base / 'review/人工复核包/仅发复核人_60条.zip'
    with zipfile.ZipFile(blind) as archive:
        for name in archive.namelist():
            assert not any(word in name.lower() for word in ['mapping', 'admin', 'private', '管理', '映射'])
    shutil.copyfile(blind, out / 'human_rater_only_60.zip')
    files = {p.relative_to(out).as_posix(): sha(p.read_bytes())
             for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'manifest.json'}
    save('manifest.json', {'schema': 'public-bundle-sha256-manifest-v1', 'files_sha256': files})
    print('Exported explicit evidence projections only; no private runtime files copied.')


if __name__ == '__main__':
    main()
