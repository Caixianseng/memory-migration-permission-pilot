"""Whitelist export and offline verification of the synthetic exchange pilot.

Export reads only the named experiment's local result files and its read-only
receiver batches. Verification uses public JSON only: no model, network, native
client, login, database or private provider history is accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
DEFAULT_OUTPUT = REPO / 'benchmarks/persistent_exchange_v1_public_20261105'
DATA = REPO / 'experiments/persistent_exchange_v1/data'


def load(path):
    return json.loads(Path(path).read_bytes())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pick(value, fields):
    return {key: value[key] for key in fields if key in value}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def local_file(root, name):
    text = str(name)
    if text.startswith('\\\\?\\'):
        text = text[4:]
    path = Path(text)
    path = path if path.is_absolute() else root / path
    path = path.resolve(strict=True)
    require(path.is_relative_to(root), 'input outside declared experiment')
    require(not any(p.casefold() in {'sdk.private', 'home.private'} for p in path.parts),
            'private provider directory forbidden')
    return path


def public_safety(raw, label):
    text = raw.decode('utf-8')
    checks = {
        'absolute_windows_path': r'(?i)\b[a-z]:[\\/]',
        'absolute_user_path': r'(?i)/(?:Users|home)/[^\s/]+/',
        'session_uuid': r'(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b',
        'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        'provider_api_key': r'\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b',
        'bearer_credential': r'(?i)bearer\s+[A-Za-z0-9._-]{24,}',
        'worker_lease_value': r'(?i)["\'](?:leaseToken|workerLease|access_token|refresh_token)["\']\s*:\s*["\'][^"\']+["\']',
    }
    for kind, pattern in checks.items():
        require(re.search(pattern, text) is None, f'public export rejected {kind}: {label}')


def write_json(output, name, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                      allow_nan=False) + '\n').encode('utf-8')
    write_raw(output, name, raw)


def write_raw(output, name, raw):
    public_safety(raw, name)
    with (output / name).open('xb') as stream:
        stream.write(raw)


LEDGER_FIELDS = (
    'artifact_count', 'platform_jobs', 'source_jobs', 'logical_source_attempts',
    'receiver_jobs', 'source_phase_jobs', 'source_attempt_outcomes',
    'successful_source_memory_jobs', 'source_protocol_failed_jobs',
    'native_source_shell_scope_failed_jobs', 'original_input_characters',
    'original_input_source_count', 'parent_input_characters',
    'serialized_source_business_input_bytes', 'source_output_memory_bytes',
    'source_observed_partial_output_bytes_not_usable_memory',
    'receiver_presented_memory_bytes', 'flash_physical_supplier_calls',
    'flash_known_physical_supplier_calls', 'flash_physical_request_count_unknown_attempts',
    'flash_usage_unknown_attempts', 'flash_native_tokens', 'flash_native_tokens_scope',
    'flash_estimated_cold_peak_cny', 'flash_estimated_cache_aware_peak_cny',
    'flash_estimates_are_supplier_bill', 'hy3_native_direct_session_submissions',
    'hy3_native_queue_submissions', 'hy3_native_tasks', 'hy3_native_tasks_scope',
    'hy3_pre_model_zero_submission_source_attempts',
    'hy3_queue_submission_without_verified_model_execution',
    'model_submission_count_unknown_attempts', 'hy3_physical_supplier_calls',
    'all_platform_physical_supplier_calls', 'workbuddy_supplier_fee_cny',
    'all_platform_supplier_fee_cny', 'supplemental_existing_session_continuation_turns',
    'supplemental_continuation_input_volume_unknown_turns',
    'sum_source_job_wall_ms', 'receiver_wall_ms', 'source_wall_sum_is_parallel_elapsed_time',
)
IDENTITY_FIELDS = (
    'platform', 'actual_model', 'actual_models', 'request_model_ids',
    'canonical_model_family', 'billing_route_ids', 'provider_identity_verified',
    'native_tasks', 'native_direct_session_submissions', 'native_queue_submissions',
    'physical_supplier_calls', 'supplier_fee_cny', 'token_usage',
    'estimated_cold_peak_cny', 'estimated_cache_aware_peak_cny',
)


def export(root, output):
    from experiments.persistent_exchange_v1.read_receiver import read_batch
    from experiments.persistent_exchange_v1.evaluate import evaluate

    root = root.resolve(strict=True)
    require(not output.exists(), 'output must not exist; use --verify for the published bundle')
    archive_names = (
        'manifest.json', 'main_records.json', 'audit_and_ledger.json',
        'evaluation_with_payload.json', 'security_probes.json', 'mechanisms/records.json',
        'completion_receipt.json', 'fixed_chunk_impact_description.json',
    )
    archives = {name: load(root / name) for name in archive_names}
    audit, original_score = archives['audit_and_ledger.json'], archives['evaluation_with_payload.json']
    manifest, original_records = archives['manifest.json'], archives['main_records.json']
    require(audit['status'] == 'audited' and len(original_records) == 96, 'complete audited study required')
    require(audit['independent_project_clusters'] == 12, 'twelve project clusters required')
    source_rows = [row for row in audit['main_jobs'] if row['kind'] == 'source']
    require(len(source_rows) == 132, 'all 132 source attempts must remain visible')
    source_id = {}
    source_attempts = []
    for index, row in enumerate(source_rows, 1):
        path = local_file(root, row['result_file'])
        raw, value = path.read_bytes(), load(path)
        require(sha(raw) == row['result_sha256'], 'original source hash mismatch')
        sid = f'source-attempt-{index:03d}'
        source_id[path] = sid
        item = {'attempt_id': sid, **pick(value, ('case_id', 'agent', 'platform', 'phase',
                'group', 'budget', 'source_ids', 'memory')),
                **pick(row, ('effective_for_study', 'source_attempt_status',
                'source_protocol_conformance', 'usable_generated_memory')),
                'original_result_sha256': sha(raw),
                'memory_text_sha256': sha(value['memory'].encode('utf-8')) if isinstance(value['memory'], str) else None,
                'reported_identity_and_usage': pick(row['identity'], IDENTITY_FIELDS)}
        source_attempts.append(item)
    require(set(source_id) == {local_file(root, p) for p in manifest['source_physical_results']},
            'source attempt list differs from frozen manifest')

    public_records = []
    for record in original_records:
        delivery, evidence = record['delivery'], record['receiver_evidence']
        database = local_file(root, delivery['receiver_db'])
        readback = read_batch(database, delivery['batch_id'])
        memory = readback['payload']['memory']
        require(sha(memory.encode('utf-8')) == delivery['reopened_content_sha256'], 'receiver payload mismatch')
        answer_raw = local_file(root, evidence['raw_answers_path']).read_bytes()
        require(sha(answer_raw) == evidence['answers_sha256'], 'original answer hash mismatch')
        require(json.loads(answer_raw) == record['answers'], 'parsed original answer mismatch')
        item = {**pick(record, ('case_id', 'direction', 'arm', 'recipient', 'receiver_platform', 'answers', 'timings')),
            'received_memory': memory, 'answers_raw_utf8': answer_raw.decode('utf-8'),
            'answers_raw_sha256': sha(answer_raw),
            'source_jobs': [source_id[local_file(root, p)] for p in record['source_jobs']],
            'delivery': pick(delivery, ('policy_epoch', 'packet_bytes', 'content_bytes',
                'dependencies', 'source_protocol_clean', 'reopened_content_sha256',
                'close_reopen_verified', 'export_import_reopen_ms')),
            'receiver_evidence': {
                **pick(evidence, ('platform', 'actual_model', 'actual_models', 'request_model_ids',
                    'canonical_model_family', 'billing_route_ids', 'status', 'answers_schema_valid',
                    'answer_schema_failure', 'physical_supplier_calls', 'workbuddy_fee_cny',
                    'input_tokens', 'output_tokens', 'automatic_retry', 'execution_mode',
                    'reader_process_boundary')),
                'reader_receipt': pick(evidence['reader_receipt'],
                    ('sqlite_uri_mode', 'query_only', 'rendered_memory_sha256'))}}
        public_records.append(item)

    rescored = evaluate(public_records, load(DATA / 'evaluation_only.json'))
    original_core = {key: value for key, value in original_score.items()
                     if key != 'source_protocol_clean_supplement'}
    require(rescored == original_core, 'public projection changed the complete frozen score or intervals')

    output.mkdir(parents=True)
    for name in ('evaluation_only.json', 'cases.public.jsonl', 'contract.json', 'mechanism_spec.json'):
        write_raw(output, name, (DATA / name).read_bytes())
    write_json(output, 'records.public.json', public_records)
    write_json(output, 'source_attempts.public.json', source_attempts)
    write_json(output, 'evaluation_report.public.json', original_score)
    clean = original_score['source_protocol_clean_supplement']
    public_audit = {
        'schema': 'persistent-exchange-public-audit-projection-v1',
        'local_audit_status_reported': audit['status'],
        'scope': 'whitelist projection of local audit; not an independently rerun native execution audit',
        'independent_project_clusters': 12, 'main_conditions': 96,
        'main_physical_ledger': pick(audit['main_physical_ledger'], LEDGER_FIELDS),
        'main_logical_per_method_ledger': {arm: pick(value, LEDGER_FIELDS)
            for arm, value in audit['main_logical_per_method_ledger'].items()},
        'source_recovery_registry': pick(audit['source_recovery_registry'],
            ('logical_source_cells', 'physical_source_result_attempts', 'registered_effective_recoveries',
             'late_continuation_events_separate_from_source_result_count', 'late_output_used_for_quality_or_selection')),
        'source_protocol_audit': pick(audit['source_protocol_audit'],
            ('arm_view_rejections_by_arm', 'arm_views_with_selected_source_protocol_rejections',
             'bound_native_shell_scope_audits', 'bound_native_shell_scope_failures',
             'closed_failed_source_attempt_count', 'failed_physical_source_job_count',
             'failed_selected_artifacts_filtered_before_export', 'main_record_count_retained',
             'no_sample_replacement_or_new_generation_for_protocol_failure',
             'retained_in_physical_and_logical_resource_ledgers', 'source_attempt_outcomes',
             'successful_approved_source_memory_count')),
        'receiver_recovery': {'original_terminal_provider_500_without_answer': 2,
            'controlled_new_receiver_attempts': 2, 'local_rechecks_new_model_prompts': 0,
            'total_receiver_outer_attempts': 98, 'workbuddy_unique_direct_receiver_sessions': 50,
            'original_failures_retained_in_ledger': True},
        'supplemental_native_continuation_ledger': pick(audit['supplemental_native_continuation_ledger'], LEDGER_FIELDS),
        'supplemental_native_continuations': [pick(value, ('schema', 'event_sha256',
            'actual_models', 'request_model_ids', 'native_additional_continuation_turns',
            'late_artifact_adopted_for_study', 'registered_replacement_selection_changed',
            'new_source_result_records', 'qualified_study_source_results', 'physical_supplier_calls',
            'supplier_fee_cny', 'input_tokens', 'output_tokens', 'native_turn_is_one_supplier_request'))
            for value in audit['supplemental_native_continuations']],
        'source_protocol_clean_supplement': clean,
        'ledger_interpretation': audit['ledger_interpretation'],
        'raw_native_evidence_publicly_included': False,
    }
    write_json(output, 'audit_summary.public.json', public_audit)
    security = archives['security_probes.json']
    write_json(output, 'security_probes.public.json', {
        'schema': 'persistent-exchange-public-security-projection-v1',
        'scope': security['scope'], 'summary': security['summary'],
        'model_invocations': security['model_invocations'], 'new_real_deliveries': security['new_real_deliveries'],
        'permission_checks': [pick(row, ('case_id', 'direction', 'recipient', 'sender',
            'revoked_source_count', 'expected_permission_result', 'permission_result',
            'matches_expected_permission_result', 'source_protocol_conformance',
            'actual_generated_memory_available', 'artifact_sha256', 'source_result_sha256'))
            for row in security['old_whole_permission_checks']],
        'packet_copy_attacks': [{**pick(row, ('case_id', 'direction', 'approved_arm', 'available',
            'approved_packet_file_sha256', 'approved_packet_sha256',
            'all_attacks_use_disposable_policy_and_receiver_copies')),
            'probes': [pick(probe, ('probe', 'rejected', 'expected_reason', 'reason', 'passed',
                'isolated_copy_only', 'no_partial_receiver_writes', 'model_invocations'))
                for probe in row['probes']]} for row in security['approved_packet_copy_attacks']],
        'interpretation': security['interpretation'],
        'raw_database_and_native_receipts_included': False})
    mechanism = audit['mechanisms']
    write_json(output, 'mechanism_probes.public.json', {
        'schema': 'persistent-exchange-public-mechanism-projection-v1',
        'local_audit_status_reported': mechanism['status'], 'excluded_from_main': True,
        'probe_results': mechanism['probe_results'],
        'physical_ledger': pick(mechanism['physical_ledger'], LEDGER_FIELDS),
        'answers': [{**pick(row, ('mechanism_id', 'case_id', 'direction', 'arm', 'answers')),
            'actual_models': row['receiver_evidence'].get('actual_models'),
            'receiver_status': row['receiver_evidence']['status']}
            for row in archives['mechanisms/records.json']],
        'raw_database_and_native_receipts_included': False})
    write_json(output, 'fixed_chunk_impact.public.json', archives['fixed_chunk_impact_description.json'])
    readme = '''# Persistent bidirectional memory exchange public results 2026-11-05

This bundle publishes synthetic task data, actual model answer text, actual
received memory text, source-output projections, and reported audit summaries
from 12 independent projects, 96 conditions and four comparison arms. It does
not contain commercial-client native histories, account/session identifiers,
queue leases, credentials, provider-private directories, or SQLite databases.

The full frozen offline scorer can be rerun without model access:

```sh
python scripts/export_persistent_exchange_public.py --verify
```

Run this from the repository root. Python 3.11 or newer and the standard library
are sufficient for verification. It imports the unchanged scorer at
`experiments/persistent_exchange_v1/evaluate.py`. No network, client login,
database or model call occurs. The verifier compares every core report field,
including all per-question/per-project scores, resources and paired-bootstrap
intervals, with `evaluation_report.public.json`.

## Files and evidence boundaries

- `records.public.json`: 96 parsed answers, exact original answer UTF-8 text and
  hashes, received payload text, and minimal reported readback fields. Source
  references are public attempt identifiers, not executable file paths.
- `source_attempts.public.json`: all 132 source-result attempts, including
  failed/closed outputs, source IDs and original local result-file hashes.
  Provider-private partial streams are not included. A reported model identity
  remains unknown when the archived attempt had no verified identity.
- `cases.public.jsonl`, `evaluation_only.json`, `contract.json`, and
  `mechanism_spec.json`: byte-preserved synthetic fixtures and frozen scoring
  definitions. Evaluation references are public now; they were not supplied to
  source/receiver models during the experiment.
- `evaluation_report.public.json`: complete offline task scores. The
  source-protocol-clean supplement is an archived local-audit result; rerunning
  the public scorer verifies the core comparison, not that native audit.
- `audit_summary.public.json`: whitelist cost/failure/protocol counters. There
  are 132 source-result attempts and 98 receiver outer attempts, representing
  96 completed main conditions. A separate late continuation is not a new
  source-result record and its text was not adopted. Local rechecks are not new
  model calls. WorkBuddy fees and supplier physical requests remain unknown;
  Flash price-derived estimates are not supplier bills.
- `security_probes.public.json`: 24 old-whole permission views and 72 isolated
  packet-copy attack outcomes, with no real extra model invocation or delivery.
- `mechanism_probes.public.json`: two real multilayer return probes, reported
  independently from the twelve-project primary comparison.
- `fixed_chunk_impact.public.json`: post-hoc descriptive invalidation counts,
  not a pre-registered replacement algorithm result.
- `provenance_manifest.json`: public artifact hashes, frozen evaluator/fixture
  hashes, original local archive hashes, availability and exclusion notes.
- `verification.json`: export-time comparison and bounded sensitive-pattern
  checks. This does not replace an independent native execution audit.

## Result and statistical scope

Project-weighted lawful-task scores were raw 100%, whole-drop 20.83%, full
rebuild 86.46%, selective 77.72%. The fixed two-hash-chunk candidate failed the
predeclared engineering screen; the proposed permission/semantic joint D1
grouping was not evaluated. All four arms had zero exact withheld-value hits
in the observed payloads and answers. That is not a semantic noninterference
proof. Lexical required-value coverage is not a full hallucination audit.
The independent unit is twelve projects, not 96 conditions or 768 answers.

Native-client evidence, private transport traces and databases remain local
because they can contain account- or execution-specific metadata. Hashes bind
the public projection to that archive but do not make the omitted evidence
publicly re-auditable. This bundle supports transparent offline re-scoring,
not a claim that fresh WorkBuddy/Harness runs are byte-identical or available
without the documented client setup.

These task fixtures are project-generated synthetic materials. No third-party
private corpus, publisher PDF, model weight, or new third-party licence is
bundled. No additional licence grant is inferred by this export; consult the
repository's stated licensing terms before reuse.
'''
    write_raw(output, 'README.md', readme.encode('utf-8'))
    verification = {'schema': 'persistent-exchange-public-export-check-v1',
        'complete_core_evaluation_equal_to_archived_final': True,
        'original_answer_hashes_verified': 96, 'original_receiver_payload_hashes_verified': 96,
        'original_source_result_hashes_verified': 132, 'source_attempt_reference_count_preserved': True,
        'evaluator_changed': False, 'new_model_prompts': 0, 'new_real_deliveries': 0,
        'public_native_execution_audit_claimed': False,
        'sensitive_pattern_scan': 'passed; bounded scan plus field whitelist, not a universal detector'}
    write_json(output, 'verification.json', verification)
    provenance = {'schema': 'persistent-exchange-public-provenance-v1', 'release_date': '2026-11-05',
        'repository': 'https://github.com/Caixianseng/memory-migration-permission-pilot',
        'materials': 'project-generated synthetic tasks and model outputs',
        'availability': {'public': 'whitelist synthetic fixtures, answer/payload text, source-output projections, scores and summary counters',
            'not_public': 'native client histories, provider-private traces, queue credentials, execution identifiers and databases',
            'original_evidence_location': 'local experiment archive; hashes below do not constitute public access'},
        'scope': 'offline scoring reproducibility; original native execution audit is reported, not independently reproduced here',
        'original_archive_sha256': {name: sha((root / name).read_bytes()) for name in archive_names},
        'fixture_sha256': {name: sha((DATA / name).read_bytes()) for name in
            ('evaluation_only.json', 'cases.public.jsonl', 'contract.json', 'mechanism_spec.json')},
        'frozen_evaluator_repository_path': 'experiments/persistent_exchange_v1/evaluate.py',
        'frozen_evaluator_sha256': sha((REPO / 'experiments/persistent_exchange_v1/evaluate.py').read_bytes()),
        'exporter_repository_path': 'scripts/export_persistent_exchange_public.py',
        'exporter_sha256': sha(Path(__file__).read_bytes()),
        'public_artifact_sha256': {path.name: sha(path.read_bytes()) for path in sorted(output.iterdir())},
        'unknown_costs_are_zero': False, 'additional_licence_inferred': False}
    write_json(output, 'provenance_manifest.json', provenance)
    return verify(output)


def verify(output):
    from experiments.persistent_exchange_v1.evaluate import evaluate

    manifest = load(output / 'provenance_manifest.json')
    files = manifest['public_artifact_sha256']
    require(set(files) | {'provenance_manifest.json'} == {p.name for p in output.iterdir()},
            'unexpected or missing public artifact')
    for name, expected in files.items():
        raw = (output / name).read_bytes()
        require(sha(raw) == expected, 'public artifact hash mismatch: ' + name)
        public_safety(raw, name)
    public_safety((output / 'provenance_manifest.json').read_bytes(), 'provenance_manifest.json')
    evaluator = REPO / manifest['frozen_evaluator_repository_path']
    require(sha(evaluator.read_bytes()) == manifest['frozen_evaluator_sha256'], 'frozen evaluator changed')
    for name, expected in manifest['fixture_sha256'].items():
        require(sha((output / name).read_bytes()) == expected, 'fixture changed: ' + name)
    records, reported = load(output / 'records.public.json'), load(output / 'evaluation_report.public.json')
    for record in records:
        raw = record['answers_raw_utf8'].encode('utf-8')
        require(sha(raw) == record['answers_raw_sha256'], 'public answer raw hash mismatch')
        require(json.loads(raw) == record['answers'], 'public answer parsed mapping mismatch')
        require(sha(record['received_memory'].encode('utf-8')) == record['delivery']['reopened_content_sha256'],
                'public payload text hash mismatch')
    result = evaluate(records, load(output / 'evaluation_only.json'))
    expected = {key: value for key, value in reported.items() if key != 'source_protocol_clean_supplement'}
    require(result == expected, 'public re-scoring differs from complete frozen core report')
    attempts = load(output / 'source_attempts.public.json')
    require(len(attempts) == 132 and len({x['attempt_id'] for x in attempts}) == 132,
            'source attempts must remain complete and unique')
    known = {x['attempt_id'] for x in attempts}
    require(all(set(r['source_jobs']) <= known for r in records), 'unknown source-attempt reference')
    for attempt in attempts:
        if isinstance(attempt.get('memory'), str):
            require(sha(attempt['memory'].encode('utf-8')) == attempt['memory_text_sha256'],
                    'public source memory text hash mismatch')
    audit = load(output / 'audit_summary.public.json')
    require(audit['main_physical_ledger']['all_platform_supplier_fee_cny'] is None,
            'unknown total supplier fee must remain unknown')
    return {'status': 'verified', 'public_files': len(files) + 1,
        'main_conditions': len(records), 'source_result_attempts': len(attempts),
        'independent_project_clusters': result['independent_project_clusters'],
        'complete_core_scores_and_intervals_match': True,
        'new_model_prompts': 0, 'new_network_calls': 0,
        'native_execution_audit_reproduced': False,
        'legal_utility': {arm: row['legal_utility'] for arm, row in result['summary'].items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true', help='verify public bundle only; no database/client access')
    parser.add_argument('--results-root', type=Path, default=REPO / 'results/persistent_exchange_v1')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = verify(args.output.resolve()) if args.verify else export(args.results_root, args.output.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
