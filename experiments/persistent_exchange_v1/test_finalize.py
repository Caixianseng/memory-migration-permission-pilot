"""Offline mock artifacts exercise audit logic, never substitute real results."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import finalize as audit


class FakePolicy:
    epoch = 7

    def __init__(self, path):
        self.path = path

    def check_dependencies(self, recipient, dependencies, epoch):
        if epoch != self.epoch:
            raise AssertionError('unexpected audit epoch')

    def close(self):
        pass


class PersistentExchangeFinalAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluation = audit._load(audit.HERE / 'data/evaluation_only.json')
        cls.cases = [json.loads(line) for line in (audit.HERE / 'data/cases.public.jsonl').read_text(encoding='utf-8').splitlines()]

    def save(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2), encoding='utf-8')

    def mock_scope(self, result_path, *, conformance=True, issues=None):
        result = audit._load(result_path)
        evidence = result['evidence']
        self.save(result_path.parent / 'native_source_shell_scope_audit.json', {
            'schema': 'native-source-shell-scope-audit-v1', 'session_id': evidence['session_id'],
            'task_id': evidence['task_id'], 'source_result_sha256': audit._sha(result_path.read_bytes()),
            'artifact_sha256': evidence['artifact_sha256'], 'protocol_conformance': conformance,
            'issues': issues or [], 'command_counts': {'mock_commands': 0},
            'full_remote_input_attestation': False, 'fixture_scope': 'MOCK TEST ONLY'})

    def receipt(self, output, tag, messages=None):
        usage = {'inputTokens': 10, 'cacheReadTokens': 20, 'cacheWriteTokens': 0,
                 'outputTokens': 5, 'totalTokens': 35}
        tokens, peak, cached = audit.usage_costs(usage)
        return {'status': 'ok', 'actual_model': 'deepseek-flash', 'provider': 'deepseek-account',
                'physical_request_count': 1, 'temporary_credentials_removed': True,
                'response_sha256': audit._sha(output), 'cost_is_supplier_bill': False,
                'usage': usage, **tokens, 'estimated_peak_cost_cny': str(peak),
                'estimated_cache_aware_peak_cost_cny': str(cached),
                'request_sha256': audit._sha(tag + '-request'),
                'business_messages_sha256': audit._sha(messages) if messages is not None else audit._sha(tag + '-messages'),
                'dispatch_sha256': audit._sha(audit.dispatch_text(messages)) if messages is not None else audit._sha(tag + '-dispatch'),
                'session_id': tag + '-session', 'request_id': tag + '-request'}

    def fixture(self, root, failed_sources=(), pre_model_sources=(), truncated_sources=(), terminal_sources=(), scope_failures=()):
        # These are explicitly synthetic *mock* model artifacts for unit tests.
        plans = audit._planned_jobs(root, self.cases)
        results = {}
        for path, plan in plans.items():
            folder = path.parent
            supplied = {'sources': plan['sources'], 'parent_memories': [],
                        'max_memory_characters': 4096 if plan['group'] == 'whole' else 2048,
                        'length_limit_scope': 'mock test input'}
            self.save(folder / 'sources.json', supplied)
            raw = (folder / 'sources.json').read_bytes()
            memory = '\n'.join(source['text'] for source in plan['sources'])
            tag = audit._sha(str(path))
            key = (plan['case_id'], plan['agent'], plan['phase'], plan['group'])
            if plan['platform'] == 'hy3':
                if key in terminal_sources:
                    self.save(folder / 'native_job.json', {'taskId': tag + '-task', 'sessionId': tag})
                    self.save(folder / 'submission_intent.json', {'task_id': tag + '-task'})
                    self.save(folder / 'task_state_1.json', {'task': {'taskId': tag + '-task', 'sessionId': tag, 'state': 'blocked'}})
                    evidence = {'platform': 'WorkBuddy native queue', 'expected_model': 'hy3',
                                'actual_models': [], 'request_model_ids': [], 'provider_identity_verified': False,
                                'source_protocol_conformance': False, 'model_attempt_closed': True,
                                'native_task_submitted': True, 'task_id': tag + '-task', 'session_id': tag,
                                'protocol_issues': ['native_queue_terminal_blocked_without_generated_artifact'],
                                'physical_supplier_calls': None, 'workbuddy_physical_supplier_calls': None,
                                'workbuddy_fee_cny': None, 'native_history_prefix_sha256': audit._sha(tag + '-history'),
                                'artifact_sha256': None, 'native_queue_state': 'blocked',
                                'protocol_failure_action': 'no verified source execution or memory; fail closed; preserve unknown usage; no replay'}
                    self.save(folder / 'native_terminal_closed.json', evidence)
                    memory = None
                elif key in pre_model_sources:
                    self.save(folder / 'created.json', {'status': 'creation_unverified', 'modelPromptsSubmitted': 0})
                    evidence = {'platform': 'WorkBuddy native HY3', 'actual_models': [], 'request_model_ids': [],
                                'expected_model': 'hy3', 'source_protocol_conformance': False, 'model_attempt_closed': True,
                                'protocol_issues': ['native_session_creation_failed_before_model_dispatch'],
                                'model_prompts_submitted': 0, 'physical_supplier_calls': 0, 'workbuddy_fee_cny': None,
                                'workbuddy_physical_supplier_calls': 0, 'artifact_sha256': None,
                                'creation_sha256': audit._sha((folder / 'created.json').read_bytes()),
                                'protocol_failure_action': 'no generated memory; fail closed; do not replay uncertain creation'}
                    self.save(folder / 'native_creation_closed.json', evidence)
                    memory = None
                else:
                    self.save(folder / 'memory.json', {'memory': memory})
                    evidence = {'actual_models': ['hy3'], 'request_model_ids': ['hy3'],
                                'session_id': tag, 'task_id': tag + '-task',
                                'artifact_path': str(folder / 'memory.json'),
                                'artifact_sha256': audit._sha((folder / 'memory.json').read_bytes()),
                                'explicit_Read_tool_paths': [str(folder / 'sources.json')],
                                'Write_tool_paths': [str(folder / 'memory.json')]}
                if key in failed_sources:
                    evidence.update(source_protocol_conformance=False,
                                    protocol_issues=['unexpected_native_artifact_write'],
                                    protocol_failure_action='fail_closed_at_delivery; retain task and cost; no regeneration')
                    evidence['Write_tool_paths'].append(str(folder / 'unrequested-output.py'))
                    self.save(folder / 'native_protocol_failed.json', evidence)
            else:
                messages = [{'role': 'system', 'content': 'MOCK TEST ONLY'},
                            {'role': 'user', 'content': raw.decode('utf-8')}]
                evidence = {'messages': messages, 'input_sha256': audit._sha(raw),
                            'receipt': self.receipt(memory, tag, messages)}
                if key in truncated_sources:
                    partial = memory[:60]
                    receipt = self.receipt(partial, tag, messages)
                    for field in ('session_id', 'request_id', 'temporary_credentials_removed'):
                        receipt.pop(field)
                    original_hash = audit._sha(tag + '-original-failed-receipt')
                    receipt.update(status='max_tokens_closed', completed=False,
                                   original_failed_receipt_sha256=original_hash,
                                   original_failure_and_reservation_preserved=True, automatic_retry=False)
                    evidence.update(actual_model='deepseek-flash', receipt=receipt,
                                    model_attempt_closed=True, source_protocol_conformance=False,
                                    protocol_issues=['source_output_token_budget_exhausted'],
                                    original_terminal_reason={'kind': 'max-tokens'},
                                    artifact_sha256=None, physical_supplier_calls=1,
                                    guard_counts={'agent_attempt_count': 1, 'stream_attempt_count': 1, 'allowed_stream_count': 1},
                                    partial_output_sha256=audit._sha(partial), original_failed_receipt_sha256=original_hash,
                                    protocol_failure_action='fail closed; keep original reservation; no new request')
                    outer = {name: value for name, value in evidence.items() if name != 'input_sha256'}
                    self.save(folder / 'failed_completion_audit.json', {'evidence': outer,
                                                                      'partial_model_output': partial, 'usable_generated_memory': False})
                    memory = None
            result = {key: value for key, value in plan.items() if key != 'sources'}
            result.update(memory=memory, evidence=evidence, wall_ms=10)
            self.save(path, result)
            if plan['platform'] == 'hy3' and evidence.get('source_protocol_conformance', True):
                self.mock_scope(path, conformance=key not in scope_failures,
                                issues=['directory_metadata_outside_own_job'] if key in scope_failures else [])
            results[path] = result
        records, planned_records, readbacks = [], [], {}
        for case in self.cases:
            policy = root / 'cases' / case['case_id'] / 'policy.sqlite'
            policy.parent.mkdir(parents=True, exist_ok=True)
            policy.write_bytes(b'MOCK POLICY; opened only by FakePolicy')
            for direction in ('A_to_B', 'B_to_A'):
                recipient = direction.split('_to_')[1]
                platform = 'hy3' if recipient == 'A' else 'flash'
                questions = audit.receiver_questions(self.evaluation, case['case_id'], direction)
                for arm in audit.ARMS:
                    folder = root / 'receiver_jobs' / case['case_id'] / direction / arm
                    folder.mkdir(parents=True)
                    database, packet = folder / 'receiver.sqlite', folder / 'transport.packet.json'
                    database.write_bytes(b'MOCK DATABASE; opened only by mocked read_batch')
                    packet.write_bytes(b'{}')
                    memory, dependencies, paths, source_protocol = audit._selected(root, case, direction, arm, results, include_protocol=True)
                    batch = case['case_id'] + direction + arm
                    keys = ['mock-memory-key'] if memory else []
                    payload = {'batch_id': batch, 'recipient_id': recipient, 'memory': memory}
                    reader_receipt = {'batch_id': batch, 'recipient_id': recipient, 'import_epoch': 7,
                                      'rendered_memory_sha256': audit._sha(memory), 'presented_memory_keys': keys,
                                      'records': [{'dependencies': dependencies}] if dependencies else [],
                                      'read_ms': 2, 'sqlite_uri_mode': 'ro', 'query_only': True}
                    readbacks[database] = {'payload': payload, 'receipt': reader_receipt}
                    answers = {q['question_id']: q['answer'] if q['primary_eligible'] else 'UNKNOWN'
                               for q in self.evaluation[case['case_id']][direction]['questions']}
                    self.save(folder / 'answers.json', answers)
                    self.save(folder / 'questions.json', questions)
                    raw_answers = (folder / 'answers.json').read_bytes()
                    tag = audit._sha(str(folder))
                    if platform == 'hy3':
                        evidence = {'actual_model': 'hy3', 'native_reader_command_verified': True,
                                    'native_reader_audit': {'actual_models': ['hy3'], 'request_model_ids': ['hy3'], 'session_id': tag},
                                    'native_evidence': {'task_id': tag + '-task', 'session_id': tag}}
                    else:
                        receipt = self.receipt(raw_answers, tag)
                        evidence = {'receipt': receipt, 'business_messages_sha256': receipt['business_messages_sha256']}
                    evidence.update(reader_receipt=deepcopy(reader_receipt), answers_schema_valid=True,
                                    questions_sha256=audit._sha(questions), answers_sha256=audit._sha(raw_answers))
                    delivery = {'receiver_db': str(database), 'policy_db': str(policy), 'policy_epoch': 7,
                                'batch_id': batch, 'memory_keys': keys, 'dependencies': dependencies,
                                'reopened_content_sha256': audit._sha(memory), 'packet_path': str(packet),
                                'packet_file_sha256': audit._sha(packet.read_bytes()), 'packet_bytes': 2,
                                'content_bytes': len(memory.encode('utf-8')), 'export_import_reopen_ms': 3,
                                'close_reopen_verified': True}
                    delivery.update({key: value for key, value in source_protocol.items() if key != 'source_protocol_rejected_job_files'})
                    planned = {'case_id': case['case_id'], 'direction': direction, 'arm': arm,
                               'recipient': recipient, 'receiver_platform': platform, 'job_dir': str(folder),
                               'delivery': delivery, 'source_jobs': [str(path) for path in paths],
                               'timings': {'delivery_ms': 3}}
                    planned_records.append(deepcopy(planned))
                    records.append({**planned, 'answers': answers, 'receiver_evidence': evidence})
        self.save(root / 'manifest.json', {'root': str(root), 'main_records': planned_records,
                                          'source_physical_results': [str(path) for path in plans]})
        self.save(root / 'main_records.json', records)
        return plans, records, readbacks

    def run_audit(self, root, readbacks):
        def mock_policy_check(path, recipient, dependencies, epoch):
            audit._need(FakePolicy.epoch == epoch, 'current_policy_epoch_changed')
        with patch.object(audit, 'read_batch', side_effect=lambda database, batch: deepcopy(readbacks[database])) as reader, \
                patch.object(audit, '_current_policy_check', side_effect=mock_policy_check):
            result = audit.finalize(root)
        return result, reader

    def add_mechanisms(self, root, main_records, readbacks):
        specs = audit._load(audit.HERE / 'data/mechanism_spec.json')['mechanisms']
        cases = {case['case_id']: case for case in self.cases}
        records = []
        for spec in specs:
            mid, case = spec['mechanism_id'], cases[spec['case_id']]
            folder = root / 'mechanisms' / mid
            parent = next(record for record in main_records if record['case_id'] == case['case_id']
                          and record['direction'] == 'A_to_B' and record['arm'] == 'full_rebuild')
            parent_memory = readbacks[Path(parent['delivery']['receiver_db'])]['payload']['memory']
            parent_inputs = [{'memory_key': parent['delivery']['memory_keys'][0], 'content': parent_memory}]
            by_id = {source['source_id']: source for source in case['agents']['B']['sources']}
            source_results, paths = [], []
            for phase, ids in (('initial', spec['child_inputs'][1:]), ('rebuild', spec['child_rebuild_inputs'][1:])):
                sources = [by_id[sid] for sid in ids]
                job = folder / 'source_jobs' / phase
                self.save(job / 'sources.json', {'sources': sources, 'parent_memories': parent_inputs})
                raw = (job / 'sources.json').read_bytes()
                memory = parent_memory + '\n\n' + '\n'.join(source['text'] for source in sources)
                messages = [{'role': 'system', 'content': 'MOCK MECHANISM ONLY'}, {'role': 'user', 'content': raw.decode('utf-8')}]
                evidence = {'messages': messages, 'input_sha256': audit._sha(raw),
                            'receipt': self.receipt(memory, mid + phase, messages)}
                result = {'platform': 'flash', 'source_ids': ids, 'memory': memory, 'evidence': evidence, 'wall_ms': 12}
                path = job / 'result.json'
                self.save(path, result)
                paths.append(str(path))
                source_results.append(result)
            legal_refs = audit._original_refs([by_id[sid] for sid in spec['child_rebuild_inputs'][1:]], 'B')
            old_refs = parent['delivery']['dependencies'] + audit._original_refs([by_id[sid] for sid in spec['child_inputs'][1:]], 'B')
            new_refs = parent['delivery']['dependencies'] + legal_refs
            job = folder / 'receiver_job'
            database, policy, packet = folder / 'AgentA.sqlite', folder / 'policy.sqlite', folder / 'rebuilt.packet.json'
            for path in (database, policy, packet):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'MOCK MECHANISM ARTIFACT')
            memory, batch = source_results[1]['memory'], mid + '-return'
            receipt = {'batch_id': batch, 'recipient_id': 'A', 'import_epoch': 7,
                       'rendered_memory_sha256': audit._sha(memory), 'presented_memory_keys': [mid + '-memory'],
                       'records': [{'dependencies': new_refs}], 'read_ms': 2,
                       'sqlite_uri_mode': 'ro', 'query_only': True}
            readbacks[database] = {'payload': {'batch_id': batch, 'recipient_id': 'A', 'memory': memory}, 'receipt': receipt}
            references = self.evaluation['_mechanisms'][mid]['questions']
            questions = [{'question_id': q['question_id'], 'question': q['question']} for q in references]
            answers = {q['question_id']: q['answer'] if q['primary_eligible'] else 'UNKNOWN' for q in references}
            self.save(job / 'questions.json', questions)
            self.save(job / 'answers.json', answers)
            evidence = {'actual_model': 'hy3', 'native_reader_command_verified': True,
                        'native_reader_audit': {'actual_models': ['hy3'], 'request_model_ids': ['hy3'], 'session_id': mid + '-HY3'},
                        'native_evidence': {'session_id': mid + '-HY3'}, 'reader_receipt': deepcopy(receipt),
                        'answers_schema_valid': True, 'questions_sha256': audit._sha(questions),
                        'answers_sha256': audit._sha((job / 'answers.json').read_bytes())}
            delivery = {'receiver_db': str(database), 'policy_db': str(policy), 'policy_epoch': 7,
                        'batch_id': batch, 'memory_keys': [mid + '-memory'], 'dependencies': new_refs,
                        'reopened_content_sha256': audit._sha(memory), 'packet_path': str(packet), 'close_reopen_verified': True}
            allowed = [source['source_id'] for source in case['agents']['A']['sources']] + spec['child_rebuild_inputs'][1:]
            self.save(folder / 'withdrawal.json', {'epoch': 7, 'allowed': allowed, 'revoked': spec['withdraw_before_first_return']})
            records.append({'mechanism_id': mid, 'case_id': case['case_id'], 'direction': 'B_to_A',
                            'arm': 'layered_rebuild', 'recipient': 'A', 'receiver_platform': 'hy3', 'job_dir': str(job),
                            'source_jobs': paths, 'answers': answers, 'receiver_evidence': evidence, 'delivery': delivery,
                            'mechanism_evidence': {'old_child_dependencies': old_refs, 'new_child_dependencies': new_refs,
                                'old_child_rejections': {'export_blocked': True, 'import_blocked': True, 'no_partial_receiver_writes': True},
                                'fresh_A_own_originals_only': True, 'main_database_sha256_unchanged': True}})
        self.save(root / 'mechanisms' / 'records.json', records)

    def test_complete_ledger_cache_miss_plus_read_unknown_cost_and_separate_scope(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            plans, records, readbacks = self.fixture(root)
            # An unrelated pending mechanism result must never enter main cost.
            self.save(root / 'mechanisms' / 'pending' / 'result.json', {'not': 'a main source job'})
            report, reader = self.run_audit(root, readbacks)
            self.assertEqual(reader.call_count, 96)
            ledger = report['main_physical_ledger']
            self.assertEqual(ledger['source_jobs'], len(plans))
            self.assertEqual(ledger['receiver_jobs'], 96)
            self.assertEqual(ledger['artifact_count'], len(plans) + 96)
            flash_count = ledger['flash_physical_supplier_calls']
            self.assertEqual(ledger['flash_native_tokens']['input_total_tokens'], flash_count * 30)
            self.assertEqual(ledger['flash_native_tokens']['input_uncached_tokens'], flash_count * 10)
            self.assertEqual(ledger['flash_native_tokens']['cache_read_tokens'], flash_count * 20)
            self.assertEqual(Decimal(ledger['flash_estimated_cache_aware_peak_cny']), Decimal('.0000608') * flash_count)
            self.assertIsNone(ledger['all_platform_supplier_fee_cny'])
            self.assertIsNone(ledger['all_platform_physical_supplier_calls'])
            logical_jobs = sum(value['artifact_count'] for value in report['main_logical_per_method_ledger'].values())
            self.assertEqual(logical_jobs - ledger['artifact_count'], 24)  # Shared initial whole charged to two methods.
            self.assertEqual(report['mechanisms']['status'], 'not_run')
            boundaries = report['study_boundaries']
            self.assertFalse(boundaries['initial_derived_sqlite_record_predates_withdrawal'])
            self.assertFalse(boundaries['source_model_direct_sql_retrieval'])
            self.assertFalse(boundaries['vendor_builtin_memory_migration_demonstrated'])
            self.assertFalse(boundaries['workbuddy_complete_remote_request_attestation'])
            self.assertIn('after withdrawal/repair', boundaries['initial_source_memory_timeline'])
            score = audit._load(root / 'evaluation_with_payload.json')
            self.assertTrue(all(value['payload_observed_records'] == 24 for value in score['summary'].values()))
            self.assertTrue(all(value['payload_surface_value_leak_rate'] == 0 for value in score['summary'].values()))
            self.assertTrue((root / 'audit_and_ledger.json').exists())

    def test_missing_actual_source_rejected_even_when_result_claims_full_input(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            plans, _, readbacks = self.fixture(root)
            first = next(iter(plans)).parent / 'sources.json'
            supplied = audit._load(first)
            supplied['sources'].pop()
            self.save(first, supplied)
            with self.assertRaisesRegex(audit.FinalizeError, 'source_actual_input_ids_mismatch'):
                self.run_audit(root, readbacks)
            self.assertFalse((root / 'audit_and_ledger.json').exists())

    def test_source_model_and_receipt_usage_tampering_rejected(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            plans, _, readbacks = self.fixture(root)
            path = next(path for path, plan in plans.items() if plan['platform'] == 'hy3')
            original = audit._load(path)
            changed = deepcopy(original)
            changed['evidence']['request_model_ids'] = ['deepseek-flash']
            self.save(path, changed)
            with self.assertRaisesRegex(audit.FinalizeError, 'hy3_actual_and_requested_model_mismatch'):
                self.run_audit(root, readbacks)
            self.save(path, original)
            path = next(path for path, plan in plans.items() if plan['platform'] == 'flash')
            changed = audit._load(path)
            changed['evidence']['receipt']['input_total_tokens'] = 10  # Incorrectly treating cache MISS as total.
            self.save(path, changed)
            with self.assertRaisesRegex(audit.FinalizeError, 'flash_usage_field_mismatch:input_total_tokens'):
                self.run_audit(root, readbacks)

    def test_changed_receiver_memory_and_policy_epoch_rejected(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            _, records, readbacks = self.fixture(root)
            database = Path(records[0]['delivery']['receiver_db'])
            readbacks[database]['payload']['memory'] += ' UNAUTHORIZED NEW TEXT'
            with self.assertRaisesRegex(audit.FinalizeError, 'receiver_reopened_memory_hash_mismatch'):
                self.run_audit(root, readbacks)
            readbacks[database]['payload']['memory'] = readbacks[database]['payload']['memory'].removesuffix(' UNAUTHORIZED NEW TEXT')
            with patch.object(FakePolicy, 'epoch', 8):
                with self.assertRaisesRegex(audit.FinalizeError, 'current_policy_epoch_changed'):
                    self.run_audit(root, readbacks)

    def test_private_and_outside_paths_rejected_before_read(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            for path in (root / 'sdk.private' / 'receipt.json', root / 'home.private' / 'anything',
                         root / '.credentials.yaml', root.parent / 'outside.json'):
                with self.assertRaises(audit.FinalizeError):
                    audit._path(root, path)

    def test_layered_real_parent_binding_and_costs_are_separate_from_main(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            plans, records, readbacks = self.fixture(root)
            self.add_mechanisms(root, records, readbacks)
            report, reader = self.run_audit(root, readbacks)
            self.assertEqual(reader.call_count, 98)
            self.assertEqual(report['main_physical_ledger']['artifact_count'], len(plans) + 96)
            mechanisms = report['mechanisms']
            self.assertEqual(mechanisms['status'], 'audited')
            self.assertTrue(mechanisms['excluded_from_main'])
            self.assertEqual(mechanisms['physical_ledger']['source_jobs'], 4)
            self.assertEqual(mechanisms['physical_ledger']['hy3_native_tasks'], 2)
            self.assertEqual(mechanisms['physical_ledger']['flash_physical_supplier_calls'], 4)
            self.assertTrue(all(probe['legal_value_coverage'] == [True] and probe['unique_withheld_unknown'] == [True]
                                and probe['payload_surface_leaked_values'] == 0 for probe in mechanisms['probe_results']))

    def test_source_protocol_failures_stay_in_cost_but_selected_outputs_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            failures = {('exchange-n020-r00', 'A', 'initial', 'chunk0'),
                        ('exchange-n020-r10', 'A', 'initial', 'whole')}
            plans, records, readbacks = self.fixture(root, failures)
            originally_failed = next(path for path, plan in plans.items() if
                                     (plan['case_id'], plan['agent'], plan['phase'], plan['group']) in failures)
            self.mock_scope(originally_failed)  # A separate True audit cannot upgrade the original failure.
            report, _ = self.run_audit(root, readbacks)
            protocol = report['source_protocol_audit']
            self.assertEqual(protocol['failed_physical_source_job_count'], 2)
            self.assertEqual(protocol['arm_views_with_selected_source_protocol_rejections'], 1)
            self.assertEqual(protocol['arm_view_rejections_by_arm']['selective'], 1)
            self.assertEqual(report['main_physical_ledger']['source_jobs'], len(plans))
            self.assertEqual(report['main_physical_ledger']['source_protocol_failed_jobs'], 2)
            self.assertEqual(protocol['main_record_count_retained'], 96)
            repaired = next(row for row in report['main_jobs'] if row['kind'] == 'receiver'
                            and row['case_id'] == 'exchange-n020-r10' and row['direction'] == 'A_to_B' and row['arm'] == 'full_rebuild')
            self.assertTrue(repaired['source_protocol_clean'])
            clean = report['source_protocol_clean_supplement']
            self.assertEqual(clean['paired_direction_count'], 23)
            self.assertEqual(clean['independent_project_clusters'], 12)
            self.assertEqual(clean['excluded_case_directions'], [['exchange-n020-r00', 'A_to_B']])
            self.assertTrue(report['source_visibility']['condition_label_visible'])
            self.assertFalse(report['source_visibility']['future_all_metadata_blinded'])
            # A resumed short native wait must never become complete model time.
            self.assertIsNone(report['main_physical_ledger']['sum_source_job_wall_ms'])
            native_source = next(row for row in report['main_jobs'] if row['kind'] == 'source' and row['platform'] == 'hy3')
            self.assertIsNone(native_source['wall_ms'])
            self.assertEqual(native_source['observed_outer_invocation_wall_ms'], 10)
            self.assertIn('not pure model time', native_source['local_file_elapsed_scope'])
            # Claiming a rejected artifact was selected is an audit failure,
            # even though the failed task itself remains an honest paid attempt.
            attacked = deepcopy(records)
            victim = next(row for row in attacked if not row['delivery']['source_protocol_clean'])
            victim['delivery']['memory_keys'] = victim['delivery']['source_protocol_rejected_memory_keys']
            self.save(root / 'main_records.json', attacked)
            manifest = audit._load(root / 'manifest.json')
            target = next(row for row in manifest['main_records'] if all(row[key] == victim[key] for key in ('case_id', 'direction', 'arm')))
            target['delivery']['memory_keys'] = victim['delivery']['memory_keys']
            self.save(root / 'manifest.json', manifest)
            with self.assertRaisesRegex(audit.FinalizeError, 'failed_source_protocol_memory_was_exported'):
                self.run_audit(root, readbacks)

    def test_closed_truncation_counts_usage_but_pre_model_failure_counts_zero_submission(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            pre = {('exchange-n020-r00', 'A', 'initial', 'chunk0')}
            truncated = {('exchange-n020-r00', 'B', 'initial', 'whole')}
            plans, records, readbacks = self.fixture(root, pre_model_sources=pre, truncated_sources=truncated)
            report, _ = self.run_audit(root, readbacks)
            ledger = report['main_physical_ledger']
            self.assertEqual(ledger['logical_source_attempts'], len(plans))
            self.assertEqual(ledger['source_attempt_outcomes']['success'], len(plans) - 2)
            self.assertEqual(ledger['source_attempt_outcomes']['output_truncated_closed'], 1)
            self.assertEqual(ledger['source_attempt_outcomes']['pre_model_creation_closed'], 1)
            self.assertEqual(ledger['known_model_calls_or_native_task_submissions'], len(plans) + 96 - 1)
            self.assertEqual(ledger['hy3_native_tasks'], sum(plan['platform'] == 'hy3' for plan in plans.values()) + 48 - 1)
            self.assertEqual(ledger['hy3_pre_model_zero_submission_source_attempts'], 1)
            self.assertEqual(ledger['flash_usage_unknown_attempts'], 0)
            self.assertEqual(ledger['flash_native_tokens']['cache_read_tokens'], ledger['flash_physical_supplier_calls'] * 20)
            self.assertGreater(ledger['source_observed_partial_output_bytes_not_usable_memory'], 0)
            failed_rows = [row for row in report['main_jobs'] if row['kind'] == 'source' and row['source_attempt_status'] != 'success']
            self.assertTrue(all(not row['usable_generated_memory'] and row['output_memory_bytes'] == 0 for row in failed_rows))
            self.assertTrue(all(row['closed_attempt_outer_audit_sha256'] for row in failed_rows))
            self.assertEqual(report['source_protocol_clean_supplement']['paired_direction_count'], 22)
            self.assertEqual(report['source_protocol_clean_supplement']['independent_project_clusters'], 11)
            self.assertEqual(report['source_protocol_audit']['main_record_count_retained'], 96)
            keys = [key for record in records for key in record['delivery']['source_protocol_rejected_memory_keys']]
            self.assertIn('FAILED-A-chunk0-initial', keys)
            self.assertIn('FAILED-B-whole-initial', keys)
            # The outer audit's partial output is hash-bound evidence, never a
            # memory fallback. Changing it cannot inherit the old usage receipt.
            truncated_path = next(path for path, plan in plans.items()
                                  if (plan['case_id'], plan['agent'], plan['phase'], plan['group']) in truncated)
            outer_path = truncated_path.parent / 'failed_completion_audit.json'
            closed = audit._load(outer_path)
            closed['partial_model_output'] += ' MODIFIED'
            self.save(outer_path, closed)
            with self.assertRaisesRegex(audit.FinalizeError, 'closed_completion_partial_or_original_failure_hash_mismatch'):
                self.run_audit(root, readbacks)

    def test_terminal_queue_submission_has_unknown_execution_and_namespace_is_same_path(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            terminal = {('exchange-n100-r00', 'A', 'initial', 'chunk0')}
            plans, records, readbacks = self.fixture(root, terminal_sources=terminal)
            # A namespace spelling of an existing drive path is an alias,
            # including for an initial task produced before plain-path repair.
            normal = next(path for path, plan in plans.items() if plan['platform'] == 'hy3'
                          and (plan['case_id'], plan['agent'], plan['phase'], plan['group']) not in terminal)
            source = audit._load(normal)
            source['evidence']['artifact_path'] = '\\\\?\\' + source['evidence']['artifact_path']
            source['evidence']['explicit_Read_tool_paths'] = ['\\\\?\\' + path for path in source['evidence']['explicit_Read_tool_paths']]
            source['evidence']['Write_tool_paths'] = ['\\\\?\\' + path for path in source['evidence']['Write_tool_paths']]
            source['evidence'].update(actual_models=['hy3', 'hy3-x'], request_model_ids=['hy3-x'],
                                      canonical_model_family='Hy3', billing_route_ids=['hy3-x'])
            self.save(normal, source)
            self.mock_scope(normal)
            self.assertEqual(audit._path(root, '\\\\?\\' + str(normal)), normal)
            report, _ = self.run_audit(root, readbacks)
            ledger = report['main_physical_ledger']
            planned_native = sum(plan['platform'] == 'hy3' for plan in plans.values()) + 48
            self.assertEqual(ledger['hy3_native_queue_submissions'], planned_native)
            self.assertEqual(ledger['hy3_native_tasks'], planned_native - 1)
            self.assertEqual(ledger['hy3_queue_submission_without_verified_model_execution'], 1)
            self.assertEqual(ledger['model_submission_count_unknown_attempts'], 1)
            self.assertEqual(ledger['source_attempt_outcomes']['terminal_queue_no_artifact_closed'], 1)
            self.assertIsNone(ledger['hy3_physical_supplier_calls'])
            self.assertIsNone(ledger['workbuddy_supplier_fee_cny'])
            closed = next(row for row in report['main_jobs'] if row.get('source_attempt_status') == 'terminal_queue_no_artifact_closed')
            self.assertEqual(closed['identity']['native_queue_submissions'], 1)
            self.assertEqual(closed['identity']['native_tasks'], 0)
            self.assertIsNone(closed['identity']['physical_supplier_calls'])
            self.assertIsNone(closed['identity']['model_execution_count'])
            self.assertFalse(closed['usable_generated_memory'])
            self.assertTrue(any('FAILED-A-chunk0-initial' in row['delivery']['source_protocol_rejected_memory_keys'] for row in records))
            preserved = next(row for row in report['main_jobs'] if row.get('result_file') == str(normal))['identity']
            self.assertEqual(preserved['actual_models'], ['hy3', 'hy3-x'])
            self.assertEqual(preserved['request_model_ids'], ['hy3-x'])
            self.assertEqual(preserved['billing_route_ids'], ['hy3-x'])
            self.assertEqual(preserved['canonical_model_family'], 'Hy3')
            self.assertFalse(preserved['route_ids_rewritten_to_family'])

    def test_official_paid_route_and_mixed_history_preserve_ids_and_reject_other_models(self):
        for actual, requested in ((['hy3-x'], ['hy3-x']),
                                  (['hy3', 'hy3-x'], ['hy3', 'hy3-x'])):
            evidence = {'actual_models': actual, 'request_model_ids': requested,
                        'billing_route_ids': requested, 'canonical_model_family': 'Hy3',
                        'session_id': 'MOCK-paid-qualification', 'task_id': 'MOCK-task'}
            identity = audit._identity(evidence, 'hy3', 'MOCK memory', source=True)
            self.assertEqual(identity['actual_models'], actual)
            self.assertEqual(identity['request_model_ids'], requested)
            self.assertEqual(identity['billing_route_ids'], requested)
            self.assertIsNone(identity['supplier_fee_cny'])
            self.assertIsNone(identity['physical_supplier_calls'])
            receiver = {'actual_model': 'hy3-x', 'native_reader_command_verified': True,
                        'native_reader_audit': evidence, 'native_evidence': evidence}
            self.assertEqual(audit._identity(receiver, 'hy3', b'MOCK answer')['request_model_ids'], requested)
        for other in ('fast-model', 'deepseek-flash', 'glm-5', 'hy3-x-unverified'):
            evidence = {'actual_models': ['hy3-x', other], 'request_model_ids': ['hy3-x'],
                        'session_id': 'MOCK-unapproved'}
            with self.assertRaisesRegex(audit.FinalizeError, 'hy3_actual_and_requested_model_mismatch'):
                audit._identity(evidence, 'hy3', 'MOCK', source=True)

    def test_known_provider_quota_without_memory_is_missing_data_not_algorithm_zero(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            path = root/'MOCK-source'/'result.json'
            self.save(path, {'memory': None, 'evidence': {'model_attempt_closed': True, 'source_protocol_conformance': False}})
            marker = path.parent/'provider_quota_evidence.json'
            for quota in ({'error_code': 6004}, {'error_code': '6020'}, {'http_status': 429}):
                self.save(marker, quota)
                with self.assertRaisesRegex(audit.FinalizeError, 'unresolved_source_provider_quota_not_algorithm_zero'):
                    audit._require_resolved_provider_quota(root, [path])
            # An existing output can proceed to the separate strict identity,
            # shell-scope and artifact audit; this guard alone approves nothing.
            self.save(path, {'memory': 'MOCK output pending independent verification'})
            audit._require_resolved_provider_quota(root, [path])

    def test_shell_scope_false_filters_only_bad_chunk_and_tampered_binding_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            failures = {('exchange-n020-r00', 'A', 'initial', 'chunk0')}
            plans, records, readbacks = self.fixture(root, scope_failures=failures)
            report, _ = self.run_audit(root, readbacks)
            source = next(row for row in report['main_jobs'] if row['kind'] == 'source'
                          and row['case_id'] == 'exchange-n020-r00' and row['agent'] == 'A' and row['group'] == 'chunk0')
            self.assertEqual(source['source_attempt_status'], 'tool_protocol_failed_closed')
            self.assertFalse(source['usable_generated_memory'])
            self.assertFalse(source['native_source_shell_scope_audit']['protocol_conformance'])
            self.assertEqual(source['identity']['native_tasks'], 1)
            self.assertEqual(report['source_protocol_audit']['bound_native_shell_scope_failures'], 1)
            selected = next(row for row in records if row['case_id'] == 'exchange-n020-r00'
                            and row['direction'] == 'A_to_B' and row['arm'] == 'selective')
            actual_ids = {ref['source_id'] for ref in selected['delivery']['dependencies']}
            case = next(case for case in self.cases if case['case_id'] == selected['case_id'])
            self.assertEqual(actual_ids, set(case['chunks']['A'][1]))
            self.assertTrue(readbacks[Path(selected['delivery']['receiver_db'])]['payload']['memory'])
            scope_path = Path(source['result_file']).parent / 'native_source_shell_scope_audit.json'
            scope = audit._load(scope_path)
            scope['source_result_sha256'] = '0' * 64
            self.save(scope_path, scope)
            with self.assertRaisesRegex(audit.FinalizeError, 'native_source_shell_scope_audit_binding_invalid'):
                self.run_audit(root, readbacks)
            scope_path.unlink()
            with self.assertRaisesRegex(audit.FinalizeError, 'native_source_shell_scope_audit_required'):
                self.run_audit(root, readbacks)


if __name__ == '__main__':
    unittest.main()
