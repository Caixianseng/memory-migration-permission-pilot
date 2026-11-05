"""MOCK-only closed-attempt auditing and failed-source delivery integration.

No native process/model is launched. All audit/partial/initial/repair artifacts
are marked MOCK and live in temporary directories, never study results.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import completion_failure as failure
from . import run_study as study
from . import test_run_study as mock_delivery
from .model_runtime import digest
from experiments.revocation_grouping_v1.sdk_adapter import encoded, dispatch_text


class ClosedCompletionFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MOCK-closed-completion-')
        self.root = Path(self.temp.name).resolve()
        self.assertFalse(self.root.is_relative_to((study.REPO/'results').resolve()))
        self.job = self.root/'MOCK-source-job'
        self.folder = self.job/'sdk.private/job-source-memory'
        self.folder.mkdir(parents=True)
        self.expected_user = json.dumps({'MOCK_fixture': True, 'sources': [
            {'source_id': 'MOCK-source-1', 'text': 'MOCK source fact'}], 'parent_memories': []})
        self.messages = [{'role': 'system', 'content': 'MOCK source-only instruction'},
                         {'role': 'user', 'content': self.expected_user}]
        self.prompt = dispatch_text(self.messages)
        self.max_tokens = 1024
        self.partial = 'MOCK_PARTIAL_OUTPUT_NOT_USABLE_AS_MEMORY'
        self.actual = encoded({'MOCK_fixture': True, 'model': 'deepseek-flash',
            'maxTokens': self.max_tokens, 'reasoningEffort': 'off', 'tools': [],
            'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': self.prompt}]},
                         {'role': 'user', 'content': [{'type': 'text', 'text': 'MOCK runtime context'}]}]})
        self.usage = {'inputTokens': 111, 'cacheReadTokens': 222, 'cacheWriteTokens': 0,
                      'outputTokens': 1024, 'totalTokens': 1357}
        self.guard = {'MOCK_fixture': True, 'agent_attempt_count': 1, 'stream_attempt_count': 1,
                      'allowed_stream_count': 1, 'reject_code': None, 'requests': [{
                          'count': 1, 'bodyhash': digest(self.actual), 'bytes': len(self.actual),
                          'maxTokens': self.max_tokens, 'business_input_sha256': digest(self.prompt),
                          'runtime_context_sha256': 'c'*64, 'user_text_blocks': 2,
                          'tools': 0, 'reasoningEffort': 'off'}]}
        self.response = {'MOCK_fixture': True, 'last_terminal_reason': {'kind': 'max-tokens'},
                         'final_assistant_interrupted': False,
                         'final_assistant_source': {'provider': 'deepseek-account', 'model': 'deepseek-flash'},
                         'assistant_usage_events': [{'usage': self.usage}],
                         'final_assistant_text': self.partial}
        self.reservation = {'MOCK_fixture': True, 'reservation_cny': '0.05', 'role': 'source',
                            'max_tokens': 1024, 'request_byte_bound': 32768, 'input_token_bound': 34816}
        self.put('receipt.json', {'MOCK_fixture': True, 'status': 'failed', 'error': 'sdk_not_completed',
                                  'physical_request_count': None, 'reservation_retained': True})
        self.put('input.json', {'messages': self.messages, 'dispatch_text': self.prompt,
                                'business_messages_sha256': digest(encoded(self.messages)),
                                'dispatch_sha256': digest(self.prompt)})
        self.put('guard.json', self.guard)
        self.put('response.json', self.response)
        self.put('reservation.json', self.reservation)
        (self.folder/'actual_request.json').write_bytes(self.actual)
        # Poison only MOCK files. No real home or credential is touched.
        (self.folder/'home.private').mkdir()
        (self.folder/'home.private/.credentials.yaml').write_text('MOCK_CREDENTIAL_MUST_NOT_BE_READ')

    def tearDown(self):
        self.temp.cleanup()

    def put(self, name, value):
        (self.folder/name).write_bytes(encoded(value))

    def inspect(self, **kwargs):
        return failure.inspect_failure(self.job, kwargs.get('job_id', 'source-memory'),
                                       kwargs.get('expected_user', self.expected_user), self.max_tokens)

    def test_max_tokens_usage_cost_partial_and_original_evidence_preserved(self):
        before = {name: (self.folder/name).read_bytes() for name in
                  ('receipt.json', 'reservation.json', 'input.json', 'guard.json',
                   'response.json', 'actual_request.json')}
        allowed = {self.folder/name for name in before}
        reads = []
        original = Path.read_bytes

        def record_read(path):
            reads.append(path)
            self.assertIn(path, allowed, 'failure audit must not read any home/credential/other file')
            return original(path)

        with patch.object(Path, 'read_bytes', record_read):
            evidence, partial = self.inspect()
        self.assertTrue(reads)
        self.assertEqual(partial, self.partial)
        self.assertEqual(evidence['physical_supplier_calls'], 1)
        self.assertFalse(evidence['source_protocol_conformance'])
        self.assertEqual(evidence['actual_model'], 'deepseek-flash')
        recovered = evidence['receipt']
        self.assertFalse(recovered['completed'])
        self.assertFalse(recovered['automatic_retry'])
        self.assertEqual(recovered['input_uncached_tokens'], 111)
        self.assertEqual(recovered['cache_read_tokens'], 222)
        self.assertEqual(recovered['input_total_tokens'], 333)
        self.assertEqual(Decimal(recovered['estimated_peak_cost_cny']), Decimal('0.008858'))
        self.assertEqual(Decimal(recovered['estimated_cache_aware_peak_cost_cny']), Decimal('0.00842288'))
        self.assertEqual(recovered['request_sha256'], digest(self.actual))
        self.assertEqual(recovered['response_sha256'], digest(self.partial))
        self.assertTrue(recovered['original_failure_and_reservation_preserved'])
        saved = json.loads((self.job/'failed_completion_audit.json').read_bytes())
        self.assertFalse(saved['usable_generated_memory'])
        self.assertEqual(saved['partial_model_output'], self.partial)
        for name, raw in before.items():
            self.assertEqual((self.folder/name).read_bytes(), raw)
        self.assertNotIn('MOCK_CREDENTIAL', json.dumps(saved))

    def test_actual_request_body_hash_mismatch_is_rejected(self):
        (self.folder/'actual_request.json').write_bytes(self.actual+b'changed')
        with self.assertRaisesRegex(RuntimeError, 'request_binding_mismatch'):
            self.inspect()

    def test_multiple_guard_requests_are_rejected(self):
        self.guard['stream_attempt_count'] = 2
        self.guard['allowed_stream_count'] = 2
        self.guard['requests'].append(deepcopy(self.guard['requests'][0]))
        self.put('guard.json', self.guard)
        with self.assertRaisesRegex(RuntimeError, 'not_single_request'):
            self.inspect()

    def test_changed_expected_source_business_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'business_inputs_changed'):
            self.inspect(expected_user='MOCK_OTHER_SOURCE_JOB')

    def test_request_dispatch_business_binding_is_rejected(self):
        self.guard['requests'][0]['business_input_sha256'] = 'd'*64
        self.put('guard.json', self.guard)
        with self.assertRaisesRegex(RuntimeError, 'request_binding_mismatch'):
            self.inspect()

    def test_output_usage_over_model_budget_is_rejected(self):
        self.usage['outputTokens'] = 1025
        self.usage['totalTokens'] = 1358
        self.put('response.json', self.response)
        with self.assertRaisesRegex(RuntimeError, 'usage_budget_mismatch'):
            self.inspect()

    def test_input_usage_over_observed_request_bound_is_rejected(self):
        self.usage['inputTokens'] = len(self.actual)+2049
        self.usage['cacheReadTokens'] = 0
        self.usage['totalTokens'] = self.usage['inputTokens']+self.usage['outputTokens']
        self.put('response.json', self.response)
        with self.assertRaisesRegex(RuntimeError, 'usage|reservation|budget'):
            self.inspect()

    def test_recomputed_cost_over_original_reservation_is_rejected(self):
        self.reservation['reservation_cny'] = '0.000001'
        self.put('reservation.json', self.reservation)
        with self.assertRaisesRegex(RuntimeError, 'usage|reservation|budget'):
            self.inspect()

    def test_nonmax_failure_keeps_request_and_cost_unknown_not_zero(self):
        self.response['last_terminal_reason'] = {'kind': 'failed'}
        self.response['final_assistant_text'] = ''
        self.put('response.json', self.response)
        evidence, partial = self.inspect()
        self.assertIsNone(partial)
        self.assertIsNone(evidence['physical_supplier_calls'])
        self.assertIsNone(evidence['actual_model'])
        self.assertIsNone(evidence['receipt']['physical_request_count'])
        self.assertNotIn('estimated_peak_cost_cny', evidence['receipt'])
        self.assertFalse(evidence['source_protocol_conformance'])

    def test_missing_response_keeps_unknown_and_no_generated_output(self):
        (self.folder/'response.json').unlink()
        evidence, partial = self.inspect()
        self.assertIsNone(partial)
        self.assertIsNone(evidence['physical_supplier_calls'])
        saved = json.loads((self.job/'failed_completion_audit.json').read_bytes())
        self.assertFalse(saved['usable_generated_memory'])
        self.assertIsNone(saved['partial_model_output'])

    def test_invalid_job_identifier_rejected_before_any_audit_read(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('unsafe audit path read attempted')):
            with self.assertRaisesRegex(RuntimeError, 'job_id|audit_path|unsafe|identifier'):
                self.inspect(job_id='MOCK/../../../home.private')


class MissingSourceSentinelTests(unittest.TestCase):
    def write_mock_closed_result(self, path, result):
        result['platform'] = 'hy3'
        result['evidence'].update(session_id='MOCK-closed-session', task_id='MOCK-closed-task',
                                  artifact_sha256=None)
        study.write_json(path, result)
        study.write_json(path.parent/'native_source_shell_scope_audit.json', {
            'schema': 'native-source-shell-scope-audit-v1',
            'session_id': 'MOCK-closed-session', 'task_id': 'MOCK-closed-task',
            'source_result_sha256': digest(path.read_bytes()), 'artifact_sha256': None,
            'protocol_conformance': False, 'issues': ['MOCK_closed_missing_source'],
            'command_counts': {'MOCK_only': 0}, 'full_remote_input_attestation': False})

    def test_none_memory_returns_sentinel_without_opening_any_agent_store(self):
        with tempfile.TemporaryDirectory(prefix='MOCK-missing-source-') as folder:
            root = Path(folder)
            case = {'case_id': 'MOCK-none-memory'}
            path = root/'source_jobs'/case['case_id']/'A/initial/whole/result.json'
            self.write_mock_closed_result(path, {'MOCK_fixture': True, 'source_ids': ['MOCK-source-id'],
                'memory': None, 'evidence': {'MOCK_fixture': True, 'source_protocol_conformance': False}})
            with patch.object(study, 'AgentStore', side_effect=AssertionError('None memory must never enter SQLite')):
                result = study.store_generated(root, case, 'A', 'initial', 'whole', ['MOCK-source-id'])
            self.assertEqual(result['kind'], 'failed_source')
            self.assertFalse(result['generated_memory_exists'])
            self.assertNotIn('content', result)
            self.assertEqual(list(root.rglob('*.sqlite')), [])

    def test_none_memory_without_closed_failure_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='MOCK-unclosed-source-') as folder:
            root = Path(folder)
            case = {'case_id': 'MOCK-unclosed-memory'}
            self.write_mock_closed_result(root/'source_jobs'/case['case_id']/'A/initial/whole/result.json',
                {'MOCK_fixture': True, 'source_ids': ['MOCK-source-id'], 'memory': None,
                 'evidence': {'MOCK_fixture': True, 'source_protocol_conformance': True}})
            with patch.object(study, 'AgentStore', side_effect=AssertionError('unclosed None cannot enter SQLite')):
                with self.assertRaisesRegex(RuntimeError, 'missing_source_without_closed_failure'):
                    study.store_generated(root, case, 'A', 'initial', 'whole', ['MOCK-source-id'])

    def test_none_initial_and_repair_artifacts_never_store_or_export(self):
        for percent, phase in ((0, 'initial'), (25, 'repair')):
            with self.subTest(MOCK_revocation_percent=percent):
                helper = mock_delivery.ProtocolFilteredDeliveryTests()
                helper.setUp()
                try:
                    case = helper.mock_case(percent)
                    failed = [('A', phase, 'whole'), ('A', phase, 'chunk0')]
                    saved = helper.mock_sources(case, failed)
                    for key in failed:
                        fixture = saved[key]
                        fixture['body']['memory'] = None
                        fixture['body']['evidence']['artifact_sha256'] = None
                        fixture['path'].write_bytes(encoded(fixture['body']))
                        # Keep the MOCK v7 audit bound even though an original
                        # conformance=false independently closes this source.
                        audit_path = fixture['path'].parent/'native_source_shell_scope_audit.json'
                        if audit_path.exists():
                            audit = json.loads(audit_path.read_bytes())
                            audit.update(source_result_sha256=digest(fixture['path'].read_bytes()),
                                         artifact_sha256=None, protocol_conformance=False,
                                         issues=['MOCK_closed_missing_source'])
                            audit_path.write_bytes(encoded(audit))
                    original_export = study.export_package
                    with patch.object(study, 'export_package', wraps=original_export) as exported:
                        records = helper.run_delivery(case)
                    helper.assert_imported(records['A_to_B', 'full_rebuild'], [])
                    helper.assert_imported(records['A_to_B', 'selective'],
                        [saved['A', 'initial', 'chunk1']['body']['memory']])
                    for call in exported.call_args_list:
                        self.assertFalse(any(key.startswith('FAILED-') for key in call.args[3]))
                    sender = Path(records['A_to_B', 'selective']['delivery']['receiver_db'])
                    self.assertTrue(sender.is_relative_to(helper.root))
                    import sqlite3
                    database = helper.root/'cases'/case['case_id']/'A.sqlite'
                    connection = sqlite3.connect(database.resolve().as_uri()+'?mode=ro', uri=True)
                    try:
                        memory_ids = {row[0] for row in connection.execute('SELECT memory_id FROM memories')}
                    finally:
                        connection.close()
                    self.assertNotIn('whole-'+phase, memory_ids)
                    self.assertNotIn('chunk0-'+phase, memory_ids)
                    self.assertFalse(records['A_to_B', 'selective']['delivery']['source_protocol_clean'])
                finally:
                    helper.tearDown()


if __name__ == '__main__':
    unittest.main()
