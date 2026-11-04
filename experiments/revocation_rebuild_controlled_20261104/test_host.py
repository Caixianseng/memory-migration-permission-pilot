"""Boundary regressions only; fixtures never create official-API evidence."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from memory_migration_study.native_agent_protocol import NativeProtocolError
from .host import Host, HostError, verify_trace
from .lineage import Lineage, LineageError, canonical, sha


SOURCES = [{'source_id': 'S0' + str(i), 'text': 'Private source ' + str(i)}
           for i in range(1, 5)]


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.count = 0

    def host(self, method='B0', view='revoke'):
        self.count += 1
        host = Host(SOURCES, case_id='boundary-test', method=method, view=view,
                    out=Path(self.temp.name) / str(self.count), instrument_only=True)
        self.addCleanup(host.close)
        return host

    def generate(self, host, artifact, ids, output=None):
        payload = host.begin_generation(artifact, ids, trace_id='trace-' + artifact)
        output = output or 'Generated ' + artifact
        host.seal_generation(output=output, observed_input=payload, receipt={
            'schema': 'controlled-fixture-generation-v1', 'instrument_only': True,
            'trace_id': payload['trace_id'], 'input_hash': payload['input_hash'],
            'output_hash': sha(output), 'logical_requests': 1, 'request_id': 'req-' + artifact})
        return payload

    def test_multilevel_closure_and_old_packet_denial(self):
        host = self.host()
        self.generate(host, 'U1', ['S01', 'S02'])
        self.generate(host, 'U2', ['U1', 'S03'])
        payload = self.generate(host, 'M', ['U2', 'S04'])
        self.assertEqual(payload['source_ids'], ['S01', 'S02', 'S03', 'S04'])
        checks = host.apply_view('S01')
        self.assertEqual(checks['M'], 'old_packet_and_new_export_denied_export_not_allowed')
        self.assertEqual(checks['U2'], checks['M'])
        with self.assertRaisesRegex(NativeProtocolError, 'export_not_allowed'):
            host.authorize_artifact('M')
        self.assertEqual(host.prepare_delivery()['status'], 'blocked')
        self.assertFalse(any(r['kind'] == 'target_callback_committed'
                             for r in verify_trace(host.out / 'events.jsonl')))

    def test_empty_unknown_and_cycle_fail_closed(self):
        lineage = Lineage(SOURCES)
        for inputs in ([], ['unknown'], ['S01', 'S01']):
            with self.assertRaises(LineageError):
                lineage.closure(inputs)
        with self.assertRaisesRegex(LineageError, 'lineage_cycle'):
            lineage.register('x', 'text', ['x'], input_hash='1' * 64)
        lineage.register('x', 'text', ['S01'], input_hash='1' * 64)
        # Corrupted registered graph cannot turn a cycle into an empty closure.
        node = lineage._nodes['x']
        lineage._nodes['x'] = replace(node, input_ids=('x',), input_hashes=(node.output_hash,))
        with self.assertRaisesRegex(LineageError, 'lineage_cycle'):
            lineage.closure(['x'])

    def test_B1_has_no_generation_and_unauthorized_C_is_denied(self):
        host = self.host('B1')
        with self.assertRaisesRegex(HostError, 'method_has_no_initial_generation'):
            host.begin_generation('M', host.source_ids, trace_id='no-M')
        host.apply_view('S02')
        with self.assertRaisesRegex(NativeProtocolError, 'recipient_read_not_allowed'):
            host.authorize_artifact('S01', recipient='C')
        envelope = host.prepare_delivery()
        self.assertEqual(envelope['source_ids'], ['S01', 'S03', 'S04'])
        self.assertNotIn(SOURCES[1]['text'], envelope['memory_text'])
        envelope['recipient'] = 'C'
        calls = []
        with self.assertRaisesRegex(HostError, 'delivery_payload_changed'):
            host.commit_delivery(envelope, calls.append)
        self.assertEqual(calls, [])

    def test_B2_rebuild_for_unchanged_is_required(self):
        host = self.host('B2', 'unchanged')
        host.apply_view()
        with self.assertRaisesRegex(HostError, 'current_legal_rebuild_required'):
            host.prepare_delivery()
        self.generate(host, 'R', list(host.source_ids))
        envelope = host.prepare_delivery()
        self.assertEqual(envelope['artifact_ids'], ['R'])
        self.assertIn('Generated R', envelope['memory_text'])
        for source in SOURCES:
            self.assertNotIn(source['text'], envelope['memory_text'])

    def test_B2_excludes_revoked_and_needs_all_legal_inputs(self):
        host = self.host('B2')
        host.apply_view('S02')
        with self.assertRaises(NativeProtocolError):
            host.begin_generation('R', list(host.source_ids), trace_id='bad-rebuild')
        with self.assertRaisesRegex(HostError, 'rebuild_requires_all_current_legal_raw_sources'):
            host.begin_generation('R', ['S01'], trace_id='incomplete-rebuild')
        self.generate(host, 'R', ['S01', 'S03', 'S04'])
        envelope = host.prepare_delivery()
        calls = []
        result = host.commit_delivery(envelope, lambda e: calls.append(e) or {'status': 'ok'})
        self.assertEqual(result, {'status': 'ok'})
        self.assertEqual(len(calls), 1)
        with self.assertRaisesRegex(HostError, 'delivery_not_prepared'):
            host.commit_delivery(envelope, calls.append)

    def test_B3_uses_only_current_legal_caches(self):
        host = self.host('B3')
        for sid in host.source_ids:
            self.generate(host, 'C_' + sid, [sid])
        checks = host.apply_view('S04')
        self.assertEqual(checks['C_S04'], 'old_packet_and_new_export_denied_export_not_allowed')
        self.assertEqual(checks['C_S01'], 'old_packet_still_authorized')
        envelope = host.prepare_delivery()
        self.assertEqual(envelope['artifact_ids'], ['C_S01', 'C_S02', 'C_S03'])
        self.assertNotIn('Generated C_S04', envelope['memory_text'])
        for source in SOURCES:
            self.assertNotIn(source['text'], envelope['memory_text'])

    def test_tampered_payload_does_not_cross_callback(self):
        host = self.host('B1', 'unchanged')
        host.apply_view()
        envelope = host.prepare_delivery()
        envelope['memory_text'] += ' extra unauthorized data'
        calls = []
        with self.assertRaisesRegex(HostError, 'delivery_payload_changed'):
            host.commit_delivery(envelope, calls.append)
        self.assertEqual(calls, [])

    def test_permission_change_after_prepare_denies_commit(self):
        for permission in ('read_allowed', 'copy_allowed', 'export_allowed'):
            with self.subTest(permission=permission):
                host = self.host('B1', 'unchanged')
                host.apply_view()
                envelope = host.prepare_delivery()
                host.change_source_permissions('S01', **{permission: False})
                calls = []
                with self.assertRaisesRegex(HostError, 'policy_changed_before_final_gate'):
                    host.commit_delivery(envelope, calls.append)
                self.assertEqual(calls, [])
                rows = verify_trace(host.out / 'events.jsonl')
                self.assertFalse(any(r['kind'] == 'target_callback_committed' for r in rows))

    def test_callback_unknown_outcome_is_not_retried(self):
        host = self.host('B1', 'unchanged')
        host.apply_view()
        envelope = host.prepare_delivery()
        calls = []

        def callback(payload):
            calls.append(payload)
            raise TimeoutError('unknown outcome')

        with self.assertRaises(TimeoutError):
            host.commit_delivery(envelope, callback)
        with self.assertRaisesRegex(HostError, 'host_closed_or_halted_no_retry'):
            host.commit_delivery(envelope, callback)
        self.assertEqual(len(calls), 1)

    def test_real_mode_rejects_fixture_and_hy3_receipts(self):
        host = Host(SOURCES, case_id='real-mode-test', method='B0', view='unchanged',
                    out=Path(self.temp.name) / 'real-mode', instrument_only=False)
        self.addCleanup(host.close)
        payload = host.begin_generation('M', list(host.source_ids), trace_id='trace-real')
        with self.assertRaisesRegex(HostError, 'official_flash_receipt_required'):
            host.seal_generation(output='memory', observed_input=payload, receipt={
                'schema': 'native_hy3_receipt', 'model': 'hy3',
                'trace_id': payload['trace_id'], 'input_hash': payload['input_hash'],
                'output_hash': sha('memory'), 'logical_requests': 1, 'request_id': 'old-hy3'})

    def test_real_mode_seals_bound_official_api_receipt(self):
        host = Host(SOURCES, case_id='real-binding-test', method='B0', view='unchanged',
                    out=Path(self.temp.name) / 'real-binding', instrument_only=False)
        self.addCleanup(host.close)
        payload = host.begin_generation('M', list(host.source_ids), trace_id='trace-bound')
        from .host import TEMPLATE
        output = 'Bound API memory'
        receipt = {
            'schema': 'controlled-official-api-generation-v1',
            'trace_id': payload['trace_id'], 'input_hash': payload['input_hash'],
            'output_hash': sha(output), 'logical_requests': 1,
            'request_id': 'chatcmpl-fixture-for-binding-test',
            'model': 'deepseek-flash', 'thinking': 'disabled', 'http_status': 200,
            'request_sha256': 'a' * 64, 'response_sha256': 'b' * 64,
            'original_model_receipt': {
                'raw_response': {'id': 'chatcmpl-fixture-for-binding-test',
                    'choices': [{'message': {'role': 'assistant', 'content': output}}]},
                'actual_messages': [
                    {'role': 'system', 'content': TEMPLATE},
                    {'role': 'user', 'content': canonical(payload).decode('utf-8')}]}}
        sealed = host.seal_generation(output=output, observed_input=payload, receipt=receipt)
        self.assertEqual(sealed['output_hash'], sha(output))
        host.apply_view()
        envelope = host.prepare_delivery()
        self.assertIn(output, envelope['memory_text'])

    def test_sdk_profile_requires_exact_input_and_raw_output_hashes(self):
        from .host import TEMPLATE
        host = Host(SOURCES, case_id='sdk-binding-test', method='B0', view='unchanged',
                    out=Path(self.temp.name) / 'sdk-binding', evidence_profile='official_sdk')
        self.addCleanup(host.close)
        payload = host.begin_generation('M', list(host.source_ids), trace_id='sdk-trace')
        options = {'model': 'deepseek-flash', 'provider': 'deepseek-account',
                   'reasoningEffort': 'off', 'maxTokens': 2048, 'tools': [],
                   'messages': [
                       {'id': 's', 'source': 'system', 'role': 'system',
                        'content': [{'type': 'text', 'text': TEMPLATE}]},
                       {'id': 'u', 'source': 'user', 'role': 'user', 'content': [
                           {'type': 'text', 'text': canonical(payload).decode('utf-8')}]}]}
        chunks = [{'type': 'block-start', 'index': 0, 'blockType': 'text'},
                  {'type': 'text-delta', 'index': 0, 'text': 'SDK '},
                  {'type': 'text-delta', 'index': 0, 'text': 'memory'},
                  {'type': 'block-end', 'index': 0, 'block': {'type': 'text', 'text': 'SDK memory'}},
                  {'type': 'usage', 'usage': {'inputTokens': 50, 'outputTokens': 2}},
                  {'type': 'finish', 'reason': {'kind': 'stop'}, 'replayState': None}]
        original = {'schema': 'controlled-official-sdk-receipt-v1', 'status': 'ok',
                    'request_id': 'sdk-client-uuid', 'provider_response_id': None,
                    'model': 'deepseek-flash', 'provider': 'deepseek-account',
                    'reasoningEffort': 'off', 'maxTokens': 2048, 'output': 'SDK memory',
                    'role': 'source', 'sdk_stream_attempts': 1, 'sdk_provider_dispatch_count': 1,
                    'actual_options': options, 'actual_options_sha256': sha(canonical(options)),
                    'raw_native_chunks': chunks, 'raw_native_chunks_sha256': sha(canonical(chunks))}
        receipt = {'schema': 'controlled-official-sdk-generation-v1',
                   'model': 'deepseek-flash', 'thinking': 'disabled', 'http_status': None,
                   'trace_id': payload['trace_id'], 'input_hash': payload['input_hash'],
                   'output_hash': sha('SDK memory'), 'logical_requests': 1,
                   'request_id': 'sdk-client-uuid', 'provider_response_id': None,
                   'request_sha256': original['actual_options_sha256'],
                   'response_sha256': original['raw_native_chunks_sha256'],
                   'original_model_receipt': original}
        host.seal_generation(output='SDK memory', observed_input=payload, receipt=receipt)
        host.apply_view()
        self.assertIn('SDK memory', host.prepare_delivery()['memory_text'])
        # A raw chunk edit cannot be concealed by leaving the binding unchanged.
        altered = deepcopy(receipt)
        altered['original_model_receipt']['raw_native_chunks'][3]['block']['text'] = 'Other memory'
        with self.assertRaisesRegex(HostError, 'actual_sdk_request_response_hash_changed'):
            host._verify_sdk_receipt('SDK memory', payload, altered)


if __name__ == '__main__':
    unittest.main()
