"""Native DSH runner tests use opaque fake auth and never launch a model."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import deepseek_native as dn
from memory_migration_study.deepseek_sdk import SDKPeer, SDKTransportError


class NativeDeepSeekTests(unittest.TestCase):
    def setUp(self):
        dn.GUARD_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='dsh_fake_test_', dir=dn.GUARD_ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / 'workspace'
        self.workspace.mkdir()
        (self.workspace / '.git').mkdir()
        self.text = 'Synthetic customer is [PVT_AAAAAAAAAAAAAAAAAAAAAAAA_CUSTOMER_1].'
        self.memory = self.workspace / 'AGENTS.md'
        self.memory.write_text(self.text, encoding='utf-8')
        self.home = self.base / 'fresh_runtime'
        self.source = self.base / 'opaque_original.credentials'
        self.source.write_bytes(b'FAKE_AUTH_OPAQUE_MUST_NOT_RETURN')
        self.guard = self.base / 'fake_guard.mjs'
        self.guard.write_text('// fake guard source; never executed', encoding='utf-8')
        self.archive = self.base / 'app.asar'
        self.archive.write_bytes(b'fake official archive, never executable')
        self.runtime = {'executable': str(self.base / 'never_launch.exe'),
            'cli': str(self.archive / 'dsh/lib/cli.js'), 'version': dn.APP_VERSION,
            'cli_entry_sha256': '1' * 64, 'archive': str(self.archive),
            'archive_sha256': hashlib.sha256(self.archive.read_bytes()).hexdigest()}
        rows = [{'id': key, 'disabled': True} for key in sorted(dn.DISABLED_IDS)]
        rows.extend([
            {'id': 'credentials', 'config': {'path': 'IGNORED', 'watch': False}},
            {'id': 'agent-instructions', 'config': deepcopy(dn.INSTRUCTIONS)},
            {'id': 'session-persistence-jsonl', 'config': {'root': 'IGNORED', 'compression': 'none'}},
            {'insert': [{'id': 'study-single-request-guard', 'name': self.guard.as_uri(),
                'config': {'receiptPath': 'IGNORED', 'maxRequests': 1, 'maxTokens': 64,
                    'maxRequestBytes': 65536, 'provider': dn.PROVIDER, 'model': dn.MODEL}}]},
        ])
        self.rows = rows
        self.template = self.base / 'template.json'
        self.save_template()
        self.calls = []

    def save_template(self):
        self.template.write_text(json.dumps(self.rows), encoding='utf-8')

    def summary(self):
        return {'last_terminal_reason': {'kind': 'completed'},
            'final_assistant_interrupted': False,
            'final_assistant_text': '[PVT_AAAAAAAAAAAAAAAAAAAAAAAA_CUSTOMER_1]',
            'final_assistant_source': {'provider': dn.PROVIDER, 'model': dn.MODEL,
                                       'replayState': 'PRIVATE_REPLAY_MUST_NOT_RETURN'},
            'native_instruction_baselines': [{'seq': 3, 'source': {
                'kind': 'agent-instructions', 'baseline': True,
                'changes': [{'path': 'AGENTS.md', 'scope': 'workspace/AGENTS.md',
                    'action': 'set', 'digest': hashlib.sha1(self.text.encode()).hexdigest()}]},
                'content': [{'type': 'text', 'text': '<system-reminder>' + self.text + '</system-reminder>'}]}],
            'assistant_usage_events': [{'turn': 1, 'step': 1,
                'usage': {'inputTokens': 10, 'outputTokens': 4,
                          'account': 'PRIVATE_ACCOUNT_MUST_NOT_RETURN'}}]}

    def invoke(self, *, summary=None, counts=None, effect=None, response_error=None):
        def exchange(argv, workspace, env, prompt, timeout, guard_receipt):
            self.calls.append((argv, workspace, env, prompt, timeout))
            self.assertEqual((self.home / '.credentials.yaml').read_bytes(), self.source.read_bytes())
            generated = json.loads((self.home / 'study.patch.yml').read_text(encoding='utf-8'))
            row = generated[-1]['insert'][0]
            destination = Path(row['config']['receiptPath'])
            self.assertEqual(destination, guard_receipt)
            self.addCleanup(destination.unlink, missing_ok=True)
            evidence = {'agent_attempt_count': 1, 'stream_attempt_count': 1,
                'allowed_stream_count': 1, 'requests': [{'count': 1, 'bodyhash': 'a' * 64,
                    'bytes': 900, 'maxTokens': 64}], 'reject_code': None, 'dry_run': False,
                'shape': {'stage': 'full_request', 'keys': ['messages', 'tools'],
                    'unknown_key_count': 0, 'provider_matches': True, 'model_matches': True,
                    'max_tokens_present': True, 'max_tokens_type': 'number', 'reasoning_off': True,
                    'reasoning_present': True, 'tools_type': 'array', 'tool_count': 0,
                    'message_count': 1, 'roles': ['user'], 'content_types': [['text']],
                    'content_arrays': [True]}}
            if counts:
                evidence.update(counts)
            destination.write_text(json.dumps(evidence), encoding='utf-8')
            if effect:
                effect()
            return {'summary': self.summary() if summary is None else summary,
                    'error': response_error, 'exit_code': 0, 'stderr_bytes': 18}
        with patch.object(dn, '_runtime_metadata', return_value=self.runtime), \
             patch.object(dn, '_restrict_private_dir') as restrict, \
             patch.object(dn, '_exchange', side_effect=exchange):
            result = dn.run_deepseek_question(self.workspace, 'Who is the customer?',
                runtime_home=self.home, patch_template=self.template, guard_path=self.guard,
                credentials_source=self.source)
        if self.calls:
            restrict.assert_called_once_with(self.home)
        return result

    def test_success_opaque_copy_removed_original_unchanged_and_safe_result(self):
        original = self.source.read_bytes()
        with patch.dict(dn.os.environ, {'DEEPSEEK_API_KEY': 'PRIVATE_ENV', 'NODE_OPTIONS': 'INJECT'}):
            result = self.invoke()
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse((self.home / '.credentials.yaml').exists())
        self.assertTrue(result['temporary_credentials_removed'])
        self.assertTrue(result['credentials_source_unchanged'])
        self.assertTrue(result['native_instruction_loaded'])
        self.assertEqual(result['usage'], {'inputTokens': 10, 'outputTokens': 4})
        self.assertIsNone(result['physical_model_requests'])
        encoded = json.dumps(result)
        for secret in ('FAKE_AUTH_OPAQUE', 'PRIVATE_ACCOUNT', 'PRIVATE_REPLAY', 'PRIVATE_ENV'):
            self.assertNotIn(secret, encoded)
        argv, _, env, question, _ = self.calls[0]
        self.assertEqual(question, 'Who is the customer?')
        self.assertNotIn(question, argv)
        self.assertEqual(argv[-4:-2], ['--profile', 'sdk'])
        self.assertEqual(env['DSH_HOME'], str(self.home))
        self.assertNotIn('DEEPSEEK_API_KEY', env)
        self.assertNotIn('NODE_OPTIONS', env)
        generated = json.loads((self.home / 'study.patch.yml').read_text(encoding='utf-8'))
        self.assertIn({'id': 'session-persistence-jsonl', 'disabled': True}, generated)
        self.assertIn({'id': 'plan-mode', 'disabled': True}, generated)
        self.assertEqual(generated[-1]['insert'][0]['config']['maxTokens'], 64)
        self.assertEqual(result['guard_counts']['shape']['tool_count'], 0)
        self.assertIs(result['guard_counts']['reject_code'], None)
        self.assertIs(result['guard_counts']['dry_run'], False)

    def test_missing_loaded_evidence_hides_even_unknown(self):
        summary = self.summary()
        summary.update(final_assistant_text='UNKNOWN', native_instruction_baselines=[])
        result = self.invoke(summary=summary)
        self.assertEqual(result['error'], 'native_instruction_evidence_missing')
        self.assertIsNone(result['answer'])
        self.assertTrue(result['temporary_credentials_removed'])

    def test_noncompleted_turn_and_overlimit_usage_do_not_publish_answer(self):
        for modify, expected in [
            (lambda s: s.update(last_terminal_reason={'kind': 'max-tokens'}), 'sdk_turn_not_completed'),
            (lambda s: s['assistant_usage_events'][0]['usage'].update(outputTokens=65), 'output_token_limit_exceeded'),
        ]:
            with self.subTest(expected=expected):
                if self.home.exists():
                    import shutil
                    shutil.rmtree(self.home)
                summary = self.summary()
                modify(summary)
                result = self.invoke(summary=summary)
                self.assertEqual(result['error'], expected)
                self.assertIsNone(result['raw_response'])

    def test_second_attempt_guard_evidence_fails(self):
        result = self.invoke(counts={'agent_attempt_count': 2})
        self.assertEqual(result['error'], 'guard_request_limit_or_missing')
        self.assertIsNone(result['answer'])

    def test_original_change_is_detected_in_finally(self):
        result = self.invoke(effect=lambda: self.source.write_bytes(b'FAKE_CHANGED_EXTERNALLY'))
        self.assertEqual(result['error'], 'credential_source_changed')
        self.assertFalse(result['credentials_source_unchanged'])
        self.assertTrue(result['temporary_credentials_removed'])
        self.assertIsNone(result['answer'])

    def test_runtime_error_is_fixed_and_temporary_copy_removed(self):
        result = self.invoke(response_error='sdk_transport_or_runtime_failure')
        self.assertEqual(result['error'], 'sdk_transport_or_runtime_failure')
        self.assertIsNone(result['answer'])
        self.assertTrue(result['temporary_credentials_removed'])

    def test_zero_request_auth_failure_keeps_counters_and_only_terminal_kind(self):
        summary = self.summary()
        summary['last_terminal_reason'] = {'kind': 'error',
            'error': {'message': 'PRIVATE_AUTH_BODY_MUST_NOT_RETURN', 'code': 'AUTH'}}
        result = self.invoke(summary=summary, counts={'agent_attempt_count': 0,
            'stream_attempt_count': 0, 'allowed_stream_count': 0, 'requests': [], 'shape': None},
            response_error='sdk_transport_or_runtime_failure')
        self.assertEqual(result['error'], 'sdk_transport_or_runtime_failure')
        self.assertEqual(result['guard_counts']['allowed_stream_count'], 0)
        self.assertEqual(result['last_terminal_reason'], {'kind': 'error'})
        self.assertTrue(result['native_instruction_loaded'])
        self.assertEqual(result['native_instruction_baselines'][0]['content'],
                         [{'type': 'text', 'text': self.text}])
        self.assertNotIn('PRIVATE_AUTH_BODY', json.dumps(result))

    def test_failed_answer_keeps_only_matching_registered_baseline(self):
        summary = self.summary()
        summary['last_terminal_reason'] = {'kind': 'error'}
        summary['native_instruction_baselines'][0]['content'][0]['text'] += ' PRIVATE_UNRELATED_BASELINE'
        summary['native_instruction_baselines'].append({'seq': 99, 'source': {
            'kind': 'agent-instructions', 'baseline': True,
            'changes': [{'path': 'AGENTS.md', 'digest': '0' * 40}]},
            'content': [{'type': 'text', 'text': 'PRIVATE_UNMATCHED_BASELINE'}]})
        result = self.invoke(summary=summary)
        self.assertEqual(result['error'], 'sdk_turn_not_completed')
        self.assertTrue(result['native_instruction_loaded'])
        self.assertEqual(len(result['native_instruction_baselines']), 1)
        self.assertNotIn('PRIVATE_UNRELATED', json.dumps(result))
        self.assertNotIn('PRIVATE_UNMATCHED', json.dumps(result))

    def test_guard_shape_metadata_is_closed_and_content_free(self):
        shape = {'stage': 'full_request', 'keys': ['tools'], 'unknown_key_count': 0,
            'provider_matches': True, 'model_matches': True, 'max_tokens_present': True,
            'max_tokens_type': 'number', 'reasoning_off': True, 'reasoning_present': True,
            'tools_type': 'array', 'tool_count': 1, 'message_count': 1, 'roles': ['user'],
            'content_types': [['text']], 'content_arrays': [True]}
        counts = {'allowed_stream_count': 0, 'requests': [], 'reject_code': 'tools_not_empty', 'shape': shape}
        result = self.invoke(counts=counts)
        self.assertEqual(result['error'], 'guard_request_limit_or_missing')
        self.assertEqual(result['guard_counts']['reject_code'], 'tools_not_empty')
        shape['body'] = 'PRIVATE_NOT_ALLOWED'
        import shutil
        shutil.rmtree(self.home)
        result = self.invoke(counts=counts)
        self.assertIsNone(result['guard_counts'])
        self.assertNotIn('PRIVATE_NOT_ALLOWED', json.dumps(result))

    def test_memory_or_guard_change_hides_result(self):
        result = self.invoke(effect=lambda: self.memory.write_text('changed', encoding='utf-8'))
        self.assertEqual(result['error'], 'memory_changed_during_call')
        self.assertIsNone(result['answer'])

    def test_active_tool_or_unknown_plugin_is_rejected_before_auth_copy(self):
        self.rows[0]['disabled'] = False
        self.save_template()
        result = self.invoke()
        self.assertEqual(result['error'], 'patch_constraints_changed')
        self.assertFalse(self.home.exists())
        self.assertEqual(self.calls, [])

    def test_unknown_insert_plugin_rejected(self):
        self.rows[-1]['insert'][0]['name'] = 'file:///unknown/plugin.mjs'
        self.save_template()
        result = self.invoke()
        self.assertEqual(result['error'], 'patch_guard_invalid')
        self.assertEqual(self.calls, [])

    def test_reused_runtime_home_is_rejected(self):
        self.home.mkdir()
        result = self.invoke()
        self.assertEqual(result['error'], 'runtime_home_not_fresh')
        self.assertEqual(self.calls, [])

    def test_workspace_outside_results_is_rejected(self):
        with patch.object(dn, '_exchange') as exchange:
            result = dn.run_deepseek_question(dn.ROOT, 'Who?', runtime_home=self.home,
                patch_template=self.template, guard_path=self.guard, credentials_source=self.source)
        self.assertEqual(result['error'], 'path_outside_results_or_linked')
        exchange.assert_not_called()

    def test_cleanup_failure_purges_result_and_is_reported(self):
        real_unlink = Path.unlink
        def unlink(path, *args, **kwargs):
            if path == self.home / '.credentials.yaml':
                raise OSError('FAKE_PRIVATE_NATIVE_MESSAGE')
            return real_unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', unlink):
            result = self.invoke()
        self.assertEqual(result['error'], 'temporary_credential_cleanup_failed')
        self.assertFalse(result['temporary_credentials_removed'])
        self.assertIsNone(result['answer'])
        self.assertNotIn('FAKE_PRIVATE_NATIVE_MESSAGE', json.dumps(result))


class SDKContractTests(unittest.TestCase):
    def test_official_catalog_stdout_notice_is_discarded_without_body_retention(self):
        class Process:
            stdin = io.StringIO()
            stdout = io.StringIO('[llm-deepseek-account] PRIVATE_CATALOG_BODY\n' +
                json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'serverInfo': 'fixture'}}) + '\n')
            stderr = io.StringIO()
        peer = SDKPeer(Process())
        self.assertEqual(peer.request('initialize', {}), {'serverInfo': 'fixture'})
        self.assertEqual(peer.stdout_catalog_diagnostics, 1)
        self.assertEqual(peer.notifications, [])
        self.assertIsNone(peer.failure_method)

    def test_unknown_stdout_and_rpc_error_remain_fixed_failures(self):
        for stdout, expected in [
            ('PRIVATE_UNKNOWN_STDOUT\n', 'sdk_non_json_stdout'),
            (json.dumps({'jsonrpc': '2.0', 'id': 1,
                'error': {'code': -32603, 'message': 'PRIVATE_AUTH_BODY'}}) + '\n', 'sdk_rpc_error'),
        ]:
            with self.subTest(expected=expected):
                class Process:
                    stdin = io.StringIO()
                    stderr = io.StringIO()
                process = Process()
                process.stdout = io.StringIO(stdout)
                peer = SDKPeer(process)
                with self.assertRaises(SDKTransportError) as raised:
                    peer.request('initialize', {})
                self.assertEqual(raised.exception.code, expected)
                self.assertEqual(peer.failure_method, 'initialize')
                self.assertNotIn('PRIVATE', str(raised.exception))
                if expected == 'sdk_rpc_error':
                    self.assertEqual(raised.exception.rpc_code, -32603)

    def test_caller_session_id_prompt_blocks_wait_and_shutdown(self):
        calls = []
        class Process:
            def __init__(self):
                self.stdin, self.stdout, self.stderr = io.StringIO(), io.StringIO(), io.StringIO()
                self.returncode = None
            def poll(self):
                return self.returncode
            def wait(self, timeout):
                self.returncode = 0
                return 0
            def kill(self):
                self.returncode = -9
        class Peer:
            def __init__(self, process, **kwargs):
                self.notifications, self.stderr_bytes = [], 0
                assert kwargs == {'allow_prompts': True, 'max_prompts': 1}
            def request(self, method, params, **kwargs):
                calls.append((method, params))
                if method == 'initialize':
                    return {'serverInfo': {'name': 'deepseek-harness-sdk-runtime', 'version': '0.0.1'}}
                if method == 'session/working-directory/set':
                    return {'cwd': params['path']}
                if method == 'session/prompt':
                    return {'messageId': 'synthetic'}
                return {}
        process = Process()
        with tempfile.TemporaryDirectory() as tmp:
            # Keep the strict production no-link check; canonicalize the fake
            # Windows TEMP root (which can be supplied as RUNNER~1 by CI).
            guard_receipt = Path(tmp).resolve() / 'counts.json'
            guard_receipt.write_text(json.dumps({'agent_attempt_count': 0,
                'stream_attempt_count': 0, 'allowed_stream_count': 0, 'requests': [],
                'reject_code': None, 'shape': None, 'dry_run': False}))
            with patch.object(dn.subprocess, 'Popen', return_value=process), patch.object(dn, 'SDKPeer', Peer):
                result = dn._exchange(['official-entry'], Path('fixture'), {}, 'Who?', 120, guard_receipt)
        self.assertIsNone(result['error'])
        self.assertEqual([method for method, _ in calls], ['initialize',
            'session/working-directory/set', 'session/prompt', 'session/wait', 'shutdown'])
        session = calls[1][1]['sessionId']
        self.assertEqual(calls[2][1], {'sessionId': session, 'contentBlocks': [{'type': 'text', 'text': 'Who?'}]})
        self.assertEqual(calls[3][1]['sessionId'], session)
        self.assertEqual(result['exit_code'], 0)

    def test_missing_or_nonzero_guard_blocks_before_prompt(self):
        for evidence in (None, {'agent_attempt_count': 1, 'stream_attempt_count': 0,
                                'allowed_stream_count': 0, 'requests': []}):
            with self.subTest(evidence=evidence), tempfile.TemporaryDirectory() as tmp:
                calls = []
                class Process:
                    def __init__(self):
                        self.stdin, self.stdout, self.stderr = io.StringIO(), io.StringIO(), io.StringIO()
                        self.returncode = None
                    def poll(self): return self.returncode
                    def wait(self, timeout): self.returncode = 0; return 0
                    def kill(self): self.returncode = -9
                class Peer:
                    def __init__(self, *args, **kwargs):
                        self.notifications, self.stderr_bytes = [], 0
                    def request(self, method, params, **kwargs):
                        calls.append(method)
                        if method == 'initialize':
                            return {'serverInfo': {'name': 'deepseek-harness-sdk-runtime', 'version': '0.0.1'}}
                        if method == 'session/working-directory/set': return {'cwd': params['path']}
                        return {}
                target = Path(tmp) / 'counts.json'
                if evidence is not None:
                    target.write_text(json.dumps(evidence))
                with patch.object(dn.subprocess, 'Popen', return_value=Process()), patch.object(dn, 'SDKPeer', Peer):
                    result = dn._exchange(['official-entry'], Path('fixture'), {}, 'Who?', 120, target)
                self.assertEqual(result['error'], 'guard_not_ready')
                self.assertEqual(calls, ['initialize', 'session/working-directory/set', 'shutdown'])
                self.assertNotIn('session/prompt', calls)


if __name__ == '__main__':
    unittest.main()
