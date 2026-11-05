"""Real disk readback with mocked model/native calls; never a paid request."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from . import receiver_runtime as runtime
from .read_receiver import canonical, export_batch
from .test_read_receiver import fixture


class ReceiverRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root/'receiver.sqlite'
        fixture(self.db)
        self.job = self.root/'receiver-job'
        self.questions = [{'question_id': 'q1', 'question': 'What is the delivered memory?'}]
        self.client = Mock()
        self.output = '{"q1":"answer from imported memory"}'
        self.receipt_model = 'deepseek-flash'
        self.client.generate.side_effect = self.fake_flash
        self.client_patch = patch.object(runtime, 'FlashSDKClient', return_value=self.client)
        self.client_patch.start()
        self.python_patch = patch.object(runtime, 'PYTHON', sys.executable)
        self.python_patch.start()
        self.native_projects = self.root/'native-projects'
        (self.native_projects/'one-session').mkdir(parents=True)
        self.native_patch = patch.object(runtime, 'NATIVE_PROJECTS', self.native_projects)
        self.native_patch.start()

    def tearDown(self):
        self.native_patch.stop()
        self.python_patch.stop()
        self.client_patch.stop()
        self.temp.cleanup()

    def fake_flash(self, messages, job_id, max_tokens, role):
        self.assertEqual((job_id, max_tokens, role), ('receiver-answer', 2048, 'target'))
        return {'output': self.output, 'receipt': {
            'status': 'ok', 'actual_model': self.receipt_model, 'provider': 'deepseek-account',
            'physical_request_count': 1, 'temporary_credentials_removed': True,
            'business_messages_sha256': runtime.digest(canonical(messages)),
            'response_sha256': runtime.digest(self.output), 'request_sha256': 'a'*64,
            'dispatch_sha256': 'b'*64, 'output_tokens': 20}}

    def native_fake(self, *, extra_shell=None, omit_reader=False, malformed=False):
        def execute(job, objective, allowed_reads, output_name):
            self.assertFalse((job/'retrieved_memory.json').exists())
            self.assertFalse((job/'answers.json').exists())
            self.assertEqual(set(allowed_reads), {job/'retrieved_memory.json', job/'questions.json'})
            self.assertEqual(output_name, 'answers.json')
            self.assertIn('worker claim --wait-seconds 0', objective)
            # Simulate files actually created by native PowerShell and Write,
            # never by the production receiver runtime before run_workbuddy.
            export_batch(self.db, 'batch-1', job/'retrieved_memory.json')
            answer = 'malformed native JSON' if malformed else self.output
            (job/'answers.json').write_text(answer, encoding='utf-8')
            runtime.write_json(job/'native_job.json', {'sessionId': 'mock-hy3-session'})
            argv = runtime._reader_command(self.db.resolve(), 'batch-1', job/'retrieved_memory.json')
            commands = [] if omit_reader else [('PowerShell', {'command': runtime._powershell(argv)})]
            commands += [('Read', {'file_path': str(job/'retrieved_memory.json')}),
                         ('Read', {'file_path': str(job/'questions.json')}),
                         ('Write', {'file_path': str(job/'answers.json')})]
            if extra_shell:
                commands.append(('PowerShell', {'command': extra_shell}))
            launcher = runtime.REPO.parent/'codex-workbuddy-gateway-windows/scripts/launch.mjs'
            commands += [('PowerShell', {'command': "& 'D:/node/node.exe' '"+str(launcher)+
                         "' worker report --status completed --text 'completed'"}),
                         ('PowerShell', {'command': "& 'D:/node/node.exe' '"+str(launcher)+
                         "' worker claim --wait-seconds 0"})]
            rows = [{'type': 'function_call', 'name': name, 'arguments': json.dumps(args),
                     'providerData': {'model': 'hy3', 'requestModelId': 'hy3'}}
                    for name, args in commands]
            path = self.native_projects/'one-session/mock-hy3-session.jsonl'
            path.write_bytes(b'\n'.join(canonical(row) for row in rows)+b'\n')
            if malformed:
                raise json.JSONDecodeError('invalid', answer, 0)
            return json.loads(answer), {'session_id': 'mock-hy3-session',
                                       'runtime_source': 'desktop_queue'}
        return execute

    def test_flash_context_only_from_real_reader_subprocess_and_public_questions(self):
        answers, evidence = runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(answers, {'q1': 'answer from imported memory'})
        self.assertTrue(evidence['answers_schema_valid'])
        self.assertEqual(evidence['reader_process_boundary'], 'fresh_python_process')
        self.assertEqual(evidence['reader_receipt']['recipient_id'], 'AgentB')
        messages = self.client.generate.call_args.args[0]
        business = json.loads(messages[1]['content'])
        self.assertEqual(set(business), {'memory', 'questions'})
        self.assertEqual(business['questions'], self.questions)
        self.assertNotIn('FORBIDDEN_ORIGINAL_CANARY', business['memory'])
        self.assertNotIn('OTHER_BATCH_CANARY', business['memory'])
        self.assertNotIn('reader_receipt', messages[1]['content'])
        again = runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(again, (answers, evidence))
        self.assertEqual(self.client.generate.call_count, 1)

    def test_questions_cannot_supply_reference_answers(self):
        invalid = [{**self.questions[0], 'answer': 'forbidden reference'}]
        with self.assertRaisesRegex(RuntimeError, 'exclude_reference_answers'):
            runtime.answer_receiver('flash', self.db, 'batch-1', invalid, self.job)
        self.client.generate.assert_not_called()

    def test_sdk_wrong_actual_model_stops_without_retry(self):
        self.receipt_model = 'some-other-model'
        with self.assertRaisesRegex(RuntimeError, 'actual_model_receipt'):
            runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        with self.assertRaisesRegex(RuntimeError, 'incomplete_sdk_dispatch_no_retry'):
            runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(self.client.generate.call_count, 1)

    def test_invalid_answer_json_is_preserved_and_counted_without_repair(self):
        self.output = '```json\n{"q1":"answer"}\n```'
        answers, evidence = runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(answers, {})
        self.assertEqual(evidence['status'], 'answer_schema_failed')
        self.assertEqual((self.job/'answers.json').read_text(encoding='utf-8'), self.output)
        runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(self.client.generate.call_count, 1)

    def test_reader_receipt_recipient_forgery_stops_before_model(self):
        self.job.mkdir()
        export_batch(self.db, 'batch-1', self.job/'retrieved_memory.json')
        receipt_path = self.job/'retrieved_memory.json.receipt.json'
        receipt = json.loads(receipt_path.read_bytes())
        receipt['recipient_id'] = 'forged-recipient'
        receipt_path.write_bytes(canonical(receipt))
        runtime.write_json(self.job/'reader_process.private.json', {'mock': 'earlier subprocess'})
        with self.assertRaisesRegex(RuntimeError, 'receipt_binding_failed:recipient_id'):
            runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        self.client.generate.assert_not_called()

    def test_hy3_native_creates_readback_and_answers_and_trace_is_verified(self):
        with patch.object(runtime, 'run_workbuddy', side_effect=self.native_fake()) as native:
            answers, evidence = runtime.answer_receiver('hy3', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(answers, {'q1': 'answer from imported memory'})
        self.assertTrue(evidence['native_reader_command_verified'])
        self.assertEqual(evidence['native_reader_audit']['reader_PowerShell_count'], 1)
        self.assertTrue(evidence['native_reader_audit']['report_then_nonwaiting_claim_verified'])
        self.assertEqual(evidence['actual_model'], 'hy3')
        self.assertIsNone(evidence['workbuddy_fee_cny'])
        self.assertEqual(native.call_count, 1)
        self.client.generate.assert_not_called()

    def test_hy3_cannot_replace_actual_reader_command_with_fabricated_files(self):
        with patch.object(runtime, 'run_workbuddy', side_effect=self.native_fake(omit_reader=True)):
            with self.assertRaisesRegex(RuntimeError, 'read_order_or_count_failed'):
                runtime.answer_receiver('hy3', self.db, 'batch-1', self.questions, self.job)

    def test_hy3_foreign_powershell_read_is_rejected(self):
        fake = self.native_fake(extra_shell="Get-Content 'C:/sender/raw-secrets.json'")
        with patch.object(runtime, 'run_workbuddy', side_effect=fake):
            with self.assertRaisesRegex(RuntimeError, 'unexpected_receiver_native_shell_command'):
                runtime.answer_receiver('hy3', self.db, 'batch-1', self.questions, self.job)

    def test_hy3_invalid_json_keeps_native_original_without_answer_repair(self):
        with patch.object(runtime, 'run_workbuddy', side_effect=self.native_fake(malformed=True)):
            answers, evidence = runtime.answer_receiver('hy3', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(answers, {})
        self.assertEqual(evidence['status'], 'answer_schema_failed')
        self.assertEqual(evidence['native_json_parser_failure'], 'JSONDecodeError')
        self.assertEqual((self.job/'answers.json').read_text(encoding='utf-8'), 'malformed native JSON')

    def test_changed_questions_prevent_cache_reuse(self):
        runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        changed = [{'question_id': 'q1', 'question': 'A different public question'}]
        with self.assertRaisesRegex(RuntimeError, 'job_inputs_changed'):
            runtime.answer_receiver('flash', self.db, 'batch-1', changed, self.job)
        self.assertEqual(self.client.generate.call_count, 1)

    def test_duplicate_json_keys_fail_schema_instead_of_silent_overwrite(self):
        self.output = '{"q1":"first","q1":"second"}'
        answers, evidence = runtime.answer_receiver('flash', self.db, 'batch-1', self.questions, self.job)
        self.assertEqual(answers, {})
        self.assertFalse(evidence['answers_schema_valid'])


if __name__ == '__main__':
    unittest.main()
