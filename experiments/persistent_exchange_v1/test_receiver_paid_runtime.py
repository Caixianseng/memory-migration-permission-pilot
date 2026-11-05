"""Real temporary SQLite/read subprocess, explicitly MOCK native inference."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from . import receiver_paid_runtime as runtime
from .store import AgentStore, TrustedPolicy, export_package, import_package


class PaidNativeReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MOCK-paid-receiver-', dir=Path(__file__).parent)
        self.root = runtime._resolve(self.temp.name)
        self.config = self.root/'MOCK-native-config'
        self.job = self.root/'MOCK-receiver-job'
        self.driver = self.root/'MOCK-one-shot-driver.mjs'
        self.driver.write_text('// MOCK driver, never executed', encoding='utf-8')
        self.qual = self.root/'MOCK-independent-qualification.json'
        self.questions = [{'question_id': 'MOCK-q1', 'question': 'What marker was transferred?'}]
        self.memory = 'MOCK_TRANSFERRED_MARKER_7F12'
        self.batch = 'MOCK-first-import'
        sender = AgentStore(self.root/'MOCK-sender.sqlite', 'B')
        receiver = AgentStore(self.root/'MOCK-receiver.sqlite', 'A')
        policy = TrustedPolicy(self.root/'MOCK-policy.sqlite')
        ref = sender.add_original('MOCK-B-source', self.memory)
        policy.register_sources([ref])
        policy.set_permissions('A', [ref['source_id']])
        generated = sender.add_memory('MOCK-model-memory', self.memory, [ref['source_id']])
        packet = export_package(sender, policy, 'A', [generated['memory_key']], batch_id=self.batch)
        receipt = import_package(receiver, policy, packet)
        self.packet_file = self.root/'MOCK-transport.packet.json'
        self.save(self.packet_file, packet)
        self.database = receiver.path
        self.delivery = {'receiver_db': str(self.database), 'policy_db': str(policy.path), 'policy_epoch': policy.epoch,
                         'batch_id': self.batch, 'memory_keys': [generated['memory_key']],
                         'dependencies': generated['dependencies'], 'receipt': receipt,
                         'reopened_content_sha256': runtime._sha(self.memory), 'packet_path': str(self.packet_file),
                         'packet_file_sha256': runtime._sha(self.packet_file.read_bytes()),
                         'packet_bytes': self.packet_file.stat().st_size, 'content_bytes': len(self.memory.encode('utf-8')),
                         'close_reopen_verified': True, 'export_import_reopen_ms': 1}
        for store in (sender, receiver, policy):
            store.close()
        qualification = {'schema': 'workbuddy-hy3-native-paid-one-shot-envelope-v1',
            'status': 'verified_native_paid_one_shot', 'jobType': 'qualification', 'jobId': 'MOCK-qualification',
            'sessionId': '00000000-0000-0000-0000-000000000001', 'canonical_model_family': 'Hy3',
            'requestedModel': 'hy3-x', 'actualModels': ['hy3-x'], 'requestModelIds': ['hy3-x'],
            'mode': 'ask', 'tools': '', 'toolCallCount': 0, 'nativeUserRequestCount': 1,
            'nativeBusinessQueryMatchesSubmitted': True, 'providerErrors': [],
            'nativeExecution': {'status': 'native_prompt_returned', 'stopReason': 'end_turn', 'modelPromptsSubmitted': 1,
                'after': {'status': 'completed', 'isProcessing': False, 'model': 'hy3-x', 'mode': 'ask', 'tools': ''}},
            'recheck': {'originalFilesModified': False, 'newNativeSessionsCreated': 0,
                        'newModelPromptsSubmitted': 0, 'nativeChannelsCalled': []}, 'MOCK_fixture': True}
        self.save(self.qual, qualification)
        self.native_calls = 0
        self.reader_calls = 0
        self.output = json.dumps({'MOCK-q1': self.memory}, ensure_ascii=False)
        self.modify_envelope = lambda envelope: envelope
        self.real_run = subprocess.run
        self.patches = [patch.object(runtime, 'DRIVER', self.driver),
                        patch.object(runtime, 'NATIVE_CONFIG', self.config),
                        patch.object(runtime.subprocess, 'run', side_effect=self.run_process)]
        for context in self.patches:
            context.start()

    def tearDown(self):
        for context in reversed(self.patches):
            context.stop()
        self.temp.cleanup()

    def save(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True), encoding='utf-8')

    def run_process(self, argv, **kwargs):
        if argv[0] == str(runtime.PYTHON):
            self.reader_calls += 1
            self.assertEqual(Path(argv[4]).name, 'read_receiver.py')
            # This is genuinely a new Python process, with no native inference.
            return self.real_run(argv, **kwargs)
        self.assertEqual(argv[:2], [str(runtime.NODE), str(self.driver)])
        self.native_calls += 1
        input_path, envelope_path = Path(argv[3]), Path(argv[5])
        job = runtime._load(input_path)
        self.assertEqual({path.name for path in input_path.parent.iterdir()}, {'job.json'})
        self.assertEqual(job['jobType'], 'receiver')
        self.assertEqual(job['model'], 'hy3-x')
        self.assertEqual(job['businessInput'], {'memory': self.memory, 'questions': self.questions})
        self.assertEqual(set(job['businessInput']), {'memory', 'questions'})
        self.assertEqual(job['instruction'], runtime.ANSWER_INSTRUCTIONS)
        self.assertNotEqual(job['sessionId'], runtime._load(self.qual)['sessionId'])
        prompt = runtime._prompt(job)
        prefix = '<system-reminder>MOCK official App reminder</system-reminder>\n'
        actual_user = prefix+'<user_query>'+prompt+'</user_query>'
        # Explicitly fake native evidence is stored under the temporary mock
        # config, never in real WorkBuddy projects or any study result folder.
        native_raw = (json.dumps({'MOCK_fixture': True, 'type': 'message', 'role': 'user', 'content': actual_user}, ensure_ascii=False)+'\n'
                      +json.dumps({'MOCK_fixture': True, 'role': 'assistant', 'content': self.output}, ensure_ascii=False)+'\n').encode('utf-8')
        history = self.config/'projects'/'MOCK-project'/(job['sessionId']+'.jsonl')
        history.parent.mkdir(parents=True, exist_ok=True)
        history.write_bytes(native_raw)
        qualification = runtime._qualification(self.qual)[2]
        envelope = {'schema': 'workbuddy-hy3-native-paid-one-shot-envelope-v1',
            'status': 'verified_native_paid_one_shot', 'canonical_model_family': 'Hy3',
            'jobId': job['jobId'], 'jobType': 'receiver', 'sessionId': job['sessionId'], 'workspace': job['workspace'],
            'mode': 'ask', 'tools': '', 'requestedModel': 'hy3-x', 'actualModels': ['hy3-x'], 'requestModelIds': ['hy3-x'],
            'toolCallCount': 0, 'nativeUserRequestCount': 1, 'nativeBusinessQueryMatchesSubmitted': True,
            'nativeUserPromptMatchesSubmitted': False, 'nativeUserPromptSha256': runtime._sha(actual_user),
            'nativeUserBusinessBinding': {'businessMatches': True, 'rawMatches': False,
                'scope': 'exact_submitted_prompt_in_single_native_user_query',
                'nativeBusinessQuerySha256': runtime._sha(prompt), 'appAddedUserContextObserved': True,
                'appAddedUserContextCharacters': len(prefix), 'appAddedUserContextSha256': runtime._sha(prefix)},
            'providerErrors': [], 'inputFileSha256': runtime._sha(input_path.read_bytes()),
            'businessInputSha256': runtime._sha(job['businessInput']), 'submittedUserPromptSha256': runtime._sha(prompt),
            'qualification': qualification, 'output': self.output, 'actualAssistantOutputSha256': runtime._sha(self.output),
            'nativeExecution': {'status': 'native_prompt_returned', 'stopReason': 'end_turn', 'modelPromptsSubmitted': 1,
                'after': {'sessionId': job['sessionId'], 'status': 'completed', 'isProcessing': False,
                          'model': 'hy3-x', 'mode': 'ask', 'tools': ''}},
            'nativeHistoryPath': str(history), 'nativeHistoryPrefixBytes': len(native_raw),
            'nativeHistoryPrefixLines': 2, 'nativeHistoryPrefixSha256': runtime._sha(native_raw),
            'automaticReplay': False, 'queueUsed': False, 'completeUpstreamSystemInputObserved': False,
            'remoteProviderRequestBytesObserved': False, 'MOCK_fixture': True}
        envelope = self.modify_envelope(envelope)
        self.save(envelope_path, envelope)
        return subprocess.CompletedProcess(argv, 0, stdout='{"MOCK_native":true}', stderr='')

    def answer(self, questions=None):
        return runtime.answer_paid_hy3(self.database, self.batch, questions or self.questions,
                                       self.job, self.qual)

    def test_fresh_real_reader_zero_tool_paid_context_and_readonly_cached_return(self):
        answers, evidence = self.answer()
        self.assertEqual(answers, {'MOCK-q1': self.memory})
        self.assertEqual((self.reader_calls, self.native_calls), (1, 1))
        self.assertEqual(evidence['execution_mode'], 'controller_readback_native_paid_one_shot')
        self.assertEqual(evidence['actual_models'], ['hy3-x'])
        self.assertEqual(evidence['request_model_ids'], ['hy3-x'])
        self.assertFalse(evidence['native_model_read_sqlite'])
        self.assertEqual(evidence['reader_process_boundary'], 'fresh_python_process')
        self.assertEqual(evidence['native_tool_call_count'], 0)
        self.assertIsNone(evidence['physical_supplier_calls'])
        self.assertIsNone(evidence['workbuddy_fee_cny'])
        self.assertFalse(evidence['complete_upstream_system_input_observed'])
        self.assertFalse(evidence['native_paid_envelope']['nativeUserPromptMatchesSubmitted'])
        self.assertTrue(evidence['native_paid_envelope']['nativeBusinessQueryMatchesSubmitted'])
        self.assertEqual((self.job/'answers.json').read_text(encoding='utf-8'), self.output)
        self.assertEqual(self.answer(), (answers, evidence))
        self.assertEqual((self.reader_calls, self.native_calls), (1, 1), 'verified resume must not spawn another reader or model')

    def test_strict_fence_failure_preserves_raw_output_without_regeneration(self):
        self.output = '```json\n'+self.output+'\n```'
        answers, evidence = self.answer()
        self.assertEqual(answers, {})
        self.assertEqual(evidence['status'], 'answer_schema_failed')
        self.assertEqual((self.job/'answers.json').read_text(encoding='utf-8'), self.output)
        self.assertEqual(self.answer()[0], {})
        self.assertEqual(self.native_calls, 1)

    def test_foreign_model_or_unverified_native_failure_never_retries(self):
        self.modify_envelope = lambda envelope: {**envelope, 'actualModels': ['deepseek-flash']}
        with self.assertRaisesRegex(RuntimeError, 'paid_native_identity_or_zero_tool_proof_failed'):
            self.answer()
        self.assertTrue((self.job/'paid_dispatch_intent.json').exists())
        with self.assertRaisesRegex(RuntimeError, 'paid_receiver_incomplete_dispatch_no_retry'):
            self.answer()
        self.assertEqual(self.native_calls, 1)

    def test_question_gold_fields_rejected_before_read_or_dispatch(self):
        poisoned = [dict(self.questions[0], answer=self.memory)]
        with self.assertRaisesRegex(RuntimeError, 'questions_must_exclude_reference_answers_and_metadata'):
            self.answer(poisoned)
        self.assertEqual((self.reader_calls, self.native_calls), (0, 0))

    def test_cache_tamper_and_changed_question_do_not_dispatch(self):
        self.answer()
        changed = [dict(self.questions[0], question='A different question')]
        with self.assertRaisesRegex(RuntimeError, 'paid_receiver_contract_changed'):
            self.answer(changed)
        (self.job/'answers.json').write_text('MODIFIED', encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'verified_paid_receiver_answers_changed'):
            self.answer()
        self.assertEqual(self.native_calls, 1)

    def test_native_prefix_change_and_business_hash_tamper_are_rejected(self):
        _, evidence = self.answer()
        history = Path(evidence['native_paid_envelope']['nativeHistoryPath'])
        raw = history.read_bytes()
        history.write_bytes(b'X'+raw[1:])
        with self.assertRaisesRegex(RuntimeError, 'paid_native_history_prefix_changed'):
            self.answer()
        self.assertEqual(self.native_calls, 1)

    def test_verified_cache_never_repairs_a_missing_public_question_artifact(self):
        self.answer()
        questions_path = self.job/'questions.json'
        questions_path.unlink()
        with self.assertRaisesRegex(RuntimeError, 'verified_paid_receiver_contract_artifact_missing'):
            self.answer()
        self.assertFalse(questions_path.exists())
        self.assertEqual((self.reader_calls, self.native_calls), (1, 1))

    def test_invalid_qualification_stops_before_model_and_reader(self):
        qualification = runtime._load(self.qual)
        qualification['requestModelIds'] = ['hy3']
        self.save(self.qual, qualification)
        with self.assertRaisesRegex(RuntimeError, 'paid_qualification_not_verified_zero_tool_hy3'):
            self.answer()
        self.assertEqual((self.reader_calls, self.native_calls), (0, 0))

    def test_final_audit_accepts_controller_reader_and_counts_native_turn_without_supplier_guess(self):
        from . import finalize as audit
        answers, evidence = self.answer()
        record = {'case_id': 'MOCK-case', 'direction': 'B_to_A', 'arm': 'full_rebuild',
                  'recipient': 'A', 'receiver_platform': 'hy3', 'job_dir': str(self.job),
                  'answers': answers, 'receiver_evidence': evidence, 'delivery': self.delivery}
        augmented, proof = audit._receiver(self.root, record, ['MOCK-B-source'], expected_memory=self.memory,
                                            expected_refs=self.delivery['dependencies'])
        self.assertEqual(augmented['received_memory'], self.memory)
        self.assertEqual(proof['execution_mode'], 'controller_readback_native_paid_one_shot')
        self.assertEqual(proof['identity']['actual_models'], ['hy3-x'])
        self.assertEqual(proof['identity']['native_tasks'], 1)
        self.assertEqual(proof['identity']['native_queue_submissions'], 0)
        self.assertEqual(proof['identity']['native_direct_session_submissions'], 1)
        self.assertNotIn('native_reader_command_verified', evidence)
        ledger = audit._aggregate([proof])
        self.assertEqual(ledger['hy3_native_tasks'], 1)
        self.assertEqual(ledger['hy3_native_queue_submissions'], 0)
        self.assertEqual(ledger['hy3_queue_submission_without_verified_model_execution'], 0)
        self.assertEqual(ledger['hy3_native_direct_session_submissions'], 1)
        self.assertIsNone(ledger['hy3_physical_supplier_calls'])
        self.assertIsNone(ledger['all_platform_supplier_fee_cny'])

    def test_local_recheck_finishes_existing_native_response_without_any_subprocess(self):
        # Simulate the observed failure point: native App has already completed,
        # but history-file I/O failed before raw answers/cache were persisted.
        with patch.object(runtime, 'verify_paid_history_prefix', side_effect=FileNotFoundError('MOCK Windows long path')):
            with self.assertRaises(FileNotFoundError):
                self.answer()
        self.assertFalse((self.job/'answers.json').exists())
        self.assertFalse((self.job/'receiver_paid_verified.json').exists())
        self.assertTrue((self.job/'paid_native_process.json').exists())
        cost, failure = self.job/'receiver_attempt_cost.json', self.job.parent/'receiver_recovery_failure.json'
        self.save(cost, {'MOCK': True, 'qualified_native_turns': 0, 'supplier_fee': None})
        self.save(failure, {'MOCK': True, 'error': 'original local path failure'})
        originals = {path: path.read_bytes() for path in (cost, failure,
                     self.job/'native_paid_one_shot/envelope.json', self.job/'paid_dispatch_intent.json')}
        with patch.object(runtime.subprocess, 'run', side_effect=AssertionError('offline recheck must never launch anything')):
            answers, evidence = runtime.recheck_paid_hy3_local(self.database, self.batch, self.questions, self.job, self.qual)
            self.assertEqual(runtime.recheck_paid_hy3_local(self.database, self.batch, self.questions, self.job, self.qual),
                             (answers, evidence))
        self.assertEqual(answers, {'MOCK-q1': self.memory})
        self.assertTrue(evidence['answers_schema_valid'])
        self.assertEqual((self.reader_calls, self.native_calls), (1, 1))
        for path, raw in originals.items():
            self.assertEqual(path.read_bytes(), raw)
        receipt = runtime._load(self.job/'offline_recheck_receipt.json')
        self.assertEqual(receipt['newNativeChannelsCalled'], [])
        self.assertEqual(receipt['newModelPromptsSubmitted'], 0)
        self.assertEqual(receipt['newNativeSessionsCreated'], 0)
        self.assertFalse(receipt['nativeIdentityPathsRewritten'])
        self.assertEqual(receipt['answersFileSha256'], runtime._sha((self.job/'answers.json').read_bytes()))
        self.assertEqual(receipt['verifiedCacheFileSha256'], runtime._sha((self.job/'receiver_paid_verified.json').read_bytes()))


if __name__ == '__main__':
    unittest.main()
