"""MOCK-ONLY provider replies; real receiver stores, readback and file bindings.

No test opens a real experiment answer, native session, SDK private directory,
gateway, or model. Published fixture questions are projected without references.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from . import receiver_recovery as recovery
from .prepare_data import receiver_questions
from .read_receiver import canonical, export_batch
from .receiver_paid_runtime import ANSWER_INSTRUCTIONS, DRIVER, _prompt
from .store import AgentStore, TrustedPolicy, export_package, import_package


def sha(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, bytes):
        value = canonical(value)
    return hashlib.sha256(value).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value)+b'\n')


def get(path):
    return json.loads(path.read_bytes())


class ReceiverRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='receiver-recovery-MOCK-ONLY-',
                                               dir=Path(__file__).resolve().parents[2])
        self.root = Path(self.temp.name)
        self.qualification = self.root/'billing'/'qualification.mock.json'
        put(self.qualification, {'mock_only': True, 'jobId': 'MOCK-ONLY-qualification',
                                 'sessionId': str(uuid.uuid4())})
        self.q_binding = {'path': str(self.qualification), 'sha256': sha(self.qualification.read_bytes()),
                          'jobId': get(self.qualification)['jobId'],
                          'sessionId': get(self.qualification)['sessionId']}
        # Only public projections enter fixtures supplied to the model stub.
        evaluation = get(Path(__file__).with_name('data')/'evaluation_only.json')
        self.records = []
        for cid, arm in (('exchange-n020-r00', 'full_rebuild'), ('exchange-n020-r50', 'selective')):
            direction = 'B_to_A'
            base = self.root/'receiver_jobs'/cid/direction/arm
            base.mkdir(parents=True)
            sender = AgentStore(base/'sender-MOCK-ONLY.sqlite', 'B')
            receiver = AgentStore(base/'receiver.sqlite', 'A')
            policy = TrustedPolicy(base/'policy.sqlite')
            try:
                source = sender.add_original('B-MOCK-'+cid, 'MOCK-ONLY original source.')
                policy.register_sources([source])
                policy.set_permissions('A', [source['source_id']])
                artifact = sender.add_memory('MOCK-memory', 'MOCK-ONLY lawful transferred memory.',
                                             [source['source_id']], provenance={'generator': 'MOCK-ONLY'})
                packet = export_package(sender, policy, 'A', [artifact['memory_key']],
                                        batch_id=cid+'-'+direction+'-'+arm)
                imported = import_package(receiver, policy, packet)
                epoch = policy.epoch
            finally:
                sender.close()
                receiver.close()
                policy.close()
            packet_path = base/'transport.packet.json'
            put(packet_path, packet)
            delivery = {'receiver_db': str(base/'receiver.sqlite'), 'batch_id': packet['batch_id'],
                'memory_keys': [artifact['memory_key']], 'policy_db': str(base/'policy.sqlite'),
                'policy_epoch': epoch, 'dependencies': artifact['dependencies'], 'receipt': imported,
                'packet_path': str(packet_path), 'packet_file_sha256': sha(packet_path.read_bytes()),
                'packet_bytes': packet_path.stat().st_size,
                'content_bytes': len(artifact['content'].encode('utf-8')),
                'reopened_content_sha256': sha(artifact['content']), 'close_reopen_verified': True,
                'source_protocol_clean': True, 'source_protocol_rejected_memory_keys': [],
                'export_import_reopen_ms': 1}
            put(base/'delivery.json', delivery)
            questions = receiver_questions(evaluation, cid, direction)
            put(base/'questions.json', questions)
            export_batch(delivery['receiver_db'], delivery['batch_id'], base/'retrieved_memory.json')
            payload = get(base/'retrieved_memory.json')
            contract = {'schema': 'persistent-paid-receiver-contract-v1',
                'receiver_database': delivery['receiver_db'], 'batch_id': delivery['batch_id'],
                'database_sha256': sha(Path(delivery['receiver_db']).read_bytes()), 'questions': questions,
                'qualification': self.q_binding, 'driver_sha256': sha(DRIVER.read_bytes()),
                'model': 'hy3-x', 'mode': 'ask', 'tools': '', 'soft_output_characters': 4096,
                'reader_sha256': sha(Path(__file__).with_name('read_receiver.py').read_bytes())}
            put(base/'receiver_paid_contract.json', contract)
            child = base/'native_paid_one_shot'
            job = self.job(child, {'memory': payload['memory'], 'questions': questions})
            put(child/'job.json', job)
            envelope = self.envelope(job, (child/'job.json').read_bytes(), '', success=False)
            put(child/'envelope.json', envelope)
            put(base/'paid_dispatch_intent.json', {'schema': 'persistent-paid-receiver-intent-v1',
                'job_id': job['jobId'], 'session_id': job['sessionId'],
                'job_sha256': sha((child/'job.json').read_bytes()),
                'business_input_sha256': sha(job['businessInput']), 'qualification': self.q_binding,
                'automatic_retry': False, 'model_request_outcome_before_dispatch': None})
            put(base/'paid_native_process.json', {'returncode': 2, 'stdout': 'MOCK-ONLY provider500',
                'stderr': '', 'automatic_retry': False, 'outer_wall_ms': 1})
            put(base/'paid_reader_process.json', {'returncode': 0, 'process_boundary': 'fresh_python_process',
                                                 'mock_only': True})
            self.records.append({'case_id': cid, 'direction': direction, 'arm': arm,
                'recipient': 'A', 'receiver_platform': 'hy3', 'job_dir': str(base),
                'delivery': delivery, 'source_jobs': [], 'timings': {'delivery_ms': 1}})
        self.write_manifest()
        self.original_files = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def write_manifest(self):
        put(self.root/'manifest.json', {'schema': 'persistent-exchange-run-v1', 'root': str(self.root),
                                       'main_records': self.records, 'cases': []})
        put(self.root/'receiver_progress.json', {'phase': 'receiver', 'planned': len(self.records),
            'finished': 0, 'failed': len(self.records),
            'errors': [{'job_dir': r['job_dir'], 'error': 'MOCK-ONLY provider500'} for r in self.records]})

    def only_first(self):
        self.records = self.records[:1]
        self.write_manifest()

    def base(self, index=0):
        return Path(self.records[index]['job_dir'])

    def job(self, child, business):
        return {'schema': 'workbuddy-hy3-paid-one-shot-job-v1', 'jobId': 'receiver-MOCK-'+uuid.uuid4().hex,
            'jobType': 'receiver', 'sessionId': str(uuid.uuid4()), 'workspace': str(child), 'model': 'hy3-x',
            'instruction': ANSWER_INSTRUCTIONS, 'businessInput': business,
            'quotaRestorationConfirmed': True, 'qualificationEnvelope': str(self.qualification),
            'timeoutSeconds': 300, 'softOutputCharacters': 4096, 'cdpPort': 18491,
            'cliElectronPath': 'D:/workbuddy/WorkBuddy.exe', 'workbuddyConfigDir': 'C:/Users/21129/.workbuddy'}

    def envelope(self, job, job_raw, output, *, success=True):
        native = {'status': 'native_prompt_returned', 'stopReason': 'end_turn' if success else 'refusal',
            'modelPromptsSubmitted': 1, 'after': {'sessionId': job['sessionId'], 'workspace': job['workspace'],
                'status': 'completed', 'isProcessing': False, 'model': 'hy3-x', 'mode': 'ask', 'tools': ''}}
        return {'schema': 'workbuddy-hy3-native-paid-one-shot-envelope-v1',
            'status': 'verified_native_paid_one_shot' if success else 'native_provider_error_no_replay',
            'jobType': 'receiver', 'jobId': job['jobId'], 'sessionId': job['sessionId'],
            'workspace': job['workspace'], 'canonical_model_family': 'Hy3', 'requestedModel': 'hy3-x',
            'mode': 'ask', 'tools': '', 'actualModels': ['hy3-x'] if success else [],
            'requestModelIds': ['hy3-x'] if success else [], 'toolCallCount': 0, 'nativeUserRequestCount': 1,
            'nativeBusinessQueryMatchesSubmitted': True, 'assistantCompletedMessages': 1 if success else 0,
            'inputFileSha256': sha(job_raw), 'businessInputSha256': sha(job['businessInput']),
            'submittedUserPromptSha256': sha(_prompt(job)), 'qualification': self.q_binding,
            'nativeUserBusinessBinding': {'businessMatches': True, 'scope': 'exact_unwrapped_native_user_text',
                                         'nativeBusinessQuerySha256': sha(_prompt(job))},
            'providerErrors': [] if success else [{'code': 11134, 'httpStatus': 500, 'resetIso': None}],
            'nativeExecution': native, 'output': output, 'actualAssistantOutputSha256': sha(output),
            'nativeHistoryPrefixBytes': 100, 'nativeHistoryPrefixLines': 6, 'nativeHistoryPrefixSha256': 'a'*64,
            'nativeHistoryPath': str(Path(job['workspace'])/'MOCK-ONLY-no-native-history.jsonl'),
            'automaticReplay': False, 'queueUsed': False, 'completeUpstreamSystemInputObserved': False,
            'remoteProviderRequestBytesObserved': False}

    def fake_answer(self, db_path, batch_id, questions, job_dir, qualification_envelope, *, malformed=False):
        directory = Path(job_dir)
        self.assertEqual(directory.name, 'provider_retry_01')
        original = directory.parent
        record = next(r for r in self.records if Path(r['job_dir']) == original)
        self.assertEqual(Path(db_path), Path(record['delivery']['receiver_db']))
        self.assertEqual(batch_id, record['delivery']['batch_id'])
        self.assertEqual(questions, get(original/'questions.json'))
        self.assertTrue(all(set(q) == {'question_id', 'question'} for q in questions))
        self.assertEqual(Path(qualification_envelope), self.qualification)
        self.calls.append(str(directory))
        directory.mkdir(parents=True, exist_ok=True)
        put(directory/'questions.json', questions)
        self.assertEqual((directory/'questions.json').read_bytes(), (original/'questions.json').read_bytes())
        export_batch(db_path, batch_id, directory/'retrieved_memory.json')
        payload = get(directory/'retrieved_memory.json')
        self.assertEqual(payload, get(original/'retrieved_memory.json'))
        reader_receipt = get(directory/'retrieved_memory.json.receipt.json')
        contract = get(original/'receiver_paid_contract.json')
        put(directory/'receiver_paid_contract.json', contract)
        business = {'memory': payload['memory'], 'questions': questions}
        child = directory/'native_paid_one_shot'
        job = self.job(child, business)
        put(child/'job.json', job)
        answers = {} if malformed else {q['question_id']: 'MOCK-ONLY response' for q in questions}
        raw = b'MOCK-ONLY invalid answer JSON' if malformed else canonical(answers)
        (directory/'answers.json').write_bytes(raw)
        envelope = self.envelope(job, (child/'job.json').read_bytes(), raw.decode('utf-8'))
        put(child/'envelope.json', envelope)
        evidence = {'schema': 'persistent-receiver-execution-v1', 'mock_only': True,
            'execution_mode': 'controller_readback_native_paid_one_shot', 'canonical_model_family': 'Hy3',
            'status': 'answer_schema_failed' if malformed else 'ok', 'answers_schema_valid': not malformed,
            'answer_schema_failure': 'answer_must_be_exact_question_id_to_string_json_map' if malformed else None,
            'actual_model': 'hy3-x', 'actual_models': ['hy3-x'], 'request_model_ids': ['hy3-x'],
            'billing_route_ids': ['hy3-x'], 'workbuddy_fee_cny': None, 'physical_supplier_calls': None,
            'reader_receipt': reader_receipt, 'native_paid_envelope': envelope,
            'native_paid_envelope_path': str(child/'envelope.json'),
            'native_paid_envelope_sha256': sha((child/'envelope.json').read_bytes()),
            'native_paid_job_path': str(child/'job.json'), 'native_paid_job_sha256': sha((child/'job.json').read_bytes()),
            'raw_answers_path': str(directory/'answers.json'), 'answers_sha256': sha(raw),
            'questions_sha256': sha(questions), 'business_input_sha256': sha(business),
            'native_turn_count': 1, 'native_user_request_count': 1, 'native_tool_call_count': 0,
            'qualification': self.q_binding, 'automatic_retry': False}
        put(directory/'receiver_paid_verified.json', {'schema': 'persistent-paid-receiver-verified-v1',
            'contract_sha256': sha(contract), 'answers': answers, 'evidence': evidence})
        return answers, evidence

    def assert_original_unchanged(self):
        self.assertEqual(self.original_files, {p: p.read_bytes() for p in self.original_files})

    def test_same_context_once_and_original_and_new_cost_attempts_are_retained(self):
        with patch.object(recovery, 'answer_paid_hy3', side_effect=self.fake_answer) as answer:
            outcomes = recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, len(self.records))
        self.assertTrue(all(o['status'] == 'recovered' and o['registered'] for o in outcomes))
        self.assert_original_unchanged()
        for original in self.records:
            base = Path(original['job_dir'])
            scored = get(base/'scored_input.json')
            self.assertEqual(scored['job_dir'], original['job_dir'])
            self.assertEqual(Path(scored['effective_receiver_job_dir']), base/'provider_retry_01')
            self.assertEqual(Path(scored['receiver_recovery_receipt_path']), base/'receiver_recovery_receipt.json')
            self.assertEqual(scored['delivery'], original['delivery'])
            attempts = scored['receiver_attempts']
            self.assertEqual(len(attempts), 2)
            self.assertEqual(attempts[0]['native_direct_session_submissions'], 1)
            self.assertEqual(attempts[0]['qualified_native_turns'], 0)
            for attempt in attempts:
                self.assertIn('supplier_fee_cny', attempt)
                self.assertIn('physical_supplier_calls', attempt)
                self.assertIsNone(attempt['supplier_fee_cny'])
                self.assertIsNone(attempt['physical_supplier_calls'])

    def test_resume_verifies_existing_artifacts_without_reasking(self):
        with patch.object(recovery, 'answer_paid_hy3', side_effect=self.fake_answer) as answer:
            recovery.run_receiver_recovery(self.root)
            repeated = recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, len(self.records))
        self.assertTrue(all(o['status'] == 'existing_recovered' for o in repeated))
        self.assert_original_unchanged()

    def test_first_pass_must_be_finished_before_any_recovery(self):
        value = get(self.root/'receiver_progress.json')
        value['failed'] -= 1
        put(self.root/'receiver_progress.json', value)
        with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO MODEL')) as answer:
            with self.assertRaisesRegex(recovery.ReceiverRecoveryError, 'first_pass_not_finished'):
                recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 0)

    def test_quota_unknown_inflight_and_complete_output_are_excluded(self):
        self.only_first()
        envelope_path = self.base()/'native_paid_one_shot/envelope.json'
        pristine = get(envelope_path)
        variants = []
        quota = deepcopy(pristine)
        quota['providerErrors'].append({'code': 6004, 'httpStatus': 429})
        variants.append(quota)
        unknown = deepcopy(pristine)
        unknown['nativeExecution']['after'].update(status='working', isProcessing=True)
        variants.append(unknown)
        output = deepcopy(pristine)
        output.update(output='MOCK-ONLY existing answer must not be asked again.', assistantCompletedMessages=1)
        variants.append(output)
        for value in variants:
            with self.subTest(case=value['providerErrors']):
                put(envelope_path, value)
                with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO MODEL')) as answer:
                    outcomes = recovery.run_receiver_recovery(self.root)
                self.assertEqual(answer.call_count, 0)
                self.assertEqual(outcomes, [])

    def test_other_platform_is_excluded(self):
        self.only_first()
        self.records[0]['receiver_platform'] = 'flash'
        self.write_manifest()
        with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO MODEL')) as answer:
            self.assertEqual(recovery.run_receiver_recovery(self.root), [])
        self.assertEqual(answer.call_count, 0)

    def test_already_scored_or_existing_raw_answer_is_not_repeated(self):
        self.only_first()
        for name, value in (('scored_input.json', {'mock_only': True}), ('answers.json', {'mock_only': True})):
            with self.subTest(name=name):
                put(self.base()/name, value)
                with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO MODEL')) as answer:
                    self.assertEqual(recovery.run_receiver_recovery(self.root), [])
                self.assertEqual(answer.call_count, 0)
                (self.base()/name).unlink()

    def test_invalid_answer_format_is_finally_saved_without_repair_or_second_request(self):
        self.only_first()
        def invalid(*args):
            return self.fake_answer(*args, malformed=True)
        with patch.object(recovery, 'answer_paid_hy3', side_effect=invalid) as answer:
            outcomes = recovery.run_receiver_recovery(self.root)
            recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 1)
        self.assertEqual(outcomes[0]['status'], 'format_failed_recovered')
        scored = get(self.base()/'scored_input.json')
        self.assertEqual(scored['answers'], {})
        self.assertFalse(scored['receiver_evidence']['answers_schema_valid'])
        self.assertEqual((self.base()/'provider_retry_01/answers.json').read_bytes(), b'MOCK-ONLY invalid answer JSON')

    def test_retry_exception_is_a_final_failed_attempt_not_an_automatic_replay(self):
        self.only_first()
        def fail(*args):
            raise RuntimeError('MOCK-ONLY provider failed again; no model called by this test')
        with patch.object(recovery, 'answer_paid_hy3', side_effect=fail) as answer:
            outcomes = recovery.run_receiver_recovery(self.root)
            repeated = recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 1)
        self.assertEqual(outcomes[0]['status'], 'failed_no_retry')
        self.assertEqual(repeated[0]['status'], 'failed_no_retry')
        self.assertFalse((self.base()/'scored_input.json').exists())

    def test_completed_output_with_wrong_model_proof_is_kept_but_never_reasked_or_scored(self):
        self.only_first()
        def wrong_model(*args):
            answers, evidence = self.fake_answer(*args)
            envelope = evidence['native_paid_envelope']
            envelope['actualModels'] = ['fast-model']
            envelope_path = Path(evidence['native_paid_envelope_path'])
            put(envelope_path, envelope)
            evidence.update(actual_model='fast-model', actual_models=['fast-model'],
                            native_paid_envelope_sha256=sha(envelope_path.read_bytes()))
            cached = self.base()/'provider_retry_01/receiver_paid_verified.json'
            value = get(cached)
            value.update(answers=answers, evidence=evidence)
            put(cached, value)
            return answers, evidence
        with patch.object(recovery, 'answer_paid_hy3', side_effect=wrong_model) as answer:
            first = recovery.run_receiver_recovery(self.root)
            repeated = recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 1)
        self.assertEqual(first[0]['status'], 'failed_no_retry')
        self.assertEqual(repeated[0]['status'], 'failed_no_retry')
        self.assertTrue((self.base()/'provider_retry_01/answers.json').is_file())
        self.assertFalse((self.base()/'scored_input.json').exists())

    def test_existing_retry_intent_without_result_cannot_dispatch_again(self):
        self.only_first()
        put(self.base()/'provider_retry_01/paid_dispatch_intent.json', {'mock_only': True, 'outcome': 'unknown'})
        with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO REPLAY')) as answer:
            outcomes = recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 0)
        self.assertFalse(any(o['registered'] for o in outcomes))
        self.assertFalse((self.base()/'scored_input.json').exists())

    def test_changed_receiver_database_is_rejected_before_model(self):
        self.only_first()
        store = AgentStore(self.records[0]['delivery']['receiver_db'], 'A')
        try:
            store.add_original('A-MOCK-ONLY-drift', 'MOCK-ONLY receiver database changed.')
        finally:
            store.close()
        with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO MODEL')) as answer:
            with self.assertRaises(recovery.ReceiverRecoveryError):
                recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 0)

    def test_changed_public_question_is_rejected_before_model(self):
        self.only_first()
        path = self.base()/'questions.json'
        questions = get(path)
        questions[0]['question'] += ' MOCK-ONLY changed public question'
        put(path, questions)
        with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO MODEL')) as answer:
            with self.assertRaises(recovery.ReceiverRecoveryError):
                recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 0)

    def test_original_envelope_hash_is_still_bound_after_recovery(self):
        self.only_first()
        with patch.object(recovery, 'answer_paid_hy3', side_effect=self.fake_answer) as answer:
            recovery.run_receiver_recovery(self.root)
            path = self.base()/'native_paid_one_shot/envelope.json'
            path.write_bytes(path.read_bytes()+b' ')
            with self.assertRaises(recovery.ReceiverRecoveryError):
                recovery.run_receiver_recovery(self.root)
        self.assertEqual(answer.call_count, 1)


if __name__ == '__main__':
    unittest.main()
