"""Pure MOCK registration of an already completed model turn; never dispatch."""
from pathlib import Path
import unittest
from unittest.mock import patch

from . import receiver_recovery as recovery
from . import receiver_recovery_offline as offline
from .test_receiver_recovery import ReceiverRecoveryTests, get, put, sha


class OfflineRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ReceiverRecoveryTests('test_same_context_once_and_original_and_new_cost_attempts_are_retained')
        self.fixture.setUp()
        self.fixture.only_first()
        self.root, self.base = self.fixture.root, self.fixture.base()

    def tearDown(self):
        self.fixture.tearDown()

    def completed_then_local_failure(self, *, malformed=False):
        def existing_turn(*args):
            self.fixture.fake_answer(*args, malformed=malformed)
            raise OSError('MOCK-ONLY local native history path failed after native completed')
        with patch.object(recovery, 'answer_paid_hy3', side_effect=existing_turn) as call:
            result = recovery.run_receiver_recovery(self.root)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(result[0]['status'], 'failed_no_retry')
        self.retry = self.base/'provider_retry_01'
        envpath, jobpath = self.retry/'native_paid_one_shot/envelope.json', self.retry/'native_paid_one_shot/job.json'
        envelope, contract = get(envpath), get(self.base/'receiver_paid_contract.json')
        saved = get(self.retry/'receiver_paid_verified.json')
        preserved = recovery._bindings([self.base/'receiver_recovery_failure.json',
            self.base/'original_receiver_failed_cost.json', self.retry/'receiver_attempt_cost.json'])
        receipt = {'schema': 'persistent-paid-receiver-offline-recheck-v1',
            'newNativeChannelsCalled': [], 'newNativeChannels': [], 'newModelPromptsSubmitted': 0,
            'newNativeSessionsCreated': 0, 'originalEnvelopePath': str(envpath),
            'originalEnvelopeSha256': sha(envpath.read_bytes()), 'nativeJobPath': str(jobpath),
            'nativeJobSha256': sha(jobpath.read_bytes()),
            'nativeHistoryPrefixSha256': envelope['nativeHistoryPrefixSha256'],
            'nativeHistoryPrefixBytes': envelope['nativeHistoryPrefixBytes'],
            'receiverDatabase': contract['receiver_database'], 'receiverDbSha256': contract['database_sha256'],
            'batchId': contract['batch_id'], 'questionsSha256': sha(contract['questions']),
            'memorySha256': sha(get(self.base/'retrieved_memory.json')['memory']),
            'businessInputSha256': envelope['businessInputSha256'],
            'qualificationEnvelopeSha256': self.fixture.q_binding['sha256'],
            'answersPath': str(self.retry/'answers.json'),
            'answersFileSha256': sha((self.retry/'answers.json').read_bytes()),
            'verifiedCachePath': str(self.retry/'receiver_paid_verified.json'),
            'verifiedCacheFileSha256': sha((self.retry/'receiver_paid_verified.json').read_bytes()),
            'preservedMetadataBindings': preserved, 'originalNativeArtifactsModified': False,
            'nativeIdentityPathsRewritten': False}
        put(self.retry/'offline_recheck_receipt.json', receipt)
        self.before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def adopt(self):
        with patch.object(recovery, 'answer_paid_hy3', side_effect=AssertionError('NO MODEL')) as model:
            with patch('subprocess.run', side_effect=AssertionError('NO NATIVE CHANNEL')) as process:
                result = offline.register_verified_receiver_recovery(self.root, self.base)
        self.assertEqual(model.call_count, 0)
        self.assertEqual(process.call_count, 0)
        return result

    def test_two_attempts_same_retry_reclassified_and_old_cost_unchanged(self):
        self.completed_then_local_failure()
        receipt = self.adopt()
        self.assertEqual(self.before, {p: p.read_bytes() for p in self.before})
        scored = get(self.base/'scored_input.json')
        self.assertEqual(scored['job_dir'], str(self.base))
        self.assertEqual(scored['effective_receiver_job_dir'], str(self.retry))
        self.assertEqual(len(scored['receiver_attempts']), 2)
        self.assertEqual([a['qualified_native_turns'] for a in scored['receiver_attempts']], [0, 1])
        self.assertEqual(get(self.retry/'receiver_attempt_cost.json')['qualified_native_turns'], 0)
        newer = get(self.retry/'receiver_attempt_rechecked_cost.json')
        self.assertTrue(newer['reclassificationOnly'])
        self.assertEqual(newer['newModelPromptsSubmitted'], 0)
        self.assertEqual(newer['native_session_id'], get(self.retry/'receiver_attempt_cost.json')['native_session_id'])
        for attempt in scored['receiver_attempts']:
            self.assertIsNone(attempt['supplier_fee_cny'])
            self.assertIsNone(attempt['physical_supplier_calls'])
        self.assertEqual(receipt['scored_input_sha256'], sha((self.base/'scored_input.json').read_bytes()))

    def test_repeat_is_immutable_with_first_pass_progress_archive(self):
        self.completed_then_local_failure()
        archive = self.root/'receiver_progress.first_pass.json'
        archive.write_bytes((self.root/'receiver_progress.json').read_bytes())
        first = self.adopt()
        put(self.root/'receiver_progress.json', {'planned': 1, 'finished': 1, 'failed': 0})
        frozen = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        second = self.adopt()
        self.assertEqual(first, second)
        self.assertEqual(frozen, {p: p.read_bytes() for p in frozen})

    def test_nonzero_new_prompts_cannot_be_called_local(self):
        self.completed_then_local_failure()
        path = self.retry/'offline_recheck_receipt.json'
        receipt = get(path); receipt['newModelPromptsSubmitted'] = 1; put(path, receipt)
        with self.assertRaisesRegex(recovery.ReceiverRecoveryError, 'submit_nothing'):
            self.adopt()
        self.assertFalse((self.base/'scored_input.json').exists())

    def test_existing_output_bytes_must_match_and_cannot_be_replaced(self):
        self.completed_then_local_failure()
        (self.retry/'answers.json').write_bytes(b'{}')
        with self.assertRaises(recovery.ReceiverRecoveryError):
            self.adopt()
        self.assertFalse((self.base/'scored_input.json').exists())

    def test_failure_preserved_binding_cannot_drift(self):
        self.completed_then_local_failure()
        path = self.base/'receiver_recovery_failure.json'
        failure = get(path); failure['error_code'] = 'MOCK-ONLY changed old reason'; put(path, failure)
        with self.assertRaisesRegex(recovery.ReceiverRecoveryError, 'preserved_failure'):
            self.adopt()

    def test_history_prefix_hash_must_be_the_same_existing_prefix(self):
        self.completed_then_local_failure()
        path = self.retry/'offline_recheck_receipt.json'
        receipt = get(path); receipt['nativeHistoryPrefixSha256'] = 'b'*64; put(path, receipt)
        with self.assertRaisesRegex(recovery.ReceiverRecoveryError, 'context_binding'):
            self.adopt()

    def test_format_failure_is_final_result_not_another_prompt(self):
        self.completed_then_local_failure(malformed=True)
        receipt = self.adopt()
        scored = get(self.base/'scored_input.json')
        self.assertEqual(scored['answers'], {})
        self.assertFalse(scored['receiver_evidence']['answers_schema_valid'])
        self.assertEqual(len(receipt['receiver_attempts']), 2)
        self.assertFalse(receipt['further_retry_authorized'])

    def test_database_change_is_rejected(self):
        self.completed_then_local_failure()
        path = Path(self.fixture.records[0]['delivery']['receiver_db'])
        path.write_bytes(path.read_bytes()+b'MOCK-ONLY drift')
        with self.assertRaises(recovery.ReceiverRecoveryError):
            self.adopt()


if __name__ == '__main__':
    unittest.main()
