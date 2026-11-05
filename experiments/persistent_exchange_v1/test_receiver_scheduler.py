"""Focused scheduler regression, using only temporary MOCK model/reader data."""
from collections import Counter
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from . import receiver_dispatch
from . import run_study as study


class ReceiverSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='receiver-scheduler-MOCK-ONLY-',
                                               dir=Path(__file__).resolve().parents[2])
        self.root = Path(self.temp.name)
        self.records, self.evaluation = [], {}
        for cid in ('MOCK-ONLY-project-01', 'MOCK-ONLY-project-02'):
            self.evaluation[cid] = {}
            for direction in ('A_to_B', 'B_to_A'):
                sender, recipient = direction.split('_to_')
                self.evaluation[cid][direction] = {'questions': [
                    {'question_id': cid+'-'+direction+'-q'+str(number),
                     'question': 'MOCK-ONLY public question '+str(number),
                     'reference_answer': 'MOCK-ONLY-DO-NOT-SEND-REFERENCE',
                     'support_ids': ['MOCK-ONLY-secret-evaluation-support']}
                    for number in (1, 2)]}
                for arm in ('raw', 'whole_drop', 'full_rebuild', 'selective'):
                    folder = self.root/'jobs'/cid/direction/arm
                    folder.mkdir(parents=True)
                    batch = cid+'-'+direction+'-'+arm
                    database = folder/'receiver.mock.json'
                    database.write_text(json.dumps({'batch_id': batch, 'recipient': recipient,
                        'memory': 'MOCK-ONLY actual assigned receiver fixture.'}), encoding='utf-8')
                    self.records.append({'case_id': cid, 'direction': direction, 'arm': arm,
                        'recipient': recipient, 'receiver_platform': 'hy3' if recipient == 'A' else 'flash',
                        'job_dir': str(folder), 'delivery': {'policy_db': str(folder/'policy.mock.sqlite'),
                            'policy_epoch': 7, 'dependencies': [], 'receiver_db': str(database), 'batch_id': batch}})
        self.manifest = {'root': str(self.root), 'main_records': self.records}
        self.original_load = study.load
        self.lock = threading.Lock()
        self.policy_checks, self.reader_calls, self.model_calls = [], [], []

    def tearDown(self):
        self.temp.cleanup()

    def load_frozen_evaluation(self, path):
        if Path(path) == study.HERE/'data/evaluation_only.json':
            return self.evaluation
        self.assertTrue(Path(path).resolve().is_relative_to(self.root))
        return self.original_load(path)

    def mock_reader(self, database, batch):
        path = Path(database).resolve()
        self.assertTrue(path.is_relative_to(self.root))
        fixture = json.loads(path.read_bytes())
        self.assertEqual(fixture['batch_id'], batch)
        with self.lock:
            self.reader_calls.append((str(path), batch))
        return fixture['memory']

    def mock_model(self, platform, database, batch, questions, job_dir):
        memory = self.mock_reader(database, batch)
        self.assertIn('MOCK-ONLY', memory)
        self.assertIn(platform, ('hy3', 'flash'))
        self.assertEqual(Path(job_dir), Path(database).parent)
        self.assertEqual(len(questions), 2)
        self.assertTrue(all(set(question) == {'question_id', 'question'} for question in questions))
        self.assertNotIn('DO-NOT-SEND-REFERENCE', json.dumps(questions))
        with self.lock:
            self.model_calls.append((platform, batch))
        return ({q['question_id']: 'MOCK-ONLY response' for q in questions},
                {'mock_only': True, 'workbuddy_fee_cny': None,
                 'workbuddy_physical_supplier_calls': None, 'physical_supplier_calls': None})

    def policy_type(self):
        owner = self
        class MockPolicy:
            def __init__(self, path):
                self.path = Path(path)
                owner.assertTrue(self.path.resolve().is_relative_to(owner.root))

            def check_dependencies(self, recipient, dependencies, epoch):
                owner.assertIn(recipient, ('A', 'B'))
                owner.assertEqual(epoch, 7)
                owner.assertEqual(dependencies, [])
                with owner.lock:
                    owner.policy_checks.append((str(self.path), recipient, epoch))
                return epoch

            def close(self):
                pass
        return MockPolicy

    def test_frozen_evaluation_reaches_every_record_once_with_unknown_fees_preserved(self):
        original_execute = study.execute_receiver
        observed = []
        def execute(record, evaluation):
            # This required second argument reproduces the original regression
            # if pool.submit accidentally omits the frozen evaluation again.
            self.assertIs(evaluation, self.evaluation)
            with self.lock:
                observed.append((record['case_id'], record['direction'], record['arm']))
            return original_execute(record, evaluation)
        with patch.object(study, 'load', side_effect=self.load_frozen_evaluation), \
             patch.object(study, 'TrustedPolicy', self.policy_type()), \
             patch.object(study, 'execute_receiver', side_effect=execute), \
             patch.object(receiver_dispatch, 'answer_receiver', side_effect=self.mock_model), \
             redirect_stdout(io.StringIO()):
            actual = study.receiver_phase(self.root, self.manifest, workers=4)
        expected_keys = [(r['case_id'], r['direction'], r['arm']) for r in self.records]
        self.assertEqual(Counter(observed), Counter(expected_keys))
        self.assertTrue(all(count == 1 for count in Counter(observed).values()))
        self.assertEqual(len(self.reader_calls), len(self.records))
        self.assertEqual(len(self.model_calls), len(self.records))
        self.assertEqual(len(self.policy_checks), len(self.records))
        self.assertEqual([r['delivery']['batch_id'] for r in actual],
                         [r['delivery']['batch_id'] for r in sorted(self.records,
                          key=lambda r: (r['case_id'], r['direction'], r['arm']))])
        for record in actual:
            self.assertIsNone(record['receiver_evidence']['workbuddy_fee_cny'])
            self.assertIsNone(record['receiver_evidence']['workbuddy_physical_supplier_calls'])
            self.assertIsNone(record['receiver_evidence']['physical_supplier_calls'])
            self.assertEqual(json.loads((Path(record['job_dir'])/'scored_input.json').read_bytes()), record)
        self.assertEqual(json.loads((self.root/'main_records.json').read_bytes()), actual)
        progress = json.loads((self.root/'receiver_progress.json').read_bytes())
        self.assertEqual(progress['planned'], len(self.records))
        self.assertEqual(progress['finished'], len(self.records))
        self.assertEqual(progress['failed'], 0)
        self.assertEqual(progress['errors'], [])

    def test_pre_reader_failure_is_recorded_without_any_model_call_or_fee_inference(self):
        def fail_before_reader(record, evaluation):
            self.assertIs(evaluation, self.evaluation)
            raise TypeError('MOCK-ONLY pre-reader evaluation argument failure')
        with patch.object(study, 'load', side_effect=self.load_frozen_evaluation), \
             patch.object(study, 'execute_receiver', side_effect=fail_before_reader) as execute, \
             patch.object(receiver_dispatch, 'answer_receiver', side_effect=AssertionError('NO MODEL DISPATCH')) as model, \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'unresolved_receiver_jobs:'+str(len(self.records))):
                study.receiver_phase(self.root, self.manifest, workers=4)
        self.assertEqual(execute.call_count, len(self.records))
        self.assertEqual(model.call_count, 0)
        self.assertEqual(self.reader_calls, [])
        self.assertFalse((self.root/'main_records.json').exists())
        self.assertFalse(any((Path(r['job_dir'])/'scored_input.json').exists() for r in self.records))
        progress = json.loads((self.root/'receiver_progress.json').read_bytes())
        self.assertEqual(progress['finished'], 0)
        self.assertEqual(progress['failed'], len(self.records))
        self.assertEqual(len(progress['errors']), len(self.records))
        # Scheduler errors describe scheduling failures; they do not invent
        # supplier fees, prices, token counts or observed paid request totals.
        self.assertEqual(set(progress), {'phase', 'planned', 'finished', 'failed', 'errors'})


if __name__ == '__main__':
    unittest.main()
