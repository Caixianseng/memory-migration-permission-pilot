import tempfile
from pathlib import Path
import unittest

from .lifecycle_host import LifecycleHost
from .lifecycle_runner import FixtureClient, run


def sources():
    return [{'source_id': f'S{i:02}', 'text': f'User: topic {i}. Assistant: confirmation {i}.',
             'version': 1, 'acl_group': str(i // 2)} for i in range(8)]


class HostTest(unittest.TestCase):
    def test_revoke_reauthorize_current_broker(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = LifecycleHost(sources(), Path(tmp) / 'host')
            self.assertEqual(len(h.allowed_sources()), 8)
            h.set_permissions(['S01'])
            self.assertEqual([s['source_id'] for s in h.allowed_sources()], ['S01'])
            with self.assertRaises(ValueError):
                h.deliver('forbidden', ['S00'], [], lambda: self.fail('must not call'))
            h.set_permissions(['S00', 'S01'])
            self.assertEqual(len(h.allowed_sources()), 2)

    def test_final_revision_change_stops_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = LifecycleHost(sources(), Path(tmp) / 'host')
            with self.assertRaisesRegex(ValueError, 'permission_changed_before_delivery'):
                h.deliver('memory', ['S00'], [], lambda: self.fail('must not call'),
                          before_commit=lambda: h.set_permissions(['S01']))

    def test_unknown_result_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = LifecycleHost(sources(), Path(tmp) / 'host')
            calls = []
            def timeout():
                calls.append(1)
                raise TimeoutError()
            with self.assertRaises(TimeoutError):
                h.deliver('memory', ['S00'], [], timeout)
            self.assertEqual(len(calls), 1)
            self.assertIn('delivery_outcome_unknown_no_retry', (h.root / 'events.jsonl').read_text())

    def test_all_nine_methods_full_chronology_fixture(self):
        import json
        from .lifecycle_runner import HERE
        contract = json.loads((HERE / 'workload_contract.json').read_text())
        case = {'case_id': 'test-case', 'sources': sources()}
        questions = {'test-case': [{'question_id': 'Q1', 'question': 'topic?', 'reference': 'EVALUATION_ONLY_SECRET'}]}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'run'
            summary = run([case], questions, contract, out, FixtureClient(), instrument_only=True)
            self.assertEqual(summary['status'], 'completed')
            self.assertEqual(len(summary['rows']), 27)
            self.assertEqual(len(summary['cases']), 9)
            for row in summary['rows']:
                self.assertTrue(set(row['dependencies']) <= set(row['allowed']))
            for call in (out / 'calls').glob('*.json'):
                body = json.loads(call.read_text())
                self.assertNotIn('EVALUATION_ONLY_SECRET', json.dumps(body['messages']))
            self.assertTrue(all(row['full_lifecycle_peak_cny'] is None for row in summary['cases']))


if __name__ == '__main__':
    unittest.main()
