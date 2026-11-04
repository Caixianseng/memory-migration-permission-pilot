from copy import deepcopy
from pathlib import Path
import json
import tempfile
import unittest

from .lineage import sha
from .runner import run_story
from .test_host import SOURCES


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.plan = {'case_id': 'story-test', 'sources': deepcopy(SOURCES),
                     'critical_sid': 'S01', 'irrelevant_sid': 'S04'}

    def source(self, payload, context):
        output = 'Memory ' + context['job_id']
        return {'output': output, 'observed_input': payload, 'receipt': {
            'schema': 'controlled-fixture-generation-v1', 'instrument_only': True,
            'trace_id': payload['trace_id'], 'input_hash': payload['input_hash'],
            'output_hash': sha(output), 'logical_requests': 1,
            'request_id': context['job_id']}}

    def test_two_stories_exact_counts_and_no_root_text_in_memories(self):
        all_source_calls, all_target_calls = [], []

        def source(payload, context):
            all_source_calls.append(context)
            return self.source(payload, context)

        def target(envelope, context):
            all_target_calls.append(context)
            if context['method'] != 'B1':
                for item in SOURCES:
                    self.assertNotIn(item['text'], envelope['memory_text'])
            return {'status': 'ok', 'three_answer_requests_in_one_call': True}

        results = []
        for i in range(2):
            plan = deepcopy(self.plan)
            plan['case_id'] += str(i)
            result = run_story(plan, Path(self.temp.name) / str(i), source, target,
                               instrument_only=True)
            self.assertEqual(result['status'], 'ok', result.get('failure'))
            self.assertEqual(result['source_callback_invocations'], 8)
            self.assertEqual(result['target_callback_invocations'], 10)
            self.assertEqual(sum(b['status'] == 'blocked_no_target'
                                 for b in result['branches'].values()), 2)
            self.assertTrue(all(r['status'] == 'sealed' for r in result['source_calls']))
            results.append(result)
        self.assertEqual(len(all_source_calls), 16)
        self.assertEqual(len(all_target_calls), 20)
        self.assertEqual(sum(b['status'] == 'blocked_no_target'
                             for r in results for b in r['branches'].values()), 4)
        self.assertEqual(sum(c['artifact'] == 'R' for c in all_source_calls), 6)
        self.assertEqual(sum(c['artifact'] == 'M' for c in all_source_calls), 2)

    def test_source_failure_is_saved_with_every_unattempted_position(self):
        calls = []

        def fail_source(payload, context):
            calls.append(context)
            raise TimeoutError('private exception detail must not be stored')

        target_calls = []
        out = Path(self.temp.name) / 'source-failed'
        result = run_story(self.plan, out, fail_source,
                           lambda e, c: target_calls.append(c), instrument_only=True)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['source_callback_invocations'], 1)
        self.assertEqual(result['target_callback_invocations'], 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(target_calls, [])
        self.assertEqual(result['source_calls'][0]['status'], 'failed_or_unknown_no_retry')
        self.assertEqual(sum(r['status'] == 'not_run' for r in result['source_calls']), 7)
        saved = json.loads((out / 'run_summary.json').read_text(encoding='utf8'))
        self.assertEqual(saved, result)
        self.assertNotIn('private exception detail', (out / 'run_summary.json').read_text())
        self.assertEqual(len(list((out / 'branches').rglob('branch_result.json'))), 12)

    def test_target_unknown_outcome_stops_remaining_story(self):
        target_calls = []

        def fail_target(envelope, context):
            target_calls.append(context)
            raise TimeoutError('unknown target result')

        out = Path(self.temp.name) / 'target-failed'
        result = run_story(self.plan, out, self.source, fail_target, instrument_only=True)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['source_callback_invocations'], 5)
        self.assertEqual(result['target_callback_invocations'], 1)
        self.assertEqual(len(target_calls), 1)
        self.assertEqual(result['branches']['B0/unchanged']['status'], 'failed')
        self.assertEqual(sum(b['status'] == 'not_run' for b in result['branches'].values()), 11)
        self.assertEqual(sum(r['status'] == 'not_run' for r in result['source_calls']), 3)

    def test_returned_failed_target_receipt_stops_story(self):
        result = run_story(self.plan, Path(self.temp.name) / 'target-rejected',
                           self.source, lambda e, c: {'status': 'failed'}, instrument_only=True)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['target_callback_invocations'], 1)
        self.assertEqual(result['failure']['error_code'], 'target_callback_unsuccessful_receipt')


if __name__ == '__main__':
    unittest.main()
