"""Offline contract tests only: importing/running these sends no model prompt."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from experiments.revocation_prefix_v1 import cache_qualification as qualification


class RecordingClient:
    instrument_only = True

    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at

    def generate(self, messages, job_id, max_tokens, role):
        self.calls.append(deepcopy((messages, job_id, max_tokens, role)))
        if len(self.calls) == self.fail_at:
            raise RuntimeError('fixture unknown outcome')
        usage = {'inputTokens': 100, 'cacheReadTokens': 200, 'cacheWriteTokens': 0,
                 'outputTokens': 10, 'totalTokens': 310}
        return {'output': '{}', 'receipt': {'status': 'ok', 'physical_request_count': 1,
                'request_id': job_id, 'usage': usage, 'instrument_only': True}}


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.case, self.batches, self.contract, self.inputs = qualification.load_workload()
        self.registry = {s['source_id']: s for s in self.case['sources']}
        self.nonces = {'raw': 'a' * 64, 'stable_first': 'b' * 64}

    def test_six_deliveries_preserve_sources_and_hide_evaluation_annotations(self):
        client = RecordingClient()
        original = deepcopy(self.case)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'new-run'
            summary = qualification.run(output, client=client, nonces=self.nonces, order_seed=17)
            self.assertEqual(summary['status'], 'completed')
            self.assertEqual(summary['model_calls_attempted'], 6)
            self.assertEqual(len(client.calls), 6)
            self.assertTrue(summary['instrument_only'])
            self.assertEqual(self.case, original)
            for row in summary['rows']:
                memory, dependencies = qualification.render_allowed([
                    {**self.registry[sid], 'allow': True} for sid in row['allowed']],
                    qualification.ARM_ORDERS[row['arm']], self.registry, row['allowed'])
                business = json.loads(row['messages'][1]['content'])
                self.assertEqual(business['memory'], memory)
                self.assertEqual(row['dependencies'], dependencies)
                self.assertEqual(row['memory_sha256'], qualification.digest(memory.encode()))
                self.assertEqual(row['messages'][0]['content'],
                                 f"Qualification tag: {self.nonces[row['arm']]}\n" + self.contract['target_prompt'])
                self.assertEqual(len(business['questions']), 3)
                self.assertTrue(all(set(q) == {'question_id', 'question'} for q in business['questions']))
                self.assertEqual(row['tokens']['input_total_tokens'], 300)
            plan = json.loads((output / 'qualification_plan.json').read_bytes())
            for step in range(3):
                self.assertEqual({r['arm'] for r in summary['rows'] if r['step'] == step}, set(qualification.ARM_ORDERS))
                self.assertEqual([r['arm'] for r in summary['rows'] if r['step'] == step], plan['step_arm_order'][step])
            for arm, costs in summary['arm_totals'].items():
                self.assertEqual(costs['successful_calls'], 3)
                self.assertEqual(costs['tokens']['input_total_tokens'], 900)
                self.assertEqual(Decimal(costs['full_lifecycle_peak_cost_cny']), Decimal('0.00204'))
                self.assertEqual(Decimal(costs['full_lifecycle_cache_aware_peak_cost_cny']), Decimal('0.000864'))
                events = [json.loads(line) for line in (output / arm / 'host/events.jsonl').read_bytes().splitlines()]
                self.assertEqual(sum(e['kind'] == 'delivery_committed' for e in events), 3)
                self.assertEqual(sum(e['kind'] == 'permission_committed' for e in events), 2)
                self.assertEqual(sum(e['kind'] == 'policy_state_reused' for e in events), 1)
            support = json.loads((output / 'evaluation_only.json').read_bytes())['expected_support_by_step']
            self.assertEqual([q['expected_legally_answerable'] for q in support[0]], [False, True, False])
            self.assertTrue(all(q['expected_legally_answerable'] for batch in support[1:] for q in batch))

    def test_duplicate_unknown_stale_and_forbidden_sources_are_rejected(self):
        current = [{**s, 'allow': True} for s in self.case['sources'] if s['source_id'] != 'S02']
        bad_order = list(qualification.SOURCE_IDS)
        bad_order[-1] = bad_order[0]
        with self.assertRaisesRegex(ValueError, 'permutation'):
            qualification.render_allowed(current, bad_order, self.registry, qualification.PERMISSIONS[0])
        mutations = [current + [current[0]], current + [{**current[0], 'source_id': 'unknown'}],
                     [{**current[0], 'text': 'changed body'}] + current[1:],
                     [{**current[0], 'allow': False}] + current[1:],
                     current + [{**self.registry['S02'], 'allow': True}]]
        for bad in mutations:
            with self.subTest(sources=len(bad)), self.assertRaises(ValueError):
                qualification.render_allowed(bad, qualification.SOURCE_IDS, self.registry, qualification.PERMISSIONS[0])

    def test_failure_stops_without_retry_and_records_incomplete_cost(self):
        client = RecordingClient(fail_at=2)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'failed'
            with self.assertRaisesRegex(RuntimeError, 'unknown outcome'):
                qualification.run(output, client=client, nonces=self.nonces, order_seed=2)
            summary = json.loads((output / 'summary.json').read_bytes())
            self.assertEqual(len(client.calls), 2)
            self.assertEqual(len(summary['rows']), 1)
            self.assertFalse(summary['full_lifecycle_cost_complete'])
            self.assertEqual(summary['status'], 'failed_no_automatic_retry')
            self.assertTrue((output / 'calls/002.input.json').exists())
            with self.assertRaisesRegex(ValueError, 'fresh_output'):
                qualification.run(output, client=client)
            self.assertEqual(len(client.calls), 2)

    def test_initial_native_read_alert_and_exact_dispatch_binding(self):
        nonce = self.nonces['raw']
        messages = [{'role': 'system', 'content': f'Qualification tag: {nonce}\nPrompt'},
                    {'role': 'user', 'content': '{"memory":"original","questions":[]}'}]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'actual_request.json'
            request = {'messages': [
                {'role': 'system', 'content': [{'type': 'text', 'text': 'Native fixed system'}]},
                {'role': 'user', 'content': [{'type': 'text', 'text': qualification.dispatch_text(messages)}]},
                {'role': 'user', 'content': [{'type': 'text', 'text': 'runtime after business'}]}]}
            path.write_text(json.dumps(request), encoding='utf-8')
            receipt = {'record_path': temp, 'usage': {'cacheReadTokens': 1024}}
            result = qualification.native_isolation(receipt, messages, nonce)
            self.assertEqual(result['status'], 'review_excess_initial_cache_read')
            self.assertFalse(result['isolation_proven'])
            request['messages'][1]['content'][0]['text'] += 'unregistered input'
            path.write_text(json.dumps(request), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'binding'):
                qualification.native_isolation(receipt, messages, nonce)


if __name__ == '__main__':
    unittest.main()
