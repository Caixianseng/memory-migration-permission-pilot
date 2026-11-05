"""Offline D2 runner boundary tests; these never initialize an SDK client."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.revocation_prefix_v1 import permission_runner as runner


class RecordingClient:
    instrument_only = True

    def __init__(self, output, fail_at=None):
        self.output, self.fail_at, self.calls = output, fail_at, []

    def generate(self, messages, job_id, max_tokens, role):
        # All material/threshold/order commitments must exist before any call.
        for name in ('frozen_manifest.json', 'frozen_case.json', 'evaluation_only.json'):
            if not (self.output / name).is_file():
                raise AssertionError('missing pre-call freeze: ' + name)
        self.calls.append(deepcopy((messages, job_id, max_tokens, role)))
        if len(self.calls) == self.fail_at:
            raise RuntimeError('fixture unknown outcome')
        return {'output': '{}', 'receipt': {'status': 'ok', 'request_id': job_id,
                'physical_request_count': 1, 'usage': {'inputTokens': 100, 'cacheReadTokens': 200,
                'cacheWriteTokens': 0, 'outputTokens': 10, 'totalTokens': 310}}}


class PermissionRunnerTests(unittest.TestCase):
    def setUp(self):
        self.case = {'case_id': 'exposed-fixture', 'sources': [
            {'source_id': sid, 'text': f'VERBATIM_BODY_{sid}: a reported statement.', 'version': 1}
            for sid in ('A', 'B', 'C', 'D')]}
        self.questions = [{'question_id': f'Q{i}', 'question': f'Question {i}?',
                           'support_source_ids': [sid], 'reference_answer': 'REFERENCE_NOT_FOR_PLANNER_OR_MODEL'}
                          for i, sid in enumerate(('A', 'B', 'C'), 1)]
        self.events = [{'time': 0, 'allowed': ['A', 'C', 'D'], 'context': 'period'},
                       {'time': 1, 'allowed': ['B', 'C', 'D'], 'context': 'period'},
                       {'time': 2, 'allowed': ['B', 'C', 'D'], 'context': 'period'}]
        self.history = [{'before': ['A', 'C', 'D'], 'after': ['B', 'C', 'D'], 'context': 'period'}]
        self.arms = ['original', 'causal_two_step']
        self.nonces = {'original': '1' * 64, 'causal_two_step': '2' * 64}

    def invoke(self, output, client, **kwargs):
        options = dict(arms=self.arms, config={'risk_cut_threshold': .75}, budget_cap_cny='.5',
                       max_jobs=6, target_prompt='Use only current evidence.',
                       client=client, nonces=self.nonces, order_seed=19)
        options.update(kwargs)
        return runner.run(self.case, self.questions, self.events, self.history, output, **options)

    def test_causal_boundaries_own_cache_verbatim_content_and_complete_costs(self):
        original_case = deepcopy(self.case)
        actual_planner = runner.planner.plan_layout
        planner_inputs = []

        def observed_planner(sources, history, observed, config):
            planner_inputs.append(deepcopy((sources, history, observed, config)))
            self.assertNotIn('REFERENCE_NOT_FOR_PLANNER_OR_MODEL', str((sources, history, observed, config)))
            self.assertFalse({'questions', 'events', 'schedule', 'answers'} & set(config))
            self.assertEqual(set(config['known_source_lengths_bytes']), {'A', 'B', 'C', 'D'})
            return actual_planner(sources, history, observed, config)

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'paired'
            client = RecordingClient(output)
            with patch.object(runner.planner, 'plan_layout', side_effect=observed_planner):
                summary = self.invoke(output, client)
            self.assertEqual(summary['status'], 'completed')
            self.assertEqual(len(client.calls), 6)
            self.assertEqual(self.case, original_case)
            # One initial validation + one decision per actual request.
            self.assertEqual(len(planner_inputs), 7)
            for sources, _, _, _ in planner_inputs[:3]:
                self.assertNotIn('B', {s['source_id'] for s in sources})
            previous = {arm: [] for arm in self.arms}
            for row in summary['rows']:
                step, arm = row['step'], row['arm']
                self.assertEqual(row['allowed'], sorted(self.events[step]['allowed']))
                self.assertEqual(set(row['dependencies']), set(row['allowed']))
                self.assertEqual(len(row['dependencies']), len(row['allowed']))
                self.assertEqual(row['planner_input_observed_orders'], previous[arm])
                self.assertEqual(len(row['planner_input_history']), len(self.history) + step)
                if step:
                    self.assertEqual(row['planner_input_history'][-1], {
                        'before': self.events[step - 1]['allowed'], 'after': self.events[step]['allowed'], 'context': 'period'})
                previous[arm].append(row['dependencies'])
                business = json.loads(row['messages'][1]['content'])
                by_id = {s['source_id']: s for s in self.case['sources']}
                expected = '\n\n'.join(sid + '\n' + by_id[sid]['text'] for sid in row['dependencies'])
                self.assertEqual(business['memory'], expected)
                self.assertEqual(row['memory_sha256'], runner.digest(expected.encode('utf-8')))
                self.assertNotIn('REFERENCE_NOT_FOR_PLANNER_OR_MODEL', str(row['messages']))
                self.assertTrue(all(set(q) == {'question_id', 'question'} for q in business['questions']))
                self.assertEqual(row['messages'][0]['content'],
                                 f"Qualification tag: {self.nonces[arm]}\nUse only current evidence.")
            self.assertEqual(summary['physical_totals']['successful_calls'], 6)
            self.assertEqual(summary['physical_totals']['tokens']['input_total_tokens'], 1800)
            self.assertEqual(Decimal(summary['physical_totals']['full_lifecycle_peak_cost_cny']), Decimal('.00408'))
            self.assertEqual(Decimal(summary['physical_totals']['full_lifecycle_cache_aware_peak_cost_cny']), Decimal('.001728'))
            for arm in self.arms:
                self.assertEqual(summary['arm_totals'][arm]['successful_calls'], 3)
            frozen = json.loads((output / 'frozen_manifest.json').read_bytes())
            self.assertEqual(frozen['planner_config']['risk_cut_threshold'], .75)
            self.assertEqual(frozen['max_jobs'], 6)
            self.assertEqual(frozen['schedule'], self.events)
            evaluation = json.loads((output / 'evaluation_only.json').read_bytes())
            self.assertEqual([q['expected_legally_answerable'] for q in evaluation['events'][0]['expected_support']], [True, False, True])

    def test_failed_unknown_request_stops_and_cannot_be_resumed(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'failed'
            client = RecordingClient(output, fail_at=2)
            with self.assertRaisesRegex(RuntimeError, 'unknown outcome'):
                self.invoke(output, client)
            summary = json.loads((output / 'summary.json').read_bytes())
            self.assertEqual(len(client.calls), 2)
            self.assertEqual(len(summary['rows']), 1)
            self.assertEqual(summary['status'], 'failed_no_automatic_retry')
            self.assertIsNone(summary['physical_totals']['full_lifecycle_peak_cost_cny'])
            self.assertFalse(summary['full_lifecycle_cost_complete'])
            with self.assertRaisesRegex(ValueError, 'fresh_output'):
                self.invoke(output, client)
            self.assertEqual(len(client.calls), 2)

    def test_foreign_or_stale_cache_scope_and_immutable_source_versions(self):
        binding = runner.source_binding(self.case['sources'])
        valid = {'completed': True, 'physical_request_count': 1, 'ordered_source_ids': ['A', 'C'],
                 'source_binding': binding, 'source_binding_sha256': runner.digest(binding)}
        self.assertEqual(runner.usable_completed_orders([valid], binding), [['A', 'C']])
        changed = deepcopy(binding)
        changed['A']['version'] = 2
        self.assertEqual(runner.usable_completed_orders([valid], changed), [])
        self.assertEqual(runner.usable_completed_orders([{**valid, 'completed': False}], binding), [])
        registry = {s['source_id']: s for s in self.case['sources']}
        for change in ({'version': 2}, {'text': 'modified'}, {'allow': False}):
            source = {**registry['A'], 'allow': True, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.render_current([source], ['A'], registry, ['A'])

    def test_bad_layout_rejected_before_call_and_exact_bounded_jobs_required(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'bad-order'
            client = RecordingClient(output)
            with patch.object(runner.planner, 'plan_layout', return_value={'ordered_source_ids': ['A', 'A', 'B']}):
                with self.assertRaisesRegex(ValueError, 'duplicate_or_unknown'):
                    self.invoke(output, client)
            self.assertEqual(client.calls, [])
            for cap, jobs in (('NaN', 6), ('0', 6), ('.5', 7), ('.5', 5)):
                fresh = Path(temp) / f'no-call-{jobs}-{cap}'
                with self.subTest(cap=cap, jobs=jobs), self.assertRaises(ValueError):
                    self.invoke(fresh, RecordingClient(fresh), budget_cap_cny=cap, max_jobs=jobs)
                self.assertFalse(fresh.exists())

    def test_scheduled_and_explicit_question_selection_with_flat_fallback(self):
        bank = self.questions + [dict(self.questions[0], question_id='Q4', question='Fourth question?')]
        spec = {'questions': bank, 'question_schedule': {'7': ['Q4', 'Q2', 'Q1']}}
        self.assertEqual([q['question_id'] for q in runner.event_questions(spec, {'time': 0, 'question_time': 7})], ['Q4', 'Q2', 'Q1'])
        self.assertEqual([q['question_id'] for q in runner.event_questions(spec, {'time': 0, 'question_ids': ['Q3', 'Q4', 'Q1']})], ['Q3', 'Q4', 'Q1'])
        self.assertEqual(runner.event_questions(self.questions, {'time': 999}), self.questions)
        with self.assertRaisesRegex(ValueError, 'duplicate_or_unknown'):
            runner.event_questions(spec, {'time': 0, 'question_ids': ['Q1', 'Q1', 'Q3']})

    def test_separate_forecast_policies_are_frozen_and_resolved_without_cross_arm_data(self):
        arms = ['joint', 'independent']
        config = {'arm_policies': {
            'joint': {'method': 'causal_two_step', 'forecast_model': 'joint_delta'},
            'independent': {'method': 'cache_greedy_forecast_tail', 'forecast_model': 'independent_status_marginal'}}}
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'separate-policies'
            result = self.invoke(output, RecordingClient(output), arms=arms, config=config,
                                 nonces={'joint': '3' * 64, 'independent': '4' * 64})
            for row in result['rows']:
                cfg = row['planner_input_config']
                self.assertNotIn('arm_policies', cfg)
                self.assertEqual(cfg['method'], config['arm_policies'][row['arm']]['method'])
                self.assertEqual(cfg['forecast_model'], config['arm_policies'][row['arm']]['forecast_model'])
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['physical_totals']['successful_calls'], 6)
        with self.assertRaisesRegex(ValueError, 'registered_arms_only'):
            runner.prepare(self.case, self.questions, self.events, self.history, arms,
                           {'arm_policies': {'unregistered': {'method': 'original'}}}, '.5', 6)
        with self.assertRaisesRegex(ValueError, 'safe_simple'):
            runner.prepare(self.case, self.questions, self.events, self.history, ['../elsewhere'], {}, '.5', 3)

    def test_exact_solver_dispatch_preserves_all_legal_materials(self):
        arms = ['exact', 'greedy']
        config = {'forecast_model': 'independent_status_marginal', 'arm_policies': {
            'exact': {'method': 'exact_two_step'},
            'greedy': {'method': 'cache_greedy_forecast_tail'}}}
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'exact'
            result = self.invoke(output, RecordingClient(output), arms=arms, config=config,
                                 nonces={'exact': '5' * 64, 'greedy': '6' * 64})
            self.assertEqual(result['status'], 'completed')
            for row in result['rows']:
                self.assertEqual(set(row['dependencies']), set(row['allowed']))
                if row['arm'] == 'exact':
                    self.assertEqual(row['planner_input_config']['method'], 'exact_two_step')


if __name__ == '__main__':
    unittest.main()
