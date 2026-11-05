"""Offline lifecycle/question-isolation regressions, never model requests."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from .lifecycle_runner import HERE, FixtureClient, expanded_schedule, history_for, questions_at_time, retrieved_sources, run, schedule_for
from .evaluate import canonical, digest, dispatch_text, evaluate, questions_for_position, retrieval_sources_for_position, runtime_context_text


def fixture_inputs(extended):
    contract = json.loads((HERE / 'workload_contract.json').read_text(encoding='utf-8'))
    case = {'case_id': 'extension-fixture', 'event_distribution': 'coordinated', 'sources': [
        {'source_id': f'S{i+1:02}', 'text': '\n'.join(f'[user] topic {i}, exchange {j}. [/user]\n[assistant] reply {j}. [/assistant]' for j in range(4)),
         'version': 1} for i in range(8)]}
    bank = [{'question_id': f'Q{i+1}', 'question': f'PUBLIC_QUESTION_{i+1}?',
             'support_source_ids': [f'S{i % 8 + 1:02}'], 'reference_answer': f'QA_REFERENCE_SECRET_{i+1}'}
            for i in range(9 if extended else 3)]
    if extended:
        contract['methods'] = ['raw', 'retrieval', 'whole', 'single', 'risk', 'joint']
        contract['repeat_deliveries_per_policy_state'] = 3
        contract['planner']['expected_deliveries'] = 9
        contract['events']['times'] = list(range(15))
        contract['events']['scoring_times'] = [0, 1, 2, 6, 7, 8, 12, 13, 14]
        spec = {'questions': bank, 'question_schedule': {
            str(tick): [f'Q{i+1}' for i in range((tick % 3) * 3, (tick % 3 + 1) * 3)]
            for tick in contract['events']['scoring_times']}}
    else:
        spec = bank
    return contract, case, {case['case_id']: spec}


class NativeShapeFixture:
    """Synthetic evidence validates replay arithmetic, not model performance."""
    def __init__(self, root):
        self.root = root
        root.mkdir()
        (root / 'config.json').write_bytes(canonical({'input_peak_cny_per_million': '2', 'output_peak_cny_per_million': '8'}))

    def generate(self, messages, job_id, max_tokens, role):
        job = self.root / ('job-' + job_id)
        job.mkdir()
        if role == 'source':
            output = 'Synthetic source text; no real model execution.'
        else:
            questions = json.loads(messages[1]['content'])['questions']
            output = json.dumps({q['question_id']: 'UNKNOWN' for q in questions})
        prompt, runtime = dispatch_text(messages), runtime_context_text(job / 'workspace')
        request = {'provider': 'deepseek-account', 'model': 'deepseek-flash', 'reasoningEffort': 'off',
                   'maxTokens': max_tokens, 'messages': [
                       {'role': 'user', 'content': [{'type': 'text', 'text': prompt}]},
                       {'role': 'user', 'content': [{'type': 'text', 'text': runtime}]}]}
        raw = canonical(request)
        receipt = {'status': 'ok', 'request_id': 'synthetic-' + job_id, 'record_path': str(job),
                   'input_tokens': 100, 'output_tokens': 20, 'physical_request_count': 1,
                   'request_sha256': digest(raw), 'business_messages_sha256': digest(messages),
                   'response_sha256': digest(output.encode()), 'dispatch_sha256': digest(prompt.encode()),
                   'estimated_peak_cost_cny': '0.00036'}
        (job / 'actual_request.json').write_bytes(raw)
        (job / 'receipt.json').write_bytes(canonical(receipt))
        (job / 'response.json').write_bytes(canonical({'final_assistant_text': output,
            'assistant_usage_events': [{'usage': {'inputTokens': 100, 'outputTokens': 20}}]}))
        (job / 'guard.json').write_bytes(canonical({'agent_attempt_count': 1, 'stream_attempt_count': 1,
            'allowed_stream_count': 1, 'reject_code': None, 'requests': [
                {'bodyhash': digest(raw), 'business_input_sha256': digest(prompt.encode()),
                 'runtime_context_sha256': digest(runtime.encode()), 'user_text_blocks': 2}]}))
        return {'output': output, 'receipt': receipt}


class WorkloadExtensionTests(unittest.TestCase):
    def test_per_question_top2_union_preserves_authorized_texts_and_six_source_bound(self):
        authorized = [{'source_id': f'S{i+1:02}', 'text': word + ' factual detail ' + str(i)}
                      for i, word in enumerate(['alpha', 'alpha', 'beta', 'beta', 'gamma', 'gamma'])]
        questions = [{'question_id': word, 'question': word} for word in ['alpha', 'beta', 'gamma']]
        contract = {'retrieval_top_k': 4, 'retrieval_strategy': 'per_question_top2_union'}
        actual = retrieved_sources(authorized, questions, contract)
        audited = retrieval_sources_for_position(authorized, questions, contract)
        self.assertEqual(actual, audited)
        self.assertEqual(actual, authorized)
        self.assertEqual(len(actual), 6)
        # A withdrawn source is absent from the input universe and cannot enter
        # by being a good keyword match; every retained text remains complete.
        subset = authorized[:5]
        selected = retrieved_sources(subset, questions, contract)
        self.assertTrue({s['source_id'] for s in selected} <= {s['source_id'] for s in subset})
        self.assertTrue(all(s == next(a for a in subset if a['source_id'] == s['source_id']) for s in selected))
        self.assertEqual(len(retrieved_sources(authorized, questions, {'retrieval_top_k': 4})), 4)

    def test_legacy_nine_methods_three_positions_and_history_are_unchanged(self):
        contract, case, questions = fixture_inputs(False)
        legacy = {'__name__': 'legacy_lifecycle_for_test', '__file__': str(HERE / 'lifecycle_runner.py'),
                  '__package__': 'experiments.revocation_grouping_v1'}
        snapshot = HERE / 'snapshots/lifecycle_runner_before_long_workload.py'
        exec(compile(snapshot.read_bytes(), str(snapshot), 'exec'), legacy)
        self.assertEqual(history_for(case['sources'], 55), legacy['history_for'](case['sources'], 55))
        for kind in ('coordinated', 'independent', 'distribution_shift'):
            self.assertEqual(expanded_schedule(schedule_for(case['sources'], kind, 55)), legacy['schedule_for'](case['sources'], kind, 55))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'legacy-run'
            summary = run([case], questions, contract, root, FixtureClient(), instrument_only=True)
            self.assertEqual(len(summary['rows']), 27)
            self.assertEqual({row['time'] for row in summary['rows']}, {0, 2, 4})
            self.assertTrue(all(row['target_jobs'] == 3 for row in summary['cases']))
            report = evaluate(root, write=False)
            self.assertTrue(report['audit_ok'], report['issues'])
            self.assertEqual([len(row['answer_evaluation']['questions']) for row in report['positions']], [3] * 27)

    def test_expanded_ticks_keep_four_changes_and_three_isolated_question_batches(self):
        contract, case, questions = fixture_inputs(True)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'extended-run'
            summary = run([case], questions, contract, root, FixtureClient(), instrument_only=True)
            self.assertEqual(len(summary['rows']), 54)
            self.assertTrue(all(row['target_jobs'] == 9 for row in summary['cases']))
            events = json.loads((root / case['case_id'] / 'events_frozen_before_models.json').read_bytes())
            self.assertEqual(len(events), 15)
            for event in events:
                self.assertEqual(event['time'], event['policy_time'] * 3 + event['query_batch'])
                self.assertEqual(event['allowed'], events[event['policy_time'] * 3]['allowed'])
            history = json.loads((root / case['case_id'] / 'training_history.json').read_bytes())
            self.assertEqual(history['expected_deliveries'], 9)
            self.assertEqual(history['expected_changes'], 4)
            for method in contract['methods']:
                host_events = [json.loads(line) for line in (root / case['case_id'] / method / 'host/events.jsonl').read_text().splitlines()]
                commits = [event for event in host_events if event['kind'] == 'permission_committed']
                self.assertEqual(len(commits), 5)
                self.assertEqual(sum(bool(event['data']['changed']) for event in commits), 4)
            for path in (root / 'calls').glob('*.json'):
                call = json.loads(path.read_bytes())
                text = json.dumps(call['messages'])
                self.assertNotIn('QA_REFERENCE_SECRET', text)
                if call['role'] == 'source':
                    self.assertNotIn('PUBLIC_QUESTION_', text)
                else:
                    payload = json.loads(call['messages'][1]['content'])
                    ids = [question['question_id'] for question in payload['questions']]
                    self.assertIn(ids, [['Q1', 'Q2', 'Q3'], ['Q4', 'Q5', 'Q6'], ['Q7', 'Q8', 'Q9']])
                    self.assertTrue(all(set(question) == {'question_id', 'question'} for question in payload['questions']))
            report = evaluate(root, write=False)
            self.assertTrue(report['audit_ok'], report['issues'])
            self.assertEqual(len(report['positions']), 54)
            self.assertTrue(all(len(row['answer_evaluation']['questions']) == 3 for row in report['positions']))

    def test_native_replay_selects_only_scheduled_subset_and_recounts_costs(self):
        contract, case, questions = fixture_inputs(True)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'native-shaped-run'
            client = NativeShapeFixture(root.parent / (root.name + '-private-sdk'))
            run([case], questions, contract, root, client)
            report = evaluate(root, write=False)
            self.assertTrue(report['audit_ok'], report['issues'])
            self.assertEqual(sum(len(row['answer_evaluation']['questions']) for row in report['positions']), 162)
            for position in report['positions']:
                expected = questions[case['case_id']]['question_schedule'][str(position['time'])]
                self.assertEqual([q['question_id'] for q in position['answer_evaluation']['questions']], expected)
                self.assertTrue(position['answer_evaluation']['format_ok'])
            for method in report['method_case_results']:
                expected = (method['source_jobs_attributed'] + 9) * Decimal('0.00036')
                self.assertAlmostEqual(method['full_lifecycle_peak_cny'], float(expected))
            # Replacing the evaluation-side batch must not silently relabel an
            # actual target request as having answered different questions.
            altered = deepcopy(questions)
            altered[case['case_id']]['question_schedule']['0'] = ['Q4', 'Q5', 'Q6']
            changed = evaluate(root, questions=altered, write=False)
            self.assertFalse(changed['audit_ok'])
            self.assertTrue(any(issue['code'] == 'actual_target_input_or_output_binding_mismatch' for issue in changed['issues']))

    def test_invalid_or_unknown_question_batch_fails_before_model_calls(self):
        contract, case, questions = fixture_inputs(True)
        for selected in (['Q1', 'Q1', 'Q2'], ['Q1', 'Q2', 'missing'], ['Q1', 'Q2']):
            spec = deepcopy(questions)
            spec[case['case_id']]['question_schedule']['14'] = selected
            client = FixtureClient()
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
                run([case], spec, contract, Path(tmp) / 'invalid', client, instrument_only=True)
            self.assertEqual(client.jobs, 0)
            with self.assertRaises(ValueError):
                questions_for_position(spec[case['case_id']], 14)

    def test_independent_question_selectors_agree_without_flattening_reference_bank(self):
        contract, case, questions = fixture_inputs(True)
        spec = questions[case['case_id']]
        self.assertEqual(len(spec['questions']), 9)
        for tick in contract['events']['scoring_times']:
            a, b = questions_at_time(spec, tick), questions_for_position(spec, tick)
            self.assertEqual(a, b)
            self.assertEqual(len(a), 3)
            self.assertEqual({q['question_id'] for q in a}, set(spec['question_schedule'][str(tick)]))
        with self.assertRaises(ValueError):
            expanded_schedule([], 0)
        with self.assertRaises(ValueError):
            history_for(case['sources'], 55, 0)


if __name__ == '__main__':
    unittest.main()
