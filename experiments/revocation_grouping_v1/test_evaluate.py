"""Offline evaluator integrity tests; synthetic receipts never call a model."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

try:
    from .evaluate import canonical, digest, dispatch_text, runtime_context_text, evaluate, evaluate_answer, audit_usage_cost, native_usage_totals, NATIVE_USAGE_SCHEMA
    from .lifecycle_runner import FixtureClient, run, HERE
except ImportError:
    from experiments.revocation_grouping_v1.evaluate import canonical, digest, dispatch_text, runtime_context_text, evaluate, evaluate_answer, audit_usage_cost, native_usage_totals, NATIVE_USAGE_SCHEMA
    from experiments.revocation_grouping_v1.lifecycle_runner import FixtureClient, run, HERE


class SyntheticNativeEvidenceClient:
    """Creates fake SDK-shaped files solely to test offline binding arithmetic."""
    def __init__(self, private, cached_input=None):
        self.root, self.counter = private, 0
        self.cached_input = cached_input
        private.mkdir()
        (private / 'config.json').write_bytes(canonical({'input_peak_cny_per_million': '2', 'output_peak_cny_per_million': '8'}))

    def generate(self, messages, job_id, max_tokens, role):
        self.counter += 1
        job = self.root / ('job-' + job_id)
        job.mkdir()
        output = 'factual fixture only' if role == 'source' else '{"Q1":"fixture only","Q2":"UNKNOWN"}'
        prompt = dispatch_text(messages)
        runtime = runtime_context_text(job / 'workspace')
        body = {'provider': 'deepseek-account', 'model': 'deepseek-flash', 'reasoningEffort': 'off',
                'maxTokens': max_tokens, 'messages': [
                    {'role': 'user', 'content': [{'type': 'text', 'text': prompt}]},
                    {'role': 'user', 'content': [{'type': 'text', 'text': runtime}]}]}
        raw = canonical(body)
        receipt = {'status': 'ok', 'request_id': 'synthetic-' + job_id, 'record_path': str(job),
            'input_tokens': 100, 'output_tokens': 20, 'physical_request_count': 1,
            'request_sha256': digest(raw), 'business_messages_sha256': digest(messages),
            'response_sha256': digest(output.encode()), 'dispatch_sha256': digest(prompt.encode()),
            'estimated_peak_cost_cny': '0.00036'}
        usage = {'inputTokens': 100, 'outputTokens': 20, 'totalTokens': 120}
        if self.cached_input is not None:
            usage['cacheReadTokens'] = self.cached_input
            usage['totalTokens'] += self.cached_input
            receipt['cache_hit_input_tokens'] = self.cached_input
            receipt['estimated_cache_aware_peak_cost_cny'] = '0.0002424'
            receipt['estimated_cache_aware_offpeak_cost_cny'] = '0.0001212'
        (job / 'actual_request.json').write_bytes(raw)
        (job / 'receipt.json').write_bytes(canonical(receipt))
        (job / 'response.json').write_bytes(canonical({'final_assistant_text': output,
            'assistant_usage_events': [{'usage': usage}]}))
        (job / 'guard.json').write_bytes(canonical({'agent_attempt_count': 1, 'stream_attempt_count': 1,
            'allowed_stream_count': 1, 'reject_code': None,
            'requests': [{'bodyhash': digest(raw), 'business_input_sha256': digest(prompt.encode()),
                          'runtime_context_sha256': digest(runtime.encode()), 'user_text_blocks': 2}]}))
        return {'output': output, 'receipt': receipt}


def inputs():
    contract = json.loads((HERE / 'workload_contract.json').read_text(encoding='utf-8'))
    contract['methods'] = ['raw', 'retrieval', 'whole', 'joint']
    case = {'case_id': 'offline-fixture', 'sources': [
        {'source_id': f'S{i + 1:02}', 'text': f'User: topic {i}. Assistant: fixture note {i}.', 'version': 1}
        for i in range(8)]}
    questions = {'offline-fixture': [
        {'question_id': 'Q1', 'question': 'topic one?', 'support_source_ids': ['S01'],
         'reference_answer': 'known fact', 'required_phrases': ['known fact']},
        {'question_id': 'Q2', 'question': 'topic eight?', 'support_source_ids': ['S08'],
         'reference_answer': 'eighth fact', 'required_phrases': ['eighth fact']}]}
    return contract, case, questions


class AnswerTests(unittest.TestCase):
    def test_phrase_miss_does_not_become_semantic_failure(self):
        _, _, questions = inputs()
        result = evaluate_answer('{"Q1":"a legitimate paraphrase","Q2":"UNKNOWN"}',
            questions['offline-fixture'], ['S01'], ['S01'])
        self.assertTrue(result['format_ok'])
        first, second = result['questions']
        self.assertFalse(first['keyword_hint_hit'])
        self.assertIsNone(first['ai_semantic_correct'])
        self.assertIsNone(first['human_semantic_correct'])
        self.assertTrue(second['expected_unknown'])
        self.assertTrue(second['unknown_requirement_correct'])

    def test_missing_or_malformed_reply_not_filled_as_correct_unknown(self):
        _, _, questions = inputs()
        result = evaluate_answer('not json', questions['offline-fixture'], [], [])
        self.assertFalse(result['format_ok'])
        self.assertFalse(any(q['unknown_requirement_correct'] for q in result['questions']))

    def test_retrieval_miss_is_not_illegal_source_unknown_requirement(self):
        _, _, questions = inputs()
        result = evaluate_answer('{"Q1":"UNKNOWN","Q2":"UNKNOWN"}', questions['offline-fixture'], ['S01', 'S08'], [])
        self.assertTrue(result['questions'][0]['currently_legal_support_available'])
        self.assertFalse(result['questions'][0]['delivered_support_available'])
        self.assertFalse(result['questions'][0]['expected_unknown'])
        self.assertFalse(result['questions'][0]['legal_question_answered_nonunknown'])


class UsageSchemaTests(unittest.TestCase):
    def setUp(self):
        # Source-verified native shape, also matching the discovered cache-heavy
        # arithmetic. This is a static fixture; no real response is rewritten.
        self.usage = {'inputTokens': 487, 'cacheReadTokens': 9344, 'cacheWriteTokens': 0,
                      'outputTokens': 91, 'totalTokens': 9922}
        self.receipt = {'input_tokens': 487, 'output_tokens': 91,
                        'estimated_peak_cost_cny': '0.001702',
                        'estimated_cache_aware_peak_cost_cny': None,
                        'estimated_cache_aware_offpeak_cost_cny': None}
        self.config = {'input_peak_cny_per_million': '2', 'output_peak_cny_per_million': '8'}

    def test_legacy_miss_only_reporting_error_is_explicitly_corrected_without_mutation(self):
        before = deepcopy((self.usage, self.receipt))
        result = audit_usage_cost(self.usage, self.receipt, self.config)
        self.assertEqual(result['tokens']['input_total_tokens'], 9831)
        self.assertEqual(result['cost'], Decimal('0.02039'))
        self.assertEqual(result['cost_cache_peak'], Decimal('0.00207576'))
        self.assertEqual(result['cost_cache_offpeak'], Decimal('0.00103788'))
        self.assertTrue(result['derived_cost_correction_applied'])
        self.assertEqual(result['cost_diagnostics'][0]['legacy_value'], '0.001702')
        self.assertEqual(result['cost_diagnostics'][0]['derived_value'], '0.02039')
        self.assertEqual((self.usage, self.receipt), before)

    def test_corrected_v2_receipt_matches_total_input_and_read_cache_prices(self):
        receipt = {**self.receipt, 'usage_schema': NATIVE_USAGE_SCHEMA,
            'input_tokens_semantics': 'legacy_uncached_input_count', 'input_total_tokens': 9831,
            'input_uncached_tokens': 487, 'cache_read_tokens': 9344, 'cache_write_tokens': 0,
            'cache_hit_input_tokens': 9344, 'estimated_peak_cost_cny': '0.02039',
            'estimated_cache_aware_peak_cost_cny': '0.00207576',
            'estimated_cache_aware_offpeak_cost_cny': '0.00103788'}
        result = audit_usage_cost(self.usage, receipt, self.config)
        self.assertFalse(result['derived_cost_correction_applied'])
        self.assertEqual(result['tokens']['total_tokens'], 9922)
        receipt['estimated_peak_cost_cny'] = '0.001702'
        with self.assertRaisesRegex(ValueError, 'native_cost_recalculation_mismatch'):
            audit_usage_cost(self.usage, receipt, self.config)

    def test_total_tokens_mismatch_or_http_alias_is_not_silently_reinterpreted(self):
        with self.assertRaisesRegex(ValueError, 'native_usage_total_tokens_mismatch'):
            native_usage_totals({**self.usage, 'totalTokens': 9923})
        with self.assertRaisesRegex(ValueError, 'native_usage_http_or_unverified_alias_mixed_in'):
            native_usage_totals({**self.usage, 'prompt_tokens': 9831})

    def test_unknown_receipt_price_formula_still_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'native_cost_recalculation_mismatch'):
            audit_usage_cost(self.usage, {**self.receipt, 'estimated_peak_cost_cny': '0.123'}, self.config)

    def test_cache_write_keeps_total_input_but_cache_aware_price_unmeasured(self):
        usage = {'inputTokens': 10, 'cacheReadTokens': 20, 'cacheWriteTokens': 5,
                 'outputTokens': 4, 'totalTokens': 39}
        receipt = {'input_tokens': 10, 'output_tokens': 4, 'estimated_peak_cost_cny': '0.000052'}
        result = audit_usage_cost(usage, receipt, self.config)
        self.assertEqual(result['tokens']['input_total_tokens'], 35)
        self.assertEqual(result['cost'], Decimal('0.000102'))
        self.assertIsNone(result['cost_cache_peak'])
        self.assertIsNone(result['cost_cache_offpeak'])


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='d1-eval-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'run'
        self.contract, self.case, self.questions = inputs()

    def execute(self, native=False, cached_input=None):
        client = SyntheticNativeEvidenceClient(self.root.parent / (self.root.name + '-private-sdk'), cached_input) if native else FixtureClient()
        return run([self.case], self.questions, self.contract, self.root, client, instrument_only=not native)

    def test_fixture_audits_inputs_without_claiming_cost_or_advantage(self):
        self.execute()
        report = evaluate(self.root)
        self.assertTrue(report['audit_ok'], report['issues'])
        self.assertIsNone(report['physical_successful_peak_cny'])
        self.assertTrue(report['instrument_only'])
        self.assertFalse(report['exploratory_continuation']['advantage_proven'])
        self.assertTrue((self.root / 'effect_report.md').is_file())

    def test_unique_source_costs_and_target_costs_are_recomputed_from_receipts(self):
        self.execute(native=True)
        report = evaluate(self.root, write=False)
        self.assertTrue(report['audit_ok'], report['issues'])
        self.assertEqual(report['native_input_binding_verified_count'], report['saved_physical_calls'])
        for item in report['method_case_results']:
            self.assertAlmostEqual(item['full_lifecycle_peak_cny'],
                (item['source_jobs_attributed'] + item['target_jobs']) * .00036)
        self.assertIsNone(report['human_gold'])
        self.assertAlmostEqual(report['physical_successful_cache_aware_peak_cny'], report['physical_successful_peak_cny'])
        self.assertTrue(all(item['human_supported_answer_completeness'] is None for item in report['method_case_results']))

    def test_cache_aware_cost_requires_raw_usage_and_is_recomputed(self):
        self.execute(native=True, cached_input=60)
        report = evaluate(self.root, write=False)
        self.assertTrue(report['audit_ok'], report['issues'])
        for item in report['method_case_results']:
            charged = item['source_jobs_attributed'] + item['target_jobs']
            self.assertAlmostEqual(item['full_lifecycle_cache_aware_peak_cny'], charged * .0003624)
            self.assertAlmostEqual(item['full_lifecycle_cache_aware_offpeak_cny'], charged * .0001812)
            self.assertAlmostEqual(item['full_lifecycle_peak_cny'], charged * .00048)
            self.assertEqual(item['source_input_total_tokens'], item['source_jobs_attributed'] * 160)
            self.assertEqual(item['target_input_total_tokens'], item['target_jobs'] * 160)
            self.assertTrue(item['derived_cost_correction_applied'])
            self.assertLess(item['full_lifecycle_cache_aware_peak_cny'], item['full_lifecycle_peak_cny'])
        self.assertTrue(report['derived_cost_correction_applied'])
        self.assertGreater(report['cost_recalculation']['diagnostic_count'], 0)

    def test_summary_forged_cost_is_detected_not_used(self):
        self.execute(native=True)
        summary = json.loads((self.root / 'summary.json').read_bytes())
        for item in summary['cases']:
            item['full_lifecycle_peak_cny'] = 0
        (self.root / 'summary.json').write_bytes(canonical(summary))
        report = evaluate(self.root, write=False)
        self.assertFalse(report['audit_ok'])
        self.assertTrue(any(item['full_lifecycle_peak_cny'] > 0 for item in report['method_case_results']))
        self.assertTrue(any(issue['code'] == 'summary_cost_does_not_match_independent_unique_receipts' for issue in report['issues']))

    def test_actual_target_memory_tampering_is_detected(self):
        self.execute(native=True)
        path = next(path for path in (self.root / 'calls').glob('*.json') if json.loads(path.read_bytes())['role'] == 'target')
        call = json.loads(path.read_bytes())
        body = json.loads(call['messages'][1]['content'])
        body['memory'] = 'tampered memory'
        call['messages'][1]['content'] = json.dumps(body, ensure_ascii=False)
        path.write_bytes(canonical(call))
        report = evaluate(self.root, write=False)
        self.assertFalse(report['audit_ok'])
        self.assertTrue(any(issue['code'] == 'actual_target_input_or_output_binding_mismatch' for issue in report['issues']))

    def test_third_native_user_block_cannot_hide_as_runtime_context(self):
        self.execute(native=True)
        job = next((self.root.parent / (self.root.name + '-private-sdk')).glob('job-*'))
        path = job / 'actual_request.json'
        body = json.loads(path.read_bytes())
        body['messages'].append({'role': 'user', 'content': [{'type': 'text', 'text': 'undeclared extra source'}]})
        path.write_bytes(canonical(body))
        report = evaluate(self.root, write=False)
        self.assertFalse(report['audit_ok'])
        self.assertTrue(any(issue['code'] == 'native_actual_business_input_mismatch' for issue in report['issues']))

    def test_arbitrary_second_block_is_not_accepted_as_sdk_runtime(self):
        self.execute(native=True)
        job = next((self.root.parent / (self.root.name + '-private-sdk')).glob('job-*'))
        path = job / 'actual_request.json'
        body = json.loads(path.read_bytes())
        body['messages'][1]['content'][0]['text'] = 'runtime plus illicit business facts'
        path.write_bytes(canonical(body))
        report = evaluate(self.root, write=False)
        self.assertFalse(report['audit_ok'])
        self.assertTrue(any(issue['code'] == 'native_actual_business_input_mismatch' for issue in report['issues']))

    def test_forged_allowed_and_dependencies_do_not_become_authorization_truth(self):
        self.execute()
        path = self.root / 'summary.json'
        summary = json.loads(path.read_bytes())
        summary['rows'][0]['allowed'] = []
        summary['rows'][0]['dependencies'] = []
        path.write_bytes(canonical(summary))
        report = evaluate(self.root, write=False)
        self.assertFalse(report['audit_ok'])
        self.assertTrue(any(issue['code'] == 'row_permission_claim_mismatch' for issue in report['issues']))

    def test_failed_run_retains_missing_positions_and_no_paired_saving_claim(self):
        class FailedClient:
            def generate(self, *args):
                raise TimeoutError('test-only')
        with self.assertRaises(TimeoutError):
            run([self.case], self.questions, self.contract, self.root, FailedClient())
        report = evaluate(self.root, write=False)
        self.assertIsNotNone(report['failure_retained'])
        self.assertTrue(any(row['status'] == 'missing_or_failed' for row in report['positions']))
        self.assertTrue(all(row['cost_reduction_fraction'] is None for row in report['story_paired_comparisons']))

    def test_ai_review_is_labelled_ai_and_does_not_fill_human_scores(self):
        self.execute()
        reviews = {'rows': [{'case_id': self.case['case_id'], 'method': 'raw', 'time': time,
            'question_id': qid, 'semantic_correct': True} for time in [0, 2, 4] for qid in ['Q1', 'Q2']]}
        report = evaluate(self.root, ai_review=reviews, write=False)
        raw = next(item for item in report['method_case_results'] if item['method'] == 'raw')
        self.assertEqual(raw['ai_supported_answer_completeness'], 1)
        self.assertIsNone(raw['human_supported_answer_completeness'])
        self.assertFalse(report['exploratory_continuation']['advantage_proven'])

    def test_grounded_partial_plus_unknown_is_ai_control_correct_without_exact_marker(self):
        self.contract['methods'] = ['raw']
        self.questions[self.case['case_id']] = [
            {'question_id': 'Q1', 'question': 'What topics appear in S01 and S05?',
             'support_source_ids': ['S01', 'S05'], 'reference_answer': 'topic 0 and topic 4'},
            {'question_id': 'Q2', 'question': 'What topics appear in S01 and S08?',
             'support_source_ids': ['S01', 'S08'], 'reference_answer': 'topic 0 and topic 7'}]
        class PartialFixtureClient(FixtureClient):
            def generate(self, messages, job_id, max_tokens, role):
                result = super().generate(messages, job_id, max_tokens, role)
                if role == 'target':
                    memory = json.loads(messages[-1]['content'])['memory']
                    def answer(parts):
                        supplied = [text for sid, text in parts if sid + '\n' in memory]
                        return '; '.join(supplied) + ('; other part UNKNOWN' if len(supplied) < len(parts) else '')
                    result['output'] = json.dumps({'Q1': answer([('S01', 'topic 0'), ('S05', 'topic 4')]),
                                                   'Q2': answer([('S01', 'topic 0'), ('S08', 'topic 7')])})
                    result['receipt']['response_sha256'] = digest(result['output'].encode())
                return result
        run([self.case], self.questions, self.contract, self.root, PartialFixtureClient(), instrument_only=True)
        review = {'rows': [{'case_id': self.case['case_id'], 'method': 'raw', 'time': time,
                           'question_id': qid, 'semantic_correct': True}
                          for time in (0, 2, 4) for qid in ('Q1', 'Q2')]}
        report = evaluate(self.root, ai_review=review, write=False)
        raw = report['method_case_results'][0]
        self.assertEqual((raw['AI_control_correct_count'], raw['AI_control_count']), (3, 3))
        self.assertEqual(raw['required_unknown_correct'], 0)
        self.assertEqual(raw['auto_unknown_marker_correct_count'], 0)
        self.assertTrue(raw['required_unknown_correct_is_auto_marker_diagnostic'])
        self.assertIsNone(report['human_gold'])

    def test_missing_ai_control_review_remains_null_not_zero(self):
        self.contract['methods'] = ['raw']
        self.execute()
        raw = evaluate(self.root, write=False)['method_case_results'][0]
        self.assertGreater(raw['required_unknown_count'], 0)
        self.assertIsNone(raw['AI_control_correct_count'])
        self.assertIsNone(raw['AI_control_count'])
        self.assertEqual(raw['auto_unknown_marker_correct_count'], raw['required_unknown_correct'])
        partial_review = {'rows': [{'case_id': self.case['case_id'], 'method': 'raw',
                                   'time': 2, 'question_id': 'Q1', 'semantic_correct': True}]}
        partial = evaluate(self.root, ai_review=partial_review, write=False)['method_case_results'][0]
        self.assertIsNone(partial['AI_control_correct_count'])
        self.assertIsNone(partial['AI_control_count'])


if __name__ == '__main__':
    unittest.main()
