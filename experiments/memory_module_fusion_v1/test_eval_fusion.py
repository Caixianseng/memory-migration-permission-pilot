"""Deterministic scoring and actual-artifact audit tests, with zero model calls."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from . import eval_fusion as ev
from .context_adapter import prepare_sources, deliver
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost
from experiments.revocation_grouping_v1.sdk_adapter import usage_costs, dispatch_text
from dataclasses import asdict


class EvaluatorTests(unittest.TestCase):
    def test_official_normalization_and_categorical_f1_edges(self):
        self.assertEqual(ev.normalize_answer(' The, QUICK! A fox  '), 'quick fox')
        self.assertEqual(ev.answer_metrics('The Yoruba', 'Yoruba')['em'], 1.)
        self.assertEqual(ev.answer_metrics('yes indeed', 'yes')['f1'], 0.)
        self.assertEqual(ev.answer_metrics('no', 'no')['f1'], 1.)
        self.assertEqual(ev.answer_metrics('noanswer extra', 'noanswer')['f1'], 0.)
        self.assertEqual(ev.answer_metrics('', ''), {'em': 1., 'f1': 0., 'precision': 0., 'recall': 0.})
        value = ev.answer_metrics('red red blue', 'red blue blue')
        self.assertAlmostEqual(value['f1'], 2 / 3)

    def test_parse_is_question_bound_and_never_selects_best_of_multiple_answers(self):
        self.assertEqual(ev.extract_answer('{"answers":[{"question_id":"Q","answer":"Cedar"}]}', 'Q'), ('Cedar', 'answers_list'))
        self.assertEqual(ev.extract_answer('{"answer":"Cedar","question_id":"other"}', 'Q')[0], '')
        self.assertEqual(ev.extract_answer('{"answer":"wrong","answer":"Cedar"}', 'Q')[0], '')
        duplicate = '[{"question_id":"Q","answer":"wrong"},{"question_id":"Q","answer":"Cedar"}]'
        self.assertEqual(ev.extract_answer(duplicate, 'Q')[0], '')
        self.assertEqual(ev.extract_answer('I think Cedar. Or perhaps Maple.', 'Q')[0], 'I think Cedar. Or perhaps Maple.')
        self.assertEqual(ev.extract_answer('1998', 'Q')[0], '1998')

    def fixture(self, directory):
        sources = [{'source_id': 'A', 'text': 'Cedar is the sponsor.', 'version': 1},
                   {'source_id': 'B', 'text': 'Friday is the deadline.', 'version': 1}]
        case = {'case_id': 'case', 'question': 'Who is the sponsor?', 'sources': sources}
        host = LifecycleHost(sources, Path(directory) / 'host')
        host.set_permissions(['A', 'B'])
        prepared = prepare_sources(host, ['A'])
        messages = [{'role': 'system', 'content': 'Use current memory only.'},
                    {'role': 'user', 'content': json.dumps({'memory': prepared.context,
                        'questions': [{'question_id': 'case', 'question': case['question']}]})}]
        output = '{"answer":"Cedar"}'
        usage = {'inputTokens': 20, 'cacheReadTokens': 80, 'outputTokens': 5, 'totalTokens': 105}
        tokens, peak, cache = usage_costs(usage)
        record = Path(directory) / 'job'
        record.mkdir()
        dispatch = dispatch_text(messages)
        native_request = {'messages': [{'role': 'user', 'content': [
            {'type': 'text', 'text': dispatch}, {'type': 'text', 'text': 'fixed runtime snapshot'}]}]}
        raw = ev._canonical(native_request)
        (record / 'actual_request.json').write_bytes(raw)
        receipt = {**tokens, 'status': 'ok', 'physical_request_count': 1, 'usage': usage,
            'response_sha256': ev._text_hash(output), 'business_messages_sha256': ev._hash(messages),
            'dispatch_sha256': ev._text_hash(dispatch), 'request_sha256': ev._hash(raw),
            'estimated_peak_cost_cny': str(peak), 'estimated_cache_aware_peak_cost_cny': str(cache),
            'cost_is_supplier_bill': False, 'record_path': str(record)}
        guard = {'agent_attempt_count': 1, 'stream_attempt_count': 1, 'allowed_stream_count': 1,
            'reject_code': None, 'requests': [{'bodyhash': ev._hash(raw), 'bytes': len(raw),
                'business_input_sha256': ev._text_hash(dispatch), 'tools': 0, 'reasoningEffort': 'off',
                'user_text_blocks': 2, 'runtime_context_sha256': ev._text_hash('fixed runtime snapshot')}]}
        (record / 'guard.json').write_text(json.dumps(guard), encoding='utf-8')
        deliver(prepared, host, messages, lambda: {'output': output, 'receipt': receipt})
        row = {'case_id': 'case', 'question_id': 'case', 'arm': 'secure', 'time': 0,
            'allowed': ['A', 'B'], 'selected': ['A'], 'context': prepared.context,
            'context_sha256': prepared.context_sha256, 'source_bytes': prepared.source_bytes,
            'trace': {'prepared': asdict(prepared)}, 'messages': messages, 'output': output,
            'receipt': receipt, 'tokens': tokens, 'host_root': str(host.root)}
        # JSON-roundtrip the same schema saved by the native runner.
        return json.loads(json.dumps(row)), case

    def test_real_host_log_and_saved_native_artifact_are_verified_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            row, case = self.fixture(directory)
            result = ev.evaluate_rows([row], {'case': {'answer': 'Cedar', 'support_ids': ['A']}},
                cases=[case], artifacts_root=directory)
            score = result['rows'][0]
            self.assertEqual(score['audit_status'], 'verified', score)
            self.assertEqual(score['guarded_answer']['em'], 1.)
            aggregate = result['summary']['arms']['secure']
            self.assertEqual(aggregate['native_tokens']['input_total_tokens'], 100)
            self.assertEqual(aggregate['native_tokens']['input_uncached_tokens'], 20)
            self.assertEqual(aggregate['native_tokens']['cache_read_tokens'], 80)
            self.assertEqual(aggregate['estimated_cache_aware_peak_cost_cny_observed'], '0.0000832')

    def test_hidden_context_or_forbidden_dependency_does_not_pass_even_if_answer_is_correct(self):
        with tempfile.TemporaryDirectory() as directory:
            row, case = self.fixture(directory)
            row['allowed'] = ['B']
            row['context'] += '\nHIDDEN_NONORIGINAL_PAYLOAD'
            result = ev.evaluate_rows([row], {'case': {'answer': 'Cedar', 'support_ids': ['B']}},
                cases=[case], artifacts_root=directory)['rows'][0]
            self.assertEqual(result['answer']['em'], 1.)
            self.assertEqual(result['guarded_answer']['em'], 0.)
            self.assertEqual(result['audit_status'], 'failed')
            self.assertIn('payload:forbidden_delivery_dependencies', result['issues'])
            self.assertIn('payload:context_not_exactly_reconstructed_from_originals', result['issues'])

    def test_guard_usage_and_chain_tampering_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            row, case = self.fixture(directory)
            row['receipt']['usage']['totalTokens'] += 1
            self.assertIn('invalid_or_missing_native_usage', ev.audit_native(row, directory)['issues'])
            missing_output = {**row, 'output': None}
            self.assertIn('output_not_bound_to_native_receipt', ev.audit_native(missing_output, directory)['issues'])
            guard_path = Path(row['receipt']['record_path']) / 'guard.json'
            guard = json.loads(guard_path.read_bytes())
            guard['stream_attempt_count'] = 2
            guard_path.write_text(json.dumps(guard), encoding='utf-8')
            self.assertIn('actual_request_guard_not_single_allowed_stream', ev.audit_native(row, directory)['issues'])
            path = Path(row['host_root']) / 'events.jsonl'
            events = [json.loads(line) for line in path.read_bytes().splitlines()]
            events[0]['data']['sources']['A'] = 'forged'
            path.write_text('\n'.join(json.dumps(event) for event in events), encoding='utf-8')
            self.assertIn('host_event_hash_chain_invalid', ev.audit_host(row, directory)['issues'])

    def test_missing_evidence_is_unverified_not_a_passing_guard_and_missing_support_is_not_unanswerable(self):
        row = {'case_id': 'case', 'arm': 'plain', 'time': 1, 'allowed': ['B'], 'selected': ['B'],
               'context': 'B\nOriginal text', 'output': 'Cedar'}
        result = ev.evaluate_rows([row], {'case': {'answer': 'Cedar', 'support_ids': ['A']}},
            cases=[{'case_id': 'case', 'question': 'Sponsor?', 'sources': [
                {'source_id': 'A', 'text': 'Cedar', 'version': 1},
                {'source_id': 'B', 'text': 'Original text', 'version': 1}]}])
        self.assertEqual(result['rows'][0]['audit_status'], 'unverified')
        self.assertFalse(result['rows'][0]['primary_eligible'])
        self.assertEqual(result['summary']['arms']['plain']['primary_eligible_views'], 0)
        self.assertIsNone(result['summary']['arms']['plain']['primary_answer_em'])
        self.assertTrue(result['summary']['changed_missing_support_views_are_not_declared_unanswerable'])

    def test_duplicate_cells_and_outside_artifact_paths_never_silently_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            row, case = self.fixture(directory)
            with self.assertRaisesRegex(ValueError, 'duplicate_case_arm_time'):
                ev.evaluate_rows([row, deepcopy(row)], {'case': {'answer': 'Cedar', 'support_ids': ['A']}}, cases=[case])
            row['receipt']['record_path'] = str(Path(directory).parent / 'not-authorized-results')
            self.assertIn('actual_guard_artifact_invalid_or_outside_results', ev.audit_native(row, directory)['issues'])


if __name__ == '__main__':
    unittest.main()
