"""Independent native artifact fixtures; no runner, SDK client or network calls."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from experiments.revocation_prefix_v1 import evaluate_real as ev
from experiments.revocation_grouping_v1.evaluate import dispatch_text, runtime_context_text


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def fixture(root, *, initial_read=0, write_tokens=0):
    case = {'case_id': 'independent-fixture', 'split': 'reserved-fixture', 'sources': [
        {'source_id': 'A', 'text': 'Alpha source fact.', 'version': 1},
        {'source_id': 'B', 'text': 'Beta source fact.', 'version': 1}]}
    binding = {s['source_id']: {'version': 1, 'text_sha256': ev.digest(s['text'].encode()),
               'text_utf8_bytes': len(s['text'].encode())} for s in case['sources']}
    questions = [{'question_id': 'QA', 'question': 'What is the first fact?', 'support_source_ids': ['A'],
                  'reference_answer': 'Alpha', 'required_phrases': ['Alpha'], 'AI_authored': True, 'human_gold': None},
                 {'question_id': 'QB', 'question': 'What is the second fact?', 'support_source_ids': ['B'],
                  'reference_answer': 'Beta', 'required_phrases': ['Beta'], 'AI_authored': True, 'human_gold': None}]
    schedule = [{'time': 0, 'allowed': ['A', 'B'], 'question_ids': ['QA', 'QB']},
                {'time': 1, 'allowed': ['B'], 'question_ids': ['QA', 'QB']}]
    config = {'known_source_lengths_bytes': {sid: b['text_utf8_bytes'] for sid, b in binding.items()},
              'next_cost_weight': 1.0, 'arm_policies': {'joint': {'method': 'causal_two_step', 'forecast_model': 'joint_delta'}}}
    manifest = {'schema': 'permission-prefix-real-paired-development-v1', 'case_id': case['case_id'],
                'materials_status': 'reserved-fixture', 'source_binding': binding,
                'source_binding_sha256': ev.digest(binding), 'case_sha256': ev.digest(case),
                'schedule': schedule, 'schedule_sha256': ev.digest(schedule), 'initial_history': [],
                'initial_history_sha256': ev.digest([]), 'planner_config': config,
                'arms': ['original', 'joint'], 'step_arm_order': [['original', 'joint']] * 2,
                'max_jobs': 4, 'nonces': {'original': '1' * 64, 'joint': '2' * 64},
                'target_prompt': 'Use only the current sources; otherwise UNKNOWN.'}
    evaluation = {'human_gold': None, 'events': []}
    for event in schedule:
        labels = [{'question_id': q['question_id'], 'support_sets': [q['support_source_ids']],
                   'expected_legally_answerable': set(q['support_source_ids']) <= set(event['allowed'])}
                  for q in questions]
        evaluation['events'].append({'time': event['time'], 'questions': questions, 'expected_support': labels})
    put(root / 'frozen_manifest.json', manifest)
    put(root / 'frozen_case.json', case)
    put(root / 'evaluation_only.json', evaluation)
    put(root / 'sdk.private' / 'config.json', {'input_peak_cny_per_million': '2', 'output_peak_cny_per_million': '8'})
    logs, caches, rows = {}, {'original': [], 'joint': []}, []

    def log(arm, kind, data, revision):
        events = logs.setdefault(arm, [])
        item = {'seq': len(events) + 1, 'previous': events[-1]['hash'] if events else '0' * 64,
                'kind': kind, 'revision': revision, 'monotonic_ns': len(events) + 1, 'data': data}
        item['hash'] = ev.digest(item)
        events.append(item)
        return item

    for arm in manifest['arms']:
        log(arm, 'registered', {'sources': {sid: b['text_sha256'] for sid, b in binding.items()}}, 0)
    for step, event in enumerate(schedule):
        for arm in manifest['arms']:
            index = len(rows) + 1
            order = list(event['allowed'])
            memory = '\n\n'.join(sid + '\n' + next(s['text'] for s in case['sources'] if s['source_id'] == sid) for sid in order)
            messages = [{'role': 'system', 'content': f"Qualification tag: {manifest['nonces'][arm]}\n" + manifest['target_prompt']},
                        {'role': 'user', 'content': json.dumps({'memory': memory, 'questions': [
                            {'question_id': q['question_id'], 'question': q['question']} for q in questions]})}]
            row = {'call_index': index, 'arm': arm, 'step': step, 'time': step, 'nonce': manifest['nonces'][arm],
                   'allowed': order, 'dependencies': order, 'permission_revision': step + 1,
                   'source_binding_sha256': ev.digest(binding), 'memory_sha256': ev.digest(memory.encode()),
                   'memory_utf8_bytes': len(memory.encode()), 'messages': messages, 'messages_sha256': ev.digest(messages),
                   'max_tokens': 1024, 'planner_input_history': [] if not step else [{'before': ['A', 'B'], 'after': ['B']}],
                   'planner_input_observed_orders': deepcopy(caches[arm]), 'planner_input_config': ev._policy(config, arm, event),
                   'layout': {'ordered_source_ids': order, 'planning_ms': 1.25}, 'all_current_allowed_sources_retained_verbatim': True}
            put(root / 'calls' / f'{index:04d}.input.json', row)
            output = json.dumps({'QA': 'Alpha' if not step else 'UNKNOWN', 'QB': 'Beta'})
            usage = {'inputTokens': 100, 'cacheReadTokens': initial_read if not step else (30 if arm == 'original' else 60),
                     'cacheWriteTokens': write_tokens, 'outputTokens': 10}
            usage['totalTokens'] = sum(usage.values())
            tokens = ev.native_usage_totals(usage)
            cost = (tokens['input_total_tokens'] * Decimal('2') + 10 * Decimal('8')) / Decimal(1_000_000)
            cached = ((100 * Decimal('2') + usage['cacheReadTokens'] * Decimal('.04') + 10 * Decimal('8'))
                      / Decimal(1_000_000)) if not write_tokens else None
            job = root / 'sdk.private' / f'job-{index:04d}'
            prompt, runtime = dispatch_text(messages), runtime_context_text(job / 'workspace')
            request = {'provider': 'deepseek-account', 'model': 'deepseek-flash', 'reasoningEffort': 'off', 'maxTokens': 1024,
                       'messages': [{'role': 'system', 'content': [{'type': 'text', 'text': 'fixed'}]},
                                    {'role': 'user', 'content': [{'type': 'text', 'text': prompt}]},
                                    {'role': 'user', 'content': [{'type': 'text', 'text': runtime}]}]}
            put(job / 'actual_request.json', request)
            receipt = {'status': 'ok', 'request_id': f'request-{index}', 'physical_request_count': 1,
                       'record_path': str(job), 'usage': usage, 'usage_schema': 'deepseek-harness-0.2.1-rc.3-anthropic-usage-v2',
                       'input_tokens_semantics': 'legacy_uncached_input_count', 'input_tokens': 100, 'output_tokens': 10,
                       'input_total_tokens': tokens['input_total_tokens'], 'input_uncached_tokens': 100,
                       'cache_read_tokens': usage['cacheReadTokens'], 'cache_write_tokens': write_tokens,
                       'request_sha256': ev.digest((job / 'actual_request.json').read_bytes()),
                       'response_sha256': ev.digest(output.encode()), 'business_messages_sha256': ev.digest(messages),
                       'dispatch_sha256': ev.digest(prompt.encode()), 'estimated_peak_cost_cny': str(cost),
                       'estimated_cache_aware_peak_cost_cny': str(cached) if cached is not None else None,
                       'estimated_cache_aware_offpeak_cost_cny': str(cached / 2) if cached is not None else None}
            put(job / 'receipt.json', receipt)
            put(job / 'guard.json', {'agent_attempt_count': 1, 'stream_attempt_count': 1, 'allowed_stream_count': 1,
                                    'reject_code': None, 'requests': [{'bodyhash': receipt['request_sha256'],
                                    'business_input_sha256': ev.digest(prompt.encode()), 'runtime_context_sha256': ev.digest(runtime.encode()),
                                    'user_text_blocks': 2}]})
            put(job / 'response.json', {'final_assistant_text': output, 'assistant_usage_events': [{'usage': usage}],
                                       'last_terminal_reason': {'kind': 'completed'}, 'final_assistant_interrupted': False,
                                       'physical_model_requests': 1})
            row.update(output=output, receipt=receipt, tokens=tokens, estimated_peak_cost_cny=str(cost),
                       estimated_cache_aware_peak_cost_cny=str(cached) if cached is not None else None)
            if not step:
                row['initial_cache_isolation'] = ev._initial_read(row, root, False)
            put(root / 'calls' / f'{index:04d}.json', row)
            rows.append(row)
            log(arm, 'permission_committed', {'allowed': order}, step + 1)
            prep = log(arm, 'delivery_prepared', {'sources': order, 'memory_sha256': row['memory_sha256'],
                                                'messages_sha256': row['messages_sha256']}, step + 1)
            log(arm, 'delivery_committed', {'prepared': prep['hash'], 'sources': order}, step + 1)
            log(arm, 'delivery_receipt', {'prepared': prep['hash'], 'receipt': receipt}, step + 1)
            log(arm, 'completed_cache_order_observed', {'ordered_source_ids': order, 'source_binding': binding,
                'source_binding_sha256': ev.digest(binding), 'completed': True, 'physical_request_count': 1,
                'request_id': receipt['request_id'], 'step': step}, step + 1)
            caches[arm].append(order)
    for arm, events in logs.items():
        path = root / arm / 'host' / 'events.jsonl'
        path.parent.mkdir(parents=True)
        path.write_text(''.join(json.dumps(item) + '\n' for item in events), encoding='utf-8')
    put(root / 'summary.json', {'status': 'completed', 'case_id': case['case_id'], 'instrument_only': False,
                              'manifest_sha256': ev.digest(manifest), 'rows': rows, 'model_calls_attempted': 4})
    return rows


class EvaluateRealTests(unittest.TestCase):
    def test_independent_native_fixture_complete_costs_and_paired_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'run'
            fixture(root)
            originals = {p: ev.digest(p.read_bytes()) for p in (root / 'calls').glob('*.json')}
            result = ev.analyze_run(root)
            self.assertEqual(result['errors'], [])
            self.assertTrue(result['comparison_eligible'])
            self.assertEqual(result['completed_model_calls'], 4)
            self.assertEqual(result['arms']['joint']['qa_counts']['control_exact_unknown_count'], 1)
            self.assertIsNone(result['human_gold'])
            for arm in result['arms'].values():
                self.assertEqual(arm['completed_model_calls'], 2)
                self.assertEqual(arm['planning_ms'], 2.5)
                self.assertTrue(arm['full_lifecycle_cost_complete'])
            paired = result['paired_costs'][0]
            self.assertNotEqual(paired['cached_right_minus_left_cny'], '0')
            multi = ev.analyze_runs([root])
            self.assertTrue(multi['all_runs_comparison_eligible'])
            ev.write_analysis(Path(temp) / 'new-analysis.json', multi)
            self.assertEqual(originals, {p: ev.digest(p.read_bytes()) for p in originals})
            with self.assertRaises(FileExistsError):
                ev.write_analysis(Path(temp) / 'new-analysis.json', multi)
            with self.assertRaisesRegex(ValueError, 'original_calls'):
                ev.write_analysis(root / 'calls' / 'new.json', multi)

    def test_tampered_payload_and_cross_arm_or_future_cache_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'run'
            rows = fixture(root)
            rows[2]['planner_input_observed_orders'] = [['B', 'A']]
            rows[2]['planner_input_history'].append({'before': ['B'], 'after': ['A']})
            put(root / 'calls' / '0003.json', rows[2])
            result = ev.analyze_run(root)
            self.assertTrue(any('planner_cache_not_own' in err for err in result['errors']))
            self.assertTrue(any('planner_history_not_causal' in err for err in result['errors']))
            self.assertFalse(result['comparison_eligible'])

    def test_raw_source_omission_is_detected_even_before_qa_scoring(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'run'
            rows = fixture(root)
            business = json.loads(rows[0]['messages'][1]['content'])
            business['memory'] = business['memory'].replace('Alpha source fact.', '[omitted]')
            rows[0]['messages'][1]['content'] = json.dumps(business)
            put(root / 'calls' / '0001.json', rows[0])
            result = ev.analyze_run(root)
            self.assertTrue(any('verbatim_memory_or_business_message_hash_mismatch' in e for e in result['errors']))
            self.assertFalse(result['comparison_eligible'])

    def test_miss_read_write_out_equation_cannot_be_reinterpreted_as_http_total(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'run'
            rows = fixture(root)
            rows[2]['receipt']['usage']['totalTokens'] = 110
            put(root / 'calls' / '0003.json', rows[2])
            result = ev.analyze_run(root)
            self.assertTrue(any('total_tokens_mismatch' in err for err in result['errors']))
            self.assertFalse(result['arms']['original']['full_lifecycle_cost_complete'])

    def test_initial_read_alert_and_unknown_write_price_do_not_invent_savings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'run'
            fixture(root, initial_read=600, write_tokens=7)
            result = ev.analyze_run(root)
            self.assertEqual(result['errors'], [])
            self.assertTrue(result['arms']['joint']['initial_read_review_required'])
            self.assertIsNone(result['arms']['joint']['full_lifecycle_cached_peak_cost_cny'])
            self.assertIsNotNone(result['arms']['joint']['full_lifecycle_no_cache_peak_cost_cny'])
            self.assertIsNone(result['paired_costs'][0]['cached_right_minus_left_cny'])

    def test_unknown_outcome_keeps_completed_spend_but_nulls_full_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'run'
            rows = fixture(root)
            (root / 'calls' / '0004.json').unlink()
            summary = ev.read(root / 'summary.json')
            summary.update(status='failed_no_automatic_retry', rows=rows[:3], model_calls_attempted=4)
            put(root / 'summary.json', summary)
            result = ev.analyze_run(root)
            self.assertFalse(result['comparison_eligible'])
            self.assertEqual(result['unreceipted_attempts'], 1)
            self.assertIsNone(result['arms']['joint']['full_lifecycle_cached_peak_cost_cny'])
            self.assertIsNotNone(result['arms']['joint']['verified_receipted_cached_peak_cost_cny'])

    def test_nonstrict_qa_never_fills_missing_answers_or_claims_semantic_accuracy(self):
        qs = [{'question_id': 'A', 'required_phrases': [['red', 'crimson']]},
              {'question_id': 'B', 'required_phrases': ['hidden']}, {'question_id': 'C'}]
        labels = [{'question_id': 'A', 'expected_legally_answerable': True},
                  {'question_id': 'B', 'expected_legally_answerable': False},
                  {'question_id': 'C', 'expected_legally_answerable': True}]
        result = ev.question_diagnostics('```json\n{"A":"Crimson","B":"UNKNOWN."}\n```', qs, labels)
        self.assertTrue(result['fenced_json_accepted_nonstrictly'])
        self.assertEqual(result['counts']['missing_answer_count'], 1)
        self.assertEqual(result['counts']['legal_required_phrase_hit_count'], 1)
        self.assertEqual(result['counts']['control_exact_unknown_count'], 1)
        self.assertFalse(result['is_semantic_or_human_score'])
        duplicate = ev.question_diagnostics('{"A":"red","A":"crimson"}', qs, labels)
        self.assertEqual(duplicate['duplicate_answer_ids'], ['A'])
        self.assertFalse(duplicate['exact_question_ids'])

    def test_multiple_runs_count_repeated_cases_without_claiming_independent_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            roots = [Path(temp) / 'one', Path(temp) / 'two']
            for root in roots:
                fixture(root)
            result = ev.analyze_runs(roots)
            self.assertEqual(result['run_count'], 2)
            self.assertEqual(result['unique_case_count'], 1)
            self.assertEqual(result['aggregate_arms']['joint']['completed_model_calls'], 4)
            self.assertTrue(result['all_runs_comparison_eligible'])
            with self.assertRaisesRegex(ValueError, 'double_count'):
                ev.analyze_runs([roots[0], roots[0]])

    def test_explicit_scale128_schema_and_quotient_policies_without_accepting_unknown_schemas(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'scale'
            rows = fixture(root)
            manifest = ev.read(root / 'frozen_manifest.json')
            manifest['schema'] = 'permission-prefix-real-paired-scale128-v1'
            manifest['planner_config']['arm_policies'] = {
                'original': {'method': 'quotient_cache_greedy'},
                'joint': {'method': 'quotient_two_step'}}
            put(root / 'frozen_manifest.json', manifest)
            for row in rows:
                row['planner_input_config'] = ev._policy(manifest['planner_config'], row['arm'], manifest['schedule'][row['step']])
                put(root / 'calls' / f"{row['call_index']:04d}.json", row)
                pending_path = root / 'calls' / f"{row['call_index']:04d}.input.json"
                pending = ev.read(pending_path)
                pending['planner_input_config'] = row['planner_input_config']
                put(pending_path, pending)
            summary = ev.read(root / 'summary.json')
            summary.update(rows=rows, manifest_sha256=ev.digest(manifest))
            put(root / 'summary.json', summary)
            result = ev.analyze_run(root)
            self.assertEqual(result['errors'], [])
            self.assertTrue(result['comparison_eligible'])
            self.assertEqual(result['source_run_schema'], manifest['schema'])
            manifest['schema'] = 'permission-prefix-real-paired-scale999-v1'
            put(root / 'frozen_manifest.json', manifest)
            with self.assertRaisesRegex(ValueError, 'unsupported_real_run_schema'):
                ev.analyze_run(root)


if __name__ == '__main__':
    unittest.main()
