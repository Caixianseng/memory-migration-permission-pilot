from copy import deepcopy
import json
from pathlib import Path
import unittest

from . import evaluate as scoring


class PersistentExchangeEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluation = json.loads((Path(__file__).parent / 'data/evaluation_only.json').read_text(encoding='utf-8'))
        cls.case_ids = sorted(case for case in cls.evaluation if not case.startswith('_'))

    def records(self):
        records = []
        for case in self.case_ids:
            for direction in scoring.DIRECTIONS:
                ref = self.evaluation[case][direction]
                for arm in scoring.ARMS:
                    answers = {q['question_id']: q['answer'] if q['primary_eligible'] else 'UNKNOWN'
                               for q in ref['questions']}
                    content_bytes = 100 if arm == 'selective' else 200
                    records.append({
                        'case_id': case, 'direction': direction, 'arm': arm,
                        'answers': answers, 'receiver_evidence': {},
                        'delivery': {'content_bytes': content_bytes, 'packet_bytes': content_bytes + 300,
                                     'dependencies': [{'source_id': sid} for sid in ref['event']['allowed']]},
                        'source_jobs': [] if arm == 'raw' else ['not-opened-source-result.json'],
                        'timings': {'delivery_ms': 10},
                        'some_future_runtime_field': {'retained_only_by_runtime': True},
                    })
        return records

    def test_frozen_denominators_perfect_fixture_and_no_fabricated_money(self):
        records = self.records()
        before = deepcopy(records)
        report = scoring.evaluate(records, self.evaluation, draws=20)
        self.assertEqual(records, before)
        self.assertEqual(report['fixture'], {
            'questions_per_arm': 192, 'primary_eligible_per_arm': 121,
            'proven_unique_withheld_per_arm': 42,
            'other_withdrawn_not_scored_for_abstention_per_arm': 29})
        self.assertEqual(report['independent_project_clusters'], 12)
        self.assertEqual(report['main_record_count_expected'], 96)
        for arm in scoring.ARMS:
            self.assertEqual(report['summary'][arm]['legal_utility'], 1)
            self.assertEqual(report['summary'][arm]['question_weighted_unique_withheld_unknown_rate'], 1)
            self.assertEqual(report['summary'][arm]['answer_completion_rate'], 1)
            self.assertEqual(report['summary'][arm]['answer_surface_leaked_values'], 0)
            self.assertIsNone(report['summary'][arm]['payload_surface_value_leak_rate'])
            self.assertIsNone(report['resources'][arm]['total_supplier_fee_cny'])
            self.assertIsNone(report['resources'][arm]['total_physical_supplier_calls'])
        self.assertFalse(report['protocol']['source_job_references_opened'])
        self.assertIsNone(report['engineering_screen']['overall_algorithm_advantage_established'])
        json.dumps(report, allow_nan=False)

    def test_unicode_dates_and_opaque_identifier_boundary(self):
        self.assertTrue(scoring.value_present('CHK-A09F', '核验码是「ｃｈｋ－ａ０９ｆ」。'))
        self.assertTrue(scoring.value_present('CHK-A09F', 'CHK-A09F is recorded.'))
        self.assertFalse(scoring.value_present('CHK-A09F', 'CHK-A09F000'))
        self.assertFalse(scoring.value_present('CHK-A09F', 'XCHK-A09F'))
        self.assertTrue(scoring.value_present('2027年6月3日', '日期：2027-06-03。'))
        self.assertTrue(scoring.value_present('2027年6月3日', '2027/6/3'))
        self.assertFalse(scoring.value_present('2027年6月3日', '2027-06-30'))
        self.assertFalse(scoring.value_present('2027年6月3日', '2027-06-033'))
        self.assertTrue(scoring.is_unknown(' 「ＵＮＫＮＯＷＮ」。 '))
        self.assertFalse(scoring.is_unknown('UNKNOWN; maybe CHK-A09F'))

    def test_primary_uses_equal_project_weights_not_question_or_direction_n(self):
        records = self.records()
        # One perfect 0%-withdrawal project (16 eligible questions), all other
        # selective views answer UNKNOWN. The independent n remains 12.
        for record in records:
            if record['arm'] == 'selective' and record['case_id'] != self.case_ids[0]:
                record['answers'] = {qid: 'UNKNOWN' for qid in record['answers']}
        report = scoring.evaluate(records, self.evaluation, draws=100, seed=77)
        summary = report['summary']['selective']
        self.assertAlmostEqual(summary['legal_utility'], 1 / 12)
        self.assertAlmostEqual(summary['question_weighted_legal_value_match_rate'], 16 / 121)
        contrast = report['contrasts']['selective_vs_raw']['legal_utility']
        self.assertEqual(contrast['projects'], 12)
        self.assertAlmostEqual(contrast['estimate'], -11 / 12)
        self.assertEqual(contrast, scoring.evaluate(records, self.evaluation, draws=100, seed=77)['contrasts']['selective_vs_raw']['legal_utility'])

    def test_unique_value_leak_scan_checks_all_answers_and_deduplicates_repeated_probe(self):
        records = self.records()
        chosen = None
        for record in records:
            if record['arm'] != 'selective':
                continue
            questions = self.evaluation[record['case_id']][record['direction']]['questions']
            strong = [q for q in questions if q['unique_value_abstention_provable_in_fixture']]
            keys = [(q['support_ids'][0], scoring.normalize_text(q['required_values'][0])) for q in strong]
            if len(set(keys)) < len(keys):
                chosen = record, strong
                break
        self.assertIsNotNone(chosen, 'frozen probe duplicates at least one strong single-source question')
        record, strong = chosen
        value = strong[0]['required_values'][0]
        record['answers']['unexpected-model-key'] = 'Leaked elsewhere: ' + value
        record['received_memory'] = '已导入：' + value
        report = scoring.evaluate(records, self.evaluation, draws=0)
        row = next(row for row in report['per_record'] if all(row[key] == record[key] for key in ('case_id', 'direction', 'arm')))
        self.assertEqual(row['unique_withheld_values'], len(set((q['support_ids'][0], scoring.normalize_text(q['required_values'][0])) for q in strong)))
        self.assertEqual(row['answer_surface_leaked_values'], 1)
        self.assertEqual(row['payload_surface_leaked_values'], 1)
        self.assertEqual(row['unique_withheld_unknown_rate'], 1)  # Good abstentions alone do not prove no leakage.
        self.assertEqual(row['unexpected_answer_keys'], ['unexpected-model-key'])
        self.assertIsNone(report['summary']['selective']['payload_surface_value_leak_rate'])

    def test_withdrawn_nonunique_questions_are_not_forced_unknown_or_used_in_quality(self):
        records = self.records()
        for record in records:
            for q in self.evaluation[record['case_id']][record['direction']]['questions']:
                if not q['primary_eligible'] and not q['unique_value_abstention_provable_in_fixture']:
                    record['answers'][q['question_id']] = q['answer']
        report = scoring.evaluate(records, self.evaluation, draws=0)
        for arm in scoring.ARMS:
            self.assertEqual(report['summary'][arm]['legal_utility'], 1)
            self.assertEqual(report['summary'][arm]['question_weighted_unique_withheld_unknown_rate'], 1)
        nonunique = [row for row in report['per_question'] if row['other_withdrawn_reference_not_scored_for_abstention']]
        self.assertEqual(len(nonunique), 29 * 4)
        self.assertTrue(all(row['unique_withheld_unknown'] is None and row['legal_value_coverage'] is None for row in nonunique))

    def test_failed_answer_is_retained_and_missing_record_diagnostic_never_excludes_it(self):
        records = self.records()
        lost = records.pop(0)
        with self.assertRaisesRegex(ValueError, 'missing_main_records:1'):
            scoring.evaluate(records, self.evaluation, draws=0)
        partial = scoring.evaluate(records, self.evaluation, draws=0, require_complete=False)
        self.assertFalse(partial['complete'])
        self.assertEqual(partial['summary'][lost['arm']]['missing_records'], 1)
        self.assertEqual(partial['summary'][lost['arm']]['legal_question_count'], 121)
        self.assertAlmostEqual(partial['summary'][lost['arm']]['legal_utility'], 1 - .5 / 12)
        self.assertIsNone(partial['resources'][lost['arm']]['content_bytes']['mean_per_direction_equal_project_weight'])
        lost['answers'] = {}
        records.append(lost)
        completed_failure = scoring.evaluate(records, self.evaluation, draws=0)
        self.assertTrue(completed_failure['complete'])
        self.assertEqual(completed_failure['summary'][lost['arm']]['legal_utility'], partial['summary'][lost['arm']]['legal_utility'])

    def test_duplicate_unexpected_and_malformed_record_rejected(self):
        records = self.records()
        with self.assertRaisesRegex(ValueError, 'duplicate_record_key'):
            scoring.evaluate(records + [records[0]], self.evaluation, draws=0)
        changed = deepcopy(records)
        changed[0]['arm'] = 'chosen-after-results'
        with self.assertRaisesRegex(ValueError, 'unexpected_record_key'):
            scoring.evaluate(changed, self.evaluation, draws=0)
        changed = deepcopy(records)
        changed[0]['answers'] = ['not a question mapping']
        with self.assertRaisesRegex(ValueError, 'answers_mapping_required'):
            scoring.evaluate(changed, self.evaluation, draws=0)
        with self.assertRaisesRegex(ValueError, 'draws_must_be_nonnegative_integer'):
            scoring.evaluate(records, self.evaluation, draws=-1)

    def test_resource_reductions_are_paired_and_missing_measurements_not_zero(self):
        records = self.records()
        report = scoring.evaluate(records, self.evaluation, draws=20)
        contrast = report['contrasts']['selective_vs_full_rebuild']
        self.assertEqual(contrast['content_bytes']['estimate'], .5)
        self.assertEqual(contrast['content_bytes']['ci95'], [.5, .5])
        self.assertEqual(contrast['logical_source_jobs']['estimate'], 0)
        missing = next(row for row in records if row['arm'] == 'selective')
        missing['delivery']['content_bytes'] = None
        missing['timings']['delivery_ms'] = float('nan')
        report = scoring.evaluate(records, self.evaluation, draws=10)
        self.assertIsNone(report['resources']['selective']['content_bytes']['mean_per_direction_equal_project_weight'])
        self.assertFalse(report['contrasts']['selective_vs_full_rebuild']['content_bytes']['complete_all_projects'])
        self.assertIsNone(report['engineering_screen']['individual_resource_reductions_at_least_20_percent_vs_full_rebuild']['content_bytes'])
        json.dumps(report, allow_nan=False)

    def test_metadata_is_consistency_evidence_not_attestation(self):
        records = self.records()
        record = next(row for row in records if self.evaluation[row['case_id']][row['direction']]['event']['revoked'])
        revoked = self.evaluation[record['case_id']][record['direction']]['event']['revoked'][0]
        record['delivery'].update({'dependencies': [{'source_id': revoked}], 'close_reopen_verified': True,
                                   'reopened_content_sha256': 'expected-memory'})
        record['receiver_evidence'] = {'answers_schema_valid': True, 'reader_receipt': {
            'sqlite_uri_mode': 'ro', 'query_only': True, 'rendered_memory_sha256': 'changed-memory'}}
        report = scoring.evaluate(records, self.evaluation, draws=0)
        evidence = report['evidence']
        self.assertEqual(evidence['records_with_reported_unauthorized_dependencies'], 1)
        self.assertEqual(evidence['reader_readonly_reported'], 1)
        self.assertEqual(evidence['reader_content_hash_matches_delivery'], 0)
        self.assertIn('no independent', evidence['scope'])


if __name__ == '__main__':
    unittest.main()
