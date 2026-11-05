"""Question-level weighting and complete-lifecycle accounting regression tests."""
import unittest

from .summarize_offline import analyze


class OfflineSummaryTests(unittest.TestCase):
    @staticmethod
    def fixture():
        contract = {'case_ids': ['one', 'two'], 'arms': ['h0p0r0', 'h0p1r0']}
        rows = []
        for cid in contract['case_ids']:
            for arm in contract['arms']:
                for time in range(3):
                    eligible = not (cid == 'one' and time == 1)
                    rows.append({'case_id': cid, 'arm': arm, 'time': time,
                        'allowed': ['S'], 'selected': ['S'], 'context': 'S\noriginal',
                        'source_bytes': 8, 'context_bytes': 10, 'commit_gate_passed': True,
                        'all_annotated_support_currently_allowed': eligible,
                        'complete_annotated_support_retrieved': cid == 'one',
                        'forbidden_source_ids': [], 'trace': {
                            'initialization_ms': 10 if 'p1' in arm else 3,
                            'total_prepare_ms': 2, 'retrieval': {'ranker_call_count': 0},
                            'cache_reuse': None if time == 0 else 'rechecked'}})
        return rows, contract

    def test_question_macro_uses_two_units_and_initialization_exactly_once(self):
        rows, contract = self.fixture()
        result = analyze(rows, contract, bootstrap_draws=40)
        point = result['summary']['arms']['h0p0r0']
        self.assertEqual(point['question_macro_eligible_support_complete_rate'], .5)
        self.assertEqual(point['eligible_observations'], 5)
        self.assertEqual(point['complete_support_eligible_observations'], 2)
        self.assertEqual(point['lifecycle_cpu_ms_total'], 18)
        self.assertEqual(point['lifecycle_source_bytes_total'], 48)
        proof = result['factorial']['proof']['averaged_main_effect']
        self.assertEqual(proof['lifecycle_cpu_ms']['independent_question_clusters'], 2)
        self.assertEqual(proof['lifecycle_cpu_ms']['paired_mean_difference_candidate_minus_control'], 7)
        self.assertEqual(proof['eligible_support_complete_rate']['pointwise_95pct_question_bootstrap_interval'], [0., 0.])
        self.assertEqual(result['proof_output_identity'][0]['exact_context_equal_views'], 6)

    def test_incomplete_matrix_and_cross_arm_policy_drift_rejected(self):
        rows, contract = self.fixture()
        with self.assertRaisesRegex(ValueError, 'complete_registered_three_state_matrix'):
            analyze(rows[:-1], contract, bootstrap_draws=10)
        rows[-1]['allowed'] = []
        with self.assertRaisesRegex(ValueError, 'policy_or_eligibility_mismatch'):
            analyze(rows, contract, bootstrap_draws=10)


if __name__ == '__main__':
    unittest.main()
