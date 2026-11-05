"""The scale bridge must retain every lawful body, including beyond 12 sources."""
from pathlib import Path
import tempfile
import unittest

from . import scale_permission_runner as runner
from .test_permission_runner import RecordingClient


class ScaleRunnerTests(unittest.TestCase):
    def test_64_source_quotient_and_strong_greedy_native_boundaries(self):
        sources = [{'source_id': f'M{i:03d}', 'text': f'UNIQUE_COMPLETE_BODY_{i}', 'version': 1} for i in range(64)]
        ids = [s['source_id'] for s in sources]
        case = {'case_id': 'scale64-fixture', 'sources': sources}
        history = [{'before': ids, 'after': ids[:32]}, {'before': ids[:32], 'after': ids}]
        events = [{'time': 0, 'allowed': ids}, {'time': 1, 'allowed': ids[:32]}]
        questions = [{'question_id': 'q', 'question': 'What was reported?', 'support_source_ids': [ids[0]]}]
        config = {'forecast_model': 'joint_delta', 'arm_policies': {
            'exact': {'method': 'quotient_two_step'}, 'greedy': {'method': 'quotient_cache_greedy'}}}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'scale64'
            client = RecordingClient(output)
            result = runner.run(case, questions, events, history, output, arms=['exact', 'greedy'],
                config=config, budget_cap_cny='.5', max_jobs=4, target_prompt='Use only current sources.',
                client=client, nonces={'exact': '7' * 64, 'greedy': '8' * 64}, order_seed=2026110522)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(len(client.calls), 4)
            for row in result['rows']:
                self.assertEqual(set(row['dependencies']), set(events[row['step']]['allowed']))
                self.assertEqual(len(row['dependencies']), len(events[row['step']]['allowed']))
                self.assertTrue(row['all_current_allowed_sources_retained_verbatim'])
                self.assertLessEqual(row['layout']['details']['maximum_remaining_cohort_count'], 2)
            self.assertEqual(result['physical_totals']['successful_calls'], 4)


if __name__ == '__main__':
    unittest.main()
