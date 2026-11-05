import unittest
from .evaluate_native import presentation


class PresentationTests(unittest.TestCase):
    def test_dependencies_do_not_count_as_displayed_evidence(self):
        row = {'selected': ['A','B','C'], 'prepared': {'source_ids': ['A','B','C'],
                'span_witnesses': [{'source_id': 'B'}, {'source_id': 'B'}]},
               'presented_source_ids': ['B']}
        self.assertEqual(presentation(row), ['B'])

    def test_cannot_claim_hidden_dependency_as_displayed(self):
        with self.assertRaises(ValueError):
            presentation({'prepared': {'source_ids': ['A','B'], 'span_witnesses': [{'source_id': 'A'}]},
                          'presented_source_ids': ['A','B']})

    def test_unbound_span_is_rejected(self):
        with self.assertRaises(ValueError):
            presentation({'prepared': {'source_ids': ['A'], 'span_witnesses': [{'source_id': 'B'}]}})


if __name__ == '__main__':
    unittest.main()
