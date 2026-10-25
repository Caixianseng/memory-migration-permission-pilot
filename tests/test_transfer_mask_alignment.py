import unittest
from scripts.verify_transfer_masking import coverage_from_literals, independent_masking

T = '[PVT_'+'A'*24+'_CUSTOMER_1]'
U = '[PVT_'+'A'*24+'_CUSTOMER_2]'


class MaskAlignmentTests(unittest.TestCase):
    def test_exact_mask_with_unicode_suffix(self):
        self.assertEqual(coverage_from_literals('客户：青河联合社。', '客户：'+T+'。'), frozenset(range(3, 8)))

    def test_partial_mask_does_not_gain_missing_prefix(self):
        self.assertEqual(coverage_from_literals('客户：青河联合社。', '客户：青河'+T+'。'), frozenset(range(5, 8)))

    def test_empty_token_replacement_is_rejected(self):
        with self.assertRaises(ValueError):
            coverage_from_literals('ABC', 'A'+T+'BC')

    def test_adjacent_tokens_same_total_coverage_are_verifiable(self):
        self.assertEqual(coverage_from_literals('A1234Z', 'A'+T+U+'Z'), frozenset(range(1, 5)))

    def test_repeated_literal_with_different_coverage_is_ambiguous(self):
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            coverage_from_literals('AxayazZ', 'A'+T+'a'+U+'Z')

    def test_plaintext_edit_and_invented_suffix_fail(self):
        for before, after in [('ABC', 'ABD'), ('name Cedar.', 'name '+T+'!')]:
            with self.assertRaises(ValueError):
                coverage_from_literals(before, after)

    def test_no_mask_keeps_zero_coverage(self):
        self.assertEqual(coverage_from_literals('公开状态', '公开状态'), frozenset())

    def test_only_fixed_registered_intent_prefix_may_be_removed(self):
        source = 'Customer: Cedar.'
        story = {'source': {'text': source}}
        task = {'query': 'Who is the customer?'}
        labels = {'sensitive_spans': [{'start': 10, 'end': 15}]}
        records = [{'text': source, 'source_start': 0, 'source_end': len(source)}]
        memories = [{'text': 'Customer: '+T+'.'}]
        good = "Requested answer field / 请求字段: customer organization's complete name / 客户组织的完整名称.\nMasked question / 脱敏问题: "
        value = independent_masking(story, task, labels, records,
            {'query': good+task['query'], 'memories': memories}, True)
        self.assertEqual(value['complete'], 1)
        bad = 'Requested answer field / 请求字段: arbitrary added Cedar.\nMasked question / 脱敏问题: '
        with self.assertRaisesRegex(ValueError, 'unregistered_query_prefix'):
            independent_masking(story, task, labels, records,
                {'query': bad+task['query'], 'memories': memories}, True)


if __name__ == '__main__':
    unittest.main()
