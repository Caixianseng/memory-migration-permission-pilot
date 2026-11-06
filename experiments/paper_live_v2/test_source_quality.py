"""Guard against falsely attributing equations or quoted rules to conclusions."""
import unittest
from evaluate_sources import explicit_math,explicit_conclusions,contains_value


class ControlledSourceChecks(unittest.TestCase):
    def test_true_and_false_complete_binary_equations(self):
        self.assertEqual(explicit_math('172-27=145组')[0]['judgment'],'exact_arithmetic_true')
        self.assertEqual(explicit_math('172-27=146组')[0]['judgment'],'exact_arithmetic_false')

    def test_not_extract_false_suffix_from_multi_operator_expression(self):
        self.assertEqual(explicit_math('223 + 27 × 1 = 250元'),[])

    def test_literal_integer_boundary_and_date_normalization(self):
        self.assertFalse(contains_value('1450组',145))
        self.assertFalse(contains_value('14.5组',14))
        self.assertTrue(contains_value('2027年3月18日','2027-03-18'))

    def test_operand_is_not_automatically_a_derived_conclusion(self):
        truth={'operation':'minimum','expected':'380'}
        self.assertEqual(explicit_conclusions('LIVE-P02','segment_one=460，segment_two=380。',truth,'Mbps'),[])
        result=explicit_conclusions('LIVE-P02','串联链路可用带宽为380Mbps。',truth,'Mbps')
        self.assertEqual(len(result),1);self.assertTrue(result[0]['matches_controlled_gold'])

    def test_quoted_rule_does_not_capture_following_operand_as_conclusion(self):
        truth={'operation':'subtract','expected':'145'}
        text='规则“库存减保留量即最多可发数量”，172组减27组，最多可发145组。'
        result=explicit_conclusions('LIVE-P01',text,truth,'组')
        self.assertEqual([r['stated_value'] for r in result],['145'])

    def test_explicit_finish_date(self):
        result=explicit_conclusions('LIVE-P05','开始日期2027-03-01，完成日期为2027-03-18。',{'operation':'date_add','expected':'2027-03-18'},'日期')
        self.assertEqual(len(result),1);self.assertTrue(result[0]['matches_controlled_gold'])


if __name__=='__main__':unittest.main()
