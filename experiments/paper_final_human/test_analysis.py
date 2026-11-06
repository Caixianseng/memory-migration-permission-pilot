"""Numerical/guard checks on artificial examples, not human study outcomes."""
import importlib.util
import json
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('human_analysis',Path(__file__).with_name('analyze.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class AnalysisChecks(unittest.TestCase):
    def test_nonconstant_kappa_hand_calculation(self):
        result=module.agreement_from_counts([40,10,10,40])
        self.assertAlmostEqual(result['agreement'],.8)
        self.assertAlmostEqual(result['cohen_kappa'],.6)

    def test_constant_marginals_not_perfect_kappa(self):
        self.assertIsNone(module.agreement_from_counts([100,0,0,0])['cohen_kappa'])
        self.assertIsNone(module.agreement_from_counts([0,0,0,0])['cohen_kappa'])

    def test_exact_signflip_and_holm(self):
        self.assertEqual(module.signflip([1,1,1]),.25)
        self.assertEqual(module.holm([.01,.04,.03]),[.03,.06,.06])

    def test_missing_human_attestation_blocks_completion(self):
        row={k:'0' for k in module.LABELS}
        row.update({'rater_id':'synthetic_guard_test','evaluable':'yes','legal_score':'1'})
        self.assertFalse(module.complete(row,{'primary_eligible':True}))

    def test_NA_requires_explicit_reason_and_illegal_score_ineligible(self):
        row={k:'0' for k in module.LABELS}
        row.update({'rater_id':'synthetic_guard_test','human_attestation':'yes','evaluable':'partial','legal_score':'NA'})
        self.assertFalse(module.complete(row,{'primary_eligible':True}))
        row['evidence_note']='Artificial unit test: source unavailable'
        self.assertTrue(module.complete(row,{'primary_eligible':True}))
        row['legal_score']='1'
        self.assertFalse(module.complete(row,{'primary_eligible':False}))

    def test_real_blank_instruments_remain_unlabelled(self):
        for slot in (1,2):
            rows=module.read_csv(module.BASE/f'rater_{slot}_blank.csv')
            self.assertEqual(len(rows),768)
            self.assertTrue(all(not r['rater_id'] and not r['human_attestation'] and all(not r[k] for k in module.LABELS) for r in rows))
        receipt=json.loads((module.BASE/'prepare_receipt.json').read_text(encoding='utf-8'))
        for name,expected in receipt['source_sha256'].items():
            self.assertEqual(module.sha(module.ROOT/'benchmarks/persistent_exchange_v1_public_20261105'/name),expected)


if __name__=='__main__':unittest.main()
