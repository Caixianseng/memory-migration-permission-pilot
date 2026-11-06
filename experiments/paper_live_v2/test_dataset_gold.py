"""Independent fixture arithmetic and no-gold-projection checks, no models."""
import json
import math
import unittest
from datetime import date, timedelta

from dataset_gold import OUT, load_project, load_gold, source_request, receiver_request, SCENARIOS
from evaluate_live import match_answer


class FixtureChecks(unittest.TestCase):
    def test_ten_distinct_business_templates_and_no_fact_ID_reuse(self):
        projects=json.loads((OUT/'projects.json').read_text(encoding='utf-8'))
        self.assertEqual(len(projects),10)
        self.assertEqual(len({p['project_name'] for p in projects.values()}),10)
        sources=[s['source_id'] for p in projects.values() for s in p['sources']]
        self.assertEqual(len(sources),len(set(sources)))

    def test_all_arithmetic_against_independent_reference(self):
        for index in range(1,11):
            gold=load_gold(f'LIVE-P{index:02d}')['arithmetic_ground_truth'];a,b=gold['operand_a'],gold['operand_b'];op=gold['operation']
            if op=='subtract':expected=a-b
            elif op=='minimum':expected=sorted([a,b])[0]
            elif op=='multiply':expected=sum(a for _ in range(b))
            elif op=='ceil_divide':expected=math.ceil(a/b)
            elif op=='floor_divide':expected=math.floor(a/b)
            elif op=='date_add':expected=(date.fromisoformat(a)+timedelta(days=b)).isoformat()
            elif op=='add':expected=sum([a,b])
            else:self.fail(op)
            self.assertEqual(str(expected),gold['expected'])

    def test_legal_rebuild_never_contains_restricted_fact_or_scoring_gold(self):
        for index in range(1,11):
            pid=f'LIVE-P{index:02d}';gold=load_gold(pid);request=source_request(pid,'A_to_B',0,'legal_rebuild');prompt=request['prompt']
            self.assertTrue(all(secret not in prompt for secret in gold['restricted_values']))
            self.assertNotIn('expected_answer',prompt);self.assertNotIn('minimal_support_sets',prompt)
            self.assertNotIn('交付前撤销',source_request(pid,'A_to_B',0,'initial_generation')['prompt'])
            self.assertEqual(set(request['host_input_scope']),set(gold['safe_source_ids_after_revocation']))

    def test_receiver_questions_do_not_include_gold(self):
        prompt=receiver_request('LIVE-P01','B_to_A',2,{s:'MEMORY_BODY' for s in SCENARIOS})['prompt']
        for key in ('expected_answer','required_values','minimal_support_sets','withheld_reference_value'):
            self.assertNotIn(key,prompt)
        self.assertNotIn(load_gold('LIVE-P01')['restricted_values'][0],prompt)

    def test_single_scenario_receiver_has_no_cross_scenario_context(self):
        for scenario in SCENARIOS:
            req=receiver_request('LIVE-P01','A_to_B',0,{s:'BODY-'+s for s in SCENARIOS},scenarios=(scenario,))
            prompt=json.loads(req['prompt'])
            self.assertEqual(set(prompt['scenarios']),{scenario})
            self.assertEqual(req['schema']['properties']['scenarios']['required'],[scenario])
            self.assertEqual(set(req['schema']['properties']['scenarios']['properties']),{scenario})

    def test_missing_and_wrong_answers_not_fabricated_as_correct(self):
        q=load_gold('LIVE-P01')['questions'][2]
        self.assertFalse(match_answer(q,None)['match'])
        self.assertFalse(match_answer(q,'UNKNOWN')['match'])
        self.assertFalse(match_answer(q,str(int(q['expected_answer'])+1))['match'])
        self.assertTrue(match_answer(q,q['expected_answer'])['match'])
        self.assertTrue(match_answer(q,q['expected_answer']+'组')['match'])


if __name__=='__main__':unittest.main()
