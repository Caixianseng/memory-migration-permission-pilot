from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from . import prepare_data as data


class FrozenExchangeDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.evaluation, cls.contract, cls.mechanisms = data.build()

    def test_full_size_rate_grid_and_distinct_owner_sources(self):
        self.assertEqual(len(self.cases), 12)
        self.assertEqual({(c['sources_per_agent'],c['revocation_percent']) for c in self.cases},
                         {(n,p) for n in (20,50,100) for p in (0,10,30,50)})
        all_ids, all_texts = [], []
        for case in self.cases:
            for owner in data.AGENTS:
                records = case['agents'][owner]['sources']
                self.assertEqual(len(records), case['sources_per_agent'])
                all_ids.extend(r['source_id'] for r in records)
                all_texts.extend(r['text'] for r in records)
                self.assertTrue(all(r['origin']['agent_id']==owner and r['origin']['synthetic'] for r in records))
        self.assertEqual(len(set(all_ids)),len(all_ids))
        self.assertEqual(len(set(all_texts)),len(all_texts))
        self.assertEqual(len(all_ids),1360)

    def test_chunks_are_fixed_exact_partitions_not_withdrawal_groups(self):
        for case in self.cases:
            for owner in data.AGENTS:
                source_ids = {r['source_id'] for r in case['agents'][owner]['sources']}
                chunks = case['chunks'][owner]
                self.assertEqual(len(chunks),2)
                self.assertFalse(set(chunks[0]) & set(chunks[1]))
                self.assertEqual(set(chunks[0]) | set(chunks[1]),source_ids)
                self.assertEqual([len(c) for c in chunks],[len(source_ids)//2]*2)
                ranked = sorted(source_ids,key=lambda sid:data.digest('fixed-chunk:'+sid))
                self.assertEqual(chunks[0]+chunks[1],ranked)

    def test_permission_masks_do_not_read_question_or_chunk_outcomes(self):
        for case in self.cases:
            for direction in data.DIRECTIONS:
                event = data.permission_event(case,direction)
                self.assertEqual(len(event['revoked']),case['sources_per_agent']*case['revocation_percent']//100)
                changed = deepcopy(case)
                changed['questions']=[{'answer':'POISON_REFERENCE'}]
                changed['chunks']={a:[[],[]] for a in data.AGENTS}
                self.assertEqual(data.permission_event(changed,direction),event)
                sender,_ = data.direction_agents(direction)
                ids={s['source_id'] for s in case['agents'][sender]['sources']}
                self.assertEqual(set(event['allowed']) | set(event['revoked']),ids)
                self.assertFalse(set(event['allowed']) & set(event['revoked']))

    def test_source_projection_has_no_future_or_reference_content(self):
        forbidden={'questions','answer','required_values','support_ids','allowed','revoked','event',
                   'revocation_percent','evaluation','chunks','expected_at_first_delivery'}
        for case in self.cases:
            for direction in data.DIRECTIONS:
                sender,_=data.direction_agents(direction)
                ids=data.permission_event(case,direction)['allowed']
                projected=data.source_projection(case,sender,ids)
                self.assertEqual(set(projected),{'case_id','source_agent','sources'})
                def visit(value):
                    if isinstance(value,dict):
                        self.assertFalse(forbidden & set(value))
                        for child in value.values():visit(child)
                    elif isinstance(value,list):
                        for child in value:visit(child)
                visit(projected)
                self.assertEqual([s['source_id'] for s in projected['sources']],ids)
                if projected['sources']:
                    projected['sources'][0]['text']='MODIFIED'
                    self.assertNotEqual(case['agents'][sender]['sources'][0]['text'],'MODIFIED')

    def test_projection_refuses_cross_agent_and_duplicate_sources(self):
        case=self.cases[0]
        with self.assertRaises(ValueError):
            data.source_projection(case,'A',[case['agents']['B']['sources'][0]['source_id']])
        sid=case['agents']['A']['sources'][0]['source_id']
        with self.assertRaises(ValueError):data.source_projection(case,'A',[sid,sid])
        with self.assertRaises(ValueError):data.direction_agents('A_to_C')

    def test_all_question_references_are_grounded_and_eligibility_fixed(self):
        question_ids=[]
        for case in self.cases:
            for direction in data.DIRECTIONS:
                reference=self.evaluation[case['case_id']][direction]
                questions=reference['questions']
                self.assertEqual(len(questions),8)
                self.assertEqual([q['question_kind'] for q in questions].count('single_source'),5)
                self.assertEqual([q['question_kind'] for q in questions].count('two_source_join'),2)
                sender,_=data.direction_agents(direction)
                texts={r['source_id']:r['text'] for r in case['agents'][sender]['sources']}
                allowed=set(data.permission_event(case,direction)['allowed'])
                for q in questions:
                    question_ids.append(q['question_id'])
                    self.assertEqual(q['primary_eligible'],set(q['support_ids'])<=allowed)
                    body='\n'.join(texts[sid] for sid in q['support_ids'])
                    self.assertTrue(all(value in body for value in q['required_values']))
                    self.assertTrue(all(value not in q['question'] for value in q['required_values']))
                    if q['question_kind']=='two_source_join':self.assertEqual(len(q['support_ids']),2)
                public=data.receiver_questions(self.evaluation,case['case_id'],direction)
                self.assertEqual(len(public),8)
                self.assertTrue(all(set(q)=={'question_id','question'} for q in public))
        self.assertEqual(len(question_ids),192)
        self.assertEqual(len(set(question_ids)),192)

    def test_strong_unknown_probes_never_exist_in_another_legal_source(self):
        strong=0
        for case in self.cases:
            for direction in data.DIRECTIONS:
                sender,recipient=data.direction_agents(direction)
                ref=self.evaluation[case['case_id']][direction]
                sources={s['source_id']:s['text'] for s in case['agents'][sender]['sources']}
                own='\n'.join(s['text'] for s in case['agents'][recipient]['sources'])
                for q in ref['questions']:
                    if not q['unique_value_abstention_provable_in_fixture']:continue
                    strong+=1
                    self.assertFalse(q['primary_eligible'])
                    self.assertEqual(q['expected_at_first_delivery'],'UNKNOWN')
                    alternatives=own+'\n'+'\n'.join(text for sid,text in sources.items() if sid not in q['support_ids'])
                    for value in q['required_values']:self.assertNotIn(value,alternatives)
                if case['revocation_percent']==0:
                    self.assertTrue(all(q['primary_eligible'] for q in ref['questions']))
                    self.assertEqual(ref['questions'][-1]['probe_status'],'no_revocation_ordinary_legal_question')
        self.assertGreater(strong,0)

    def test_layered_mechanisms_use_distinct_actual_parent_and_fresh_receiver(self):
        specs=self.mechanisms['mechanisms']
        self.assertEqual(len(specs),2)
        self.assertEqual([s['case_id'] for s in specs],[c['case_id'] for c in self.cases[:2]])
        for spec in specs:
            case=next(c for c in self.cases if c['case_id']==spec['case_id'])
            first,second=case['agents']['B']['sources'][:2]
            self.assertEqual(first['origin']['record_type'],'code')
            self.assertEqual(second['origin']['record_type'],'date')
            self.assertEqual(spec['child_inputs'],['actual_imported_parent_memory',first['source_id'],second['source_id']])
            self.assertEqual(spec['withdraw_before_first_return'],[first['source_id']])
            refs=self.evaluation['_mechanisms'][spec['mechanism_id']]['questions']
            self.assertEqual(refs[1]['expected_at_first_delivery'],'UNKNOWN')
            self.assertTrue(spec['not_in_main_twelve_project_cost_or_quality_comparison'])
            self.assertIn('fresh layered A store',spec['receiver'])

    def test_repeat_build_byte_identity_and_write_once(self):
        repeat=data.build()
        self.assertEqual(data.encoded(repeat),data.encoded((self.cases,self.evaluation,self.contract,self.mechanisms)))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'frozen.json'
            data.write_once(path,b'{"value":1}\n')
            data.write_once(path,b'{"value":1}\n')
            with self.assertRaises(ValueError):data.write_once(path,b'{"value":2}\n')
            self.assertEqual(path.read_bytes(),b'{"value":1}\n')


if __name__=='__main__':unittest.main()
