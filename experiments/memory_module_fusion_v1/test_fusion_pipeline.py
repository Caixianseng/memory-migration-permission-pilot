from pathlib import Path
import json
import tempfile
import unittest

from .fusion_pipeline import ARMS, FusionPipeline
from .bridge_repair import expand_authorized_links
from .reranker_runtime import TinyBERTReranker
from .context_adapter import deliver, ContextError
from .run_offline import CONFIG
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost


def fixture():
    texts = ['Alpha\nThe project deadline is Friday.', 'Alpha\nThe project deadline is Friday.',
             'Beta\nThe project review is on Tuesday.', 'Beta\nThe owner is Mira.',
             'Gamma\nThe archive is open.', 'Gamma\nThe office is in Lima.']
    sources = [{'source_id':f'S{i+1:03d}','text':text,'version':1,
                'origin':{'parent_index':i//2}} for i,text in enumerate(texts)]
    hierarchy = {s['source_id']:{'parent_id':f'P{i//2}','position':i%2,
        'prev_id':sources[i-1]['source_id'] if i%2 else None,
        'next_id':sources[i+1]['source_id'] if i%2==0 else None} for i,s in enumerate(sources)}
    return {'case_id':'literal-proof-integration-fixture','question':'When is the Alpha project deadline?',
            'sources':sources,'hierarchy':hierarchy}


class FusionTests(unittest.TestCase):
    def test_all_eight_real_module_combinations_pass_final_gate(self):
        case=fixture()
        with tempfile.TemporaryDirectory() as directory, TinyBERTReranker() as ranker:
            for arm in ARMS:
                host=LifecycleHost(case['sources'],Path(directory)/arm)
                pipeline=FusionPipeline(case,arm,host,ranker=ranker,retrieval_config=CONFIG)
                try:
                    host.set_permissions([s['source_id'] for s in case['sources']])
                    prepared,trace=pipeline.prepare()
                    calls=[]
                    messages=[{'role':'system','content':'Use only supplied memory.'},
                        {'role':'user','content':json.dumps({'memory':prepared.context,
                           'questions':[{'question_id':'Q','question':case['question']}]})}]
                    def send():
                        calls.append(1)
                        return {'output':'{}','receipt':{'instrument_only':True,'physical_request_count':0}}
                    deliver(prepared,host,messages,send)
                    self.assertEqual(calls,[1])
                    self.assertTrue(prepared.source_ids)
                    if trace['features']['proof']:
                        self.assertTrue(trace['retrieval_bundle_AND_fact'])
                    host.set_permissions([])
                    with self.assertRaises(ContextError):
                        deliver(prepared,host,messages,send)
                    self.assertEqual(calls,[1])
                finally:
                    pipeline.close()

    def test_alternative_literal_proof_repairs_cache_without_ranking_again(self):
        case=fixture()
        with tempfile.TemporaryDirectory() as directory:
            host=LifecycleHost(case['sources'],Path(directory)/'proof')
            pipeline=FusionPipeline(case,'h0p1r0',host,retrieval_config=CONFIG)
            try:
                host.set_permissions([s['source_id'] for s in case['sources']])
                first,trace=pipeline.prepare()
                self.assertIn('S001',first.source_ids)
                host.set_permissions([s['source_id'] for s in case['sources'] if s['source_id']!='S001'])
                second,trace=pipeline.prepare()
                self.assertNotIn('S001',second.source_ids)
                self.assertIn('S002',second.source_ids)
                self.assertEqual(trace['cache_reuse'],'surviving_exact_context_bound_proofs')
                self.assertEqual(trace['retrieval'],{})
                self.assertIn('deadline is Friday',second.context)
            finally:
                pipeline.close()

    def test_lexical_bridge_reads_only_current_allowed_parents(self):
        current=[{'source_id':'A','text':'Alpha\nThis event involved Beta.', 'allow':True,
                    'origin':{'title':'Alpha'}},
                 {'source_id':'B','text':'Beta\nThe event took place in 2001.', 'allow':True,
                    'origin':{'title':'Beta'}}]
        hierarchy={'A':{'parent_id':'PA'},'B':{'parent_id':'PB'},'C':{'parent_id':'PC'}}
        ids,trace=expand_authorized_links(current,['A'],hierarchy,'When was the Alpha event?')
        self.assertEqual(ids,['A','B'])
        self.assertEqual(trace['linked_parents'],['PB'])
        ids,_=expand_authorized_links(current[:1],['A'],hierarchy,'When was the Alpha event?')
        self.assertEqual(ids,['A'])


if __name__=='__main__':
    unittest.main()
