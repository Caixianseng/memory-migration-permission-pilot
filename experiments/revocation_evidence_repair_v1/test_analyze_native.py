"""Small adversarial tests of analysis units, accounting and source coverage."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from . import analyze_native as analysis


def fixture(arms=('raw','repair_selective','parent_bm25_4','repair_rebuild')):
    qids=['one','two']
    labels={'one':{'support_ids':['B']},'two':{'support_ids':['A']}}
    manifest={'cases':[{'case_id':qid} for qid in qids],'arms':list(arms),
        'max_calls':len(qids)*len(arms)*3,
        'plans':[{'case_id':qid,'events':[{'event':{'time':t},'arms':list(arms)} for t in range(3)]} for qid in qids]}
    rows=[];scores=[]
    for qid in qids:
        for arm in arms:
            for t in range(3):
                allowed=['A'] if t==1 else ['A','B']
                spans=[{'source_id':sid,'start':0,'end':5,'excerpt':'literal'} for sid in allowed]
                packet={'source_ids':allowed,'span_witnesses':spans}
                context='\n\n'.join(sid+'\nliteral' for sid in allowed)
                cost=(1. if t==1 else .1) if arm=='raw' else {'repair_selective':.02,'parent_bm25_4':.03,'repair_rebuild':.025}[arm]
                trace={'total_prepare_ms':2.,'initialization_ms':999.,'fallback':False,
                    'query_reused':t!=1,'exact_view_reuse':t!=1,'ranking_recomputed':t==1,
                    'retrieval':{'query_build_performed':t==1},'local_query_generation_model_calls':0}
                row={'case_id':qid,'arm':arm,'time':t,'step':t,'status':'completed','allowed':allowed,
                    'selected':allowed,'presented_source_ids':allowed,'prepared':packet,'trace':trace,
                    'context':context,'messages':[{'role':'system','content':f'Qualification tag: {arm}_{qid}\nFrozen task'},
                        {'role':'user','content':json.dumps({'memory':context,'questions':[{'question_id':qid,'question':'Public question'}]})}],
                    'initial_build_trace':{'initialization_ms':10.,'generation_model_calls':0,'retrieval':{'query_build_performed':True}} if t==0 else {},
                    'target_wall_ms':3.,'receipt':{'physical_request_count':1,'estimated_peak_cost_cny':str(cost),
                        'estimated_cache_aware_peak_cost_cny':str(cost),'usage':{'inputTokens':100,'outputTokens':13 if arm=='repair_selective' else 12}}}
                score={'case_id':qid,'arm':arm,'time':t,'audit_status':'verified','presented_source_ids':sorted(allowed),
                    'complete_annotated_support_retrieved':set(labels[qid]['support_ids'])<=set(allowed),
                    'primary_eligible':set(labels[qid]['support_ids'])<=set(allowed),
                    'answer':{'f1':1. if qid=='one' else 0.,'em':1. if qid=='one' else 0.}}
                rows.append(row);scores.append(score)
    return rows,{'rows':scores},manifest,labels


class AnalysisTests(unittest.TestCase):
    def test_unprinted_influence_dependency_cannot_receive_evidence_credit(self):
        rows,evaluated,_,labels=fixture()
        row=rows[0];score=evaluated['rows'][0]
        row['prepared']['span_witnesses']=row['prepared']['span_witnesses'][:1]
        row['presented_source_ids']=['A']
        score['presented_source_ids']=['A'];score['complete_annotated_support_retrieved']=False
        self.assertEqual(analysis.validate_presentation(row,score,labels['one']['support_ids']),{'A'})
        forged=deepcopy(score);forged['complete_annotated_support_retrieved']=True
        with self.assertRaisesRegex(ValueError,'dependency_ids_must_not_receive'):
            analysis.validate_presentation(row,forged,labels['one']['support_ids'])

    def test_question_macro_all_cost_views_once_only_build_and_exact_reuse(self):
        rows,evaluated,manifest,labels=fixture()
        result=analysis.analyze(rows,evaluated,manifest,labels,bootstrap_draws=40)
        raw=result['summary']['arms']['raw']
        self.assertEqual(raw['primary_views'],5)
        self.assertEqual(raw['question_macro_f1'],.5) # not view-weighted 2/5
        self.assertEqual(raw['all_cost_requests'],6)
        self.assertEqual(raw['lifecycle_estimated_native_cache_aware_peak_cny'],'2.4')
        self.assertEqual(raw['local_initial_build_ms'],20.) # repeated trace 999 is not charged 3x
        self.assertEqual(raw['local_prepare_ms'],12.)
        self.assertEqual(raw['local_initial_build_plus_prepare_ms'],32.)
        reuse=result['summary']['arms']['repair_selective']['reuse_by_view_type']
        self.assertEqual(reuse['exact_authorized_view']['query_reused_views'],4)
        self.assertEqual(reuse['changed_authorized_view']['query_reused_views'],0)

    def test_bootstrap_resamples_question_clusters_and_ratio_of_total_cost(self):
        samples=analysis.cluster_samples(['one','two'],5000)
        self.assertTrue(all(len(sample)==2 for sample in samples))
        values={sum([1.,0.][i] for i in sample)/2 for sample in samples}
        self.assertEqual(values,{0.,.5,1.}) # no independently resampled policy states
        cand=[{'f1':1.,'cache_cny':.1},{'f1':0.,'cache_cny':90.}]
        raw=[{'f1':0.,'cache_cny':1.},{'f1':0.,'cache_cny':100.}]
        stats=analysis.pair_statistics(cand,raw,samples)
        self.assertAlmostEqual(stats['lifecycle_cache_cost_reduction_fraction'],1-90.1/101)
        self.assertNotAlmostEqual(stats['lifecycle_cache_cost_reduction_fraction'],(.9+.1)/2)

    def test_quality_failure_does_not_pick_correct_subset_for_same_quality_cost(self):
        rows,evaluated,manifest,labels=fixture()
        for score in evaluated['rows']:
            if score['arm']=='repair_selective' and score['case_id']=='one':score['answer']['f1']=.7
        result=analysis.analyze(rows,evaluated,manifest,labels,bootstrap_draws=40)
        gate=result['gate']
        self.assertFalse(gate['quality_point_estimate_pass'])
        self.assertTrue(gate['cost_point_estimate_pass'])
        self.assertFalse(gate['worth_fresh40_native_screening'])
        self.assertIsNone(gate['same_quality_method_level_cost_comparison']['whole_lifecycle_cost_difference_candidate_minus_raw_cny'])

    def test_qualifying_cheaper_simple_control_blocks_combination_increment_claim(self):
        rows,evaluated,manifest,labels=fixture()
        for row in rows:
            if row['arm']=='parent_bm25_4':row['receipt']['estimated_cache_aware_peak_cost_cny']='0.01'
        gate=analysis.analyze(rows,evaluated,manifest,labels,bootstrap_draws=40)['gate']
        self.assertTrue(gate['raw_screen_point_estimate_pass'])
        self.assertTrue(gate['strong_simple_baseline_review']['candidate_quality_cost_pareto_dominated_by_simple_point_estimates'])
        self.assertFalse(gate['worth_fresh40_native_screening'])

    def test_identical_payload_and_request_count_never_claim_query_model_savings(self):
        rows,_,_,_=fixture()
        comparison=analysis.payload_comparison(rows)
        self.assertEqual(len(comparison),6)
        self.assertTrue(all(r['context_identical'] and r['business_messages_identical_except_independent_nonce'] for r in comparison))
        self.assertTrue(all(r['rebuild_requests']==r['selective_requests']==1 for r in comparison))
        self.assertTrue(all(not r['selective_model_generation_cost_benefit_established'] for r in comparison))
        self.assertTrue(all(r['selective_output_tokens']!=r['rebuild_output_tokens'] for r in comparison))

    def test_disjoint_blocks_are_merged_before_question_resampling(self):
        rows,evaluated,manifest,labels=fixture()
        parts=[]
        for cid in ('one','two'):
            block_manifest=deepcopy(manifest)
            block_manifest['cases']=[case for case in manifest['cases'] if case['case_id']==cid]
            block_manifest['plans']=[plan for plan in manifest['plans'] if plan['case_id']==cid]
            block_manifest['max_calls']=manifest['max_calls']//2
            parts.append({'rows':[r for r in rows if r['case_id']==cid],
                'evaluated':{'rows':[r for r in evaluated['rows'] if r['case_id']==cid]},
                'manifest':block_manifest,'labels':labels})
        merged_rows,merged_eval,merged_manifest,merged_labels=analysis.merge_blocks(parts,case_order=['one','two'])
        combined=analysis.analyze(merged_rows,merged_eval,merged_manifest,merged_labels,bootstrap_draws=40)
        original=analysis.analyze(rows,evaluated,manifest,labels,bootstrap_draws=40)
        self.assertEqual(combined['contrasts_against_raw'],original['contrasts_against_raw'])
        self.assertEqual(combined['summary']['all_planned_requests'],len(rows))
        with self.assertRaisesRegex(ValueError,'overlapping_original_question_blocks'):
            analysis.merge_blocks([parts[0],parts[0]])
        with self.assertRaisesRegex(ValueError,'not_exact_frozen_partition'):
            analysis.merge_blocks(parts,case_order=['one'])

    def test_no_rows_or_fresh_labels_loaded_while_any_block_is_running(self):
        manifest={'max_calls':300}
        mapping={str(Path('run1')/'manifest.json'):json.dumps(manifest).encode(),
            str(Path('run1')/'status.json'):json.dumps({'status':'completed','completed':300,'attempted':300}).encode(),
            str(Path('run2')/'manifest.json'):json.dumps(manifest).encode(),
            str(Path('run2')/'status.json'):json.dumps({'status':'running','completed':299,'attempted':300}).encode()}
        argv=['analyze_native','--run','run1','--data','block1','--run','run2','--data','block2',
              '--phase','fresh_confirmation','--partition','partition.json','--output','new-output']
        with patch.object(sys,'argv',argv), patch.object(Path,'exists',return_value=False), \
                patch.object(Path,'read_bytes',new=lambda path:mapping[str(path)]), \
                patch.object(analysis,'load_completed_part') as load:
            with self.assertRaisesRegex(ValueError,'all_completed_native_blocks_before_reading_labels'):
                analysis.main()
            load.assert_not_called()


if __name__=='__main__':unittest.main()
