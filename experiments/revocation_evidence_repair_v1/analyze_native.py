"""Question-paired development gate and complete native lifecycle accounting.

No client or model is constructed. Quality uses every question, averaging its
eligible repeated policy views first; costs use EVERY planned request. The sole
pre-fixed gate candidate is repair_selective. Labels are read only after every
supplied block is complete. Fresh confirmation requires the frozen disjoint
40-question partition; no intermediate fresh result is analyzed.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from decimal import Decimal
import argparse
import hashlib
import json
from pathlib import Path
import random

from .evaluate_native import presentation
from experiments.revocation_grouping_v1.sdk_adapter import usage_costs

CANDIDATE = 'repair_selective'
SIMPLE_CONTROL = 'parent_bm25_4'
QUALITY_MARGIN = .05
MIN_COST_REDUCTION = .20
BOOTSTRAP_DRAWS = 5000
BOOTSTRAP_SEED = 2026110593
METRIC_KEYS = ('f1', 'em', 'cold_cny', 'cache_cny', 'initial_ms', 'prepare_ms', 'local_ms', 'target_wall_ms')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mean(values):
    return sum(values)/len(values)


def percentile(values, q):
    ordered = sorted(values)
    index = (len(ordered)-1)*q
    low = int(index)
    high = min(low+1, len(ordered)-1)
    return ordered[low]+(ordered[high]-ordered[low])*(index-low)


def cluster_samples(question_ids, draws=BOOTSTRAP_DRAWS, seed=BOOTSTRAP_SEED):
    if not question_ids or len(set(question_ids)) != len(question_ids) or draws <= 0:
        raise ValueError('unique_independent_questions_and_positive_draws_required')
    rng = random.Random(seed)
    return [[rng.randrange(len(question_ids)) for _ in question_ids] for _ in range(draws)]


def pair_statistics(candidate, control, samples):
    diff = [candidate[i]['f1']-control[i]['f1'] for i in range(len(candidate))]
    quality = [mean([diff[i] for i in sample]) for sample in samples]
    reductions = [1-sum(candidate[i]['cache_cny'] for i in sample)/sum(control[i]['cache_cny'] for i in sample)
                  for sample in samples]
    costs = [mean([candidate[i]['cache_cny']-control[i]['cache_cny'] for i in sample]) for sample in samples]
    return {'independent_question_clusters': len(diff), 'paired_question_f1_differences': diff,
        'mean_f1_difference': mean(diff), 'f1_difference_95pct_cluster_bootstrap': [percentile(quality,.025), percentile(quality,.975)],
        'lifecycle_cache_cost_reduction_fraction': 1-sum(p['cache_cny'] for p in candidate)/sum(p['cache_cny'] for p in control),
        'cost_reduction_95pct_cluster_bootstrap': [percentile(reductions,.025),percentile(reductions,.975)],
        'mean_per_question_lifecycle_cache_cost_difference': mean([candidate[i]['cache_cny']-control[i]['cache_cny'] for i in range(len(candidate))]),
        'per_question_cache_cost_difference_95pct_cluster_bootstrap': [percentile(costs,.025),percentile(costs,.975)],
        'exploratory_joint_gate_bootstrap_fraction_not_probability_or_p_value':
            mean([float(q >= -QUALITY_MARGIN and c >= MIN_COST_REDUCTION) for q,c in zip(quality,reductions)])}


def validate_presentation(row, scored, required):
    shown = set(presentation(row))
    if set(row['selected'])-set(row['allowed']):
        raise ValueError('unauthorized_complete_dependency')
    if scored['audit_status'] != 'verified':
        raise ValueError('strict_native_guard_not_verified')
    if scored['presented_source_ids'] != sorted(shown):
        raise ValueError('scored_presentation_not_actual_span_source_ids')
    if scored['complete_annotated_support_retrieved'] != (set(required) <= shown):
        raise ValueError('dependency_ids_must_not_receive_presentation_evidence_credit')
    if scored['primary_eligible'] != (set(required) <= set(row['allowed'])):
        raise ValueError('primary_eligibility_not_current_permission')
    return shown


def _sum_cost(rows, key):
    return sum((Decimal(row['receipt'][key]) for row in rows), Decimal(0))


def _state_counts(rows):
    result = {}
    for exact in (True, False):
        subset = [row for row in rows if bool(row['trace']['exact_view_reuse']) == exact]
        result['exact_authorized_view' if exact else 'changed_authorized_view'] = {
            'views': len(subset), 'query_reused_views': sum(bool(r['trace']['query_reused']) for r in subset),
            'query_build_performed_views': sum(bool((r['trace'].get('retrieval') or {}).get('query_build_performed')) for r in subset),
            'ranking_recomputed_views': sum(bool(r['trace']['ranking_recomputed']) for r in subset),
            'fallback_views': sum(bool(r['trace']['fallback']) for r in subset),
            'prepare_ms': sum(r['trace']['total_prepare_ms'] for r in subset)}
    return result


def payload_comparison(rows):
    by = {(r['case_id'],r['arm'],r['time']):r for r in rows}
    output = []
    for cid,time in sorted({(r['case_id'],r['time']) for r in rows}):
        if (cid,'repair_rebuild',time) not in by or (cid,'repair_selective',time) not in by:
            continue
        a,b = by[cid,'repair_rebuild',time],by[cid,'repair_selective',time]
        def without_nonce(message):
            value = deepcopy(message)
            value[0]['content'] = value[0]['content'].split('\n',1)[1]
            return value
        output.append({'case_id':cid,'time':time,'context_identical':a['context']==b['context'],
            'presented_source_ids_identical':presentation(a)==presentation(b),
            'complete_dependencies_identical':a['selected']==b['selected'],
            'business_messages_identical_except_independent_nonce':without_nonce(a['messages'])==without_nonce(b['messages']),
            'rebuild_requests':a['receipt']['physical_request_count'],'selective_requests':b['receipt']['physical_request_count'],
            'rebuild_output_tokens':a['receipt']['usage']['outputTokens'],
            'selective_output_tokens':b['receipt']['usage']['outputTokens'],
            'observed_cached_cost_difference_selective_minus_rebuild':str(Decimal(b['receipt']['estimated_cache_aware_peak_cost_cny'])-Decimal(a['receipt']['estimated_cache_aware_peak_cost_cny'])),
            'selective_model_generation_cost_benefit_established':False,
            'reason':'Same payload and one request per state cannot establish a query-cache generation benefit; output, nonce, runtime and supplier-cache variation remain.'})
    return output


def analyze(rows, evaluated, manifest, labels, *, bootstrap_draws=BOOTSTRAP_DRAWS):
    case_ids = [case['case_id'] for case in manifest['cases']]
    arms = manifest['arms']
    scored = {(r['case_id'],r['arm'],r['time']):r for r in evaluated['rows']}
    by = {(r['case_id'],r['arm'],r['time']):r for r in rows}
    expected = {(plan['case_id'],arm,entry['event']['time']) for plan in manifest['plans'] for entry in plan['events'] for arm in entry['arms']}
    if len(by) != len(rows) or set(by) != expected or set(scored) != expected:
        raise ValueError('complete_unique_registered_matrix_required')
    if 'raw' not in arms or CANDIDATE not in arms:
        raise ValueError('fixed_raw_and_selective_arms_required')
    for key,row in by.items():
        if row.get('status') != 'completed' or row['receipt']['physical_request_count'] != 1:
            raise ValueError('all_completed_single_request_rows_required')
        validate_presentation(row,scored[key],labels[row['case_id']]['support_ids'])
    points,summary = {},{}
    for arm in arms:
        question_points=[]
        for cid in case_ids:
            trajectory=sorted([r for r in rows if r['case_id']==cid and r['arm']==arm],key=lambda r:r['time'])
            if len(trajectory)!=3:
                raise ValueError('three_repeated_permission_states_required')
            primary=[scored[cid,arm,r['time']] for r in trajectory if scored[cid,arm,r['time']]['primary_eligible']]
            if not primary:
                raise ValueError('question_without_any_primary_view')
            initial=[r['initial_build_trace'] for r in trajectory if r.get('initial_build_trace')]
            if len(initial)!=1 or trajectory[0].get('initial_build_trace') != initial[0]:
                raise ValueError('initial_local_build_must_be_recorded_once_at_first_delivery')
            initial_ms=initial[0]['initialization_ms']
            prepare_ms=sum(r['trace']['total_prepare_ms'] for r in trajectory)
            question_points.append({'case_id':cid,'primary_views':len(primary),'all_cost_views':len(trajectory),
                'f1':mean([r['answer']['f1'] for r in primary]),'em':mean([r['answer']['em'] for r in primary]),
                'cold_cny':float(_sum_cost(trajectory,'estimated_peak_cost_cny')),
                'cache_cny':float(_sum_cost(trajectory,'estimated_cache_aware_peak_cost_cny')),
                'initial_ms':initial_ms,'prepare_ms':prepare_ms,'local_ms':initial_ms+prepare_ms,
                'target_wall_ms':sum(r['target_wall_ms'] for r in trajectory)})
        points[arm]=question_points
        subset=[r for r in rows if r['arm']==arm]
        summary[arm]={'independent_questions':len(case_ids),'primary_views':sum(p['primary_views'] for p in question_points),
            'all_cost_requests':len(subset),'question_macro_f1':mean([p['f1'] for p in question_points]),
            'question_macro_em':mean([p['em'] for p in question_points]),
            'lifecycle_estimated_cold_peak_cny':str(_sum_cost(subset,'estimated_peak_cost_cny')),
            'lifecycle_estimated_native_cache_aware_peak_cny':str(_sum_cost(subset,'estimated_cache_aware_peak_cost_cny')),
            'local_initial_build_ms':sum(p['initial_ms'] for p in question_points),
            'local_prepare_ms':sum(p['prepare_ms'] for p in question_points),
            'local_initial_build_plus_prepare_ms':sum(p['local_ms'] for p in question_points),
            'target_wall_ms':sum(p['target_wall_ms'] for p in question_points),
            'fallback_views':sum(bool(r['trace']['fallback']) for r in subset),
            'reuse_by_view_type':_state_counts(subset),
            'initial_local_query_builds':sum(bool((r.get('initial_build_trace',{}).get('retrieval') or {}).get('query_build_performed')) for r in subset),
            'generation_model_calls_for_query_or_initial_build':sum(r['trace'].get('local_query_generation_model_calls',0)+r.get('initial_build_trace',{}).get('generation_model_calls',0) for r in subset),
            'output_tokens':sum(r['receipt']['usage']['outputTokens'] for r in subset),
            'input_MISS':sum(r['receipt']['usage']['inputTokens'] for r in subset),
            'input_READ':sum(r['receipt']['usage'].get('cacheReadTokens',0) for r in subset),
            'input_WRITE':sum(r['receipt']['usage'].get('cacheWriteTokens',0) for r in subset),
            'input_TOTAL':sum(r['receipt']['input_total_tokens'] for r in subset) if all('input_total_tokens' in r['receipt'] for r in subset) else None}
    samples=cluster_samples(case_ids,bootstrap_draws)
    contrasts={arm:pair_statistics(points[arm],points['raw'],samples) for arm in arms if arm!='raw'}
    candidate=contrasts[CANDIDATE]
    quality_ok=candidate['mean_f1_difference'] >= -QUALITY_MARGIN-1e-12
    cost_ok=candidate['lifecycle_cache_cost_reduction_fraction'] >= MIN_COST_REDUCTION-1e-12
    raw_cost=Decimal(summary['raw']['lifecycle_estimated_native_cache_aware_peak_cny'])
    candidate_cost=Decimal(summary[CANDIDATE]['lifecycle_estimated_native_cache_aware_peak_cny'])
    simple_review={'fixed_simple_control':SIMPLE_CONTROL,'available':SIMPLE_CONTROL in points}
    simple_blocks_increment=False
    simple_contrast=None
    if SIMPLE_CONTROL in points:
        simple_cost=Decimal(summary[SIMPLE_CONTROL]['lifecycle_estimated_native_cache_aware_peak_cny'])
        simple_f1=summary[SIMPLE_CONTROL]['question_macro_f1']
        candidate_f1=summary[CANDIDATE]['question_macro_f1']
        simple_qualifies=contrasts[SIMPLE_CONTROL]['mean_f1_difference'] >= -QUALITY_MARGIN-1e-12
        simple_blocks_increment=simple_qualifies and simple_cost < candidate_cost
        simple_contrast=pair_statistics(points[CANDIDATE],points[SIMPLE_CONTROL],samples)
        simple_review.update({'simple_f1_difference_vs_raw':contrasts[SIMPLE_CONTROL]['mean_f1_difference'],
            'simple_passes_same_raw_quality_tolerance':simple_qualifies,
            'simple_full_lifecycle_cache_cost_cny':str(simple_cost),
            'candidate_minus_simple_lifecycle_cache_cost_cny':str(candidate_cost-simple_cost),
            'simple_cost_lower_than_candidate':simple_cost<candidate_cost,
            'candidate_quality_cost_pareto_dominated_by_simple_point_estimates':
                simple_f1>=candidate_f1-1e-12 and simple_cost<=candidate_cost and (simple_f1>candidate_f1+1e-12 or simple_cost<candidate_cost),
            'qualified_simple_is_cheaper_incremental_savings_claim_blocked':simple_blocks_increment,
            'no_favorable_simple_arm_selection':True})
    raw_screen=quality_ok and cost_ok
    gate={'fixed_candidate':CANDIDATE,'reference':'raw','question_macro_f1_tolerance':QUALITY_MARGIN,
        'required_native_cache_cost_reduction':MIN_COST_REDUCTION,'quality_point_estimate_pass':quality_ok,
        'cost_point_estimate_pass':cost_ok,'raw_screen_point_estimate_pass':raw_screen,
        'strong_simple_baseline_review':simple_review,
        'worth_fresh40_native_screening':raw_screen and not simple_blocks_increment,
        'decision':('stop_loss_do_not_launch_fresh40_for_this_candidate' if not raw_screen else
                    'qualifying_simple_control_is_cheaper_no_combination_increment_claim' if simple_blocks_increment else
                    'worth_confirming_on_frozen_fresh40'),
        'automatic_launch_performed':False,
        'screening_gate_is_not_noninferiority_or_stable_superiority_proof':True,
        'same_quality_method_level_cost_comparison':{'eligible_only_if_whole_method_quality_gate_passes':True,
            'whole_lifecycle_cost_difference_candidate_minus_raw_cny':str(candidate_cost-raw_cost) if quality_ok else None,
            'whole_lifecycle_cost_reduction_fraction':candidate['lifecycle_cache_cost_reduction_fraction'] if quality_ok else None,
            'matched_correct_or_same_score_question_subset_used':False}}
    comparison=payload_comparison(rows)
    return {'summary':{'status':'completed','independent_question_clusters':len(case_ids),'all_planned_requests':len(rows),
        'costs_include_every_initial_delivery_revocation_and_regrant_request':True,
        'quality_uses_all_questions_and_eligible_views_within_question':True,
        'bootstrap':{'unit':'paired question cluster, repeated states kept together','draws':bootstrap_draws,'seed':BOOTSTRAP_SEED,
            'interval':'pointwise percentile 95%, exploratory; no multiplicity correction'},
        'local_query_construction_is_CPU_only_no_supplier_generation':True,
        'local_timers_are_wall_time_not_process_CPU_utilization':True,'cost_is_supplier_bill':False,
        'official_gold_or_aliases_changed':False,'fresh40_answers_read':False,'analysis_model_calls':0,'arms':summary},
        'gate':gate,'question_metrics':points,'contrasts_against_raw':contrasts,
        'fixed_candidate_against_strong_simple':simple_contrast,
        'rebuild_selective_payloads':comparison,
        'rebuild_selective_attribution':{'paired_views':len(comparison),'identical_context_views':sum(r['context_identical'] for r in comparison),
            'same_call_count_views':sum(r['rebuild_requests']==r['selective_requests'] for r in comparison),
            'selective_generation_cost_savings_established':False,
            'do_not_attribute_random_output_token_cost_differences_to_selective_query_reuse':True}}


def require_completed(manifest,status):
    if (status['status']!='completed' or status['completed']!=manifest['max_calls']
            or status['attempted']!=manifest['max_calls']):
        raise ValueError('wait_for_all_completed_native_blocks_before_reading_labels')


def merge_blocks(parts, *, case_order=None):
    """Merge raw question units before any bootstrap; never merge block CIs."""
    manifests=[part['manifest'] for part in parts]
    first=manifests[0]
    for manifest in manifests[1:]:
        if any(manifest.get(field)!=first.get(field) for field in ('arms','config','target_prompt','lock_sha256','code_hashes')):
            raise ValueError('block_method_prompt_or_lock_mismatch')
        if any(manifest.get('data_hashes',{}).get(name)!=first.get('data_hashes',{}).get(name)
               for name in ('evaluation_only.json','schedules.json')):
            raise ValueError('blocks_must_share_frozen_full_evaluation_and_schedule_copy')
    cases={};original_ids=set();rows=[];scores=[];labels={};plans=[]
    for part in parts:
        manifest=part['manifest']
        for case in manifest['cases']:
            cid=case['case_id'];original=case.get('original_id',case.get('cluster_id',cid))
            if cid in cases or original in original_ids:
                raise ValueError('overlapping_original_question_blocks')
            cases[cid]=case;original_ids.add(original);labels[cid]=part['labels'][cid]
        rows.extend(part['rows']);scores.extend(part['evaluated']['rows']);plans.extend(manifest['plans'])
    case_order=list(cases) if case_order is None else case_order
    if len(case_order)!=len(set(case_order)) or set(case_order)!=set(cases):
        raise ValueError('merged_question_ids_not_exact_frozen_partition')
    merged=deepcopy(first)
    merged.update(cases=[cases[cid] for cid in case_order],plans=plans,max_calls=sum(m['max_calls'] for m in manifests))
    return rows,{'rows':scores},merged,labels


def load_completed_part(run,data,evaluated_root,manifest):
    for name,value in manifest['data_hashes'].items():
        if sha(data/name)!=value:raise ValueError('frozen_block_data_hash_mismatch')
    paths=sorted((run/'rows').glob('*.json'))
    row_hashes={str(path.resolve()):sha(path) for path in paths}
    rows=[json.loads(path.read_bytes()) for path in paths]
    for row in rows:
        tokens,cold,cached=usage_costs(row['receipt']['usage'])
        if (Decimal(row['receipt']['estimated_peak_cost_cny'])!=cold
                or cached is None or Decimal(row['receipt']['estimated_cache_aware_peak_cost_cny'])!=cached
                or any(row['receipt'].get(field)!=tokens[field] for field in
                       ('input_total_tokens','input_uncached_tokens','cache_read_tokens','cache_write_tokens','output_tokens')
                       if field in row['receipt'])):
            raise ValueError('native_usage_or_frozen_price_estimate_not_reproducible')
    labels=json.loads((data/'evaluation_only.json').read_bytes())
    evaluated={'rows':json.loads((evaluated_root/'rows.json').read_bytes()),
               'summary':json.loads((evaluated_root/'summary.json').read_bytes())}
    provenance=json.loads((evaluated_root/'provenance.json').read_bytes())
    if (Path(provenance['source_run']).resolve()!=run.resolve()
            or provenance['evaluator_sha256']!=sha(Path(__file__).with_name('evaluate_native.py'))):
        raise ValueError('strict_evaluation_source_or_evaluator_hash_mismatch')
    return {'rows':rows,'evaluated':evaluated,'labels':labels,'manifest':manifest,
        'provenance':{'source_run':str(run.resolve()),'manifest_sha256':sha(run/'manifest.json'),
            'status_sha256':sha(run/'status.json'),'row_sha256':row_hashes,
            'frozen_data_sha256':manifest['data_hashes'],'consumed_strict_evaluation':str(evaluated_root.resolve()),
            'strict_evaluation_rows_sha256':sha(evaluated_root/'rows.json'),
            'strict_evaluation_summary_sha256':sha(evaluated_root/'summary.json')}}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True,action='append',help='repeat once per disjoint block')
    p.add_argument('--data',type=Path,required=True,action='append',help='corresponding block data directory')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--evaluated',type=Path,action='append',help='repeat for existing strict evaluator outputs; default each RUN-evaluated')
    p.add_argument('--phase',choices=['development','fresh_confirmation'],default='development')
    p.add_argument('--partition',type=Path,help='required frozen block1/block2 40-question partition for fresh phase')
    a=p.parse_args()
    if a.output.exists():raise ValueError('fresh_analysis_output_required')
    if len(a.run)!=len(a.data) or (a.evaluated and len(a.evaluated)!=len(a.run)):
        raise ValueError('matching_run_data_and_evaluated_argument_counts_required')
    manifests=[]
    # ALL statuses are checked before loading any rows, score files or labels.
    for run in a.run:
        manifest=json.loads((run/'manifest.json').read_bytes())
        require_completed(manifest,json.loads((run/'status.json').read_bytes()))
        manifests.append(manifest)
    order=None;partition_hash=None
    if a.phase=='development':
        if len(manifests)!=1 or 'development' not in manifests[0]['stage'] or any(case.get('split')!='development' for case in manifests[0]['cases']):
            raise ValueError('development_mode_must_not_read_fresh40_answers')
    else:
        if len(manifests)!=2 or a.partition is None:
            raise ValueError('fresh_confirmation_requires_two_complete_blocks_and_partition')
        partition=json.loads(a.partition.read_bytes());partition_hash=sha(a.partition)
        expected=partition['blocks'];order=[cid for block in ('block1','block2') for cid in expected[block]]
        if len(set(order))!=40 or any(len(expected[name])!=20 for name in ('block1','block2')) or partition['method_or_prompt_changed'] is not False:
            raise ValueError('fixed_disjoint_twenty_plus_twenty_partition_required')
        for manifest,data in zip(manifests,a.data):
            if ([case['case_id'] for case in manifest['cases']]!=expected[data.name]
                    or manifest['max_calls']!=300 or 'fresh' not in manifest['stage']):
                raise ValueError('fresh_manifest_not_exact_locked_block')
    eval_roots=a.evaluated or [Path(str(run)+'-evaluated') for run in a.run]
    parts=[load_completed_part(run,data,ev,manifest) for run,data,ev,manifest in zip(a.run,a.data,eval_roots,manifests)]
    rows,evaluated,manifest,labels=merge_blocks(parts,case_order=order)
    result=analyze(rows,evaluated,manifest,labels)
    result['summary'].update(phase=a.phase,fresh40_answers_read=a.phase=='fresh_confirmation',
        blocks_combined_before_bootstrap=len(parts),block_intervals_averaged=False)
    if a.phase=='fresh_confirmation':
        result['gate'].update(phase='fresh_confirmation',automatic_launch_performed=False,
            next_stage_launch_recommendation=None,
            fresh_point_thresholds_and_simple_review_pass=result['gate']['worth_fresh40_native_screening'])
        result['gate']['worth_fresh40_native_screening']=None
        result['gate']['decision']=('fresh_point_thresholds_pass_with_simple_control_review' if result['gate']['fresh_point_thresholds_and_simple_review_pass']
                                  else 'fresh_point_thresholds_or_simple_control_review_fail')
    initial=[row for row in rows if row['step']==0]
    nonces=[value for plan in manifest['plans'] for value in plan['nonces'].values()]
    if len(set(nonces))!=len(nonces) or len(set(map(len,nonces)))!=1:
        raise ValueError('independent_equal_length_case_arm_nonces_required')
    plans={plan['case_id']:plan for plan in manifest['plans']}
    for row in rows:
        nonce=plans[row['case_id']]['nonces'][row['arm']]
        if row['messages'][0]['content']!='Qualification tag: '+nonce+'\n'+manifest['target_prompt']:
            raise ValueError('fixed_system_prompt_or_nonce_binding_failed')
    result['summary']['initial_cache_isolation']={'initial_calls':len(initial),
        'READ':[row['initial_cache_isolation']['initial_cache_read_tokens'] for row in initial],
        'flags':dict(Counter(row['initial_cache_isolation']['status'] for row in initial))}
    if any(sha(path)!=value for part in parts for path,value in part['provenance']['row_sha256'].items()):raise ValueError('native_rows_changed_during_analysis')
    a.output.mkdir(parents=True)
    for name,value in {**result,'strict_evaluation':evaluated,'provenance':{'blocks':[part['provenance'] for part in parts],
        'frozen_partition_sha256':partition_hash,
        'analysis_code_sha256':sha(__file__),'evaluator_code_sha256':sha(Path(__file__).with_name('evaluate_native.py'))}}.items():
        with (a.output/(name+'.json')).open('x',encoding='utf-8') as stream:json.dump(value,stream,ensure_ascii=False,indent=2,allow_nan=False)
    (a.output/'analyze_native.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print(json.dumps({'summary':result['summary'],'gate':result['gate'],'fixed_candidate_contrast':result['contrasts_against_raw'][CANDIDATE]},ensure_ascii=False))


if __name__=='__main__':main()
