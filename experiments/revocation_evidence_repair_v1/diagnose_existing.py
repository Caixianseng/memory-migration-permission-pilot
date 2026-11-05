"""Frozen-record failure diagnosis, with no SDK client or model calls.

Annotations are a finite reference witness, not an exhaustive answerability
oracle. Two-AI consensus is a supplementary review signal, never human truth.
Official gold/aliases/EM/F1 and all original records remain unchanged.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from decimal import Decimal
import hashlib
from itertools import combinations
import json
from pathlib import Path
import re

from experiments.memory_module_fusion_v1.eval_fusion import evaluate_rows, normalize_answer

REPO = Path(__file__).resolve().parents[2]
FUSION = REPO/'results/memory_module_fusion_v1'
DATA = REPO/'experiments/memory_module_fusion_v1/data_hotpot'
REPAIR = REPO/'results/revocation_evidence_repair_v1'
OUTPUT = REPAIR/'existing-diagnosis-v1'
FOCUS = ('raw', 'h1p1r1', 'fusion_bridge', 'authorized_parent_bm25_top4')
WATCH = {}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


def read(path):
    path = Path(path).resolve()
    WATCH[str(path)] = sha(path)
    return json.loads(path.read_bytes())


def cell(row):
    return row['case_id'], row['arm'], row['time']


def load_run(root, labels, schedules, cases):
    manifest, status = read(root/'manifest.json'), read(root/'status.json')
    files = sorted((root/'rows').glob('*.json'))
    rows = [read(file) for file in files]
    if (status['status'] != 'completed' or len(rows) != manifest['max_calls']
            or status['completed'] != len(rows) or any(row['status'] != 'completed' for row in rows)):
        raise ValueError('complete_original_native_run_required')
    evaluated = evaluate_rows(rows, labels, cases=cases, schedules=schedules, artifacts_root=REPO/'results')
    if any(row['audit_status'] != 'verified' for row in evaluated['rows']):
        raise ValueError('strict_actual_payload_host_native_audit_must_pass')
    for row in rows:
        job = Path(row['receipt']['record_path'])
        for artifact in (job/'actual_request.json', job/'guard.json', Path(row['host_root'])/'events.jsonl'):
            WATCH[str(artifact.resolve())] = sha(artifact)
    return rows, {cell(row): file.resolve() for file, row in zip(files, rows)}, manifest, evaluated


def review_signal(review, row):
    if review is None:
        return {'available': False, 'is_human_gold': False}
    pair = [review['review_a'], review['review_b']]
    allowed, selected = set(row['allowed']), set(row['selected'])
    proofs = []
    for value in pair:
        ids = value.get('support_source_ids', [])
        proofs.append({'source_ids': ids, 'all_ids_currently_allowed': set(ids) <= allowed,
                       'all_ids_delivered': set(ids) <= selected})
    return {'available': True, 'item_id': review['item_id'], 'assessment_agreement': review['assessment_agreement'],
        'both_assess_supported_correct': all(r['answer_assessment'] == 'supported_correct' for r in pair),
        'both_assess_incorrect': all(r['answer_assessment'] == 'incorrect' for r in pair),
        'both_say_delivered_answerable': all(r['delivered_answerability'] == 'yes' for r in pair),
        'both_say_delivered_not_answerable': all(r['delivered_answerability'] == 'no' for r in pair),
        'reviewer_a': pair[0], 'reviewer_b': pair[1], 'suggested_witness_ids_authorization_check': proofs,
        'is_human_gold': False, 'relabels_official_metric': False,
        'review_source_ids_are_proposals_not_verified_logical_proofs': True}


def diagnose(rows, scored, labels, reviews, row_paths, cases, run_name):
    scored = {cell(row): row for row in scored}
    registry = {case['case_id']: {s['source_id']: s for s in case['sources']} for case in cases}
    raw = {(row['case_id'], row['time']): row for row in rows if row['arm'] == 'raw'}
    result = []
    for row in rows:
        key = cell(row)
        value, gold = scored[key], labels[row['case_id']]
        required, allowed, selected = set(gold['support_ids']), set(row['allowed']), set(row['selected'])
        legal = required <= allowed
        complete = required <= selected
        exact = value['answer']['em'] == 1.
        unknown = normalize_answer(value['prediction']) in {'unknown', 'noanswer'}
        signal = review_signal(reviews.get(key), row)
        form_review = not exact and signal.get('both_assess_supported_correct', False)
        if not legal:
            condition = 'reference_support_not_all_currently_allowed'
            priority = 'policy_limited_unresolved_do_not_force_answer'
        elif exact:
            condition = 'official_exact_match'
            priority = 'no_reference_mismatch_trigger'
        elif complete:
            condition = 'complete_annotated_evidence_but_official_reference_mismatch'
            priority = 'reference_or_answer_form_review_first' if form_review else 'reading_or_reasoning_diagnostic_first'
        else:
            condition = 'annotation_selection_gap_and_official_reference_mismatch'
            priority = ('reference_or_answer_form_review_first' if form_review else
                        'reading_or_reasoning_diagnostic_first' if signal.get('both_say_delivered_answerable') else
                        'retrieve_more_current_legal_evidence_first')
        raw_row = raw[row['case_id'], row['time']]
        raw_score = scored[cell(raw_row)]
        raw_review = review_signal(reviews.get(cell(raw_row)), raw_row)
        sources = registry[row['case_id']]
        legal_missing = sorted((required-selected) & allowed)
        result.append({'run': run_name, 'row_path': str(row_paths[key]),
            'row_sha256': WATCH[str(row_paths[key])], 'case_id': key[0], 'arm': key[1], 'time': key[2],
            'question': next(case['question'] for case in cases if case['case_id'] == key[0]),
            'original_reference_answer_evaluation_only': gold['answer'], 'prediction': value['prediction'],
            'official_answer': value['answer'], 'unknown_or_noanswer': unknown,
            'strict_delivery_audit_status': value['audit_status'], 'allowed_source_ids': row['allowed'],
            'selected_source_ids': row['selected'], 'reference_annotated_support_ids': gold['support_ids'],
            'all_annotated_support_currently_legal': legal, 'all_annotated_support_selected': complete,
            'reference_support_denied_ids': sorted(required-allowed),
            'reference_support_omitted_ids': sorted(required-selected),
            'currently_legal_missing_reference_witness_bindings': [
                {'source_id': sid, 'version': sources[sid].get('version', 1),
                 'source_sha256': hashlib.sha256(sources[sid]['text'].encode('utf-8')).hexdigest()}
                for sid in legal_missing],
            'base_observation': condition,
            'hypotheses': {'evidence_omission_compatible_not_causally_established': legal and not complete and not exact,
                'complete_reference_evidence_abstention': legal and complete and unknown,
                'complete_reference_evidence_other_reference_mismatch': legal and complete and not unknown and not exact,
                'complete_reference_evidence_error_ai_corroborated_not_human_truth':
                    legal and complete and signal.get('both_assess_incorrect', False),
                'reference_alias_format_or_semantics_pending_human_review': form_review,
                'withdrawn_reference_support_not_equivalent_to_unanswerability': not legal},
            'suggested_next_stage': priority, 'supplementary_blind_review': signal,
            'raw_same_question_same_policy_view': {'row_path': str(row_paths[cell(raw_row)]),
                'prediction': raw_score['prediction'], 'official_answer': raw_score['answer'],
                'official_exact_match': raw_score['answer']['em'] == 1.,
                'unknown_or_noanswer': normalize_answer(raw_score['prediction']) in {'unknown', 'noanswer'},
                'ai_both_supported_correct_supplement_only': raw_review.get('both_assess_supported_correct'),
                'not_an_oracle_and_no_human_correctness_claim': True}})
    return result


def summarize(rows, arms):
    output = {}
    for arm in arms:
        subset = [row for row in rows if row['arm'] == arm]
        eligible = [row for row in subset if row['all_annotated_support_currently_legal']]
        by_question = defaultdict(list)
        for row in subset:
            by_question[row['case_id']].append(row)
        output[arm] = {'independent_questions': len(by_question), 'repeated_views': len(subset),
            'reference_legal_views': len(eligible),
            'reference_legal_selected_complete_views': sum(r['all_annotated_support_selected'] for r in eligible),
            'unknown_reference_legal_views': sum(r['unknown_or_noanswer'] for r in eligible),
            'hypothesis_view_counts_overlap': {name: sum(r['hypotheses'][name] for r in subset) for name in subset[0]['hypotheses']},
            'priority_view_counts': dict(Counter(r['suggested_next_stage'] for r in subset)),
            'per_question': [{'case_id': cid, 'policy_times': [r['time'] for r in group],
                'observations': [{'time': r['time'], 'reference_legal': r['all_annotated_support_currently_legal'],
                    'reference_complete': r['all_annotated_support_selected'], 'prediction': r['prediction'],
                    'official_answer': r['official_answer'], 'unknown': r['unknown_or_noanswer'],
                    'base_observation': r['base_observation'], 'next_stage': r['suggested_next_stage']}
                    for r in sorted(group, key=lambda r: r['time'])]} for cid, group in sorted(by_question.items())]}
    return output


def differences(a, b, path=''):
    if type(a) is not type(b):
        return [path+':type']
    if isinstance(a, dict):
        return [value for key in sorted(set(a)|set(b)) for value in
                ([path+'/'+key+':missing'] if key not in a or key not in b else differences(a[key], b[key], path+'/'+key))]
    if isinstance(a, list):
        return [path+':length'] if len(a) != len(b) else [value for i, (x, y) in enumerate(zip(a, b)) for value in differences(x, y, path+'/'+str(i))]
    return [] if a == b else [path]


def request_core(row):
    job = Path(row['receipt']['record_path'])
    request, guard = read(job/'actual_request.json'), read(job/'guard.json')
    core = deepcopy(request)
    core.pop('sessionId', None)
    runtime_hash = guard['requests'][0]['runtime_context_sha256']
    kept, runtime_indices = [], []
    for index, message in enumerate(core['messages']):
        message.pop('id', None)
        content = message.get('content', [])
        is_runtime = message.get('role') == 'user' and len(content) == 1 and isinstance(content[0].get('text'), str) and hashlib.sha256(content[0]['text'].encode('utf-8')).hexdigest() == runtime_hash
        if is_runtime:
            runtime_indices.append(index)
        else:
            kept.append(message)
    if len(runtime_indices) != 1:
        raise ValueError('single_guard_bound_runtime_message_required')
    core['messages'] = kept
    return request, canonical_sha(core), runtime_indices


def repeated_context_audit(rows, scored):
    grouped, output = defaultdict(list), []
    scores = {cell(row): row for row in scored}
    for row in rows:
        grouped[row['case_id'], row['arm'], row['context_sha256']].append(row)
    for (cid, arm, context_hash), group in grouped.items():
        if len(group) < 2:
            continue
        group = sorted(group, key=lambda row: row['time'])
        native = [request_core(row) for row in group]
        pairs = []
        for i, j in combinations(range(len(group)), 2):
            paths = differences(native[i][0], native[j][0])
            pairs.append({'times': [group[i]['time'], group[j]['time']], 'actual_request_differing_paths': paths,
                'business_messages_identical': group[i]['messages'] == group[j]['messages'],
                'native_core_equal_after_removing_session_message_ids_and_guard_bound_runtime': native[i][1] == native[j][1]})
        output.append({'case_id': cid, 'arm': arm, 'context_sha256': context_hash,
            'selected_source_ids': group[0]['selected'],
            'business_messages_sha256': [row['receipt']['business_messages_sha256'] for row in group],
            'dispatch_sha256': [row['receipt']['dispatch_sha256'] for row in group],
            'observations': [{'time': row['time'], 'prediction': scores[cell(row)]['prediction'],
                              'official_answer': scores[cell(row)]['answer']} for row in group],
            'distinct_normalized_predictions': sorted({normalize_answer(scores[cell(row)]['prediction']) for row in group}),
            'pairwise_actual_request_comparisons': pairs,
            'sampling_controls_exposed_in_native_requests': [{key: req[key] for key in ('temperature', 'topP', 'seed') if key in req} for req, _, _ in native],
            'full_native_request_bytes_identical_claimed': False,
            'temperature_or_stochastic_cause_identified': False,
            'interpretation': 'Business evidence can be identical while outputs vary; fresh native runtime/session metadata also varies. Temperature/internal sampling are not identified by this comparison.'})
    return output


def main():
    if OUTPUT.exists():
        raise ValueError('fresh_diagnosis_output_required_no_original_overwrite')
    labels, schedules = read(DATA/'evaluation_only.json'), read(DATA/'schedules.json')
    main_manifest = read(FUSION/'hotpot-native-20261105-v2/manifest.json')
    cases = main_manifest['cases']
    old_a, paths_a, _, eval_a = load_run(FUSION/'hotpot-native-20261105-v2', labels, schedules, cases)
    old_b, paths_b, _, eval_b = load_run(FUSION/'hotpot-native-strong-20261105-v1', labels, schedules, cases)
    old, paths = old_a+old_b, {**paths_a, **paths_b}
    cached = read(FUSION/'native-comparison-v1/rows_evaluated.json')
    fresh = {cell(row): row for row in eval_a['rows']+eval_b['rows']}
    if len(old) != 228 or len(fresh) != 228 or len(cached) != 228:
        raise ValueError('all_228_original_rows_required')
    for row in cached:
        now = fresh[cell(row)]
        if any(row[key] != now[key] for key in ('prediction', 'answer', 'primary_eligible', 'audit_status', 'complete_annotated_support_retrieved')):
            raise ValueError('cached_safety_or_official_score_not_reproducible')
    consensus = read(FUSION/'semantic-blind-20261105-v1/consensus_rows.json')['rows']
    read(FUSION/'semantic-blind-20261105-v1/consensus_summary.json')
    reviews = {cell(row): row for row in consensus}
    if len(reviews) != len(consensus) or set(reviews) != set(paths):
        raise ValueError('complete_unique_consensus_join_required')
    for key, value in reviews.items():
        if Path(value['row']).resolve() != paths[key]:
            raise ValueError('consensus_original_row_path_binding_failed')
    diagnosed = diagnose(old, list(fresh.values()), labels, reviews, paths, cases, 'original_228')
    focus = [row for row in diagnosed if row['arm'] in FOCUS]
    new_root = REPAIR/'native-reference-diagnostic-20261105-v1'
    new, new_paths, new_manifest, new_eval = load_run(new_root, labels, schedules, cases)
    cached_new = read(REPAIR/'native-reference-diagnostic-20261105-v1-evaluated/rows.json')
    if {cell(row): row['answer'] for row in cached_new} != {cell(row): row['answer'] for row in new_eval['rows']}:
        raise ValueError('reference_diagnostic_official_scores_not_reproducible')
    expected_new = {(plan['case_id'], arm, entry['event']['time']) for plan in new_manifest['plans'] for entry in plan['events'] for arm in entry['arms']}
    if len(new) != 34 or set(map(cell, new)) != expected_new:
        raise ValueError('complete_34_call_predeclared_reference_diagnostic_required')
    for row in new:
        if row['arm'] == 'diagnostic_reference_only' and (set(row['selected']) != set(labels[row['case_id']]['support_ids']) or not set(row['selected']) <= set(row['allowed'])):
            raise ValueError('reference_arm_must_contain_exact_current_legal_original_support_ids')
    reference_diagnosed = diagnose(new, new_eval['rows'], labels, {}, new_paths, cases, 'new_reference_34')
    repeated = repeated_context_audit(new, new_eval['rows'])
    reference = {'scope': 'label-assisted diagnostic, not a production retrieval policy or a new content replication',
        'official_aggregate': new_eval['summary'], 'rows': reference_diagnosed,
        'expected_plan_cells': 34, 'executed_plan_cells': len(new),
        'two_reference_cells_intentionally_skipped_for_policy': new_eval['summary']['observed_matrix_missing_cells'],
        'all_34_initial_and_repeated_calls_in_lifecycle_cost': True,
        'estimated_cold_peak_cny': str(sum((Decimal(row['receipt']['estimated_peak_cost_cny']) for row in new), Decimal(0))),
        'estimated_native_cache_aware_peak_cny': str(sum((Decimal(row['receipt']['estimated_cache_aware_peak_cost_cny']) for row in new), Decimal(0))),
        'cost_is_supplier_bill': False, 'blind_review_available_for_this_new_run': False}
    recommendations = {'priority': 'Complete the single disclosed reader-development comparison on exposed questions before freezing a 40-new-question study; avoid adaptive repeated reader tuning on the future 40.',
        'retrieval': 'Use Q1/Q2 annotation gaps to develop authorized entity/relation evidence completion. Reference IDs guide diagnostics only, never an unlabelled production selector.',
        'reading': 'Even a complete finite reference witness does not guarantee a correct response; compare title/entity attributes and relations, unit conversions and Boolean counterexamples using a common frozen reader prompt across arms.',
        'reference_review': 'Keep original official EM/F1; name variants, plural variants and the Q4 Boolean/reference mismatch require independent reference review. AI agreement is not human gold.',
        'forty_question_next_step': 'Freeze prompt, method-selection rule, independent question IDs, policies, complete raw and strong simple controls, endpoints, cost accounting and semantic-review rules before new model calls; retain all outcomes.',
        'diagnostic_reference_API': {'inputs': ['host', 'case_id', 'reference_source_ids_evaluation_only', 'expected_epoch'],
            'implementation': 'current=host.allowed_sources(); require every reference ID in current; prepare_sources(host,ids,current_sources=current,expected_epoch=epoch); build public question-only messages; context_adapter.deliver(prepared,host,messages,call)',
            'missing_or_stale_dependency': 'fail closed / record diagnostic skipped; do not fill from old parent or revoked body',
            'body_binding': 'reconstruct complete original bodies from current host, bind version/hash and full dependencies, recheck at commit',
            'never_send': ['reference answer', 'gold support label text', 'AI review reasons or claims', 'old summary of unknown dependencies'],
            'reference_only_ids_are_label_assisted_not_production': True,
            'review_suggested_source_IDs_are_not_accepted_as_new_gold': True}}
    summary = {'status': 'completed', 'old_rows': 228, 'new_reference_rows': 34, 'strict_verified_rows': 262,
        'independent_questions': 4, 'additional_requests_do_not_create_new_question_clusters': True,
        'focus_arms': list(FOCUS), 'focus_views': len(focus), 'focus_primary_reference_legal_views': sum(r['all_annotated_support_currently_legal'] for r in focus),
        'annotations_are_not_exhaustive': True, 'ai_reviews_are_supplementary_not_truth': True,
        'official_gold_aliases_and_metrics_unchanged': True, 'new_model_calls_by_diagnosis': 0,
        'counts_are_descriptive_repeated_views_not_independent_replicates': True,
        'reference_diagnostic_question_macro_f1': {arm: value['primary_question_macro_f1'] for arm, value in new_eval['summary']['arms'].items()}}
    # Pure decision-boundary checks, not extra experiments or requests.
    q2 = [group for group in repeated if group['arm'] == 'diagnostic_reference_only' and group['case_id'].endswith('82a3e46a')]
    if len(q2) != 1 or len(q2[0]['distinct_normalized_predictions']) != 2 or not all(pair['business_messages_identical'] and pair['native_core_equal_after_removing_session_message_ids_and_guard_bound_runtime'] for pair in q2[0]['pairwise_actual_request_comparisons']):
        raise ValueError('Q2_same_business_evidence_variation_claim_not_supported')
    if any(sha(path) != digest for path, digest in WATCH.items()):
        raise ValueError('original_artifacts_changed_during_read_only_diagnosis')
    OUTPUT.mkdir(parents=True)
    for name, value in {'summary': summary, 'old_228_diagnosed_rows': diagnosed, 'focus_rows': focus,
        'focus_question_summary': summarize(focus, FOCUS), 'reference_diagnostic': reference,
        'same_context_native_request_audit': repeated, 'recommendations': recommendations,
        'provenance': {'input_file_sha256': WATCH, 'diagnosis_code_sha256': sha(__file__),
            'all_read_inputs_unchanged_at_finish': True, 'safety_audit_recomputed': True,
            'blind_review_join': 'original row path and case/arm/time; no new semantic judgment or human labels'}}.items():
        (OUTPUT/(name+'.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    (OUTPUT/'diagnose_existing_snapshot.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps({'summary': summary, 'focus_counts': {arm: {key: value for key, value in info.items() if key != 'per_question'} for arm, info in summarize(focus, FOCUS).items()},
        'output': str(OUTPUT)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
