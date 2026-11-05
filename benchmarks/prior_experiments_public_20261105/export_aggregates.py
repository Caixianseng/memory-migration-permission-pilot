"""Whitelist projections of local aggregate reports; never calls a model.

The result reports are intentionally not distributed. This exporter requires
the original local aggregate files, while verify.py checks the public bundle.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DROP = object()
KEY = re.compile(r'^[A-Za-z][A-Za-z0-9_.+%\-]{0,110}$')
DECIMAL = re.compile(r'^-?\d+(?:\.\d+)?$')
ARM = re.compile(r'^[a-z][a-z0-9_\-+]{0,80}$')


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False)+'\n').encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(relative):
    path = ROOT/relative
    raw = path.read_bytes()
    return json.loads(raw), {'repository_relative_source': relative,
                             'source_file_sha256': sha(raw)}


def numeric(value):
    """Only numeric/bool/null leaves; decimal strings preserve fee precision."""
    if value is None or type(value) in (bool, int, float):
        return value
    if isinstance(value, str):
        return value if DECIMAL.fullmatch(value) else DROP
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not KEY.fullmatch(key):
                continue
            projected = numeric(item)
            if projected is not DROP:
                result[key] = projected
        return result
    if isinstance(value, list):
        items = [numeric(item) for item in value]
        return items if all(item is not DROP for item in items) else DROP
    return DROP


def fields(value, names):
    result = {}
    for name in names.split():
        if name not in value:
            continue
        item = numeric(value[name])
        if item is not DROP:
            result[name] = item
    return result


def envelope(batch, kind, sources, measurements, units):
    return {'schema': 'prior-experiment-aggregate-public-v1', 'batch': batch,
            'evidence_kind': kind, 'source_files': sources,
            'source_scope': 'whitelist projection of aggregate local reports; not an independent native-execution re-audit',
            'model_calls_by_exporter': 0, 'independent_unit': units,
            'actual_supplier_bill_cny': None,
            'planned_request_count_is_actual_success_count': False,
            'raw_answers_original_data_native_logs_and_local_paths_included': False,
            'measurements': measurements}


def export():
    outputs = {}
    name = 'results/permission_context_v1/granular-20261105-v1/summary.json'
    v, source = load(name)
    outputs['permission_context.json'] = envelope('permission-context-granular',
        'offline_permission_and_evidence_coverage', [source],
        {'status': v['status'], **fields(v, 'policy_seeds independent_content_clusters retrieval_rows question_observations_per_method_budget model_calls embedding_calls network_requests mixed_permissions methods no_unique_utility_advantage_claim_from_whole_parent_gate_comparison')},
        'content cluster; permission masks and question observations are repeated measures')

    base = 'results/memory_module_fusion_v1/native-comparison-v1/'
    v, source = load(base+'summary.json')
    table, ts = load(base+'table.json')
    measures = {'status': v['status'], **fields(v, 'full_two_run_lifecycle_complete strict_audit_status_counts rows arms calls_per_arm independent_question_clusters primary_eligible_views_per_arm first_calls_retained cross_run_nonces_distinct all_initial_cache_read_tokens_zero total_estimated_cold_peak_cost_cny total_estimated_native_cache_aware_peak_cost_cny cost_is_supplier_bill bootstrap sequential_runs_are_not_a_single_interleaved_19_arm_randomized_run analysis_model_api_calls')}
    measures['method_metrics'] = []
    for row in table:
        assert ARM.fullmatch(row['arm'])
        measures['method_metrics'].append({'arm': row['arm'], **fields(row, 'calls independent_questions primary_eligible_views official_primary_view_em official_primary_view_f1 official_primary_question_macro_em official_primary_question_macro_f1 eligible_complete_annotated_support_views estimated_cold_peak_cny estimated_native_cache_aware_peak_cny native_tokens initialization_ms_total prepare_ms_total local_initialization_plus_prepare_ms_total target_wall_ms_total native_latency_seconds_total all_first_and_regrant_calls_in_costs cost_is_supplier_bill')})
    outputs['memory_module_fusion.json'] = envelope('fusion-native-comparison',
        'native_answer_aggregate_with_lexical_metrics', [source, ts], measures,
        'question cluster; the two source runs are sequential rather than one randomized interleaved experiment')

    v, source = load('results/revocation_evidence_repair_v1/fresh40-native-combined-20261105-v1-analysis/summary.json')
    measures = {'status': v['status'], **fields(v, 'independent_question_clusters all_planned_requests costs_include_every_initial_delivery_revocation_and_regrant_request quality_uses_all_questions_and_eligible_views_within_question bootstrap local_query_construction_is_CPU_only_no_supplier_generation local_timers_are_wall_time_not_process_CPU_utilization cost_is_supplier_bill official_gold_or_aliases_changed analysis_model_calls blocks_combined_before_bootstrap block_intervals_averaged')}
    measures['actual_native_success_count_not_separately_asserted_by_exporter'] = None
    measures['arms'] = {}
    for arm, row in v['arms'].items():
        assert ARM.fullmatch(arm)
        measures['arms'][arm] = fields(row, 'independent_questions primary_views all_cost_requests question_macro_f1 question_macro_em lifecycle_estimated_cold_peak_cny lifecycle_estimated_native_cache_aware_peak_cny local_initial_build_ms local_prepare_ms local_initial_build_plus_prepare_ms target_wall_ms fallback_views reuse_by_view_type initial_local_query_builds generation_model_calls_for_query_or_initial_build output_tokens input_MISS input_READ input_WRITE input_TOTAL')
    outputs['evidence_repair_fresh40.json'] = envelope('evidence-repair-fresh40-combined',
        'native_answer_aggregate_with_lexical_metrics', [source], measures,
        'question cluster; the source report combines both blocks before its bootstrap')

    v, source = load('results/revocation_prefix_v1/quotient-native64-20261105-v1/summary.json')
    analysis, als = load('results/revocation_prefix_v1/quotient-native64-20261105-v1/analysis.json')
    measures = {'status': v['status'], **fields(v, 'instrument_only model_calls_attempted automatic_retry cost_is_supplier_bill human_gold checkpoint full_lifecycle_cost_complete isolation_review_required arm_totals physical_totals')}
    measures['aggregate_analysis'] = fields(analysis, 'run_count unique_case_count independent_content_cluster_count all_runs_comparison_eligible cost_is_supplier_bill qa_is_semantic_or_human_score human_gold aggregate_arms')
    outputs['prefix_quotient64.json'] = envelope('prefix-quotient-scale64',
        'native_scale_bridge_development', [source, als], measures,
        'one combined scale-bridge case derived from two existing content clusters; requests are repeated measures')

    for batch in ['development-20261104-v1','reserved-20261104-v2','long-workload-20261104-v2']:
        base = 'results/revocation_grouping_v1/'+batch+'/'
        v, source = load(base+'independent_evaluation.json')
        summary, ss = load(base+'summary.json')
        ids = sorted({row['case_id'] for row in v['method_case_results']})
        measures = {'status': v['run_status'], 'independent_story_clusters': len(ids),
            **fields(v, 'instrument_only human_gold audit_ok failure_retained native_input_binding_verified_count saved_physical_calls native_pending_or_failed_jobs physical_successful_peak_cny physical_successful_cache_aware_peak_cny physical_source_token_totals physical_target_token_totals derived_cost_correction_applied cost_is_supplier_bill'),
            'planned_physical_jobs_from_summary': summary.get('physical_jobs'), 'method_cluster_metrics': []}
        for row in v['method_case_results']:
            assert ARM.fullmatch(row['method'])
            measures['method_cluster_metrics'].append({'cluster_index': ids.index(row['case_id'])+1,
                'method': row['method'], **fields(row, 'source_jobs_attributed target_jobs full_lifecycle_peak_cny observed_receipted_peak_cny full_lifecycle_cost_complete full_lifecycle_cache_aware_peak_cny full_lifecycle_cache_aware_offpeak_cny source_token_totals target_token_totals source_input_total_tokens target_input_total_tokens derived_cost_correction_applied audit_ok format_ok_count legally_answerable_question_count legal_nonunknown_answers required_unknown_count required_unknown_correct required_unknown_correct_is_auto_marker_diagnostic auto_unknown_marker_correct_count AI_control_correct_count AI_control_count ai_supported_answer_completeness human_supported_answer_completeness human_gold')})
        outputs['grouping_'+batch+'.json'] = envelope('grouping-'+batch,
            'native_development_or_exploratory_check_with_AI_references', [source, ss], measures,
            'persona/story cluster; requests, sources and question positions are repeated measures; human_gold remains null')

    for name, body in outputs.items():
        path = HERE/name; raw = encode(body)
        if path.exists() and path.read_bytes() != raw:
            raise ValueError('published_projection_changed:'+name)
        if not path.exists():
            path.write_bytes(raw)
    manifest = {'schema': 'prior-experiment-public-manifest-v1',
        'export_type': 'aggregate_projection_only', 'model_calls_by_exporter': 0,
        'source_reports_are_not_distributed': True,
        'independent_native_reaudit_possible_from_this_bundle_alone': False,
        'files': {name: {'bytes': len(encode(body)), 'sha256': sha(encode(body))}
                  for name, body in outputs.items()}}
    path = HERE/'manifest.json'; raw = encode(manifest)
    if path.exists() and path.read_bytes() != raw:
        raise ValueError('published_projection_manifest_changed')
    if not path.exists():
        path.write_bytes(raw)
    return manifest


if __name__ == '__main__':
    manifest = export()
    print(json.dumps({'public_aggregate_files': len(manifest['files']),
                      'model_calls': 0, 'independent_native_reaudit': False}))
