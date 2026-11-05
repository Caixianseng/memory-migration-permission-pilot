"""Strict native audit plus answer/evidence evaluation for repair packets.

Selected is the complete influence dependency set used by the existing audit.
Evidence coverage instead uses ONLY actual original span witnesses displayed to
the recipient. No model call occurs; label files enter only this evaluator.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from experiments.memory_module_fusion_v1.eval_fusion import evaluate_rows, _load_rows
from experiments.revocation_grouping_v1.lifecycle_host import save


def presentation(row):
    packet = row.get('prepared') or row.get('trace', {}).get('prepared')
    if packet is None:
        raise ValueError('prepared_original_spans_required')
    ids = list(dict.fromkeys(span['source_id'] for span in packet['span_witnesses']))
    if row.get('presented_source_ids', ids) != ids:
        raise ValueError('presented_ids_not_bound_to_actual_spans')
    if set(ids) - set(packet['source_ids']):
        raise ValueError('presented_span_missing_complete_dependency')
    return ids


def evaluate(run_root, evaluation_path, cases_path, schedules_path):
    rows = _load_rows(run_root)
    cases = [json.loads(line) for line in Path(cases_path).read_bytes().splitlines() if line.strip()]
    labels = json.loads(Path(evaluation_path).read_bytes())
    schedules = json.loads(Path(schedules_path).read_bytes())
    result = evaluate_rows(rows, labels, cases=cases, schedules=schedules, artifacts_root=run_root)
    by_cell = {(r['case_id'], r['arm'], r['time']): r for r in rows}
    for scored in result['rows']:
        row = by_cell[(scored['case_id'], scored['arm'], scored['time'])]
        shown = set(presentation(row))
        support = set(labels[scored['case_id']]['support_ids'])
        scored['presented_source_ids'] = sorted(shown)
        scored['complete_annotated_support_retrieved'] = support <= shown
        current_support = support & set(row['allowed'])
        scored['current_annotated_support_recall'] = len(shown & current_support)/len(current_support) if current_support else None
        scored['full_annotation_recall'] = len(shown & support)/len(support) if support else None
    for arm, aggregate in result['summary']['arms'].items():
        arm_rows = [r for r in result['rows'] if r['arm'] == arm]
        eligible = [r for r in arm_rows if r['primary_eligible']]
        aggregate['primary_complete_annotated_support_views'] = sum(r['complete_annotated_support_retrieved'] for r in eligible)
        original = [r for r in rows if r['arm'] == arm]
        aggregate['fallback_views'] = sum(bool(r.get('trace', {}).get('fallback')) for r in original)
        aggregate['query_reused_views'] = sum(bool(r.get('trace', {}).get('query_reused')) for r in original)
        aggregate['local_prepare_ms_total'] = sum(r.get('trace', {}).get('total_prepare_ms', 0) for r in original)
        aggregate['initial_build_ms_total'] = sum(r.get('initial_build_trace', {}).get('initialization_ms', 0) for r in original)
        aggregate['target_wall_ms_total'] = sum(r.get('target_wall_ms', 0) for r in original)
        aggregate['presented_source_bytes_total'] = sum(r.get('source_bytes', 0) for r in original)
    paired = []
    by = {(r['case_id'], r['arm'], r['time']): r for r in result['rows']}
    for arm in sorted(result['summary']['arms']):
        if arm == 'raw':
            continue
        diffs = defaultdict(list)
        for row in result['rows']:
            if row['arm'] == arm and row['primary_eligible']:
                raw = by.get((row['case_id'], 'raw', row['time']))
                if raw:
                    diffs[row['case_id']].append(row['guarded_answer']['f1']-raw['guarded_answer']['f1'])
        units = {qid: sum(values)/len(values) for qid, values in diffs.items()}
        paired.append({'arm': arm, 'reference': 'raw', 'independent_question_units': len(units),
                       'question_mean_f1_differences': units,
                       'mean_question_f1_difference': sum(units.values())/len(units) if units else None})
    result['paired_contrasts'] = paired
    result['summary'].update({'evidence_coverage_uses_presented_spans_not_dependency_ids': True,
        'all_initial_local_build_costs_recorded': True,
        'query_builder_is_local_no_paid_source_model': True,
        'human_gold_for_changed_permissions': None,
        'audit_status_counts': dict(Counter(r['audit_status'] for r in result['rows']))})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--data', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise ValueError('fresh_evaluation_output_required')
    result = evaluate(a.run, a.data/'evaluation_only.json', a.data/'cases.public.jsonl', a.data/'schedules.json')
    a.output.mkdir(parents=True)
    for name, value in result.items():
        save(a.output/(name+'.json'), value)
    save(a.output/'provenance.json', {'evaluator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'source_run': str(a.run.resolve()), 'generation_calls': 0})
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
