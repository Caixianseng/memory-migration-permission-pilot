"""Five-arm local development screen with labels opened only after sealing.

Old24 previously exposed questions are all development here.  Fresh40 selection
is blocked unless the parent explicitly supplies --allow-fresh after freezing
the candidate. This measures local work and nonexhaustive support coverage,
not generated answer quality or actual supplier fees.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time

from .pipeline import ARMS, DEFAULT_CONFIG, RepairPipeline
from experiments.memory_module_fusion_v1.context_adapter import deliver
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, save

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CODE = [HERE/'pipeline.py', HERE/'retrieval.py', Path(__file__).resolve(),
    REPO/'experiments/memory_module_fusion_v1/context_adapter.py',
    REPO/'experiments/memory_module_fusion_v1/strong_controls.py',
    REPO/'experiments/revocation_grouping_v1/lifecycle_host.py',
    REPO/'experiments/revocation_grouping_v1/retrieval_baseline.py',
    REPO/'experiments/permission_context_v1/authorized_expansion.py']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashes():
    return {str(path.relative_to(REPO)): sha(path) for path in CODE}


def run(split, output, *, allow_fresh=False, case_count=None):
    if split not in ('development', 'fresh'):
        raise ValueError('unknown_split')
    if split == 'fresh' and not allow_fresh:
        raise ValueError('fresh_data_requires_explicit_parent_authorization')
    if output.exists():
        raise ValueError('fresh_output_required_no_silent_resume')
    data = (REPO/'experiments/memory_module_fusion_v1/data_hotpot'
            if split == 'development' else HERE/'data_fresh')
    cases = [json.loads(line) for line in (data/'cases.public.jsonl').read_text(encoding='utf-8').splitlines()]
    if len(cases) != (24 if split == 'development' else 40):
        raise ValueError('frozen_case_count_changed')
    if case_count is not None:
        if split != 'development' or type(case_count) is not int or case_count != 8:
            raise ValueError('case_count_only_fixed_first8_exposed_development')
        cases = sorted(cases, key=lambda case: case['case_id'])[:case_count]
    schedules = json.loads((data/'schedules.json').read_text(encoding='utf-8'))
    frozen = hashes()
    output.mkdir(parents=True, exist_ok=False)
    save(output/'contract.json', {'split': split, 'case_ids': [case['case_id'] for case in cases],
        'case_selection': ('first8 lexicographic previously exposed development cases' if case_count == 8
                           else 'all24 previously exposed cases for development') if split == 'development'
                          else 'all40 preselected fresh original IDs; explicit parent authorization',
        'arms': ARMS, 'config': DEFAULT_CONFIG, 'code': frozen,
        'input_hashes': {name: sha(data/name) for name in ('cases.public.jsonl', 'schedules.json')},
        'evaluation_opened_after_payload_sealing': True,
        'generation_model_calls': 0, 'local_model_calls': 0, 'network_calls': 0,
        'local_bm25_and_query_building_executed': True,
        'render_format': 'full_sources_v1_for_all_arms', 'raw_byte_cap': None,
        'internal_offset_and_dependency_witnesses_not_sent_as_context_headers': True,
        'T0_construction_retained': True, 'same_exact_authorized_view_caching_available_to_all': True,
        'selected_field_is_complete_read_dependencies': True,
        'presented_source_ids_used_for_support_metrics': True,
        'support_annotations_exhaustive': False, 'human_gold': None})
    rows, started = [], time.perf_counter()
    for case_index, case in enumerate(cases):
        for arm in ARMS:
            host = LifecycleHost(case['sources'], output/'hosts'/case['case_id']/arm)
            pipeline = RepairPipeline(case, arm, host)
            try:
                initial = pipeline.initialize()
                save(output/'initial'/f'{case["case_id"]}-{arm}.json', initial)
                for event in schedules[case['case_id']]:
                    if hashes() != frozen:
                        raise ValueError('frozen_code_changed_during_screen')
                    host.set_permissions(event['allowed'])
                    prepared, trace = pipeline.prepare()
                    messages = [{'role': 'system', 'content': 'Use only the supplied memory.'},
                        {'role': 'user', 'content': json.dumps({'memory': prepared.context,
                            'questions': [{'question_id': case['case_id'], 'question': case['question']}]})}]
                    calls = []
                    def local_commit():
                        calls.append(1)
                        return {'output': '{}', 'receipt': {'instrument_only': True,
                                                           'physical_request_count': 0}}
                    gate_started = time.perf_counter()
                    deliver(prepared, host, messages, local_commit)
                    if len(calls) != 1:
                        raise AssertionError('final_gate_did_not_commit_once')
                    presented = list(dict.fromkeys(span.source_id for span in prepared.span_witnesses))
                    if presented != trace['presented_source_ids']:
                        raise AssertionError('presented_span_ID_mismatch')
                    live = {source['source_id']: source for source in host.allowed_sources()}
                    for span in prepared.span_witnesses:
                        if span.start != 0 or span.end != len(live[span.source_id]['text']) or span.excerpt != live[span.source_id]['text']:
                            raise AssertionError('selected_original_truncated_or_modified')
                    row = {'case_id': case['case_id'], 'cluster_id': case['cluster_id'],
                        'split': split, 'arm': arm, 'time': event['time'],
                        'question': case['question'], 'allowed': event['allowed'],
                        'selected': list(prepared.source_ids), 'presented_source_ids': presented,
                        'context': prepared.context, 'context_sha256': prepared.context_sha256,
                        'source_bytes': prepared.source_bytes,
                        'context_bytes': len(prepared.context.encode('utf-8')),
                        'current_total_source_bytes': sum(len(source['text'].encode('utf-8')) for source in live.values()),
                        'source_witnesses': [asdict(witness) for witness in prepared.witnesses],
                        'trace': trace, 'host_root': str(host.root),
                        'forbidden_source_ids': sorted(set(prepared.source_ids)-set(event['allowed'])),
                        'commit_gate_passed': True, 'local_commit_gate_ms': (time.perf_counter()-gate_started)*1000,
                        'generation_model_calls': 0, 'local_model_calls': 0,
                        'human_new_permission_semantic_gold': None}
                    save(output/'sealed_payloads'/f'{len(rows):05d}.json', row)
                    rows.append(row)
            finally:
                pipeline.close()
        print(json.dumps({'cases_completed': case_index+1, 'cases': len(cases),
                          'sealed_payload_rows': len(rows)}), flush=True)
    # This checkpoint exists before the first evaluation-label decode.
    save(output/'selections_sealed.json', {'rows': len(rows), 'generation_model_calls': 0,
        'code': hashes(), 'labels_not_decoded_during_selection': True,
        'selection_payload_hashes': {path.name: sha(path) for path in sorted((output/'sealed_payloads').glob('*.json'))}})
    evaluation = json.loads((data/'evaluation_only.json').read_text(encoding='utf-8'))
    for index, row in enumerate(rows):
        required = set(evaluation[row['case_id']]['support_ids'])
        visible, allowed = set(row['presented_source_ids']), set(row['allowed'])
        row.update(all_annotated_support_currently_allowed=required <= allowed,
            complete_annotated_support_retrieved=required <= visible,
            original_annotated_support_recall=len(required & visible)/len(required) if required else None,
            current_annotated_support_recall=len(required & allowed & visible)/len(required & allowed)
                if required & allowed else None)
        save(output/'rows'/f'{index:05d}.json', row)
    aggregate = {}
    for arm in ARMS:
        subset = [row for row in rows if row['arm'] == arm]
        eligible = [row for row in subset if row['all_annotated_support_currently_allowed']]
        aggregate[arm] = {'observations': len(subset),
            'eligible_annotated_support_views': len(eligible),
            'complete_support_views': sum(row['complete_annotated_support_retrieved'] for row in eligible),
            'source_bytes': sum(row['source_bytes'] for row in subset),
            'context_bytes': sum(row['context_bytes'] for row in subset),
            'fallback_views': sum(row['trace']['fallback'] for row in subset),
            'query_reuses': sum(row['trace']['query_reused'] for row in subset),
            'exact_view_reuses': sum(row['trace']['exact_view_reuse'] for row in subset),
            'prepare_ms': sum(row['trace']['total_prepare_ms'] for row in subset),
            'initialization_ms': sum(next(row['trace']['initialization_ms'] for row in subset
                if row['case_id'] == case['case_id']) for case in cases),
            'forbidden_payloads': sum(bool(row['forbidden_source_ids']) for row in subset),
            'generation_model_calls': 0, 'local_model_calls': 0}
    by_case = {(row['case_id'], row['time'], row['arm']): row for row in rows}
    comparable = [(by_case[case['case_id'], event['time'], 'repair_rebuild'],
                   by_case[case['case_id'], event['time'], 'repair_selective'])
                  for case in cases for event in schedules[case['case_id']]]
    equal = sum(left['context'] == right['context'] and
                left['presented_source_ids'] == right['presented_source_ids']
                for left, right in comparable)
    summary = {'status': 'completed', 'split': split, 'cases': len(cases), 'rows': len(rows),
        'views_per_case': 3, 'aggregate': aggregate,
        'rebuild_selective_context_equal_pairs': equal, 'rebuild_selective_pairs': len(comparable),
        'measurement': 'authorization, local CPU work and nonexhaustive annotation coverage; not generated answer accuracy or supplier fees',
        'independent_units': 'original question; permission states are repeated observations',
        'generation_model_calls': 0, 'local_model_calls': 0,
        'local_bm25_and_query_building_executed': True, 'human_gold': None,
        'evaluation_file_sha256': sha(data/'evaluation_only.json'),
        'elapsed_seconds': time.perf_counter()-started}
    if equal != len(comparable):
        raise AssertionError('rebuild_selective_rule_mismatch')
    save(output/'summary.json', summary)
    print(json.dumps(summary, ensure_ascii=False))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', choices=('development', 'fresh'), default='development')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-fresh', action='store_true')
    parser.add_argument('--case-count', type=int, choices=(8,))
    args = parser.parse_args()
    run(args.split, args.output.absolute(), allow_fresh=args.allow_fresh, case_count=args.case_count)


if __name__ == '__main__':
    main()
