"""Fixed-seed granular revocation applicability probe; no model/API calls.

All current complete public source bodies are unchanged. Revocation fractions
0/.1/.3/.5 select source IDs independently of questions; every seed ends with
full regrant. The full-raw baseline remains uncapped. This tests context flow,
not model answers, native cost or algorithm superiority over safe retrieval.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from experiments.permission_context_v1 import authorized_expansion as expansion
from experiments.permission_context_v1.offline_probe import hierarchy_for
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost
from experiments.revocation_grouping_v1.retrieval_baseline import select

HERE = Path(__file__).resolve().parent
DATA = REPO / 'experiments/revocation_prefix_v1/data_scale64'
SEEDS = tuple(range(2026110524, 2026110532))
PERCENTAGES = (0, 10, 30, 50)
BUDGETS = (8192, 16384)
METHODS = ('child_bm25', 'authorized_bundle', 'authorized_neighbor_window',
           'naive_parent_render', 'whole_parent_gate')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)


def make_permission_events(source_ids):
    """Deliberately has no question, support, reference or result argument."""
    events = []
    for seed_index, seed in enumerate(SEEDS):
        for ordinal, percentage in enumerate(PERCENTAGES):
            sample_seed = seed * 100 + percentage
            revoked = set(random.Random(sample_seed).sample(source_ids, len(source_ids) * percentage // 100))
            events.append({'event_id': f'{seed}-revoke-{percentage:02d}', 'seed': seed,
                'trace_ordinal': ordinal, 'global_rotation_ordinal': seed_index * 5 + ordinal,
                'state_kind': f'revoke_{percentage:02d}', 'revocation_percent': percentage,
                'independent_mask_sample_seed': sample_seed, 'revoked': sorted(revoked),
                'allowed': [sid for sid in source_ids if sid not in revoked]})
        events.append({'event_id': f'{seed}-regrant-full', 'seed': seed, 'trace_ordinal': 4,
            'global_rotation_ordinal': seed_index * 5 + 4, 'state_kind': 'regrant_full',
            'revocation_percent': 0, 'independent_mask_sample_seed': None,
            'revoked': [], 'allowed': list(source_ids)})
    return events


def attach_question_rotation(events, question_spec):
    """Fixed global rotation balances every original question across mask levels."""
    result = []
    for event in events:
        ordinal = event['global_rotation_ordinal']
        persona, group = (8 if ordinal % 2 == 0 else 9), (ordinal // 2) % 4
        ids = [qid for qid in question_spec['question_rotation_groups'][group]
               if qid.startswith(f'personamem-long-{persona:03d}-')]
        if len(ids) != 4:
            raise ValueError('fixed_four_question_rotation_missing')
        result.append({**event, 'question_ids': ids, 'question_persona': persona,
                       'original_rotation_group': group})
    return result


def support_coverage(questions, allowed, selected, dispatchable):
    allowed, selected, dispatchable = set(allowed), set(selected), set(dispatchable)
    rows = []
    for question in questions:
        supports = question.get('support_sets', [question['support_source_ids']])
        legal = any(set(support) <= allowed for support in supports)
        rows.append({'question_id': question['question_id'], 'currently_legally_answerable': legal,
            'complete_support_in_hypothetical_context': any(set(s) <= selected for s in supports),
            'legal_complete_support_in_context': legal and any(set(s) <= selected & allowed for s in supports),
            'legal_complete_support_dispatchable': legal and any(set(s) <= dispatchable for s in supports)})
    return {'questions': rows, 'legally_answerable': sum(row['currently_legally_answerable'] for row in rows),
            'legal_complete_support_in_context': sum(row['legal_complete_support_in_context'] for row in rows),
            'legal_complete_support_dispatchable': sum(row['legal_complete_support_dispatchable'] for row in rows),
            'qa_model_quality_measured': False, 'human_gold': None}


def summarize(rows):
    result = {}
    for row in rows:
        key = row['strategy'] + (f"-budget-{row['max_source_bytes']}" if row['max_source_bytes'] is not None else '')
        groups = result.setdefault(key, {})
        for state in ('all_states', row['state_kind']):
            total = groups.setdefault(state, {'events': 0, 'selected_source_utf8_bytes': 0,
                'illegal_source_utf8_bytes': 0, 'illegal_context_events': 0,
                'selected_legal_source_count': 0, 'available_legal_source_count': 0,
                'selected_legal_source_utf8_bytes': 0, 'available_legal_source_utf8_bytes': 0,
                'legally_answerable_questions': 0, 'legal_complete_support_in_context': 0,
                'legal_complete_support_dispatchable': 0, 'dispatchable_context_events': 0})
            total['events'] += 1
            for target, source in (
                ('selected_source_utf8_bytes', 'source_utf8_bytes'),
                ('illegal_source_utf8_bytes', 'illegal_source_utf8_bytes'),
                ('selected_legal_source_count', 'legal_selected_source_count'),
                ('available_legal_source_count', 'current_allowed_source_count'),
                ('selected_legal_source_utf8_bytes', 'legal_selected_source_utf8_bytes'),
                ('available_legal_source_utf8_bytes', 'current_allowed_source_utf8_bytes')):
                total[target] += row[source]
            total['illegal_context_events'] += bool(row['illegal_source_ids'])
            total['dispatchable_context_events'] += row['eligible_for_final_host_delivery']
            total['legally_answerable_questions'] += row['support_coverage']['legally_answerable']
            total['legal_complete_support_in_context'] += row['support_coverage']['legal_complete_support_in_context']
            total['legal_complete_support_dispatchable'] += row['support_coverage']['legal_complete_support_dispatchable']
    for groups in result.values():
        for total in groups.values():
            total['current_allowed_source_retention'] = total['selected_legal_source_count'] / total['available_legal_source_count']
            total['current_allowed_raw_byte_retention'] = total['selected_legal_source_utf8_bytes'] / total['available_legal_source_utf8_bytes']
            count = total['legally_answerable_questions']
            total['legal_complete_support_coverage'] = total['legal_complete_support_in_context'] / count if count else None
            total['dispatchable_legal_complete_support_coverage'] = total['legal_complete_support_dispatchable'] / count if count else None
    return result


def run(case, spec, events, hierarchy, output):
    originals = {source['source_id']: source for source in case['sources']}
    source_bytes = {sid: len(source['text'].encode('utf-8')) for sid, source in originals.items()}
    parents = {}
    for sid, meta in hierarchy.items():
        parents.setdefault(meta['parent_id'], []).append(sid)
    parents = {p: sorted(ids, key=lambda sid: hierarchy[sid]['position']) for p, ids in parents.items()}
    bank = {q['question_id']: q for q in spec['questions']}
    hosts, rows, state_diagnostics = {}, [], []

    for event in events:
        seed = event['seed']
        if seed not in hosts:
            hosts[seed] = LifecycleHost(case['sources'], output / 'hosts' / str(seed))
        host = hosts[seed]
        host.set_permissions(event['allowed'])
        allowed = set(event['allowed'])
        current = host.allowed_sources()
        current_by_id = {source['source_id']: source for source in current}
        questions = [bank[qid] for qid in event['question_ids']]
        seeds = sorted({source['source_id'] for q in questions
                        for source in select(current, [q['question']], top_k=2)})
        seed_parents = list(dict.fromkeys(hierarchy[sid]['parent_id'] for sid in seeds))
        mixed = [parent for parent, ids in parents.items() if set(ids) & allowed and not set(ids) <= allowed]
        mixed_seed = [parent for parent in seed_parents if parent in mixed]
        state_diagnostics.append({**event, 'bm25_seed_ids': seeds, 'mixed_parent_ids': mixed,
                                  'mixed_seed_parent_ids': mixed_seed})

        def append(strategy, selected, budget, prepared=None, diagnostics=()):
            selected = list(selected)
            if len(set(selected)) != len(selected):
                raise AssertionError('duplicate_delivered_source')
            illegal, legal = sorted(set(selected) - allowed), sorted(set(selected) & allowed)
            eligible = strategy != 'naive_parent_render' and not illegal
            dispatchable = selected if eligible else []
            if eligible:
                host.authorize(dispatchable, 'granular-offline-final-check')
            used = sum(source_bytes[sid] for sid in selected)
            if budget is not None and used > budget:
                raise AssertionError('retrieval_source_byte_budget_exceeded')
            if prepared and used != prepared.source_bytes:
                raise AssertionError('whole_source_byte_cost_mismatch')
            row = {'event_id': event['event_id'], 'seed': seed, 'state_kind': event['state_kind'],
                'strategy': strategy, 'max_source_bytes': budget, 'bm25_seed_ids': seeds,
                'source_ids': selected, 'dispatchable_source_ids': dispatchable,
                'eligible_for_final_host_delivery': eligible,
                'illegal_source_ids': illegal, 'illegal_source_utf8_bytes': sum(source_bytes[sid] for sid in illegal),
                'source_utf8_bytes': used, 'legal_selected_source_count': len(legal),
                'legal_selected_source_utf8_bytes': sum(source_bytes[sid] for sid in legal),
                'current_allowed_source_count': len(allowed),
                'current_allowed_source_utf8_bytes': sum(source_bytes[sid] for sid in allowed),
                'current_allowed_source_retention': len(legal) / len(allowed),
                'current_allowed_raw_byte_retention': sum(source_bytes[sid] for sid in legal) / sum(source_bytes[sid] for sid in allowed),
                'mixed_parent_count': len(mixed), 'mixed_seed_parent_count': len(mixed_seed),
                'question_ids': event['question_ids'],
                'support_coverage': support_coverage(questions, allowed, selected, dispatchable),
                'diagnostics': list(diagnostics), 'model_dispatch_attempts': 0,
                'naive_is_local_only_counterfactual': strategy == 'naive_parent_render'}
            if prepared:
                row.update(prepared_epoch=prepared.prepared_epoch, context_sha256=prepared.context_sha256,
                           rendered_context_utf8_bytes=len(prepared.context.encode('utf-8')),
                           source_witnesses=[asdict(w) for w in prepared.witnesses],
                           diagnostics=list(prepared.diagnostics) + list(diagnostics))
                if strategy != 'naive_parent_render':
                    assert all(current_by_id[w.source_id]['text'] in prepared.context for w in prepared.witnesses)
            rows.append(row)

        append('raw_all_full_reference', list(current_by_id), None)
        for budget in BUDGETS:
            for strategy, implementation in (
                ('child_bm25', 'child_only'), ('authorized_bundle', 'authorized_bundle'),
                ('authorized_neighbor_window', 'authorized_neighbor_window'),
                ('naive_parent_render', 'naive_parent_render')):
                # Concatenation adds no bytes beyond complete source bodies;
                # naive and safe arms therefore share the exact same byte cap.
                renderer = lambda parent: ''.join(originals[sid]['text'] for sid in parents[parent])
                prepared = expansion.prepare_context(current, seeds, hierarchy,
                    strategy=implementation, authorize=host.authorize, get_epoch=lambda: host.revision,
                    max_source_bytes=budget, neighbor_window=2,
                    diagnostic_parent_renderer=renderer, allow_unsafe_diagnostic=strategy == 'naive_parent_render')
                if strategy == 'naive_parent_render' and prepared.can_dispatch:
                    raise AssertionError('naive_diagnostic_must_not_dispatch')
                append(strategy, prepared.source_ids, budget, prepared)
            gate_ids, gate_bytes, gate_diagnostics = [], 0, []
            for parent in seed_parents:
                members = parents[parent]
                if not set(members) <= allowed:
                    gate_diagnostics.append({'kind': 'whole_parent_dropped_for_any_denied_child',
                        'parent_id': parent, 'denied_child_ids': sorted(set(members) - allowed),
                        'legal_children_also_dropped': sorted(set(members) & allowed)})
                    continue
                cost = sum(source_bytes[sid] for sid in members)
                if gate_bytes + cost > budget:
                    gate_diagnostics.append({'kind': 'whole_parent_budget_skip', 'parent_id': parent})
                    continue
                gate_ids.extend(members)
                gate_bytes += cost
            gate = expansion.prepare_context(current, gate_ids, hierarchy, strategy='child_only',
                authorize=host.authorize, get_epoch=lambda: host.revision, max_source_bytes=budget)
            append('whole_parent_gate', gate.source_ids, budget, gate, gate_diagnostics)
    save(output / 'retrieval_rows.json', rows)
    save(output / 'permission_state_diagnostics.json', state_diagnostics)
    return rows, state_diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    case_raw = (DATA / 'cases.jsonl').read_bytes()
    case = json.loads(case_raw)
    # Draw every permission mask before loading any question/evidence labels.
    events = make_permission_events([source['source_id'] for source in case['sources']])
    questions_raw = (DATA / 'questions.json').read_bytes()
    spec = json.loads(questions_raw)[case['case_id']]
    events = attach_question_rotation(events, spec)
    hierarchy = hierarchy_for(case)
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    contract = {'schema': 'granular-permission-context-offline-probe-v1',
        'case_id': case['case_id'], 'independent_content_clusters': 2, 'policy_seeds': SEEDS,
        'percentages': PERCENTAGES, 'ratio_semantics': 'revoked_fraction; current_allowed=64_minus_independent_sample',
        'sample_rule': 'Random(seed*100+percentage).sample(source_IDs,64*percentage//100)',
        'regrant_full_after_each_seed': True, 'original_source_body_count': 64,
        'parent_unit': 'four complete original exchanges from one persona; no old parent blob in safe strategies',
        'question_rule': 'global ordinal=seed_index*5+event_index; even uses persona8, odd persona9; original group=(ordinal//2)%4; always four QIDs',
        'budgets_original_source_utf8_bytes': BUDGETS, 'neighbor_window': 2,
        'methods': METHODS, 'full_raw_reference_uncapped': True,
        'whole_parent_gate_rule': 'drop whole parent if any child denied; otherwise whole-parent byte budget admission',
        'naive_parent_rule': 'local unchecked full-parent rendering only, can_dispatch=False in all states',
        'all_masks_frozen_independently_of_questions_or_gold': True,
        'source_files_sha256': {'cases.jsonl': sha(case_raw), 'questions.json': sha(questions_raw)},
        'code_sha256': {str(path.relative_to(REPO)): sha(path.read_bytes()) for path in (
            Path(__file__), Path(expansion.__file__), HERE / 'offline_probe.py',
            REPO / 'experiments/revocation_grouping_v1/retrieval_baseline.py')},
        'model_calls': 0, 'embedding_calls': 0, 'network_requests': 0,
        'model_QA_quality_or_supplier_cost_measured': False, 'human_gold': None}
    save(output / 'frozen_contract.json', contract)
    save(output / 'frozen_events.json', events)
    rows, diagnostics = run(case, spec, events, hierarchy, output)
    aggregates = summarize(rows)
    mixed_summary = {'events': len(events), 'events_with_mixed_parents': sum(bool(r['mixed_parent_ids']) for r in diagnostics),
        'events_with_mixed_seed_parents': sum(bool(r['mixed_seed_parent_ids']) for r in diagnostics),
        'mixed_parent_instances': sum(len(r['mixed_parent_ids']) for r in diagnostics),
        'source_parent_instances': len(events) * 16}
    summary = {'schema': contract['schema'], 'status': 'completed', 'mixed_permissions': mixed_summary,
        'policy_seeds': len(SEEDS), 'independent_content_clusters': 2, 'retrieval_rows': len(rows),
        'question_observations_per_method_budget': len(events) * 4, 'methods': aggregates,
        'model_calls': 0, 'embedding_calls': 0, 'network_requests': 0,
        'scope': 'permission-flow applicability and evidence coverage only; repeated masks are not new independent stories',
        'no_unique_utility_advantage_claim_from_whole_parent_gate_comparison': True}
    save(output / 'summary.json', summary)
    print(json.dumps({'mixed_permissions': mixed_summary, 'policy_seeds': len(SEEDS),
        'retrieval_rows': len(rows), 'all_state_totals': {key: values['all_states'] for key, values in aggregates.items()},
        'model_calls': 0}, ensure_ascii=False))


if __name__ == '__main__':
    main()
