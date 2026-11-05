"""Freeze and run local expansion fixture plus six public retrieval-only ticks.

No SDK/model/embedding calls. Source-byte budgets are retrieval parameters;
full authorized raw text and the original uncapped BM25 union stay intact as
reference baselines. Outcomes measure supplied evidence coverage, not QA quality.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from experiments.permission_context_v1 import authorized_expansion as expansion
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost
from experiments.revocation_grouping_v1.lifecycle_runner import target_messages
from experiments.revocation_grouping_v1.retrieval_baseline import select

HERE = Path(__file__).resolve().parent
DATA = REPO / 'experiments/revocation_prefix_v1/data_scale64'
SAFE = ('child_only', 'authorized_bundle', 'authorized_neighbor_window')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)


def record(prepared):
    return asdict(prepared)


def fixture_probe(fixture, output):
    host = LifecycleHost(fixture['sources'], output / 'fixture/host')
    host.set_permissions(fixture['allowed'])
    current, results, callback_calls = host.allowed_sources(), {}, []

    def old_parent(parent):
        return '\n\n'.join(source['text'] for source in fixture['sources']
                           if fixture['hierarchy'][source['source_id']]['parent_id'] == parent)

    for strategy in expansion.STRATEGIES:
        prepared = expansion.prepare_context(current, fixture['seed_ids'], fixture['hierarchy'],
            strategy=strategy, authorize=host.authorize, get_epoch=lambda: host.revision,
            max_source_bytes=fixture['max_source_bytes'], neighbor_window=fixture['neighbor_window'],
            diagnostic_parent_renderer=old_parent, allow_unsafe_diagnostic=strategy == 'naive_parent_render')
        row = record(prepared)
        row['contains_revoked_canary'] = fixture['canary'] in prepared.context
        row['unavailable_source_ids_claimed'] = sorted(set(prepared.source_ids) - set(fixture['allowed']))
        row['complete_fixture_support_available'] = set(fixture['needed_complete_support_set']) <= set(prepared.source_ids)
        if strategy == 'naive_parent_render':
            messages = target_messages(prepared.context, [{'question_id': 'fixture-q', 'question': 'Which project and deadline?'}],
                                       {'target_prompt': 'Use current evidence only.'})
            try:
                expansion.deliver(prepared, host, messages, lambda: callback_calls.append('forbidden'))
            except expansion.ExpansionError as error:
                row['dispatch_blocked_code'] = error.code
            else:
                raise AssertionError('unsafe_diagnostic_was_dispatchable')
        results[strategy] = row
    fresh = expansion.prepare_context(host.allowed_sources(), fixture['seed_ids'], fixture['hierarchy'],
        strategy='authorized_bundle', authorize=host.authorize, get_epoch=lambda: host.revision,
        max_source_bytes=fixture['max_source_bytes'])
    host.set_permissions(fixture['allowed'])
    try:
        expansion.deliver(fresh, host, target_messages(fresh.context, [], {'target_prompt': 'Fixture only.'}),
                          lambda: callback_calls.append('stale'))
    except expansion.ExpansionError as error:
        results['epoch_change'] = {'blocked_code': error.code, 'diagnostics': error.diagnostics}
    else:
        raise AssertionError('stale_context_was_dispatchable')
    assert not callback_calls
    assert not results['authorized_bundle']['contains_revoked_canary']
    assert results['naive_parent_render']['contains_revoked_canary']
    assert results['authorized_neighbor_window']['source_ids'] == results['authorized_bundle']['source_ids']
    save(output / 'fixture/results.json', results)
    return results


def hierarchy_for(case):
    result = {}
    for persona in case['persona_ids']:
        sources = [source for source in case['sources'] if source['persona_id'] == persona]
        for i, source in enumerate(sources):
            result[source['source_id']] = {
                'parent_id': f'persona-{persona:03d}-original-four-exchange-block-{i // 4 + 1:02d}',
                'position': i % 4,
                'prev_id': sources[i - 1]['source_id'] if i else None,
                'next_id': sources[i + 1]['source_id'] if i + 1 < len(sources) else None}
    return result


def frozen_schedule(case, questions):
    ids = [source['source_id'] for source in case['sources']]
    denied_groups = ((), (0,), (0, 7), (6, 7), (6, 7), ())
    rows = []
    for tick, denied in enumerate(denied_groups):
        allowed = [sid for i, sid in enumerate(ids) if i // 8 not in denied]
        persona, group = (8 if tick % 2 == 0 else 9), (tick // 2) % 4
        original_rotation = questions['question_rotation_groups'][group]
        qids = [qid for qid in original_rotation if qid.startswith(f'personamem-long-{persona:03d}-')]
        assert len(qids) == 4
        rows.append({'time': tick, 'allowed': allowed, 'denied_eight_source_groups': list(denied),
                     'question_ids': qids, 'persona': persona, 'original_rotation_group': group})
    return rows


def coverage(questions, allowed, selected):
    allowed, selected = set(allowed), set(selected)
    rows = []
    for question in questions:
        support_sets = question.get('support_sets', [question['support_source_ids']])
        legal = any(set(support) <= allowed for support in support_sets)
        delivered = any(set(support) <= selected for support in support_sets)
        rows.append({'question_id': question['question_id'], 'currently_legally_answerable': legal,
                     'complete_support_delivered': delivered,
                     'legal_complete_support_covered': legal and delivered})
    return {'questions': rows, 'legally_answerable': sum(row['currently_legally_answerable'] for row in rows),
            'legal_complete_support_covered': sum(row['legal_complete_support_covered'] for row in rows),
            'qa_semantic_quality_measured': False, 'human_gold': None}


def public_probe(case, question_spec, schedule, hierarchy, budgets, output):
    host = LifecycleHost(case['sources'], output / 'public/host')
    bank = {q['question_id']: q for q in question_spec['questions']}
    rows = []
    for event in schedule:
        host.set_permissions(event['allowed'])
        current = host.allowed_sources()
        by_id = {source['source_id']: source for source in current}
        questions = [bank[qid] for qid in event['question_ids']]
        seed_ids = sorted({source['source_id'] for question in questions
                           for source in select(current, [question['question']], top_k=2)})
        seed_parents = {hierarchy[sid]['parent_id'] for sid in seed_ids}
        legal_parent_children = {sid for sid in by_id if hierarchy[sid]['parent_id'] in seed_parents}
        parent_members = {}
        for sid, info in hierarchy.items():
            parent_members.setdefault(info['parent_id'], set()).add(sid)
        mixed_parents = [p for p, members in parent_members.items()
                         if members & set(event['allowed']) and not members <= set(event['allowed'])]

        def append(strategy, selected, source_bytes, budget=None, prepared=None):
            illegal = sorted(set(selected) - set(event['allowed']))
            assert not illegal
            row = {'time': event['time'], 'strategy': strategy, 'max_source_bytes': budget,
                   'allowed': event['allowed'], 'bm25_seed_ids': seed_ids, 'source_ids': list(selected),
                   'source_count': len(selected), 'source_utf8_bytes': source_bytes,
                   'forbidden_source_ids': illegal, 'question_ids': event['question_ids'],
                   'legal_seed_parent_child_count': len(legal_parent_children),
                   'legal_seed_parent_children_delivered': len(set(selected) & legal_parent_children),
                   'mixed_permission_parent_count': len(mixed_parents),
                   'evidence_coverage': coverage(questions, event['allowed'], selected)}
            if prepared:
                row['prepared'] = record(prepared)
            rows.append(row)

        # Complete original full-memory baseline: no artificial retrieval cap.
        append('raw_legal_full_reference', list(by_id), sum(len(s['text'].encode()) for s in current))
        append('bm25_top2_union_original_uncapped', seed_ids,
               sum(len(by_id[sid]['text'].encode()) for sid in seed_ids))
        for budget in budgets:
            for strategy in SAFE:
                prepared = expansion.prepare_context(current, seed_ids, hierarchy, strategy=strategy,
                    authorize=host.authorize, get_epoch=lambda: host.revision,
                    max_source_bytes=budget, neighbor_window=2)
                assert all(by_id[w.source_id]['text'] in prepared.context for w in prepared.witnesses)
                append(strategy, prepared.source_ids, prepared.source_bytes, budget, prepared)
    save(output / 'public/retrieval_rows.json', rows)
    totals = {}
    for row in rows:
        key = row['strategy'] + ('-budget-' + str(row['max_source_bytes']) if row['max_source_bytes'] is not None else '')
        total = totals.setdefault(key, {'ticks': 0, 'source_utf8_bytes': 0, 'legally_answerable_questions': 0,
                                       'legal_complete_support_covered': 0, 'forbidden_sources': 0,
                                       'mixed_permission_parent_ticks': 0})
        total['ticks'] += 1
        total['source_utf8_bytes'] += row['source_utf8_bytes']
        total['legally_answerable_questions'] += row['evidence_coverage']['legally_answerable']
        total['legal_complete_support_covered'] += row['evidence_coverage']['legal_complete_support_covered']
        total['forbidden_sources'] += len(row['forbidden_source_ids'])
        total['mixed_permission_parent_ticks'] += bool(row['mixed_permission_parent_count'])
    for total in totals.values():
        total['legal_complete_support_coverage'] = total['legal_complete_support_covered'] / total['legally_answerable_questions'] if total['legally_answerable_questions'] else None
    return totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--budgets', default='8192,16384')
    args = parser.parse_args()
    budgets = [int(value) for value in args.budgets.split(',')]
    if len(set(budgets)) != len(budgets) or any(value < 0 for value in budgets):
        raise ValueError('unique_nonnegative_retrieval_budgets_required')
    inputs = {path: path.read_bytes() for path in (
        DATA / 'cases.jsonl', DATA / 'questions.json', DATA / 'data_validation.json', HERE / 'fixture_contract.json')}
    case = json.loads(inputs[DATA / 'cases.jsonl'])
    questions = json.loads(inputs[DATA / 'questions.json'])[case['case_id']]
    validation = json.loads(inputs[DATA / 'data_validation.json'])
    assert sha(inputs[DATA / 'cases.jsonl']) == validation['cases_sha256']
    assert sha(inputs[DATA / 'questions.json']) == validation['questions_sha256']
    fixture = json.loads(inputs[HERE / 'fixture_contract.json'])
    hierarchy, schedule = hierarchy_for(case), frozen_schedule(case, questions)
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    contract = {'schema': 'permission-context-expansion-offline-probe-v1',
        'scope': 'dataflow safety fixture and exposed public retrieval-only evidence coverage; no answer generation',
        'source_input_sha256': {str(path.relative_to(REPO)): sha(raw) for path, raw in inputs.items()},
        'code_sha256': {str(path.relative_to(REPO)): sha(path.read_bytes()) for path in (
            Path(__file__), Path(expansion.__file__), REPO / 'experiments/revocation_grouping_v1/retrieval_baseline.py')},
        'case_id': case['case_id'], 'independent_content_clusters': 2, 'source_count': 64,
        'hierarchy': hierarchy, 'schedule': schedule, 'retrieval_source_byte_budgets': budgets,
        'same_seed_ids_and_budget_for_safe_strategies': True, 'neighbor_window': 2,
        'raw_full_reference_not_capped_or_truncated': True,
        'existing_bm25_top2_union_uncapped_reference_retained': True,
        'not_a_model_context_window_restriction': True, 'human_gold': None,
        'no_answer_reference_or_support_ids_given_to_retrieval': True,
        'model_calls': 0, 'embedding_calls': 0, 'network_requests': 0}
    save(output / 'frozen_contract.json', contract)
    fixture_result = fixture_probe(fixture, output)
    public = public_probe(case, questions, schedule, hierarchy, budgets, output)
    summary = {'schema': contract['schema'], 'status': 'completed', 'fixture': {
        'naive_contains_revoked_canary': fixture_result['naive_parent_render']['contains_revoked_canary'],
        'naive_dispatch_blocked': fixture_result['naive_parent_render']['dispatch_blocked_code'],
        'child_only_complete_support': fixture_result['child_only']['complete_fixture_support_available'],
        'authorized_bundle_complete_support': fixture_result['authorized_bundle']['complete_fixture_support_available'],
        'authorized_neighbor_window_matches_bundle': fixture_result['authorized_neighbor_window']['source_ids'] == fixture_result['authorized_bundle']['source_ids'],
        'stale_epoch_blocked': fixture_result['epoch_change']['blocked_code']},
        'public_case': public, 'human_gold': None, 'model_calls': 0,
        'claims': {'actual_QA_quality_or_native_cost_measured': False,
                   'public_policies_align_with_parent_blocks_if_mixed_parent_ticks_zero': True,
                   'fixture_does_not_prove_advantage_over_authorized_neighbor_window': True}}
    save(output / 'summary.json', summary)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == '__main__':
    main()
