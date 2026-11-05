"""Offline development probe: learn a source-prefix forest across recipient views.

All initial deliveries/priming are charged. No prefetch, LLM, network or QA is
used. This tests a cost proxy on two predeclared ACL application generators,
not real cache billing or semantic quality. No existing planner is modified.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import random
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from experiments.revocation_prefix_v1.planner import plan_layout

FAMILIES = ('department_review_round', 'service_role_rotation')
SEEDS = tuple(range(17001, 17013))
BASELINES = ('original', 'static_joint_dp', 'conditional_static', 'cache_greedy', 'causal_two_step')
CANDIDATES = ('learned_view_trie', 'full_hot_else_view_trie')
READ_PRICE_RATIO = .02
PER_CALL_FIXED_COST_BYTES = 2048
CONTRACT = {
    'schema': 'recipient-view-trie-development-proxy-v1', 'families': FAMILIES,
    'development_seeds': SEEDS, 'source_count': 8, 'training_acl_rounds': 12,
    'evaluation_delivery_rounds': 2, 'baselines': BASELINES, 'candidates': CANDIDATES,
    'source_length_rule': 'seeded integer multiples of 128 bytes, from 3072 through 10112',
    'training': 'independent previous ACL audit history; does not prime supplier cache',
    'candidate': 'minimum-byte prefix forest over previously observed recipient permission views; no future sequence',
    'provider_model': 'ideal persisted full-source prefix trie, 2% cached read price',
    'cost_proxy': 'uncached source bytes + .02*cached source bytes + 2048 fixed cost bytes per real delivery',
    'initial_and_all_priming_deliveries_counted': True, 'extra_prefetch_calls': 0,
    'human_gold': None, 'real_model_requests': 0, 'real_token_or_billing_claim': False,
    'all_materials_are_development_only': True,
    'continuation_gate': 'at least 20% pooled cost reduction vs cache_greedy in both families; report all seeds and strongest baseline',
}


def common_bytes(left, right, lengths):
    total = 0
    for a, b in zip(left, right):
        if a != b:
            break
        total += lengths[a]
    return total


def cache_hit(order, cache, lengths):
    return max((common_bytes(order, old, lengths) for old in cache), default=0)


def optimal_view_forest(views, lengths):
    """Exact minimum distinct prefix-edge bytes for <= 5 known views.

    A view may terminate at an internal trie node. Every root branch containing
    a pivot view chooses one common first source; enumerate the other views
    joining that branch. The complement forms other roots. This optimizes a
    view inventory learned from ACL history, not the evaluation delivery order.
    """
    ids = tuple(sorted(lengths))
    views = tuple(sorted(set(tuple(sorted(view)) for view in views)))
    if len(views) > 5:
        raise ValueError('bounded_probe_supports_at_most_five_unique_historical_views')
    bit = {sid: 1 << i for i, sid in enumerate(ids)}
    masks = tuple(sum(bit[sid] for sid in view) for view in views)

    @lru_cache(None)
    def solve(state):
        empty = tuple((index, ()) for index, mask in state if mask == 0)
        live = tuple((index, mask) for index, mask in state if mask)
        if not live:
            return 0, empty
        if empty:
            cost, routes = solve(live)
            return cost, tuple(sorted(empty + routes))
        pivot, pivot_mask = live[0]
        best = None
        for sid in ids:
            source_bit = bit[sid]
            if not pivot_mask & source_bit:
                continue
            eligible = tuple(index for index, mask in live[1:] if mask & source_bit)
            for subset in range(1 << len(eligible)):
                branch_ids = {pivot} | {index for i, index in enumerate(eligible) if subset & (1 << i)}
                branch = tuple((index, mask ^ source_bit) for index, mask in live if index in branch_ids)
                remainder = tuple((index, mask) for index, mask in live if index not in branch_ids)
                branch_cost, branch_routes = solve(branch)
                other_cost, other_routes = solve(remainder)
                routes = tuple(sorted(tuple((index, (sid,) + route) for index, route in branch_routes) + other_routes))
                choice = lengths[sid] + branch_cost + other_cost, routes
                if best is None or choice < best:
                    best = choice
        return best

    cost, routes = solve(tuple(enumerate(masks)))
    mapping = {frozenset(views[index]): route for index, route in routes}
    for view, route in mapping.items():
        if len(route) != len(view) or set(route) != set(view):
            raise AssertionError('forest_dropped_or_duplicated_legal_source')
    return mapping, {'optimal_distinct_prefix_edge_bytes': cost, 'dp_states': solve.cache_info().currsize,
                     'historical_distinct_views': len(views), 'exact_only_for_known_inventory_trie_proxy': True}


def generated_workload(family, seed):
    rng = random.Random(seed)
    ids = tuple(f'S{i:02d}' for i in range(1, 9))
    shuffled = list(ids)
    rng.shuffle(shuffled)
    lengths = {sid: rng.randrange(24, 80) * 128 for sid in ids}
    if family == 'department_review_round':
        # Four recipient roles: two shared policy records plus overlapping
        # finance/engineering/legal collaboration records. A business review
        # round delivers each role's complete authorized view exactly once.
        templates = ((0, 1, 2, 4, 6), (0, 1, 2, 3, 7),
                     (0, 1, 3, 4, 5), (0, 1, 5, 6, 7))
    elif family == 'service_role_rotation':
        # Five adjacent service roles on a cyclic eight-record responsibility
        # ring; each role sees five complete records, with no global common core.
        templates = tuple(tuple((start + offset) % 8 for offset in range(5)) for start in (0, 1, 3, 4, 6))
    else:
        raise ValueError('unregistered_generator_family')
    views = [tuple(sorted(shuffled[index] for index in template)) for template in templates]
    train_rng, evaluation_rng = random.Random(seed ^ 0xA53F), random.Random(seed ^ 0xC429)

    def rounds(generator, count):
        result = []
        for _ in range(count):
            roles = list(range(len(views)))
            generator.shuffle(roles)
            result.extend(views[role] for role in roles)
        return result

    training_states = rounds(train_rng, CONTRACT['training_acl_rounds'])
    history = [{'before': list(before), 'after': list(after)}
               for before, after in zip(training_states, training_states[1:])]
    events = rounds(evaluation_rng, CONTRACT['evaluation_delivery_rounds'])
    return lengths, history, events


def evaluate_workload(family, seed):
    lengths, initial_history, events = generated_workload(family, seed)
    # Synthetic byte-length carriers only, never represented as real documents.
    sources = {sid: {'source_id': sid, 'text': 'x' * size, 'allow': True} for sid, size in lengths.items()}
    historical_views = [row[key] for row in initial_history for key in ('before', 'after')]
    forest, forest_diagnostics = optimal_view_forest(historical_views, lengths)
    results = {}
    for method in BASELINES + CANDIDATES:
        cache, history, rows = [], list(initial_history), []
        for index, current in enumerate(events):
            if index:
                history.append({'before': list(events[index - 1]), 'after': list(current)})
            allowed = [sources[sid] for sid in sources if sid in current]
            if method in CANDIDATES:
                route = forest.get(frozenset(current))
                if route is None:
                    route = plan_layout(allowed, history, cache, {
                        'method': 'cache_greedy', 'known_source_lengths_bytes': lengths})['ordered_source_ids']
                if method == 'full_hot_else_view_trie':
                    full = [old for old in cache if len(old) == len(current) and set(old) == set(current)]
                    if full:
                        route = min(full)
            else:
                route = plan_layout(allowed, history, cache, {
                    'method': method, 'known_source_lengths_bytes': lengths,
                    'risk_cut_threshold': .75, 'next_cost_weight': 1.0})['ordered_source_ids']
            route = tuple(route)
            if len(route) != len(current) or set(route) != set(current):
                raise AssertionError('not_an_exact_current_lawful_permutation')
            hit, total = cache_hit(route, cache, lengths), sum(lengths[sid] for sid in current)
            cost = total - hit + READ_PRICE_RATIO * hit + PER_CALL_FIXED_COST_BYTES
            rows.append({'event': index, 'allowed': current, 'order': route,
                         'hit_source_bytes_PROXY': hit, 'miss_source_bytes_PROXY': total - hit,
                         'charged_cost_proxy_bytes': cost})
            cache.append(route)
        results[method] = {'full_lifecycle_cost_proxy_bytes': sum(row['charged_cost_proxy_bytes'] for row in rows),
                           'delivery_calls_including_initial_primes': len(rows), 'rows': rows}
    return {'family': family, 'seed': seed, 'lengths': lengths,
            'training_history_sha256': sha(initial_history), 'evaluation_events_sha256': sha(events),
            'forest_diagnostics': forest_diagnostics, 'methods': results}


def sha(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def summarize(rows):
    summary = {}
    for family in FAMILIES:
        selected = [row for row in rows if row['family'] == family]
        costs = {method: sum(row['methods'][method]['full_lifecycle_cost_proxy_bytes'] for row in selected)
                 for method in BASELINES + CANDIDATES}
        best_baseline = min(BASELINES, key=lambda method: (costs[method], method))
        summary[family] = {'development_seed_count': len(selected), 'pooled_cost_proxy_bytes': costs,
                           'strongest_pooled_baseline': best_baseline,
                           'candidates': {method: {
                               'reduction_vs_cache_greedy': 1 - costs[method] / costs['cache_greedy'],
                               'reduction_vs_strongest_baseline': 1 - costs[method] / costs[best_baseline],
                               'seeds_better_than_cache_greedy': sum(row['methods'][method]['full_lifecycle_cost_proxy_bytes'] < row['methods']['cache_greedy']['full_lifecycle_cost_proxy_bytes'] for row in selected),
                               'per_seed_reduction_vs_cache_greedy': [1 - row['methods'][method]['full_lifecycle_cost_proxy_bytes'] / row['methods']['cache_greedy']['full_lifecycle_cost_proxy_bytes'] for row in selected]}
                               for method in CANDIDATES}}
    summary['gate_passed'] = any(all(summary[family]['candidates'][method]['reduction_vs_cache_greedy'] >= .2 for family in FAMILIES) for method in CANDIDATES)
    summary['real_model_requests'] = 0
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    contract = {**CONTRACT, 'code_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'planner_sha256': hashlib.sha256((Path(__file__).with_name('planner.py')).read_bytes()).hexdigest()}
    (output / 'frozen_contract.json').write_text(json.dumps(contract, indent=2), encoding='utf-8')
    print(json.dumps({'frozen_contract_sha256': sha(contract), 'real_model_requests': 0}), flush=True)
    started, rows = time.monotonic(), []
    for family in FAMILIES:
        for seed in SEEDS:
            result = evaluate_workload(family, seed)
            rows.append(result)
            (output / f'{family}-{seed}.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps({family: summarize(rows)[family] if len(rows) == len(FAMILIES) * len(SEEDS) else {
            'completed_seeds': len(SEEDS), 'elapsed_seconds': time.monotonic() - started}}), flush=True)
    summary = summarize(rows)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
