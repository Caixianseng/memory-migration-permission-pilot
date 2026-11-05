"""Fair exact-subset-DP versus exhaustive permutation optimizer benchmark.

Both optimizers reuse one identical ExactProblem delta table and cache trie.
The exhaustive inner loop skips redundant per-permutation input validation and
metric dictionary creation. A separately timed reference scores EVERY order by
direct current LCP / forecast retained prefixes, without using the delta table.
No model, network or supplier-cost claim is involved.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import statistics
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from experiments.revocation_prefix_v1 import exact_planner

SIZES = (5, 6, 7, 8)
SEEDS = (202611051701, 202611051702)
TIMING_REPEATS = 3
CONTRACT = {
    'schema': 'exact-prefix-optimizer-fair-enumeration-benchmark-v1',
    'current_source_counts': SIZES, 'seeds': SEEDS, 'timing_repeats': TIMING_REPEATS,
    'cache_order_count': 'uniform integer 3..8', 'forecast_distinct_state_count': 'uniform integer 8..16',
    'known_universe': 'n current legal IDs plus two currently forbidden but previously known IDs',
    'byte_lengths': 'fixed seeded positive integer multiples of 64 from 64..6400',
    'state_masses': 'fixed seeded positive integer 1..9, normalized by identical ExactProblem',
    'current_first_cache': 'a fixed seeded random proper current-source prefix; no hidden priming',
    'weight': 1.0, 'initial_cache_is_fixed_optimizer_input_not_a_lifecycle_cost_result': True,
    'shared_preprocessing': 'one identical ExactProblem delta table and current cache trie',
    'fair_enumeration': 'all n! permutations, compact trusted-valid-order scalar score using shared delta/trie',
    'independent_validation': 'every permutation also scored by direct old-cache LCP and forecast legal-prefix formula; timed separately',
    'end_to_end_comparison': 'the same measured shared preprocessing is charged to both optimizer totals',
    'real_model_requests': 0, 'supplier_cost_or_global_novelty_claim': False,
}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sha(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)


def make_case(n, seed):
    rng = random.Random(seed + n * 100003)
    ids = tuple(f'S{i:02d}' for i in range(1, n + 1))
    universe = ids + ('OLD_ONLY_1', 'OLD_ONLY_2')
    known = {sid: rng.randrange(1, 101) * 64 for sid in universe}
    wanted_cache = rng.randint(3, 8)
    cache = [tuple(rng.sample(ids, rng.randint(1, n - 1)))]
    while len(cache) < wanted_cache:
        order = tuple(rng.sample(universe, rng.randint(2, len(universe))))
        if order not in cache:
            cache.append(order)
    wanted_states, states, seen = rng.randint(8, 16), [], set()
    while len(states) < wanted_states:
        state = tuple(sid for sid in universe if rng.random() < .65)
        if state not in seen:
            seen.add(state)
            states.append((state, rng.randint(1, 9)))
    return {'case_id': f'n{n}-seed{seed}', 'n': n, 'seed': seed,
            'lengths': {sid: known[sid] for sid in ids}, 'known_lengths': known,
            'cache': cache, 'states': states, 'weight': 1.0}


def exhaustive_shared(problem):
    """All n! valid orders; same precomputed objective, no validation overhead."""
    ids, index, delta, trie = problem.ids, problem.index, problem.delta, problem.trie
    lengths, weight, base = problem.lengths, problem.weight, problem.old_next_hit
    best_key, best_order, visited = None, None, 0
    for order in itertools.permutations(ids):
        mask, gain, node, hit, active = 0, 0.0, 0, 0, True
        for sid in order:
            bit = index[sid]
            gain += delta[mask][bit]
            mask |= 1 << bit
            if active:
                child = trie[node]['children'].get(sid)
                if child is None:
                    active = False
                else:
                    hit += lengths[sid]
                    node = child
        objective = hit + weight * (base + gain)
        key = (-objective, -hit, order)
        if best_key is None or key < best_key:
            best_key, best_order = key, order
        visited += 1
    return {'ordered_source_ids': list(best_order), 'expectedobj': -best_key[0],
            'current_hit_bytes': -best_key[1], 'permutations_evaluated': visited}


def independent_workspace(case):
    """Direct reference data built from raw instance, not ExactProblem tables."""
    total_mass = sum(mass for _, mass in case['states'])
    workspace = []
    for state, mass in case['states']:
        state = frozenset(state)
        old_hit = 0
        for cached in case['cache']:
            retained = 0
            for sid in cached:
                if sid not in state:
                    break
                retained += case['known_lengths'][sid]
            old_hit = max(old_hit, retained)
        workspace.append((state, mass / total_mass, old_hit))
    return workspace


def independent_score(order, case, workspace):
    now_hit = 0
    for cached in case['cache']:
        hit = 0
        for actual, old in zip(order, cached):
            if actual != old:
                break
            hit += case['lengths'][actual]
        now_hit = max(now_hit, hit)
    next_hit = 0.0
    for state, probability, old_hit in workspace:
        retained = 0
        for sid in order:
            if sid not in state:
                break
            retained += case['lengths'][sid]
        next_hit += probability * max(old_hit, retained)
    return now_hit + case['weight'] * next_hit, now_hit


def check_every_order_independently(problem, case):
    started = time.perf_counter()
    workspace = independent_workspace(case)
    workspace_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    best, checked = None, 0
    max_error = 0.0
    for order in itertools.permutations(problem.ids):
        objective, hit = independent_score(order, case, workspace)
        shared = problem.score_order(order)
        error = abs(shared['expectedobj'] - objective)
        max_error = max(max_error, error)
        if not math.isclose(shared['expectedobj'], objective, rel_tol=1e-12, abs_tol=1e-7):
            raise AssertionError('shared_delta_and_independent_direct_score_disagree')
        key = (-objective, -hit, order)
        if best is None or key < best:
            best = key
        checked += 1
    return {'permutations_independently_checked': checked, 'independent_best_objective': -best[0],
            'max_absolute_objective_error': max_error,
            'reference_workspace_ms': workspace_ms,
            'reference_plus_public_score_validation_ms': (time.perf_counter() - started) * 1000,
            'validation_work_excluded_from_fair_speedup': True}


def benchmark(case):
    started = time.perf_counter()
    problem = exact_planner.ExactProblem(case['lengths'], case['states'], case['cache'],
                                         case['weight'], case['known_lengths'])
    preprocessing_ms = (time.perf_counter() - started) * 1000
    dp_times, exhaustive_times, dp, brute = [], [], None, None
    # Alternate optimizer timing order, using the same object throughout.
    for repeat in range(TIMING_REPEATS):
        funcs = ('dp', 'exhaustive') if repeat % 2 == 0 else ('exhaustive', 'dp')
        for method in funcs:
            started = time.perf_counter()
            if method == 'dp':
                dp = problem.solve()
                dp_times.append((time.perf_counter() - started) * 1000)
            else:
                brute = exhaustive_shared(problem)
                exhaustive_times.append((time.perf_counter() - started) * 1000)
    validation = check_every_order_independently(problem, case)
    if brute['permutations_evaluated'] != math.factorial(case['n']):
        raise AssertionError('not_all_permutations_evaluated')
    for other in (brute['expectedobj'], validation['independent_best_objective']):
        if not math.isclose(dp['expectedobj'], other, rel_tol=1e-12, abs_tol=1e-7):
            raise AssertionError('exact_dp_and_exhaustive_optimum_disagree')
    dp_ms, exhaustive_ms = statistics.median(dp_times), statistics.median(exhaustive_times)
    return {'case_id': case['case_id'], 'n': case['n'], 'seed': case['seed'],
            'forecast_states_M': len(problem.states), 'cache_orders_K': len(problem.cache),
            'known_universe_N': len(problem.known), 'legal_cache_trie_nodes_T': len(problem.trie),
            'subset_states': problem.size, 'delta_state_checks': problem.delta_state_checks,
            'preprocessing_shared_ms': preprocessing_ms,
            'dp_optimizer_ms_samples': dp_times, 'exhaustive_optimizer_ms_samples': exhaustive_times,
            'dp_optimizer_median_ms': dp_ms, 'exhaustive_optimizer_median_ms': exhaustive_ms,
            'optimization_only_speedup': exhaustive_ms / dp_ms,
            'dp_end_to_end_ms': preprocessing_ms + dp_ms,
            'exhaustive_end_to_end_ms': preprocessing_ms + exhaustive_ms,
            'shared_preprocessing_end_to_end_speedup': (preprocessing_ms + exhaustive_ms) / (preprocessing_ms + dp_ms),
            'exact_result': dp, 'exhaustive_result': brute, 'independent_validation': validation,
            'optimality_matches_all_permutations': True, 'real_model_requests': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    cases = [make_case(n, seed) for n in SIZES for seed in SEEDS]
    contract = {**CONTRACT, 'benchmark_code_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'solver_code_sha256': hashlib.sha256(Path(exact_planner.__file__).read_bytes()).hexdigest(),
                'instances_sha256': sha(cases)}
    output.mkdir(parents=True, exist_ok=False)
    save(output / 'frozen_contract.json', contract)
    save(output / 'frozen_instances.json', cases)
    print(json.dumps({'frozen_contract_sha256': sha(contract), 'instances': len(cases), 'real_model_requests': 0}), flush=True)
    results = []
    for case in cases:
        result = benchmark(case)
        results.append(result)
        save(output / (case['case_id'] + '.json'), result)
        print(json.dumps({key: result[key] for key in (
            'case_id', 'forecast_states_M', 'legal_cache_trie_nodes_T', 'preprocessing_shared_ms',
            'dp_optimizer_median_ms', 'exhaustive_optimizer_median_ms',
            'optimization_only_speedup', 'shared_preprocessing_end_to_end_speedup',
            'optimality_matches_all_permutations')}), flush=True)
    summary = {'schema': CONTRACT['schema'], 'status': 'completed', 'instances': len(results),
               'all_optimality_checks_passed': all(row['optimality_matches_all_permutations'] for row in results),
               'independently_checked_distinct_instance_orders': sum(row['independent_validation']['permutations_independently_checked'] for row in results),
               'results': results, 'real_model_requests': 0,
               'complexity': {'n': 'current legal sources', 'N': 'all known source IDs / maximum old order length',
                              'M': 'explicit positive-mass forecast states', 'K': 'old cache orders',
                              'T': 'legal cache trie nodes including root',
                              'shared_preprocessing': 'O(M*K*N + M*n*2^n + K*N)',
                              'exact_optimizer_after_preprocessing': 'O(n*2^n + n*T)',
                              'fair_exhaustive_after_preprocessing': 'O(n*n!)',
                              'important_worst_case': 'if M itself grows as 2^n, naive delta preprocessing is O(n*4^n), not O(n*2^n)',
                              'no_global_novelty_claim': True}}
    save(output / 'summary.json', summary)
    print(json.dumps({key: summary[key] for key in ('status', 'instances', 'all_optimality_checks_passed',
                     'independently_checked_distinct_instance_orders', 'real_model_requests')}), flush=True)


if __name__ == '__main__':
    main()
