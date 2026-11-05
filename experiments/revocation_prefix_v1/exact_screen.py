"""Fixed-seed residual-coverage solver screen; source-byte proxy, never a bill."""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random
import statistics
import time

from . import planner
from . import exact_planner
from .offline_screen import make_cases, catalog, ledger_miss, prime_order

HERE = Path(__file__).resolve().parent
ARMS = ('cache_greedy', 'cache_greedy_forecast_tail', 'conditional_static',
        'cache_greedy_risk_cut', 'causal_two_step', 'exact_two_step')


def save(path, obj):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(obj, stream, ensure_ascii=False, sort_keys=True)


def bootstrap(rows, baseline, seed=2026110508):
    clusters = defaultdict(lambda: defaultdict(int))
    for row in rows:
        clusters[row['case_id']][row['arm']] += row['miss']
    ids, rng = sorted(clusters), random.Random(seed)
    values = []
    for _ in range(4000):
        draw = rng.choices(ids, k=len(ids))
        b = sum(clusters[i][baseline] for i in draw)
        c = sum(clusters[i]['exact_two_step'] for i in draw)
        if b:
            values.append(1 - c / b)
    values.sort()
    return [values[int(.025 * len(values))], values[min(len(values)-1, int(.975 * len(values)))]]


def main():
    output = HERE / 'exact_screen_v1'
    output.mkdir(exist_ok=False)
    # Prior D2/D3 trajectories remain exposed development material. New seeds
    # below were chosen before this solver's outcomes and never selected by gain.
    import experiments.revocation_prefix_v1.offline_screen as generator
    generator.SEED = 2026110507
    cases = make_cases(replicates=6, train_steps=128, test_steps=16)
    contract = {'stage': 'new_solver_fixed_seed_proxy_screen', 'seed': generator.SEED,
        'arms': ARMS, 'forecast_model': 'independent_status_marginal',
        'next_cost_weight': 1, 'risk_cut_threshold': .75, 'warm_modes': ['partial','full'],
        'clusters': len(cases), 'future_trace_seen_by_algorithm': False,
        'previously_exposed_synthetic_traces': False, 'target_api_calls': 0,
        'baseline_fixed_before_results': 'cache_greedy_forecast_tail',
        'no_subset_or_regime_dropped': True,
        'code_hash': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                      (Path(__file__), Path(planner.__file__), Path(exact_planner.__file__))}}
    save(output / 'contract.json', contract)
    save(output / 'frozen_cases.json', cases)
    rows, aggregate = [], defaultdict(lambda: defaultdict(int))
    started = time.perf_counter()
    for case in cases:
        materials, lengths = catalog(case), case['lengths']
        for warm in ('partial', 'full'):
            for arm in ARMS:
                prime = prime_order(case, case['test_states'][0], warm)
                cache = [prime] if prime else []
                miss = raw = sum(lengths[s] for s in prime)
                actions, planning = [], 0.0
                for tick, allowed in enumerate(case['test_states']):
                    cfg = {'method': arm, 'forecast_model': 'independent_status_marginal',
                        'known_source_lengths_bytes': lengths, 'risk_cut_threshold': .75}
                    fn = exact_planner.plan_layout if arm == 'exact_two_step' else planner.plan_layout
                    decision = fn([materials[s] for s in sorted(allowed)], case['training_transitions'], cache, cfg)
                    order = decision['ordered_source_ids']
                    if sorted(order) != sorted(allowed):
                        raise AssertionError('all_current_sources_required')
                    now = ledger_miss(order, cache, lengths)
                    if abs(now - decision['predicted_now_miss_bytes']) > 1e-7:
                        raise AssertionError('independent_current_cost_disagreement')
                    miss += now
                    raw += sum(lengths[s] for s in allowed)
                    planning += decision['planning_ms']
                    actions.append({'tick': tick, 'order': order, 'actual_proxy_miss': now,
                        'expected_next_miss': decision['predicted_next_miss_bytes']})
                    cache.append(order)
                row = {'case_id': case['case_id'], 'regime': case['regime'], 'warm': warm,
                    'arm': arm, 'miss': miss, 'raw': raw, 'planning_ms': planning, 'actions': actions}
                rows.append(row)
                for key in ('overall', case['regime']):
                    aggregate[key][arm] += miss
        print(json.dumps({'completed': case['case_id']}, ensure_ascii=False), flush=True)
    baselines = [arm for arm in ARMS if arm != 'exact_two_step']
    best = min(baselines, key=lambda arm: aggregate['overall'][arm])
    result = {'status': 'completed', 'measurement': 'ideal_source_byte_prefix_proxy',
        'rows': rows, 'totals': dict(aggregate), 'baseline_frozen': contract['baseline_fixed_before_results'],
        'saving_vs_frozen_baseline': 1 - aggregate['overall']['exact_two_step'] / aggregate['overall']['cache_greedy_forecast_tail'],
        'saving_vs_best_simple_posthoc_diagnostic': 1 - aggregate['overall']['exact_two_step'] / aggregate['overall'][best],
        'best_simple_posthoc_diagnostic': best,
        'paired_cluster_bootstrap95_vs_frozen': bootstrap(rows, 'cache_greedy_forecast_tail'),
        'elapsed_seconds': time.perf_counter() - started, 'api_calls': 0,
        'guarantee_is_one_step_model_optimum_not_real_lifecycle_optimum': True}
    save(output / 'summary.json', result)
    print(json.dumps({k:v for k,v in result.items() if k != 'rows'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
