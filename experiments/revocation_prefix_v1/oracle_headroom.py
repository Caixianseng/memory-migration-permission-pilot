"""NON-DEPLOYABLE future-oracle diagnostic; never an algorithm-effect result.

Uses sealed screen-v1 traces only AFTER their first result was recorded. This
diagnoses headroom for two-step ordering. It is not a lower bound on all online
controllers, and must never enter a fair baseline table as a causal method.
"""
import importlib.util
import json
from pathlib import Path
from collections import defaultdict

from .offline_screen import catalog, prime_order, ledger_miss

HERE = Path(__file__).resolve().parent


def main():
    path = HERE / 'snapshots/planner_screen_v1.py'
    spec = importlib.util.spec_from_file_location('frozen_prefix_planner', path)
    planner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(planner)
    cases = json.loads((HERE / 'offline_screen_v1/frozen_traces.json').read_text())
    rows = []
    sums = defaultdict(lambda: defaultdict(int))
    for case in cases:
        sources, lengths, states = catalog(case), case['lengths'], case['test_states']
        for warm in ('partial', 'full'):
            for arm in ('cache_greedy', 'NONCAUSAL_next_state_oracle'):
                prime = prime_order(case, states[0], warm)
                cache = [prime] if prime else []
                miss = sum(lengths[s] for s in prime)
                for tick, allowed in enumerate(states):
                    if arm.startswith('NONCAUSAL'):
                        after = states[min(tick + 1, len(states) - 1)]
                        history = [{'before': allowed, 'after': after}] * 2
                        method = 'causal_two_step'
                    else:
                        history = case['training_transitions']
                        method = 'cache_greedy'
                    action = planner.plan_layout([sources[s] for s in sorted(allowed)], history, cache,
                        {'method': method, 'known_source_lengths_bytes': lengths})['ordered_source_ids']
                    miss += ledger_miss(action, cache, lengths)
                    cache.append(action)
                row = {'case_id': case['case_id'], 'warm': warm, 'arm': arm,
                       'lifecycle_miss_bytes': miss}
                rows.append(row)
                sums['overall'][arm] += miss
                sums[case['regime']][arm] += miss
    result = {'diagnostic_only': True, 'future_trace_used': True,
        'deployable': False, 'real_api_calls': 0, 'rows': rows,
        'totals': dict(sums), 'saving': {k: 1 - v['NONCAUSAL_next_state_oracle'] / v['cache_greedy']
                                       for k, v in sums.items()}}
    output = HERE / 'offline_screen_v1/noncausal_headroom_diagnostic.json'
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({'totals': dict(sums), 'saving': result['saving'], 'diagnostic_only': True}))


if __name__ == '__main__':
    main()
