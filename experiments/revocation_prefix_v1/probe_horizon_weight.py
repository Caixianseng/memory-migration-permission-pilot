"""Development-only horizon-weight probe on already exposed screen-v1 traces."""
import importlib.util
import json
from pathlib import Path
from collections import defaultdict

from .offline_screen import catalog, prime_order, ledger_miss

HERE = Path(__file__).resolve().parent
WEIGHTS = (0, 1, 2, 4, 8, 16)


def main():
    output = HERE / 'development_weight_probe_v1'
    output.mkdir(exist_ok=False)
    frozen = HERE / 'snapshots/planner_screen_v1.py'
    spec = importlib.util.spec_from_file_location('frozen_prefix_planner', frozen)
    planner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(planner)
    cases = json.loads((HERE / 'offline_screen_v1/frozen_traces.json').read_text())
    (output / 'contract.json').write_text(json.dumps({'development_only': True,
        'previously_exposed_traces': True, 'weights': WEIGHTS, 'uses_future_trace_for_planning': False,
        'fixed_before_probe_outcomes': True, 'real_calls': 0,
        'note': 'weight0 frozen-v1 tie uses future; not a clean ablation'}), encoding='utf-8')
    totals, rows = defaultdict(lambda: defaultdict(int)), []
    for case in cases:
        sources, lengths, states = catalog(case), case['lengths'], case['test_states']
        for warm in ('partial', 'full'):
            for weight in WEIGHTS:
                prime = prime_order(case, states[0], warm)
                cache = [prime] if prime else []
                miss = sum(lengths[s] for s in prime)
                for allowed in states:
                    action = planner.plan_layout([sources[s] for s in sorted(allowed)],
                        case['training_transitions'], cache, {'method': 'causal_two_step',
                        'next_cost_weight': weight, 'known_source_lengths_bytes': lengths,
                        'risk_cut_threshold': .75})['ordered_source_ids']
                    miss += ledger_miss(action, cache, lengths)
                    cache.append(action)
                rows.append({'case_id': case['case_id'], 'warm': warm, 'weight': weight, 'miss': miss})
                totals['overall'][weight] += miss
                totals[case['regime']][weight] += miss
    result = {'development_only': True, 'no_supplier_cache_measurements': True,
        'rows': rows, 'totals': dict(totals)}
    (output / 'summary.json').write_text(json.dumps(result), encoding='utf-8')
    print(json.dumps({'development_totals': dict(totals)}))


if __name__ == '__main__':
    main()
