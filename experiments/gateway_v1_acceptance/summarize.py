"""Read saved CPU results; export per-row measurements and engineering plots.

No model inference, benchmark rerun, significance test, resampling, exclusions
or frozen-evaluation rescoring is performed here.
"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys


METHODS = ('acl', 'transaction', 'gateway')
LABELS = ('A: ACL', 'B: transaction', 'C: Gateway')


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quantile95(values):
    """Predeclared descriptive nearest-rank P95, without interpolation."""
    return sorted(values)[math.ceil(0.95 * len(values)) - 1] if values else None


def write_json(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')


def write_csv(path, rows):
    with path.open('x', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run = args.run_dir.resolve()
    if args.output.exists():
        raise SystemExit('new summary output directory required')
    args.output.mkdir(parents=True)
    raw = read_rows(run / 'raw_regression.jsonl')
    perf = read_rows(run / 'raw_performance.jsonl')
    if len(raw) != 24 or len(perf) != 180:
        raise ValueError('incomplete fixed campaign; no replacement data or exclusions')
    rows = []
    for r in perf:
        rows.append({k: r[k] for k in ('project_id', 'method', 'repeat_index', 'accepted',
            'wall_ns', 'cpu_ns', 'sql_logical_statements', 'receiver_storage_delta_bytes',
            'policy_storage_delta_bytes', 'spool_storage_delta_bytes')})
        rows[-1].update({f'sql_{verb.lower()}': r['sql_logical_counts'].get(verb, 0)
                         for verb in ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'PRAGMA')})
    write_csv(args.output / 'performance_measurements.csv', rows)
    regression_table = []
    for r in raw:
        counts = r.get('after_snapshot', {}).get('effect_count')
        operations = r.get('operations', [])
        recovery_ns = [op['result']['wall_ns'] for op in operations
            if (op.get('result', {}).get('receipt') or {}).get('status') == 'already_committed']
        for op in operations:
            recovery_ns.extend(x['wall_ns'] for x in op.get('rows', [])
                               if (x.get('receipt') or {}).get('status') == 'already_committed')
        accepted = [op.get('result', {}).get('accepted') for op in operations]
        regression_table.append({'scenario': r['scenario_id'], 'method': r['method'],
            'full_contract_pass': r['passed'], 'final_effect_count': counts,
            'expected_effect_count': r['expected']['final_effect_count'],
            'unauthorized_first_effects': counts if r['scenario_id'] == 'R5' else 0,
            'duplicate_effects': max(0, (counts or 0) - 1) if r['scenario_id'] != 'R8' else 0,
            'metadata_recovery_confirmations': len(recovery_ns),
            'metadata_recovery_mean_ms': statistics.mean(recovery_ns)/1e6 if recovery_ns else None,
            'metadata_recovery_p95_ms': quantile95(recovery_ns)/1e6 if recovery_ns else None,
            'harness_error': r.get('harness_error')})
    write_csv(args.output / 'regression_outcomes.csv', regression_table)
    method_summaries = {}
    project_rows = []
    for m in METHODS:
        p = [r for r in perf if r['method'] == m]
        rr = [r for r in regression_table if r['method'] == m]
        end_sizes = []
        for project in sorted({r['project_id'] for r in p}):
            subset = [r for r in p if r['project_id'] == project]
            last = max(subset, key=lambda r:r['repeat_index'])
            first = min(subset, key=lambda r:r['repeat_index'])
            sizes = last['after_snapshot']['storage']
            end_sizes.append(sizes)
            project_rows.append({'project_id': project, 'method': m,
                'normal_commits': sum(r['accepted'] for r in subset),
                'mean_ms': statistics.mean(r['wall_ns'] for r in subset)/1e6,
                'p95_ms': quantile95([r['wall_ns'] for r in subset])/1e6,
                'logical_sql_mean': statistics.mean(r['sql_logical_statements'] for r in subset),
                'receiver_db_bytes': sizes['receiver_db_bytes'],
                'policy_db_bytes': sizes['policy_db_bytes'], 'spool_bytes': sizes['spool_bytes'],
                'receiver_growth_bytes': sizes['receiver_db_bytes']-first['before_snapshot']['storage']['receiver_db_bytes']})
        method_summaries[m] = {
            'regression_full_contract_passes': sum(r['full_contract_pass'] for r in rr),
            'regression_scenarios': len(rr),
            'unauthorized_first_effects': sum(r['unauthorized_first_effects'] or 0 for r in rr),
            'duplicate_effects': sum(r['duplicate_effects'] for r in rr),
            'normal_commits': sum(r['accepted'] for r in p), 'normal_attempts': len(p),
            'mean_delivery_ms': statistics.mean(r['wall_ns'] for r in p)/1e6,
            'p95_delivery_ms': quantile95([r['wall_ns'] for r in p])/1e6,
            'mean_logical_sql_statements': statistics.mean(r['sql_logical_statements'] for r in p),
            'mean_logical_select_statements': statistics.mean(r['sql_logical_counts'].get('SELECT',0) for r in p),
            'mean_logical_write_statements': statistics.mean(sum(r['sql_logical_counts'].get(v,0) for v in ('INSERT','UPDATE','DELETE','REPLACE')) for r in p),
            'mean_final_receiver_db_bytes': statistics.mean(s['receiver_db_bytes'] for s in end_sizes),
            'mean_final_policy_db_bytes': statistics.mean(s['policy_db_bytes'] for s in end_sizes),
            'mean_final_spool_bytes': statistics.mean(s['spool_bytes'] for s in end_sizes),
            'physical_io_operations': None}
    write_csv(args.output / 'project_measurements.csv', project_rows)
    summary = {'methods': method_summaries, 'new_model_calls': 0, 'inference_or_semantic_evaluation': False,
        'n': {'fault_schedules': 8, 'fault_method_rows': 24, 'synthetic_size_fixtures': 10,
              'repeats_per_fixture_method': 6, 'performance_rows': 180},
        'uncertainty': 'Descriptive observations; no CI or significance claim. Repeats within a controlled fixture are not independent projects.',
        'p95_definition': 'nearest-rank ceil(0.95*n), all observations retained',
        'method_relation': 'B and C use the same mature security core. C adds the service/spool wrapper, not a new atomicity algorithm.',
        'latency_scope': load(run/'config.json')['timing_scope'],
        'metric_scope': 'Unauthorized and duplicate counts are events in the eight fixed schedules, not population rates. Successful metadata confirmations exclude retry failures and are separately counted.',
        'inputs': {p.name:sha(p) for p in (run/'raw_regression.jsonl',run/'raw_performance.jsonl',run/'config.json',run/'completion.json')}}
    write_json(args.output / 'summary.json', summary)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    colors = ('#595959','#0072B2','#D55E00')
    markers = ('o','s','^')
    with plt.rc_context({'font.size':10,'svg.fonttype':'none','pdf.fonttype':42}):
        fig, axes = plt.subplots(1,3,figsize=(12,4.1),layout='constrained')
        metrics = [('mean_ms','Mean commit latency (ms)'),
                   ('logical_sql_mean','Mean logical SQL statements'),
                   ('receiver_db_bytes','Final receiver database (KiB)')]
        for ax, (metric, title) in zip(axes, metrics):
            for index,m in enumerate(METHODS):
                values = [r[metric]/(1024 if metric=='receiver_db_bytes' else 1) for r in project_rows if r['method']==m]
                ax.scatter([index]*len(values),values,color=colors[index],marker=markers[index],s=30,alpha=.8)
                ax.plot([index-.2,index+.2],[statistics.mean(values)]*2,color='black',lw=2)
            ax.set_xticks(range(3),LABELS,rotation=15,ha='right')
            ax.set_ylabel(title); ax.set_ylim(bottom=0); ax.grid(axis='y',alpha=.2)
        fig.suptitle('Fixed single-host CPU campaign: 10 controlled fixtures, 6 commits per method\nPoints: fixture means / final sizes; black line: mean. No model calls or CI.')
        for extension in ('png','svg'):
            fig.savefig(args.output/('engineering_overhead.'+extension),dpi=160)
        plt.close(fig)
    write_json(args.output/'figure_provenance.json', {
        'destination':'engineering acceptance report, not a journal submission',
        'data':'project_measurements.csv','data_sha256':sha(args.output/'project_measurements.csv'),
        'python':sys.version,'matplotlib':matplotlib.__version__,
        'aggregation':'Arithmetic mean of six repeated commits per fixture and method; all ten fixture values shown. Storage is final actual file size.',
        'exclusions':0,'transformations':['nanoseconds / 1e6 for milliseconds','bytes / 1024 for KiB'],
        'alt_text':'Three panels compare ACL, the mature transaction reference and the Gateway wrapper. Each method shows ten controlled-fixture observations for latency, logical SQL statements and final receiver storage; both strong methods share their security core.',
        'figures':{p.name:sha(p) for p in args.output.glob('engineering_overhead.*')}})
    print(json.dumps(method_summaries,ensure_ascii=False))


if __name__ == '__main__':
    main()
