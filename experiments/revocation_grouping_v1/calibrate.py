"""Two explicitly requested real SDK calls, bounded by 0.5 CNY peak estimate.

This is an interface calibration, excluded from comparative effect denominators.
"""
import argparse
from decimal import Decimal
import json
from pathlib import Path

from .lifecycle_runner import HERE, source_messages, target_messages, output_limit
from .lifecycle_host import LifecycleHost, save
from .sdk_adapter import FlashSDKClient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    contract = json.loads((HERE / 'workload_contract.json').read_text(encoding='utf-8'))
    case = json.loads((HERE / 'data/cases.jsonl').read_text(encoding='utf-8').splitlines()[0])
    questions = json.loads((HERE / 'data/evaluation_only/questions.json').read_text(encoding='utf-8'))[case['case_id']][:1]
    sources = [s for s in case['sources'] if s['source_id'] in questions[0]['support_source_ids']]
    committed_elsewhere = Decimal(0)
    for sibling in out.parent.glob('calibration-*'):
        if sibling == out:
            continue
        for reservation in (sibling / 'sdk.private').glob('job-*/reservation.json'):
            receipt_file = reservation.parent / 'receipt.json'
            receipt = json.loads(receipt_file.read_text(encoding='utf-8')) if receipt_file.exists() else {}
            value = receipt.get('estimated_peak_cost_cny') if receipt.get('status') == 'ok' else json.loads(reservation.read_text())['reservation_cny']
            committed_elsewhere += Decimal(str(value))
    remaining = Decimal('.5') - committed_elsewhere
    if remaining <= 0:
        raise ValueError('aggregate_calibration_budget_exhausted')
    save(out / 'aggregate_budget.json', {'stage_cap_cny': '.5', 'other_spent_or_retained_cny': str(committed_elsewhere), 'this_run_cap_cny': str(remaining)})
    client = FlashSDKClient(out / 'sdk.private', budget_cap_cny=remaining, max_jobs=2)
    save(out / 'metadata_preflight.json', client.preflight())
    host = LifecycleHost(sources, out / 'host')
    sm = source_messages(sources, contract)
    generated = host.generate(sources, sm, lambda: client.generate(sm, 'calibration-source', output_limit(sources), 'source'))
    save(out / 'source.json', {'messages': sm, 'result': generated})
    tm = target_messages(generated['output'], questions, contract)
    received = host.deliver(generated['output'], [s['source_id'] for s in sources], tm,
                           lambda: client.generate(tm, 'calibration-target', 1024, 'target'))
    save(out / 'target.json', {'messages': tm, 'result': received})
    summary = {'status': 'completed', 'physical_model_requests': 2,
               'source_output': generated['output'], 'target_output': received['output'],
               'estimated_peak_cost_cny': sum(float(x['receipt']['estimated_peak_cost_cny']) for x in (generated, received)),
               'counts_as_method_effect': False, 'human_gold': None}
    save(out / 'calibration_result.json', summary)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == '__main__':
    main()
