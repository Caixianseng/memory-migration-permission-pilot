"""Read only fixed public experiment artifacts, including unfinished pipelines.

Never inspect SDK private session trees or native account configuration.  Preserve
original strict-format failures after any local parse recovery.
"""
import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data'
JOBS=('source_initial_generation','source_legal_rebuild',*(f'receiver_{p}_{s}' for p in ('initial','legal_successor') for s in ('raw','summary','multi_source')))


def read(path):
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--run',type=Path,default=BASE/'qualification_isolated_v1');parser.add_argument('--out',type=Path,default=BASE/'attempt_audit');args=parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    rows=[];cases=[]
    for case in sorted(args.run.iterdir()):
        if not case.is_dir() or not case.name.startswith('LIVE-P'):continue
        complete=read(case/'complete.json');blocked=read(case/'blocked.json')
        cases.append({'case_id':case.name,'current_status':'complete' if complete else ('blocked' if blocked else 'in_progress'),
            'prior_block_file_present':bool(blocked),'blocked_error_if_current':blocked.get('error') if blocked and not complete else None,
            'complete_path':str(case/'complete.json') if complete else None})
        for name in JOBS:
            p=case/name
            if not p.is_dir():continue
            contract=read(p/'contract.json') or {};result=read(p/'result.json') or {};recovery=read(p/'local_parse_recovery.json') or {}
            selected=p;effective=recovery or result
            # Match live_runtime's explicit cached-result precedence. These
            # two fixed directories are separate attempts after audited zero
            # submission, not recursion through private account/session trees.
            if not recovery and result.get('status')=='failed':
                for child in ('safe_predispatch_retry','safe_precreation_retry'):
                    candidate=p/child;retried=read(candidate/'result.json') or {}
                    if retried.get('status')=='ok':selected=candidate;effective=retried;break
            raw=read(selected/'raw_output.json');text=raw.get('text') if raw else None
            strict=None;strict_error=None
            if isinstance(text,str):
                try:json.loads(text);strict=True
                except json.JSONDecodeError as exc:strict=False;strict_error=str(exc)
            metadata=effective.get('metadata',{})
            raw_path=selected/'raw_output.json';result_path=p/'result.json';contract_path=p/'contract.json'
            rows.append({'case_id':case.name,'job':name,'role':contract.get('role'),'platform':contract.get('platform'),
                'intent_present':(p/'intent.json').exists(),'original_result_status':result.get('status','not_returned'),
                'original_error':result.get('error'),'effective_status':effective.get('status','not_returned'),
                'selected_model_attempt_directory':str(selected),'new_attempt_after_verified_zero_submission':selected!=p,
                'zero_submission_evidence_paths':[str(p/n) for n in ('predispatch_failure_inspection.json','precreation_failure_inspection.json','account_predispatch_failure_inspection.json') if (p/n).exists()],
                'root_attempt_raw_output_present':(p/'raw_output.json').exists(),
                'raw_output_present':isinstance(text,str),'raw_strict_json':strict,'raw_strict_json_error':strict_error,
                'local_parse_recovery_present':bool(recovery),'serialization_adapter':metadata.get('serialization_adapter'),
                'observed_model':metadata.get('model'),'physical_supplier_calls':metadata.get('physical_supplier_calls'),
                'inference_wall_seconds':effective.get('inference_wall_seconds'),'elapsed_seconds':result.get('elapsed_seconds'),
                'actual_cost_cny':metadata.get('actual_cost_cny'),'estimated_cost_cny_not_invoice':metadata.get('estimated_cost_cny'),
                'contract_path':str(contract_path),'raw_output_path':str(raw_path) if raw else None,
                'original_result_path':str(result_path) if result else None,
                'input_sha256':digest(contract_path),'raw_output_sha256':digest(raw_path),'original_result_sha256':digest(result_path),
                'local_recovery_sha256':digest(p/'local_parse_recovery.json'),
                'selected_attempt_result_sha256':digest(selected/'result.json'),
                'new_model_calls_by_audit':0,'human_confirmed':False})
    counts={}
    for platform in ('hy3','flash'):
        subset=[r for r in rows if r['platform']==platform]
        counts[platform]={'job_directories':len(subset),'intent_count':sum(r['intent_present'] for r in subset),
            'original_result_status':dict(Counter(r['original_result_status'] for r in subset)),
            'effective_status':dict(Counter(r['effective_status'] for r in subset)),
            'raw_outputs':sum(r['raw_output_present'] for r in subset),
            'raw_strict_json_pass':sum(r['raw_strict_json'] is True for r in subset),
            'raw_strict_json_fail':sum(r['raw_strict_json'] is False for r in subset),
            'local_recoveries':sum(r['local_parse_recovery_present'] for r in subset),
            'fresh_attempts_after_proven_zero_submission':sum(r['new_attempt_after_verified_zero_submission'] for r in subset),
            'observed_physical_supplier_calls':sum(r['physical_supplier_calls'] for r in subset if isinstance(r['physical_supplier_calls'],int)) if any(isinstance(r['physical_supplier_calls'],int) for r in subset) else None,
            'supplier_call_count_observed_for_all_jobs':all(isinstance(r['physical_supplier_calls'],int) for r in subset),
            'cost_invoice_observed':False}
        estimates=[Decimal(str(r['estimated_cost_cny_not_invoice'])) for r in subset if r['estimated_cost_cny_not_invoice'] is not None]
        counts[platform]['estimated_cost_cny_not_invoice_sum']=str(sum(estimates,Decimal(0))) if estimates else None
        counts[platform]['estimate_observed_job_count']=len(estimates)
    summary={'snapshot_utc':datetime.now(timezone.utc).isoformat(),'run_path':str(args.run),'case_status_counts':dict(Counter(c['current_status'] for c in cases)),
        'planned_cases':60,'planned_inference_jobs_if_all_complete':480,'observed_job_directories':len(rows),
        'platform_counts':counts,'cases':cases,'new_model_calls_by_audit':0,
        'strict_json_definition':'json.loads of complete raw returned text with no extraction, repair or fence removal',
        'completion_rule':'complete.json supersedes a retained earlier blocked.json',
        'cost_warning':'Intent count is reservation count, not physical supplier call count. HY3 supplier call counts and invoices are not observed. Pending jobs are not failures.',
        'selection_warning':'Completed-pipeline quality alone can be biased by format or transport failure. This artifact-level audit retains failed and pending jobs.',
        'script_sha256':digest(Path(__file__))}
    (args.out/'attempt_rows.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
    (args.out/'attempt_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in summary.items() if k!='cases'},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
