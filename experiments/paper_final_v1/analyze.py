"""Descriptive attribute and performance summaries; no experiments or p-values."""
import json
import statistics
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research_paper_v1/paper_final/evidence/cpu'


def load(path):return [json.loads(s)for s in path.read_text(encoding='utf8').splitlines()]
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def percentile(values,p):
    values=sorted(values);rank=(len(values)-1)*p;lo=int(rank);hi=min(lo+1,len(values)-1)
    return values[lo]+(values[hi]-values[lo])*(rank-lo)


def main():
    rows=load(OUT/'run_20261106_v2/raw.jsonl')
    methods=list(dict.fromkeys(r['method']for r in rows));detail=[]
    mapping={'revoked_source':{'F01','F02','F03','F12'},'stale_source_version':{'F11'},
             'wrong_recipient':{'F14'},'forged_body':{'F15'},'old_global_epoch_current_sources_eligible':{'F13','F18'}}
    for method in methods:
        selected=[r for r in rows if r['method']==method]
        row={'method':method}
        for attribute,cases in mapping.items():
            candidates=[r for r in selected if r['case_id'] in cases]
            row[attribute]={'case_denominator':len(candidates),'admitted_cases':sum(r['actual_commits']>0 for r in candidates)}
        row['false_confirmation_rejections']={r['case_id']:r['operations'][-1].get('reason') for r in selected if r['case_id'] in ('F16','F21')}
        detail.append(row)
    save(OUT/'run_20261106_v2/attribute_breakdown.json',{'scope':'descriptive clarification of the frozen joint invalid-admission indicator; not new experiments or post-hoc significance','methods':detail})
    perf_path=OUT/'run_20261106_perf_v3/performance_raw.jsonl'
    if perf_path.exists():
        perf=load(perf_path);summaries=[]
        for n in (1,8,32):
            for method in methods[:4]:
                selected=[r for r in perf if r['memory_count']==n and r['method']==method]
                if not selected:continue
                summary={'memory_count':n,'method':method,'repetitions':len(selected)}
                for key in ('host_processing_ns','authorization_validation_ns','package_verification_ns','persistent_commit_sql_ns','recovery_attempt_ns','cpu_ns','python_peak_allocated_bytes','receiver_storage_delta_bytes','persistent_storage_delta_bytes','packet_bytes'):
                    values=[r[key]for r in selected if r[key]is not None]
                    summary[key]={'median':statistics.median(values),'p95_linear':percentile(values,.95),'minimum':min(values),'maximum':max(values)} if values else None
                summary['recovery_without_new_effect_count']=sum(r['recovery_without_new_effect']for r in selected)
                summaries.append(summary)
        save(OUT/'run_20261106_perf_v3/performance_summary.json',{'scope':'single-machine repeated local operations, not independent business projects; no population inference or speed-superiority claim','summaries':summaries})
    print(json.dumps({'qualification_rows':len(rows),'attribute_methods':len(detail),'performance_available':perf_path.exists()}))


if __name__=='__main__':main()
