"""Read recorded A--E results and describe attribute and timing distributions."""
import json
import statistics
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DEFAULT=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/protocol/protocol_run_20261106_v1'


def percentile(values,p):
    v=sorted(values);at=(len(v)-1)*p;i=int(at);return v[i]+(v[min(i+1,len(v)-1)]-v[i])*(at-i)


def main():
    path=Path(sys.argv[1]).resolve()if len(sys.argv)>1 else DEFAULT
    rows=[json.loads(s)for s in (path/'raw.jsonl').read_text(encoding='utf8').splitlines()]
    config=json.loads((path/'config.json').read_text(encoding='utf8'))
    assert len(rows)==len(config['cases'])*len(config['methods'])
    assert len({(r['case_id'],r['method'])for r in rows})==len(rows)
    groups={'revoked_source':{'F01','F02','F03','F12','F22'},'stale_source_version':{'F11'},
            'wrong_recipient':{'F14'},'forged_body':{'F15'}}
    detail=[]
    for method in config['methods']:
        selected=[r for r in rows if r['method']==method]
        r={'method':method,'label':config['labels'][method],'case_count':len(selected)}
        for attr,ids in groups.items():
            subset=[q for q in selected if q['case_id']in ids]
            r[attr]={'denominator':len(subset),'admitted':sum(q['actual_commits']>0 for q in subset)}
        r['strict_oracle_matches']=sum(q['matches_strict_frozen_oracle']for q in selected)
        r['safe_recoveries']=sum(q['safe_recovery']is True for q in selected)
        r['safe_recovery_denominator']=sum(q['safe_recovery']is not None for q in selected)
        r['existing_commit_confirmations']=sum(q['existing_commit_confirmation']for q in selected)
        r['existing_commit_confirmation_denominator']=6
        # F22 expected zero effects: its one unauthorized first acceptance is
        # not a duplicate. Preserve frozen raw coding, correct interpretation.
        r['duplicate_effects']=sum(q['duplicate_effects']for q in selected if q['expected_commits']>0)
        r['conservative_refusals']=sum(q['current_policy_legal_false_reject']for q in selected)
        r['state_consistency_failures']=sum(q['state_consistency_failed']for q in selected)
        r['stale_epoch_admissions']=sum(q['stale_epoch_admission']for q in selected)
        detail.append(r)
    perf_dir=Path(sys.argv[2]).resolve()if len(sys.argv)>2 else path
    perf_file=perf_dir/'performance_raw.jsonl'
    perf=[json.loads(s)for s in perf_file.read_text(encoding='utf8').splitlines()]if perf_file.exists()else[]
    if perf:assert len(perf)==3*8*5
    summaries=[]
    for size in config['performance_sizes']:
        for method in config['methods'][:5]:
            selected=[r for r in perf if r['memory_count']==size and r['method']==method]
            if not selected:continue
            r={'memory_count':size,'method':method,'repetitions':len(selected)}
            for key in ('host_processing_ns','recovery_attempt_ns','cpu_ns','python_peak_allocated_bytes','persistent_storage_delta_bytes'):
                values=[q[key]for q in selected]
                r[key]={'median':statistics.median(values),'p95_linear':percentile(values,.95),'min':min(values),'max':max(values)}
            r['retry_without_new_effects']=sum(q['recovery_without_new_effect']for q in selected)
            summaries.append(r)
    out={'schema':'paper-live-v2-protocol-descriptive-analysis','protocol_rows':len(rows),'performance_rows':len(perf),
      'attributes':detail,'performance':summaries,'performance_raw_source':str(perf_file.relative_to(ROOT)),
      'unit':'targeted deterministic trace and single-machine technical repetition; no population significance claims',
      'metrics':'joint invalid admission is not identical to sensitive leakage; safe recovery = six existing-commit confirmations plus one F19 fresh retry',
      'coding_erratum':'F22 raw duplicate_effects used excess-over-zero; corrected duplicate totals exclude expected-zero cases, without changing actual effects or raw rows',
      'phase_zero_codebook':'C package checks and C/B implicit commits are not separately timed by those zero-valued probes; zero is not zero cost'}
    (path/'analysis.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'protocol_rows':len(rows),'performance_rows':len(perf),'attributes':detail},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
