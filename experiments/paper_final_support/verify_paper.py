"""Artifact, citation, raw-count and historical-integrity checks; no experiment rerun."""
import hashlib
import json
import re
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import unquote
ROOT=Path(__file__).resolve().parents[2]
P=ROOT/'research_paper_v1/paper_final'


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text(encoding='utf-8-sig'))


def main():
    required=['security_model','system_architecture','protocol_specification','related_work_comparison',
              'contribution_evidence_matrix','baseline_experiment','failure_injection_results','ablation_study',
              'human_evaluation','performance_evaluation','statistical_analysis','reproducibility_report',
              'paper_outline','paper_draft_en','journal_selection','submission_checklist','PROJECT_STATUS','AI_EXECUTION_LOG']
    errors=[]
    for name in required:
        path=P/(name+'.md')
        if not path.exists() or path.stat().st_size<400:errors.append('missing/substantively empty '+name)
    broken=[]
    for path in P.rglob('*.md'):
        # code tokens and prose paths are intentionally not treated as links.
        body=path.read_text(encoding='utf-8-sig')
        for link in re.findall(r'\]\(([^)]+)\)',body):
            link=link.strip('<>').split('#')[0]
            if not link or re.match(r'^[a-z]+://',link):continue
            target=(path.parent/unquote(link)).resolve()
            if not target.exists():broken.append({'file':str(path.relative_to(P)),'link':link})
    bib=(P/'references.bib').read_text(encoding='utf8')
    keys=re.findall(r'@\w+\s*\{\s*([^,\s]+)',bib)
    draft=(P/'paper_draft_en.md').read_text(encoding='utf8')
    cites=re.findall(r'@([A-Za-z][\w-]+)',draft)
    unknown=sorted(set(cites)-set(keys))
    if unknown:errors.append('unknown citation keys '+str(unknown))
    if 'CURRENT RUN INTEGRATION' in draft or 'CURRENT EVALUATION INTEGRATION' in draft:errors.append('unintegrated result paragraph')
    def lines(path):return [json.loads(s) for s in path.read_text(encoding='utf8').splitlines() if s]
    q=lines(P/'evidence/cpu/run_20261106_v2/raw.jsonl')
    perf=lines(P/'evidence/cpu/run_20261106_perf_v3/performance_raw.jsonl')
    ai=lines(P/'evidence/ai_evaluation/final.jsonl')
    if (len(q),len(perf),len(ai))!=(220,144,768):errors.append('raw row counts mismatch')
    if len({r['item_id'] for r in ai})!=768:errors.append('AI IDs incomplete/duplicated')
    ai_summary=load(P/'evidence/ai_evaluation/summary.json')
    if ai_summary['B_pending']!=0:errors.append('B semantic review unfinished')
    if ai_summary['human_confirmed_items']!=0:errors.append('Unexpected human confirmation: verify actual input before asserting')
    figures=load(P/'figures/figure_manifest.json')
    if len(figures['figures'])!=8:errors.append('figure count')
    for fig in figures['figures']:
        for ext in ['png','pdf','svg']:
            if not (P/'figures'/(fig['figure']+'.'+ext)).exists():errors.append('missing figure format')
        for source in fig['sources']:
            if not (ROOT/source).exists():errors.append('missing figure source '+source)
    audit=load(P/'evidence/core_asset_audit.json')
    old_changes=[]
    for row in audit['modules']+audit['required_reports']+audit['historical_data']+audit['databases']:
        if sha(ROOT/row['path'])!=row['sha256']:old_changes.append(row['path'])
    prior=load(ROOT/'research_paper_v1/publication_reassessment/evidence/local_read_coverage.json')
    exception={'research_paper_v1/PROJECT_STATUS.md','research_paper_v1/AI_EXECUTION_LOG.md'}
    for row in prior['files']:
        if row['path'] not in exception and sha(ROOT/row['path'])!=row['sha256']:old_changes.append(row['path'])
    trace=load(P/'evidence/ai_evaluation/local_source_trace.json')
    for rel,expected in trace['input_hashes'].items():
        if sha(ROOT/rel)!=expected:old_changes.append(rel)
    parsed=0
    for path in P.rglob('*.json'):
        if path.name=='paper_artifact_receipt.json':continue
        load(path);parsed+=1
    receipt={'schema':'paper-final-artifact-receipt-v1','checked_utc':datetime.now(timezone.utc).isoformat(),
             'local_date':'2026-11-06 Asia/Shanghai','required_documents':len(required),'qualification_rows':len(q),
             'performance_rows':len(perf),'ai_evaluated_items':len(ai),'ai_levels':ai_summary['final_levels'],
             'causal_trace_summary':trace['summary'],'additional_local_trace_inputs_checked':len(trace['input_hashes']),
             'human_confirmed_items':0,'human_validation_status':'pending actual researcher input',
             'draft_status':'English research draft; not submission-ready final manuscript',
             'figures':8,'figure_formats':['png','pdf','svg'],'json_parsed':parsed,
             'bibliography_keys':len(keys),'unknown_citations':unknown,'broken_links':broken,
             'historical_changes':sorted(set(old_changes)),'errors':errors,
             'paid_model_calls':0,'github_writes':0,'legacy_experiment_reruns':0,
             'artifact_check':'pass' if not(errors or broken or old_changes) else 'fail',
             'scope':'Artifact checks do not certify academic novelty, human validity, target quartile or acceptance',
             'files':[{'path':str(x.relative_to(ROOT)).replace('\\','/'),'sha256':sha(x),'bytes':x.stat().st_size}
                      for x in sorted(P.rglob('*')) if x.is_file() and x.name!='paper_artifact_receipt.json']}
    (P/'evidence/paper_artifact_receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in receipt.items() if k!='files'},ensure_ascii=False,indent=2))
    if receipt['artifact_check']!='pass':raise SystemExit(1)


if __name__=='__main__':main()
