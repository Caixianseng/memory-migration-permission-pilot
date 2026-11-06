"""Validate frozen stage-3 evidence without replaying any experiment."""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

ROOT=Path(__file__).resolve().parents[3]
STAGE=ROOT/'research_paper_v1/stage3_research_pivot'
E=STAGE/'evidence'
CODE=ROOT/'experiments/paper_v1/stage3_research_pivot'
REQUIRED=('real_world_constraints_audit','batch_read_assumption_analysis',
 'direction_A_provenance_security','direction_B_lifecycle_consistency',
 'direction_C_cumulative_disclosure','related_work_comparison','existing_failure_evidence',
 'minimal_qualification_experiments','statistical_evaluation','final_research_direction_decision')


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def lines(p):return [json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x.strip()]
def dump(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def main():
 for n in REQUIRED:assert (STAGE/(n+'.md')).stat().st_size>800,n
 a=read(E/'A_raw_results.json');ar=read(E/'A_run_receipt.json');af=read(E/'A_code_freeze.json')
 assert len(a)==ar['raw_records']==27 and len({x['case_id'] for x in a})==9
 assert sha(E/'A_raw_results.json')==ar['raw_sha256']
 assert sha(CODE/'direction_a/qualify.py')==af['script_sha256']
 assert sha(E/'A_config.json')==af['config_sha256']
 assert sha(ROOT/'experiments/persistent_exchange_v1/store.py')==af['existing_store_sha256']
 av=read(E/'A_views.json');ag=read(E/'A_ground_truth.json')
 assert av[-1]['view']==av[-2]['view'] and ag[-1]['gold_allowed']!=ag[-2]['gold_allowed']
 astr=read(E/'A_summary.json')['methods']['attempt_scoped_trusted_envelope']
 assert astr['false_allow']==0 and astr['false_reject']==1
 b=lines(E/'B_raw.jsonl');br=read(E/'B_run.json')
 assert len(b)==br['cases']==10 and all(x['qualification_passed'] for x in b)
 assert sha(E/'B_raw.jsonl')==br['raw_sha256']
 assert sha(CODE/'direction_b/qualify.py')==br['runner_sha256']
 race=next(x for x in b if x['case_id']=='B10')['observation']['comparison']
 assert race[0]['revocation_committed_before_payload'] and not race[1]['revocation_committed_before_payload']
 c=lines(E/'C_raw.jsonl');cr=read(E/'C_run.json')
 assert len(c)==cr['rows']==30 and len({x['case_id'] for x in c})==10
 assert sha(E/'C_raw.jsonl')==cr['raw_sha256'] and sha(CODE/'direction_c/qualify.py')==cr['code_sha256']
 cs=lines(E/'C_strong_raw.jsonl');csr=read(E/'C_strong_run.json')
 assert len(cs)==csr['rows']==10 and all(not(x['false_allow'] or x['false_reject'] or x['new_secret_exposures']) for x in cs)
 assert sha(E/'C_strong_raw.jsonl')==csr['raw_sha256']
 assert sha(CODE/'direction_c/strong_extension.py')==csr['extension_code_sha256']
 assert sha(CODE/'direction_c/qualify.py')==csr['original_code_sha256']
 assert sha(E/'C_config.json')==csr['old_config_sha256']
 al=read(E/'A_literature.json');bl=read(E/'B_literature.json');cl=read(E/'C_literature.json')
 papers=al['topical_papers']+bl['closest_papers']+cl['papers']
 assert len(al['closest_comparison_ids'])>=5 and len(bl['closest_papers'])>=5 and len(cl['papers'])>=5
 unique={(p.get('doi') or p['title']).lower().strip() for p in papers}
 audit=read(E/'existing_evidence_capture.json')
 for entry in audit['historical_inputs']+audit['code_anchors']:
  assert sha(ROOT/entry['path'])==entry['sha256'],entry['path']
 # The two project-management ledgers are intentionally mutable; old raw, code,
 # statistical artifacts and reports listed by stage 2 remain byte-identical.
 mutable={'research_paper_v1/PROJECT_STATUS.md','research_paper_v1/AI_EXECUTION_LOG.md'}
 unchanged=0
 for entry in read(ROOT/'research_paper_v1/stage2_evidence_gap/evidence/stage2_completion_receipt.json')['files']:
  if entry['path'] in mutable:continue
  assert sha(ROOT/entry['path'])==entry['sha256'],entry['path'];unchanged+=1
 broken=[]
 for path in STAGE.rglob('*.md'):
  for m in re.finditer(r'\[[^\]]*\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
   target=m.group(1).strip('<>').split('#')[0]
   if target and not target.startswith(('https:','http:','mailto:')) and not (path.parent/unquote(target)).resolve().exists():
    broken.append([path.relative_to(ROOT).as_posix(),target])
 assert not broken,broken
 parsed=0
 for path in E.glob('*.json'):
  if path.name not in ('stage3_completion_receipt.json','qualification_summary.json'):read(path);parsed+=1
 summary={'schema':'stage3-qualification-summary-v1','direction_scenarios':{'A':9,'B':10,'C':10},
  'total_handpicked_scenarios':29,'structured_records':{'A':27,'B':10,'C_initial':30,'C_stronger_baseline':10},
  'A':read(E/'A_summary.json'),'B':br,'C_initial':cr['summary'],'C_stronger_baseline':csr['summary'],
  'literature_direction_entries':len(papers),'unique_literature_records':len(unique),
  'literature_counts':{'A':len(al['topical_papers']),'B_closest':len(bl['closest_papers']),'C':len(cl['papers'])},
  'statistics':'Exact case observations only; no pooling across contracts, production CIs or P values.',
  'decision':'STOP','retained_engineering_object':'B, not approved as SCI paper core',
  'new_paid_model_calls':0,'github_writes':0,'historical_experiments_replayed':0,
  'limits':['A violates original trusted-writer assumption in diagnosis; not an original-contract exploit.',
            'B only establishes selected local schedules, not distributed provider atomicity.',
            'C only evaluates new positive-fact payload entailment; excludes refusal/timing side channels.',
            'No general novelty impossibility or production zero-risk claim.']}
 dump(E/'qualification_summary.json',summary)
 receipt=E/'stage3_completion_receipt.json'
 paths=set(STAGE.rglob('*'))|set(CODE.rglob('*.py'))|{ROOT/p for p in mutable}
 files=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(paths)
        if p.is_file() and p!=receipt and '__pycache__' not in p.parts]
 result={'schema':'stage3-completion-receipt-v1','checked_utc':datetime.now(timezone.utc).isoformat(),
  'artifact_checks':'pass','required_documents':10,'json_parsed':parsed,'broken_local_links':broken,
  'unchanged_stage2_artifacts':unchanged,'mutable_ledger_exceptions':sorted(mutable),
  'scientific_gate':'not_passed','decision':'STOP','files':files,
  'new_paid_model_calls':0,'github_writes':0,'original_store_unchanged':True}
 dump(receipt,result)
 print(json.dumps({**{k:v for k,v in result.items() if k!='files'},'scenarios':29,
                   'structured_records':77,'unique_topical_papers':len(unique)},ensure_ascii=False))


if __name__=='__main__':main()
