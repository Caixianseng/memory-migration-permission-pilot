"""Read-only evidence checks, then write one stage-2 completion receipt.

Does not execute any model, experiment, historical replay or solver.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[3]
STAGE = ROOT / 'research_paper_v1/stage2_evidence_gap'
EVIDENCE = STAGE / 'evidence'
REQUIRED = ('research_question_refinement','related_work_comparison','evidence_model',
            'baseline_design','pilot_dataset_design','pilot_experiment_results',
            'cost_analysis','statistical_analysis','failure_case_analysis','go_no_go_decision')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    receipt_path = EVIDENCE / 'stage2_completion_receipt.json'
    for name in REQUIRED:
        assert (STAGE / (name+'.md')).stat().st_size > 300, name
    broken=[]
    for path in STAGE.rglob('*.md'):
        for match in re.finditer(r'\[[^\]]*\]\(([^)]+)\)', path.read_text(encoding='utf-8')):
            target=match.group(1).strip('<>').split('#')[0]
            if not target or target.startswith(('https:','http:','mailto:')):continue
            if not (path.parent/unquote(target)).resolve().exists():broken.append([str(path),target])
    assert not broken,broken
    parsed=0
    for path in STAGE.rglob('*.json'):
        if path!=receipt_path:read(path);parsed+=1
    freeze=read(EVIDENCE/'code_freeze_v4.json')
    for path,key in [(ROOT/'experiments/paper_v1/stage2_evidence_gap/runner.py','runner_sha256'),
                     (EVIDENCE/'config.json','config_sha256'),(EVIDENCE/'dataset_v3.json','dataset_sha256')]:
        assert sha(path)==freeze[key],str(path)
    stats=read(EVIDENCE/'statistical_results.json')
    cfg=read(EVIDENCE/'config.json')
    counts={};allrows=[]
    for split,n in [('development',3584),('heldout',3360)]:
        path=EVIDENCE/f'raw_{split}.jsonl'
        run=read(EVIDENCE/f'run_{split}.json')
        rows=[json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        assert len(rows)==n==run['rows']
        assert sha(path)==run['raw_sha256']
        assert run['status']=='complete' and not run['failed_conditions']
        assert len(run['crosschecks'])==480
        assert all(abs(c['dp_cost']-c['scipy_milp_cost'])<1e-6 for c in run['crosschecks'])
        assert all(r['new_model_calls']==0 and r['actual_paid_api_cost_cny']==0 for r in rows)
        assert all(r['human_review_time_seconds'] is None and not r['human_review_performed'] for r in rows)
        assert all(not(r['unauthorized_releases'] or r['false_allows'] or r['missing_fp'] or r['missing_fn']) for r in rows)
        assert {r['method'] for r in rows}==set(cfg['methods'])
        assert len({r['project_id'] for r in rows})==12
        counts[split]=len(rows);allrows+=rows
    mainrows=[r for r in allrows if r['budget_units']==cfg['main_budget_units']]
    assert len(mainrows)==stats['main_arm_rows']==6720
    assert len(allrows)-len(mainrows)==stats['tight_arm_rows']==224
    assert len(stats['primary'])==5 and not any(p['passes_resource_screen'] for p in stats['primary'])
    for contrast in stats['primary']:
        def average(method):
            values=[r['tool_requests'] for r in mainrows if (r['split'],r['regime'],r['method'])==('heldout',contrast['regime'],method)]
            assert len(values)==120
            return sum(values)/len(values)
        assert abs(average(contrast['candidate'])-contrast['effect']['candidate_mean'])<1e-10
        assert abs(average(contrast['baseline'])-contrast['effect']['baseline_mean'])<1e-10
    probes=read(EVIDENCE/'raw_boundary_probes.json')['probes']
    assert len(probes)==9 and all(p['passed'] for p in probes)
    lit=read(EVIDENCE/'literature_verification.json')
    assert lit['screened_topical_papers']>=10 and len(lit['deep_comparison_ids'])>=5
    for name in ('request_counts','recovery_and_bytes'):
        for ext in ('png','pdf'):assert (STAGE/'figures'/f'{name}.{ext}').stat().st_size>1000
    fig=read(STAGE/'figures/figure_manifest.json')
    assert fig['source_script_sha256']==sha(Path(__file__).with_name('analyze.py'))
    # Stage-1 artifacts remain immutable except the two explicitly maintained ledgers.
    prior=read(ROOT/'research_paper_v1/evidence/stage1_completion_receipt.json')
    ledgers={'research_paper_v1/PROJECT_STATUS.md','research_paper_v1/AI_EXECUTION_LOG.md'}
    unchanged=[]
    for entry in prior['files']:
        if entry['path'] in ledgers:continue
        assert sha(ROOT/entry['path'])==entry['sha256'],entry['path']
        unchanged.append(entry['path'])
    files=set(STAGE.rglob('*'))
    files.update((ROOT/'experiments/paper_v1/stage2_evidence_gap').rglob('*.py'))
    files.update(Path(__file__).parent.glob('*.py'))
    files.update(ROOT/p for p in ledgers)
    manifest=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
              for p in sorted(files) if p.is_file() and p!=receipt_path and '__pycache__' not in p.parts]
    result={'schema':'stage2-completion-receipt-v1','checked_utc':datetime.now(timezone.utc).isoformat(),
            'artifact_checks':'pass','decision':'REDUCE','algorithm_development_gate':'not_passed',
            'required_documents':len(REQUIRED),'evidence_json_parsed':parsed,'raw_rows':counts,
            'main_rows':len(mainrows),'tight_rows':224,'independent_projects':{'development':12,'heldout':12},
            'boundary_probes':9,'dp_milp_crosschecks':960,'primary_resource_screens_passed':0,
            'unchanged_stage1_artifacts':unchanged,'mutable_ledger_exceptions':sorted(ledgers),
            'new_paid_model_calls':0,'github_writes_in_this_stage':0,'broken_local_links':broken,'files':manifest,
            'limits':['Synthetic generator qualification, not production risk or commercial Agent internals.',
                      'Serial policy injection does not prove atomic read-time revocation safety.',
                      'Synthetic cost weights are not measured monetary costs.']}
    receipt_path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('files','unchanged_stage1_artifacts')},ensure_ascii=False))


if __name__=='__main__':main()
