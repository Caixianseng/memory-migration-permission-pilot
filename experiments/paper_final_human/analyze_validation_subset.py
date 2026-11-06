"""Report pending until two actual human validation forms are supplied."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_final/evidence/ai_evaluation'


def main():
    spec=importlib.util.spec_from_file_location('full_human_analysis',Path(__file__).with_name('analyze.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    p=argparse.ArgumentParser();p.add_argument('--rater-1',type=Path,default=BASE/'human_validation_subset/validation_rater_1_blank.csv');p.add_argument('--rater-2',type=Path,default=BASE/'human_validation_subset/validation_rater_2_blank.csv');p.add_argument('--out',type=Path,default=BASE/'human_validation_subset/analysis');args=p.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    selected=json.loads((BASE/'human_validation_subset/selection.json').read_text(encoding='utf-8'))['item_ids']
    expected=set(selected);allitems=json.loads((m.BASE/'items.blinded.json').read_text(encoding='utf-8'))['items'];items={q['item_id']:q for q in allitems}
    rr=[m.read_csv(args.rater_1),m.read_csv(args.rater_2)]
    report={'schema':'human-validation-subset-analysis-v1','date_local':'2026-11-06','status':'pending','selected_items':48,'project_clusters':12,'human_confirmed_items':0,'completed_items_by_rater':[],'human_agreement':None,'AI_human_agreement':None,'errors':[],'scope':'AI-assisted exploratory full dataset; this subset is human validation, not full-batch human gold.'}
    for i,rows in enumerate(rr):
        ids=[r.get('item_id') for r in rows]
        if len(ids)!=len(set(ids)) or set(ids)!=expected:report['errors'].append(f'rater {i+1}: fixed 48-item set mismatch')
        report['completed_items_by_rater'].append(sum(m.complete(r,items[r['item_id']]) for r in rows if r.get('item_id') in expected))
    if report['errors']:report['status']='invalid_input'
    elif report['completed_items_by_rater']!=[48,48]:report['reason']='Two actual human validation forms not yet completed; no human agreement or accuracy calculated.'
    else:
        identities=[{r.get('rater_id','') for r in rows} for rows in rr]
        if any(len(x)!=1 for x in identities) or identities[0]==identities[1]:report['errors'].append('Two distinct single actual-rater IDs required');report['status']='invalid_input'
        else:
            r1,r2=[{r['item_id']:r for r in rows} for rows in rr];ai={r['item_id']:r for r in map(json.loads,(BASE/'final.jsonl').read_text(encoding='utf-8').splitlines())}
            human={};av={}
            for label in m.LABELS:
                counts=[0]*4
                for ident in selected:
                    a,b=r1[ident][label],r2[ident][label]
                    if a in {'0','1'} and b in {'0','1'}:counts[int(a)*2+int(b)]+=1
                human[label]=m.agreement_from_counts(counts)
                av[label]={}
                for slot,humanrows in ((1,r1),(2,r2)):
                    counts=[0]*4
                    for ident in selected:
                        a,b=str(ai[ident]['labels'][label]),humanrows[ident][label]
                        if a in {'0','1'} and b in {'0','1'}:counts[int(a)*2+int(b)]+=1
                    av[label][f'rater_{slot}']=m.agreement_from_counts(counts)
            disagreements=[ident for ident in selected if any(r1[ident][f]!=r2[ident][f] for f in m.FIELDS)]
            report.update({'status':'human_validation_rated_adjudication_pending' if disagreements else 'human_validation_rated','human_agreement':human,'AI_human_agreement':av,'human_scoring_disagreements':disagreements,'note':'Raw paired judgments are not a consensus gold set. Inspect disagreements; do not automatically majority-vote AI and two humans. Subset agreement is descriptive, not proof of all 768 labels.'})
    (args.out/'validation_status.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ['human_agreement','AI_human_agreement']},ensure_ascii=False,indent=2))
    if report['status']=='invalid_input':raise SystemExit(2)


if __name__=='__main__':main()
