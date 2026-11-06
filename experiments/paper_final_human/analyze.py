"""Validate two actual human rating files, prepare adjudication, and analyse.

Blank instruments deliberately yield pending, never fabricated agreement or CIs.
"""
import argparse
import csv
import hashlib
import itertools
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_final/evidence/human'
LABELS=['ProtocolFailure','FactualError','LegalInformationOmission','UnauthorizedInformationDisclosure','Unverifiable']
FIELDS=['evaluable',*LABELS,'legal_score']
ARMS=['raw','whole_drop','full_rebuild','selective']
SEED=2026110603


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read_csv(p):
    with p.open(encoding='utf-8-sig',newline='') as f:
        return list(csv.DictReader(f))


def complete(row, item):
    return row.get('human_attestation')=='yes' and bool(row.get('rater_id',row.get('adjudicator_id','')).strip()) and row.get('evaluable') in {'yes','partial','no'} and all(row.get(k) in {'0','1','NA'} for k in LABELS) and row.get('legal_score') in ({'0','0.5','1','NA'} if item['primary_eligible'] else {'NA'}) and (not any(row.get(k)=='NA' for k in FIELDS) or bool(row.get('evidence_note','').strip()))


def quantile(vals, q):
    if not vals:return None
    vals=sorted(vals); idx=(len(vals)-1)*q; lo=int(idx); hi=min(lo+1,len(vals)-1)
    return vals[lo]+(vals[hi]-vals[lo])*(idx-lo)


def bootstrap(vals, draws):
    n=len(vals)
    stats=[sum(vals[i] for i in draw)/n for draw in draws]
    return [quantile(stats,.025),quantile(stats,.975)]


def agreement_from_counts(c):
    n=sum(c)
    if not n:return {'n_both_binary':0,'agreement':None,'cohen_kappa':None,'reason':'no paired binary labels'}
    a,b,c1,d=c
    po=(a+d)/n; pe=((a+b)*(a+c1)+(c1+d)*(b+d))/(n*n)
    return {'n_both_binary':n,'agreement':po,'cohen_kappa':(po-pe)/(1-pe) if pe<1 else None,'reason':'constant marginal labels: kappa undefined' if pe==1 else None}


def signflip(values):
    observed=abs(sum(values)/len(values))
    exceed=sum(abs(sum(v*s for v,s in zip(values,signs))/len(values))>=observed-1e-12 for signs in itertools.product((-1,1),repeat=len(values)))
    return exceed/(2**len(values))


def holm(ps):
    order=sorted(range(len(ps)),key=lambda i:ps[i]); out=[None]*len(ps); last=0
    for k,i in enumerate(order):
        last=max(last,min(1,(len(ps)-k)*ps[i]));out[i]=last
    return out


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--rater-1',type=Path,default=BASE/'rater_1_blank.csv');ap.add_argument('--rater-2',type=Path,default=BASE/'rater_2_blank.csv');ap.add_argument('--adjudication',type=Path);ap.add_argument('--out',type=Path,default=BASE/'analysis');args=ap.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    items_data=json.loads((BASE/'items.blinded.json').read_text(encoding='utf-8'))
    items={x['item_id']:x for x in items_data['items']}
    mapping=json.loads((BASE/'private_unblinding_key.json').read_text(encoding='utf-8'))['key']
    rows=[read_csv(args.rater_1),read_csv(args.rater_2)]
    state={'schema':'human-review-analysis-v1','date_local':'2026-11-06','checked_utc':datetime.now(timezone.utc).isoformat(),'human_evaluation_status':'pending','raters':[],'label_generation':'This script never generates outcome labels; two actual human raters are required. Human declarations do not independently attest identity or independence.','analysis_plan_seed':SEED,'agreement':None,'adjudicated_results':None,'source_files':{str(args.rater_1):sha(args.rater_1),str(args.rater_2):sha(args.rater_2)},'errors':[]}
    dictionaries=[]
    for i,rr in enumerate(rows):
        ids=[x.get('item_id') for x in rr]
        if len(ids)!=len(set(ids)) or set(ids)!=set(items):state['errors'].append(f'rater {i+1}: item set must contain each of 768 IDs exactly once')
        for r in rr:
            for field in FIELDS:
                value=r.get(field,'')
                allowed={'','yes','partial','no'} if field=='evaluable' else ({'','0','0.5','1','NA'} if field=='legal_score' else {'','0','1','NA'})
                if value not in allowed:state['errors'].append(f'rater {i+1}: {r.get("item_id")} invalid {field}={value}')
        dd={r['item_id']:r for r in rr if r.get('item_id') in items};dictionaries.append(dd)
        done=sum(complete(r,items[r['item_id']]) for r in dd.values())
        identities=sorted({r.get('rater_id','').strip() for r in rr if r.get('rater_id','').strip()})
        state['raters'].append({'slot':i+1,'rows':len(rr),'fully_completed_items':done,'incomplete_items_first20':[ident for ident,r in dd.items() if not complete(r,items[ident])][:20],'rater_ids':identities,'human_attested_rows':sum(r.get('human_attestation')=='yes' for r in rr)})
    if state['errors']:state['human_evaluation_status']='invalid_input'
    elif any(x['fully_completed_items']!=768 for x in state['raters']):state['pending_reason']='Two independent humans have not completed and attested all 768 items. No human outcome statistics calculated.'
    elif any(len(x['rater_ids'])!=1 for x in state['raters']) or state['raters'][0]['rater_ids']==state['raters'][1]['rater_ids']:
        state['human_evaluation_status']='invalid_input';state['errors'].append('Two distinct, single rater identities are required; declaration cannot independently prove human independence.')
    else:
        r1,r2=dictionaries;projects=sorted({m['case_id'] for m in mapping.values()});rng=random.Random(SEED);draws=[[rng.randrange(len(projects)) for _ in projects] for _ in range(5000)]
        agreement={}
        for label in LABELS:
            pc={p:[0,0,0,0] for p in projects}
            for ident in items:
                a,b=r1[ident][label],r2[ident][label]
                if a in {'0','1'} and b in {'0','1'}:pc[mapping[ident]['case_id']][int(a)*2+int(b)]+=1
            counts=[sum(pc[p][j] for p in projects) for j in range(4)]
            result=agreement_from_counts(counts);bs=[]
            for draw in draws:
                c=[sum(pc[projects[i]][j] for i in draw) for j in range(4)]; k=agreement_from_counts(c)['cohen_kappa']
                if k is not None:bs.append(k)
            result.update({'excluded_NA_pairs':768-result['n_both_binary'],'project_cluster_bootstrap_kappa_ci95':[quantile(bs,.025),quantile(bs,.975)] if bs else None,'valid_kappa_bootstrap_draws':len(bs),'binary_confusion_00_01_10_11':counts})
            agreement[label]=result
        state['agreement']=agreement
        disagree=[ident for ident in items if any(r1[ident][f]!=r2[ident][f] for f in FIELDS)]
        state['disagreement_items']=len(disagree)
        path=args.out/'disagreement_queue.csv'
        with path.open('w',encoding='utf-8-sig',newline='') as f:
            fields=['item_id','question','answer',*[f'rater_{i}_{field}' for i in (1,2) for field in FIELDS]];w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
            for ident in disagree:w.writerow({'item_id':ident,'question':items[ident]['question'],'answer':items[ident]['answer'],**{f'rater_{i}_{field}':rr[ident][field] for i,rr in ((1,r1),(2,r2)) for field in FIELDS}})
        finals={ident:r1[ident] for ident in items if ident not in disagree}
        adjudicated={}
        if args.adjudication:
            state['source_files'][str(args.adjudication)]=sha(args.adjudication)
            aa=read_csv(args.adjudication)
            if len({x.get('item_id') for x in aa})!=len(aa):state['errors'].append('duplicate adjudication item')
            for row in aa:
                ident=row.get('item_id')
                if ident in disagree and complete(row,items[ident]) and row.get('evidence_note','').strip():adjudicated[ident]=row
        state['adjudicated_disagreement_items']=len(adjudicated);finals.update(adjudicated)
        if state['errors']:state['human_evaluation_status']='invalid_input'
        elif len(finals)!=768:
            state['human_evaluation_status']='adjudication_pending';state['pending_reason']='Agreement is available; final outcome statistics withheld until all scoring disagreements are human-adjudicated.'
        else:
            utility=defaultdict(list)
            for ident,row in finals.items():
                meta=mapping[ident]
                if meta['primary_eligible']:utility[(meta['case_id'],meta['direction'],meta['arm'])].append(0.0 if row['legal_score']=='NA' else float(row['legal_score']))
            project_values={arm:[sum(sum(utility[(p,d,arm)])/len(utility[(p,d,arm)]) for d in ('A_to_B','B_to_A'))/2 for p in projects] for arm in ARMS}
            effects=[]
            for arm in ('full_rebuild','selective'):
                differences=[a-b for a,b in zip(project_values[arm],project_values['raw'])]
                effects.append({'contrast':arm+'_minus_raw','mean_paired_project_difference':sum(differences)/len(differences),'ci95':bootstrap(differences,draws),'exact_two_sided_signflip_p':signflip(differences)})
            for effect,adj in zip(effects,holm([x['exact_two_sided_signflip_p'] for x in effects])):effect['holm_p_two_primary_contrasts']=adj
            class_results={}
            for arm in ARMS:
                perclass={}
                for label in LABELS:
                    vals=[];nknown=nall=0
                    for p in projects:
                        rr=[finals[i][label] for i,m in mapping.items() if m['case_id']==p and m['arm']==arm]
                        known=[int(x) for x in rr if x in {'0','1'}];nknown+=len(known);nall+=len(rr)
                        vals.append(sum(known)/len(known) if known else None)
                    available=[x for x in vals if x is not None]
                    perclass[label]={'project_mean_known_label_rate':sum(available)/len(available) if available else None,'ci95':bootstrap(vals,draws) if all(x is not None for x in vals) else None,'known_items':nknown,'all_items':nall,'projects_with_known_labels':len(available),'note':'descriptive; unknown labels excluded and reported, no zero-production-risk inference'}
                class_results[arm]=perclass
            unknown_legal=sum(items[i]['primary_eligible'] and finals[i]['legal_score']=='NA' for i in items)
            state['adjudicated_results']={'n_projects':12,'human_legal_utility':{arm:{'project_equal_mean':sum(v)/len(v),'project_bootstrap_ci95':bootstrap(v,draws),'values':dict(zip(projects,v))} for arm,v in project_values.items()},'human_unverifiable_legal_items_treated_as_zero_for_conservative_utility':unknown_legal,'known_label_class_rates':class_results,'primary_effects':effects,'plan':'pre-human-label plan after historical outcomes seen; not retrospective preregistration of original experiment','bootstrap_draws':5000,'bootstrap_seed':SEED,'unit':'project; methods, directions and questions kept together','signflip_assumption':'paired differences exchangeable/symmetric under null; limited synthetic projects, not production random sample'}
            state['human_evaluation_status']='complete'
    state['analysis_script_sha256']=sha(Path(__file__))
    (args.out/'human_evaluation_status.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in state.items() if k not in ['agreement','adjudicated_results','source_files']},ensure_ascii=False,indent=2))
    if state['human_evaluation_status']=='invalid_input':raise SystemExit(2)


if __name__=='__main__':main()
