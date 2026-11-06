"""Project-paired analysis of stage-2 CPU qualification (no new experiments)."""
from __future__ import annotations

import csv
import hashlib
import itertools
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[3]
STAGE = ROOT / 'research_paper_v1/stage2_evidence_gap'
EVIDENCE = STAGE / 'evidence'
METRICS = ('tool_requests','returned_rows','evidence_bytes','verification_operations',
           'cost_units','latency_seconds','total_wall_seconds','planning_seconds','source_reads')
METHODS = ('fail_closed','full_reaudit','set_difference','cheapest_path_union',
           'simple_setdiff_batch','weighted_greedy','exact_dp')
REGIMES = ('singleton','partition','overlap','universal_batch')
LABELS = ('Fail closed','Full audit','Set difference','Cheap-path union',
          'Simple bulk','Weighted greedy','Exact DP')


def dump(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')


def quantiles(values):
    values=np.asarray(values,dtype=float)
    return {name:float(v) for name,v in zip(('min','q25','median','q75','max'),np.percentile(values,[0,25,50,75,100]))}


def paired(a,b,indices):
    a=np.asarray(a,dtype=float);b=np.asarray(b,dtype=float);delta=a-b
    boot=delta[indices].mean(axis=1)
    baseline=float(b.mean())
    # The exact sign-flip test is conditional on exchangeability under the null;
    # it is not evidence of random assignment to a population of real businesses.
    observed=abs(float(delta.mean()))
    flips=np.asarray(list(itertools.product((-1,1),repeat=len(delta))),dtype=float)
    permuted=np.abs((flips*delta).mean(axis=1))
    p=float(np.mean(permuted>=observed-1e-12))
    return {'n_projects':len(a),'candidate_mean':float(a.mean()),'baseline_mean':baseline,
            'mean_difference_candidate_minus_baseline':float(delta.mean()),
            'paired_bootstrap95':np.percentile(boot,[2.5,97.5]).tolist(),
            'relative_reduction':(baseline-float(a.mean()))/baseline if baseline else None,
            'exact_sign_flip_p_two_sided':p,
            'projects_lower':int(np.sum(delta<0)), 'projects_equal':int(np.sum(delta==0)),
            'projects_higher':int(np.sum(delta>0)),
            'project_differences':delta.tolist(), 'difference_distribution':quantiles(delta)}


def holm(results):
    order=sorted(range(len(results)),key=lambda i:results[i]['effect']['exact_sign_flip_p_two_sided'])
    maximum=0.0
    for rank,i in enumerate(order):
        maximum=max(maximum,min(1.0,(len(results)-rank)*results[i]['effect']['exact_sign_flip_p_two_sided']))
        results[i]['effect']['holm_adjusted_p']=maximum


def main():
    allrows=[];inputs=[]
    for split in ('development','heldout'):
        path=EVIDENCE/f'raw_{split}.jsonl'
        rows=[json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
        assert all(r['split']==split for r in rows)
        allrows.extend(rows)
        inputs.append({'path':path.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'rows':len(rows)})
    cfg=json.loads((EVIDENCE/'config.json').read_text(encoding='utf-8'))
    mainrows=[r for r in allrows if r['budget_units']==cfg['main_budget_units']]
    keys=[(r['project_id'],r['regime'],r['scenario'],r['method'],r['budget_units']) for r in allrows]
    assert len(keys)==len(set(keys)), 'duplicate arm rows'
    projects=sorted({r['project_id'] for r in mainrows})
    assert len(projects)==24
    for project in projects:
        rows=[r for r in mainrows if r['project_id']==project]
        assert len(rows)==len(REGIMES)*len(METHODS)*len(cfg['scenarios']),project
    grouped=defaultdict(list)
    for row in mainrows:grouped[(row['split'],row['project_id'],row['regime'],row['method'])].append(row)
    projectrows=[]
    for (split,project,regime,method),rows in sorted(grouped.items()):
        out={'split':split,'project_id':project,'regime':regime,'method':method,'scenarios':len(rows)}
        out.update({metric:float(np.mean([r[metric] for r in rows])) for metric in METRICS})
        for metric in ('unauthorized_releases','false_allows','missing_tp','missing_fp','missing_fn',
                       'recoverable_memories','recovered_legal_memories','forbidden_memories','permission_forbidden_memories'):
            out[metric]=sum(r[metric] for r in rows)
        out['legal_recovery_rate']=out['recovered_legal_memories']/out['recoverable_memories'] if out['recoverable_memories'] else None
        out['localization_precision']=out['missing_tp']/(out['missing_tp']+out['missing_fp']) if out['missing_tp']+out['missing_fp'] else None
        out['localization_recall']=out['missing_tp']/(out['missing_tp']+out['missing_fn']) if out['missing_tp']+out['missing_fn'] else None
        projectrows.append(out)
    with (EVIDENCE/'project_metrics.csv').open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(projectrows[0]));writer.writeheader();writer.writerows(projectrows)
    summaries=[]
    for split in ('development','heldout'):
        for regime in REGIMES:
            for method in METHODS:
                rows=[r for r in projectrows if (r['split'],r['regime'],r['method'])==(split,regime,method)]
                metric_summary={k:{'mean':float(np.mean([r[k] for r in rows])),**quantiles([r[k] for r in rows])} for k in METRICS}
                summaries.append({'split':split,'regime':regime,'method':method,'n_projects':len(rows),
                                  'resources':metric_summary,
                                  'legal_recovery_mean':float(np.mean([r['legal_recovery_rate'] for r in rows if r['legal_recovery_rate'] is not None])),
                                  'unauthorized_releases':sum(r['unauthorized_releases'] for r in rows),
                                  'false_allows':sum(r['false_allows'] for r in rows)})
    held=sorted({r['project_id'] for r in projectrows if r['split']=='heldout'})
    rng=np.random.default_rng(202611052)
    indices=rng.integers(0,len(held),size=(10000,len(held)))
    def values(method,regime,metric):
        lookup={r['project_id']:r[metric] for r in projectrows if (r['split'],r['regime'],r['method'])==('heldout',regime,method)}
        return [lookup[p] for p in held]
    primary=[]
    for regime,baseline in [(r,'cheapest_path_union') for r in REGIMES]+[('universal_batch','simple_setdiff_batch')]:
        effect=paired(values('weighted_greedy',regime,'tool_requests'),values(baseline,regime,'tool_requests'),indices)
        recovery_diff=np.asarray(values('weighted_greedy',regime,'legal_recovery_rate'))-np.asarray(values(baseline,regime,'legal_recovery_rate'))
        primary.append({'regime':regime,'candidate':'weighted_greedy','baseline':baseline,'metric':'tool_requests',
                        'effect':effect,'project_recovery_losses':int(np.sum(recovery_diff< -1e-12)),
                        'passes_resource_screen':bool(effect['relative_reduction'] is not None and effect['relative_reduction']>=0.2 and effect['paired_bootstrap95'][1]<0 and not np.any(recovery_diff< -1e-12))})
    holm(primary)
    secondary=[]
    for regime in REGIMES:
        for baseline in ('full_reaudit','set_difference','cheapest_path_union','simple_setdiff_batch','exact_dp'):
            for metric in ('tool_requests','evidence_bytes','cost_units','latency_seconds'):
                result=paired(values('weighted_greedy',regime,metric),values(baseline,regime,metric),indices)
                result.pop('exact_sign_flip_p_two_sided')
                secondary.append({'regime':regime,'candidate':'weighted_greedy','baseline':baseline,'metric':metric,
                                  'status':'exploratory descriptive contrast, no confirmatory p-value', 'effect':result})
    byscenario=[]
    for regime in REGIMES:
        for scenario in cfg['scenarios']:
            for method in METHODS:
                rows=[r for r in mainrows if (r['split'],r['regime'],r['scenario'],r['method'])==('heldout',regime,scenario,method)]
                byscenario.append({'regime':regime,'scenario':scenario,'method':method,'projects':len(rows),
                                   'requests_mean':float(np.mean([r['tool_requests'] for r in rows])),
                                   'bytes_mean':float(np.mean([r['evidence_bytes'] for r in rows])),
                                   'modeled_cost_mean':float(np.mean([r['cost_units'] for r in rows])),
                                   'eligible':sum(r['recoverable_memories'] for r in rows),'recovered':sum(r['recovered_legal_memories'] for r in rows)})
    tightrows=[r for r in allrows if r['budget_units']!=cfg['main_budget_units']]
    tight=[]
    for regime in REGIMES:
        for method in METHODS:
            rows=[r for r in tightrows if (r['regime'],r['method'])==(regime,method)]
            tight.append({'regime':regime,'method':method,'rows':len(rows),'n_projects':len({r['project_id'] for r in rows}),
                          'requests':sum(r['tool_requests'] for r in rows),'cost_units':sum(r['cost_units'] for r in rows),
                          'eligible':sum(r['recoverable_memories'] for r in rows),'recovered':sum(r['recovered_legal_memories'] for r in rows)})
    report={'schema':'stage2-project-paired-analysis-v1','inputs':inputs,'independent_unit':'synthetic project, conditional on generator',
            'development_n':12,'heldout_n':12,'main_arm_rows':len(mainrows),'tight_arm_rows':len(tightrows),
            'bootstrap':{'n':10000,'seed':202611052,'level':'paired project','interval':'95% percentile'},
            'primary_family':'5 predeclared comparisons, two-sided exact project sign-flip, Holm',
            'primary':primary,'summaries':summaries,'exploratory_secondary':secondary,
            'heldout_scenario_summaries':byscenario,'tight_budget_descriptive':tight,
            'safety_counts':{k:sum(r[k] for r in mainrows) for k in ('unauthorized_releases','false_allows','missing_fp','missing_fn')},
            'denominators_by_method':[
                {'split':split,'method':method,'arm_rows':len(rows),
                 'attempted_memory_decisions':sum(len(r['decisions']) for r in rows),
                 **{k:sum(r[k] for r in rows) for k in ('permission_forbidden_memories','forbidden_memories',
                    'recoverable_memories','recovered_legal_memories','unauthorized_releases','false_allows')}}
                for split in ('development','heldout') for method in METHODS
                for rows in [[r for r in mainrows if (r['split'],r['method'])==(split,method)]]],
            'notes':['Zero measured violations are not a production zero-risk guarantee.',
                     'Holdout seeds are new synthetic graphs, not external business replication.',
                     'Synthetic cost_units are not measured money; local latency is not remote supplier latency.',
                     'All failure/unknown cases retained; fail_closed low cost is read alongside low recovery.',
                     'Repeated diagnosis rows across methods are not independent detection samples.']}
    dump(EVIDENCE/'statistical_results.json',report)
    figdir=STAGE/'figures';figdir.mkdir(exist_ok=True)
    colors=['#777777','#0072B2','#E69F00','#009E73','#56B4E9','#D55E00','#CC79A7']
    matplotlib.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'pdf.fonttype':42,'svg.fonttype':'none'})
    fig,axes=plt.subplots(2,2,figsize=(12,7.5),layout='constrained')
    figure_data=[]
    for ax,regime in zip(axes.flat,REGIMES):
        for i,method in enumerate(METHODS):
            points=values(method,regime,'tool_requests')
            mean=float(np.mean(points));ci=np.percentile(np.asarray(points)[indices].mean(axis=1),[2.5,97.5])
            ax.scatter(np.arange(len(points))*0.012+i-0.066,points,s=12,color=colors[i],alpha=0.7,marker='o')
            ax.errorbar(i,mean,yerr=[[mean-ci[0]],[ci[1]-mean]],fmt='D',color='black',capsize=3,markersize=4)
            figure_data.extend({'project_id':p,'regime':regime,'method':method,'requests':v} for p,v in zip(held,points))
        ax.set(title=regime.replace('_',' '),ylabel='Receipt-fetch requests per scenario',xticks=range(7),xticklabels=LABELS,ylim=(0,None))
        ax.tick_params(axis='x',rotation=28);ax.grid(axis='y',alpha=0.2)
    fig.suptitle('Held-out synthetic projects: request counts (12 projects; paired scenario means)')
    for ext in ('png','pdf'):fig.savefig(figdir/f'request_counts.{ext}',dpi=240,facecolor='white')
    plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(11,4.5),layout='constrained')
    for i,regime in enumerate(REGIMES):
        vals=[next(r for r in summaries if (r['split'],r['regime'],r['method'])==('heldout',regime,m)) for m in METHODS]
        axes[0].plot(range(7),[r['legal_recovery_mean'] for r in vals],marker=('o','s','^','D')[i],label=regime.replace('_',' '))
        axes[1].plot(range(7),[r['resources']['evidence_bytes']['mean']/1024 for r in vals],marker=('o','s','^','D')[i],label=regime.replace('_',' '))
    for ax in axes:
        ax.set(xticks=range(7),xticklabels=LABELS);ax.tick_params(axis='x',rotation=28);ax.grid(axis='y',alpha=0.2)
    axes[0].set(ylabel='Reference-eligible memory recovery',ylim=(0,1.05));axes[0].legend(fontsize=8)
    axes[1].set(ylabel='Returned evidence KiB per scenario',ylim=(0,None))
    fig.suptitle('Function and transferred evidence: equal project weights, main budget')
    for ext in ('png','pdf'):fig.savefig(figdir/f'recovery_and_bytes.{ext}',dpi=240,facecolor='white')
    plt.close(fig)
    dump(EVIDENCE/'figure_source_data.json',{'request_counts':figure_data,'source':'project_metrics.csv','other_panels':'statistical_results.json summaries'})
    dump(figdir/'figure_manifest.json',{'audience':'internal qualification, not submission-specific',
         'formats':['png','pdf'],'dpi':240,'request_figure_inches':[12,7.5],'recovery_figure_inches':[11,4.5],
         'uncertainty':'request diamonds=project mean, whiskers=95% project bootstrap; points=12 heldout projects',
         'recovery_bytes_panels':'descriptive project means; no hypothesis tests encoded',
         'matplotlib':matplotlib.__version__,'numpy':np.__version__,
         'alt_text':'Four panels compare actual receipt-fetch requests by method and interface; separate panels show recovery and returned evidence so zero-request refusal is not mistaken for superior recovery.',
         'source_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    print(json.dumps({'main_rows':len(mainrows),'tight_rows':len(tightrows),'safety':report['safety_counts'],'primary':primary},ensure_ascii=False))


if __name__=='__main__':main()
