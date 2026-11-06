"""Truthful static figures from the new protocol run; preserve every timing."""
import csv
import hashlib
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
RUN=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/protocol/protocol_run_20261106_v1'
PERF=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/protocol/protocol_perf_20261106_v2'
OUT=ROOT/'research_paper_v1/paper_live_v2/paper_figures'
METHODS=['plain_file','basic_integrity_acl','source_dynamic_version_no_tx','transaction_reference','complete_host']
COLORS=['#777777','#E69F00','#0072B2','#009E73','#CC79A7']
NAMES=['A File','B Static','C Nonatomic','D Transaction','E Host']


def write_csv(path,rows):
    with path.open('w',encoding='utf8',newline='')as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)


def export(fig,name,caption,alt,source):
    prefix=OUT/name
    for ext in ('png','pdf','svg'):fig.savefig(prefix.with_suffix('.'+ext),dpi=300,facecolor='white')
    plt.close(fig)
    (OUT/(name+'.json')).write_text(json.dumps({'caption':caption,'alt_text':alt,'source':source,
      'figure_code_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      'publisher_profile':'provisional manuscript figure; final journal checks pending','raw_exclusions':0,
      'software':{'matplotlib':matplotlib.__version__,'numpy':np.__version__}},ensure_ascii=False,indent=2)+'\n',encoding='utf8')


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    analysis=json.loads((RUN/'analysis.json').read_text(encoding='utf8'))
    stats={r['method']:r for r in analysis['attributes']}
    perf=[json.loads(line)for line in (PERF/'performance_raw.jsonl').read_text(encoding='utf8').splitlines()]
    source_rows=[]
    for m in METHODS:
        s=stats[m]
        source_rows.append({'method':m,'revoked_admissions':s['revoked_source']['admitted'],
          'stale_source_admissions':s['stale_source_version']['admitted'],'wrong_recipient_admissions':s['wrong_recipient']['admitted'],
          'forged_body_admissions':s['forged_body']['admitted'],'extra_duplicate_effects':s['duplicate_effects'],
          'confirmed_existing_commits':s['existing_commit_confirmations'],'confirmation_denominator':6,
          'fresh_recovery':int(s['safe_recoveries']-s['existing_commit_confirmations']),
          'fresh_recovery_denominator':1,'safe_recovery_total':s['safe_recoveries'],'safe_recovery_denominator':7})
    write_csv(OUT/'protocol_safety_recovery_source.csv',source_rows)
    timing_rows=[{'method':r['method'],'memory_count':r['memory_count'],'repetition':r['repetition'],
                 'host_processing_ms':r['host_processing_ns']/1e6,'retry_ms':r['recovery_attempt_ns']/1e6,
                 'retry_status':r['recovery_status'],'retry_without_new_effect':r['recovery_without_new_effect']}for r in perf]
    write_csv(OUT/'protocol_performance_source.csv',timing_rows)
    (OUT/'protocol_figure_source.json').write_text(json.dumps({'safety_recovery':source_rows,'performance':timing_rows,
      'source_run':str(RUN.relative_to(ROOT)),'source_performance':str(PERF.relative_to(ROOT)),
      'correction':'F22 invalid first effect excluded from duplicate effects per saved coding erratum'},ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    style={'font.family':'DejaVu Sans','font.size':9,'axes.spines.top':False,'axes.spines.right':False,
           'pdf.fonttype':42,'ps.fonttype':42,'svg.fonttype':'none','axes.labelsize':9}
    with plt.rc_context(style):
        fig,axes=plt.subplots(1,2,figsize=(9.2,3.9),layout='constrained')
        components=[('revoked_admissions','Revoked source','#D55E00','//'),('stale_source_admissions','Stale source','#0072B2','..'),
                    ('wrong_recipient_admissions','Wrong receiver','#009E73','xx'),('forged_body_admissions','Forged body','#CC79A7','++')]
        bottoms=np.zeros(5)
        for key,label,color,hatch in components:
            values=np.array([r[key]for r in source_rows]);axes[0].bar(np.arange(5),values,bottom=bottoms,label=label,color=color,edgecolor='black',linewidth=.4,hatch=hatch);bottoms+=values
        for x,total in enumerate(bottoms):axes[0].text(x,total+.15,str(int(total)),ha='center')
        axes[0].set(title='a  Contract-invalid first acceptance',ylabel='Targeted cases (24 per method)',ylim=(0,10),xticks=np.arange(5),xticklabels=NAMES)
        axes[0].legend(fontsize=7,loc='upper right');axes[0].tick_params(axis='x',rotation=25)
        values=[r['extra_duplicate_effects']for r in source_rows]
        axes[1].bar(np.arange(5),values,color=COLORS,edgecolor='black',linewidth=.5)
        for i,v in enumerate(values):axes[1].text(i,v+.15,str(v),ha='center')
        axes[1].set(title='b  Additional duplicate effects',ylabel='Effects beyond legitimate operation count',ylim=(0,11),xticks=np.arange(5),xticklabels=NAMES)
        axes[1].tick_params(axis='x',rotation=25)
        export(fig,'protocol_safety','New model-free protocol runs. Panel a separates different invalid-acceptance attributes; these are not all sensitive-information leaks. Panel b excludes the F22 expected-zero first violation from duplicate counts. D and E share the mature verifier. Fixed targeted cases, no production-rate inference.',
               'A has eight invalid first acceptances and nine duplicate effects; B seven and nine; C one and zero; D and E zero and zero.',
               ['protocol_safety_recovery_source.csv','protocol_figure_source.json'])
        fig,axes=plt.subplots(1,2,figsize=(9.2,3.6),layout='constrained')
        for ax,key,den,title in [(axes[0],'confirmed_existing_commits',6,'a  Existing-commit metadata confirmation'),(axes[1],'fresh_recovery',1,'b  Fresh retry after pre-COMMIT crash')]:
            values=[r[key]for r in source_rows];ax.bar(np.arange(5),values,color=COLORS,edgecolor='black',linewidth=.5)
            for i,v in enumerate(values):ax.text(i,v+.05*den,f'{v}/{den}',ha='center')
            ax.set(title=title,ylabel='Successful targeted recovery cases',ylim=(0,den*1.23),xticks=np.arange(5),xticklabels=NAMES)
            ax.tick_params(axis='x',rotation=25);ax.set_yticks(range(den+1))
        export(fig,'protocol_recovery','Six cases already contain a durable effect and require metadata confirmation. F19 has no prior effect and requires one fresh retry. Safe recovery totals are 1/7 for A/B/C and 7/7 for D/E; do not call all seven metadata confirmations.',
               'D and E confirm six of six existing commits; A, B and C confirm none. All five configurations complete the one fresh retry after a precommit crash.',
               ['protocol_safety_recovery_source.csv','protocol_figure_source.json'])
        fig,axes=plt.subplots(1,3,figsize=(11.1,3.8),layout='constrained',sharey=True)
        for ax,size in zip(axes,(1,8,32)):
            for i,(method,color)in enumerate(zip(METHODS,COLORS)):
                values=[r['host_processing_ns']/1e6 for r in perf if r['method']==method and r['memory_count']==size]
                assert len(values)==8
                jitter=np.linspace(-.13,.13,len(values))
                ax.scatter(i+jitter,values,s=24,color=color,edgecolor='black',linewidth=.35,alpha=.85)
                ax.scatter([i],[np.median(values)],marker='D',s=30,color='black',zorder=4)
            ax.set_yscale('log');ax.set(title=f'{size} memory/source bindings',xticks=np.arange(5),xticklabels=['A','B','C','D','E'],xlabel='Protocol configuration')
            ax.grid(axis='y',which='major',alpha=.22)
        axes[0].set_ylabel('Prepared-packet receiver processing (ms; log scale)')
        export(fig,'protocol_performance','All 120 new local first-operation measurements (eight technical repetitions per cell); deterministic horizontal jitter only, black diamonds mark medians. Log axis preserves the long-tail B one-binding sample. Connections are preopened and packages prepared; clocks and tracemalloc add measurement overhead. Technical repetitions are not independent business projects.',
               'Three panels show all A–E timings for one, eight and thirty-two bindings, including the unusually slow static-ACL observation. D/E medians are similar with no speed-superiority claim.',
               ['protocol_performance_source.csv','protocol_figure_source.json'])
    print(json.dumps({'figures':3,'formats':['png','pdf','svg'],'timing_points':len(perf),'source_tables':2,'out':str(OUT)},ensure_ascii=False))


if __name__=='__main__':main()
