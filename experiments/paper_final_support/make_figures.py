"""Render eight evidence-linked figures; never fabricate missing measurements."""
import csv
import hashlib
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research_paper_v1/paper_final/figures'
CPU=ROOT/'research_paper_v1/paper_final/evidence/cpu/run_20261106_v2'
PERF=ROOT/'research_paper_v1/paper_final/evidence/cpu/run_20261106_perf_v3'
COLORS=['#0072B2','#D55E00','#009E73','#CC79A7']
MAIN=['plain_file','basic_integrity_acl','transaction_reference','complete_host']
NAMES=['File handoff','Basic hash + ACL','Transaction reference','Complete Host']
MANIFEST=[]


def save(fig,stem,caption,sources):
    OUT.mkdir(parents=True,exist_ok=True)
    for suffix in ['png','pdf','svg']:
        fig.savefig(OUT/(stem+'.'+suffix),dpi=250,facecolor='white')
    MANIFEST.append({'figure':stem,'caption':caption,'sources':sources})
    plt.close(fig)


def box(ax,x,y,w,h,text,color='#E7F1F8'):
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.01',facecolor=color,edgecolor='#303030',linewidth=.8))
    ax.text(x+w/2,y+h/2,text,ha='center',va='center',fontsize=9)


def arrow(ax,a,b,text=None):
    ax.annotate('',xy=b,xytext=a,arrowprops={'arrowstyle':'->','lw':1.2,'color':'#303030'})
    if text: ax.text((a[0]+b[0])/2,(a[1]+b[1])/2+.02,text,fontsize=8,ha='center')


def diagrams():
    fig,ax=plt.subplots(figsize=(10,4.7));ax.set(xlim=(0,1),ylim=(0,1));ax.axis('off')
    nodes=[(.02,.67,.21,.18,'WorkBuddy HY3\ntrusted adapter'),(.02,.19,.21,.18,'Harness Flash\ntrusted adapter'),
           (.33,.43,.22,.2,'Staging + seal\nregistered lineage'),(.68,.7,.27,.17,'Policy SQLite\ngrants / epoch / nonce'),
           (.67,.39,.29,.2,'Receiver transaction\nvalidate + write + consume'),(.68,.08,.27,.17,'Receiver SQLite\nbatch / body / audit')]
    for x,y,w,h,t in nodes:box(ax,x,y,w,h,t)
    arrow(ax,(.23,.76),(.33,.55));arrow(ax,(.23,.28),(.33,.47));arrow(ax,(.55,.53),(.67,.49))
    arrow(ax,(.8,.7),(.8,.59));arrow(ax,(.81,.39),(.81,.25));arrow(ax,(.68,.15),(.23,.22),'read-only reopen / model input')
    ax.set_title('1. Host-mediated architecture',loc='left');ax.text(.02,.97,'Code-derived architecture; no product-internal memory access claimed.',fontsize=9)
    save(fig,'fig01_architecture','Actual code-derived architecture. Both commercial endpoints use Host-owned stores.', ['experiments/persistent_exchange_v1/store.py','experiments/persistent_exchange_v1/run_study.py'])
    fig,ax=plt.subplots(figsize=(10,4));ax.set(xlim=(0,1),ylim=(0,1));ax.axis('off')
    labels=['Generate','Stage','Verify lineage','Prepare seal','Final validate','COMMIT','ACK']
    xs=np.linspace(.02,.86,7)
    for x,t in zip(xs,labels):box(ax,x,.58,.12,.16,t,'#E6F4EF' if t=='COMMIT' else '#E7F1F8')
    for i in range(6):arrow(ax,(xs[i]+.12,.66),(xs[i+1],.66))
    box(ax,.58,.15,.37,.19,'ACK unknown: verify identical durable commit\nreturn metadata only (new adapter)','#FFF1DA')
    arrow(ax,(xs[5]+.06,.58),(.76,.34));arrow(ax,(.94,.34),(.94,.58))
    ax.text(.02,.36,'First delivery linearizes at COMMIT.\nReceiving a packet and receiving an ACK are different events.',fontsize=10)
    ax.set_title('2. Delivery lifecycle and confirmation recovery',loc='left')
    save(fig,'fig02_lifecycle','Code-derived lifecycle. Recovery is the current extension; the legacy core only rejects replay.', ['research_paper_v1/paper_final/security_model.md','experiments/paper_final_v1/durable_delivery.py'])
    fig,axes=plt.subplots(2,1,figsize=(10,4.4),layout='constrained')
    for ax in axes:ax.set(xlim=(0,10),ylim=(0,1));ax.axis('off');ax.annotate('',xy=(9.7,.5),xytext=(.3,.5),arrowprops={'arrowstyle':'->','color':'black'})
    for ax,items in zip(axes,[[(1,'Generate'),(3,'Seal e'),(5,'Revoke commits'),(8,'Import rejects')],[(1,'Generate'),(3,'Seal e'),(5,'Import commits'),(8,'Revoke commits')]]):
        for x,t in items:ax.plot(x,.5,'o',color='#0072B2');ax.text(x,.68,t,ha='center',fontsize=10)
    axes[0].text(.3,.12,'Revocation before first COMMIT: no acceptance.',fontsize=10)
    axes[1].text(.3,.12,'First COMMIT before revocation: valid past delivery; retry confirms metadata only.',fontsize=10)
    fig.suptitle('3. Authorization follows commit order, not RPC start order',x=.02,ha='left')
    save(fig,'fig03_revocation_timing','Contract sequence diagram, not simulated timing measurements.', ['experiments/persistent_exchange_v1/store.py','research_paper_v1/paper_final/security_model.md'])


def results():
    run=json.loads((CPU/'qualification_summary.json').read_text(encoding='utf8'))
    rows=[json.loads(s) for s in (CPU/'raw.jsonl').read_text(encoding='utf8').splitlines()]
    summaries={r['method']:r for r in run['summary']}
    properties=[('Authorization preservation','F01 / F02 / F03 / F12'),('Registered binding integrity','F15 / F21'),('Replay resistance','F08 / F09'),
                ('Receiver acceptance integrity','F14 / F16 / F21'),('Revocation consistency','F02 / F04 / F13'),('Idempotent delivery / recovery','F05 / F06 / F07 / F08 / F17 / F19'),('Auditability','Persisted event + batch binding')]
    fig,ax=plt.subplots(figsize=(10,3.8));ax.axis('off')
    table=ax.table(cellText=properties,colLabels=['Contract property','Concrete evidence / targeted cases'],loc='center',cellLoc='left',colWidths=[.36,.64]);table.auto_set_font_size(False);table.set_fontsize(10);table.scale(1,1.9)
    ax.set_title('4. Property-to-test coverage (specification, not a security score)',loc='left')
    save(fig,'fig04_property_coverage','Mapping of bounded properties to tests. This is a coverage specification; no empirical percentage or general proof is implied.', ['research_paper_v1/paper_final/security_model.md',str((CPU/'config.json').relative_to(ROOT))])
    fig,axes=plt.subplots(1,2,figsize=(10,4),layout='constrained')
    for ax,key,title in zip(axes,['unauthorized_case_count','duplicate_effects'],['Contract-invalid first acceptance cases','Additional duplicate acceptance effects']):
        vals=[summaries[m][key] for m in MAIN];bars=ax.bar(np.arange(4),vals,color=COLORS,edgecolor='black',linewidth=.6)
        for b,v in zip(bars,vals):ax.text(b.get_x()+b.get_width()/2,v+.15,str(v),ha='center')
        ax.set_xticks(np.arange(4),['File','Basic','Txn ref.','Host']);ax.set_ylim(0,max(vals+[1])*1.3);ax.set_title(title,fontsize=10);ax.set_ylabel('Observed count')
    fig.suptitle('5. Targeted fault outcomes; counts are not production attack rates',x=.02,ha='left')
    save(fig,'fig05_security_results','Observed targeted case counts, not production rates. The first metric combines revoked access, stale sources, wrong receivers and forged content; it is not solely a sensitive-disclosure metric. Mature reference and Host have equal safeguards.', [str((CPU/'raw.jsonl').relative_to(ROOT)),str((CPU/'qualification_summary.json').relative_to(ROOT))])
    old=ROOT/'benchmarks/persistent_exchange_v1_public_20261105/evaluation_report.public.json';e=json.loads(old.read_text(encoding='utf8'))
    arms=['raw','whole_drop','full_rebuild','selective'];labels=['Legal raw','Whole drop','Full rebuild','Fixed selective'];fig,ax=plt.subplots(figsize=(8.3,4.5),layout='constrained')
    underlying=[]
    for i,(arm,color) in enumerate(zip(arms,COLORS)):
        vals=[r['legal_utility']*100 for r in e['per_project'] if r['arm']==arm]
        jit=np.linspace(-.11,.11,len(vals));ax.scatter(np.repeat(i,len(vals))+jit,vals,s=29,color=color,alpha=.7,edgecolor='black',linewidth=.4)
        ax.scatter(i,np.mean(vals),marker='D',s=80,color=color,edgecolor='black',zorder=4)
        ax.text(i,np.mean(vals)+4,f'{np.mean(vals):.2f}%',ha='center',fontsize=10)
        underlying.extend({'arm':arm,'case_id':r['case_id'],'legal_utility_percent':r['legal_utility']*100} for r in e['per_project'] if r['arm']==arm)
    ax.set_xticks(range(4),labels);ax.set(ylim=(-3,112),ylabel='Legal task utility (%)',title='6. Historical real-model utility: 12 synthetic project clusters');ax.text(.01,-.19,'Dots: project scores averaged over two directions. Diamonds: project means. Frozen lexical scoring.',transform=ax.transAxes,fontsize=9)
    save(fig,'fig06_legal_utility','All 12 project points per method are shown; no independent n=768 claim or semantic-human accuracy is implied. Existing paired contrast intervals are reported in the manuscript.', [str(old.relative_to(ROOT))])
    with (OUT/'fig06_source.csv').open('w',encoding='utf8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(underlying[0]));w.writeheader();w.writerows(underlying)
    methods=MAIN+['legacy_host'];fig,ax=plt.subplots(figsize=(8.3,4.4),layout='constrained')
    for i,m in enumerate(methods):
        s=summaries[m];v=s['recovery_confirmed'];den=s['recovery_evaluable'];ax.bar(i,v,color=(COLORS+["#777777"])[i],edgecolor='black');ax.text(i,v+.13,f'{v}/{den}',ha='center')
    ax.set_xticks(range(5),['File','Basic','Txn ref.','Host + recovery','Legacy Host']);ax.set(ylabel='Safe recovery with correct disk effects',title='7. Recovery is stricter than returning a success response');ax.set_ylim(0,max(summaries[m]['recovery_evaluable'] for m in methods)+1)
    save(fig,'fig07_recovery','Five cases require confirmation of an existing commit; one requires a fresh retry after a precommit crash. Safe recovery requires correct disk effects, not only a success response. The raw field recovery_confirmed encodes this six-case composite.', [str((CPU/'raw.jsonl').relative_to(ROOT)),str((CPU/'qualification_summary.json').relative_to(ROOT))])
    perf=[json.loads(s) for s in (PERF/'performance_raw.jsonl').read_text(encoding='utf8').splitlines()]
    for r in perf:r['host_processing_ms']=r['host_processing_ns']/1e6
    # Discover the documented timing key explicitly; fail if measurements are absent.
    key=next((k for k in ['host_processing_ms','host_total_ms','total_ms','elapsed_ms'] if k in perf[0]),None)
    if key is None: raise RuntimeError('performance timing key must be reviewed: '+str(list(perf[0])))
    sizekey=next((k for k in ['memory_count','sources','source_count','n','size','n_sources'] if k in perf[0]),None)
    if sizekey is None:raise RuntimeError('performance size key must be reviewed')
    sizes=sorted({r[sizekey] for r in perf});fig,axes=plt.subplots(1,len(sizes),figsize=(10,4),layout='constrained',sharey=True)
    for ax,n in zip(np.atleast_1d(axes),sizes):
        for i,m in enumerate(MAIN):
            vals=[r[key] for r in perf if r['method']==m and r[sizekey]==n]
            ax.scatter(np.repeat(i,len(vals))+np.linspace(-.1,.1,len(vals)),vals,s=15,color=COLORS[i],alpha=.6)
            ax.plot([i-.18,i+.18],[np.median(vals)]*2,color='black',lw=2)
        ax.set_xticks(range(4),['File','Basic','Txn','Host']);ax.set_title(f'{n} memory/source bindings');ax.set_yscale('log')
    axes[0].set_ylabel('Local Host processing (ms; log scale)');fig.suptitle('8. All technical repetitions, including observed long tails',x=.02,ha='left')
    save(fig,'fig08_overhead','All 12 technical repetitions and medians at each size/method. Logarithmic y-axis preserves long-tail observations. Connections are preopened and packets prepared before timing; provider time excluded. Phase timings and absent-phase zero codes are defined in performance report.', [str((PERF/'performance_raw.jsonl').relative_to(ROOT))])


def main():
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'pdf.fonttype':42,'svg.fonttype':'none','axes.spines.top':False,'axes.spines.right':False})
    diagrams();results()
    (OUT/'figure_manifest.json').write_text(json.dumps({'scope':'provisional manuscript figures, no journal compliance certification','style':'color plus labels; white background; all numerical data from frozen records','figures':MANIFEST},indent=2)+'\n',encoding='utf8')
    (OUT/'captions.md').write_text('# Figure captions\n\n'+'\n\n'.join('**'+x['figure']+'**. '+x['caption'] for x in MANIFEST)+'\n',encoding='utf8')
    print(json.dumps({'figures':len(MANIFEST),'formats':['png','pdf','svg']}))


if __name__=='__main__':main()
