"""Figures from saved data only; no model or protocol rerun."""
import csv,hashlib,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from .live_runtime import OUT

def load(p):return json.loads(p.read_text(encoding='utf-8'))
def main():
    dst=OUT/'paper_figures';dst.mkdir(exist_ok=True)
    qpath=OUT/'raw_experiment_data/evaluation/quality_summary.json';q=load(qpath)
    spath=OUT/'raw_experiment_data/source_evaluation/source_summary.json';s=load(spath)
    lpath=OUT/'raw_experiment_data/live_summary.json';l=load(lpath)
    fpath=OUT/'same_family_control/final_audit.json';f=load(fpath)
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False,'pdf.fonttype':42,'svg.fonttype':'none'})
    figures=[]
    def output(fig,name,data,caption):
        for ext in ('png','pdf','svg'):fig.savefig(dst/(name+'.'+ext),dpi=300)
        plt.close(fig)
        record={'name':name,'caption':caption,'data':data,
                'sources':{str(p.relative_to(OUT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (qpath,spath,lpath,fpath)}}
        (dst/(name+'.json')).write_text(json.dumps(record,indent=2),encoding='utf-8');figures.append(record)
    scenarios=['raw','summary','multi_source'];projects=sorted(q['scenario_utility']['raw']['project_values'])
    errors=np.array([[round(18*(1-q['scenario_utility'][sc]['project_values'][pid])) for sc in scenarios] for pid in projects])
    fig,ax=plt.subplots(figsize=(6.6,4.6),layout='constrained')
    ax.imshow(errors,cmap='Oranges',vmin=0,vmax=2,aspect='auto')
    ax.set(xticks=range(3),xticklabels=['Factual restatement','Summary','Multi-source'],yticks=range(10),yticklabels=[p.replace('LIVE-','') for p in projects],title='Reference mismatches in legal answers')
    for i in range(10):
        for j in range(3):ax.text(j,i,f'{errors[i,j]}/18',ha='center',va='center')
    fig.supxlabel('10 project clusters; directions and repetitions averaged within project')
    output(fig,'live_legal_quality',{'projects':projects,'representations':scenarios,'incorrect_legal_fields_per_18':errors.tolist()},
        'Frozen-reference mismatches, not a count of adjudicated factual errors. One date calculation is wrong; P09 pricing wording remains ambiguous. Each project contributes 18 legal fields per representation. AI evaluation, no human labels. The exact-original control separately scores 180/180 legal fields.')
    initial=[s['groups']['initial_generation.'+sc]['actual_sensitive_payload_hits'] for sc in scenarios]
    legal=[s['groups']['legal_rebuild.'+sc]['actual_sensitive_payload_hits'] for sc in scenarios]
    fig,ax=plt.subplots(figsize=(6.6,3.8),layout='constrained');x=np.arange(3)
    ax.bar(x-.18,initial,.36,color='#D55E00',hatch='//',label='Initial artifact: token present')
    ax.bar(x-.18,60-np.array(initial),.36,bottom=initial,color='#DDDDDD',edgecolor='black',label='Initial artifact: token absent')
    ax.bar(x+.22,legal,.28,color='#0072B2',hatch='xx',label='Legal successor: token present')
    for i,(a,b) in enumerate(zip(initial,legal)):
        ax.text(i-.18,a/2,f'{a}/60',ha='center',va='center',color='white')
        ax.text(i+.22,1.5,f'{b}/60',ha='center')
    ax.set(xticks=x,xticklabels=['Restatement','Summary','Multi-source'],ylim=(0,75),ylabel='Generated texts',title='Controlled audit token and conservative source scope')
    ax.legend(fontsize=8,loc='upper center',bbox_to_anchor=(.5,1.02),ncol=1)
    output(fig,'live_controlled_token',{'representations':scenarios,'initial_exact_token_present':initial,'legal_exact_token_present':legal,'denominator_each':60},
        'All 180 initial artifacts have a revoked source in the recorded input scope, but 16 do not contain its exact audit token. A/B initially persist these artifacts; C/D/E block them. No successor contains the controlled token. Exact token absence does not prove universal semantic noninterference.')
    values=[(l['platforms']['hy3']['strict_raw_json_valid'],240),(l['platforms']['flash']['strict_raw_json_valid'],240),
        (f['platform_results']['workbuddy_flash']['strict_schema_success'],10),(f['platform_results']['harness_flash']['strict_schema_success'],10)]
    fig,ax=plt.subplots(figsize=(7.0,4.0),layout='constrained')
    x=np.arange(4);rates=[100*a/b for a,b in values]
    bars=ax.bar(x,rates,color=['#0072B2','#E69F00','#0072B2','#E69F00'],edgecolor='black')
    for i,bar in enumerate(bars):
        bar.set_hatch('//');a,b=values[i];ax.text(i,rates[i]+2,f'{a}/{b}',ha='center')
    ax.set(xticks=x,xticklabels=['WB Hy3\nMain tasks','Harness Flash\nMain tasks','WB Flash\nPaired QA','Harness Flash\nPaired QA'],ylim=(0,112),ylabel='Strict raw JSON (%)',title='Original format failures remain visible after recovery')
    output(fig,'live_raw_format',{'groups':['WB_Hy3_main','Harness_Flash_main','WB_Flash_paired','Harness_Flash_paired'],'valid_numerator_denominator':values},
        'Raw JSON means the complete original assistant output parses as JSON, without stripping fences or redundant braces. Counts are inference outputs, not independent projects. Main tasks include generation and reception; paired QA uses identical business inputs. This is descriptive, not a causal platform comparison.')
    (dst/'live_figure_manifest.json').write_text(json.dumps(figures,indent=2),encoding='utf-8')
    with (dst/'live_quality_source.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.writer(stream);writer.writerow(['project','representation','reference_mismatches','legal_fields'])
        for i,p in enumerate(projects):
            for j,sc in enumerate(scenarios):writer.writerow([p,sc,errors[i,j],18])
    print(json.dumps({'figures':len(figures),'formats':['png','pdf','svg']}))
if __name__=='__main__':main()
