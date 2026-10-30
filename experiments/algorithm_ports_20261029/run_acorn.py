"""Frozen author ACORN comparison; deterministic numeric fixtures, zero models."""
import argparse, hashlib, json, math, os, subprocess, time
from pathlib import Path
import numpy as np

WORKSPACE=Path(__file__).resolve().parents[2]
OUT=WORKSPACE/'results'/'algorithm_ports_20261029'/'acorn_run01'
METHODS=('acorn','hnsw_post','hnsw_adaptive','exact')
SEED=20261029
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')

def reference(p):
    xb=np.asarray(p['vectors'],np.float32);rows=[]
    for q,m in zip(np.asarray(p['queries'],np.float32),p['masks']):
        ids=np.flatnonzero(m);ds=np.sum((xb[ids]-q)**2,axis=1,dtype=np.float32)
        ix=np.lexsort((ids,ds))[:p['k']]
        rows.append({'allowed_count':len(ids),'ids':ids[ix].tolist(),'distances':ds[ix].tolist()})
    return rows

def invoke(binary,p,path):
    path.mkdir(parents=True,exist_ok=True);ip=path/'input.json';op=path/'output.json'
    if op.exists():raise RuntimeError('prediction exists; no automatic replay')
    write(ip,p);env=os.environ.copy();env.update(OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1')
    t=time.perf_counter()
    with (path/'stdout.log').open('wb') as so,(path/'stderr.log').open('wb') as se:
        r=subprocess.run([str(binary),'--input',str(ip),'--output',str(op)],cwd=WORKSPACE,env=env,stdout=so,stderr=se,timeout=300)
    call={'returncode':r.returncode,'wall_seconds':time.perf_counter()-t,'input_sha256':digest(ip),'binary_sha256':digest(binary)}
    if op.exists():call['output_sha256']=digest(op)
    write(path/'invocation.json',call)
    if r.returncode:raise RuntimeError('author runner failed; native logs retained')
    return json.loads(op.read_text(encoding='utf-8')),call

def preflight(binary):
    p={'vectors':np.eye(4).tolist(),'queries':[[1,0,0,0],[1,0,0,0],[0,1,0,0]],'masks':[[1,1,1,1],[0,0,1,0],[0,0,0,0]],'k':1}
    refs=reference(p);write(OUT/'preflight_reference.json',refs);o,call=invoke(binary,p,OUT/'preflight');checks=[]
    for method in METHODS:
        for qi,(row,ref) in enumerate(zip(o[method],refs)):
            target=ref['ids'] or [-1]
            checks.append({'method':method,'query':qi,'ids':row['ids'],'expected':target,'pass':row['ids']==target and row['illegal_result_count']==0 and row['duplicate_id_count']==0})
    result={'schema':'author_acorn_preflight_v1','passed':len(checks)==12 and all(x['pass'] for x in checks),'checks':checks,'call':call,'binary_sha256':digest(binary),'model_calls':0}
    write(OUT/'preflight.json',result)
    if not result['passed']:raise RuntimeError('preflight failed; no benchmark')

def fixture(n):
    rng=np.random.default_rng(SEED);d=32
    centers=np.zeros((4,d),np.float32);centers[np.arange(4),np.arange(4)]=8
    xb=(rng.standard_normal((n,d))*.4+centers[rng.integers(0,4,n)]).astype(np.float32)
    base=(xb[rng.choice(n,16,replace=False)]+rng.standard_normal((16,d))*.05).astype(np.float32)
    queries=[];masks=[];labels=[]
    for qi,q in enumerate(base):
        ds=np.sum((xb-q)**2,axis=1,dtype=np.float32)
        for kind in ('all_allowed','uniform_10percent','farthest_10percent','uniform_2percent'):
            m=np.zeros(n,np.uint8)
            if kind=='all_allowed':m[:]=1
            else:
                count=max(1,math.ceil(n*(.02 if kind=='uniform_2percent' else .1)))
                ids=np.argsort(ds,kind='stable')[-count:] if kind=='farthest_10percent' else rng.choice(n,count,replace=False)
                m[ids]=1
            queries.append(q.tolist());masks.append(m.tolist());labels.append({'base_query':qi,'filter':kind,'allowed_count':int(m.sum())})
    return {'vectors':xb.tolist(),'queries':queries,'masks':masks,'k':10},labels

def score(o,refs,labels,k):
    rows=[]
    for method in METHODS:
        if len(o[method])!=len(refs):raise RuntimeError('query count mismatch')
        for qi,(x,r,label) in enumerate(zip(o[method],refs,labels)):
            ids=[int(i) for i in x['ids'] if int(i)>=0];truth=set(r['ids']);possible=min(k,r['allowed_count'])
            if method=='exact' and set(ids)!=truth:raise RuntimeError('C++ exact differs from independent same-vector NumPy reference')
            rows.append({'method':method,'query':qi,**label,'recall':len(set(ids)&truth)/possible if possible else None,'returned':len(ids),'returned_lt_k':len(ids)<k,'search_shortfall':max(0,possible-len(ids)),'illegal':x['illegal_result_count'],'duplicates':x['duplicate_id_count'],'stable':x['replicate_ids_stable'],'latency_ms':x['latency_ms'],'rounds':x['search_rounds'],'final_candidates':x['final_candidates']})
    groups=[]
    for method in METHODS:
        for kind in ('all_allowed','uniform_10percent','farthest_10percent','uniform_2percent'):
            rs=[r for r in rows if r['method']==method and r['filter']==kind]
            groups.append({'method':method,'filter':kind,'queries':len(rs),'mean_recall':float(np.mean([r['recall'] for r in rs])),'returned_fewer_than_k':sum(r['returned_lt_k'] for r in rs),'search_shortfall_queries':sum(r['search_shortfall']>0 for r in rs),'illegal_results':sum(r['illegal'] for r in rs),'duplicates':sum(r['duplicates'] for r in rs),'median_latency_ms':float(np.median([r['latency_ms'] for r in rs])),'median_rounds':float(np.median([r['rounds'] for r in rs]))})
    return rows,groups

def benchmark(binary):
    pre=json.loads((OUT/'preflight.json').read_text(encoding='utf-8'))
    if not pre['passed'] or pre['binary_sha256']!=digest(binary):raise RuntimeError('matching binary preflight required')
    plan=json.loads((OUT/'plan.json').read_text(encoding='utf-8'))
    manifest={'plan_sha256':digest(OUT/'plan.json'),'amendment_sha256':digest(OUT/'plan_amendment01_baseline.json'),'binary_sha256':digest(binary),'fixtures':[]};prepared=[]
    for size in plan['datasets']:
        name=size['name'];p,labels=fixture(size['n']);refs=reference(p);path=OUT/name;path.mkdir(parents=True,exist_ok=True)
        write(path/'frozen_input.json',p);write(path/'reference.json',refs);write(path/'query_groups.json',labels)
        manifest['fixtures'].append({'name':name,'n':size['n'],'input_sha256':digest(path/'frozen_input.json'),'reference_sha256':digest(path/'reference.json'),'groups_sha256':digest(path/'query_groups.json')})
        prepared.append((name,p,refs,labels))
    write(OUT/'fixture_manifest.json',manifest)
    summary={'schema':'fixed_author_acorn_comparison_run01_v1','source_commit':plan['source_commit'],'model_calls':0,'datasets':{},'nonclaims':plan['claims_excluded'],'parameters_retuned_after_results':False}
    try:
        for name,p,refs,labels in prepared:
            o,call=invoke(binary,p,OUT/name/'native');rows,groups=score(o,refs,labels,p['k']);write(OUT/name/'scored_rows.json',rows)
            summary['datasets'][name]={'groups':groups,'metadata':o['metadata'],'invocation':call,'rows':len(rows)};write(OUT/'metrics.json',summary)
            if any(r['illegal'] or r['duplicates'] for r in rows):raise RuntimeError('illegal or duplicate native result retained; no silent filtering')
        summary['status']='closed_fixed_run_no_parameter_retuning';write(OUT/'metrics.json',summary)
    except Exception as error:
        summary.update(status='failed_preserved',failure_type=type(error).__name__,failure_message=str(error));write(OUT/'metrics.json',summary);raise
    print(json.dumps({'status':summary['status'],'datasets':list(summary['datasets']),'model_calls':0}),flush=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path);parser.add_argument('--preflight-only',action='store_true');parser.add_argument('--bench-only',action='store_true');args=parser.parse_args()
    binary=args.binary or Path(json.loads((OUT/'build_receipt.json').read_text(encoding='utf-8'))['binary'])
    if not args.bench_only:preflight(binary)
    if not args.preflight_only:benchmark(binary)

if __name__=='__main__':main()
