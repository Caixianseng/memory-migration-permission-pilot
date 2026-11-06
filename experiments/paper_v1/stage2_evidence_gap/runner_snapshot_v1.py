"""Controlled local evidence-recovery qualification; no model/provider traffic.

All methods receive the same trusted requirement manifest, observed projection,
current policy, acquisition catalogue and budget. Hidden ground truth is consumed
only by the scorer. Mature planners are baselines, not proposed novel algorithms.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import itertools
import json
import math
import platform
import random
import sqlite3
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
import numpy as np
import scipy
from scipy.optimize import Bounds, LinearConstraint, milp

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'research_paper_v1/stage2_evidence_gap/evidence'
METHODS = ('fail_closed', 'full_reaudit', 'set_difference', 'cheapest_path_union',
           'simple_setdiff_batch', 'weighted_greedy', 'exact_dp')
SCENARIOS = ('single_missing', 'multiple_missing', 'shared_dependency',
             'multilayer_missing', 'conflict', 'duplicate_alias',
             'stale_permission', 'revoked', 'unavailable', 'opaque')
REGIMES = ('singleton', 'partition', 'overlap', 'universal_batch')

def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

def digest(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()

def write_new(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write('\n')

def config():
    return {'schema':'stage2-evidence-gap-config-v1','seed':2026110601,
            'projects':24,'development_projects':12,'scenarios':SCENARIOS,
            'regimes':REGIMES,'methods':METHODS,'main_budget_units':10000,
            'tight_budget_units':8,'tight_projects':4,
            'tight_scenarios':['single_missing','shared_dependency'],
            'primary_endpoints':['unauthorized_releases','false_allows','tool_requests'],
            'primary_comparisons':[['weighted_greedy','cheapest_path_union'],
                                   ['weighted_greedy','simple_setdiff_batch']],
            'secondary_resources':['returned_rows','evidence_bytes','verification_operations','latency_seconds'],
            'cost_units':'Synthetic positive catalogue acquisition weights, not money/time/API bills.',
            'scope':'New controlled synthetic projects; one generator family, not commercial prevalence.',
            'cache':'All methods have global deduplication, shared validated evidence and identical validators.',
            'candidate_status':'No novel Proposed method; weighted greedy and exact DP are mature candidates.',
            'stop_rule':'No unsafe acceptance; no model or paid API; heldout generation fixed before development results.',
            'new_model_calls':0}

def make_project(index, cfg):
    rng = random.Random(cfg['seed'] + index * 7919)
    n = 8 + index % 5
    ids = [f'P{index:02}-S{k:02}' for k in range(n)]
    records = {}
    for k,sid in enumerate(ids):
        content = ''.join(rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(rng.choice([96,256,768])))
        records[sid] = {'source_id':sid,'source_version':1,'source_digest':hashlib.sha256(content.encode()).hexdigest(),
                        'input_run':f'controlled-P{index:02}', 'receipt_kind':'historical_host_input',
                        'issuer':'controlled-trusted-host','payload':content}
    edges = []
    memories = []
    shared = ids[0]
    for m in range(6):
        mid=f'P{index:02}-M{m}'
        srcs=sorted(set([shared]+rng.sample(ids, rng.randint(1,min(4,n)))))
        if m >= 3:
            parent=memories[m-3]
            srcs=sorted(set(srcs)|set(parent['sources']))
            edges.append((parent['memory_id'],mid))
        direct=sorted(set(srcs) - (set(memories[m-3]['sources']) if m>=3 else set()))
        edges += [(sid,mid) for sid in direct]
        memories.append({'memory_id':mid,'sources':srcs,'generation_run':f'controlled-P{index:02}',
                         'content':f'Synthetic derived memory {index}/{m}; no model generated text.'})
    # An independent implementation checks stored flattened requirements.
    graph=nx.DiGraph(edges)
    for mem in memories:
        assert sorted(set(nx.ancestors(graph,mem['memory_id'])) & set(ids)) == mem['sources']
    required=sorted(set().union(*(set(m['sources']) for m in memories)))
    ids=required
    provider={s:rng.randrange(3) for s in ids}
    single_cost={s:rng.randint(1,5) for s in ids}
    bundles=[]
    for b in range(5):
        covers=sorted(rng.sample(ids,rng.randint(2,min(len(ids),6))))
        bundles.append({'id':f'bundle{b}','covers':covers,'cost_units':rng.randint(2,9),
                        'filterable':False,'kind':'historical_host_input'})
    return {'project_id':f'P{index:02}','split':'development' if index<12 else 'heldout',
            'source_records':records,'requirements':memories,'edges':edges,
            'provider':provider,'single_cost':single_cost,'bundles':bundles,'shared_source':shared}

def make_case(project, scenario, regime):
    ids=sorted(set().union(*(set(m['sources']) for m in project['requirements'])))
    rng=random.Random(int(hashlib.sha256((project['project_id']+scenario).encode()).hexdigest()[:12],16))
    observed=copy.deepcopy([project['source_records'][s] for s in ids])
    missing=set()
    conflict=set()
    revoked=set()
    unavailable=set()
    opaque=False
    aliases={}
    epoch=1
    if scenario in ('single_missing','stale_permission','unavailable'):
        missing={ids[-1]}
    if scenario in ('multiple_missing','multilayer_missing','opaque'):
        missing=set(rng.sample(ids,min(4,len(ids))))
    if scenario=='shared_dependency': missing={project['shared_source']}|set(rng.sample(ids,min(3,len(ids))))
    if scenario=='conflict':
        conflict={ids[0]}
        bad=copy.deepcopy(observed[0]);bad['source_digest']='0'*64; observed.append(bad)
        missing={ids[-1]}
    if scenario=='duplicate_alias':
        observed.extend(copy.deepcopy(observed[:3]))
        aliases={'legacy:'+ids[0]:ids[0]}
        for rec in observed:
            if rec['source_id']==ids[0]:rec['source_id']='legacy:'+ids[0]
        missing={ids[-1]}
    if scenario=='revoked':revoked={project['shared_source']};missing={ids[-1]}
    if scenario=='unavailable':unavailable=set(missing)
    if scenario=='opaque':opaque=True
    if scenario=='stale_permission':epoch=2
    observed=[r for r in observed if aliases.get(r['source_id'],r['source_id']) not in missing]
    expected={s:{k:v for k,v in project['source_records'][s].items() if k!='payload'} for s in ids}
    operations=[{'id':'single:'+s,'covers':[s],'cost_units':project['single_cost'][s],
                 'filterable':False,'kind':'historical_host_input'} for s in ids]
    if regime=='partition':
        operations.extend({'id':f'provider:{p}','covers':[s for s in ids if project['provider'][s]==p],
                           'cost_units':2+p,'filterable':True,'kind':'historical_host_input'} for p in range(3))
    elif regime=='overlap':operations+=copy.deepcopy(project['bundles'])
    elif regime=='universal_batch':operations.append({'id':'all-filterable','covers':ids,'cost_units':3,
                                                     'filterable':True,'kind':'historical_host_input'})
    for op in operations:
        op['available']=True  # outages are revealed by the actual query, not gold labels
        op['legal']=not bool(set(op['covers'])&revoked) or op['filterable']
    # All planners can see these typed paths, but source reread cannot prove historical input.
    operations += [{'id':'reread:'+s,'covers':[s],'cost_units':1,'filterable':False,
                    'kind':'current_source_content','available':True,'legal':s not in revoked} for s in ids]
    req=copy.deepcopy(project['requirements'])
    view={'project_id':project['project_id'],'split':project['split'],'scenario':scenario,'regime':regime,
          'requirements':req,'expected_manifest':expected,'observed':observed,'aliases':aliases,
          'coverage_complete':not opaque,'permissions':{s:s not in revoked for s in ids},
          'policy_epoch':epoch,'observed_policy_epoch':1,'operations':operations}
    truth={'actually_missing':sorted(missing),'conflicts':sorted(conflict),'revoked':sorted(revoked),
           'unavailable':sorted(unavailable),'opaque':opaque,
           'recoverable_memories':[m['memory_id'] for m in req if not opaque and not(set(m['sources'])&(conflict|revoked|unavailable))],
           'forbidden_memories':[m['memory_id'] for m in req if opaque or bool(set(m['sources'])&(conflict|revoked|unavailable))]}
    return {'case_id':project['project_id']+'/'+scenario+'/'+regime,'view':view,'truth':truth,
            'receipt_database_rows':{s:r for s,r in project['source_records'].items() if s not in unavailable}}

def diagnose(view):
    bysource={}
    verification=0
    for record in view['observed']:
        verification+=1
        record=copy.deepcopy(record)
        sid=view['aliases'].get(record['source_id'],record['source_id'])
        record['source_id']=sid
        bysource.setdefault(sid,[]).append(record)
    missing=set(view['expected_manifest'])-set(bysource)
    conflict=set()
    valid={}
    for sid,rows in bysource.items():
        exp=view['expected_manifest'].get(sid)
        if exp is None or any(any(r.get(k)!=v for k,v in exp.items()) for r in rows):
            conflict.add(sid)
        else:valid[sid]=rows[0]
    revoked={s for s,allowed in view['permissions'].items() if not allowed}
    return {'missing':missing,'conflict':conflict,'revoked':revoked,'valid':valid,
            'unverifiable':not view['coverage_complete'],'verification_operations':verification}

def eligible_operations(view, target):
    result=[]
    for op in view['operations']:
        if op['kind']!='historical_host_input' or not op['available'] or not op['legal']:continue
        op=copy.deepcopy(op)
        covers=set(op['covers'])
        if op['filterable']:
            covers &= target
            covers={s for s in covers if view['permissions'][s]}
        if not covers & target:continue
        op['fetch']=sorted(covers)
        op['maskset']=covers & target
        result.append(op)
    return result

def plan(method, target, operations):
    uncovered=set(target)
    ordered=[]
    if not target:return []
    if method=='cheapest_path_union':
        chosen={}
        for sid in sorted(target):
            candidates=[o for o in operations if sid in o['maskset']]
            if candidates:
                op=min(candidates,key=lambda o:(o['cost_units'],len(o['fetch']),o['id']))
                chosen[op['id']]=op
        return [chosen[key] for key in sorted(chosen)]
    if method=='exact_dp':
        ids=sorted(target);full=(1<<len(ids))-1
        op_masks=[sum(1<<i for i,s in enumerate(ids) if s in op['maskset']) for op in operations]
        best={0:(0,())}
        for mask in range(full+1):
            if mask not in best:continue
            cost,indices=best[mask]
            for j,op in enumerate(operations):
                new=mask|op_masks[j]
                candidate=(cost+op['cost_units'],indices+(j,))
                if new!=mask and (new not in best or candidate<best[new]):best[new]=candidate
        attainable=0
        for mask in op_masks:attainable|=mask
        return [operations[j] for j in best[attainable][1]]
    while uncovered:
        avail=[o for o in operations if o['maskset']&uncovered]
        if not avail:break
        if method=='set_difference':
            sid=min(uncovered); candidates=[o for o in avail if o['id']=='single:'+sid]
            if not candidates:uncovered.remove(sid);continue
            op=candidates[0]
        elif method=='cheapest_path_union':
            sid=min(uncovered)
            candidates=[o for o in avail if sid in o['maskset']]
            if not candidates:uncovered.remove(sid);continue
            op=min(candidates,key=lambda o:(o['cost_units'],len(o['fetch']),o['id']))
        elif method in ('simple_setdiff_batch','full_reaudit'):
            op=min(avail,key=lambda o:(-len(o['maskset']&uncovered),o['cost_units'],o['id']))
        elif method=='weighted_greedy':
            op=min(avail,key=lambda o:(o['cost_units']/len(o['maskset']&uncovered),o['cost_units'],o['id']))
        else:raise ValueError(method)
        ordered.append(op);uncovered-=op['maskset']
    return ordered

def milp_cost(target, operations):
    if not target:return 0.0
    target=set(target)&set().union(*(o['maskset'] for o in operations)) if operations else set()
    if not target:return 0.0
    rows=sorted(target)
    matrix=np.array([[int(s in o['maskset']) for o in operations] for s in rows],dtype=float)
    result=milp(c=np.array([o['cost_units'] for o in operations],dtype=float),
                integrality=np.ones(len(operations)),bounds=Bounds(0,1),
                constraints=LinearConstraint(matrix,np.ones(len(rows)),np.full(len(rows),np.inf)),
                options={'time_limit':5.0})
    assert result.success, result.message
    return float(result.fun)

def run_method(case,method,budget):
    # The function sees only the method view and trusted query endpoint; truth stays outside.
    view=copy.deepcopy(case['view'])
    start=time.perf_counter()
    diag=diagnose(view)
    blocked=diag['conflict']|diag['revoked']
    eligible=[m for m in view['requirements'] if not diag['unverifiable'] and not(set(m['sources'])&blocked)]
    wanted=set().union(*(set(m['sources']) for m in eligible)) if eligible else set()
    target=(wanted if method=='full_reaudit' else wanted-set(diag['valid']))
    if method=='fail_closed':target=set()
    operations=eligible_operations(view,target)
    planning_start=time.perf_counter()
    planned=plan(method,target,operations) if method!='fail_closed' else []
    planning_seconds=time.perf_counter()-planning_start
    setup_start=time.perf_counter()
    db=sqlite3.connect(':memory:',isolation_level=None)
    db.execute('CREATE TABLE receipts(source_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)')
    db.executemany('INSERT INTO receipts VALUES(?,?)',[(s,canonical(r)) for s,r in case['receipt_database_rows'].items()])
    db.execute('CREATE TABLE policy(source_id TEXT PRIMARY KEY, allowed INTEGER, version INTEGER, epoch INTEGER)')
    db.executemany('INSERT INTO policy VALUES(?,?,?,?)',[(s,int(a),1,view['policy_epoch']) for s,a in view['permissions'].items()])
    db.execute('CREATE TABLE committed(memory_id TEXT PRIMARY KEY, policy_epoch INTEGER, requirements_json TEXT)')
    setup_seconds=time.perf_counter()-setup_start
    valid={} if method=='full_reaudit' else copy.deepcopy(diag['valid'])
    cost=0;calls=0;rows=0;wire=0;verifications=diag['verification_operations'];executed=[];source_reads=0
    failed_receipt_reads=set();query_log=[]
    # Setup is excluded from execution latency; each arm uses an identical fresh fixture.
    execute_start=time.perf_counter()
    for op in planned:
        if cost+op['cost_units']>budget:continue
        assert all(view['permissions'][s] for s in op['fetch'])
        payload=db.execute('SELECT receipt FROM receipts WHERE source_id IN ('+','.join('?' for _ in op['fetch'])+') ORDER BY source_id',op['fetch']).fetchall()
        calls+=1;cost+=op['cost_units'];rows+=len(payload)
        for (body,) in payload:
            wire+=len(body.encode());verifications+=1
            record=json.loads(body);sid=record['source_id'];exp=view['expected_manifest'][sid]
            assert all(record.get(k)==v for k,v in exp.items())
            valid[sid]=record
        returned={json.loads(body)['source_id'] for (body,) in payload}
        failed_receipt_reads |= set(op['fetch'])-returned
        query_log.append({'operation':op['id'],'requested_sources':op['fetch'],
                          'returned_sources':sorted(returned),'missing_rows':sorted(set(op['fetch'])-returned)})
        executed.append(op['id'])
    # Current-policy check is separate from source evidence queries; always done for each attempted memory.
    delivered=[];reasons={};commit_log=[]
    db.execute('BEGIN IMMEDIATE')
    for memory in view['requirements']:
        needed=set(memory['sources']);why=[]
        if diag['unverifiable']:why.append('UNVERIFIABLE')
        if needed&diag['conflict']:why.append('CONFLICT')
        if needed&diag['revoked']:why.append('REVOKED')
        if not needed<=set(valid):why.append('MISSING')
        if (needed-set(valid))&failed_receipt_reads:why.append('UNVERIFIABLE')
        current=db.execute('SELECT source_id,allowed,version,epoch FROM policy WHERE source_id IN ('+','.join('?' for _ in needed)+')',sorted(needed)).fetchall()
        if len(current)!=len(needed) or any(not r[1] or r[2]!=1 or r[3]!=view['policy_epoch'] for r in current):
            why.append('FINAL_POLICY_CHECK_FAILED')
        if not why:
            db.execute('INSERT INTO committed VALUES(?,?,?)',(memory['memory_id'],view['policy_epoch'],canonical(sorted(needed))))
            delivered.append(memory['memory_id'])
        reasons[memory['memory_id']]=why or ['VERIFIED']
        commit_log.append({'memory_id':memory['memory_id'],'policy_epoch':view['policy_epoch'],'decision':reasons[memory['memory_id']]})
    db.execute('COMMIT')
    assert sorted(r[0] for r in db.execute('SELECT memory_id FROM committed'))==sorted(delivered)
    latency=time.perf_counter()-start-setup_seconds
    db.close()
    return {'case_id':case['case_id'],'project_id':view['project_id'],'split':view['split'],
            'scenario':view['scenario'],'regime':view['regime'],'method':method,'budget_units':budget,
            'located_missing':sorted(diag['missing']),'located_conflict':sorted(diag['conflict']),
            'located_revoked':sorted(diag['revoked']),'unverifiable':diag['unverifiable'],
            'target_sources':sorted(target),'planned_operations':[o['id'] for o in planned],
            'executed_operations':executed,'delivered':delivered,'decisions':reasons,
            'query_log':query_log,'commit_log':commit_log,'failed_receipt_reads':sorted(failed_receipt_reads),
            'supplemented_sources':sorted(set(valid)-set(diag['valid'])),
            'tool_requests':calls,'returned_rows':rows,'source_reads':source_reads,
            'evidence_bytes':wire,'verification_operations':verifications,
            'policy_checks':len(view['requirements']),'cost_units':cost,
            'planning_seconds':planning_seconds,'latency_seconds':latency,
            'total_wall_seconds':time.perf_counter()-start,
            'human_review_time_seconds':0,'human_review_performed':False,
            'actual_paid_api_cost_cny':0,'commercial_internal_cost':None,
            'new_model_calls':0}

def score(row,truth):
    missing=set(row['located_missing']);gold=set(truth['actually_missing'])
    allowed=set(truth['recoverable_memories']);given=set(row['delivered'])
    row.update(missing_tp=len(missing&gold),missing_fp=len(missing-gold),missing_fn=len(gold-missing),
               recoverable_memories=len(allowed),recovered_legal_memories=len(given&allowed),
               forbidden_memories=len(truth['forbidden_memories']),
               unauthorized_releases=len(given&set(truth['forbidden_memories'])),
               false_allows=len(given-allowed),legal_memory_recovery=(len(given&allowed)/len(allowed) if allowed else None),
               localization_precision=(len(missing&gold)/len(missing) if missing else None),
               localization_recall=(len(missing&gold)/len(gold) if gold else None))
    return row

def prepare():
    OUT.mkdir(parents=True,exist_ok=True)
    cfg=config();projects=[make_project(i,cfg) for i in range(cfg['projects'])]
    dataset=[make_case(p,s,r) for p in projects for s in SCENARIOS for r in REGIMES]
    write_new(OUT/'config.json',cfg)
    write_new(OUT/'dataset.json',{'schema':'stage2-controlled-dataset-v1','projects':projects,'cases':dataset})
    write_new(OUT/'code_freeze.json',{'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                    'config_sha256':hashlib.sha256((OUT/'config.json').read_bytes()).hexdigest(),
                                    'dataset_sha256':hashlib.sha256((OUT/'dataset.json').read_bytes()).hexdigest(),
                                    'frozen_utc':datetime.now(timezone.utc).isoformat(),
                                    'note':'Freeze precedes smoke/development/heldout result generation; two splits fixed.'})
    print('prepared',len(projects),'projects',len(dataset),'cases',flush=True)

def run(part):
    cfg=json.loads((OUT/'config.json').read_text());data=json.loads((OUT/'dataset.json').read_text())
    freeze=json.loads((OUT/'code_freeze.json').read_text())
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==freeze['runner_sha256']
    assert hashlib.sha256((OUT/'dataset.json').read_bytes()).hexdigest()==freeze['dataset_sha256']
    cases=[c for c in data['cases'] if c['view']['split']==part]
    if part=='smoke':cases=data['cases'][:4]
    path=OUT/f'raw_{part}.jsonl'
    start=time.perf_counter();total=0;crosschecks=[]
    with path.open('x',encoding='utf-8') as f:
        for case in cases:
            budgets=[cfg['main_budget_units']]
            if int(case['view']['project_id'][1:])<cfg['tight_projects'] and case['view']['scenario'] in cfg['tight_scenarios']:
                budgets.append(cfg['tight_budget_units'])
            # Optimize only over public required receipts and legal catalogue, not hidden outcome labels.
            view=case['view'];d=diagnose(view)
            eligible=[m for m in view['requirements'] if not d['unverifiable'] and not(set(m['sources'])&(d['conflict']|d['revoked']))]
            target=(set().union(*(set(m['sources']) for m in eligible)) if eligible else set())-set(d['valid'])
            ops=eligible_operations(view,target)
            dp=sum(o['cost_units'] for o in plan('exact_dp',target,ops))
            mip=milp_cost(target,ops)
            assert abs(dp-mip)<1e-6,(case['case_id'],dp,mip)
            crosschecks.append({'case_id':case['case_id'],'dp_cost':dp,'scipy_milp_cost':mip})
            for budget in budgets:
                method_order=list(METHODS)
                random.Random(cfg['seed']+sum(map(ord,case['case_id']))+budget).shuffle(method_order)
                for method in method_order:
                    row=score(run_method(case,method,budget),case['truth'])
                    assert row['unauthorized_releases']==row['false_allows']==0,row
                    assert row['missing_fp']==row['missing_fn']==0,row
                    f.write(json.dumps(row,ensure_ascii=False)+'\n');total+=1
            if len(crosschecks)%40==0:print(part,len(crosschecks),'cases',total,'rows',flush=True)
    write_new(OUT/f'run_{part}.json',{'status':'complete','split':part,'rows':total,'cases':len(cases),
              'elapsed_seconds':time.perf_counter()-start,'crosschecks':crosschecks,
              'raw_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
              'python':sys.version,'sqlite':sqlite3.sqlite_version,'networkx':nx.__version__,
              'scipy':scipy.__version__,'numpy':np.__version__,'platform':platform.platform(),
              'new_model_calls':0,'actual_paid_api_cost_cny':0,'run_started_after_freeze':True})
    print(part,'complete',total,flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['prepare','smoke','development','heldout'])
    args=parser.parse_args()
    prepare() if args.mode=='prepare' else run(args.mode)
