"""Bounded payload-inference qualification; no model, no new algorithm.

Traditional history-aware Horn closure is contrasted with a stateless gate.
The independent oracle enumerates propositional worlds, not the closure code.
Only new positive secret entailment from delivered fact payloads is scored;
decision/refusal side channels and arbitrary natural-language inference are out.
"""
from __future__ import annotations
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[4]
OUT=ROOT/'research_paper_v1/stage3_research_pivot/evidence'
RULES=[(['p','q'],'secret')]


def closure(facts,rules):
    result=set(facts)
    changed=True
    while changed:
        changed=False
        for body,head in rules:
            if set(body)<=result and head not in result:
                result.add(head);changed=True
    return result


def world_entails(facts,rules,secret):
    atoms=sorted(set(facts)|{secret}|{a for body,head in rules for a in body+[head]})
    models=[]
    for bits in itertools.product([False,True],repeat=len(atoms)):
        world={a for a,b in zip(atoms,bits) if b}
        if not set(facts)<=world:continue
        if all(not set(body)<=world or head in world for body,head in rules):models.append(world)
    assert models
    return all(secret in world for world in models)


def corpus():
    basic={'rules':RULES,'secrets':['secret'],'background':{},'truth_background':{},'groups':{},'complete_background':True}
    defs=[
      ('C01_two_safe_fragments', [('B','p'),('B','q')],{}),
      ('C02_legal_utility',[('B','p'),('B','r')],{}),
      ('C03_known_receiver_background',[('B','p')],{'background':{'B':['q']},'truth_background':{'B':['q']}}),
      ('C04_direct_secret',[('B','secret')],{}),
      ('C05_idempotent_repetition',[('B','p'),('B','p'),('B','q')],{}),
      ('C06_separate_recipients',[('B','p'),('C','q')],{}),
      ('C07_explicit_coalition_bidirectional',[('B','p'),('C','q')],{'groups':{'B':'BC','C':'BC'}}),
      ('C08_reopen_before_second_delivery',[('B','p'),('B','q')],{'reopen_at':1}),
      ('C09_unknown_background',[('B','p'),('B','r')],{'truth_background':{'B':['q']},'complete_background':False}),
      ('C10_concurrent_fragments',[('B','p'),('B','q')],{'concurrent':True}),
    ]
    return [{**basic,**extra,'case_id':name,'deliveries':[{'recipient':r,'fact':f}for r,f in events]}for name,events,extra in defs]


def group(case,recipient):return case['groups'].get(recipient,recipient)


def open_db(path):
    db=sqlite3.connect(path,timeout=10,isolation_level=None)
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT,fact TEXT)')
    return db


def execute(case,method,path):
    init=open_db(path);init.close()
    log=[];lock=threading.Lock();barrier=threading.Barrier(2) if case.get('concurrent') else None
    stats={'closure_calls':0,'history_selects':0,'committed_payloads':0}
    def deliver(index,request):
        db=open_db(path);r=request['recipient'];g=group(case,r);fact=request['fact']
        t=time.perf_counter()
        if barrier:barrier.wait(timeout=10)
        if method=='persistent_atomic_CQE':db.execute('BEGIN IMMEDIATE')
        known=set(case['background'].get(g,[]))
        if method=='persistent_atomic_CQE':
            known|={v[0] for v in db.execute('SELECT fact FROM history WHERE group_id=?',(g,))}
            with lock:stats['history_selects']+=1
        elif method=='unserialized_CQE':
            known|={v[0] for v in db.execute('SELECT fact FROM history WHERE group_id=?',(g,))}
            with lock:stats['history_selects']+=1
        # Force both snapshots to be read before either write for the diagnostic arm.
        if barrier and method=='unserialized_CQE':barrier.wait(timeout=10)
        allowed=case['complete_background'] and not(set(case['secrets'])&closure(known|{fact},case['rules']))
        with lock:stats['closure_calls']+=1
        if allowed:db.execute('INSERT INTO history(group_id,fact) VALUES(?,?)',(g,fact))
        if method=='persistent_atomic_CQE':db.execute('COMMIT')
        # seq in the persisted ledger defines actual disclosed order in concurrent tests.
        seq=db.execute('SELECT MAX(seq) FROM history WHERE group_id=? AND fact=?',(g,fact)).fetchone()[0] if allowed else None
        with lock:
            log.append({'request_index':index,'recipient':r,'group':g,'fact':fact,'allowed':allowed,
                        'commit_sequence':seq,'observed_before':sorted(known),'latency_seconds':time.perf_counter()-t})
            stats['committed_payloads']+=int(allowed)
        db.close()
    if barrier:
        threads=[threading.Thread(target=deliver,args=(i,r))for i,r in enumerate(case['deliveries'])]
        for th in threads:th.start()
        for th in threads:th.join(timeout=15)
        assert all(not th.is_alive()for th in threads)
    else:
        for i,r in enumerate(case['deliveries']):deliver(i,r)
    assert len(log)==len(case['deliveries'])
    # In sequential cases use request order. In concurrent cases evaluate commits before rejections.
    ordered=sorted(log,key=lambda r:(not r['allowed'],r['commit_sequence'] or 999,r['request_index'])) if barrier else sorted(log,key=lambda r:r['request_index'])
    truth={g:set(v) for g,v in case['truth_background'].items()}
    fa=fr=exposures=0
    for item in ordered:
        g=item['group'];before=truth.setdefault(g,set())
        new=[s for s in case['secrets']if world_entails(before|{item['fact']},case['rules'],s) and not world_entails(before,case['rules'],s)]
        oracle_allow=not new
        item['truth_new_secrets_if_delivered']=new;item['truth_payload_allow']=oracle_allow
        fa+=int(item['allowed'] and not oracle_allow);fr+=int(not item['allowed'] and oracle_allow)
        if item['allowed']:before.add(item['fact']);exposures+=len(new)
    return {'case_id':case['case_id'],'method':method,'events':ordered,'false_allow':fa,'false_reject':fr,
            'new_secret_exposures':exposures,'allowed':sum(r['allowed']for r in log),
            'observability':'complete finite background' if case['complete_background'] else 'background incomplete; conservative refusal',
            **stats}


def actual_store_probe(temp):
    path=ROOT/'experiments/persistent_exchange_v1/store.py'
    spec=importlib.util.spec_from_file_location('actual_store_C_probe',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    a=module.AgentStore(temp/'original_A.sqlite','A');b=module.AgentStore(temp/'original_B.sqlite','B');p=module.TrustedPolicy(temp/'original_policy.sqlite')
    src=[a.add_original('src_p','p'),a.add_original('src_q','q')]
    p.register_sources(src);p.set_permissions('B',['src_p','src_q'])
    rows=[]
    for i,fact in enumerate(['p','q']):
        m=a.add_memory('mem_'+fact,fact,source_ids=['src_'+fact],provenance={'probe':'CPU_no_model'})
        receipt=module.import_package(b,p,module.export_package(a,p,'B',[m['memory_key']],batch_id='C-real-'+fact))
        rows.append({'fact':fact,'status':receipt['status'],'batch_id':receipt['batch_id']})
    obtained=[b.retrieve('C-real-'+f)['memory']for f in ['p','q']]
    result={'status':'both source-authorized packages imported','imports':rows,'retrieved':obtained,
            'explicit_additional_inference_rule':RULES,'derived_secret_under_added_policy':world_entails({'p','q'},RULES,'secret'),
            'classification':'Added inference policy is outside original source-sharing contract; not an in-model vulnerability.',
            'store_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    for s in (a,b,p):s.close()
    return result


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    cases=corpus();code=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    cfg={'schema':'stage3-C-bounded-qualification-v1','cases':cases,'methods':['stateless_fragment_gate','persistent_atomic_CQE','unserialized_CQE'],
         'scope':'positive propositional Horn payload inference only; refusal/metadata side channels excluded',
         'oracle':'independent exhaustive satisfying-world entailment','new_paid_model_calls':0,'code_sha256':code,
         'no_proposed_algorithm':True,'stop':'If correctly scoped traditional history-aware atomic CQE equals oracle, no new-algorithm gate.'}
    (OUT/'C_config.json').write_text(json.dumps(cfg,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    with tempfile.TemporaryDirectory(prefix='stage3_c_')as td:
        temp=Path(td);rows=[]
        for case in cases:
            for method in cfg['methods']:
                rows.append(execute(case,method,temp/(case['case_id']+'_'+method+'.sqlite')))
        original=actual_store_probe(temp)
    raw=OUT/'C_raw.jsonl'
    with raw.open('x',encoding='utf8')as f:
        for row in rows:f.write(json.dumps(row,ensure_ascii=False)+'\n')
    summary={m:{k:sum(r[k]for r in rows if r['method']==m)for k in ['false_allow','false_reject','new_secret_exposures','allowed','closure_calls','history_selects']}for m in cfg['methods']}
    record={'schema':'stage3-C-result-v1','case_count':len(cases),'rows':len(rows),'summary':summary,'actual_store_probe':original,
            'raw_sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),'code_sha256':code,'python':sys.version,'sqlite':sqlite3.sqlite_version,
            'new_paid_model_calls':0,'interpretation':'Traditional atomic history-aware CQE is strong baseline; any gap to stateless source checks is changed security contract, not algorithm novelty.'}
    (OUT/'C_run.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(record,ensure_ascii=False))


if __name__=='__main__':main()
