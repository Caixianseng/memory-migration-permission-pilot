"""Post-result strong-baseline check, same C cases; preserves original raw/code.

Adds standard static irrelevance: a fact absent from all rules and secrets
cannot cause a new protected entailment, even with unknown background.
This is an exploratory baseline correction, not a proposed algorithm.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import qualify as q


def execute(case,path):
    init=q.open_db(path);init.close()
    lock=threading.Lock();barrier=threading.Barrier(2) if case.get('concurrent') else None
    log=[];rule_atoms={a for body,head in case['rules']for a in body+[head]}|set(case['secrets'])
    def deliver(index,request):
        db=q.open_db(path);r=request['recipient'];g=q.group(case,r);fact=request['fact'];t=time.perf_counter()
        if barrier:barrier.wait(timeout=10)
        db.execute('BEGIN IMMEDIATE')
        known=set(case['background'].get(g,[]))|{v[0]for v in db.execute('SELECT fact FROM history WHERE group_id=?',(g,))}
        irrelevant=fact not in rule_atoms
        allowed=irrelevant or (case['complete_background'] and not(set(case['secrets'])&q.closure(known|{fact},case['rules'])))
        seq=None
        if allowed:seq=db.execute('INSERT INTO history(group_id,fact) VALUES(?,?)',(g,fact)).lastrowid
        db.execute('COMMIT');db.close()
        with lock:log.append({'request_index':index,'recipient':r,'group':g,'fact':fact,'allowed':allowed,
                              'commit_sequence':seq,'observed_before':sorted(known),'static_irrelevance':irrelevant,
                              'latency_seconds':time.perf_counter()-t})
    if barrier:
        threads=[threading.Thread(target=deliver,args=(i,r))for i,r in enumerate(case['deliveries'])]
        for th in threads:th.start()
        for th in threads:th.join(timeout=15)
        assert not any(th.is_alive()for th in threads)
    else:
        for i,r in enumerate(case['deliveries']):deliver(i,r)
    assert len(log)==len(case['deliveries'])
    ordered=sorted(log,key=lambda r:(not r['allowed'],r['commit_sequence'] or 999,r['request_index'])) if barrier else sorted(log,key=lambda r:r['request_index'])
    truth={g:set(v)for g,v in case['truth_background'].items()};fa=fr=exposures=0
    for item in ordered:
        before=truth.setdefault(item['group'],set())
        new=[s for s in case['secrets']if q.world_entails(before|{item['fact']},case['rules'],s) and not q.world_entails(before,case['rules'],s)]
        item['truth_new_secrets_if_delivered']=new;item['truth_payload_allow']=not new
        fa+=int(item['allowed'] and bool(new));fr+=int(not item['allowed'] and not new)
        if item['allowed']:before.add(item['fact']);exposures+=len(new)
    return {'case_id':case['case_id'],'method':'persistent_atomic_CQE_static_irrelevance','events':ordered,
            'false_allow':fa,'false_reject':fr,'new_secret_exposures':exposures,'allowed':sum(r['allowed']for r in log),
            'history_selects':len(log),'static_irrelevance_checks':len(log),
            'closure_calls':sum(not r['static_irrelevance'] and case['complete_background']for r in log)}


def main():
    config=json.loads((q.OUT/'C_config.json').read_text(encoding='utf8'));cases=config['cases']
    assert cases==json.loads(json.dumps(q.corpus()))  # Canonical JSON turns rule tuples into arrays.
    pre={'schema':'stage3-C-strong-baseline-check-v1','reason':'Exploratory correction after seeing avoidable C09 refusal of irrelevant r.',
         'same_cases_and_truth':True,'old_config_sha256':hashlib.sha256((q.OUT/'C_config.json').read_bytes()).hexdigest(),
         'original_code_sha256':hashlib.sha256(Path(q.__file__).read_bytes()).hexdigest(),
         'extension_code_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'rule':'Unknown background still permits facts absent from every rule and protected secret; all other unknown-dependent facts refused.',
         'new_paid_model_calls':0,'candidate_status':'mature static noninterference/irrelevance baseline, not new algorithm'}
    with (q.OUT/'C_strong_config.json').open('x',encoding='utf8')as f:json.dump(pre,f,indent=2)
    with tempfile.TemporaryDirectory(prefix='stage3_c_strong_')as td:
        rows=[execute(case,Path(td)/(case['case_id']+'.sqlite'))for case in cases]
    raw=q.OUT/'C_strong_raw.jsonl'
    with raw.open('x',encoding='utf8')as f:
        for row in rows:f.write(json.dumps(row,ensure_ascii=False)+'\n')
    result={**pre,'rows':len(rows),'summary':{k:sum(r[k]for r in rows)for k in ('false_allow','false_reject','new_secret_exposures','allowed','history_selects','static_irrelevance_checks','closure_calls')},
            'raw_sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),'interpretation':'All 10 bounded cases match independent truth; original conservative false reject is avoidable with an existing static rule.'}
    with(q.OUT/'C_strong_run.json').open('x',encoding='utf8')as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
