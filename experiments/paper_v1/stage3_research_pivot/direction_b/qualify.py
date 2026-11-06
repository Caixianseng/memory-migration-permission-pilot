"""Stage-3 B: ten bounded lifecycle checks; original Store is imported unchanged.

No LLM, API, history rewrite or large generator. Thread Events/Barriers select
explicit schedules; cases are mechanism checks, not independent samples.
"""
import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
OUT=ROOT/'research_paper_v1/stage3_research_pivot/evidence'
SOURCE=ROOT/'experiments/persistent_exchange_v1/store.py'
spec=importlib.util.spec_from_file_location('original_store',SOURCE)
store=importlib.util.module_from_spec(spec);spec.loader.exec_module(store)

CONFIG={'schema':'stage3-B-qualification-v1','date':'2026-11-05',
        'independent_unit':'none; 10 hand-selected mechanism checks, not a population estimate',
        'source':'experiments/persistent_exchange_v1/store.py','source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'baseline':'existing SQLite ATTACH + BEGIN IMMEDIATE + epoch + single-use seal; mature transaction/fencing baseline',
        'cases':[
          {'id':'B01','case':'unchanged resumed process','expected':'allow once'},
          {'id':'B02','case':'revoke before import','expected':'deny old seal'},
          {'id':'B03','case':'revoke then regrant ABA','expected':'deny old seal'},
          {'id':'B04','case':'source version update after sealing','expected':'deny old seal'},
          {'id':'B05','case':'replay after receiver restart','expected':'deny second effect'},
          {'id':'B06','case':'late artifact created after revocation','expected':'deny export'},
          {'id':'B07','case':'concurrent precheck then revoke wins before import','expected':'deny import'},
          {'id':'B08','case':'two concurrent importers replay same seal','expected':'exactly one effect'},
          {'id':'B09','case':'import transaction wins before concurrent revoke','expected':'one authorized effect then revocation'},
          {'id':'B10','case':'separate ACL SELECT / payload SELECT race vs shared read transaction','expected':'unlocked pattern stale read; ordinary transaction ordered read'}],
        'new_model_calls':0,'paid_api_cost':0,'non_go_rule':'A flaw in separated checks or a fix using ordinary transactions is not algorithm novelty.'}


def dump(name,value):
    (OUT/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf8')


def setup(path):
    a=store.AgentStore(path/'A.sqlite','A');b=store.AgentStore(path/'B.sqlite','B');p=store.TrustedPolicy(path/'policy.sqlite')
    s=a.add_original('S','controlled input v1');p.register_sources([s]);p.set_permissions('B',['S'])
    a.add_memory('M','controlled derived body',source_ids=['S'])
    packet=store.export_package(a,p,'B',['M'])
    a.close();b.close();p.close()
    return packet


def call_import(path,packet,before_commit=None,trace=None):
    b=store.AgentStore(path/'B.sqlite','B');p=store.TrustedPolicy(path/'policy.sqlite')
    if trace:b.db.set_trace_callback(trace)
    start=time.perf_counter()
    try:
        r=store.import_package(b,p,packet,before_commit=before_commit)
        return {'allow':True,'result':r['status'],'elapsed_seconds':time.perf_counter()-start}
    except Exception as e:
        return {'allow':False,'error':type(e).__name__,'reason':str(e),'elapsed_seconds':time.perf_counter()-start}
    finally:b.close();p.close()


def permissions(path,ids):
    p=store.TrustedPolicy(path/'policy.sqlite')
    try:return p.set_permissions('B',ids)
    finally:p.close()


def effect_count(path):
    with closing(sqlite3.connect(path/'B.sqlite')) as db:return db.execute('SELECT count(*) FROM batches').fetchone()[0]


def join(thread):
    thread.join(15)
    if thread.is_alive():raise RuntimeError('bounded worker did not finish')


def qualify(case,path):
    packet=setup(path);cid=case['id'];logs=[]
    if cid=='B01':
        r=call_import(path,packet);ok=r['allow'] and effect_count(path)==1
    elif cid in ('B02','B03'):
        permissions(path,[])
        if cid=='B03':permissions(path,['S'])
        r=call_import(path,packet);ok=not r['allow'] and effect_count(path)==0
    elif cid=='B04':
        a=store.AgentStore(path/'A.sqlite','A');s=a.add_original('S','updated controlled input',version=2);a.close()
        p=store.TrustedPolicy(path/'policy.sqlite');p.register_sources([s]);p.close()
        r=call_import(path,packet);ok=not r['allow'] and effect_count(path)==0
    elif cid=='B05':
        first=call_import(path,packet);second=call_import(path,packet)
        r={'first':first,'second':second};ok=first['allow'] and not second['allow'] and effect_count(path)==1
    elif cid=='B06':
        permissions(path,[])
        a=store.AgentStore(path/'A.sqlite','A');p=store.TrustedPolicy(path/'policy.sqlite')
        a.add_memory('late','late generation body',source_ids=['S'])
        try:store.export_package(a,p,'B',['late']);r={'allow':True}
        except Exception as e:r={'allow':False,'reason':str(e)}
        finally:a.close();p.close()
        ok=not r['allow'] and effect_count(path)==0
    elif cid=='B07':
        checked=threading.Event();revoked=threading.Event();answer={}
        def before():
            checked.set()
            if not revoked.wait(10):raise RuntimeError('revoke schedule timeout')
        def revoker():
            if not checked.wait(10):return
            answer['epoch']=permissions(path,[]);revoked.set()
        t=threading.Thread(target=revoker);t.start()
        r=call_import(path,packet,before_commit=before);join(t)
        r['revoke_epoch']=answer.get('epoch');ok=not r['allow'] and effect_count(path)==0
    elif cid=='B08':
        barrier=threading.Barrier(2,timeout=10);answers=[]
        def worker():answers.append(call_import(path,packet,before_commit=barrier.wait))
        threads=[threading.Thread(target=worker) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:join(t)
        r={'workers':answers};ok=len(answers)==2 and sum(a['allow'] for a in answers)==1 and effect_count(path)==1
    elif cid=='B09':
        held=threading.Event();started=threading.Event();done=threading.Event();answer={};first=[True]
        # Create the writer's SQLite connection before the import lock is held.
        def revoker():
            p=store.TrustedPolicy(path/'policy.sqlite');started.set()
            if not held.wait(10):p.close();return
            answer['attempt_at']=time.perf_counter();answer['epoch']=p.set_permissions('B',[])
            answer['committed_at']=time.perf_counter();done.set();p.close()
        t=threading.Thread(target=revoker);t.start()
        if not started.wait(10):raise RuntimeError('writer setup timeout')
        def trace(sql):
            if first[0] and "SELECT value FROM authority.policy_metadata" in sql:
                first[0]=False;held.set()
                answer['writer_completed_while_import_reserved']=done.wait(.2)
        r=call_import(path,packet,trace=trace);answer['import_returned_at']=time.perf_counter();join(t)
        r['schedule']=answer;ok=r['allow'] and effect_count(path)==1 and not answer.get('writer_completed_while_import_reserved',True) and done.is_set()
    elif cid=='B10':
        # Same two-connection schedule and rows, changing only transaction scope.
        # This is the stage-2 separated-check pattern, not a mutation of production Store.
        outcomes=[]
        for atomic in (False,True):
            dbpath=path/f'read-{atomic}.sqlite'
            with closing(sqlite3.connect(dbpath,isolation_level=None)) as db:
                db.execute('CREATE TABLE p(allowed INTEGER)');db.execute('INSERT INTO p VALUES(1)')
                db.execute('CREATE TABLE payload(body TEXT)');db.execute("INSERT INTO payload VALUES('controlled protected payload')")
            checked=threading.Event();attempted=threading.Event();committed=threading.Event();stamps={}
            def revoke():
                db=sqlite3.connect(dbpath,timeout=10,isolation_level=None)
                if not checked.wait(10):db.close();return
                db.execute('BEGIN IMMEDIATE');db.execute('UPDATE p SET allowed=0');attempted.set()
                db.execute('COMMIT');stamps['revoked_at']=time.perf_counter();committed.set();db.close()
            t=threading.Thread(target=revoke);t.start();db=sqlite3.connect(dbpath,timeout=10,isolation_level=None)
            if atomic:db.execute('BEGIN')
            allowed=db.execute('SELECT allowed FROM p').fetchone()[0];checked.set()
            if not attempted.wait(10):raise RuntimeError('writer attempt timeout')
            if not atomic and not committed.wait(10):raise RuntimeError('writer commit timeout')
            # If atomic, the read snapshot precedes a revocation that cannot commit yet.
            revoked_before_payload=committed.is_set()
            body=db.execute('SELECT body FROM payload').fetchone()[0] if allowed else None
            stamps['payload_read_at']=time.perf_counter()
            if atomic:db.execute('COMMIT')
            db.close();join(t)
            outcomes.append({'shared_transaction':atomic,'cached_allowed':allowed,'payload_returned':body is not None,
                             'revocation_committed_before_payload':revoked_before_payload,'times':stamps})
        r={'comparison':outcomes};ok=outcomes[0]['revocation_committed_before_payload'] and not outcomes[1]['revocation_committed_before_payload']
    else:raise ValueError(cid)
    return {'case_id':cid,'case':case['case'],'expected':case['expected'],'qualification_passed':bool(ok),
            'observation':r,'committed_batches':effect_count(path),'independent_truth':'fixed schedule and permission/version events in CONFIG',
            'cost_measurement':'actual local elapsed where recorded; no network/model costs',
            'scope':'single-host SQLite, not business-agent internal state or erasure after release'}


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    for name in ('B_config.json','B_raw.jsonl','B_run.json'):
        if (OUT/name).exists():raise FileExistsError(name)
    dump('B_config.json',CONFIG);results=[];start=time.perf_counter()
    with (OUT/'B_raw.jsonl').open('x',encoding='utf8') as f:
        for case in CONFIG['cases']:
            with tempfile.TemporaryDirectory(prefix='stage3-B-') as temp:
                try:row=qualify(case,Path(temp))
                except Exception as e:row={'case_id':case['id'],'qualification_passed':False,'runtime_error':repr(e)}
            f.write(json.dumps(row,ensure_ascii=False)+'\n');f.flush();results.append(row)
            print(row['case_id'],row['qualification_passed'],flush=True)
    unchanged=CONFIG['source_sha256']==hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    run={'schema':'stage3-B-run-v1','cases':len(results),'passed':sum(r['qualification_passed'] for r in results),
         'elapsed_seconds':time.perf_counter()-start,'source_unchanged':unchanged,
         'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'raw_sha256':hashlib.sha256((OUT/'B_raw.jsonl').read_bytes()).hexdigest(),
         'new_model_calls':0,'paid_api_cost':0,'sqlite':sqlite3.sqlite_version,
         'decision_implication':'ordinary transaction/fencing covers tested lifecycle; no new-algorithm necessity established'}
    dump('B_run.json',run);print(json.dumps(run))


if __name__=='__main__':main()
