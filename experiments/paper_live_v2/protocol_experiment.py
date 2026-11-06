"""New A--E protocol experiments and six receiver-path ablations.

Reuses frozen model-free fixture definitions; every result is a new execution
in new SQLite/files. D and E intentionally share the same mature verifier core.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import types
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from experiments.paper_final_v1 import durable_delivery
FROZEN=ROOT/'research_paper_v1/paper_final/evidence/cpu/run_20261106_perf_v3/code/runner.py'
spec=importlib.util.spec_from_file_location('frozen_protocol_fixture',FROZEN)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
base.ROOT=ROOT;base.SOURCE=ROOT/'experiments/persistent_exchange_v1/store.py'
OUT=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/protocol'
METHODS=['plain_file','basic_integrity_acl','source_dynamic_version_no_tx','transaction_reference','complete_host',
         'without_provenance_check','without_dynamic_acl','without_version','without_nonce_check',
         'without_receiver_verification','without_ack_recovery']
LABELS=dict(zip(METHODS,['A_file','B_static_acl_hash','C_dynamic_version_nonatomic','D_transaction_idempotent',
 'E_complete_Host_core','E_no_provenance','E_no_dynamic_permission','E_no_version',
 'E_no_explicit_replay_guard','E_no_receiver_verification','E_no_confirmation_recovery']))
ORIGINAL_QUALIFY=base.qualify
ORIGINAL_FIXTURE=base.fixture
CASES=base.CASES+[('F22','check_use_revocation_between_verification_and_effect',0),
                  ('F23','crash_after_receiver_effect_before_naive_nonce_consumption',1)]


def module_for(method):
    if method not in METHODS:raise ValueError(method)
    text=base.SOURCE.read_text(encoding='utf8')
    if method=='without_provenance_check':text=text.replace('    _validate_lineage(packet)\n','    # isolated lineage validation ablation\n')
    if method in ('without_dynamic_acl','without_version'):
        text=text.replace("            _need(epoch==packet['epoch'],'stale_policy_epoch')",'            # global policy epoch check omitted with this capability')
    if method=='without_nonce_check':text=text.replace("            _need(seal['consumed_by']is None,'transfer_replay_rejected')",'            # explicit used-nonce check omitted; other guards retained')
    if method=='without_receiver_verification':
        text=text.replace('    _validate_lineage(packet)\n','    # receiver lineage verification omitted\n')
        text=text.replace("    _need(packet['schema']==SCHEMA and packet['recipient_id']==receiver.agent_id and packet['sender_id']!=receiver.agent_id,'packet_recipient_or_schema_invalid')",'    # receiver schema/identity predicate omitted')
        text=text.replace("    _need(packet['content_sha256']==digest({k:v for k,v in packet.items()if k!='content_sha256'}),'packet_content_hash_invalid')",'    # receiver packet digest predicate omitted')
        text=text.replace("            for key in ('nonce','batch_id','sender_id','recipient_id','epoch'):_need(seal[key]==packet[key],'trusted_seal_metadata_mismatch')",'            # receiver seal metadata binding omitted')
        text=text.replace("            _need(seal['packet_sha256']==packet['content_sha256'],'trusted_packet_seal_mismatch')",'            # receiver seal digest binding omitted')
    m=types.ModuleType('live_'+method);m.__file__=str(base.SOURCE)
    exec(compile(text,str(base.SOURCE),'exec'),m.__dict__)
    if method in ('without_dynamic_acl','without_version'):
        def authority(db,prefix,recipient,dependencies):
            for ref in dependencies:
                if method!='without_version':
                    row=db.execute('SELECT * FROM '+prefix+'sources WHERE source_id=?',(ref['source_id'],)).fetchone()
                    m._need(row is not None and dict(row)==ref,'source_version_or_hash_is_not_current')
                if method!='without_dynamic_acl':
                    row=db.execute('SELECT 1 FROM '+prefix+'grants WHERE recipient_id=? AND source_id=?',(recipient,ref['source_id'])).fetchone()
                    m._need(row is not None,'source_not_currently_authorized_for_recipient')
        m._validate_authority=authority
    return m


def fixture(path,n=1,unsealed=False):
    packet=ORIGINAL_FIXTURE(path,n,unsealed)
    db=sqlite3.connect(path/'policy.sqlite')
    try:grants=[list(r)for r in db.execute('SELECT recipient_id,source_id FROM grants')]
    finally:db.close()
    base.dump(path/'static_acl_snapshot.json',{'known_recipients':['B'],'grants':grants})
    return packet


def effects(path,method,agent='B'):
    if method in ('plain_file','basic_integrity_acl'):return OLD_EFFECTS(path,method,agent)
    if method=='source_dynamic_version_no_tx':
        db=sqlite3.connect(path/(agent+'.sqlite'))
        try:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='nonatomic_effects'").fetchone():return 0
            return db.execute('SELECT count(*) FROM nonatomic_effects').fetchone()[0]
        finally:db.close()
    return OLD_EFFECTS(path,method,agent)


def execute_open(path,packet,method,m,b,p,phase=None):
    agent=b.agent_id;hook=getattr(m,'_after_precheck',None)
    if method=='plain_file':
        if hook:hook()
        with (path/(agent+'.handoff.jsonl')).open('a',encoding='utf8')as f:
            f.write(json.dumps(packet,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
        return {'status':'committed','metadata_only':True}
    if method=='basic_integrity_acl':
        start=time.perf_counter_ns()
        m._need(packet['recipient_id']==agent,'basic_wrong_recipient')
        m._need(packet['content_sha256']==m.digest({k:v for k,v in packet.items()if k!='content_sha256'}),'basic_content_hash')
        if phase is not None:phase['package_verification_ns']+=time.perf_counter_ns()-start
        snap=json.loads((path/'static_acl_snapshot.json').read_text(encoding='utf8'))
        # A newly introduced reverse-direction principal is initialized once;
        # existing B's grants are never refreshed after revocation.
        if agent not in snap['known_recipients']:
            snap['known_recipients'].append(agent)
            snap['grants'] += [list(r)for r in p.db.execute('SELECT recipient_id,source_id FROM grants WHERE recipient_id=?',(agent,))]
        allowed={sid for principal,sid in snap['grants']if principal==agent}
        for ref in packet['sources']:m._need(ref['source_id']in allowed,'static_acl_denied')
        if hook:hook()
        b.db.execute('CREATE TABLE IF NOT EXISTS basic_effects(seq INTEGER PRIMARY KEY,packet_json TEXT NOT NULL)')
        b.db.execute('INSERT INTO basic_effects(packet_json) VALUES(?)',(json.dumps(packet),))
        return {'status':'committed','metadata_only':True}
    if method=='source_dynamic_version_no_tx':
        m._need(packet['recipient_id']==agent,'wrong_recipient')
        m._need(packet['content_sha256']==m.digest({k:v for k,v in packet.items()if k!='content_sha256'}),'package_hash')
        m._validate_lineage(packet)
        m._need(p.epoch==packet['epoch'],'stale_policy_epoch')
        m._validate_authority(p.db,'',agent,packet['sources'])
        seal=p.db.execute('SELECT * FROM seals WHERE import_id=?',(packet['import_id'],)).fetchone()
        m._need(seal is not None and seal['consumed_by']is None,'seal_absent_or_consumed')
        m._need(seal['packet_sha256']==packet['content_sha256'],'trusted_seal_mismatch')
        if hook:hook()
        b.db.execute('CREATE TABLE IF NOT EXISTS nonatomic_effects(import_id TEXT PRIMARY KEY,batch_id TEXT UNIQUE NOT NULL,packet_sha256 TEXT NOT NULL,packet_json TEXT NOT NULL)')
        b.db.execute('INSERT INTO nonatomic_effects VALUES(?,?,?,?)',(packet['import_id'],packet['batch_id'],packet['content_sha256'],json.dumps(packet)))
        if getattr(m,'_crash_after_receiver_effect',False):os._exit(91)
        p.db.execute('UPDATE seals SET consumed_by=? WHERE import_id=?',(agent,packet['import_id']))
        return {'status':'committed','metadata_only':True}
    original=m.import_package
    if hook:
        def imported(receiver,policy,pack):return original(receiver,policy,pack,before_commit=hook)
        m.import_package=imported
    try:
        if method=='without_ack_recovery':return m.import_package(b,p,packet)
        return durable_delivery.deliver(b,p,packet,module=m)
    finally:m.import_package=original


def call(path,packet,method,agent='B',synchronize=None,after_precheck=None,crash_after_effect=False):
    m=module_for(method);m._after_precheck=after_precheck;m._crash_after_receiver_effect=crash_after_effect
    b=m.AgentStore(path/(agent+'.sqlite'),agent);p=m.TrustedPolicy(path/'policy.sqlite')
    start=time.perf_counter_ns();cpu=time.process_time_ns()
    try:
        if synchronize:synchronize()
        r=execute_open(path,packet,method,m,b,p)
        return {'accepted':True,'status':r['status'],'metadata_only':r.get('metadata_only',False),
                'receipt_contains_memory':any(k in r for k in ('content','memory','memories')),
                'elapsed_ns':time.perf_counter_ns()-start,'cpu_ns':time.process_time_ns()-cpu}
    except Exception as exc:return {'accepted':False,'reason':str(exc),'error':type(exc).__name__,
                                  'elapsed_ns':time.perf_counter_ns()-start,'cpu_ns':time.process_time_ns()-cpu}
    finally:b.close();p.close()


def worker(path,packet,method,mode):
    if mode=='before_commit' and method!='source_dynamic_version_no_tx':
        m=module_for(method);b=m.AgentStore(path/'B.sqlite','B');p=m.TrustedPolicy(path/'policy.sqlite')
        b.db.set_trace_callback(lambda sql:os._exit(92)if sql.strip().upper()=='COMMIT'else None)
        m.import_package(b,p,packet);os._exit(94)
    if mode=='before_commit':os._exit(92)
    result=call(path,packet,method,crash_after_effect=(mode=='after_receiver_effect'))
    base.dump(path/'worker_commit_observation.json',result)
    os._exit(91 if result['accepted']else 93)


def crash(path,packet,method,mode):
    file=path/'live_worker_packet.json';base.dump(file,packet)
    command=[sys.executable,'-B','-X','utf8',str(Path(__file__).resolve()),'--worker',str(path),str(file),method,mode]
    proc=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=25)
    return {'mode':mode,'exit_code':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr,
            'disk_effects_after_exit':effects(path,method)}


def qualify(cid,label,expected,path,method):
    base.store=module_for(method)
    if cid not in ('F22','F23'):
        result=ORIGINAL_QUALIFY(cid,label,expected,path,method)
    else:
        packet=fixture(path);operations=[];events=['generation','package_prepared'];crash_result=None
        if cid=='F22':
            checked=threading.Event();revoked=threading.Event();thread_errors=[]
            def revoke():
                try:
                    if not checked.wait(10):raise RuntimeError('check_boundary_timeout')
                    base.permission(path,[]);events.append('revocation_committed');revoked.set()
                except BaseException as e:thread_errors.append(repr(e));revoked.set()
            def hook():
                checked.set()
                if not revoked.wait(15):raise RuntimeError('revocation_timeout')
                if thread_errors:raise RuntimeError(str(thread_errors))
            thread=threading.Thread(target=revoke);thread.start()
            operations.append(call(path,packet,method,after_precheck=hook));thread.join(20)
            if thread.is_alive()or thread_errors:raise RuntimeError('revoke_worker_failed:'+str(thread_errors))
            events.append('receiver_effect_attempted')
        else:
            crash_result=crash(path,packet,method,'after_receiver_effect');events+=['worker_exited_after_effect','retry']
            operations.append(call(path,packet,method))
        count=effects(path,method)
        result={'case_id':cid,'case':label,'method':method,'expected_commits':expected,'actual_commits':count,
          'matches_strict_frozen_oracle':count==expected,'unauthorized_first_delivery':cid=='F22'and count>0,
          'stale_epoch_admission':False,'duplicate_effects':max(0,count-expected)if expected>0 else 0,
          'legal_commit_missing':expected>0 and count<expected,
          'recovery_confirmed':(operations[-1]['accepted']and count==expected)if cid=='F23'else None,
          'retry_request_accepted':operations[-1]['accepted']if cid=='F23'else None,
          'current_source_policy_eligible':cid=='F23','current_policy_legal_false_reject':False,
          'ack_plaintext_safe':True,'operations':operations,'events':events,'crash':crash_result,
          'database_directory':str(path.relative_to(ROOT))}
    db=sqlite3.connect(path/'policy.sqlite')
    try:
        rows=db.execute('SELECT consumed_by FROM seals').fetchall()
        result['unconsumed_seals_after_effect']=sum(v[0]is None for v in rows)if result['actual_commits']>0 else 0
    finally:db.close()
    result['baseline_label']=LABELS[method]
    result['safe_recovery']=result['recovery_confirmed']
    result['existing_commit_confirmation']=(result['case_id']in ('F05','F06','F07','F08','F17','F23')and bool(result['operations'])and result['operations'][-1].get('status')=='already_committed')
    result['state_consistency_failed']=bool(cid=='F23'and method=='source_dynamic_version_no_tx'and result['unconsumed_seals_after_effect'])
    return result


OLD_EFFECTS=base.raw_effect_count
base.module_for=module_for;base.fixture=fixture;base.execute_open=execute_open
base.call=call;base.crash=crash;base.raw_effect_count=effects;base.METHODS=METHODS
# Reuse frozen measured-stage code with all five A--E configurations and eight
# repeats per size. Function bodies and reuse hashes are saved with each run.
perf_text=inspect.getsource(base.performance).replace('range(12)','range(8)').replace('order=METHODS[:4]','order=METHODS[:5]').replace('repetition%4','repetition%5')
perf_text=perf_text.replace('                recovery_result=execute_open(path,packet,method,m,b,p)',
'''                try:
                    recovery_result=execute_open(path,packet,method,m,b,p)
                except Exception as exc:
                    recovery_result={'status':'rejected:'+type(exc).__name__+':'+str(exc)}''')
exec(compile(perf_text,str(FROZEN),'exec'),base.__dict__)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--run-id',default='protocol_run_20261106_v1');parser.add_argument('--worker',nargs=4);parser.add_argument('--performance-only',action='store_true');args=parser.parse_args()
    if args.worker:
        p,f,m,mode=args.worker;worker(Path(p),json.loads(Path(f).read_text(encoding='utf8')),m,mode);return
    target=OUT/args.run_id
    if target.exists():raise SystemExit('Refusing overwrite: '+str(target))
    target.mkdir(parents=True);(target/'code').mkdir()
    for file in (Path(__file__),FROZEN,base.SOURCE,Path(durable_delivery.__file__)):
        (target/'code'/file.name).write_bytes(file.read_bytes())
    config={'schema':'paper-live-v2-protocol-contract','date':'2026-11-06','methods':METHODS,'labels':LABELS,
      'cases':[{'id':i,'case':n,'expected_effects':e}for i,n,e in CASES],
      'strong_reference':'D/E same frozen complete Store + same identity-bound metadata recovery; no private advantage for E',
      'frozen_fixture_source':str(FROZEN.relative_to(ROOT)),'frozen_fixture_sha256':base.sha(FROZEN),
      'store_sha256':base.sha(base.SOURCE),'runner_sha256':base.sha(__file__),
      'performance_sizes':[1,8,32],'performance_repetitions':8,
      'baseline_C':'same source/permission/version/seal checks, before a receiver autocommit; separate nonce consumption; unique operation IDs retained',
      'baseline_B':'ACL snapshot at scenario initial preparation; newly introduced reverse principal initialized at its first use; existing grants never refreshed',
      'new_paid_model_calls':0,'experiment_unit':'controlled lifecycle trace, not business project','performance_only':args.performance_only}
    base.dump(target/'config.json',config);start=time.perf_counter();results=[]
    with (target/'raw.jsonl').open('w',encoding='utf8')as f:
        if not args.performance_only:
            for cid,label,expected in CASES:
                for method in METHODS:
                    row=qualify(cid,label,expected,target/f'{cid}-{method}',method);results.append(row)
                    f.write(json.dumps(row,ensure_ascii=False)+'\n');f.flush()
                print(cid,'done',flush=True)
    perf=base.performance(target)
    with (target/'performance_raw.jsonl').open('w',encoding='utf8')as f:
        for row in perf:f.write(json.dumps(row,ensure_ascii=False)+'\n')
    summary=[]
    for method in METHODS:
        selected=[r for r in results if r['method']==method]
        summary.append({'method':method,'label':LABELS[method],'cases':len(selected),
          'invalid_admission_cases':sum(r['unauthorized_first_delivery']for r in selected),
          'duplicate_effects':sum(r['duplicate_effects']for r in selected),
          'stale_epoch_cases':sum(r['stale_epoch_admission']for r in selected),
          'current_policy_conservative_rejections':sum(r['current_policy_legal_false_reject']for r in selected),
          'safe_recoveries':sum(r['safe_recovery']is True for r in selected),
          'recovery_case_denominator':sum(r['safe_recovery']is not None for r in selected),
          'existing_commit_confirmations':sum(r['existing_commit_confirmation']for r in selected),
          'state_consistency_failure_cases':sum(r['state_consistency_failed']for r in selected)})
    receipt={'schema':'paper-live-v2-protocol-run','finished_utc':datetime.now(timezone.utc).isoformat(),
      'case_count':0 if args.performance_only else len(CASES),'protocol_rows':len(results),'performance_rows':len(perf),
      'summary':summary,'elapsed_seconds':time.perf_counter()-start,'old_store_unchanged':base.sha(base.SOURCE)==config['store_sha256'],
      'raw_sha256':base.sha(target/'raw.jsonl'),'performance_raw_sha256':base.sha(target/'performance_raw.jsonl'),
      'config_sha256':base.sha(target/'config.json'),'new_paid_model_calls':0,'github_writes':0}
    base.dump(target/'run.json',receipt);print(json.dumps(receipt,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
