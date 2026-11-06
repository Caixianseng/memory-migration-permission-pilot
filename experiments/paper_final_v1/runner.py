"""Model-free, isolated lifecycle qualification and local performance runs.

All accepted effects are counted from disk, not method return codes. Mature
reference and full Host intentionally have identical authorization semantics.
The reference reuses the frozen verifier core: this is not an independent
algorithm replication. An independent scenario oracle supplies expected effects.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
import tracemalloc
import types
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.persistent_exchange_v1 import store
from experiments.paper_final_v1 import durable_delivery

OUT = ROOT/'research_paper_v1/paper_final/evidence/cpu'
SOURCE = ROOT/'experiments/persistent_exchange_v1/store.py'
METHODS = ['plain_file', 'basic_integrity_acl', 'transaction_reference', 'complete_host',
           'legacy_host', 'without_provenance_check', 'without_epoch_check',
           'without_nonce_check', 'without_final_authorization', 'without_ack_recovery']
CASES = [
 ('F00', 'normal', 1), ('F01', 'revoke_after_generation_before_preparation', 0),
 ('F02', 'revoke_after_preparation', 0), ('F03', 'revoke_just_before_commit_entry', 0),
 ('F04', 'revoke_after_successful_commit', 1), ('F05', 'ack_lost_retry', 1),
 ('F06', 'ack_received_source_state_not_updated', 1),
 ('F07', 'process_crash_after_commit_before_ack', 1),
 ('F08', 'duplicate_submission', 1), ('F09', 'concurrent_same_packet', 1),
 ('F10', 'concurrent_distinct_tasks', 2), ('F11', 'old_source_version_task_resumed', 0),
 ('F12', 'late_generated_artifact_after_revocation', 0),
 ('F13', 'old_permission_epoch_revoke_regrant', 0),
 ('F14', 'wrong_recipient', 0), ('F15', 'tampered_body_with_recomputed_hashes', 0),
 ('F16', 'same_batch_different_packet_confirmation', 1),
 ('F17', 'committed_retry_after_revocation_metadata_only', 1),
 ('F18', 'unrelated_permission_epoch_change', 0),
 ('F19', 'crash_before_commit_and_retry', 1),
 ('F20', 'bidirectional_independent_commits', 2),
 ('F21', 'committed_packet_modified_before_confirmation', 1),
]


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf8')


def module_for(method):
    if method not in METHODS: raise ValueError(method)
    text = SOURCE.read_text(encoding='utf8')
    if method == 'without_provenance_check':
        text = text.replace('    _validate_lineage(packet)\n', '    # isolated ablation: lineage check omitted\n')
    elif method == 'without_epoch_check':
        text = text.replace("            _need(epoch==packet['epoch'],'stale_policy_epoch')", "            # isolated ablation: epoch equality omitted")
    elif method == 'without_nonce_check':
        text = text.replace("            _need(seal['consumed_by']is None,'transfer_replay_rejected')", "            # isolated ablation: explicit consumed-nonce gate omitted")
    elif method == 'without_final_authorization':
        text = text.replace("            _need(epoch==packet['epoch'],'stale_policy_epoch')", "            # isolated ablation: final epoch omitted")
        text = text.replace("            _validate_authority(db,'authority.',receiver.agent_id,packet['sources'])", "            # isolated ablation: final authority validation omitted")
    module = types.ModuleType('isolated_'+method)
    module.__file__ = str(SOURCE)
    exec(compile(text, str(SOURCE), 'exec'), module.__dict__)
    return module


def draft_packet(a, p, recipient, memory_ids, batch='batch-1'):
    memories = [a.get_memory(mid) for mid in memory_ids]
    packet = {'schema':store.SCHEMA, 'import_id':'draft-import', 'nonce':'draft-nonce',
              'batch_id':batch, 'sender_id':a.agent_id, 'recipient_id':recipient,
              'epoch':p.epoch, 'memories':memories, 'lineage':store._lineage(a, memories),
              'sources':store._merge_refs([r for m in memories for r in m['dependencies']])}
    packet['content_sha256'] = store.digest(packet)
    return packet


def fixture(path, n=1, unsealed=False):
    path.mkdir(parents=True, exist_ok=True)
    a=store.AgentStore(path/'A.sqlite','A');b=store.AgentStore(path/'B.sqlite','B')
    p=store.TrustedPolicy(path/'policy.sqlite')
    refs=[]; mids=[]
    for i in range(n):
        sid=f'S{i:03d}'; refs.append(a.add_original(sid, f'Controlled fact {i}: value-{i}; '+('x'*128)))
        mid=f'M{i:03d}'; mids.append(mid)
        a.add_memory(mid, f'Derived controlled value-{i}', source_ids=[sid],
                     provenance={'attempt_id':'frozen-attempt-1','generator':'scripted-fixture'})
    p.register_sources(refs); p.set_permissions('B',[r['source_id'] for r in refs])
    packet = draft_packet(a,p,'B',mids) if unsealed else store.export_package(a,p,'B',mids,batch_id='batch-1')
    a.close();b.close();p.close();return packet


def permission(path, ids, recipient='B'):
    p=store.TrustedPolicy(path/'policy.sqlite')
    try:return p.set_permissions(recipient, ids)
    finally:p.close()


def raw_effect_count(path, method, agent='B'):
    if method == 'plain_file':
        file=path/(agent+'.handoff.jsonl')
        return len(file.read_text(encoding='utf8').splitlines()) if file.exists() else 0
    db=sqlite3.connect(path/(agent+'.sqlite'))
    try:
        if method=='basic_integrity_acl':
            return db.execute("SELECT count(*) FROM sqlite_master WHERE name='basic_effects'").fetchone()[0] and db.execute('SELECT count(*) FROM basic_effects').fetchone()[0]
        return db.execute('SELECT count(*) FROM batches').fetchone()[0]
    finally:db.close()


def execute_open(path, packet, method, m, b, p, phase=None):
        agent=b.agent_id
        if method=='plain_file':
            with (path/(agent+'.handoff.jsonl')).open('a',encoding='utf8') as f:
                f.write(json.dumps(packet, sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
            result={'status':'committed','metadata_only':True}
        elif method=='basic_integrity_acl':
            verify_started=time.perf_counter_ns()
            if packet['recipient_id']!=agent:raise m.StoreError('basic_wrong_recipient')
            if packet['content_sha256']!=m.digest({k:v for k,v in packet.items() if k!='content_sha256'}):raise m.StoreError('basic_content_hash')
            if phase is not None:phase['package_verification_ns']+=time.perf_counter_ns()-verify_started
            auth_started=time.perf_counter_ns()
            for source in packet['sources']:
                if not p.db.execute('SELECT 1 FROM grants WHERE recipient_id=? AND source_id=?',(agent,source['source_id'])).fetchone():raise m.StoreError('basic_current_acl_denied')
            if phase is not None:phase['authorization_validation_ns']+=time.perf_counter_ns()-auth_started
            b.db.execute('CREATE TABLE IF NOT EXISTS basic_effects(seq INTEGER PRIMARY KEY,packet_json TEXT NOT NULL)')
            b.db.execute('INSERT INTO basic_effects(packet_json) VALUES(?)',(json.dumps(packet),))
            result={'status':'committed','metadata_only':True}
        elif method in ('legacy_host','without_ack_recovery'):
            result=m.import_package(b,p,packet)
        else:
            # Both mature transaction reference and full Host receive the same
            # identity-bound metadata recovery. The full protocol is not granted
            # privileged data, looser authorization or an exclusive cache.
            result=durable_delivery.deliver(b,p,packet,module=m)
        return result


def call(path, packet, method, agent='B', synchronize=None):
    m=module_for(method); b=m.AgentStore(path/(agent+'.sqlite'),agent);p=m.TrustedPolicy(path/'policy.sqlite')
    started=time.perf_counter_ns();cpu=time.process_time_ns()
    try:
        if synchronize:synchronize()
        result=execute_open(path,packet,method,m,b,p)
        return {'accepted':True,'status':result['status'],'metadata_only':bool(result.get('metadata_only',False)),
                'receipt_contains_memory':any(k in result for k in ('memory','memories','content')),
                'elapsed_ns':time.perf_counter_ns()-started,'cpu_ns':time.process_time_ns()-cpu}
    except Exception as exc:
        return {'accepted':False,'error':type(exc).__name__,'reason':str(exc),
                'elapsed_ns':time.perf_counter_ns()-started,'cpu_ns':time.process_time_ns()-cpu}
    finally:b.close();p.close()


def worker(path, packet_path, method, mode):
    packet=json.loads(packet_path.read_text(encoding='utf8'))
    if mode=='after_commit':
        result=call(path,packet,method)
        dump(path/'worker_commit_observation.json',result)
        os._exit(91 if result['accepted'] else 93)
    if mode=='before_commit':
        m=module_for(method);b=m.AgentStore(path/'B.sqlite','B');p=m.TrustedPolicy(path/'policy.sqlite')
        def trace(sql):
            if sql.strip().upper()=='COMMIT':os._exit(92)
        b.db.set_trace_callback(trace)
        m.import_package(b,p,packet)
        os._exit(94)


def crash(path,packet,method,mode):
    file=path/'worker_packet.json';dump(file,packet)
    command=[sys.executable,'-B','-X','utf8',str(Path(__file__).resolve()),'--worker',str(path),str(file),method,mode]
    proc=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=20)
    return {'mode':mode,'exit_code':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr,
            'disk_effects_after_exit':raw_effect_count(path,method)}


def qualify(cid,label,expected,path,method):
    packet=fixture(path,unsealed=cid=='F01'); events=['generation_completed'];results=[];crash_result=None
    def invoke(pack=packet,agent='B'):return call(path,pack,method,agent)
    if cid=='F01':
        permission(path,[]);events+=['revocation_committed','delivery_preparation']
        if method in ('plain_file','basic_integrity_acl'):results.append(invoke())
        else:
            a=store.AgentStore(path/'A.sqlite','A');p=store.TrustedPolicy(path/'policy.sqlite')
            try:
                pack=store.export_package(a,p,'B',['M000'],batch_id='batch-1');results.append(call(path,pack,method))
            except Exception as e:results.append({'accepted':False,'reason':str(e),'phase':'preparation'})
            finally:a.close();p.close()
    elif cid in ('F02','F03','F12'):
        events+=['delivery_prepared','revocation_committed']
        permission(path,[])
        if cid=='F12':
            a=store.AgentStore(path/'A.sqlite','A');p=store.TrustedPolicy(path/'policy.sqlite')
            a.add_memory('LATE','Late controlled result',source_ids=['S000'])
            try:
                if method in ('plain_file','basic_integrity_acl'):pack=draft_packet(a,p,'B',['LATE'])
                else:pack=store.export_package(a,p,'B',['LATE'])
                results.append(call(path,pack,method))
            except Exception as e:results.append({'accepted':False,'reason':str(e),'phase':'late_preparation'})
            finally:a.close();p.close()
        else:results.append(invoke())
    elif cid=='F04':
        results.append(invoke());events+=['first_import_committed'];permission(path,[]);events+=['revocation_committed']
    elif cid in ('F05','F06','F08','F17'):
        results.append(invoke());events+=['first_import_committed']
        if cid=='F05':events+=['ack_discarded']
        if cid=='F06':events+=['ack_received','source_state_update_discarded']
        if cid=='F17':permission(path,[]);events+=['revocation_committed']
        results.append(invoke());events+=['same_packet_retried']
    elif cid=='F07':
        crash_result=crash(path,packet,method,'after_commit');events+=['receiver_process_exited_without_ack'];results.append(invoke())
    elif cid in ('F09','F10'):
        packets=[packet,deepcopy(packet)]
        if cid=='F10':
            a=store.AgentStore(path/'A.sqlite','A');p=store.TrustedPolicy(path/'policy.sqlite')
            packets[1]=store.export_package(a,p,'B',['M000'],batch_id='batch-2');a.close();p.close()
        barrier=threading.Barrier(2,timeout=15);threads=[]
        for pack in packets:
            threads.append(threading.Thread(target=lambda q=pack:results.append(call(path,q,method,synchronize=barrier.wait))))
        for thread in threads:thread.start()
        for thread in threads:
            thread.join(20)
            if thread.is_alive():raise RuntimeError('worker_timeout')
        events+=['two_delivery_workers_joined']
    elif cid=='F11':
        a=store.AgentStore(path/'A.sqlite','A');ref=a.add_original('S000','controlled source v2',version=2);a.close()
        p=store.TrustedPolicy(path/'policy.sqlite');p.register_sources([ref]);p.close();events+=['source_version_2_committed','old_task_resumed'];results.append(invoke())
    elif cid=='F13':
        permission(path,[]);permission(path,['S000']);events+=['revocation_committed','regrant_committed','old_epoch_submission'];results.append(invoke())
    elif cid=='F14':
        packet['recipient_id']='C';packet['content_sha256']=store.digest({k:v for k,v in packet.items() if k!='content_sha256'});results.append(invoke())
    elif cid in ('F15','F21'):
        if cid=='F21':results.append(invoke())
        artifact=packet['memories'][0];artifact['content']='Counterfeit controlled replacement'
        artifact['content_sha256']=store.digest(artifact['content'].encode())
        artifact['artifact_sha256']=store.digest({k:v for k,v in artifact.items() if k!='artifact_sha256'})
        packet['lineage']=[store._node(artifact)]
        packet['content_sha256']=store.digest({k:v for k,v in packet.items() if k!='content_sha256'});results.append(invoke())
    elif cid=='F16':
        results.append(invoke())
        a=store.AgentStore(path/'A.sqlite','A');p=store.TrustedPolicy(path/'policy.sqlite')
        other=store.export_package(a,p,'B',['M000'],batch_id=packet['batch_id']);a.close();p.close()
        results.append(call(path,other,method));events+=['different_packet_claims_same_batch']
    elif cid=='F18':
        permission(path,['S000'],recipient='C');events+=['unrelated_recipient_policy_changed'];results.append(invoke())
    elif cid=='F19':
        if method in ('plain_file','basic_integrity_acl'):
            # Their single durable operation has no multi-table pre-COMMIT
            # partial state; terminate a worker before invoking that operation.
            proc=subprocess.run([sys.executable,'-c','import os; os._exit(92)'],capture_output=True,timeout=10)
            crash_result={'mode':'before_operation','exit_code':proc.returncode,'disk_effects_after_exit':raw_effect_count(path,method)}
        else:crash_result=crash(path,packet,method,'before_commit')
        results.append(invoke());events+=['precommit_process_crash','restart_and_retry']
    elif cid=='F20':
        a=store.AgentStore(path/'A.sqlite','A');b=store.AgentStore(path/'B.sqlite','B');p=store.TrustedPolicy(path/'policy.sqlite')
        ref=b.add_original('B-S','Controlled reverse fact');b.add_memory('B-M','Controlled reverse memory',source_ids=['B-S'])
        p.register_sources([ref]);p.set_permissions('A',['B-S'])
        packet=store.export_package(a,p,'B',['M000'],batch_id='forward-batch')
        reverse=store.export_package(b,p,'A',['B-M'],batch_id='reverse-batch');a.close();b.close();p.close()
        barrier=threading.Barrier(2,timeout=15)
        threads=[threading.Thread(target=lambda q=q, ag=ag:results.append(call(path,q,method,ag,barrier.wait))) for q,ag in [(packet,'B'),(reverse,'A')]]
        for t in threads:t.start()
        for t in threads:
            t.join(20)
            if t.is_alive():raise RuntimeError('bidirectional_timeout')
        events+=['two_independent_direction_commits']
    else:results.append(invoke())
    effects=raw_effect_count(path,method)+(raw_effect_count(path,method,'A') if cid=='F20' else 0)
    unauthorized=effects>0 and cid in ('F01','F02','F03','F11','F12','F14','F15')
    epoch_inconsistent=effects>0 and cid in ('F13','F18')
    duplicate=max(0,effects-expected) if expected>0 else 0
    expected_recovery=cid in ('F05','F06','F07','F08','F09','F17','F19')
    retry_accepted=bool(results and results[-1].get('accepted')) if expected_recovery else None
    recovery=bool(retry_accepted and effects==expected and not unauthorized) if expected_recovery else None
    metadata_safe=all(not r.get('receipt_contains_memory',False) for r in results)
    if cid in ('F09','F10','F20'):recovery=None
    policy_eligible=expected>0 or cid in ('F13','F18')
    return {'case_id':cid,'case':label,'method':method,'expected_commits':expected,'actual_commits':effects,
            'matches_strict_frozen_oracle':effects==expected,'unauthorized_first_delivery':bool(unauthorized),
            'stale_epoch_admission':bool(epoch_inconsistent),'duplicate_effects':duplicate,
            'legal_commit_missing':bool(expected>0 and effects<expected),'recovery_confirmed':recovery,
            'retry_request_accepted':retry_accepted,
            'current_source_policy_eligible':policy_eligible,
            'current_policy_legal_false_reject':bool(policy_eligible and effects==0),
            'ack_plaintext_safe':metadata_safe,'operations':results,'crash':crash_result,
            'events':events,'database_directory':str(path.relative_to(ROOT)),
            'unit':'targeted deterministic lifecycle case, not independent business project'}


def process_rss_bytes():
    if os.name!='nt':return None
    from ctypes import wintypes
    class PMC(ctypes.Structure):
        _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD),('PeakWorkingSetSize',ctypes.c_size_t),('WorkingSetSize',ctypes.c_size_t),('QuotaPeakPagedPoolUsage',ctypes.c_size_t),('QuotaPagedPoolUsage',ctypes.c_size_t),('QuotaPeakNonPagedPoolUsage',ctypes.c_size_t),('QuotaNonPagedPoolUsage',ctypes.c_size_t),('PagefileUsage',ctypes.c_size_t),('PeakPagefileUsage',ctypes.c_size_t)]
    counters=PMC();counters.cb=ctypes.sizeof(counters)
    psapi=ctypes.WinDLL('psapi',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(PMC),wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype=wintypes.BOOL
    if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):return None
    return counters.WorkingSetSize


def performance(run_dir):
    rows=[]
    for n in (1,8,32):
        for repetition in range(12):
            # Rotate methods deterministically to reduce monotonic warming bias.
            order=METHODS[:4];order=order[repetition%4:]+order[:repetition%4]
            for method in order:
                path=run_dir/f'perf-{n:02d}-{repetition:02d}-{method}';packet=fixture(path,n)
                m=module_for(method)
                phase={'authorization_validation_ns':0,'package_verification_ns':0,'persistent_commit_sql_ns':0}
                class TimedConnection(sqlite3.Connection):
                    def execute(self, sql, parameters=()):
                        start=time.perf_counter_ns()
                        try:return super().execute(sql,parameters)
                        finally:
                            if sql.strip().upper()=='COMMIT':phase['persistent_commit_sql_ns']+=time.perf_counter_ns()-start
                def connect_timed(file):
                    file=Path(file).resolve()
                    db=sqlite3.connect(file,factory=TimedConnection,isolation_level=None,timeout=10)
                    db.row_factory=sqlite3.Row
                    db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA busy_timeout=10000')
                    assert db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete'
                    db.execute('PRAGMA synchronous=FULL')
                    return file,db
                m._connect=connect_timed
                b=m.AgentStore(path/'B.sqlite','B');p=m.TrustedPolicy(path/'policy.sqlite')
                for key in phase:phase[key]=0
                for fn,key in [('_validate_authority','authorization_validation_ns')]:
                    original=getattr(m,fn)
                    def timed(*args,_fn=original,_key=key,**kwargs):
                        start=time.perf_counter_ns()
                        try:return _fn(*args,**kwargs)
                        finally:phase[_key]+=time.perf_counter_ns()-start
                    setattr(m,fn,timed)
                original_import=m.import_package
                def timed_import(receiver,policy,pack):
                    start=time.perf_counter_ns()
                    def verified():phase['package_verification_ns']+=time.perf_counter_ns()-start
                    return original_import(receiver,policy,pack,before_commit=verified)
                m.import_package=timed_import
                initial_storage={name:(path/name).stat().st_size for name in ('A.sqlite','B.sqlite','policy.sqlite')}
                rss_before=process_rss_bytes();tracemalloc.start();cpu=time.process_time_ns();started=time.perf_counter_ns()
                try:
                    result=execute_open(path,packet,method,m,b,p,phase)
                    elapsed=time.perf_counter_ns()-started;cpu_elapsed=time.process_time_ns()-cpu
                    current,peak=tracemalloc.get_traced_memory()
                    first_phase=dict(phase)
                    first_storage={name:(path/name).stat().st_size for name in ('A.sqlite','B.sqlite','policy.sqlite')}
                    first_handoff_bytes=(path/'B.handoff.jsonl').stat().st_size if (path/'B.handoff.jsonl').exists() else 0
                    first_effects=raw_effect_count(path,method)
                finally:
                    tracemalloc.stop()
                rss_after=process_rss_bytes()
                recovery_start=time.perf_counter_ns()
                recovery_result=execute_open(path,packet,method,m,b,p)
                recovery_ns=time.perf_counter_ns()-recovery_start
                retry_effects=raw_effect_count(path,method)
                b.close();p.close()
                rows.append({'memory_count':n,'repetition':repetition,'method':method,
                    'host_processing_ns':elapsed,'cpu_ns':cpu_elapsed,'python_peak_allocated_bytes':peak,
                    'recovery_attempt_ns':recovery_ns,'recovery_status':recovery_result['status'],
                    'recovery_without_new_effect':retry_effects==first_effects,
                    'process_working_set_before_bytes':rss_before,'process_working_set_after_bytes':rss_after,
                    'packet_bytes':len(store.canonical(packet)),
                    'receiver_storage_bytes':first_storage['B.sqlite']+first_handoff_bytes,
                    'receiver_storage_delta_bytes':first_storage['B.sqlite']-initial_storage['B.sqlite']+first_handoff_bytes,
                    'persistent_storage_delta_bytes':sum(first_storage.values())-sum(initial_storage.values())+first_handoff_bytes,
                    'initial_fixture_storage_bytes':sum(initial_storage.values()),
                    'scope':'all connections preopened; packet already generated/sealed; first verification+persist effect; recovery separately timed; phase clocks add instrumentation overhead',
                    **first_phase,'model_api_calls':0,'model_api_cost':0})
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker',nargs=4);parser.add_argument('--run-id',default='run_20261106_v1');parser.add_argument('--skip-performance',action='store_true');parser.add_argument('--performance-only',action='store_true');args=parser.parse_args()
    if args.worker:
        path,packet,method,mode=args.worker;worker(Path(path),Path(packet),method,mode);return
    run_dir=OUT/args.run_id
    if run_dir.exists():raise SystemExit('Refusing to overwrite an existing run directory: '+str(run_dir))
    run_dir.mkdir(parents=True)
    (run_dir/'code').mkdir()
    for file in (Path(__file__),Path(__file__).with_name('durable_delivery.py'),SOURCE):
        (run_dir/'code'/file.name).write_bytes(file.read_bytes())
    source_hash=sha(SOURCE)
    config={'schema':'paper-final-cpu-contract-v1','date':'2026-11-06','methods':METHODS,
            'cases':[] if args.performance_only else [{'case_id':c,'name':n,'strict_expected_commits':e}for c,n,e in CASES],
            'source_sha256':source_hash,'runner_sha256':sha(__file__),
            'adapter_sha256':sha(Path(__file__).with_name('durable_delivery.py')),
            'new_paid_model_calls':0,'statistical_unit':'targeted case; method rows are repeated configurations',
            'strong_reference':'same frozen mature transactional verifier core plus same metadata-only recovery as complete Host; not independent implementation',
            'precommit_durability':'SQLite DELETE journals and synchronous FULL on local disks; process crashes, not power-loss proof',
            'performance_repetitions':12,'performance_sizes':[1,8,32]}
    dump(run_dir/'config.json',config);started=time.perf_counter();rows=[]
    with (run_dir/'raw.jsonl').open('w',encoding='utf8') as f:
        for cid,label,expected in ([] if args.performance_only else CASES):
            for method in METHODS:
                row=qualify(cid,label,expected,run_dir/f'{cid}-{method}',method)
                rows.append(row);f.write(json.dumps(row,ensure_ascii=False)+'\n');f.flush()
            print(cid,'completed',flush=True)
    perf=[] if args.skip_performance else performance(run_dir)
    with (run_dir/'performance_raw.jsonl').open('w',encoding='utf8') as f:
        for row in perf:f.write(json.dumps(row,ensure_ascii=False)+'\n')
    summary=[]
    for method in METHODS:
        selected=[r for r in rows if r['method']==method]
        summary.append({'method':method,'cases':len(selected),'strict_oracle_matches':sum(r['matches_strict_frozen_oracle']for r in selected),
                        'unauthorized_case_count':sum(r['unauthorized_first_delivery']for r in selected),
                        'stale_epoch_case_count':sum(r['stale_epoch_admission']for r in selected),
                        'duplicate_effects':sum(r['duplicate_effects']for r in selected),
                        'legal_missing_case_count':sum(r['legal_commit_missing']for r in selected),
                        'current_policy_legal_false_reject_case_count':sum(r['current_policy_legal_false_reject']for r in selected),
                        'recovery_confirmed':sum(r['recovery_confirmed'] is True for r in selected),
                        'recovery_evaluable':sum(r['recovery_confirmed'] is not None for r in selected)})
    result={'schema':'paper-final-cpu-run-v1','finished_utc':datetime.now(timezone.utc).isoformat(),
            'targeted_cases':0 if args.performance_only else len(CASES),'method_rows':len(rows),'performance_rows':len(perf),
            'elapsed_seconds':time.perf_counter()-started,'python':sys.version,'platform':platform.platform(),'sqlite':sqlite3.sqlite_version,
            'source_unchanged':source_hash==sha(SOURCE),'summary':summary,
            'runner_sha256':sha(__file__),'config_sha256':sha(run_dir/'config.json'),'raw_sha256':sha(run_dir/'raw.jsonl'),
            'performance_raw_sha256':sha(run_dir/'performance_raw.jsonl'),'new_paid_model_calls':0,'github_writes':0}
    dump(run_dir/'run.json',result);print(json.dumps(result,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
