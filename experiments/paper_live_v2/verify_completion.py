"""Read-only artifact/SQLite verification, separate from scientific validity."""
import hashlib,json,sqlite3,time
from pathlib import Path
from .live_runtime import ROOT,OUT
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def effective(job):
    for name in ('local_parse_recovery.json','safe_predispatch_retry/result.json','safe_precreation_retry/result.json','result.json'):
        f=job/name
        if f.exists():
            j=load(f)
            if j.get('status')=='ok':return j
    raise AssertionError('no verified effective output '+str(job))
def main():
    base=OUT/'raw_experiment_data/qualification_isolated_v1'
    projects=load(OUT/'raw_experiment_data/dataset/projects.json');golds=load(OUT/'raw_experiment_data/dataset/gold.scoring_only.json')
    rows=[];qa=[];databases=0;hashchecks=0;safety={m:{'initial_accepts':0,'initial_exact_controlled_token_payloads':0,'legal_accepts':0} for m in ('A_file','B_static_hash','C_dynamic_precheck','D_transaction','E_host')}
    initial_answer_token_hits=0
    for pid in projects:
        for direction in ('A_to_B','B_to_A'):
            for repeat in range(3):
                c=base/f'{pid}.{direction}.r{repeat}';assert load(c/'complete.json')['status']=='completed'
                delivery=load(c/'delivery_records.json');assert len(delivery)==30;rows.extend(delivery)
                answers=load(c/'evaluation_records.json');assert len(answers)==6;qa.extend(answers)
                actual=load(c/'persistent/readback.json');restricted=golds[pid]['restricted_values'][0]
                for phase,source_job in [('initial','source_initial_generation'),('legal_successor','source_legal_rebuild')]:
                    src=effective(c/source_job)
                    texts={s:src['parsed']['scenarios'][s]['memory_text'] for s in ('raw','summary','multi_source')}
                    assert actual[phase]['A_file']==actual[phase]['B_static_hash']==texts
                    for scenario,text in texts.items():
                        f=c/'persistent/B_static_hash'/f'{phase}.{scenario}.txt';meta=load(f.with_suffix('.integrity.json'))
                        assert hashlib.sha256(f.read_bytes()).hexdigest()==meta['sha256']==hashlib.sha256(text.encode()).hexdigest();hashchecks+=1
                    if phase=='initial':assert all(not actual[phase][m] for m in ('C_dynamic_precheck','D_transaction','E_host'))
                    else:assert all(actual[phase][m]==texts for m in safety)
                for row in delivery:
                    if row['accepted']:
                        key='initial_accepts' if row['phase']=='initial' else 'legal_accepts';safety[row['method']][key]+=1
                        if row['phase']=='initial' and restricted in actual['initial'][row['method']][row['scenario']]:safety[row['method']]['initial_exact_controlled_token_payloads']+=1
                for answer in answers:
                    if answer['phase']=='initial' and any(restricted in v for v in answer['answers'].values()):initial_answer_token_hits+=1
                    if answer['phase']=='legal_successor':assert restricted not in answer['source_memory']
                for name in ('sender.sqlite','authority.sqlite','D_transaction.sqlite','E_host.sqlite'):
                    dbpath=c/'persistent'/name;before=sha(dbpath)
                    db=sqlite3.connect(dbpath.resolve().as_uri()+'?mode=ro',uri=True)
                    try:
                        assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
                        if name in ('D_transaction.sqlite','E_host.sqlite'):
                            assert db.execute('SELECT COUNT(*) FROM batches').fetchone()[0]==3
                            assert all(restricted not in row[0] for row in db.execute('SELECT content FROM memories'))
                    finally:db.close()
                    assert before==sha(dbpath);databases+=1
    assert len(rows)==1800 and len(qa)==360
    audit=load(OUT/'raw_experiment_data/attempt_audit/attempt_summary.json')
    live=load(OUT/'raw_experiment_data/live_summary.json')
    assert live['case_counts']=={'completed':60}
    assert live['platforms']['hy3']['native_prompts_observed']==240
    assert live['platforms']['flash']['physical_requests_observed']==240
    config=load(OUT/'raw_experiment_data/protocol/protocol_run_20261106_v1/config.json')
    assert sha(ROOT/'experiments/persistent_exchange_v1/store.py')==config['store_sha256']
    old=load(ROOT/'research_paper_v1/paper_final/evidence/paper_artifact_receipt.json');historical=[]
    for record in old['files']:
        p=ROOT/record['path']
        if sha(p)!=record['sha256']:historical.append(record['path'])
    assert not historical,historical
    exact=load(OUT/'raw_experiment_data/exact_original_live/quality/summary.json');assert exact['observed_conditions']==60
    paired=load(OUT/'same_family_control/final_audit.json');assert paired['completed_projects']==10 and paired['new_receiver_prompts']==20
    required=['llm_model_comparison.md','agent_memory_generation_experiments.md','protocol_baseline_comparison.md','ablation_experiments.md','attack_and_failure_injection.md','model_quality_evaluation.md','performance_benchmark.md']
    assert all((OUT/n).is_file() and (OUT/n).stat().st_size>100 for n in required)
    assert all((OUT/n).is_dir() for n in ('raw_experiment_data','analysis_scripts','paper_figures'))
    figures=[p for p in (OUT/'paper_figures').glob('*.png')];assert len(figures)==6
    assert all((p.with_suffix('.pdf')).exists() and (p.with_suffix('.svg')).exists() for p in figures)
    receipt={'schema':'live-v2-completion-readonly-check-v1','observed_unix':time.time(),
        'primary_projects':10,'primary_pipeline_cases':60,'primary_actual_inference_jobs':480,
        'primary_native_user_turns':240,'primary_sdk_physical_requests':240,'primary_reserved_attempts':487,
        'primary_known_zero_dispatch_failures':7,'primary_source_texts':360,'primary_receiver_answer_rows':360,
        'primary_receiver_answer_fields':1440,'primary_delivery_rows':1800,'retrospective_B_file_hash_checks':hashchecks,
        'hash_check_timing':'final read-only verification; CPU B verifies hash at its accept gate. Live data have no body tampering.',
        'host_databases_readonly_quick_checked':databases,'original_paper_final_files_hash_checked':len(old['files']),
        'historical_changes':historical,'frozen_store_unchanged':True,'live_persistence_safety':safety,
        'initial_QA_exact_controlled_token_answers':initial_answer_token_hits,
        'exact_original_actual_receiver_calls':60,'same_family_actual_QA_calls':20,
        'smoke_joint_context_inference_jobs_excluded_from_main':8,'actual_arithmetic_qualification_calls':3,
        'total_new_completed_inference_jobs_across_substudies':571,
        'native_user_turns_not_assumed_equal_supplier_request_count':True,
        'main_sdk_usage_peak_estimate_cny':live['sdk_known_usage_peak_estimate_cny'],'supplier_invoice_available':False,
        'human_confirmation_not_fabricated':True,'github_writes':0,'legacy_experiment_reruns':0,
        'checks':'pass','scope':'Counts/hashes/disk effects; not novelty, universal semantic security or submission readiness.'}
    target=OUT/'raw_experiment_data/completion_audit.json';target.write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in receipt.items() if k not in ('scope','hash_check_timing')},ensure_ascii=False))
if __name__=='__main__':main()
