"""Final offline receipts: never dispatch, alter raw inputs, or fill human labels."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data'


def load(path):return json.loads(path.read_text(encoding='utf-8'))
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    quality=load(BASE/'evaluation/quality_summary.json');source=load(BASE/'source_evaluation/source_summary.json')
    semantic=load(BASE/'source_evaluation/semantic_review_summary.json');attempt=load(BASE/'attempt_audit/attempt_summary.json')
    cards_path=BASE.parent/'human_semantic_validation_cards.json';cards=load(cards_path)
    registry_versions=list(BASE.glob('receiver_semantic_review_v[0-9]*.json'));registry=max(registry_versions,key=lambda p:int(p.stem.rsplit('v',1)[1]));reviews=load(registry)
    assert quality['observed_conditions']==180 and quality['observed_question_fields']==720 and quality['complete_project_count']==10 and quality['missing_conditions']==0
    assert quality['AI_levels']=={'A':709,'B':10,'C':1} and quality['human_confirmed']==0 and quality['semantic_review_needed_items']==0
    assert source['observed_usable_source_texts']==360 and source['effective_usable_jobs']==120
    assert source['source_semantic_review_needed_records']==0 and source['source_semantic_review_completed_records']==360
    assert semantic['text_level_asserted_fact_consistency']=={'supported':355,'contradicted':2,'unknown':3}
    assert semantic['exactly_once_complete'] and semantic['all_memory_hashes_match_real_source_outputs']
    assert semantic['merged_review_sha256']==digest(BASE/'source_evaluation/semantic_review_all.jsonl')
    assert attempt['case_status_counts']=={'complete':60} and attempt['observed_job_directories']==480
    assert attempt['platform_counts']['hy3']['raw_strict_json_pass']==229 and attempt['platform_counts']['flash']['raw_strict_json_pass']==140
    assert attempt['platform_counts']['flash']['observed_physical_supplier_calls']==240
    assert attempt['platform_counts']['flash']['estimated_cost_cny_not_invoice_sum']=='0.778320'
    assert all(attempt['platform_counts'][p]['effective_status']=={'ok':240} for p in ('hy3','flash'))
    assert all(not c['human_confirmed'] and c['human_answer'] is None for c in cards['cards'])
    for c in cards['cards']:
        for path,h in c['evidence_sha256'].items():assert digest(Path(path))==h
    for path,h in quality['record_sha256'].items():assert digest(Path(path))==h
    for partition in semantic['source_partitions']:
        assert digest(BASE/'source_evaluation'/partition['file'])==partition['sha256']
    for r in reviews['records']:
        assert not r['human_confirmed'] and digest(Path(r['evidence_paths'][0]))==r['evidence_record_sha256']
    semantic_receipt={'cards':5,'distinct_execution_cases':5,'genuine_C_receiver':1,'AI_contextually_reviewed_receiver_fields':11,
        'AI_contextually_reviewed_source_texts':360,'actual_human_confirmed':0,
        'concise_characters':len((BASE.parent/'human_semantic_validation_cards_concise.md').read_text(encoding='utf-8')),
        'all_card_evidence_hashes_verified':True,'all_review_record_hashes_verified':True,'no_new_model_calls':True,
        'review_registry_sha256':digest(registry),'card_json_sha256':digest(cards_path)}
    (BASE/'semantic_evaluation_receipt.json').write_text(json.dumps(semantic_receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    files=[BASE/'evaluation/quality_summary.json',BASE/'source_evaluation/source_summary.json',BASE/'source_evaluation/semantic_review_all.jsonl',BASE/'source_evaluation/semantic_review_summary.json',BASE/'attempt_audit/attempt_summary.json',registry,BASE.parent/'model_quality_evaluation.md',cards_path]
    receipt={'status':'complete_controlled_field_and_full_AI_source_context_evaluation','main_completed_cases':60,'main_effective_jobs':480,
        'model_quality_conditions':180,'question_fields':720,'source_texts':360,'independent_project_units':10,
        'AI_levels':quality['AI_levels'],'AI_contextually_reviewed_receiver_fields':11,'genuine_C_receiver_fields':1,'actual_humans':0,
        'full_source_contextual_review_completed':360,'source_text_consistency':semantic['text_level_asserted_fact_consistency'],
        'source_input_omission_texts_at_least':semantic['at_least_texts_with_detected_input_omissions'],
        'source_requested_result_not_explicit':semantic['requested_derived_conclusion_not_explicit'],
        'source_atomic_fact_precision':'not_claimed_or_fabricated','human_gold':'not_claimed','uniform_exhaustive_completeness_rate':'not_claimed',
        'original_strict_json_main':{'hy3':'229/240','flash':'140/240'},'safe_zero_submission_fresh_attempts':7,
        'source_original_strict_json':'107/120','main_flash_estimated_cost_CNY_not_invoice':'0.778320',
        'manifest_self_reference_valid':quality['manifest_self_reference_check']['valid'],'other_manifest_data_hashes_verified':True,
        'all_completed_record_card_and_source_partition_hashes_verified':True,'new_model_calls_by_this_evaluation_subtask':0,
        'files_sha256':{str(p.resolve()):digest(p) for p in files}}
    (BASE/'final_evaluation_receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in receipt.items() if k!='files_sha256'},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
