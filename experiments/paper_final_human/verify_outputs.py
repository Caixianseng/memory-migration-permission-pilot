"""Artifact/source checks only; no model, annotation or scientific rerun."""
import csv
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HUMAN=ROOT/'research_paper_v1/paper_final/evidence/human'
AI=HUMAN.parent/'ai_evaluation'


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    prepared=json.loads((HUMAN/'prepare_receipt.json').read_text(encoding='utf-8'))
    for name,expected in prepared['source_sha256'].items():assert sha(ROOT/'benchmarks/persistent_exchange_v1_public_20261105'/name)==expected,name
    preserved=['rater_1.html','rater_2.html','rater_1_blank.csv','rater_2_blank.csv','private_unblinding_key.json','items.blinded.json','presentation_order.json','historical_statistics_snapshot.json']
    for name in preserved:assert sha(HUMAN/name)==prepared['outputs_sha256'][name],name
    rows_by_stage={}
    required={'item_id','level','labels','confidence','basis','evidence_paths','judge','human_confirmed'}
    for stage in ('preliminary','crosscheck','final'):
        rows=[json.loads(line) for line in (AI/f'{stage}.jsonl').read_text(encoding='utf-8').splitlines()]
        assert len(rows)==768 and len({r['item_id'] for r in rows})==768
        assert all(required<=set(r) and r['human_confirmed'] is False for r in rows)
        rows_by_stage[stage]=rows
    assert all({r['item_id'] for r in rows}=={r['item_id'] for r in rows_by_stage['final']} for rows in rows_by_stage.values())
    summary=json.loads((AI/'summary.json').read_text(encoding='utf-8'));assert summary['B_pending']==0 and summary['B_reviewed_by_root']==98
    cards=json.loads((AI/'Ccards.json').read_text(encoding='utf-8'))
    case_items=[item for group in cards for item in group['items']]
    assert len(cards)==1 and len(case_items)==2
    assert {v['case_id'] for v in case_items}=={r['item_id'] for r in rows_by_stage['final'] if r['level']=='C'}
    card_fields={'case_id','original_input','agent_original_answer','ground_truth','permissions_at_time','AI_recommended_labels','dispute_reason','possible_interpretations','AI_recommended_final_judgment','one_question_for_researcher'}
    assert all(card_fields<=set(item) and item['human_confirmed'] is False for item in case_items)
    subset=json.loads((AI/'human_validation_subset/selection.json').read_text(encoding='utf-8'));assert subset['items']==48 and len(set(subset['item_ids']))==48
    for slot in (1,2):
        with (AI/f'human_validation_subset/validation_rater_{slot}_blank.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
        assert len(rows)==48 and all(not r['human_attestation'] and not r['rater_id'] and not r['FactualError'] for r in rows)
    validation=json.loads((AI/'human_validation_subset/analysis/validation_status.json').read_text(encoding='utf-8'));assert validation['status']=='pending' and validation['completed_items_by_rater']==[0,0]
    trace=json.loads((AI/'local_source_trace.json').read_text(encoding='utf-8'))
    for name,expected in trace['input_hashes'].items():assert sha(ROOT/name)==expected,name
    assert len(trace['items'])==51 and trace['summary']['multiple_or_unresolved_causes']==2
    assert all(x['reference_supports_currently_authorized'] for x in trace['items'])
    metadata={'schema':'AI-and-human-evaluation-artifact-verification-v1','date_local':'2026-11-06','checks':'pass','AI_items':768,'B_reviewed':98,'C_items':2,'C_root_cause_cards':1,'additional_local_trace_inputs':len(trace['input_hashes']),'former_C_items_resolved_operationally':49,'human_validation_subset_items':48,'human_validation_optional':True,'human_confirmed':0,'original_data_hashes_unchanged':True,'original_full_human_blank_instruments_unchanged':True,'human_labels_fabricated':False,'paid_model_calls':0,'scientific_experiment_reruns':0,'source_script_hashes':{p.name:sha(p) for p in Path(__file__).parent.iterdir() if p.is_file()},'final_outputs_hashes':{p.name:sha(p) for p in AI.iterdir() if p.is_file() and p.name!='evaluation_receipt.json'}}
    (AI/'evaluation_receipt.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in metadata.items() if not k.endswith('hashes')},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
