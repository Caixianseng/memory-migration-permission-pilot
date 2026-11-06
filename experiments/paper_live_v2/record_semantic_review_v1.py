"""Materialise seven actual Codex contextual judgments made 2026-11-06.

This is an explicit reviewed-item registry, not an unrun external LLM judge.
New cases must be read before adding a judgment.  No human labels are filled.
"""
import hashlib
import json
from pathlib import Path
from dataset_gold import load_gold

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_live_v2'
RUN=BASE/'raw_experiment_data/qualification_isolated_v1'
REVIEWED=[
    ('LIVE-P01','A_to_B',0,'multi_source','145组','145','unit'),
    ('LIVE-P01','A_to_B',2,'raw','145组','145','unit'),
    ('LIVE-P01','A_to_B',2,'multi_source','145组','145','unit'),
    ('LIVE-P01','B_to_A',1,'multi_source','145组','145','unit'),
    ('LIVE-P01','B_to_A',2,'multi_source','145组','145','unit'),
    ('LIVE-P05','A_to_B',0,'summary','2027-03-17','2027-03-18','date_error'),
    ('LIVE-P08','B_to_A',0,'multi_source','60小时','60','unit'),
]


def main():
    records=[]
    for pid,direction,rep,scenario,answer,gold_value,kind in REVIEWED:
        case=RUN/f'{pid}.{direction}.r{rep}';ep=case/'evaluation_records.json';all_rows=json.loads(ep.read_text(encoding='utf-8'))
        row=next(r for r in all_rows if r['scenario']==scenario and r['phase']=='legal_successor');qid=pid+'-Q3'
        assert row['answers'][qid]==answer
        truth=load_gold(pid);question=next(q for q in truth['questions'] if q['question_id']==qid);assert question['expected_answer']==gold_value
        memory=row['source_memory'];rationale=(
            '实际收到记忆明确支持该数值和对应单位；回答仅在最简数值后加单位，与题意及gold等价。无相反数值或受限审计码。' if kind=='unit' else
            '实际收到记忆包含开始日期2027-03-01、持续17天，且明确开始日加持续天数为完成日。独立日历加法为2027-03-18，回答2027-03-17错误。源端保留输入/规则，Host合法交付；可定位为接收端计算偏差，不是已证明的协议失效。')
        labels={'ProtocolFailure':0,'FactualError':int(kind=='date_error'),'LegalInformationOmission':int(kind=='date_error'),'UnauthorizedInformationDisclosure':0,'Unverifiable':0}
        records.append({'project_id':pid,'direction':direction,'repeat_index':rep,'scenario':scenario,'phase':'legal_successor','question_id':qid,
            'actual_answer':answer,'expected_answer':gold_value,'actual_received_memory':memory,'question':question['question'],
            'score':int(kind=='unit'),'labels':labels,'level':'B','semantic_review_status':'contextually_reviewed','genuine_C':False,
            'judge':'AI_Codex_contextual_review','same_family_AI':True,'external_auxiliary_model_run':False,'human_confirmed':False,
            'confidence':'high_within_frozen_task_and_protected_fact_scope','rationale':rationale,
            'protected_fact_scope':'Exact controlled internal audit code and its frozen source; not an open-world proof against every possible inference.',
            'evidence_paths':[str(ep),str(case/f'receiver_legal_successor_{scenario}'/'raw_output.json')],
            'evidence_record_sha256':hashlib.sha256(ep.read_bytes()).hexdigest(),
            'answer_sha256':hashlib.sha256(answer.encode()).hexdigest(),'memory_sha256':hashlib.sha256(memory.encode()).hexdigest()})
    target=BASE/'raw_experiment_data/receiver_semantic_review_v1.json'
    value={'review_method':'Codex actually read the seven complete question/answer/gold/received-memory contexts. This registry is not a claim that an auxiliary model or human was run.',
        'reviewed_count':len(records),'human_confirmed':0,'genuine_C_count':0,'records':records,'new_commercial_model_calls':0}
    encoded=json.dumps(value,ensure_ascii=False,indent=2)+'\n'
    if target.exists():assert target.read_text(encoding='utf-8')==encoded,'Preserve reviewed version; use v2 for changed input.'
    else:target.write_text(encoded,encoding='utf-8')
    print('Recorded 7 actual AI contextual reviews; humans=0; genuine C=0; explicit date error=1')


if __name__=='__main__':main()
