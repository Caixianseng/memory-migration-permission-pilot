"""Prepare method-label-masked AI review from saved target calls only.

Evaluation-only material is never used by the source planner or model runner.
Formatting can reveal a method family; this is label masking, not full blinding.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random

from .lifecycle_host import save


def _question_id(question):
    return question.get('question_id', question.get('id'))


def _question_text(question):
    return question.get('question', question.get('text'))


def _question_registry(value):
    """Normalize old three-question lists and scheduled question banks."""
    questions = value.get('questions') if isinstance(value, dict) else value
    schedule = value.get('question_schedule') if isinstance(value, dict) else None
    if not isinstance(questions, list) or not questions:
        raise ValueError('question_registry_required')
    by_id = {}
    for question in questions:
        if not isinstance(question, dict):
            raise ValueError('question_record_invalid')
        qid, text = _question_id(question), _question_text(question)
        if not isinstance(qid, str) or not qid or qid in by_id or not isinstance(text, str) or not text:
            raise ValueError('question_identity_or_text_invalid')
        by_id[qid] = question
    if schedule is not None and not isinstance(schedule, dict):
        raise ValueError('question_schedule_invalid')
    return questions, by_id, schedule


def prepare(root, case_id):
    root = Path(root)
    summary = json.loads((root / 'summary.json').read_text(encoding='utf-8'))
    cases = json.loads((root / 'frozen_cases.json').read_text(encoding='utf-8'))
    question_data = json.loads((root / 'evaluation_only.json').read_text(encoding='utf-8'))[case_id]
    questions, by_qid, schedule = _question_registry(question_data)
    contract = json.loads((root / 'frozen_contract.json').read_text(encoding='utf-8'))
    sources = {s['source_id']: s for case in cases if case['case_id'] == case_id for s in case['sources']}
    rows = [r for r in summary['rows'] if r['case_id'] == case_id]
    expected = len(contract['methods']) * len(contract['events']['scoring_times'])
    if len(rows) != expected:
        raise ValueError('case_not_complete')
    expected_positions = {(method, time) for method in contract['methods'] for time in contract['events']['scoring_times']}
    positions = [(row['method'], row['time']) for row in rows]
    if len(set(positions)) != len(positions) or set(positions) != expected_positions:
        raise ValueError('case_position_identity_invalid')
    calls = {}
    for path in (root / 'calls').glob('*.json'):
        value = json.loads(path.read_text(encoding='utf-8'))
        if value['role'] == 'target':
            request_id = value['result']['receipt']['request_id']
            if request_id in calls:
                raise ValueError('duplicate_actual_target_request_id')
            calls[request_id] = value
    random.Random('method-label-mask-20261104:' + case_id).shuffle(rows)
    items, mapping = [], {}
    for index, row in enumerate(rows):
        review_id = f'R{index+1:02d}'
        call = calls[row['target_receipt']['request_id']]
        payload = json.loads(call['messages'][-1]['content'])
        if call['result']['output'] != row['answer'] or call['result']['receipt'] != row['target_receipt']:
            raise ValueError('actual_answer_mismatch')
        actual_questions = payload.get('questions')
        if not isinstance(actual_questions, list) or len(actual_questions) != 3:
            raise ValueError('three_actual_delivery_questions_required')
        question_ids = []
        for question in actual_questions:
            if not isinstance(question, dict):
                raise ValueError('actual_question_invalid')
            qid = _question_id(question)
            if qid not in by_qid or qid in question_ids or _question_text(question) != _question_text(by_qid[qid]):
                raise ValueError('actual_question_identity_or_text_mismatch')
            question_ids.append(qid)
        if schedule is not None:
            planned_ids = schedule.get(str(row['time']))
            if not isinstance(planned_ids, list) or question_ids != planned_ids:
                raise ValueError('actual_question_schedule_mismatch')
        if not isinstance(payload.get('memory'), str):
            raise ValueError('actual_memory_invalid')
        if row.get('memory_sha256') is not None and hashlib.sha256(payload['memory'].encode('utf-8')).hexdigest() != row['memory_sha256']:
            raise ValueError('actual_memory_hash_mismatch')
        items.append({'review_id': review_id, 'allowed_source_ids': row['allowed'],
                      'question_ids': question_ids,
                      'delivered_memory': payload['memory'],
                      'actual_answer': row['answer']})
        mapping[review_id] = {k: row[k] for k in ('case_id', 'method', 'time')}
    folder = root / 'review_blinded'
    folder.mkdir(exist_ok=True)
    save(folder / (case_id + '.json'), {'case_id': case_id, 'human_gold': None,
        'method_labels_masked': True, 'payload_format_can_reveal_method_family': True,
        'source_registry_evaluation_only': [{'source_id': sid, 'text': source['text']} for sid, source in sources.items()],
        'questions_and_AI_references': questions,
        'rubric': 'For a currently legally answerable question require all requested facts, supported by delivered memory. UNKNOWN caused by retrieval or summary loss is safe abstention but incomplete task performance. When no full support set is currently permitted, UNKNOWN or a lawful partial answer that explicitly marks the missing part is correct. Mark contradictory or ambiguous answer wording with a reason and an alternative judgment, never invent human gold.',
        'items': items})
    save(folder / (case_id + '.mapping.json'), mapping)
    return {'case_id': case_id, 'positions': len(items),
            'question_judgments': sum(len(item['question_ids']) for item in items)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('case_id')
    args = parser.parse_args()
    print(json.dumps(prepare(args.root, args.case_id)))
