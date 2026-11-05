"""Offline identity checks for old fixed and new per-delivery question banks.

Every case, answer and receipt here is a synthetic transport fixture. No model,
API, real run, frozen research reference or evaluation result is read.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from .make_blind_review import prepare
from .merge_blind_reviews import merge


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def fixture(root, scheduled):
    cid = 'synthetic-blind-fixture'
    methods = [f'fixture-method-{i}' for i in range(6 if scheduled else 9)]
    times = [0, 1, 2, 6, 7, 8, 12, 13, 14] if scheduled else [0, 2, 4]
    questions = [{'question_id': f'Q{i + 1}', 'question': f'Fixture question {i + 1}?',
                  'reference_answer': f'EVALUATION_ONLY_{i + 1}', 'support_source_ids': ['S01']}
                 for i in range(9 if scheduled else 3)]
    schedule = {str(time): [questions[(time % 3) * 3 + i]['question_id'] for i in range(3)] for time in times} if scheduled else None
    value = {'questions': questions, 'question_schedule': schedule} if scheduled else questions
    sources = [{'source_id': 'S01', 'text': 'Entire synthetic fixture source.'}]
    write(root / 'frozen_contract.json', {'methods': methods, 'events': {'scoring_times': times}})
    write(root / 'frozen_cases.json', [{'case_id': cid, 'sources': sources}])
    write(root / 'evaluation_only.json', {cid: value})
    rows = []
    for index, (method, time) in enumerate((method, time) for method in methods for time in times):
        selected = schedule[str(time)] if scheduled else [q['question_id'] for q in questions]
        public = [{'question_id': q['question_id'], 'question': q['question']} for q in questions if q['question_id'] in selected]
        memory = 'Synthetic fixture memory.'
        answer = json.dumps({qid: 'UNKNOWN' for qid in selected})
        receipt = {'request_id': f'synthetic-only-{index + 1:04}', 'instrument_only': True}
        rows.append({'case_id': cid, 'method': method, 'time': time, 'allowed': ['S01'],
                     'memory_sha256': hashlib.sha256(memory.encode()).hexdigest(),
                     'target_receipt': receipt, 'answer': answer})
        write(root / 'calls' / f'{index + 1:04}.json', {'role': 'target',
            'messages': [{'role': 'user', 'content': json.dumps({'memory': memory, 'questions': public})}],
            'result': {'receipt': receipt, 'output': answer}})
    write(root / 'summary.json', {'rows': rows})
    return cid, methods, times


def review_fixture(root, cid, *, legacy=False):
    folder = root / 'review_blinded'
    package = json.loads((folder / (cid + '.json')).read_text(encoding='utf-8'))
    if legacy:
        for item in package['items']:
            item.pop('question_ids')
        write(folder / (cid + '.json'), package)
    global_ids = [q['question_id'] for q in package['questions_and_AI_references']]
    rows = [{'review_id': item['review_id'], 'question_id': qid, 'semantic_correct': True,
             'reason': 'Synthetic evaluator identity fixture only.', 'ambiguous': False}
            for item in package['items'] for qid in item.get('question_ids', global_ids)]
    review = {'human_gold': None, 'method_labels_masked': True,
              'input_package_sha256': hashlib.sha256((folder / (cid + '.json')).read_bytes()).hexdigest(), 'rows': rows}
    write(folder / (cid + '.review.json'), review)
    return package, review


class BlindReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='d1-blind-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_old_three_question_package_27_positions_81_identities(self):
        cid, methods, times = fixture(self.root, False)
        result = prepare(self.root, cid)
        self.assertEqual((result['positions'], result['question_judgments']), (27, 81))
        package, _ = review_fixture(self.root, cid, legacy=True)
        self.assertEqual(len(package['questions_and_AI_references']), 3)
        result = merge(self.root)
        self.assertEqual(result['question_judgments'], 81)
        restored = json.loads((self.root / 'ai_semantic_review.json').read_text(encoding='utf-8'))['rows']
        self.assertEqual({(row['method'], row['time']) for row in restored}, {(method, time) for method in methods for time in times})

    def test_new_question_bank_54_positions_162_delivery_specific_identities(self):
        cid, methods, times = fixture(self.root, True)
        result = prepare(self.root, cid)
        self.assertEqual((result['positions'], result['question_judgments']), (54, 162))
        package, _ = review_fixture(self.root, cid)
        self.assertEqual(len(package['questions_and_AI_references']), 9)
        self.assertEqual(len(package['items']), 54)
        self.assertTrue(all(len(item['question_ids']) == 3 for item in package['items']))
        self.assertTrue(all('method' not in item and 'time' not in item for item in package['items']))
        result = merge(self.root)
        self.assertEqual(result['question_judgments'], 162)
        restored = json.loads((self.root / 'ai_semantic_review.json').read_text(encoding='utf-8'))['rows']
        self.assertEqual(len({(row['method'], row['time'], row['question_id']) for row in restored}), 162)
        for row in restored:
            self.assertIn(row['question_id'], {f'Q{(row["time"] % 3) * 3 + i + 1}' for i in range(3)})

    def test_prepare_rejects_duplicate_position_even_when_row_count_matches(self):
        cid, _, _ = fixture(self.root, True)
        summary = json.loads((self.root / 'summary.json').read_text())
        summary['rows'][1]['time'] = summary['rows'][0]['time']
        write(self.root / 'summary.json', summary)
        with self.assertRaisesRegex(ValueError, 'case_position_identity_invalid'):
            prepare(self.root, cid)

    def test_prepare_rejects_question_id_not_in_reference_bank(self):
        cid, _, _ = fixture(self.root, True)
        path = self.root / 'calls' / '0001.json'
        call = json.loads(path.read_text())
        payload = json.loads(call['messages'][-1]['content'])
        payload['questions'][0]['question_id'] = 'UNREGISTERED'
        call['messages'][-1]['content'] = json.dumps(payload)
        write(path, call)
        with self.assertRaisesRegex(ValueError, 'actual_question_identity_or_text_mismatch'):
            prepare(self.root, cid)

    def test_prepare_rejects_registered_question_from_wrong_delivery(self):
        cid, _, _ = fixture(self.root, True)
        path = self.root / 'calls' / '0001.json'
        call = json.loads(path.read_text())
        payload = json.loads(call['messages'][-1]['content'])
        payload['questions'] = [{'question_id': f'Q{i}', 'question': f'Fixture question {i}?'} for i in (4, 5, 6)]
        call['messages'][-1]['content'] = json.dumps(payload)
        write(path, call)
        with self.assertRaisesRegex(ValueError, 'actual_question_schedule_mismatch'):
            prepare(self.root, cid)

    def test_prepare_rejects_changed_question_text_under_valid_id(self):
        cid, _, _ = fixture(self.root, True)
        path = self.root / 'calls' / '0001.json'
        call = json.loads(path.read_text())
        payload = json.loads(call['messages'][-1]['content'])
        payload['questions'][0]['question'] = 'Different unregistered question?'
        call['messages'][-1]['content'] = json.dumps(payload)
        write(path, call)
        with self.assertRaisesRegex(ValueError, 'actual_question_identity_or_text_mismatch'):
            prepare(self.root, cid)

    def test_merge_rejects_cross_delivery_question_even_if_in_global_bank(self):
        cid, _, _ = fixture(self.root, True)
        prepare(self.root, cid)
        package, review = review_fixture(self.root, cid)
        first = review['rows'][0]
        selected = next(item['question_ids'] for item in package['items'] if item['review_id'] == first['review_id'])
        first['question_id'] = next(q['question_id'] for q in package['questions_and_AI_references'] if q['question_id'] not in selected)
        write(self.root / 'review_blinded' / (cid + '.review.json'), review)
        with self.assertRaisesRegex(ValueError, 'review_identity_or_score_invalid'):
            merge(self.root)

    def test_merge_rejects_duplicate_or_incomplete_judgments(self):
        cid, _, _ = fixture(self.root, True)
        prepare(self.root, cid)
        _, review = review_fixture(self.root, cid)
        path = self.root / 'review_blinded' / (cid + '.review.json')
        original = deepcopy(review)
        review['rows'][-1] = deepcopy(review['rows'][0])
        write(path, review)
        with self.assertRaisesRegex(ValueError, 'review_identity_or_score_invalid'):
            merge(self.root)
        original['rows'].pop()
        write(path, original)
        with self.assertRaisesRegex(ValueError, 'incomplete_review'):
            merge(self.root)

    def test_merge_rejects_mapping_identity_not_in_package(self):
        cid, _, _ = fixture(self.root, True)
        prepare(self.root, cid)
        review_fixture(self.root, cid)
        path = self.root / 'review_blinded' / (cid + '.mapping.json')
        mapping = json.loads(path.read_text())
        mapping['EXTRA'] = dict(next(iter(mapping.values())))
        write(path, mapping)
        with self.assertRaisesRegex(ValueError, 'package_mapping_identity_mismatch'):
            merge(self.root)

    def test_merge_rejects_old_style_missing_ids_for_nine_question_bank(self):
        cid, _, _ = fixture(self.root, True)
        prepare(self.root, cid)
        package, review = review_fixture(self.root, cid)
        package['items'][0].pop('question_ids')
        write(self.root / 'review_blinded' / (cid + '.json'), package)
        with self.assertRaisesRegex(ValueError, 'question_bank_requires_per_item_question_ids'):
            merge(self.root)


if __name__ == '__main__':
    unittest.main()
