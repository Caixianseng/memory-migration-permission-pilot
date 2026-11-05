"""Restore identities only after masked AI judgements have been saved."""
import argparse
import hashlib
import json
from pathlib import Path


def merge(root):
    root = Path(root)
    cases = json.loads((root / 'frozen_cases.json').read_text(encoding='utf-8'))
    rows, evidence = [], []
    for case in cases:
        cid = case['case_id']
        folder = root / 'review_blinded'
        package = json.loads((folder / (cid + '.json')).read_text(encoding='utf-8'))
        mapping = json.loads((folder / (cid + '.mapping.json')).read_text(encoding='utf-8'))
        review_path = folder / (cid + '.review.json')
        raw = review_path.read_bytes()
        review = json.loads(raw)
        if review.get('human_gold') is not None or review.get('method_labels_masked') is not True:
            raise ValueError('review_disclosure_missing')
        if package.get('case_id') != cid or package.get('method_labels_masked') is not True:
            raise ValueError('package_identity_invalid')
        global_ids = [q.get('question_id', q.get('id')) for q in package['questions_and_AI_references']]
        if any(not isinstance(qid, str) or not qid for qid in global_ids) or len(set(global_ids)) != len(global_ids):
            raise ValueError('package_question_identity_invalid')
        qids = set(global_ids)
        item_ids, expected = set(), set()
        for item in package['items']:
            rid = item['review_id']
            if not isinstance(rid, str) or not rid or rid in item_ids:
                raise ValueError('package_review_identity_invalid')
            item_ids.add(rid)
            selected = item.get('question_ids')
            if selected is None:
                if len(global_ids) != 3:
                    raise ValueError('question_bank_requires_per_item_question_ids')
                selected = global_ids  # Older three-question review packages.
            if (not isinstance(selected, list) or len(selected) != 3 or any(not isinstance(qid, str) for qid in selected)
                    or len(set(selected)) != 3 or not set(selected) <= qids):
                raise ValueError('package_item_question_identity_invalid')
            expected.update((rid, qid) for qid in selected)
        if set(mapping) != item_ids:
            raise ValueError('package_mapping_identity_mismatch')
        mapped_positions = []
        for identity in mapping.values():
            if identity.get('case_id') != cid or not isinstance(identity.get('method'), str) or type(identity.get('time')) is not int:
                raise ValueError('mapped_position_identity_invalid')
            mapped_positions.append((identity['case_id'], identity['method'], identity['time']))
        if len(set(mapped_positions)) != len(mapped_positions):
            raise ValueError('duplicate_mapped_position_identity')
        if review.get('input_package_sha256') is not None:
            package_raw = (folder / (cid + '.json')).read_bytes()
            if review['input_package_sha256'] != hashlib.sha256(package_raw).hexdigest():
                raise ValueError('review_package_hash_mismatch')
        seen = set()
        for row in review['rows']:
            key = (row['review_id'], row['question_id'])
            if (key not in expected or key in seen or type(row['semantic_correct']) is not bool
                    or type(row.get('ambiguous', False)) is not bool
                    or row.get('alternative_semantic_correct') is not None and type(row['alternative_semantic_correct']) is not bool
                    or not isinstance(row.get('reason'), str) or not row['reason'].strip()):
                raise ValueError('review_identity_or_score_invalid')
            seen.add(key)
            rows.append({**mapping[row['review_id']], 'question_id': row['question_id'],
                         'semantic_correct': row['semantic_correct'], 'reason': row['reason'],
                         'ambiguous': row.get('ambiguous', False),
                         'alternative_semantic_correct': row.get('alternative_semantic_correct'),
                         'masked_review_id': row['review_id']})
        if seen != expected:
            raise ValueError('incomplete_review')
        evidence.append({'case_id': cid, 'review_sha256': hashlib.sha256(raw).hexdigest(), 'judgments': len(seen)})
    output = {'schema': 'method-label-masked-AI-review-v1', 'human_gold': None,
              'method_labels_masked': True, 'payload_format_can_reveal_method_family': True,
              'independent_human_review': False, 'source_reviews': evidence, 'rows': rows}
    destination = root / 'ai_semantic_review.json'
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2)
    return {'case_clusters': len(cases), 'question_judgments': len(rows), 'human_gold': None}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    print(json.dumps(merge(args.root)))
