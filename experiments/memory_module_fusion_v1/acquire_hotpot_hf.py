"""Canonical HotpotQA repository fallback, pinned Parquet + mandatory LFS hash."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

from .prepare_hotpot import DATA, HERE, encode, write_once

REPOSITORY = 'hotpotqa/hotpot_qa'
REVISION = '1908d6afbbead072334abe2965f91bd2709910ab'
FILE = 'distractor/validation-00000-of-00001.parquet'
HOST = 'https://hf-mirror.com'


def get(url, limit=70_000_000):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=40) as response:
        raw = response.read(limit+1)
    if len(raw) > limit:
        raise ValueError('public_file_size_limit')
    return raw


def main():
    sys.path.insert(0, str(HERE / '.deps/data'))
    import pyarrow.parquet as pq
    DATA.mkdir(parents=True, exist_ok=True)
    metadata_path = DATA / 'hf_tree_pinned.json'
    if not metadata_path.exists():
        tree = json.loads(get(f'{HOST}/api/datasets/{REPOSITORY}/tree/{REVISION}/distractor?expand=true'))
        write_once(metadata_path, encode(tree))
    tree = json.loads(metadata_path.read_text(encoding='utf-8'))
    entry = next(row for row in tree if row['path'] == FILE)
    expected = entry.get('lfs', {}).get('oid')
    if not expected or len(expected) != 64:
        raise ValueError('pinned_lfs_sha256_missing')
    target = DATA / 'upstream_validation.parquet'
    if target.exists():
        raw = target.read_bytes()
    else:
        raw = get(f'{HOST}/datasets/{REPOSITORY}/resolve/{REVISION}/{FILE}?download=1')
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected or len(raw) != entry['size']:
        raise ValueError('pinned_lfs_hash_or_size_mismatch')
    write_once(target, raw)
    rows = pq.read_table(target).to_pylist()
    converted = []
    for row in rows:
        context = row['context']
        if isinstance(context, dict):
            context = [[title, sentences] for title, sentences in zip(context['title'], context['sentences'])]
        support = row['supporting_facts']
        if isinstance(support, dict):
            support = [[title, index] for title, index in zip(support['title'], support['sent_id'])]
        converted.append({'_id': row.get('id', row.get('_id')), 'question': row['question'],
            'answer': row['answer'], 'type': row['type'], 'level': row['level'],
            'context': context, 'supporting_facts': support})
    if len({row['_id'] for row in converted}) != len(converted):
        raise ValueError('duplicate_question_identity')
    body = json.dumps(converted, ensure_ascii=False).encode('utf-8')
    write_once(DATA / 'upstream_hotpot_dev_distractor_v1.json', body)
    write_once(DATA / 'acquisition_hf_fallback.json', encode({'repository': REPOSITORY,
        'revision': REVISION, 'origin': f'https://huggingface.co/datasets/{REPOSITORY}',
        'retrieval_host': HOST, 'file': FILE, 'upstream_parquet_sha256': actual,
        'mandatory_lfs_hash_matches': True, 'rows': len(rows),
        'converted_json_sha256': hashlib.sha256(body).hexdigest(),
        'conversion': 'schema-only id/context/supporting_facts conversion, no content or answer changes',
        'original_cmu_json_hash_verified': False, 'license': 'CC-BY-SA-4.0', 'model_calls': 0}))
    print(json.dumps({'rows': len(rows), 'parquet_sha256_verified': actual,
                      'converted_json_bytes': len(body)}))


if __name__ == '__main__':
    main()
