"""Fixed HotpotQA dev projection; selectors never receive evaluation labels."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import urllib.request

HERE = Path(__file__).resolve().parent
DATA = HERE / 'data_hotpot'
URLS = ('https://curtis.ml.cmu.edu/datasets/hotpot/hotpot_dev_distractor_v1.json',
        'http://curtis.ml.cmu.edu/datasets/hotpot/hotpot_dev_distractor_v1.json')
DEV, TEST, SEED = 8, 16, 2026110537


def sha(value):
    return hashlib.sha256(value).hexdigest()


def write_once(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != body:
            raise ValueError('frozen_data_changed:' + path.name)
    else:
        with path.open('xb') as stream:
            stream.write(body)


def encode(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode('utf-8')


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    write_once(DATA / 'selection_contract.json', encode({'dataset': 'HotpotQA dev_distractor_v1',
        'official_route': 'https://hotpotqa.github.io/', 'license': 'CC-BY-SA-4.0',
        'selection': 'sort all original _id lexicographically; first8 development, next16 reserved; no outcome/type/support/length selection',
        'dev': DEV, 'reserved': TEST, 'source_unit': 'one entire original sentence with paragraph title',
        'permission_seed': SEED, 'permission_schedule': 'all -> independently sampled floor(30% source count) revoked -> all regranted',
        'gold_support_not_exhaustive': True, 'model_calls': 0}))
    raw_path = DATA / 'upstream_hotpot_dev_distractor_v1.json'
    if not raw_path.exists():
        errors = []
        for url in URLS:
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 research-reproduction'})
                with urllib.request.urlopen(request, timeout=35) as response:
                    raw = response.read(70_000_001)
                if len(raw) > 70_000_000:
                    raise ValueError('public_data_too_large')
                parsed = json.loads(raw)
                if not isinstance(parsed, list) or len(parsed) < DEV + TEST:
                    raise ValueError('dataset_schema_mismatch')
                write_once(raw_path, raw)
                write_once(DATA / 'acquisition.json', encode({'url': url, 'bytes': len(raw),
                    'sha256': sha(raw), 'retrieved_utc': datetime.now(timezone.utc).isoformat()}))
                break
            except Exception as error:
                errors.append({'url': url, 'error_class': type(error).__name__})
        else:
            write_once(DATA / 'acquisition_failures.json', encode(errors))
            raise RuntimeError('official_public_route_unavailable')
    raw = raw_path.read_bytes()
    records = sorted(json.loads(raw), key=lambda item: item['_id'])[:DEV+TEST]
    cases, labels, schedules = [], {}, {}
    for index, record in enumerate(records):
        split = 'development' if index < DEV else 'reserved'
        sources, hierarchy, lookup = [], {}, {}
        for parent_index, (title, sentences) in enumerate(record['context']):
            parent = f'P{parent_index:02d}'
            for sentence_index, sentence in enumerate(sentences):
                if not isinstance(sentence, str):
                    raise ValueError('non_string_original_sentence')
                # Preserve even empty source sentences; the original title
                # provides nonempty bytes. No gold-driven pruning or padding.
                sid = f'S{len(sources)+1:03d}'
                prefix = title + '\n'
                sources.append({'source_id': sid, 'text': prefix+sentence, 'version': 1,
                    'origin': {'title': title, 'sentence_index': sentence_index,
                        'parent_index': parent_index, 'quote_start': len(prefix),
                        'quote_end': len(prefix)+len(sentence), 'quote_sha256': sha(sentence.encode('utf-8'))}})
                hierarchy[sid] = {'parent_id': parent, 'position': sentence_index, 'prev_id': None, 'next_id': None}
                lookup[(title, sentence_index)] = sid
        for sid, row in hierarchy.items():
            siblings = [key for key, val in hierarchy.items() if val['parent_id'] == row['parent_id']]
            position = siblings.index(sid)
            row.update(prev_id=siblings[position-1] if position else None,
                       next_id=siblings[position+1] if position+1 < len(siblings) else None)
        case_id = 'hotpot-'+record['_id']
        cases.append({'case_id': case_id, 'cluster_id': record['_id'], 'split': split,
            'question': record['question'], 'sources': sources, 'hierarchy': hierarchy})
        labels[case_id] = {'answer': record['answer'], 'type': record['type'], 'level': record['level'],
            'support_ids': [lookup[tuple(s)] for s in record['supporting_facts']],
            'support_annotation_is_exhaustive': False, 'human_new_permissions_review': None}
        ids = [s['source_id'] for s in sources]
        rng = random.Random(SEED + int(sha(case_id.encode())[:12], 16))
        revoked = set(rng.sample(ids, int(.3*len(ids))))
        schedules[case_id] = [{'time': 0, 'allowed': ids},
            {'time': 1, 'allowed': [sid for sid in ids if sid not in revoked]},
            {'time': 2, 'allowed': ids}]
    body = b''.join(json.dumps(case, ensure_ascii=False, sort_keys=True).encode('utf-8')+b'\n' for case in cases)
    write_once(DATA / 'cases.public.jsonl', body)
    write_once(DATA / 'evaluation_only.json', encode(labels))
    write_once(DATA / 'schedules.json', encode(schedules))
    result = {'upstream_sha256': sha(raw), 'cases_sha256': sha(body), 'cases': len(cases),
        'dev': DEV, 'reserved': TEST, 'sources_minmax': [min(len(c['sources']) for c in cases), max(len(c['sources']) for c in cases)],
        'total_complete_sentences': sum(len(c['sources']) for c in cases), 'model_calls': 0}
    write_once(DATA / 'validation.json', encode(result))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
