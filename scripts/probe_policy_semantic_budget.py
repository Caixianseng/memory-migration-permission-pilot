"""Zero-model request-size check using prior development baseline spans.

Only registered source text, task query and baseline findings are supplied to
the request constructor. Old answers/scores do not enter the component.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study import policy_semantics as sem
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.privacy import _policy


def probe(directory):
    directory = Path(directory)
    read = lambda name: json.loads((directory/name).read_bytes())
    stories = {s['story_id']: s for s in read('runtime.json')}
    stores = {(s['story_id'], s['builder']): s['records'] for s in read('record_store.json')}
    checks = []
    for row in read('rows.json'):
        if row['arm'] != 'reference_id' or row['actor_id'] != 'owner':
            continue
        story = stories[row['story_id']]
        task = next(t for t in story['tasks'] if t['task_id'] == row['task_id'])
        records = stores[(row['story_id'], 'reference_id')]
        payload = {'query': task['query'], 'memories': [{'source_id': r['record_id'], 'text': r['text']} for r in records]}
        policy = _policy(story['policy'])
        pool = propose_candidates(payload, policy, row['detection']['findings'])
        messages, schema = sem._input_material(payload, policy, pool, 24, 256)
        request = {'model': sem.runtime.MODEL, 'messages': messages, 'format': schema,
                   'stream': False, 'keep_alive': '30m', 'options': dict(sem.OPTIONS)}
        initial = len(sem._json(request).encode('utf-8'))+320+1024
        repair = {**request, 'messages': [*messages, {'role': 'user', 'content': sem.REPAIR_PROMPT}]}
        repaired = len(sem._json(repair).encode('utf-8'))+320+1024
        checks.append({'story_id': row['story_id'], 'task_id': row['task_id'],
            'candidate_count': len(pool['candidates']), 'initial_bound': initial, 'repair_bound': repaired,
            'fits': initial <= 4096 and repaired <= 4096})
    return {'purpose': 'request_size_preflight_not_effectiveness', 'actual_model_calls': 0,
        'prompt_version': sem.PROMPT_VERSION, 'requests': checks,
        'fit_count': sum(row['fits'] for row in checks),
        'max_initial': max(row['initial_bound'] for row in checks),
        'max_repair': max(row['repair_bound'] for row in checks),
        'implementation_sha256': hashlib.sha256(Path(sem.__file__).read_bytes()).hexdigest(),
        'trace_sha256': {name: hashlib.sha256((directory/name).read_bytes()).hexdigest()
                        for name in ('runtime.json','record_store.json','rows.json')}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, default=ROOT/'results/reference_memory_development_20261025_v1')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('new_probe_output_required')
    result = probe(args.trace)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in {'requests','trace_sha256'}},ensure_ascii=False))
    raise SystemExit(0 if result['fit_count'] == len(result['requests']) else 1)
