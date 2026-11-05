"""Acquire fixed unseen PersonaMem 8/9 histories; never fetch benchmark answers."""
from __future__ import annotations

import json
from pathlib import Path
import urllib.parse
from datetime import datetime, timezone

from experiments.revocation_grouping_v1.prepare_data import (
    REPO, REVISION, ORIGIN, get, digest, git_blob, encode, write_once_or_same,
)
from experiments.revocation_grouping_v1.prepare_long_workload import project

HERE = Path(__file__).resolve().parent
PERSONAS = (8, 9)
HOST = 'https://hf-mirror.com'


def main():
    data = HERE / 'data_reserved'
    manifest_path = data / 'upstream_manifest.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest['revision'] != REVISION or manifest['persona_ids'] != list(PERSONAS):
            raise ValueError('frozen_selection_mismatch')
    else:
        tree = HOST + '/api/datasets/' + REPO + '/tree/' + REVISION
        root, listing = json.loads(get(tree)), json.loads(get(tree + '/data/chat_history_32k'))
        selected = [row for row in root if row['path'] == 'README.md']
        for persona in PERSONAS:
            path = f'data/chat_history_32k/chat_history_250911_213118_persona{persona}.json'
            rows = [row for row in listing if row['path'] == path]
            if len(rows) != 1:
                raise ValueError('fixed_persona_missing_no_substitution')
            selected.extend(rows)
        manifest = {'schema': 'revocation-prefix-reserved-acquisition-v1',
            'repository': REPO, 'revision': REVISION, 'persona_ids': list(PERSONAS),
            'origin': ORIGIN + '/datasets/' + REPO + '/tree/' + REVISION,
            'host': HOST, 'license': 'CC-BY-4.0', 'files': selected,
            'selection_rule': 'fixed previously unused persona IDs 8,9; first32 complete exchanges in8 chronological blocks; no padding, truncation or outcome selection',
            'permissions': 'controlled simulated access policy, not original dataset permissions',
            'benchmark_question_answer_downloads': False,
            'retrieved_utc': datetime.now(timezone.utc).isoformat()}
        write_once_or_same(manifest_path, encode(manifest))
    verified = []
    for row in manifest['files']:
        target = data / 'upstream' / Path(row['path']).name
        if target.exists():
            raw = target.read_bytes()
        else:
            url = HOST + '/api/resolve-cache/datasets/' + REPO + '/' + REVISION + '/' + urllib.parse.quote(row['path'], safe='')
            raw = get(url)
        if len(raw) != row['size'] or git_blob(raw) != row['oid']:
            raise ValueError('immutable_upstream_blob_mismatch')
        write_once_or_same(target, raw)
        verified.append({'path': row['path'], 'sha256': digest(raw), 'git_blob_oid': git_blob(raw)})
    cases = []
    for persona in PERSONAS:
        row = next(row for row in manifest['files'] if row['path'].endswith(f'_persona{persona}.json'))
        case = project(persona, data / 'upstream' / Path(row['path']).name, row)
        case['split'] = 'prefix_permission_reserved'
        cases.append(case)
    body = b''.join(json.dumps(case, ensure_ascii=False, sort_keys=True).encode('utf-8') + b'\n' for case in cases)
    write_once_or_same(data / 'cases.jsonl', body)
    validation = {'case_ids': [case['case_id'] for case in cases], 'cases_sha256': digest(body),
        'clusters': 2, 'sources_each': 8, 'source_lengths_bytes': {
            case['case_id']: {s['source_id']: len(s['text'].encode('utf-8')) for s in case['sources']} for case in cases},
        'upstream': verified, 'model_calls': 0, 'human_gold': None}
    write_once_or_same(data / 'data_validation.json', encode(validation))
    print(json.dumps(validation, ensure_ascii=False))


if __name__ == '__main__':
    main()
