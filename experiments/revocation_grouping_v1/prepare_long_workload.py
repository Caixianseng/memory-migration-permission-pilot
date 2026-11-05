"""Fixed public long workload: personas 6/7, 32 exchanges, eight source blocks.

Each block contains four consecutive complete user/assistant exchanges from
the first 32 exchanges. No padding, question files, model calls or old-data
writes. Raw files are verified against the fixed HF revision's git blob IDs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import urllib.error
import urllib.parse

try:
    from .prepare_data import REPO, REVISION, ORIGIN, digest, encode, get, git_blob, write_once_or_same
except ImportError:
    from prepare_data import REPO, REVISION, ORIGIN, digest, encode, get, git_blob, write_once_or_same

HERE = Path(__file__).resolve().parent
PERSONAS = (6, 7)
EXCHANGES = 32
BLOCK_EXCHANGES = 4


def acquire(data, host, offline):
    manifest_path = data / 'upstream_manifest.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest['revision'] != REVISION or manifest['selected_persona_ids'] != list(PERSONAS):
            raise ValueError('long_acquisition_selection_changed')
    elif offline:
        raise ValueError('offline_long_manifest_missing')
    else:
        api = host + '/api/datasets/' + REPO + '/tree/' + REVISION
        root = json.loads(get(api))
        listing = json.loads(get(api + '/data/chat_history_32k'))
        selected = [item for item in root if item['path'] == 'README.md']
        for persona in PERSONAS:
            exact = 'data/chat_history_32k/chat_history_250911_213118_persona' + str(persona) + '.json'
            matches = [item for item in listing if item['path'] == exact]
            if len(matches) != 1:
                raise ValueError('fixed_long_persona_path_not_unique')
            selected.extend(matches)
        manifest = {
            'schema': 'revocation-grouping-long-upstream-acquisition-v1',
            'repository': REPO, 'revision': REVISION, 'license': 'CC-BY-4.0',
            'origin': ORIGIN + '/datasets/' + REPO + '/tree/' + REVISION,
            'retrieval_host': host, 'selected_persona_ids': list(PERSONAS),
            'selection_rule': 'fixed persona IDs 6 and 7; fixed 250911_213118 release; first 32 complete adjacent user-assistant exchanges; every four consecutive exchanges form one source block; no padding, truncation, outcome selection or substitution if fewer than 32 exchanges',
            'split': 'workload_check', 'previous_persona_data': '0..5 kept unchanged',
            'retrieved_at_utc': datetime.now(timezone.utc).isoformat(), 'files': selected,
        }
        write_once_or_same(manifest_path, encode(manifest))
    verified = []
    for item in manifest['files']:
        local = data / 'upstream' / Path(item['path']).name
        if local.exists():
            raw = local.read_bytes()
        elif offline:
            raise ValueError('offline_long_raw_file_missing:' + local.name)
        else:
            url = manifest['retrieval_host'] + '/datasets/' + REPO + '/resolve/' + REVISION + '/' + item['path'] + '?download=1'
            try:
                raw = get(url)
            except (OSError, urllib.error.URLError):
                # Public read-only fallback for mirror redirect timeouts. The
                # revision and mandatory tree/blob checks stay unchanged.
                cache_url = manifest['retrieval_host'] + '/api/resolve-cache/datasets/' + REPO + '/' + REVISION + '/' + urllib.parse.quote(item['path'], safe='')
                raw = get(cache_url)
        if len(raw) != item['size'] or git_blob(raw) != item['oid']:
            raise ValueError('long_raw_git_blob_mismatch:' + local.name)
        write_once_or_same(local, raw)
        verified.append({'path': item['path'], 'size': len(raw), 'sha256': digest(raw),
                         'git_blob_oid': git_blob(raw), 'git_blob_matches_tree': True})
    return manifest, verified


def project(persona, raw_file, manifest_item):
    raw = raw_file.read_bytes()
    original = json.loads(raw)
    if original.get('metadata', {}).get('persona_id') != persona:
        raise ValueError('long_persona_identity_changed')
    history = original['chat_history']
    pairs = [(i, i + 1) for i in range(len(history) - 1)
             if history[i].get('role') == 'user' and history[i + 1].get('role') == 'assistant']
    if len(pairs) < EXCHANGES:
        raise ValueError('fixed_long_persona_has_fewer_than_32_complete_exchanges:' + str(persona))
    pairs = pairs[:EXCHANGES]
    sources = []
    for block in range(8):
        sid = 'S' + str(block + 1).zfill(2)
        block_pairs = pairs[block * BLOCK_EXCHANGES:(block + 1) * BLOCK_EXCHANGES]
        exchange_numbers = list(range(block * BLOCK_EXCHANGES + 1, (block + 1) * BLOCK_EXCHANGES + 1))
        text = f'[{sid}; complete consecutive exchanges {exchange_numbers[0]}-{exchange_numbers[-1]}]\n'
        origins = []
        for exchange, pair in zip(exchange_numbers, block_pairs):
            text += f'[exchange {exchange}; original message indices {pair[0]},{pair[1]}]\n'
            for index in pair:
                message = history[index]
                content = message['content']
                if not isinstance(content, str) or not content.strip():
                    raise ValueError('long_nontext_or_empty_message')
                text += '[' + message['role'] + ']\n'
                start = len(text)
                text += content
                end = len(text)
                origins.append({'exchange_number': exchange, 'message_index': index,
                    'role': message['role'], 'json_pointer': '/chat_history/' + str(index) + '/content',
                    'original_content_start': 0, 'original_content_end': len(content),
                    'rendered_content_start': start, 'rendered_content_end': end,
                    'content_sha256': digest(content.encode('utf-8'))})
                text += '\n[/' + message['role'] + ']\n'
        sources.append({'source_id': sid, 'text': text, 'sha256': digest(text.encode('utf-8')),
            'origin': {'repository': REPO, 'revision': REVISION, 'path': manifest_item['path'],
                'raw_file_sha256': digest(raw), 'exchange_numbers': exchange_numbers,
                'message_indices': [i for pair in block_pairs for i in pair], 'messages': origins}})
    return {'case_id': 'personamem-long-' + str(persona).zfill(3),
        'persona_id': persona, 'cluster_id': 'personamem-persona-' + str(persona),
        'split': 'workload_check', 'human_gold': None,
        'source_unit': 'four consecutive complete user-assistant exchanges from one synthetic persona history; eight blocks are not eight independent conversations',
        'permissions': 'controlled research simulation; not original PersonaMem permissions',
        'sources': sources}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='https://hf-mirror.com')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--data-dir', type=Path, default=HERE / 'data_long_workload')
    args = parser.parse_args()
    if args.host not in (ORIGIN, 'https://hf-mirror.com'):
        raise ValueError('unregistered_long_public_host')
    data = args.data_dir.resolve()
    if data == (HERE / 'data').resolve() or (HERE / 'data').resolve() in data.parents:
        raise ValueError('old_data_directory_must_not_be_modified')
    manifest, verified = acquire(data, args.host, args.offline)
    cases = []
    for persona in PERSONAS:
        item = next(item for item in manifest['files'] if item['path'].endswith('_persona' + str(persona) + '.json'))
        cases.append(project(persona, data / 'upstream' / Path(item['path']).name, item))
    lines = b''.join(json.dumps(case, ensure_ascii=False, sort_keys=True).encode('utf-8') + b'\n' for case in cases)
    write_once_or_same(data / 'cases.jsonl', lines)
    validation = {'schema': 'revocation-grouping-long-data-validation-v1',
        'revision': REVISION, 'persona_ids': list(PERSONAS), 'independent_persona_clusters': 2,
        'sources_per_persona': 8, 'exchanges_per_source': 4, 'exchanges_per_persona': 32,
        'selected_messages_per_persona': 64, 'source_text_truncation': False, 'padding': False,
        'upstream_question_or_answer_files_downloaded': False, 'system_persona_messages_included': False,
        'frozen_before_algorithm_outcomes': True, 'human_gold': None, 'model_calls': 0,
        'upstream_files': verified, 'cases_sha256': digest(lines),
        'source_lengths_chars': {case['case_id']: [len(s['text']) for s in case['sources']] for case in cases}}
    write_once_or_same(data / 'data_validation.json', encode(validation))
    print(json.dumps(validation, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
