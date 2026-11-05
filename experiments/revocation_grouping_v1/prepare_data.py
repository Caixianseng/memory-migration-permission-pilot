"""Acquire six fixed public histories and project eight complete exchanges each.

No benchmark question/answer files, credentials, generation or model calls.
Defaults to the fixed-revision public mirror because the official host is
unreachable from this machine. Every raw file must match its git blob ID from
that revision's tree. The original owner URL is retained in all provenance.
Use --offline after acquisition to rebuild/verify against the saved tree.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import urllib.parse
import urllib.request

REVISION = 'ed956dea41521fc4499acbc63f966e0fd3c053ba'
REPO = 'bowen-upenn/PersonaMem-v2'
ORIGIN = 'https://huggingface.co'
IDS = (0, 1, 2, 3, 4, 5)
EXCLUDED_ALREADY_EXPOSED = (173, 366, 479, 605, 931, 944, 962, 990, 995)
HERE = Path(__file__).resolve().parent
MAX_FILE_BYTES = 2_000_000
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/132.0.0.0 Safari/537.36'


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()


def write_once_or_same(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError('refusing_to_change_frozen_file:' + str(path))
    else:
        with path.open('xb') as stream:
            stream.write(raw)


def get(url):
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': '*/*'})
    with urllib.request.urlopen(request, timeout=35) as response:
        raw = response.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError('public_file_exceeds_acquisition_limit')
    return raw


def metadata(host):
    base = host + '/api/datasets/' + REPO + '/tree/' + REVISION
    root = json.loads(get(base))
    tree = json.loads(get(base + '/data/chat_history_32k'))
    selected = [row for row in root if row['path'] == 'README.md']
    for persona in IDS:
        # The tree has later alternate files for some persona IDs (including
        # persona0). Fix the 250911 history release for every selected persona;
        # never choose a variant based on questions or algorithm performance.
        filename = 'data/chat_history_32k/chat_history_250911_213118_persona' + str(persona) + '.json'
        rows = [row for row in tree if row['path'] == filename]
        if len(rows) != 1:
            raise ValueError('fixed_persona_path_not_unique')
        selected.extend(rows)
    return {
        'schema': 'revocation-grouping-upstream-acquisition-v1',
        'repository': REPO, 'revision': REVISION,
        'license': 'CC-BY-4.0', 'license_scope': 'public synthetic dataset',
        'origin': ORIGIN + '/datasets/' + REPO + '/tree/' + REVISION,
        'retrieval_host': host,
        'selected_persona_ids': list(IDS),
        'selection_rule': 'first six numeric persona IDs not previously exposed; fixed 250911_213118 history release for all; first eight complete adjacent user-assistant exchanges; no algorithm outcome screening',
        'excluded_previously_exposed_persona_ids': list(EXCLUDED_ALREADY_EXPOSED),
        'development_ids': [0, 1], 'reserved_check_ids': [2, 3, 4, 5],
        'retrieved_at_utc': datetime.now(timezone.utc).isoformat(),
        'files': selected,
    }


def acquire(data, host, offline):
    manifest_path = data / 'upstream_manifest.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest['revision'] != REVISION or manifest['selected_persona_ids'] != list(IDS):
            raise ValueError('acquisition_selection_changed')
    elif offline:
        raise ValueError('offline_manifest_missing')
    else:
        manifest = metadata(host)
        write_once_or_same(manifest_path, encode(manifest))
    facts = []
    for item in manifest['files']:
        basename = Path(item['path']).name
        local = data / 'upstream' / basename
        if local.exists():
            raw = local.read_bytes()
        elif offline:
            raise ValueError('offline_upstream_missing:' + basename)
        else:
            url = manifest['retrieval_host'] + '/datasets/' + REPO + '/resolve/' + REVISION + '/' + item['path'] + '?download=1'
            raw = get(url)
        if len(raw) != item['size'] or git_blob(raw) != item['oid']:
            raise ValueError('upstream_git_blob_mismatch:' + basename)
        write_once_or_same(local, raw)
        facts.append({'path': item['path'], 'size': len(raw), 'sha256': digest(raw),
                      'git_blob_oid': git_blob(raw), 'git_blob_matches_tree': True})
    return manifest, facts


def project(persona, file, metadata_item):
    raw = file.read_bytes()
    original = json.loads(raw)
    if original.get('metadata', {}).get('persona_id') != persona:
        raise ValueError('persona_identity_changed')
    history = original['chat_history']
    pairs = [(i, i + 1) for i in range(len(history) - 1)
             if history[i].get('role') == 'user' and history[i + 1].get('role') == 'assistant'][:8]
    if len(pairs) != 8:
        raise ValueError('eight_complete_exchanges_required')
    sources = []
    for number, (user, assistant) in enumerate(pairs, 1):
        sid = 'S' + str(number).zfill(2)
        text = f'[{sid}; exchange {number}; original message indices {user},{assistant}]\n'
        origins = []
        for index in (user, assistant):
            message = history[index]
            content = message['content']
            if not isinstance(content, str) or not content.strip():
                raise ValueError('nontext_or_empty_message')
            text += '[' + message['role'] + ']\n'
            start = len(text)
            text += content
            end = len(text)
            origins.append({'message_index': index, 'role': message['role'],
                            'json_pointer': '/chat_history/' + str(index) + '/content',
                            'original_content_start': 0, 'original_content_end': len(content),
                            'rendered_content_start': start, 'rendered_content_end': end,
                            'content_sha256': digest(content.encode('utf-8'))})
            text += '\n[/' + message['role'] + ']\n'
        sources.append({'source_id': sid, 'text': text, 'sha256': digest(text.encode('utf-8')),
                        'origin': {'repository': REPO, 'revision': REVISION,
                                   'path': metadata_item['path'], 'raw_file_sha256': digest(raw),
                                   'message_indices': [user, assistant], 'messages': origins}})
    return {'case_id': 'personamem-v1-' + str(persona).zfill(3), 'persona_id': persona,
            'split': 'development' if persona < 2 else 'reserved_check',
            'source_unit': 'one complete adjacent user-assistant exchange from one synthetic persona history; not an independent natural conversation',
            'permissions': 'controlled research simulation; not native PersonaMem permissions',
            'human_gold': None, 'sources': sources}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='https://hf-mirror.com')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--data-dir', type=Path, default=HERE / 'data')
    args = parser.parse_args()
    if args.host not in (ORIGIN, 'https://hf-mirror.com'):
        raise ValueError('unregistered_public_host')
    data = args.data_dir.resolve()
    manifest, verified = acquire(data, args.host, args.offline)
    cases = []
    for persona in IDS:
        item = next(item for item in manifest['files'] if item['path'].endswith('_persona' + str(persona) + '.json'))
        cases.append(project(persona, data / 'upstream' / Path(item['path']).name, item))
    lines = b''.join(json.dumps(case, ensure_ascii=False, sort_keys=True).encode('utf-8') + b'\n' for case in cases)
    write_once_or_same(data / 'cases.jsonl', lines)
    check = {'schema': 'revocation-grouping-data-validation-v1', 'revision': REVISION,
             'selected_personas': list(IDS), 'independent_persona_clusters': len(cases),
             'development_persona_clusters': 2, 'reserved_check_persona_clusters': 4,
             'sources_per_persona': 8, 'source_messages_per_persona': 16,
             'upstream_files': verified, 'cases_sha256': digest(lines),
             'upstream_question_or_answer_files_downloaded': False,
             'source_system_persona_messages_included': False,
             'frozen_before_algorithm_outcomes': True,
             'source_lengths_chars': {case['case_id']: [len(s['text']) for s in case['sources']] for case in cases},
             'human_gold': None, 'model_calls': 0}
    write_once_or_same(data / 'data_validation.json', encode(check))
    print(json.dumps(check, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
