"""Freeze 40 previously unused Hotpot questions without outcome-based selection.

This module performs no network requests and no model calls.  Its only input is
the previously hash-verified canonical Parquet's schema-only JSON conversion.
Public cases and scheduler state are separate from evaluation-only answers.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
OLD_DATA = HERE.parent / 'memory_module_fusion_v1' / 'data_hotpot'
DATA = HERE / 'data_fresh'
COUNT = 40
SEED = 2026110579
PERCENTS = (10, 30, 50)
JSON_SHA256 = 'd3ad9b87a18ba9a3ce5054f8633310e441ae9e13ada08d66e47acf8d0ae0f7f2'
PARQUET_SHA256 = 'c20b638ca82b21d04fe12e14ff417ad05153d4d215a65de54497fca4e972f7c6'
REVISION = '1908d6afbbead072334abe2965f91bd2709910ab'


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encode(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def write_once(path: Path, body: bytes) -> None:
    """Idempotent reproduction is allowed; changing a frozen file is rejected."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != body:
            raise ValueError('frozen_data_changed:' + path.name)
        return
    with path.open('xb') as stream:
        stream.write(body)


def select_records(records: list[dict], old_cases: list[dict], *, count: int = COUNT) -> list[dict]:
    if type(count) is not int or count <= 0:
        raise ValueError('positive_integer_count_required')
    ids = [record['_id'] for record in records]
    if len(ids) != len(set(ids)) or any(type(value) is not str or not value for value in ids):
        raise ValueError('invalid_or_duplicate_upstream_ids')
    previous = [case.get('original_id', case['cluster_id']) for case in old_cases]
    if len(previous) != len(set(previous)) or not set(previous) <= set(ids):
        raise ValueError('previous_identity_registry_invalid')
    excluded = set(previous)
    selected = [record for record in sorted(records, key=lambda record: record['_id'])
                if record['_id'] not in excluded][:count]
    if len(selected) != count:
        raise ValueError('not_enough_unused_questions')
    return selected


def project_record(record: dict) -> tuple[dict, dict]:
    """Preserve every original sentence, its paragraph, and its exact offsets."""
    sources, hierarchy, lookup = [], {}, {}
    for parent_index, (title, sentences) in enumerate(record['context']):
        if type(title) is not str or type(sentences) is not list:
            raise ValueError('original_context_schema_invalid')
        parent = f'P{parent_index:02d}'
        siblings = []
        for sentence_index, sentence in enumerate(sentences):
            if type(sentence) is not str:
                raise ValueError('non_string_original_sentence')
            sid = f'S{len(sources)+1:03d}'
            prefix = title + '\n'
            sources.append({'source_id': sid, 'text': prefix + sentence, 'version': 1,
                'origin': {'title': title, 'sentence_index': sentence_index,
                    'parent_index': parent_index, 'quote_start': len(prefix),
                    'quote_end': len(prefix) + len(sentence),
                    'quote_sha256': sha(sentence.encode('utf-8'))}})
            hierarchy[sid] = {'parent_id': parent, 'position': sentence_index,
                              'prev_id': None, 'next_id': None}
            siblings.append(sid)
            lookup[(title, sentence_index)] = sid
        for index, sid in enumerate(siblings):
            hierarchy[sid].update(prev_id=siblings[index-1] if index else None,
                next_id=siblings[index+1] if index+1 < len(siblings) else None)
    if type(record['question']) is not str or not sources:
        raise ValueError('question_or_sources_invalid')
    case_id = 'hotpot-' + record['_id']
    case = {'case_id': case_id, 'cluster_id': record['_id'], 'original_id': record['_id'],
        'split': 'fresh_reserved', 'question': record['question'],
        'sources': sources, 'hierarchy': hierarchy}
    labels = {'answer': record['answer'], 'type': record['type'], 'level': record['level'],
        'support_ids': [lookup[tuple(support)] for support in record['supporting_facts']],
        'support_annotation_is_exhaustive': False,
        'human_new_permissions_review': None}
    return case, labels


def make_schedule(case: dict, index: int) -> tuple[list[dict], dict]:
    """Scheduler-only future state: never pass this object into a planner."""
    percent = PERCENTS[index % len(PERCENTS)]
    ids = [source['source_id'] for source in case['sources']]
    seed = SEED + int(sha(case['original_id'].encode('utf-8'))[:12], 16)
    rng = random.Random(seed)
    revoked = set(rng.sample(ids, percent * len(ids) // 100))
    surviving = [sid for sid in ids if sid not in revoked]
    schedule = [
        {'time': 0, 'state': 'unchanged', 'allowed': ids, 'revocation_percent': 0},
        {'time': 1, 'state': 'random_revocation', 'allowed': surviving,
         'revocation_percent': percent},
        {'time': 2, 'state': 'regrant', 'allowed': ids, 'revocation_percent': 0},
    ]
    episodes = {
        'case_id': case['case_id'],
        'scheduler_only': True,
        'question_known_at_initial_construction': True,
        'policy_events_are_controlled_simulation': True,
        'initial_construction': {'phase': 'T0', 'allowed': ids,
            'question_id': case['case_id'], 'receiver_has_received_package': False},
        'deliveries': [{
            'episode_id': f'{case["case_id"]}-first-{event["time"]}',
            'policy_time': event['time'], 'state': event['state'],
            'policy_update_phase': 'T1', 'allowed': event['allowed'],
            'first_delivery_phase': 'T2',
            'receiver_context_id': f'{case["case_id"]}-fresh-B-{event["time"]}',
            'receiver_has_received_package': False,
        } for event in schedule],
        'source_artifacts_and_maintenance_persist_in_time_order': True,
        'all_initial_and_repair_costs_counted': True,
        'past_plaintext_erasure_claimed': False,
    }
    return schedule, episodes


def current_planner_input(case: dict, allowed_ids) -> dict:
    """Return only current authorized originals; no labels or future schedule.

    The authority owning allowed_ids remains responsible for commit-time checks.
    Neighbor pointers are rebound to currently authorized siblings only.
    """
    forbidden = {'answer', 'answers', 'support_ids', 'supporting_facts', 'evaluation',
                 'schedule', 'schedules', 'episodes', 'future_events'}
    if forbidden & set(case):
        raise ValueError('labels_or_future_state_in_public_case')
    if type(allowed_ids) not in (list, tuple, set, frozenset):
        raise ValueError('allowed_ids_collection_required')
    if any(type(sid) is not str for sid in allowed_ids) or len(allowed_ids) != len(set(allowed_ids)):
        raise ValueError('allowed_ids_invalid')
    registry = {source['source_id']: source for source in case['sources']}
    if len(registry) != len(case['sources']) or not set(allowed_ids) <= set(registry):
        raise ValueError('allowed_ids_not_in_original_registry')
    allowed = set(allowed_ids)
    sources = [source for source in case['sources'] if source['source_id'] in allowed]
    # A JSON copy prevents a planner from modifying the frozen registry.
    sources = json.loads(json.dumps(sources, ensure_ascii=False))
    hierarchy = {sid: dict(case['hierarchy'][sid]) for sid in registry if sid in allowed}
    parents = {}
    for sid, row in hierarchy.items():
        parents.setdefault(row['parent_id'], []).append(sid)
    for siblings in parents.values():
        siblings.sort(key=lambda sid: (hierarchy[sid]['position'], sid))
        for index, sid in enumerate(siblings):
            hierarchy[sid].update(prev_id=siblings[index-1] if index else None,
                next_id=siblings[index+1] if index+1 < len(siblings) else None)
    return {'question': case['question'], 'current_sources': sources, 'hierarchy': hierarchy}


def prepare(*, output: Path = DATA, old_data: Path = OLD_DATA) -> dict:
    upstream_path = old_data / 'upstream_hotpot_dev_distractor_v1.json'
    parquet_path = old_data / 'upstream_validation.parquet'
    old_cases_path = old_data / 'cases.public.jsonl'
    raw = upstream_path.read_bytes()
    if sha(raw) != JSON_SHA256 or sha(parquet_path.read_bytes()) != PARQUET_SHA256:
        raise ValueError('pinned_canonical_data_hash_changed')
    previous_raw = old_cases_path.read_bytes()
    previous = [json.loads(line) for line in previous_raw.decode('utf-8').splitlines() if line]
    if len(previous) != 24:
        raise ValueError('expected_all_24_previous_questions')
    records = json.loads(raw)
    selected = select_records(records, previous)
    cases, labels, schedules, episodes = [], {}, {}, {}
    for index, record in enumerate(selected):
        case, label = project_record(record)
        schedule, episode = make_schedule(case, index)
        cases.append(case)
        labels[case['case_id']] = label
        schedules[case['case_id']] = schedule
        episodes[case['case_id']] = episode
    bodies = {
        'cases.public.jsonl': b''.join(json.dumps(case, ensure_ascii=False, sort_keys=True).encode('utf-8')
                                      + b'\n' for case in cases),
        'evaluation_only.json': encode(labels),
        'schedules.json': encode(schedules),
        'episodes.json': encode(episodes),
    }
    old_ids = {case.get('original_id', case['cluster_id']) for case in previous}
    fresh_ids = [case['original_id'] for case in cases]
    counts = Counter(schedules[case['case_id']][1]['revocation_percent'] for case in cases)
    manifest = {
        'stage': 'fresh_reserved_data_frozen_before_candidate_outcomes',
        'dataset': 'HotpotQA validation distractor', 'license': 'CC-BY-SA-4.0',
        'official_route': 'https://hotpotqa.github.io/',
        'canonical_repository': 'https://huggingface.co/datasets/hotpotqa/hotpot_qa',
        'canonical_revision': REVISION,
        'canonical_file': 'distractor/validation-00000-of-00001.parquet',
        'parquet_sha256': PARQUET_SHA256, 'converted_upstream_json_sha256': JSON_SHA256,
        'original_cmu_json_hash_verified': False,
        'upstream_conversion': 'schema-only conversion; unchanged question, context sentences, answers, annotations',
        'previous_cases_sha256': sha(previous_raw), 'previous_questions': len(previous),
        'selection': 'sort all original IDs lexicographically, exclude all previous24 IDs, take next40; no answer/type/support/length/outcome selection',
        'selected_original_ids': fresh_ids, 'previous_fresh_id_intersection': sorted(old_ids & set(fresh_ids)),
        'questions': len(cases), 'independent_unit': 'original question; permission states are repeated observations',
        'sample_size_is_power_justification': False,
        'permission_seed': SEED, 'revocation_percent_assignment': 'cycle10,30,50 by selected question index',
        'questions_by_revocation_percent': dict(sorted(counts.items())),
        'revocation_selection': 'uniform source sample without replacement, floor(percent*source_count/100); no gold labels',
        'policy_states': ['unchanged', 'random_revocation', 'regrant'],
        'permission_events_are_controlled_simulation': True,
        'source_unit': 'entire original sentence plus original paragraph title; no pruning or padding',
        'total_complete_sentences': sum(len(case['sources']) for case in cases),
        'sources_minmax': [min(len(case['sources']) for case in cases), max(len(case['sources']) for case in cases)],
        'public_case_fields': sorted(cases[0]),
        'evaluation_only_fields': ['answer', 'type', 'level', 'support_ids'],
        'scheduler_only_files': ['schedules.json', 'episodes.json'],
        'planner_projection': 'current_planner_input(case, current_allowed_ids); no labels or future events',
        'artifact_sha256': {name: sha(body) for name, body in bodies.items()},
        'generator_sha256': sha(Path(__file__).read_bytes()), 'model_calls': 0,
        'support_annotations_exhaustive': False, 'human_new_permissions_review': None,
    }
    for name, body in bodies.items():
        write_once(output / name, body)
    write_once(output / 'manifest.json', encode(manifest))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DATA)
    args = parser.parse_args()
    manifest = prepare(output=args.output)
    print(json.dumps({key: manifest[key] for key in ('questions', 'total_complete_sentences',
        'sources_minmax', 'questions_by_revocation_percent', 'previous_fresh_id_intersection', 'model_calls')},
        ensure_ascii=False))


if __name__ == '__main__':
    main()
