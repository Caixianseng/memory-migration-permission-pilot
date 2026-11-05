"""Offline 64-source scale bridge from the existing two PersonaMem histories.

One complete original user/assistant exchange per source, 32 from persona 8
then 32 from persona 9. Every message, quote and provenance span is checked
against both the immutable upstream JSON and the previous four-exchange blocks.
No network, SDK, prompt, old-data write, padding or content truncation.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = HERE / 'data_reserved'
CASE_ID = 'personamem-scale64-008-009'
PERSONAS = (8, 9)
REVISION = 'ed956dea41521fc4499acbc63f966e0fd3c053ba'
REPOSITORY = 'bowen-upenn/PersonaMem-v2'

# Source-only contextual review of repetitions that were inside one old block.
# These are complete alternative evidence routes, not additional required facts.
ALTERNATIVES = {
    'personamem-long-008-q07': (8, 15, 'The explicitly requested vivid rewrite preserves the same client-report lake scene.'),
    'personamem-long-008-q08': (8, 15, 'The same client-report rewrite explicitly preserves the matrilineal lineage.'),
    'personamem-long-008-q09': (8, 18, 'The revised email retains Auntie Margaret, the maritime book and both ports.'),
    'personamem-long-008-q15': (8, 32, 'The expanded version preserves the same great-aunt papers and 1954 letter.'),
    'personamem-long-008-q16': (8, 32, 'The same expanded post preserves the envelope postage stamp and its vivid colours.'),
    'personamem-long-009-q09': (9, 18, 'The sensory rewrite retains the email to Mara, balcony pots and both herbs.'),
    'personamem-long-009-q16': (9, 32, 'The explicit English back-translation preserves the same rainy-afternoon reflection and Darjeeling.'),
}
REJECTED_ALTERNATIVE = {
    'question_id': 'personamem-long-009-q13', 'persona_id': 9, 'exchange_number': 28,
    'reason': 'The workout advice attributes an appendectomy to the user as biography. It does not identify the literary personal piece or the summer at age nineteen; matching the operation word alone is not complete event-specific support.',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def require(value, message):
    if not value:
        raise ValueError(message)


def load_json(path, inputs):
    raw = path.read_bytes()
    inputs[path.relative_to(HERE).as_posix()] = sha(raw)
    return json.loads(raw)


def phrase_match(text, phrases):
    folded = text.casefold()
    return all(any(item.casefold() in folded for item in phrase) if isinstance(phrase, list)
               else phrase.casefold() in folded for phrase in phrases)


def build():
    inputs = {}
    raw_cases = (OLD / 'cases.jsonl').read_bytes()
    inputs['data_reserved/cases.jsonl'] = sha(raw_cases)
    old_cases = {case['case_id']: case for case in map(json.loads, raw_cases.decode('utf-8').splitlines())}
    old_validation = load_json(OLD / 'data_validation.json', inputs)
    manifest = load_json(OLD / 'upstream_manifest.json', inputs)
    old_questions = load_json(OLD / 'questions_reserved.json', inputs)
    old_evidence = load_json(OLD / 'questions_reserved.evidence.json', inputs)
    require(manifest['revision'] == REVISION and manifest['repository'] == REPOSITORY
            and manifest['persona_ids'] == list(PERSONAS), 'fixed_upstream_identity_changed')
    require(old_validation['cases_sha256'] == sha(raw_cases) == old_evidence['cases_file_sha256'],
            'old_case_evidence_hash_mismatch')
    sources, raw_histories, exchange_sources, messages_checked = [], {}, {}, []
    old_source_by_persona, raw_provenance = {}, []
    for persona in PERSONAS:
        old_id = f'personamem-long-{persona:03d}'
        old_case = old_cases[old_id]
        require(old_case['persona_id'] == persona and len(old_case['sources']) == 8, 'old_persona_source_selection_changed')
        old_sources = {source['source_id']: source for source in old_case['sources']}
        old_source_by_persona[persona] = old_sources
        entry = next(row for row in manifest['files'] if row['path'].endswith(f'_persona{persona}.json'))
        raw_path = OLD / 'upstream' / Path(entry['path']).name
        raw = raw_path.read_bytes()
        inputs[raw_path.relative_to(HERE).as_posix()] = sha(raw)
        require(len(raw) == entry['size'] and git_blob(raw) == entry['oid'], 'upstream_fixed_git_blob_mismatch')
        original = json.loads(raw)
        require(original['metadata']['persona_id'] == persona, 'upstream_persona_mismatch')
        history = original['chat_history']
        raw_histories[persona] = history
        pairs = [(i, i + 1) for i in range(len(history) - 1)
                 if history[i].get('role') == 'user' and history[i + 1].get('role') == 'assistant'][:32]
        require(len(pairs) == 32, 'fewer_than_32_complete_pairs_no_substitution')
        raw_provenance.append({'persona_id': persona, 'path': entry['path'], 'raw_file_sha256': sha(raw),
                               'git_blob_oid': git_blob(raw), 'size': len(raw)})
        for exchange, pair in enumerate(pairs, 1):
            sid = f'M{len(sources) + 1:03d}'
            old_sid = f'S{(exchange - 1) // 4 + 1:02d}'
            previous = old_sources[old_sid]
            require(sha(previous['text'].encode('utf-8')) == previous['sha256'], 'old_source_body_hash_mismatch')
            require(previous['origin']['raw_file_sha256'] == sha(raw)
                    and previous['origin']['revision'] == REVISION, 'old_source_upstream_binding_mismatch')
            old_messages = [item for item in previous['origin']['messages'] if item['exchange_number'] == exchange]
            require([item['message_index'] for item in old_messages] == list(pair), 'old_exchange_pair_selection_changed')
            text = f'[{sid}; persona {persona}; complete exchange {exchange}; original message indices {pair[0]},{pair[1]}]\n'
            origins = []
            for index, old_origin in zip(pair, old_messages):
                message = history[index]
                role, content = message['role'], message['content']
                require(isinstance(content, str) and bool(content), 'nontext_or_empty_original_message')
                require(old_origin['role'] == role and old_origin['content_sha256'] == sha(content.encode('utf-8'))
                        and old_origin['original_content_start'] == 0 and old_origin['original_content_end'] == len(content)
                        and previous['text'][old_origin['rendered_content_start']:old_origin['rendered_content_end']] == content,
                        'old_origin_span_is_not_the_full_upstream_content')
                text += f'[{role}]\n'
                start = len(text)
                text += content
                end = len(text)
                text += f'\n[/{role}]\n'
                origin = {'persona_id': persona, 'exchange_number': exchange, 'message_index': index,
                          'role': role, 'json_pointer': f'/chat_history/{index}/content',
                          'original_content_start': 0, 'original_content_end': len(content),
                          'rendered_content_start': start, 'rendered_content_end': end,
                          'content_sha256': sha(content.encode('utf-8')),
                          'previous_block_source_id': old_sid,
                          'previous_block_rendered_content_start': old_origin['rendered_content_start'],
                          'previous_block_rendered_content_end': old_origin['rendered_content_end']}
                origins.append(origin)
                messages_checked.append({'source_id': sid, **origin, 'content_utf8_bytes': len(content.encode('utf-8')),
                                         'new_rendered_matches_full_upstream_content': True,
                                         'old_rendered_matches_full_upstream_content': True})
            source = {'source_id': sid, 'text': text, 'sha256': sha(text.encode('utf-8')), 'version': 1,
                      'persona_id': persona, 'exchange_number': exchange,
                      'exchange_id': f'persona-{persona:03d}-exchange-{exchange:03d}',
                      'cluster_id': old_case['cluster_id'],
                      'origin': {'repository': REPOSITORY, 'revision': REVISION, 'path': entry['path'],
                                 'raw_file_sha256': sha(raw), 'raw_git_blob_oid': entry['oid'],
                                 'persona_id': persona, 'exchange_numbers': [exchange],
                                 'message_indices': list(pair), 'messages': origins,
                                 'previous_case_id': old_id, 'previous_block_source_id': old_sid,
                                 'previous_block_source_sha256': previous['sha256']}}
            for item in origins:
                require(text[item['rendered_content_start']:item['rendered_content_end']] == history[item['message_index']]['content'],
                        'new_source_content_changed')
            sources.append(source)
            exchange_sources[persona, exchange] = source
    require(len(sources) == 64 and len(messages_checked) == 128
            and len({(row['persona_id'], row['message_index']) for row in messages_checked}) == 128,
            'each_of_128_selected_messages_must_appear_exactly_once')
    combined = {'case_id': CASE_ID, 'persona_ids': list(PERSONAS),
                'original_case_ids': [f'personamem-long-{p:03d}' for p in PERSONAS],
                'cluster_id': 'personamem-personas-8-and-9-combined-scale-bridge',
                'independent_content_cluster_ids': [old_cases[f'personamem-long-{p:03d}']['cluster_id'] for p in PERSONAS],
                'independent_content_clusters': 2, 'sources_are_not_independent_content_clusters': True,
                'split': 'scale_bridge_development', 'human_gold': None, 'license': 'CC-BY-4.0',
                'source_unit': 'one complete adjacent original user/assistant exchange; 32 per persona; 64 sources from two correlated persona histories',
                'purpose': 'scale and real-cache bridge, not 64 independent stories or benchmark padding',
                'permissions': 'controlled research simulation; not original PersonaMem permissions', 'sources': sources}
    cases_bytes = json.dumps(combined, ensure_ascii=False, sort_keys=True).encode('utf-8') + b'\n'
    questions, evidence, quote_checks = [], [], []
    original_specs = []

    def evidence_row(old_id, question, row, route_kind):
        persona = old_cases[old_id]['persona_id']
        previous = old_source_by_persona[persona][row['source_id']]
        require(row['source_sha256'] == previous['sha256']
                and previous['text'][row['rendered_source_char_start']:row['rendered_source_char_end']] == row['exact_quote'],
                'previous_evidence_exact_quote_or_body_hash_mismatch')
        source = exchange_sources[persona, row['source_exchange_number']]
        origin = next(item for item in source['origin']['messages'] if item['message_index'] == row['source_message_index'])
        require(origin['role'] == row['source_message_role'] and origin['json_pointer'] == row['upstream_json_pointer'],
                'evidence_message_role_or_pointer_mismatch')
        content = raw_histories[persona][row['source_message_index']]['content']
        begin, end = row['original_content_char_start'], row['original_content_char_end']
        require(0 <= begin < end <= len(content) and content[begin:end] == row['exact_quote'], 'upstream_quote_span_mismatch')
        new_begin, new_end = origin['rendered_content_start'] + begin, origin['rendered_content_start'] + end
        require(source['text'][new_begin:new_end] == row['exact_quote'], 'new_quote_span_mismatch')
        require(sha(source['text'].encode('utf-8')) == source['sha256'], 'new_source_body_hash_mismatch')
        result = {**deepcopy(row), 'source_id': source['source_id'], 'source_sha256': source['sha256'],
                  'rendered_source_char_start': new_begin, 'rendered_source_char_end': new_end,
                  'original_case_id': old_id, 'persona_id': persona, 'evidence_route': route_kind,
                  'evidence_id': question['question_id'] + '-' + route_kind + '-' + source['source_id'],
                  'previous_block_evidence': {'source_id': previous['source_id'], 'source_sha256': previous['sha256'],
                                              'rendered_source_char_start': row['rendered_source_char_start'],
                                              'rendered_source_char_end': row['rendered_source_char_end']},
                  'other_sources_containing_all_required_phrases': [candidate['source_id'] for candidate in sources
                      if candidate['persona_id'] == persona and candidate['source_id'] != source['source_id']
                      and phrase_match(candidate['text'], question['required_phrases'])],
                  'other_source_phrase_matches_are_only_lexical_diagnostics': True}
        quote_checks.append({'question_id': question['question_id'], 'evidence_id': result['evidence_id'],
                             'source_id': source['source_id'], 'quote_sha256': sha(row['exact_quote'].encode('utf-8')),
                             'quote_chars': len(row['exact_quote']), 'upstream_span_verified': True,
                             'previous_block_span_verified': True, 'new_source_span_verified': True,
                             'new_source_body_sha256_verified': True})
        return result

    for persona in PERSONAS:
        old_id = f'personamem-long-{persona:03d}'
        spec = old_questions[old_id]
        original_specs.append(spec)
        require(spec['cases_file_sha256'] == sha(raw_cases) and len(spec['questions']) == 16, 'old_qa_case_binding_mismatch')
        for original_question in spec['questions']:
            question = deepcopy(original_question)
            primary_rows = [row for row in old_evidence['cases'][old_id]['evidence'] if row['question_id'] == question['question_id']]
            require(primary_rows and {row['source_id'] for row in primary_rows} == set(question['support_source_ids']),
                    'question_support_and_primary_evidence_mismatch')
            remapped = [evidence_row(old_id, question, row, 'primary') for row in primary_rows]
            support_sets = [sorted({row['source_id'] for row in remapped})]
            if question['question_id'] in ALTERNATIVES:
                alt_persona, exchange, reason = ALTERNATIVES[question['question_id']]
                require(alt_persona == persona, 'alternative_cross_persona_mismatch')
                source = exchange_sources[persona, exchange]
                origin = next(item for item in source['origin']['messages'] if item['role'] == 'assistant')
                previous = old_source_by_persona[persona][source['origin']['previous_block_source_id']]
                old_origin = next(item for item in previous['origin']['messages'] if item['message_index'] == origin['message_index'])
                content = raw_histories[persona][origin['message_index']]['content']
                require(phrase_match(content, question['required_phrases']), 'reviewed_alternative_lost_required_fact_phrases')
                alternate = {**deepcopy(primary_rows[0]), 'source_id': previous['source_id'], 'source_sha256': previous['sha256'],
                             'exact_quote': content, 'source_exchange_number': exchange,
                             'source_message_index': origin['message_index'], 'source_message_role': 'assistant',
                             'upstream_json_pointer': origin['json_pointer'], 'original_content_char_start': 0,
                             'original_content_char_end': len(content),
                             'rendered_source_char_start': old_origin['rendered_content_start'],
                             'rendered_source_char_end': old_origin['rendered_content_end'],
                             'semantic_review': reason + ' AI source-only contextual review; human verification pending.'}
                remapped.append(evidence_row(old_id, question, alternate, 'alternative_complete'))
                support_sets.append([source['source_id']])
            question.update(original_case_id=old_id, original_support_source_ids=original_question['support_source_ids'],
                            original_support_sets=original_question.get('support_sets'),
                            support_source_ids=sorted({sid for support in support_sets for sid in support}),
                            support_sets=support_sets,
                            support_source_ids_semantics='union of alternative complete support sets; evaluate support_sets',
                            evidence_ids=[row['evidence_id'] for row in remapped])
            for field in ('question', 'reference_answer', 'required_phrases', 'question_id', 'human_gold'):
                require(question[field] == original_question[field], 'original_question_or_answer_was_rewritten')
            questions.append(question)
            evidence.extend(remapped)
    require(len(questions) == 32 and len({q['question_id'] for q in questions}) == 32, 'exactly_32_original_questions_required')
    rotations = [sum((spec['question_rotation_groups'][i] for spec in original_specs), []) for i in range(4)]
    question_bank = {CASE_ID: {'questions': questions, 'question_rotation_groups': rotations,
        'question_schedule': {str(i): group for i, group in enumerate(rotations)}, 'questions_per_event': 8,
        'question_schedule_rule': 'concatenate the two unchanged original rotation groups at the same ordinal; no permission/outcome selection',
        'question_count': 32, 'cases_file_sha256': sha(cases_bytes), 'human_gold': None, 'AI_authored': True,
        'independent_content_clusters': 2, 'scale_bridge_development_only': True,
        'source_fact_scope': original_specs[0]['source_fact_scope'],
        'upstream_questions_or_answers_used': False, 'planner_results_used_for_support_remapping': False}}
    rejected = {**REJECTED_ALTERNATIVE,
                'source_id': exchange_sources[9, 28]['source_id'],
                'source_sha256': exchange_sources[9, 28]['sha256'],
                'accepted_as_complete_support': False, 'review_is_AI_not_human_gold': True}
    evidence_copy = {'schema': 'scale64-exact-quote-remapping-v1', 'AI_authored': True, 'human_gold': None,
        'cases_file_sha256': sha(cases_bytes), 'original_evidence_sha256': inputs['data_reserved/questions_reserved.evidence.json'],
        'support_remapping_inputs': 'original evidence exact quotes, upstream JSON and matching complete exchange origins',
        'permission_traces_read_for_support_remapping': False, 'planner_results_read_for_support_remapping': False,
        'upstream_questions_or_answers_downloaded': False,
        'alternative_support_review': 'AI contextual source-only review of repeated complete drafts; lexical matches alone do not establish support',
        'rejected_lexical_candidate_reviews': [rejected],
        'cases': {CASE_ID: {'question_count': 32, 'primary_question_evidence_count': 32,
                            'alternative_complete_evidence_count': len(evidence) - 32, 'evidence': evidence}}}
    questions_bytes, evidence_bytes = encode(question_bank), encode(evidence_copy)
    validation = {'schema': 'scale64-full-exchange-and-evidence-validation-v1', 'case_id': CASE_ID,
        'persona_ids': list(PERSONAS), 'independent_content_clusters': 2,
        'source_count': 64, 'original_complete_exchanges': 64, 'original_complete_message_contents': 128,
        'source_count_is_not_independent_sample_count': True, 'benchmark_padding': False,
        'source_text_truncation': False, 'summarization_or_content_rewriting': False,
        'source_headers_are_provenance_metadata': True, 'system_persona_messages_included': False,
        'old_materials_modified': False, 'model_calls': 0, 'network_requests': 0, 'human_gold': None,
        'source_input_sha256': inputs, 'preparer_code_sha256': sha(Path(__file__).read_bytes()),
        'upstream_files': raw_provenance, 'cases_sha256': sha(cases_bytes),
        'questions_sha256': sha(questions_bytes), 'evidence_sha256': sha(evidence_bytes),
        'source_lengths_utf8_bytes': {s['source_id']: len(s['text'].encode('utf-8')) for s in sources},
        'source_body_sha256': {s['source_id']: s['sha256'] for s in sources},
        'all_source_body_hashes_verified': all(sha(s['text'].encode('utf-8')) == s['sha256'] for s in sources),
        'full_original_message_checks': messages_checked, 'exact_quote_checks': quote_checks,
        'primary_question_evidence_count': 32, 'alternative_complete_evidence_count': len(evidence) - 32,
        'all_39_primary_and_alternative_quotes_verified': len(quote_checks) == 39,
        'question_and_reference_texts_unchanged': True,
        'support_sets_are_AI_authored_not_exhaustive_semantic_gold': True}
    for relative, fingerprint in inputs.items():
        require(sha((HERE / relative).read_bytes()) == fingerprint, 'read_only_input_changed_during_build')
    return {'cases.jsonl': cases_bytes, 'questions.json': questions_bytes,
            'questions.evidence.json': evidence_bytes, 'data_validation.json': encode(validation)}, validation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=HERE / 'data_scale64')
    parser.add_argument('--check', action='store_true', help='Verify existing output only; do not write')
    args = parser.parse_args()
    output = args.output.resolve()
    require(output != OLD.resolve() and OLD.resolve() not in output.parents, 'old_data_directory_is_read_only')
    files, validation = build()
    for filename, raw in files.items():
        target = output / filename
        if target.exists():
            require(target.read_bytes() == raw, 'refusing_to_change_frozen_scale64_output:' + filename)
        else:
            require(not args.check, 'missing_scale64_output:' + filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw)
    print(json.dumps({key: validation[key] for key in (
        'case_id', 'independent_content_clusters', 'source_count', 'original_complete_exchanges',
        'original_complete_message_contents', 'cases_sha256', 'questions_sha256', 'evidence_sha256',
        'all_source_body_hashes_verified', 'all_39_primary_and_alternative_quotes_verified',
        'primary_question_evidence_count', 'alternative_complete_evidence_count', 'model_calls', 'network_requests')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
