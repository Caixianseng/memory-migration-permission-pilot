"""Offline, read-only public metadata consistency reproduction; no raw data."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = {'gate0.json', 'role_baseline.json', 'README.md', 'reproduce.py'}
USAGE_KEYS = ('inputTokens', 'cacheReadTokens', 'cacheWriteTokens', 'outputTokens', 'totalTokens')


def need(value, code):
    if not value:
        raise ValueError(code)


def read(name):
    return json.loads((HERE / name).read_text(encoding='utf-8'))


def count(value):
    need(type(value) is int and value >= 0, 'invalid_nonnegative_counter')
    return value


def verify_usage(usage):
    if usage is None:
        return
    need(set(usage) == set(USAGE_KEYS), 'unexpected_usage_fields')
    for value in usage.values():
        count(value)
    need(usage['totalTokens'] == sum(usage[k] for k in USAGE_KEYS[:-1]), 'usage_sum_mismatch')


def main():
    seal = read('seal.json')
    need(seal['schema'] == 'innovation-gate0-public-metadata-seal-v1', 'unknown_seal')
    need(set(seal['files']) == FILES, 'unexpected_sealed_file_set')
    for name, expected in seal['files'].items():
        need(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == expected, 'file_hash_mismatch:' + name)
    g, r = read('gate0.json'), read('role_baseline.json')
    need(g['schema'] == 'gate0-existing-capacity-measure-v1', 'unexpected_gate0_schema')
    need(r['schema'] == 'source-role-frozen-development-diagnostic-v1', 'unexpected_role_schema')
    for data in (g, r):
        need(data['new_model_calls'] == 0 and data['new_account_queries'] == 0 and data['network_requests'] == 0,
             'diagnostic_side_effect_declaration_changed')
    raw = [case[arm] for case in g['cases'] for arm in ('raw_legal_off', 'raw_legal_max')]
    limits = g['limits_from_source']['transport']
    for case in g['cases']:
        sources = case['source_texts']
        need(count(case['allowed_sources']) == len(sources), 'source_count_mismatch')
        need(sum(count(s['utf8_bytes']) for s in sources) == case['source_text_total_utf8_bytes'], 'source_byte_sum_mismatch')
        need(sum(count(s['characters']) for s in sources) == case['source_text_total_characters'], 'source_char_sum_mismatch')
        need(all(s['exact_text_tokens'] is None for s in sources), 'standalone_token_claim_changed')
        quote = case['ordinary_full_source_quote']
        need(quote['exact_text_tokens'] is None and quote['full_request_utf8_bytes'] is None,
             'unexecuted_quote_request_claim_changed')
        for arm in ('raw_legal_off', 'raw_legal_max', 'existing_source_cache_max4096', 'existing_source_cache_max12288'):
            request = case[arm]
            if request is None:
                continue
            verify_usage(request['whole_call_vendor_usage'])
            need(request['memory']['exact_text_tokens'] is None and request['prompt']['exact_text_tokens'] is None,
                 'standalone_request_text_tokens_not_unknown')
        verify_usage(case['cache_initial_whole_call_usage_total'])
    fits = all(row['verified'] is True and row['memory']['utf8_bytes'] <= limits['MAX_MEMORY_BYTES'] and
               row['prompt']['utf8_bytes'] <= limits['MAX_PROMPT_BYTES'] and
               row['full_request_utf8_bytes'] <= limits['HARD_REQUEST_BYTES'] for row in raw)
    gate_counts = {'known_development_cases': len(g['cases']),
        'actual_complete_legal_source_target_calls_checked': len(raw),
        'all_existing_raw_calls_fit_and_verified': fits,
        'maximum_raw_memory_utf8_bytes': max(count(x['memory']['utf8_bytes']) for x in raw),
        'maximum_raw_prompt_utf8_bytes': max(count(x['prompt']['utf8_bytes']) for x in raw),
        'maximum_actual_raw_full_request_utf8_bytes': max(count(x['full_request_utf8_bytes']) for x in raw),
        'minimum_actual_raw_full_request_remaining_bytes': min(limits['HARD_REQUEST_BYTES'] - x['full_request_utf8_bytes'] for x in raw)}
    for key, value in gate_counts.items():
        need(g['summary'][key] == value, 'gate0_aggregate_mismatch:' + key)
    totals, same = {}, 0
    for case in r['cases']:
        arms = case['arms']
        need(len(arms) == 2 and len({a['strategy'] for a in arms}) == 2, 'role_arm_inventory_mismatch')
        for arm in arms:
            selected = count(arm['selected_count'])
            need(sum(count(x) for x in arm['selected_by_source'].values()) == selected, 'source_selection_sum_mismatch')
            need(sum(count(x) for x in arm['selected_by_speaker'].values()) == selected, 'role_selection_sum_mismatch')
            need(count(arm['exact_whole_quotes']) == selected and arm['exact_quote_rate'] == 1,
                 'declared_quote_numerator_denominator_mismatch')
            need(selected == count(arm['candidate_count']) and arm['original_message_coverage'] == 1,
                 'declared_candidate_coverage_mismatch')
            need(count(arm['payload_utf8_bytes']) <= r['budget'], 'recorded_payload_exceeds_budget')
            need(arm['model_answer_correctness'] is None and arm['semantic_or_task_success_established'] is False,
                 'model_success_claim_changed')
            totals[arm['strategy']] = totals.get(arm['strategy'], 0) + selected
        equal = (arms[0]['payload_sha256'] == arms[1]['payload_sha256'] and
                 arms[0]['payload_utf8_bytes'] == arms[1]['payload_utf8_bytes'])
        need(case['payload_bytes_identical'] == equal, 'payload_equality_metadata_mismatch')
        need(case['candidate_pool_identical'] == (arms[0]['candidate_pool_sha256'] == arms[1]['candidate_pool_sha256']),
             'candidate_pool_equality_mismatch')
        same += equal
    aggregate = r['aggregate']
    need(aggregate['cases'] == len(r['cases']) and aggregate['arms_per_case'] == 2, 'role_case_count_mismatch')
    need(all(n == aggregate['selected_messages_per_arm'] for n in totals.values()), 'role_selected_total_mismatch')
    need(aggregate['original_legal_messages'] == aggregate['selected_messages_per_arm'], 'role_original_count_mismatch')
    need(aggregate['payloads_identical_cases'] == same, 'role_identical_case_total_mismatch')
    need(r['budget'] == limits['MAX_MEMORY_BYTES'], 'role_budget_not_current_recorded_memory_cap')
    print(json.dumps({'status': 'ok', 'scope': 'file_hashes_and_public_numeric_metadata_only',
        'gate0': gate_counts, 'role_baseline': {'cases': len(r['cases']), 'selected_messages_by_strategy': totals,
                                             'payload_hash_and_length_identical_cases': same},
        'raw_quote_integrity_independently_reverified': False, 'semantic_scoring_reproduced': False,
        'client_models_rerun': False, 'new_model_calls': 0}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
