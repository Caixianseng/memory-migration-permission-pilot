"""Offline arithmetic and content verification of the public evidence projection.

Python standard library only. No network, models, accounts, SDK or project imports.
AI semantic labels are counted as annotations, never independently re-judged.
"""
from collections import Counter
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent


def need(condition, message):
    if not condition:
        raise ValueError(message)


def path(name):
    candidate = (ROOT / name).resolve()
    need(candidate.is_relative_to(ROOT), 'Bundle path escapes its directory')
    return candidate


def load(name):
    return json.loads(path(name).read_text(encoding='utf-8'))


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def sha(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    return hashlib.sha256(value).hexdigest()


def cny(value):
    return format(value, 'f')


def aggregate(rows):
    result = Counter()
    amounts = {k: Decimal(0) for k in ['source_cost_upper_cny', 'target_cost_upper_cny',
        'source_plus_target_cost_upper_cny', 'gross_reserved_cny', 'pending_reserved_cny']}
    for job in rows:
        u = job['usage']
        inp = u['inputTokens'] + u['cacheReadTokens'] + u['cacheWriteTokens']
        out = u['outputTokens']
        role = job['role']
        result.update({'requests': 1, role + '_requests': 1, 'raw_input_tokens': u['inputTokens'],
            'cache_read_tokens': u['cacheReadTokens'], 'cache_write_tokens': u['cacheWriteTokens'],
            'total_input_tokens': inp, 'output_tokens': out,
            role + '_input_tokens': inp, role + '_output_tokens': out})
        cost = Decimal(inp * 2 + out * 8) / Decimal(1000000)
        amounts[role + '_cost_upper_cny'] += cost
        amounts['source_plus_target_cost_upper_cny'] += cost
        amounts['gross_reserved_cny'] += Decimal(job['reservation']['reserved_cny'])
    # Every exported reservation has a final ok settlement, so none remains pending.
    for key in ['requests', 'source_requests', 'target_requests', 'raw_input_tokens',
                'cache_read_tokens', 'cache_write_tokens', 'total_input_tokens', 'output_tokens',
                'source_input_tokens', 'source_output_tokens', 'target_input_tokens', 'target_output_tokens']:
        result.setdefault(key, 0)
    return {**dict(result), **{k: cny(v) for k, v in amounts.items()}}


def compare_aggregate(actual, reference, name):
    for key, value in reference.items():
        need(key in actual, f'{name}: unsupported reference field {key}')
        need(Decimal(str(actual[key])) == Decimal(str(value)), f'{name}: mismatch {key}')


def main():
    manifest = load('manifest.json')
    for name, digest in manifest['files_sha256'].items():
        need(sha(path(name).read_bytes()) == digest, 'Bundle file hash mismatch: ' + name)
    materials = load('materials.json')
    ai = load('ai_review.json')
    qualification = load('qualification.json')
    for obj in [materials, ai, qualification, qualification['sdk_qualification']]:
        need(obj['human_gold'] is None, 'human_gold must remain null')
    index = load('sdk_jobs.json')
    jobs = [row for name in index['job_files'] for row in load(name)['jobs']]
    by_id = {job['job_id']: job for job in jobs}
    need(len(by_id) == len(jobs), 'Duplicate logical SDK job')
    payloads = {}
    for job in jobs:
        job_id = job['job_id']
        need(job['status'] == job['settlement']['status'] == 'ok', job_id + ': unsettled job')
        need(job['sdk_stream_attempts'] == job['sdk_provider_dispatch_count'] == 1,
             job_id + ': unexpected logical dispatch count')
        need(job['stop_reason'] == {'kind': 'stop'}, job_id + ': incomplete SDK response')
        need(sha(job['user_message']) == job['user_message_sha256'], job_id + ': user message hash')
        need(sha(job['output']) == job['output_sha256'], job_id + ': raw output hash')
        system = index['system_templates'][job['system_template_id']]
        need(sha(system) == job['system_template_id'], job_id + ': system prompt hash')
        texts = [system, job['user_message']]
        messages = [{**meta, 'content': [{'text': text, 'type': 'text'}]}
                    for meta, text in zip(job['message_metadata'], texts)]
        need(len(messages) == 2, job_id + ': expected two independent messages')
        options = {**job['settings'], 'messages': messages}
        need(sha(canonical(options)) == job['actual_options_sha256'], job_id + ': SDK options hash')
        need(options['tools'] == [] and options['reasoningEffort'] == 'off', job_id + ': SDK settings')
        u, settlement, reservation = job['usage'], job['settlement'], job['reservation']
        need(all(isinstance(v, int) and v >= 0 for v in u.values()), job_id + ': usage values')
        inp = u['inputTokens'] + u['cacheReadTokens'] + u['cacheWriteTokens']
        need(u['totalTokens'] == inp + u['outputTokens'], job_id + ': token accounting')
        cost = Decimal(inp * 2 + u['outputTokens'] * 8) / Decimal(1000000)
        need(cost == Decimal(settlement['peak_cost_upper_cny']), job_id + ': cost mismatch')
        need(settlement['input_tokens'] == inp and settlement['output_tokens'] == u['outputTokens'],
             job_id + ': settlement tokens')
        need(Decimal(settlement['reserved_cny']) == Decimal(reservation['reserved_cny']),
             job_id + ': reservation mismatch')
        need(settlement['receipt_sha256'] == job['archive_sdk_receipt_sha256'],
             job_id + ': original receipt digest binding')
        need(settlement['invoice_cny'] is None and settlement['provider_physical_requests'] is None,
             job_id + ': unknown provider fields changed')
        payloads[job_id] = json.loads(job['user_message'])
        if job['role'] == 'source':
            payload = payloads[job_id]
            need(payload['input_hash'] == sha(canonical({k: v for k, v in payload.items()
                 if k != 'input_hash'})), job_id + ': source input hash')
            need(payload['template'] == system, job_id + ': source prompt binding')
            need(payload['source_ids'] == sorted(item['input_id'] for item in payload['inputs']),
                 job_id + ': source roots')
            for item in payload['inputs']:
                need(item['input_hash'] == sha(item['text']), job_id + ': source text digest')

    formal_jobs = [j for j in jobs if j['kind'] == 'formal']
    refs = load('accounting_reference.json')
    totals = {kind: aggregate([j for j in jobs if j['kind'] == kind])
              for kind in ['formal', 'qualification', 'external_qualification']}
    compare_aggregate(totals['formal'], refs['formal_total'], 'formal')
    compare_aggregate(totals['qualification'], refs['qualification_total'], 'qualification')
    compare_aggregate(aggregate([j for j in jobs if j['kind'] != 'external_qualification']),
                      refs['live_run02_combined_total'], 'live_run02')
    method_costs = {}
    for method in refs['by_method']:
        method_costs[method] = aggregate([j for j in formal_jobs if j['method'] == method])
        compare_aggregate(method_costs[method], refs['by_method'][method], method)
    for story_id in refs['by_story']:
        compare_aggregate(aggregate([j for j in formal_jobs if j['story_id'] == story_id]),
                          refs['by_story'][story_id], story_id)

    sources = {s['story_id']: {x['source_id']: x['text'] for x in s['sources']}
               for s in materials['formal_sources']['stories']}
    questions = {s['story_id']: s['questions'] for s in materials['formal_questions']['stories']}
    policies = {s['story_id']: {v['view']: v for v in s['states']}
                for s in materials['formal_policy']['stories']}
    source_index = {(j['story_id'], j['artifact'], j['view']): j for j in formal_jobs if j['role'] == 'source'}
    for (story_id, artifact, view), job in source_index.items():
        payload = payloads[job['job_id']]
        expected = (list(policies[story_id][view]['allowed_source_ids']) if artifact == 'R'
                    else [artifact[2:]] if artifact.startswith('C_') else sorted(sources[story_id]))
        need(payload['source_ids'] == expected, 'Generation dependency mismatch: ' + job['job_id'])
        for item in payload['inputs']:
            need(item['text'] == sources[story_id][item['input_id']], 'Frozen source content mismatch')

    branch_counts, memory_hashes, used_targets = Counter(), {}, set()
    for story in load('formal_delivery.json')['stories']:
        sid = story['story_id']
        for call in story['source_calls']:
            job = source_index[(sid, call['artifact'], call['view'])]
            need(payloads[job['job_id']]['input_hash'] == call['input_hash'] and
                 job['output_sha256'] == call['output_hash'], 'Source call summary hash mismatch')
        for branch in story['branches']:
            method, view = branch['method'], branch['view']
            cell = sid + '/' + branch['branch_id']
            legal = policies[sid][view]['allowed_source_ids']
            blocked = method == 'B0' and set(legal) != set(sources[sid])
            branch_counts[method + '/' + ('blocked' if blocked else 'delivered')] += 1
            if blocked:
                need(branch['status'] == 'blocked_no_target' and
                     branch['target_callback_invocations'] == 0 and 'sdk_job_id' not in branch,
                     cell + ': blocking evidence mismatch')
                continue
            need(branch['status'] == 'delivered' and branch['source_ids'] == legal,
                 cell + ': illegal dependency delivery')
            target = by_id[branch['sdk_job_id']]
            need(target['role'] == 'target' and target['story_id'] == sid and
                 target['method'] == method and target['view'] == view, cell + ': wrong target job')
            used_targets.add(target['job_id'])
            payload = payloads[target['job_id']]
            need(payload['questions'] == questions[sid], cell + ': changed question text')
            ids = branch['artifact_ids']
            facts = []
            roots = set()
            for artifact in ids:
                if method == 'B1':
                    text = sources[sid][artifact]
                    roots.add(artifact)
                else:
                    source = source_index[(sid, artifact, view if artifact == 'R' else None)]
                    text = source['output']
                    roots.update(payloads[source['job_id']]['source_ids'])
                facts.append({'input_id': artifact, 'text': text})
                need(sha(text) == branch['host_envelope']['output_hashes'][artifact], cell + ': fact hash')
            need(roots == set(legal), cell + ': dependency closure differs from legal sources')
            reconstructed_memory = json.dumps({'facts': facts}, ensure_ascii=False, sort_keys=True)
            need(payload['memory'] == reconstructed_memory, cell + ': actual target memory mismatch')
            memory_hashes[cell] = sha(payload['memory'])
            need(memory_hashes[cell] == branch['memory_hash'] == branch['host_envelope']['memory_sha256'],
                 cell + ': host memory hash mismatch')
    need(used_targets == {j['job_id'] for j in formal_jobs if j['role'] == 'target'}, 'Extra or missing formal target')

    for row in qualification['hy3_sources']:
        obs = row['observation']
        need(sha(canonical(row['input'])) == obs['input_sha256'], 'HY3 input digest')
        need(sha(row['submitted_prompt']) == row['submitted_prompt_sha256'], 'HY3 prompt digest')
        need(sha(row['output']) == obs['output_sha256'] == row['receipt']['outputSha256'], 'HY3 output digest')
    external_target = payloads[qualification['sdk_job_id']]
    rebuilt = next(row for row in qualification['hy3_sources'] if row['artifact'] == 'R')
    # The historical cross-client adapter uses a Markdown task-memory envelope.
    memory_json = external_target['memory'].split('```json\n', 1)[1].split('\n```', 1)[0]
    external_facts = json.loads(memory_json)['facts']
    need(external_facts == [{'record_id': 'R', 'text': rebuilt['output']}], 'HY3 to SDK memory binding')
    need(sha(external_target['memory']) == load('security_review_summary.json')['external']['target']['memory_sha256'],
         'External target memory hash')

    labels = [row for name in ai['question_files'] for row in load(name)['question_reviews']]
    # Counting imported labels is arithmetic, not a semantic accuracy test.
    label_tally = {'review_kind': 'AI annotations, not independently re-scored by this script',
        'question_annotations': len(labels),
        'legal_question_labels': sum(bool(r['policy_legally_answerable']) for r in labels),
        'legal_correct_labels': sum(bool(r['legitimate_answer_credit']) for r in labels),
        'UNKNOWN_correct_labels': sum(bool(r['correct_missing_evidence_abstention']) for r in labels),
        'semantic_judgments': dict(Counter(r['semantic_judgment'] for r in labels)),
        'unresolved_reservations': [r['answer_id'] for r in ai['reservations'] if r['human_resolution'] is None]}
    print(json.dumps({'status': 'PASS_PUBLIC_PROJECTION_CHECKS', 'human_gold': None,
        'native_receipts_or_HMAC_reverified': False, 'sdk_job_count': len(jobs),
        'totals_recomputed_from_job_usage': totals, 'formal_method_costs': method_costs,
        'formal_branch_counts': dict(branch_counts), 'target_memory_hashes': memory_hashes,
        'HY3_output_and_prompt_hash_checks': len(qualification['hy3_sources']),
        'ai_annotation_tally_only': label_tally}, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print('FAIL_PUBLIC_PROJECTION_CHECKS: ' + str(exc), file=sys.stderr)
        sys.exit(1)
