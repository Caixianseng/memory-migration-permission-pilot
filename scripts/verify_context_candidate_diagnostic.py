"""Read-only offline audit of the exposed 120-material candidate diagnostic.

Never loads neural weights, opens a model endpoint, or executes archived code.
Scores are independently recomputed. Current pinned pure adapters are replayed
only against recorded observations after source hashes have been checked.
Checksums/timestamps establish consistency, not resistance to coordinated forgery.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import random
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
VERSION = 'independent_context_candidate_diagnostic_verification_v2'
ARMS = ('ner_rules', 'typed_seeded_only', 'typed_all_candidates')
SPLITS = {'development': 80, 'heldout': 40}
SEED = 2026102602
CATEGORIES = frozenset({'EMAIL', 'PHONE', 'ID', 'PERSON', 'ADDRESS', 'CUSTOMER', 'PROJECT', 'AMOUNT', 'DATE'})
SOURCES = {'scripts/run_context_candidate_diagnostic.py', 'scripts/run_semantic_detection_benchmark.py',
    *('memory_migration_study/' + name + '.py' for name in ('privacy', 'local_detector', 'ner_detector',
       'candidate_proposals', 'candidate_adjudicator', 'context_candidate_typing', 'context_typed_detection'))}
BOUND = {'plan.json', 'identities.json', 'materials.json', 'model_calls.json',
         'encoding_invocations.json', 'unscored_rows.json'}
FORBIDDEN_MODEL_KEYS = {'case_id', 'source_id', 'policy_id', 'payload_sha256', 'pool_sha256',
    'expected_status', 'findings', 'gold', 'score', 'answers', 'features', 'policy_pair_id',
    'shared_story_id', 'template_family', 'language', 'split'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def same(left, right):
    return json.dumps(left, ensure_ascii=False, sort_keys=True, allow_nan=False) == json.dumps(
        right, ensure_ascii=False, sort_keys=True, allow_nan=False)


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 80 * 1024 * 1024:
        raise ValueError('artifact_missing_linked_or_too_large')
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate_json_key')
            value[key] = item
        return value
    return json.loads(path.read_bytes(), object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))


def moment(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError('timestamp_not_aware')
    return result


def clean_times(value):
    if isinstance(value, dict):
        return {key: clean_times(item) for key, item in value.items()
                if key not in {'elapsed_seconds', 'agent_elapsed_seconds'}}
    if isinstance(value, list):
        return [clean_times(item) for item in value]
    return value


def text_sources(payload):
    # The production payload contract reserves __query__ for question text.
    # Corpus findings may legitimately label that source rather than a memory.
    result = {'__query__': payload['query']}
    for item in payload['memories']:
        if item['source_id'] in result:
            raise ValueError('duplicate_source_id')
        result[item['source_id']] = item['text']
    return result


def span_keys(findings, payload, *, strict=False):
    sources = text_sources(payload)
    result, invalid, duplicate = set(), 0, 0
    for item in findings:
        if not isinstance(item, dict):
            invalid += 1
            continue
        sid, start, end, category = (item.get(key) for key in ('source_id', 'start', 'end', 'category'))
        if (not isinstance(sid, str) or sid not in sources or type(start) is not int
                or type(end) is not int or not 0 <= start < end <= len(sources[sid])
                or category not in CATEGORIES):
            invalid += 1
            continue
        key = (sid, start, end, category)
        duplicate += key in result
        result.add(key)
    if strict and (invalid or duplicate):
        raise ValueError('invalid_gold_spans')
    return result, invalid, duplicate


def counts(predicted, expected):
    tp, fp, fn = len(predicted & expected), len(predicted - expected), len(expected - predicted)
    return {'tp': tp, 'fp': fp, 'fn': fn, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None}


def score(detection, gold, payload):
    """Independent whole-span scoring; failed materials retain every gold FN."""
    expected, _, _ = span_keys(gold['findings'], payload, strict=True)
    candidate, invalid, duplicate = span_keys(detection.get('findings', []), payload)
    accepted = candidate if detection.get('status') == 'ok' and not invalid else set()
    return {'accepted': counts(accepted, expected), 'validated_candidate': counts(candidate, expected),
        'invalid_candidate_count': invalid, 'duplicate_candidate_count': duplicate,
        'accepted_complete_exact': detection.get('status') == 'ok' and not invalid and accepted == expected,
        'gold_spans': len(expected), 'accepted_spans': len(accepted), 'validated_candidate_spans': len(candidate),
        'by_category': {category: {
            'accepted': counts({p for p in accepted if p[3] == category}, {p for p in expected if p[3] == category}),
            'validated_candidate': counts({p for p in candidate if p[3] == category}, {p for p in expected if p[3] == category})}
            for category in sorted(CATEGORIES)}}


def sum_counts(items):
    total = {key: sum(item[key] for item in items) for key in ('tp', 'fp', 'fn')}
    tp, fp, fn = (total[key] for key in ('tp', 'fp', 'fn'))
    return {**total, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None}


def no_gold_fields(value):
    if isinstance(value, dict):
        return not (set(value) & FORBIDDEN_MODEL_KEYS) and all(no_gold_fields(item) for item in value.values())
    return not isinstance(value, list) or all(no_gold_fields(item) for item in value)


def usage_evidence(calls):
    """Missing/invalid usage never turns into an observed zero-token call."""
    totals = {'prompt_eval_count': 0, 'eval_count': 0}
    unavailable, overruns = [], []
    for call in calls:
        response = call.get('response')
        if not isinstance(response, dict):
            unavailable.append(call['index'])
            continue
        prompt, output = response.get('prompt_eval_count'), response.get('eval_count')
        if type(prompt) is not int or prompt <= 0 or type(output) is not int or output <= 0:
            unavailable.append(call['index'])
            continue
        totals['prompt_eval_count'] += prompt
        totals['eval_count'] += output
        if prompt > 3072 or output > 1024:
            overruns.append(call['index'])
    return {'observed_positive_token_counts': totals,
        'usage_unavailable_call_indices': unavailable, 'over_budget_call_indices': overruns,
        'all_runtime_usage_observed_within_budget': False if overruns else None if unavailable else True}


def static_phase_order(source):
    tree = ast.parse(source)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
    closed = [node.lineno for node in ast.walk(function) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
            and target.value.id == 'observer' and target.attr == 'closed' for target in node.targets)
        and isinstance(node.value, ast.Constant) and node.value.value is True]
    parsed = [node.lineno for node in ast.walk(function) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'gold' for target in node.targets)
        and isinstance(node.value, ast.Call)]
    scored = [node.lineno for node in ast.walk(function) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == 'score_detection']
    return len(closed) == len(parsed) == 1 and bool(scored) and closed[0] < parsed[0] < min(scored)


def _replay_material(case, material, encodings, observed_calls, identities):
    # Imports are current approved source only, never run/frozen_source modules.
    from memory_migration_study.ner_detector import GlinerEntityAgent
    from memory_migration_study.context_candidate_typing import LocalContextCandidateTyper, preflight
    from memory_migration_study.context_typed_detection import compose_typed_detection
    from memory_migration_study.candidate_proposals import propose_candidates
    from memory_migration_study.privacy import detect_sensitive
    from scripts.run_semantic_detection_benchmark import CountingAgent

    remaining_encodings = list(encodings)
    replay_faults = []
    ner_identity = identities['ner']
    def infer(text, labels, *, splitter, threshold):
        if not remaining_encodings:
            replay_faults.append('missing_encoding_observation')
            raise AssertionError('missing_encoding_observation')
        record = remaining_encodings.pop(0)
        if (record['text_sha256'] != sha(text.encode('utf-8')) or not same(record['labels'], labels)
                or record['splitter'] != splitter or record['threshold'] != threshold):
            replay_faults.append('encoding_input_mismatch')
            raise AssertionError('encoding_input_mismatch')
        if record.get('error') is not None:
            # The public observer uses a fixed exception code. Preserve the
            # adapter's explicit pre-forward budget branch without hiding it.
            if 'input_budget_exceeded' in material['baseline'].get('errors', []):
                raise ValueError('input_budget_exceeded')
            raise RuntimeError('recorded_encoder_failure')
        return deepcopy(record['response'])
    fake_runtime = SimpleNamespace(identity=ner_identity['runtime'], infer=infer)
    ner = GlinerEntityAgent(fake_runtime, approved_policies=[case['policy']],
        splitter=ner_identity['splitter'], threshold=ner_identity['threshold'])
    agent = CountingAgent(ner, 'local_encoder')
    baseline = detect_sensitive(case['payload'], case['policy'], agent=agent, mode='combined')
    # Adapters deliberately catch inference exceptions. Mismatches therefore
    # need an out-of-band flag; a recorded method failure must not hide tampering.
    assert not remaining_encodings and not replay_faults
    assert same(clean_times(baseline), clean_times(material['baseline']))
    assert same(clean_times(agent.accounting(baseline)), clean_times(material['encoder_accounting']))
    pool = propose_candidates(case['payload'], case['policy'], material['baseline']['findings'],
                              max_candidates=16, max_quote_chars=256)
    assert same(pool, material['pool'])
    assert same(preflight(case['payload'], case['policy'], pool), material['preflight'])

    stage = material['typing']
    remaining = list(observed_calls)
    def transport(method, path, body=None):
        if method != 'POST' or path != '/api/chat' or not remaining:
            replay_faults.append('generation_transport_mismatch')
            raise AssertionError('generation_transport_mismatch')
        call = remaining.pop(0)
        if not same(body, call['request']):
            replay_faults.append('generation_body_mismatch')
            raise AssertionError('generation_body_mismatch')
        if call.get('transport_error') is not None:
            raise RuntimeError('recorded_generation_failure')
        return deepcopy(call['response'])
    typer = LocalContextCandidateTyper(stage.get('config'), transport=transport)
    def health():
        if stage.get('error') == 'typing_local_health_failed':
            raise RuntimeError('recorded_health_failure')
        return deepcopy(stage.get('health'))
    typer.health = health
    replayed = typer.classify(case['payload'], case['policy'], pool)
    assert not remaining and not replay_faults and same(clean_times(replayed), clean_times(stage))
    return {'ner_rules': material['baseline'],
        'typed_seeded_only': compose_typed_detection(case['payload'], case['policy'], material['baseline'], pool, stage, promote_untyped=False),
        'typed_all_candidates': compose_typed_detection(case['payload'], case['policy'], material['baseline'], pool, stage)}


def verify(run, *, data_root=None):
    run = Path(run).resolve()
    data_root = Path(data_root).resolve() if data_root else ROOT / 'examples/privacy_semantics_v1/detection'
    checks = []
    def check(name, predicate):
        try:
            value = predicate() if callable(predicate) else predicate
            passed = bool(value)
        except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, AssertionError, StopIteration, RecursionError):
            passed = False
        checks.append({'check': name, 'passed': passed})
        return passed
    def finish(status=None, **extra):
        return {'version': VERSION, 'status': status or ('passed' if all(c['passed'] for c in checks) else 'failed'),
            'checks': checks, 'verification_model_calls': 0, 'privacy_or_recall_acceptance': False,
            'scope': 'Offline consistency/replay only. Failed methods remain failures; exposed data is not fresh acceptance.',
            'limitations': ['Hashes/timestamps do not prevent coordinated artifact forgery.',
                'Encoder records observe LocalNerRuntime.infer entrypoints, not GPU kernels.',
                'The fixed encoder exception observer cannot independently distinguish every pre-forward failure cause.'], **extra}
    try:
        plan = read(run / 'plan.json')
        corpus = []
        for split, expected in SPLITS.items():
            values = read(run / split / 'runtime.json')
            if not check(split + '_original_runtime_hash', lambda: len(values) == expected
                and sha((run / split / 'runtime.json').read_bytes()) == plan['corpus_sha256'][split + '/runtime.json']
                == sha((data_root / split / 'runtime.json').read_bytes())):
                return finish()
            corpus.extend({**value, 'split': split} for value in values)
        ordered = deepcopy(corpus)
        random.Random(SEED).shuffle(ordered)
        ids = [case['case_id'] for case in ordered]
        expected_encodings = sum(bool(text.strip()) and bool(case['policy']['protected_categories'])
            for case in corpus for text in text_sources(case['payload']).values())
        check('registered_scope_and_budgets', lambda: plan['arms'] == list(ARMS) and plan['seed'] == SEED
            and plan['case_order'] == ids and len(ids) == len(set(ids)) == plan['material_count'] == 120
            and plan['max_generations'] == 240 and plan['max_encodings'] == expected_encodings
            and plan['max_candidates'] == 16 and plan['max_quote_chars'] == 256
            and plan['context_window_chars'] == 24 and plan['context_tokens'] == 4096 and plan['max_output_tokens'] == 1024
            and plan['strict_processing_failures_in_recall_denominator'] is True
            and plan['heldout_scope'] == 'already_exposed_regression_not_fresh_acceptance'
            and plan['cloud_calls'] == plan['new_api_cost_cny'] == 0 and plan['no_default_branch_change'] is True
            and 'not a standalone' in plan['shared_verdict_ablation'])
        manifest = plan['implementation_sha256']
        normalized = {name.replace('\\', '/'): value for name, value in manifest.items()}
        source_ok = check('frozen_and_current_approved_source_hashes', lambda: set(normalized) == SOURCES
            and all(sha((ROOT / name).read_bytes()) == expected
                == sha((run / 'frozen_source' / name).read_bytes()) for name, expected in normalized.items()))
        check('declared_gold_after_model_closure_source_order', lambda: static_phase_order(
            (run / 'frozen_source/scripts/run_context_candidate_diagnostic.py').read_text(encoding='utf-8')))
        if not (run / 'model_phase_closed.json').is_file():
            return finish('incomplete' if all(c['passed'] for c in checks) else 'failed',
                execution_complete=False, note='No closed model phase; no gold parsed or score accepted.')
        closure, scoring = read(run / 'model_phase_closed.json'), read(run / 'score_phase_started.json')
        check('closed_artifact_hashes', lambda: closure['model_phase_closed'] is True
            and set(closure['artifact_sha256']) == BOUND
            and all(sha((run / name).read_bytes()) == expected for name, expected in closure['artifact_sha256'].items())
            and closure['unscored_rows_sha256'] == sha((run / 'unscored_rows.json').read_bytes())
            and scoring['model_phase_closed_sha256'] == sha((run / 'model_phase_closed.json').read_bytes())
            and moment(plan['created_at']) <= moment(closure['closed_at']) <= moment(scoring['started_at']))
        materials, calls, encodings, unscored, rows, report, identities, network = [read(run / name) for name in (
            'materials.json', 'model_calls.json', 'encoding_invocations.json', 'unscored_rows.json',
            'rows.json', 'report.json', 'identities.json', 'network_audit.json')]
        by_id = {case['case_id']: case for case in corpus}
        check('all_materials_and_three_arms_in_registered_order', lambda:
            [m['case_id'] for m in materials] == ids
            and [(r['case_id'], r['arm']) for r in rows] == [(cid, arm) for cid in ids for arm in ARMS]
            and same([{key: value for key, value in row.items() if key != 'score'} for row in rows], unscored)
            and len(rows) == 360 and all('score' not in row for row in unscored)
            and closure['material_count'] == report['material_count'] == len(materials) == 120)
        forbidden_ids = {case['case_id'] for case in corpus}
        forbidden_ids.update(item['source_id'] for case in corpus for item in case['payload']['memories'])
        forbidden_ids.update(case['policy'][key] for case in corpus for key in ('version', 'policy_id') if key in case['policy'])
        def calls_ok():
            assert len(calls) <= 240 and [c['index'] for c in calls] == list(range(len(calls)))
            assert closure['generation_posts'] == report['actual_generations'] == len(calls)
            for call in calls:
                body = call['request']
                assert call['case_id'] in by_id and call['path'] == '/api/chat'
                assert set(body) == {'model', 'messages', 'format', 'stream', 'keep_alive', 'options'}
                assert body['options'] == {'num_ctx': 4096, 'num_predict': 1024, 'temperature': 0, 'seed': 42}
                assert body['stream'] is False and body['keep_alive'] == '30m'
                assert no_gold_fields(body)
                assert isinstance(body['messages'], list) and len(body['messages']) in (2, 3)
                assert body['messages'][1]['role'] == 'user'
                model_data = json.loads(body['messages'][1]['content'])
                assert set(model_data) == {'trusted_policy', 'candidates', 'evidence'}
                assert no_gold_fields(model_data)
                assert set(model_data['trusted_policy']) == {'protected_categories', 'instructions'}
                serialized = compact(body)
                assert not any(identifier in serialized for identifier in forbidden_ids if len(identifier) > 6)
                assert call['request_utf8_bytes'] == len(serialized.encode('utf-8'))
                assert call['request_sha256'] == sha(serialized.encode('utf-8'))
                assert len(serialized.encode('utf-8')) + 320 + 1024 <= 4096
                assert moment(plan['created_at']) <= moment(call['started_at']) <= moment(call['completed_at']) <= moment(closure['closed_at'])
                assert call['transport_error'] in {None, 'local_transport_failed'}
            return True
        check('physical_chat_observations_input_schema_no_gold_ids_and_budgets', calls_ok)
        def encoding_ok():
            assert len(encodings) <= expected_encodings and [e['index'] for e in encodings] == list(range(len(encodings)))
            assert report['encoder_invocations_observed'] == len(encodings)
            for item in encodings:
                case = by_id[item['case_id']]
                assert item['text_sha256'] in {sha(text.encode('utf-8')) for text in text_sources(case['payload']).values() if text.strip()}
                assert item['splitter'] == 'cjk_aware' and item['threshold'] == .5
                assert item['error'] in {None, 'local_encoder_failed'}
                assert moment(plan['created_at']) <= moment(item['started_at']) <= moment(item['completed_at']) <= moment(closure['closed_at'])
            return True
        check('observed_encoder_entrypoints_and_budget', encoding_ok)
        check('network_local_only_receipt', lambda: network == report['network']
            and set(network) == {'allowed_loopback_connections', 'blocked_external_connections'}
            and all(type(value) is int and value >= 0 for value in network.values())
            and network['blocked_external_connections'] == 0
            and report['cloud_calls'] == report['new_api_cost_cny'] == 0)
        if not source_ok:
            return finish(note='Archived source is data; mismatched code was not imported/executed.')
        from memory_migration_study.context_candidate_typing import LocalContextCandidateTyper
        from memory_migration_study import ner_detector as ner_module
        check('pinned_typer_identity', lambda: same(identities['typer'], LocalContextCandidateTyper().cache_identity())
            and identities['health'] == {'version': identities['typer']['runtime'], 'model': identities['typer']['model'],
                'digest': identities['typer']['digest'], 'endpoint': 'http://127.0.0.1:11435'})
        check('pinned_encoder_identity', lambda: identities['ner']['runtime']['code_revision'] == ner_module.CODE_REVISION
            and identities['ner']['runtime']['model_revision'] == ner_module.MODEL_REVISION
            and identities['ner']['runtime']['model_id'] == ner_module.MODEL_ID
            and same(identities['ner']['labels'], ner_module.LABELS) and identities['ner']['splitter'] == 'cjk_aware'
            and identities['ner']['threshold'] == .5 and identities['ner']['runtime']['device'] == 'cpu')
        row_index = {(row['case_id'], row['arm']): row for row in rows}
        all_indices = []
        for material in materials:
            cid = material['case_id']
            case = by_id[cid]
            indices = material['generation_indices']
            all_indices.extend(indices)
            selected = [calls[index] for index in indices]
            stage = material['typing']
            check('generation_binding_' + cid, lambda: all(c['case_id'] == cid for c in selected)
                and len(indices) == stage['local_calls'] == len(stage['raw_calls']) <= 2
                and all(same(c['request'], raw['request']) and same(c['response'], raw['response'])
                    and (c['transport_error'] is None) == (raw['error'] is None)
                    for c, raw in zip(selected, stage['raw_calls'])))
            selected_encodings = [item for item in encodings if item['case_id'] == cid]
            try:
                recomposed = _replay_material(case, material, selected_encodings, selected, identities)
                check('recorded_observation_replay_' + cid, all(same(clean_times(value),
                    clean_times(row_index[(cid, arm)]['detection'])) for arm, value in recomposed.items()))
            except (OSError, ValueError, TypeError, KeyError, AssertionError, AttributeError, IndexError):
                check('recorded_observation_replay_' + cid, False)
            immutable = {key for key in span_keys(material['baseline']['findings'], case['payload'])[0]
                if key[3] not in {'PERSON', 'CUSTOMER', 'PROJECT', 'ADDRESS'} or any(
                    (f.get('source_id'), f.get('start'), f.get('end'), f.get('category')) == key
                    and 'registry' in f.get('method', '').split('+') for f in material['baseline']['findings'])}
            check('immutable_protection_' + cid, all(row_index[(cid, arm)]['detection']['status'] != 'ok'
                or immutable <= span_keys(row_index[(cid, arm)]['detection']['findings'], case['payload'])[0]
                for arm in ARMS[1:]))
        check('every_observed_chat_attempt_owned_once', all_indices == list(range(len(calls))))
        usage = usage_evidence(calls)
        invalid_usage = set(usage['over_budget_call_indices'] + usage['usage_unavailable_call_indices'])
        check('invalid_or_overbudget_runtime_usage_never_scores_as_typing_success', all(
            not (set(material['generation_indices']) & invalid_usage)
            or material['typing']['status'] != 'typing_only' for material in materials))
        reported = sum(m['encoder_accounting']['inference_counts']['local_encoder'] for m in materials)
        check('reported_encoder_totals_separate_from_observed', lambda: report['encoder_calls_reported'] == reported
            and report['encoder_invocations_observed'] == len(encodings)
            and report['complete_encoder_accounting'] == all(
                m['encoder_accounting']['complete'] for m in materials))
        check('typing_and_preflight_totals', lambda: report['typing_statuses'] == dict(Counter(m['typing']['status'] for m in materials))
            and report['preflight_executable'] == sum(m['preflight'].get('executable') is True for m in materials)
            and report['row_count'] == 360 and report['implementation_unchanged'] is True)
        # Gold is parsed only here, after requiring a closed execution receipt.
        gold = {}
        for split, number in SPLITS.items():
            check(split + '_original_gold_hash', lambda: sha((run / split / 'evaluation.json').read_bytes())
                == plan['corpus_sha256'][split + '/evaluation.json']
                == sha((data_root / split / 'evaluation.json').read_bytes()))
            labels = read(run / split / 'evaluation.json')
            check(split + '_gold_identity_complete', set(labels) == {case['case_id'] for case in corpus if case['split'] == split})
            gold.update(labels)
        summaries = {split: {} for split in SPLITS}
        for row in rows:
            cid = row['case_id']
            expected = score(row['detection'], gold[cid], by_id[cid]['payload'])
            check('independent_whole_span_score_' + cid + '_' + row['arm'], same(expected, row['score'])
                and row['split'] == by_id[cid]['split'] and row['language'] == by_id[cid]['language']
                and row['template_family'] == by_id[cid]['template_family'])
        for split, number in SPLITS.items():
            for arm in ARMS:
                selected = [row for row in rows if row['split'] == split and row['arm'] == arm]
                recomputed = [score(row['detection'], gold[row['case_id']], by_id[row['case_id']]['payload']) for row in selected]
                summaries[split][arm] = {'materials': len(selected), 'accepted': sum_counts([s['accepted'] for s in recomputed]),
                    'ok': sum(row['detection']['status'] == 'ok' for row in selected),
                    'exact_materials': sum(s['accepted_complete_exact'] for s in recomputed),
                    'errors': dict(Counter(e for row in selected for e in row['detection']['errors']))}
                check('full_denominator_' + split + '_' + arm, len(selected) == number)
        check('independently_recomputed_summary', same(summaries, report['summary']))
        return finish(execution_complete=True, material_count=120, row_count=360,
            observed_generations=len(calls), observed_encoder_entrypoints=len(encodings),
            runtime_token_usage=usage, recomputed_summary=summaries)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, AssertionError, StopIteration, RecursionError):
        check('artifact_structure_complete', False)
        return finish(execution_complete=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--data-root', type=Path)
    parser.add_argument('--output', type=Path,
        help='New verification receipt; defaults to RUN/independent_verification_v2.json. Never overwrites.')
    args = parser.parse_args()
    result = verify(args.run, data_root=args.data_root)
    result['verifier_sha256'] = sha(Path(__file__).read_bytes())
    output = args.output or args.run / 'independent_verification_v2.json'
    try:
        with output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
    except OSError:
        print(json.dumps({'status': 'receipt_not_written', 'error': 'output_exists_or_unwritable'}, ensure_ascii=False))
        raise SystemExit(2)
    failed = [item['check'] for item in result['checks'] if not item['passed']]
    print(json.dumps({'status': result['status'], 'report_file': str(output.resolve()),
        'check_count': len(result['checks']), 'failed_check_count': len(failed),
        'failed_checks_first_12': failed[:12], 'verification_model_calls': result['verification_model_calls'],
        'privacy_or_recall_acceptance': result['privacy_or_recall_acceptance']}, ensure_ascii=False))
    raise SystemExit(0 if result['status'] == 'passed' else 1)
