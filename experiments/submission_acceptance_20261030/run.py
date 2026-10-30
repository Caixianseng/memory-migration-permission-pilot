"""One-case joint evidence, frozen prediction phase, then separate scoring."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from itertools import product
from unittest.mock import patch

from .pipeline import (JointHost, JointTransaction, METHODS, canonical, digest, request,
                       normalized_view, deterministic_consumer)
from .reference import judge
from experiments.journal_methods_20261030.client_smoke import invoke, PROMPT, install_metadata, wallet
from experiments.journal_methods_20261030.account_budget_probe import probe
from memory_migration_study.deepseek_native import run_deepseek_question

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    with path.open('xb') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False).encode('utf-8') + b'\n')


def matrix_for(host):
    rows = []
    for fid, fact in host.rows.items():
        variants = []
        for user, agent, op in product(('alice', 'bob'), ('qoder', 'harness', 'rogue'), ('read', 'handoff', 'restore')):
            variants.append(('principal_operation', dict(request(host.case, fact, op), user_id=user, agent_id=agent)))
        base = request(host.case, fact)
        for key, value in (('source_id', 'wrong-source'), ('policy_version', 'stale'), ('audience', 'wrong'),
                           ('model_recipient', 'wrong'), ('now', 200), ('now', '100')):
            variants.append(('mutation:' + key, dict(base, **{key: value})))
        for key in base:
            query = dict(base); del query[key]
            variants.append(('missing:' + key, query))
        for name, query in variants:
            state = {'revoked': False, 'authority_unknown': False}
            rows.append(dict(case_id=host.case['case_id'], split=host.case['split'], fact_id=fid,
                        variant=name, request=query, state=state,
                        reference=judge(host.case, fact, query, state), observed=host.execute(query)))
    # Actual current unknown and revocation, independent reference state.
    fid = next(iter(host.rows)); fact = host.rows[fid]; query = request(host.case, fact)
    host.unknown = True
    state = {'revoked': False, 'authority_unknown': True}
    rows.append(dict(case_id=host.case['case_id'], split=host.case['split'], fact_id=fid,
                variant='current_authority_unknown', request=query, state=state,
                reference=judge(host.case, fact, query, state), observed=host.execute(query)))
    host.unknown = False
    # Revocation runs on a separate host in the runner, never contaminates task tests.
    return rows


def run(out, *, client='deterministic', execute=False):
    out = Path(out).resolve()
    if out.exists():
        raise ValueError('output_must_be_new')
    out.mkdir(parents=True)
    raw = json.loads((HERE/'data/cases.json').read_text(encoding='utf-8'))
    cases = raw['cases']
    if client == 'harness':
        # Fixed two-story feasibility slice, not the six-story offline effect set.
        cases = [c for c in cases if c['case_id'] in ('joint-check-01', 'joint-check-02')]
        if not execute:
            raise ValueError('native_execution_requires_explicit_execute_flag')
    files = list(HERE.glob('*.py')) + [HERE/'data/cases.json', HERE/'data/manifest.json', HERE/'CONTRACT.md']
    native_guard = None
    native_template = None
    if client == 'harness':
        origin_guard = ROOT/'results/native_agent_probe_20261026/dsh_single_request_guard.mjs'
        guard_text = origin_guard.read_text(encoding='utf-8')
        old = "if (bytes > 65536) block('request_too_large', options);"
        if guard_text.count(old) != 1:
            raise ValueError('original_guard_version_changed')
        native_guard = origin_guard.parent/'submission_request_guard_7500.mjs'
        tightened = guard_text.replace(old, "if (bytes > 7500) block('request_too_large', options);")
        if native_guard.exists() and native_guard.read_text(encoding='utf-8') != tightened:
            raise ValueError('existing_tight_guard_changed')
        if not native_guard.exists():
            native_guard.write_text(tightened, encoding='utf-8')
        rows = json.loads((origin_guard.parent/'sdk_guard_metadata.patch.yml').read_text(encoding='utf-8'))
        inserts = [row['insert'][0] for row in rows if 'insert' in row]
        if len(inserts) != 1:
            raise ValueError('original_patch_insert_count_changed')
        inserts[0]['name'] = native_guard.as_uri()
        native_template = out/'sdk_tight_guard.patch.json'
        save(native_template, rows)
        # Exercise the wrapper's actual config parser before accounts/prompts.
        from memory_migration_study.deepseek_native import _patch
        _patch(native_template, native_guard, out/'preflight_runtime', out/'preflight_guard.json')
        save(out/'native_patch_preflight.json', {'status': 'passed', 'model_calls': 0,
             'guard_sha256': sha(native_guard), 'template_sha256': sha(native_template)})
        files += [native_guard, native_template]
    files += list((ROOT/'memory_migration_study').glob('*.py'))
    files += list((ROOT/'experiments/journal_methods_20261030').glob('*.py'))
    hashes = {p.relative_to(ROOT).as_posix(): sha(p) for p in files}
    plan = {'schema': 'submission_joint_acceptance_v1', 'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'git_base': subprocess.check_output(['git', '-c', 'safe.directory=' + ROOT.as_posix(), 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'implementation_sha256': hashes, 'cases_sha256': sha(HERE/'data/cases.json'),
        'python_version': sys.version, 'runtime_dependencies': 'standard library for offline recomputation; native clients separately hashed',
        'references_sha256': sha(HERE/'data/references.json'), 'reference_values_opened': False,
        'methods': list(METHODS), 'client': client, 'case_ids': [c['case_id'] for c in cases],
        'scope': 'exact-field synthetic EMAIL controls; real rules, no local LLM; trusted host, static-client content interoperability',
        'native_budget': {'attempts_max': 8, 'automatic_retries': 0, 'output_tokens_max': 64,
                          'new_money_limit_cny': 0.5, 'top_up': False,
                          'guarded_full_request_bytes': 7500,
                          'estimated_reserve_each_cny': 0.060512,
                          'estimate_assumptions': '2 input tokens/serialized byte, input 4 CNY/M (2x official peak), output 8 CNY/M; not supplier atomic cap',
                          'pricing_verified_url': 'https://api-docs.deepseek.com/zh-cn/quick_start/pricing/',
                          'pricing_verified_date': '2026-10-30'},
        'native_identical_method_inputs': 'share one actual call only after normalized complete payload and prompt equality',
        'human_review': None, 'novel_algorithm_claim': False}
    save(out/'plan.json', plan)
    rows, matrices, challenges = [], [], []
    attempts = 0; stopped = None; before = None
    if client == 'harness':
        before = probe(); save(out/'account_before.json', before)
        if wallet(before) < 1 or before.get('harness', {}).get('status') != 'ready':
            raise ValueError('native_budget_not_ready')
        save(out/'installed.json', install_metadata())
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='submission-host-') as temporary:
        for case in cases:
            host = JointHost(case, Path(temporary)/case['case_id'])
            matrices.extend(matrix_for(host))
            revoked_host = JointHost(case, Path(temporary)/(case['case_id'] + '-revoke'))
            fid = next(iter(revoked_host.rows)); fact = revoked_host.rows[fid]
            revoked_host.revoke(fid)
            query = request(case, fact)
            state = {'revoked': True, 'authority_unknown': False}
            matrices.append(dict(case_id=case['case_id'], split=case['split'], fact_id=fid,
                    variant='grant_revoked', request=query, state=state,
                    reference=judge(case, fact, query, state), observed=revoked_host.execute(query)))
            for task in case['tasks']:
                transactions = [JointTransaction(host, task, method) for method in METHODS]
                views = [normalized_view(tr.safe) if tr.safe is not None else None for tr in transactions]
                equivalent = (views[0] is not None and len(set(views)) == 1
                              and all(tr.retained == transactions[0].retained for tr in transactions))
                # Even equivalent methods retain separate one-use restoration states.
                shared_answer = None; shared_receipt = None; shared_slot = None; origin_text = None
                for ordinal, tr in enumerate(transactions):
                    slot = task['task_id'] + '-' + tr.method
                    workspace = out/slot; workspace.mkdir()
                    row = dict(slot_id=slot, case_id=case['case_id'], split=case['split'], task_id=task['task_id'],
                        method=tr.method, client=client, client_status='not_run', raw_answer=None,
                        final_answer=None, processing_status='blocked', processing_error=None,
                        authorized_fact_ids=tr.selected, selected_fact_ids=tr.retained,
                        detector_status=tr.detector_status, generation_findings=host.generation_findings,
                        migration_findings=tr.migration_findings,
                        target_payload=None, source_bindings_verified=tr.all_sources_bound,
                        packet_validated=tr.packet_validated, target_loaded=False,
                        restoration_rechecked=False, mapping_persisted=False,
                        equivalent_method_inputs=equivalent, shared_actual_call_with=None)
                    tick = time.monotonic()
                    try:
                        text = tr.target_text()
                        (workspace/'AGENTS.md').write_text(text, encoding='utf-8', newline='\n')
                        text_hash = sha(workspace/'AGENTS.md')
                        # Reopen the actual target file. This proves file loading only
                        # for the deterministic consumer; native events are separate.
                        loaded = json.loads((workspace/'AGENTS.md').read_text(encoding='utf-8').split('```json\n', 1)[1].split('\n```', 1)[0])
                        if len(loaded['memories']) != len(tr.retained):
                            raise ValueError('retained_target_projection_count_mismatch')
                        row['target_payload'] = {'query': loaded['query'], 'memories': [
                            {'source_id': fid, 'text': m['text']} for fid, m in zip(tr.retained, loaded['memories'])]}
                        row['target_loaded'] = client == 'deterministic'
                        row['target_file_sha256'] = text_hash
                        prompt = PROMPT.format(question=loaded['query'])
                        if client == 'deterministic':
                            answer = deterministic_consumer(loaded, task['field_label'])
                            receipt = {'status': 'ok', 'answer': answer, 'scope': 'exact-field software consumer, not model effect'}
                        elif equivalent and shared_receipt is not None:
                            # Translate request-specific tokens only after exact input
                            # equivalence; this row is a linked replay, never a new call.
                            a_tokens = list(dict.fromkeys(__import__('re').findall(r'\[PVT_[^\]]+\]', shared_answer or '')))
                            origin_tokens = list(dict.fromkeys(__import__('re').findall(r'\[PVT_[^\]]+\]', origin_text)))
                            own_tokens = list(dict.fromkeys(__import__('re').findall(r'\[PVT_[^\]]+\]', text)))
                            answer = shared_answer
                            for old in a_tokens:
                                if old not in origin_tokens:
                                    raise ValueError('unknown_token_in_shared_answer')
                                answer = answer.replace(old, own_tokens[origin_tokens.index(old)])
                            receipt = dict(shared_receipt, answer=answer)
                            row['shared_actual_call_with'] = shared_slot
                            row['target_loaded'] = False
                        else:
                            if stopped or attempts >= 8:
                                raise ValueError(stopped or 'attempt_budget_exhausted')
                            # Disclosed conservative estimate, including hidden-input
                            # allowance; account delta is observed, not atomic billing.
                            byte_count = len(text.encode('utf-8')) + len(prompt.encode('utf-8'))
                            reserve = 0.060512
                            if (byte_count > 1800 or (attempts + 1) * reserve > 0.5):
                                raise ValueError('input_or_estimated_cost_budget_exceeded')
                            if any(sha(ROOT/p) != h for p, h in hashes.items()):
                                raise ValueError('frozen_code_changed')
                            save(out/(slot + '_reservation.json'), {'attempt': attempts+1, 'estimated_reserve_cny': reserve,
                                'input_bytes': byte_count, 'supplier_atomic_cap': False})
                            subprocess.run(['git', 'init', '-q', str(workspace)], capture_output=True, check=True, timeout=15)
                            attempts += 1
                            (out/'runtime').mkdir(exist_ok=True)
                            receipt = run_deepseek_question(workspace, prompt, runtime_home=out/'runtime'/slot,
                                patch_template=native_template,
                                guard_path=native_guard)
                            save(out/(slot + '_receipt.json'), receipt)
                            answer = receipt.get('answer')
                            shared_answer, shared_receipt, shared_slot = answer, receipt, slot
                            origin_text = text
                            row['target_loaded'] = receipt.get('native_instruction_loaded') is True
                            if receipt.get('status') != 'ok':
                                stopped = 'client_failure_no_retry'
                        row['client_status'] = receipt.get('status', 'error')
                        row['raw_answer'] = receipt.get('raw_response') or answer
                        row['answer_for_restoration'] = answer
                        row['target_load_evidence'] = ('linked_identical_input_call' if row['shared_actual_call_with'] else
                            'native_instruction_event' if row['target_loaded'] and client == 'harness' else
                            'software_file_reopen' if row['target_loaded'] else 'unverified')
                        if row['client_status'] != 'ok':
                            raise ValueError(receipt.get('error') or 'client_error')
                        if sha(workspace/'AGENTS.md') != text_hash:
                            raise ValueError('target_file_changed')
                        restored = tr.restore(answer)
                        row['restoration_rechecked'] = True
                        row['processing_status'] = restored['status']
                        row['processing_error'] = restored.get('error')
                        row['final_answer'] = restored.get('answer')
                        row['restoration'] = restored
                    except Exception as exc:
                        row['processing_error'] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
                        row['processing_status'] = 'needs_review' if tr.detector_status != 'ok' else 'error'
                    row['elapsed_seconds'] = round(time.monotonic() - tick, 6)
                    rows.append(row)
                    save(out/(slot + '_result.json'), row)
                    print(json.dumps({'slot': slot, 'client_status': row['client_status'], 'processing': row['processing_status'],
                                      'error': row['processing_error']}, ensure_ascii=False), flush=True)
        from memory_migration_study import privacy
        for challenge in raw.get('auxiliary_challenges', []):
            result = privacy.detect_sensitive(challenge['payload'], challenge['sensitivity_policy'], mode='rules')
            challenges.append({'id': challenge['challenge_id'], 'result': result,
                               'scope': 'separate engineering challenge, excluded from task effect'})
    save(out/'predictions.json', {'rows': rows})
    save(out/'authorization_matrix.json', {'rows': matrices})
    save(out/'challenges.json', challenges)
    if client == 'harness':
        after = probe(); save(out/'account_after.json', after)
        spent = max(wallet(before) - wallet(after), 0)
        save(out/'accounting.json', {'client_attempts': attempts, 'observed_wallet_delta_cny': str(spent),
            'limit_cny': 0.5, 'supplier_atomic_cap': False, 'supplier_bill_verified': False,
            'no_top_up': True, 'stopped_reason': stopped})
    save(out/'prediction_phase_closed.json', {'all_slots_closed': len(rows) == len(cases)*4*len(METHODS),
        'predictions_sha256': sha(out/'predictions.json'), 'authorization_sha256': sha(out/'authorization_matrix.json'),
        'cases_sha256': plan['cases_sha256'], 'references_sha256': plan['references_sha256'],
        'reference_values_opened': False, 'restoration_maps_persisted': False,
        'client_attempts': attempts, 'elapsed_seconds': round(time.monotonic()-started, 6)})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--client', choices=('deterministic', 'harness'), default='deterministic')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.client == 'deterministic':
        with patch('socket.create_connection', side_effect=RuntimeError('network_disabled')):
            run(args.out, client=args.client, execute=args.execute)
    else:
        run(args.out, client=args.client, execute=args.execute)


if __name__ == '__main__':
    main()
