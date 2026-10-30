"""No-model finite qualification. Score references are never opened here."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

from memory_migration_study import privacy
from memory_migration_study.current_authority import prepare_current_transfer, restore_current_answer
from memory_migration_study.native_agent_protocol import NativeProtocolError, render_agents_md
from memory_migration_study.selective_memory_isolation import (
    bind_dependency_groups, prepare_selective_private_payload,
)
from .controlled_host import ControlledHost, DeclaredReplay, POLICY_VERSION, MODEL_RECIPIENT
from .policy_semantics_reference import evaluate
from .reference_contract import policy_for, requests_for
from .verify_memory_flow import (verify_exact_record, verify_handoff,
    verify_annotation_projection, verify_joint_readers, verify_pseudonymized_view)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
METHODS = ('current_default', 'whole_block', 'per_fragment', 'existing_selective')


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+'\n', encoding='utf-8')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def request(case, fact, op='handoff'):
    return {'user_id': 'alice', 'agent_id': 'harness', 'operation': op,
        'resource_id': fact['fact_id'],
        'source_id': fact.get('declared_origin_source_id', case['source']['source_id']),
        'audience': 'harness', 'model_recipient': MODEL_RECIPIENT,
        'policy_version': POLICY_VERSION, 'now': 100}


def context_request(case, fact):
    q = request(case, fact)
    # Preserve omitted fields in the declared scenario; no permissive defaults.
    context = case.get('request_context')
    if context is not None:
        for key in ('user_id', 'agent_id', 'operation', 'audience', 'model_recipient', 'policy_version'):
            if key not in context:
                q.pop(key, None)
            else:
                q[key] = context[key]
    return q


def freeze(out):
    if out.exists():
        raise ValueError('output_must_be_new')
    out.mkdir(parents=True)
    files = sorted(HERE.glob('*.py')) + sorted((HERE/'data').glob('*.json')) + [HERE/'smoke_plan.json']
    files += [ROOT/'memory_migration_study'/name for name in (
        'current_authority.py', 'memory_labels.py', 'native_agent_protocol.py', 'privacy.py',
        'selective_memory_isolation.py', 'source_annotation.py')]
    plan = {'schema': 'journal_frozen_execution_v1', 'date': '2026-10-30',
        'git_base': '3e3c9641e6e96b4b4480c80a6b57abd1df6924a0',
        'working_files_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'methods': list(METHODS), 'new_model_calls_limit': 0, 'new_client_calls_limit': 0,
        'detector_mode': 'declared synthetic control receipts, no detector effectiveness estimate',
        'scoring_reference_values_opened': False, 'human_review': None,
        'matrix_scope': 'all registered user-Agent-operation combinations plus named single boundary mutations',
        'strict_native_acl': 'unsupported as in existing static adapter',
        'indirect_metrics': None, 'ABAC': 'not_enabled_no_conversion_need', 'SMT': 'not_needed_finite_domain',
        'frozen_at_utc': datetime.now(timezone.utc).isoformat()}
    write(out/'plan.json', plan)
    return plan


def check_frozen(plan):
    if any(sha(ROOT/p) != h for p, h in plan['working_files_sha256'].items()):
        raise ValueError('frozen_input_or_code_changed')


def prepare_method(host, method, selected, question, rid):
    # Every strategy gets the same candidates, grants, receipt contents and
    # independently declared source partition. No score labels are consulted.
    payload = {'query': question, 'memories': [
        {'source_id': host.records[f]['record_id'], 'text': host.rows[f]['text']} for f in selected]}
    if not selected:
        return {'status': 'blocked', 'error': 'no_authorized_candidates', 'payload': None, 'mapping': None}, []
    replay = DeclaredReplay(host)
    independent = host.case.get('trusted_independent_facts') is True
    if method in {'current_default', 'whole_block', 'existing_selective'}:
        groups = bind_dependency_groups(payload, host.policy, [[sid] for sid in privacy._sources(payload)]) if independent else None
        prepared = prepare_selective_private_payload(payload, host.policy, replay,
            actor_id='alice', request_id=rid, authorizer=host.authorize_map,
            strategy='record' if method == 'existing_selective' else 'request', dependency_groups=groups,
            max_local_calls=16)
        kept_ids = set(prepared['mapping']._memories) if prepared.get('mapping') is not None else set()
        return prepared, [f for f in selected if host.records[f]['record_id'] in kept_ids]
    # Ordinary independent-fragment baseline: isolate unresolved original
    # records and reprepare one combined request. Requires the same trusted
    # independence declaration as the existing selective implementation.
    if not independent and any(host.rows[f].get('detection_status') != 'ok' for f in selected):
        return {'status': 'blocked', 'error': 'dependency_not_independent', 'payload': None, 'mapping': None}, []
    retained = [f for f in selected if host.rows[f].get('detection_status') == 'ok']
    if not retained:
        return {'status': 'blocked', 'error': 'all_fragments_unresolved', 'payload': None, 'mapping': None}, []
    filtered = {'query': question, 'memories': [m for m in payload['memories']
        if m['source_id'] in {host.records[f]['record_id'] for f in retained}]}
    detected = privacy.detect_sensitive(filtered, host.policy, agent=replay, mode='combined')
    prepared = privacy.prepare_private_payload(filtered, detected, actor_id='alice', request_id=rid,
        policy_version=POLICY_VERSION, authorizer=host.authorize_map, sensitivity_policy=host.policy)
    return prepared, retained if prepared['status'] == 'ok' else []


def restoration_probe(host, fid, probe_id):
    """Probe existing current endpoint separately from added restore policy gate."""
    record = host.records[fid]
    prepared = prepare_current_transfer([record], 'Return the recorded value.', host.policy,
        authority=host.authority, actor_id='alice', agent_id='harness', request_id=probe_id,
        mode='generation', agent=lambda **_: {'status': 'ok', 'findings': [], 'local_calls': 0,
                                             'elapsed_seconds': 0.0})
    if prepared['status'] != 'ok':
        return {'fact_id': fid, 'status': 'not_prepared', 'error': prepared.get('error')}
    text = prepared['payload']['memories'][0]['text']
    token = privacy._TOKEN.search(text)
    answer = token.group() if token else record['text'].rstrip('。.!！')
    raw = restore_current_answer(answer, prepared, [record], host.policy,
        authority=host.authority, actor_id='alice', agent_id='harness', request_id=probe_id)
    guarded = host.restore(answer, prepared, [fid], probe_id)
    # Raw restored originals are synthetic and locally evidenced, never maps.
    result = {'fact_id': fid, 'input_answer': answer, 'raw_current_endpoint': raw,
        'explicit_restore_allowed': host.rows[fid].get('restore_allowed'), 'opt_in_gate': guarded,
        'scope': 'deterministic protocol control, not a model-generated answer'}
    return result


def run(out):
    plan = freeze(out)
    started = time.perf_counter()
    matrices, flows, baselines, restore_rows, cases_seen = [], [], [], [], []
    # Reading case texts/policies is expected. Neither score reference file is
    # opened by this runner, including when preparing check stories.
    with tempfile.TemporaryDirectory(prefix='journal-qualification-') as temp:
        for split in ('dev', 'check'):
            cases = json.loads((HERE/'data'/f'{split}_cases.json').read_text(encoding='utf-8'))['cases']
            for case in cases:
                cases_seen.append({'case_id': case['case_id'], 'split': split, 'scenario': case['scenario']})
                host = ControlledHost(case, Path(temp)/case['case_id'])
                selected = []
                for fact in case['facts']:
                    fid, record = fact['fact_id'], host.records[fact['fact_id']]
                    policy = policy_for(case, fact)
                    write(out/'policies'/f'{fid}.json', policy)
                    for q in requests_for(case, fact):
                        reference = evaluate(policy, q, {'source_binding': True})
                        observed = host.execute(q)
                        matrices.append({'case_id': case['case_id'], 'split': split,
                            'fact_id': fid, 'request': q, 'reference': reference,
                            'observed': observed,
                            'entry': 'existing-read-or-broker plus explicit bounded request/restore gate'})
                    q = context_request(case, fact)
                    observed = host.execute(q)
                    matrices.append({'case_id': case['case_id'], 'split': split, 'fact_id': fid,
                        'request': q, 'reference': evaluate(policy, q, {'source_binding': True}),
                        'observed': observed, 'entry': 'declared_scenario_context'})
                    if observed['decision'] == 'allow':
                        selected.append(fid)
                    declared_source = dict(case['source'], source_id=fact.get(
                        'declared_origin_source_id', case['source']['source_id']))
                    exact = verify_exact_record(record, expected_source=declared_source,
                        expected_policy_version=POLICY_VERSION, expected_principals=fact['allowed_principals'],
                        expected_origin={'source_id': declared_source['source_id'],
                            'source_start': fact['start'], 'source_end': fact['end']})
                    source_findings = [dict(s, start=s['start']+fact['start'], end=s['end']+fact['start'])
                                       for s in fact['privacy_spans']]
                    annotation = verify_annotation_projection(source_findings, record)
                    flows += [{'case_id': case['case_id'], 'fact_id': fid, 'kind': 'exact', 'result': exact},
                              {'case_id': case['case_id'], 'fact_id': fid, 'kind': 'annotation', 'result': annotation}]
                    if host.read(fid)['decision'] == 'allow':
                        restore_rows.append(restoration_probe(host, fid, 'restore-probe-' + fid))
                for method in METHODS:
                    rid = method + '-' + case['case_id']
                    prepared, kept = prepare_method(host, method, selected, 'Return one recorded fact.', rid)
                    original = {'query': 'Return one recorded fact.', 'memories': [
                        {'source_id': host.records[f]['record_id'], 'text': host.rows[f]['text']} for f in kept]}
                    view_check = None
                    if prepared['status'] == 'ok':
                        view_check = verify_pseudonymized_view(original, prepared, recipient=MODEL_RECIPIENT,
                            disclosure_policy={'policy_version': POLICY_VERSION,
                                'allowed_transformations': ['fixed_pseudonymization'],
                                'allowed_recipients': [MODEL_RECIPIENT],
                                'allowed_source_ids': [m['source_id'] for m in original['memories']]})
                    packet_check, rendered_check, strict_error, lifecycle = None, None, None, None
                    if kept:
                        packet = host.export(kept, 'loaded-' + rid)
                        host.broker.validate(packet, sender_actor_id='sender', actor_id='receiver')
                        packet_check = verify_handoff(packet, [host.records[f] for f in kept],
                            expected_audience={'user_id':'alice','agent_id':'harness','workspace_id':'target'},
                            expected_policy_version=POLICY_VERSION)
                        # Do not hand a raw packet renderer a pseudonymized text
                        # masquerading as signed original. Protected load bytes
                        # are a separate explicit host view in this experiment.
                        raw_md = render_agents_md(packet)
                        raw_data = json.loads(raw_md.split('```json\n')[1].split('\n```')[0])
                        rendered_check = {'status': 'ok' if [x['text'] for x in raw_data['facts']] ==
                                          [host.rows[f]['text'] for f in kept] else 'failed',
                            'scope': 'existing deterministic raw renderer parsed locally, client not launched',
                            'raw_render_sha256': hashlib.sha256(raw_md.encode()).hexdigest(),
                            'protected_payload_sha256': hashlib.sha256(json.dumps(prepared['payload'],
                                sort_keys=True, ensure_ascii=False).encode()).hexdigest()}
                        try:
                            host.broker.export([host.records[f]['record_id'] for f in kept],
                                sender_actor_id='sender', recipient_actor_id='receiver',
                                transfer_id='strict-'+rid, mode='strict',
                                capabilities=['before_import','fresh_session','source_integrity','native_read_acl','live_revocation'])
                        except NativeProtocolError as exc:
                            strict_error = exc.code
                    # Per-task context/protection availability only. No QA model
                    # is replaced by an oracle keyed on fact_id.
                    availability = [{'task_id': t['task_id'], 'kind': t['kind'],
                        'fact_present': t.get('fact_id') in kept,
                        'answer': None, 'model_outcome': 'not_executed'} for t in case['tasks']]
                    protected_leaks = []
                    if prepared.get('payload'):
                        serialized = json.dumps(prepared['payload'], ensure_ascii=False)
                        for fid in kept:
                            for span in host.rows[fid]['privacy_spans']:
                                raw = host.rows[fid]['text'][span['start']:span['end']]
                                if raw in serialized:
                                    protected_leaks.append({'fact_id': fid, 'start': span['start'], 'end': span['end']})
                    baselines.append({'case_id': case['case_id'], 'split': split, 'method': method,
                        'selected_facts': selected, 'kept_facts': kept, 'status': prepared['status'],
                        'error': prepared.get('error'), 'payload': prepared.get('payload'),
                        'view_check': view_check, 'packet_check': packet_check, 'rendered_check': rendered_check,
                        'strict_mode_error': strict_error, 'registered_raw_leaks': protected_leaks,
                        'task_availability': availability, 'model_task_metrics': None,
                        'availability_phase': 'pre_revocation_context_availability_only',
                        'control_receipts': 'same trusted synthetic detections and source partition',
                        'lifecycle': lifecycle})
                # Revocation qualification is a fresh deterministic one-record
                # probe after other paired conditions, never a reused stale map.
                lifecycle_spec = case.get('lifecycle', {})
                if isinstance(lifecycle_spec, dict) and lifecycle_spec.get('event') == 'revoke_before_restore' and selected:
                    fid = lifecycle_spec['fact_id']
                    if fid not in selected:
                        raise ValueError('declared_lifecycle_fact_not_prepared')
                    record = host.records[fid]
                    rid = 'lifecycle-' + case['case_id']
                    p = prepare_current_transfer([record], 'Return one fact.', host.policy,
                        authority=host.authority, actor_id='alice', agent_id='harness', request_id=rid,
                        mode='generation', agent=lambda **_: {'status':'ok','findings':[],
                            'local_calls':0,'elapsed_seconds':0.0})
                    packet = host.export([fid], rid)
                    host.revoke(fid)
                    protected_text = p['payload']['memories'][0]['text']
                    token = privacy._TOKEN.search(protected_text)
                    controlled_answer = token.group() if token else record['text'].rstrip('。.!！')
                    restored = restore_current_answer(controlled_answer, p, [record], host.policy,
                        authority=host.authority, actor_id='alice', agent_id='harness', request_id=rid)
                    try:
                        host.broker.validate(packet, sender_actor_id='sender', actor_id='receiver')
                        replay = {'status':'unexpected_allow'}
                    except NativeProtocolError as exc:
                        replay = {'status':'blocked','error':exc.code}
                    flows.append({'case_id':case['case_id'],'kind':'lifecycle','result':{
                        'status':'ok' if restored['status']=='blocked' and replay['status']=='blocked' else 'failed',
                        'restore':restored,'old_packet':replay}})
                flows.append({'case_id':case['case_id'],'kind':'joint_readers','result':
                    verify_joint_readers([[{'user_id':'alice','agent_id':'harness'}],
                        [{'user_id':'alice','agent_id':'qoder'}]], [])})
    check_frozen(plan)
    for name, rows in [('requests', matrices), ('flows', flows), ('baselines', baselines), ('restoration', restore_rows)]:
        write(out/(name+'.json'), rows)
    closure = {'status':'deterministic_predictions_closed', 'closed_at_utc':datetime.now(timezone.utc).isoformat(),
        'plan_sha256':sha(out/'plan.json'), 'output_sha256': {name+'.json':sha(out/(name+'.json'))
            for name in ('requests','flows','baselines','restoration')}, 'cases':cases_seen,
        'scoring_reference_values_opened':False, 'new_model_calls':0, 'new_client_calls':0,
        'automatic_retries':0, 'elapsed_seconds':round(time.perf_counter()-started,6)}
    write(out/'prediction_closure.json', closure)
    print(json.dumps({'status':closure['status'], 'requests':len(matrices), 'flow_checks':len(flows),
                      'baseline_conditions':len(baselines), 'new_model_calls':0}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    # Any accidental networking in imported production paths is an execution
    # error. No client subprocess API exists in this runner.
    with patch('socket.socket', side_effect=AssertionError('network_forbidden')), \
         patch('socket.create_connection', side_effect=AssertionError('network_forbidden')):
        run(args.out.resolve())


if __name__ == '__main__':
    main()
