"""Pure callback coordinator: eight source and ten target calls per story.

This file has no model, account, question, reference or credential access. A
source callback returns bound capture evidence; a target callback owns the
single independent target request. Any failure ends this story without replay.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import secrets

from .host import Capture, Host, HostError, save
from .lineage import Lineage, canonical, sha

METHODS = ('B0', 'B1', 'B2', 'B3')
VIEWS = ('unchanged', 'revoke_critical', 'revoke_irrelevant')


def _need(condition, code):
    if not condition:
        raise HostError(code)


def run_story(plan, out, source_callback, target_callback, *,
              evidence_profile='official_sdk', instrument_only=False):
    """Return a durable success/failure summary; never resume an existing out.

    Callback contexts contain a safe job_id, role, case_id and adapter_dir.
    Source contexts additionally contain artifact, input_ids, branch_ids,
    method/view (None for shared initial captures), and the first input_path.
    Target contexts contain branch_id, method and view. Target callbacks must
    return a JSON object with status='ok'; other results stop the story.
    """
    _need(isinstance(plan, dict)
          and set(plan) == {'case_id', 'sources', 'critical_sid', 'irrelevant_sid'},
          'story_plan_fields_invalid')
    lineage = Lineage(plan['sources'])
    _need(plan['critical_sid'] in lineage.source_ids
          and plan['irrelevant_sid'] in lineage.source_ids
          and plan['critical_sid'] != plan['irrelevant_sid'], 'story_revocation_sources_invalid')
    _need(callable(source_callback) and callable(target_callback), 'story_callbacks_required')
    root = Path(out).absolute()
    _need(root.resolve() == root and not root.exists(), 'fresh_story_output_no_resume')
    root.mkdir(parents=True, exist_ok=False)
    save(root / 'plan.json', plan)
    token = sha(canonical(plan))[:16]
    summary = {'schema': 'controlled-rebuild-story-result-v1',
               'case_id': plan['case_id'], 'plan_hash': sha(canonical(plan)),
               'evidence_profile': evidence_profile, 'instrument_only': instrument_only,
               'status': 'running', 'source_callback_invocations': 0,
               'target_callback_invocations': 0, 'source_calls': [],
               'branches': {m + '/' + v: {'method': m, 'view': v, 'status': 'planned',
                            'target_callback_invocations': 0}
                            for v in VIEWS for m in METHODS}, 'failure': None}
    summary['source_calls'] = [
        {'artifact': 'M', 'view': None, 'branch_ids': ['B0/' + v for v in VIEWS], 'status': 'planned'},
        *({'artifact': 'C_' + sid, 'view': None,
           'branch_ids': ['B3/' + v for v in VIEWS], 'status': 'planned'}
          for sid in lineage.source_ids),
        *({'artifact': 'R', 'view': v, 'branch_ids': ['B2/' + v], 'status': 'planned'}
          for v in VIEWS)]
    save(root / 'planned.json', summary)
    hosts = {}
    active = {'phase': 'initialization'}

    def context(role, name, **extra):
        return {'case_id': plan['case_id'], 'role': role,
                'job_id': token + '-' + role + '-' + name,
                'adapter_dir': str(root / 'adapter' / role / name), **extra}

    def generate(artifact, ids, branch_ids, *, view=None):
        nonlocal active
        active = {'phase': 'source', 'artifact': artifact, 'branch_ids': list(branch_ids)}
        trace_id = 'gen-' + secrets.token_hex(16)
        payloads = [hosts[b].begin_generation(artifact, ids, trace_id=trace_id)
                    for b in branch_ids]
        _need(all(canonical(p) == canonical(payloads[0]) for p in payloads),
              'shared_source_registration_payload_changed')
        name = artifact if view is None else artifact + '-' + view
        ctx = context('source', name, artifact=artifact, input_ids=list(ids),
                      branch_ids=list(branch_ids),
                      method=hosts[branch_ids[0]].method, view=view,
                      input_path=str(hosts[branch_ids[0]].out / 'generation' / artifact / 'input.json'))
        record = next(r for r in summary['source_calls']
                      if r['artifact'] == artifact and r['view'] == view)
        record.update(input_hash=payloads[0]['input_hash'], status='callback_started')
        summary['source_callback_invocations'] += 1
        result = source_callback(deepcopy(payloads[0]), deepcopy(ctx))
        if isinstance(result, Capture):
            capture = result
        else:
            _need(isinstance(result, dict)
                  and {'output', 'observed_input', 'receipt'} <= set(result),
                  'source_callback_capture_required')
            capture = Capture(result['output'], result['observed_input'], result['receipt'])
        for branch_id in branch_ids:
            hosts[branch_id].seal_generation(capture)
        record.update(status='sealed', output_hash=sha(capture.output))

    try:
        for view in VIEWS:
            for method in METHODS:
                branch_id = method + '/' + view
                hosts[branch_id] = Host(plan['sources'], case_id=plan['case_id'],
                    method=method, view=view, out=root / 'branches' / method / view,
                    evidence_profile=evidence_profile, instrument_only=instrument_only)
        generate('M', list(lineage.source_ids), ['B0/' + v for v in VIEWS])
        for sid in lineage.source_ids:
            generate('C_' + sid, [sid], ['B3/' + v for v in VIEWS])

        for view in VIEWS:
            revoked_sid = (None if view == 'unchanged' else plan['critical_sid']
                           if view == 'revoke_critical' else plan['irrelevant_sid'])
            for method in METHODS:
                branch_id = method + '/' + view
                branch = summary['branches'][branch_id]
                active = {'phase': 'branch', 'branch_id': branch_id}
                host = hosts[branch_id]
                branch['old_artifact_checks'] = host.apply_view(revoked_sid)
                if method == 'B2':
                    generate('R', host.legal_sources(), [branch_id], view=view)
                    active = {'phase': 'branch', 'branch_id': branch_id}
                envelope = host.prepare_delivery()
                if envelope['status'] == 'blocked':
                    branch.update(status='blocked_no_target', reason=envelope['reason'])
                    save(host.out / 'branch_result.json', branch)
                    continue
                ctx = context('target', method + '-' + view,
                              branch_id=branch_id, method=method, view=view)

                def target_once(bound_envelope):
                    summary['target_callback_invocations'] += 1
                    branch['target_callback_invocations'] += 1
                    result = target_callback(bound_envelope, deepcopy(ctx))
                    _need(isinstance(result, dict) and result.get('status') == 'ok',
                          'target_callback_unsuccessful_receipt')
                    return result

                receipt = host.commit_delivery(envelope, target_once)
                branch.update(status='delivered', memory_hash=envelope['memory_hash'],
                              source_ids=envelope['source_ids'], artifact_ids=envelope['artifact_ids'],
                              target_receipt_hash=sha(canonical(receipt)))
                save(host.out / 'branch_result.json', branch)
        _need(summary['source_callback_invocations'] == 8
              and summary['target_callback_invocations'] == 10,
              'completed_story_callback_count_mismatch')
        summary['status'] = 'ok'
    except BaseException as error:
        summary['status'] = 'failed'
        summary['failure'] = {**active, 'error_type': type(error).__name__}
        if isinstance(error, (HostError, ValueError)) and type(error).__module__.startswith(
                ('experiments.revocation_rebuild_controlled_20261104', 'memory_migration_study.native_agent_protocol')):
            summary['failure']['error_code'] = str(error)
        if active.get('branch_id') in summary['branches']:
            summary['branches'][active['branch_id']]['status'] = 'failed'
        if active.get('phase') == 'source':
            for branch_id in active.get('branch_ids', []):
                if summary['branches'][branch_id]['status'] == 'planned':
                    summary['branches'][branch_id]['status'] = 'failed_source'
            for record in summary['source_calls']:
                if record['artifact'] == active['artifact'] and record['status'] == 'callback_started':
                    record['status'] = 'failed_or_unknown_no_retry'
        for branch in summary['branches'].values():
            if branch['status'] == 'planned':
                branch['status'] = 'not_run'
        for record in summary['source_calls']:
            if record['status'] == 'planned':
                record['status'] = 'not_run'
    finally:
        for host in hosts.values():
            host.close()
        for branch in summary['branches'].values():
            result_path = root / 'branches' / branch['method'] / branch['view'] / 'branch_result.json'
            if not result_path.exists():
                save(result_path, branch)
        save(root / 'run_summary.json', summary)
    return deepcopy(summary)
