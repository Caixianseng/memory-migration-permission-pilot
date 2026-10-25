"""Complete local A->B development comparison of policy-aware semantic repair.

One authentic construction per story, five conditions, shared joint semantic
receipts, original authorization/restoration, and scoring after model closure.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
import random
import secrets
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_migration_study.answer_serialization import canonicalize_answer
from memory_migration_study.detection_cache import DetectionCache, detector_revision
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.memory_generation_experiment import LocalFactAnswerer, score_masking
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import _digest
from memory_migration_study.reuse_benchmark import save
from memory_migration_study.semantic_memory_benchmark import RecordingAnswerer, aggregate, score
from memory_migration_study.union_detector import IndependentUnionDetector
from scripts.run_reference_memory_study import TypedCountingDetector, StageTransport, file_sha

VERSION = 'policy_semantic_transfer_development_v2'
ARMS = {name: ('reference', 'migration', False) for name in ('baseline', 'union', 'roles', 'completion', 'joint')}
SEED = 2026102509
GENERATION_CAP = 464


class SemanticTransport(StageTransport):
    def __init__(self, output, original):
        # A new fixed protocol includes a cache-disabled worst-case union arm.
        # Reuse body/usage validation and observation, not the old experiment cap.
        self.output, self.original = Path(output), original
        self.maximum = GENERATION_CAP
        self.attempts = self.results = self.errors = self.token_budget_violations = 0
        self.context = {'stage': 'initialization', 'arm': None, 'story_id': None, 'task_id': None}
        self.model_phase_closed = False
        self.closed_phase_attempts = 0

    def call(self, client, method, path, body=None):
        if method == 'POST' and self.model_phase_closed:
            self.closed_phase_attempts += 1
            raise RuntimeError('model_phase_closed')
        return super().call(client, method, path, body)


def event(journal, kind, **fields):
    item = {'sequence': len(journal)+1, 'kind': kind, **fields}
    journal.append(item)
    return item


class AuditedAuthority(MemoryLabelAuthority):
    def __init__(self, key, journal):
        super().__init__(key)
        self.journal, self.operation = journal, None

    def validate_access(self, record, **kwargs):
        result = super().validate_access(record, **kwargs)
        event(self.journal, 'access_check', operation=self.operation,
            record_id=record.get('record_id') if isinstance(record, dict) else None,
            actor_id=kwargs.get('actor_id'), agent_id=kwargs.get('agent_id'),
            policy_version=kwargs.get('policy_version'), error=result)
        return result


class AuditedRefiner:
    def __init__(self, refiner, observer, journal, authority):
        self.refiner, self.observer, self.journal, self.authority = refiner, observer, journal, authority

    def __call__(self, payload, policy, baseline_detection, **kwargs):
        baseline_spans = sorted(({key: item[key] for key in ('source_id', 'start', 'end', 'category')}
            for item in baseline_detection.get('findings', [])),
            key=lambda item: (item['source_id'], item['start'], item['end'], item['category']))
        start = event(self.journal, 'semantic_callback_start', operation=self.authority.operation,
            payload_sha256=_digest(payload), policy_sha256=_digest(policy),
            baseline_sha256=_digest(baseline_detection), baseline_spans=baseline_spans,
            baseline_spans_sha256=_digest(baseline_spans), mode=kwargs.get('mode'),
            actor_id=kwargs.get('actor_id'), agent_id=kwargs.get('agent_id'))
        previous = dict(self.observer.context)
        self.observer.context = {**previous, 'stage': 'semantic'}
        before = self.observer.attempts
        try:
            result = self.refiner(payload, policy, baseline_detection, **kwargs)
        finally:
            self.observer.context = previous
        event(self.journal, 'semantic_callback_end', operation=self.authority.operation,
            callback_start_sequence=start['sequence'], result_sha256=_digest(result), status=result.get('status'),
            new_generation_attempts=self.observer.attempts-before,
            semantic_local_counts=result.get('semantic_local_counts'),
            semantic_audit=result.get('policy_semantics'))
        return result


def render(output, report):
    keys = ('legal_tasks', 'correct', 'joint_correct_no_masking_gap', 'secondary_serialization_correct',
            'secondary_joint_correct_no_masking_gap', 'ready', 'true_model_unknown', 'restoration_failure',
            'ready_with_masking_gaps', 'extra_masked_characters', 'outsider_blocked')
    esc = lambda value: html.escape(str(value))
    body = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>权限迁移中的语义隐私校正</title>'
        '<style>body{font:16px/1.7 system-ui;margin:32px}table{border-collapse:collapse;display:block;overflow:auto}'
        'th,td{border:1px solid #bbc7ce;padding:8px}p{max-width:1100px}</style>'
        '<h1>完整A→B开发对照：角色判断与完整名称补全</h1>'
        '<p>既有8个已暴露合成开发故事；同一真实模型构建与签名记录，经原认证、来源、当前权限、外发和恢复检查。'
        '包括原NER、独立双检测器合并强基线、仅角色、仅补全、联合应用。三语义条件共享同一联合判断，'
        '是应用消融而非三套独立生成器。不是新盲测、原生跨后端验证或创新证明。</p>')
    body += '<table><tr><th>条件</th>'+''.join('<th>'+esc(key)+'</th>' for key in keys)+'</tr>'
    for arm, metrics in report['arms'].items():
        body += '<tr><td>'+esc(arm)+'</td>'+''.join('<td>'+esc(metrics[key])+'</td>' for key in keys)+'</tr>'
    body += ('</table><p>主成绩保留原输出，补括号仅是同一输出的次要分析。失败、待审和拒答保留在32题分母。'
        '注册字符遮蔽不等于语义隐私；较少回答或全部拒绝不算成功。共享缓存的物理费用不能当作每臂独立部署费用。</p>'
        '<p><a href="report.json">完整汇总</a> · <a href="rows.json">逐题真实输入与回答</a> · '
        '<a href="builds.json">共同构建</a> · <a href="auth_events.json">实际授权与callback序列</a> · '
        '<a href="plan.json">冻结协议</a></p></html>')
    (Path(output)/'index.html').write_text(body, encoding='utf-8')


def run(corpus, output, model_root, config, observer, *, progress=None):
    from memory_migration_study.reference_memory import ReferenceMemoryBuilder, propose_fact_pool
    from memory_migration_study.policy_semantics import LocalPolicySemanticAgent, PolicySemanticRefiner
    corpus, output = Path(corpus), Path(output)
    runtime_bytes = (corpus/'development/runtime.json').read_bytes()
    evaluation_bytes = (corpus/'development/evaluation.json').read_bytes()
    runtime = json.loads(runtime_bytes)
    if len(runtime) != 8 or sum(len(s['tasks']) for s in runtime) != 40 or sum(
            t['actor_id'] == 'owner' for s in runtime for t in s['tasks']) != 32:
        raise ValueError('registered_development_matrix_required')
    if len({s['story_id'] for s in runtime}) != 8 or any(len({t['task_id'] for t in s['tasks']}) != len(s['tasks']) for s in runtime):
        raise ValueError('duplicate_runtime_identity')
    output.mkdir(parents=True, exist_ok=False)
    package = ROOT/'memory_migration_study'
    entrypoints = [Path(__file__), ROOT/'scripts/run_reference_memory_study.py', ROOT/'scripts/run_boundary_transfer_diagnostic.py']
    source_files = list(package.glob('*.py'))+entrypoints
    hashes = {str(p.relative_to(ROOT)): file_sha(p) for p in source_files}
    archive = output/'implementation'
    for path in source_files:
        destination = archive/path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    plan = {'version': VERSION, 'score_schema_version': 2, 'split': 'development', 'arms': ARMS,
        'source_stories': 8, 'expected_rows': 200, 'legal_per_arm': 32, 'outsider_per_arm': 8,
        'runtime_sha256': hashlib.sha256(runtime_bytes).hexdigest(),
        'evaluation_sha256': hashlib.sha256(evaluation_bytes).hexdigest(),
        'implementation_sha256': hashes, 'config_sha256': _digest(config), 'ordering_seed': SEED,
        'generation_limits': {'total': GENERATION_CAP, 'build': 16, 'semantic_shared': 64,
                              'answer': 160, 'union_detection_no_cache_worst_case': 224},
        'evaluation_timing': 'after_model_phase_closed', 'query_intent': False,
        'secondary_serialization': 'same_output_exact_outer_brackets_then_original_restore',
        'semantic_scope': 'roles/completion/joint apply one shared joint receipt, keyed to current source/policy/principals/authority lifecycle',
        'scope': 'Exposed synthetic development; shared authentic A construction and local signed JSON handoff. Not independent generalization, native backend or research novelty.'}
    save(output/'plan.json', plan)
    save(output/'runtime.json', runtime)
    save(output/'config.json', config)
    ner = LocalNerRuntime(model_root)
    raw_ner = GlinerEntityAgent(ner, approved_policies=[s['policy'] for s in runtime])
    base_detector = TypedCountingDetector(raw_ner)
    local = LocalSensitivityAgent(config)
    health = local.health()
    union_detector = TypedCountingDetector(IndependentUnionDetector(raw_ner, local,
        member_kinds=('local_encoder', 'local_generation')))
    builder = ReferenceMemoryBuilder(mode='select', detector=base_detector, config=config)
    raw_refiner = PolicySemanticRefiner(LocalPolicySemanticAgent(config))
    answerer = RecordingAnswerer(LocalFactAnswerer(config))
    save(output/'runtime_identity.json', {'ner': ner.identity, 'local_generation': health,
        'detector': base_detector.cache_identity(), 'union': union_detector.cache_identity()})
    rows, builds, stores, pools, pending, journal = [], [], [], [], [], []
    for story in runtime:
        sid, source, policy = story['story_id'], story['source'], story['policy']
        authority = AuditedAuthority(secrets.token_bytes(32), journal)
        refiner = AuditedRefiner(raw_refiner, observer, journal, authority)
        union_cache = DetectionCache(max_entries=256, ttl_seconds=3600)
        pool = propose_fact_pool(source['text'], source['source_id'])
        pools.append({'story_id': sid, 'pool': pool})
        observer.stage('build', 'reference', sid)
        before, post_before = dict(base_detector.counts), observer.attempts
        built = builder(text=source['text'], source_id=source['source_id'], policy=policy, pool=pool)
        records = []
        if built['status'] == 'ok':
            records = [authority.build_record(source, fact, policy, owner_id='owner', readers=['owner'],
                agent_id='source-agent', allowed_agent_ids=['target-agent'], builder_version=built['builder_version'],
                detector_version=detector_revision(base_detector)) for fact in built['facts']]
        records = json.loads(json.dumps(records, ensure_ascii=False))
        builds.append(dict(built, story_id=sid, language=story['language'], builder='reference',
            generation_calls_observed=observer.attempts-post_before, inference_counts=base_detector.delta(before),
            stored_characters=sum(len(r['text']) for r in records),
            stored_record_json_bytes=len(json.dumps(records, ensure_ascii=False).encode('utf-8')),
            stored_source_copy_characters=sum(len(r['source']['text']) for r in records), source_characters=len(source['text'])))
        stores.append({'story_id': sid, 'builder': 'reference', 'records': records})
        for name, value in (('builds.json', builds), ('record_store.json', stores), ('pools.json', pools)):
            save(output/name, value)
        for task in story['tasks']:
            order = list(ARMS)
            random.Random(f"{SEED}:{sid}:{task['task_id']}").shuffle(order)
            for arm in order:
                request_id = secrets.token_hex(16)
                authority.operation = f"{sid}:{task['task_id']}:{arm}"
                event(journal, 'prepare_start', operation=authority.operation, arm=arm, story_id=sid,
                    task_id=task['task_id'], actor_id=task['actor_id'], agent_id='target-agent',
                    record_ids=[r['record_id'] for r in records], record_set_sha256=_digest(records),
                    request_sha256=hashlib.sha256(request_id.encode()).hexdigest())
                observer.stage('union' if arm == 'union' else 'prepare', arm, sid, task['task_id'])
                detector = union_detector if arm == 'union' else base_detector
                counts_before, posts_before = dict(detector.counts), observer.attempts
                row = {'story_id': sid, 'task_id': task['task_id'], 'actor_id': task['actor_id'],
                    'language': story['language'], 'template_family': story['template_family'], 'arm': arm,
                    'mode': 'migration', 'privacy_pipeline': 'legacy' if arm in {'baseline','union'} else 'semantic',
                    'build_status': built['status'], 'prepare_status': 'blocked', 'prepare_error': 'memory_build_unavailable',
                    'detector_calls': 0, 'answer_calls': 0, 'model_answer': None, 'final_answer': None,
                    'restoration_status': None, 'intent_applied': False, 'secondary_serialization_registered': True}
                prepared = None
                answerer.last_payload = None
                if records:
                    options = ({'detection_cache': union_cache} if arm == 'union' else
                        {'semantic_refiner': refiner, 'semantic_mode': arm} if arm in {'roles','completion','joint'} else {})
                    prepared = prepare_labeled_transfer(records, task['query'], policy, authority=authority,
                        actor_id=task['actor_id'], agent_id='target-agent', request_id=request_id,
                        mode='migration', agent=detector, privacy_pipeline=row['privacy_pipeline'], **options)
                    row.update(prepare_status=prepared['status'], prepare_error=prepared.get('error'),
                        module_authorization_error=prepared.get('error'), detector_calls=prepared.get('local_calls', 0),
                        detection=prepared.get('detection'), checks=prepared.get('checks'),
                        prepare_metadata=prepared.get('metadata'), egress=prepared.get('egress'))
                    if prepared['status'] == 'ok':
                        observer.stage('answer', arm, sid, task['task_id'])
                        response = answerer(prepared['payload'])
                        row.update(answer_calls=response['local_calls'], model_answer=response.get('answer'),
                            answer_status=response['status'], answer_error=response.get('error'),
                            outbound=answerer.last_payload, actual_payload_sha256=_digest(answerer.last_payload))
                        if response['status'] == 'ok':
                            restored = restore_labeled_answer(response['answer'], prepared, records, policy,
                                authority=authority, actor_id=task['actor_id'], agent_id='target-agent', request_id=request_id)
                            row.update(final_answer=restored.get('answer'), restoration_status=restored['status'], restoration_error=restored.get('error'))
                            normalized = canonicalize_answer(response['answer'], answerer.last_payload)
                            secondary = restore_labeled_answer(normalized['answer'], prepared, records, policy,
                                authority=authority, actor_id=task['actor_id'], agent_id='target-agent', request_id=request_id)
                            row['secondary_serialization'] = {'decision': normalized['decision'], 'canonical_answer': normalized['answer'],
                                'final_answer': secondary.get('answer'), 'restoration_status': secondary['status'], 'restoration_error': secondary.get('error')}
                row['inference_counts'] = detector.delta(counts_before)
                row['prepare_generation_calls_observed'] = observer.attempts-posts_before-row['answer_calls']
                pending.append((row, story, records, prepared))
                rows.append(row)
                event(journal, 'task_processing_end', operation=authority.operation, prepare_status=row['prepare_status'],
                    answer_calls=row['answer_calls'])
                save(output/'rows.json', rows)
                save(output/'auth_events.json', journal)
                if progress:
                    progress({'completed': len(rows), 'expected': 200, 'story': sid, 'arm': arm,
                              'prepare': row['prepare_status'], 'scored': False})
    if len(rows) != 200 or file_sha(corpus/'development/runtime.json') != plan['runtime_sha256'] or file_sha(corpus/'development/evaluation.json') != plan['evaluation_sha256']:
        raise ValueError('study_matrix_or_source_changed')
    observer.model_phase_closed = True
    event(journal, 'model_phase_closed', actual_generation_attempts=observer.attempts)
    evaluation = json.loads(evaluation_bytes)
    if set(evaluation) != {s['story_id'] for s in runtime}:
        raise ValueError('evaluation_story_mismatch')
    for row, story, records, prepared in pending:
        gold = evaluation[row['story_id']]
        expected = gold['answers'].get(row['task_id'])
        row['required_fact_retained'] = bool(expected and any(expected in r['text'] for r in records))
        row['masking'] = score_masking(story, gold, records, prepared or {'status': 'blocked'})
        row['score'] = score(row, gold)
        if prepared:
            prepared['mapping'] = None
    pending.clear()
    save(output/'rows.json', rows)
    save(output/'evaluation.json', evaluation)
    save(output/'auth_events.json', journal)
    if hashes != {str(p.relative_to(ROOT)): file_sha(p) for p in list(package.glob('*.py'))+entrypoints}:
        raise ValueError('implementation_changed_during_study')
    events = [json.loads(line) for line in (output/'request_transport.jsonl').read_text(encoding='utf-8').splitlines()] if (output/'request_transport.jsonl').exists() else []
    posts = [e for e in events if e['phase'] == 'request']
    report = {'version': VERSION, 'registered_rows': 200, 'recorded_rows': len(rows), 'source_stories': 8,
        'arms': aggregate(rows, builds, ARMS), 'generation_calls_observed': observer.attempts,
        'builder_generations': sum(e['stage'] == 'build' for e in posts),
        'semantic_shared_generations': sum(e['stage'] == 'semantic' for e in posts),
        'union_detection_generations': sum(e['stage'] == 'union' for e in posts),
        'answer_generations': sum(e['stage'] == 'answer' for e in posts),
        'build_encoder_calls': sum(b['inference_counts']['local_encoder'] for b in builds),
        'total_encoder_calls': base_detector.counts['local_encoder']+union_detector.counts['local_encoder'],
        'request_wire_json_bytes': sum(e['wire_json_utf8_bytes'] for e in posts),
        'detector_call_accounting_complete': base_detector.complete and union_detector.complete,
        'implementation_unchanged': True, 'closed_phase_attempts': observer.closed_phase_attempts,
        'cloud_calls': 0, 'new_api_cost_cny': 0, 'scope': plan['scope']}
    save(output/'report.json', report)
    render(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'results'):
        raise ValueError('new_project_results_directory_required')
    network = {'loopback_connections': 0, 'external_attempts_blocked': 0}
    def audit(event_name, values):
        if event_name == 'socket.connect':
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {'127.0.0.1', '::1'}:
                network['external_attempts_blocked'] += 1
                raise RuntimeError('external_network_disabled')
            network['loopback_connections'] += 1
    sys.addaudithook(audit)
    config = json.loads((ROOT/'configs/local_privacy_detector.json').read_bytes())
    observer = SemanticTransport(output, LocalSensitivityAgent._transport)
    started, completed = time.monotonic(), False
    try:
        with observer.installed():
            run(ROOT/'examples/privacy_semantics_v1', output, ROOT/'.runtime/github_ner', config, observer,
                progress=lambda row: print(json.dumps(row), flush=True))
        completed = True
    finally:
        if output.exists():
            summary = dict(observer.summary(), completed=completed, elapsed_seconds=time.monotonic()-started,
                python_executable=sys.executable, python_version=sys.version, network=network,
                closed_phase_attempts=observer.closed_phase_attempts, registered_protocol=VERSION)
            save(output/'transport_audit.json', summary)
            save(output/'network_audit.json', network)
            print(json.dumps({'output': str(output), 'audit': summary}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
