"""Local, paired A->B development study of reference-based memory construction.

Evaluation labels are parsed only after all construction, authorization,
model-answer and restoration processing has finished. This is a development
comparison, not independent effectiveness acceptance or native interoperability.
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
from memory_migration_study.coverage_memory import CoverageMemoryBuilder
from memory_migration_study.detection_cache import detector_revision
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.memory_builder import LocalMemoryBuilder
from memory_migration_study.memory_generation_experiment import LocalFactAnswerer, score_masking
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import _digest
from memory_migration_study.reuse_benchmark import save
from memory_migration_study.semantic_memory_benchmark import CountingDetector, RecordingAnswerer, aggregate, score
from scripts.run_boundary_transfer_diagnostic import ObservedTransport

VERSION = 'reference_memory_construction_development_v1'
ARMS = {name: (name, 'migration', False) for name in
        ('old_joint_quote', 'reference_id', 'reference_quote', 'retain_all', 'coverage')}
ORDER_SEED = 2026102507
GENERATION_CAP = 208


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class TypedCountingDetector(CountingDetector):
    """Trusted host adapter: publish the validated physical per-call delta.

    The wrapped backend is constructed here as the pinned local GLiNER class;
    no model-provided inference-kind string is used to infer its runtime.
    """
    def __call__(self, **kwargs):
        before = dict(self.counts)
        result = super().__call__(**kwargs)
        return {**result, 'inference_counts': self.delta(before),
                'local_calls_complete': self.complete and result.get('local_calls_complete', True) is True}


class StageTransport(ObservedTransport):
    def __init__(self, output, original):
        super().__init__(output, original, max_generations=GENERATION_CAP)
        self.context = {'stage': 'initialization', 'arm': None, 'story_id': None, 'task_id': None}

    def stage(self, stage, arm, story_id, task_id=None):
        self.context = {'stage': stage, 'arm': arm, 'story_id': story_id, 'task_id': task_id}

    def append(self, record):
        event = {**record, **self.context}
        if event['phase'] == 'request':
            encoded = json.dumps(event['request'], ensure_ascii=False).encode('utf-8')
            event.update(wire_json_utf8_bytes=len(encoded),
                wire_json_utf8_sha256=hashlib.sha256(encoded).hexdigest(),
                wire_encoding='LocalSensitivityAgent._transport json.dumps ensure_ascii=False default separators; JSON body only')
        super().append(event)


def render(output, report):
    keys = ('legal_tasks', 'correct', 'joint_correct_no_masking_gap', 'secondary_serialization_correct',
            'secondary_joint_correct_no_masking_gap', 'build_successes', 'supported_legal_tasks',
            'ready_with_masking_gaps', 'outsider_blocked', 'answer_calls')
    esc = lambda value: html.escape(str(value))
    body = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>引用式记忆构建对照</title>'
        '<style>body{font:16px/1.7 system-ui;margin:32px}table{border-collapse:collapse;display:block;overflow:auto}'
        'th,td{border:1px solid #bac6cf;padding:8px}p{max-width:1100px}</style>'
        '<h1>事实选择与敏感标注分离：A→B真实本地开发对照</h1>'
        '<p>既有8个已暴露合成开发故事，5个完整条件；同一原授权、迁移与回答流程。'
        '编号选择、原文选择与全保留使用同一候选池和独立检测。原联合构建、Coverage额外保留。'
        '不是新的盲测、原生后端迁移或论文创新证明。无云端调用和新增API费用。</p>')
    body += '<table><tr><th>条件</th>'+''.join('<th>'+esc(k)+'</th>' for k in keys)+'</tr>'
    for arm, values in report['arms'].items():
        body += '<tr><td>'+esc(arm)+'</td>'+''.join('<td>'+esc(values[k])+'</td>' for k in keys)+'</tr>'
    body += ('</table><p>主成绩保留模型原答；严格补括号只作同一输出的次要分析。'
        '构建失败、事实遗漏、待审和拒答保留在32道合法题分母。缺失事实不算隐私收益。'
        '只计算已注册字符遮蔽，不代表语义或推断隐私。</p>'
        '<p><a href="report.json">完整汇总</a> · <a href="rows.json">逐题输入/原答/主次成绩</a> · '
        '<a href="builds.json">构建原始决定与成本</a> · <a href="plan.json">冻结协议</a> · '
        '<a href="transport_audit.json">实际调用账本汇总</a></p></html>')
    (Path(output)/'index.html').write_text(body, encoding='utf-8')


def run(corpus, output, model_root, config, observer, *, progress=None):
    from memory_migration_study.reference_memory import ReferenceMemoryBuilder, propose_fact_pool
    corpus, output = Path(corpus), Path(output)
    runtime_bytes = (corpus/'development/runtime.json').read_bytes()
    evaluation_bytes = (corpus/'development/evaluation.json').read_bytes()
    runtime = json.loads(runtime_bytes)
    legal = sum(t['actor_id'] == 'owner' for s in runtime for t in s['tasks'])
    if len(runtime) != 8 or legal != 32 or sum(len(s['tasks']) for s in runtime) != 40:
        raise ValueError('frozen_development_matrix_required')
    if len({s['story_id'] for s in runtime}) != len(runtime) or any(
            len({t['task_id'] for t in s['tasks']}) != len(s['tasks']) for s in runtime):
        raise ValueError('duplicate_runtime_identity')
    output.mkdir(parents=True, exist_ok=False)
    package = ROOT/'memory_migration_study'
    source_files = list(package.glob('*.py'))+[Path(__file__), ROOT/'scripts/run_boundary_transfer_diagnostic.py']
    hashes = {str(p.relative_to(ROOT)): file_sha(p) for p in source_files}
    archive = output/'implementation'
    archive.mkdir()
    for path in source_files:
        target = archive/path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    save(output/'runtime.json', runtime)
    save(output/'config.json', config)
    plan = {'version': VERSION, 'score_schema_version': 2, 'split': 'development', 'arms': ARMS,
        'expected_rows': 200, 'legal_per_arm': 32, 'outsider_per_arm': 8,
        'runtime_sha256': hashlib.sha256(runtime_bytes).hexdigest(),
        'evaluation_sha256': hashlib.sha256(evaluation_bytes).hexdigest(),
        'implementation_sha256': hashes, 'config_sha256': _digest(config),
        'ordering_seed': ORDER_SEED, 'privacy_pipeline': 'legacy', 'transfer_mode': 'migration',
        'query_intent': False, 'evaluation_timing': 'after_all_model_processing',
        'generation_limits': {'total': GENERATION_CAP, 'answers': 160, 'builders': 48,
            'per_model_builder_per_story': 2},
        'secondary_serialization': 'exact_current_token_outer_brackets_then_original_full_restore',
        'scope': 'Exposed synthetic development stories; same-host authority and JSON transfer. No native backend, independent generalization, compression, novelty or cloud utility claim.'}
    save(output/'plan.json', plan)
    ner = LocalNerRuntime(model_root)
    detector = TypedCountingDetector(GlinerEntityAgent(ner, approved_policies=[s['policy'] for s in runtime]))
    health = LocalSensitivityAgent(config).health()
    builders = {
        'old_joint_quote': LocalMemoryBuilder(config),
        'reference_id': ReferenceMemoryBuilder(mode='select', detector=detector, config=config),
        'reference_quote': ReferenceMemoryBuilder(mode='quote_select', detector=detector, config=config),
        'retain_all': ReferenceMemoryBuilder(mode='retain_all', detector=detector, config=config),
        'coverage': CoverageMemoryBuilder(detector=detector),
    }
    answerer = RecordingAnswerer(LocalFactAnswerer(config))
    save(output/'runtime_identity.json', {'ner': ner.identity, 'ner_initialization_seconds': ner.initialization_seconds,
                                        'local_generation': health, 'detector': detector.cache_identity()})
    rows, builds, stores, pools, pending = [], [], [], [], []
    for story in runtime:
        sid, source, policy = story['story_id'], story['source'], story['policy']
        authority = MemoryLabelAuthority(secrets.token_bytes(32))
        pool = propose_fact_pool(source['text'], source['source_id'])
        pool_before = _digest(pool)
        pools.append({'story_id': sid, 'pool': pool})
        save(output/'pools.json', pools)
        records_by_arm, builds_by_arm = {}, {}
        build_order = list(ARMS)
        random.Random(f'{ORDER_SEED}:build:{sid}').shuffle(build_order)
        for arm in build_order:
            observer.stage('build', arm, sid)
            before, initial_posts = dict(detector.counts), observer.attempts
            options = {'pool': pool} if arm in {'reference_id', 'reference_quote', 'retain_all'} else {}
            built = builders[arm](text=source['text'], source_id=source['source_id'], policy=policy, **options)
            if _digest(pool) != pool_before:
                raise ValueError('shared_candidate_pool_modified')
            records = []
            accepted_status = built['status']
            if accepted_status == 'ok' and not built['facts']:
                accepted_status = 'needs_review'
            if accepted_status == 'ok':
                for fact in built['facts']:
                    records.append(authority.build_record(source, fact, policy, owner_id='owner', readers=['owner'],
                        agent_id='source-agent', allowed_agent_ids=['target-agent'], builder_version=built['builder_version'],
                        detector_version=built['builder_version'] if arm == 'old_joint_quote' else detector_revision(detector)))
            records = json.loads(json.dumps(records, ensure_ascii=False))
            counts = detector.delta(before)
            item = dict(built, raw_build_status=built['status'], status=accepted_status,
                story_id=sid, language=story['language'], builder=arm,
                generation_calls_observed=observer.attempts-initial_posts, inference_counts=counts,
                stored_characters=sum(len(r['text']) for r in records),
                stored_record_json_bytes=len(json.dumps(records, ensure_ascii=False).encode('utf-8')),
                stored_source_copy_characters=sum(len(r['source']['text']) for r in records),
                source_characters=len(source['text']),
                candidate_pool_json_bytes=len(json.dumps(pool, ensure_ascii=False).encode('utf-8')) if options else 0,
                construction_result_json_bytes=len(json.dumps(built, ensure_ascii=False).encode('utf-8')))
            builds.append(item)
            stores.append({'story_id': sid, 'builder': arm, 'records': records})
            records_by_arm[arm], builds_by_arm[arm] = records, item
            save(output/'builds.json', builds)
            save(output/'record_store.json', stores)
        for task in story['tasks']:
            order = list(ARMS)
            random.Random(f"{ORDER_SEED}:answer:{sid}:{task['task_id']}").shuffle(order)
            for arm in order:
                records, built = records_by_arm[arm], builds_by_arm[arm]
                request_id = secrets.token_hex(16)
                observer.stage('answer', arm, sid, task['task_id'])
                answerer.last_payload = None
                before = dict(detector.counts)
                row = {'story_id': sid, 'task_id': task['task_id'], 'language': story['language'],
                    'template_family': story['template_family'], 'actor_id': task['actor_id'], 'arm': arm,
                    'mode': 'migration', 'privacy_pipeline': 'legacy', 'intent_applied': False,
                    'build_status': built['status'], 'prepare_status': 'blocked',
                    'prepare_error': 'memory_build_unavailable', 'detector_calls': 0, 'answer_calls': 0,
                    'model_answer': None, 'final_answer': None, 'restoration_status': None,
                    'secondary_serialization_registered': True}
                prepared = None
                if records:
                    prepared = prepare_labeled_transfer(records, task['query'], policy, authority=authority,
                        actor_id=task['actor_id'], agent_id='target-agent', request_id=request_id,
                        mode='migration', agent=detector, privacy_pipeline='legacy')
                    row.update(prepare_status=prepared['status'], prepare_error=prepared.get('error'),
                        module_authorization_error=prepared.get('error'), detector_calls=prepared.get('local_calls', 0),
                        checks=prepared.get('checks'), detection=prepared.get('detection'),
                        prepare_metadata=prepared.get('metadata'), egress=prepared.get('egress'))
                    if prepared['status'] == 'ok':
                        response = answerer(prepared['payload'])
                        row.update(answer_calls=response['local_calls'], model_answer=response.get('answer'),
                            answer_status=response['status'], answer_error=response.get('error'),
                            outbound=answerer.last_payload, actual_payload_sha256=_digest(answerer.last_payload))
                        if response['status'] == 'ok':
                            restored = restore_labeled_answer(response['answer'], prepared, records, policy,
                                authority=authority, actor_id=task['actor_id'], agent_id='target-agent', request_id=request_id)
                            row.update(final_answer=restored.get('answer'), restoration_status=restored['status'],
                                       restoration_error=restored.get('error'))
                            normalized = canonicalize_answer(response['answer'], answerer.last_payload)
                            secondary = restore_labeled_answer(normalized['answer'], prepared, records, policy,
                                authority=authority, actor_id=task['actor_id'], agent_id='target-agent', request_id=request_id)
                            row['secondary_serialization'] = {'decision': normalized['decision'],
                                'canonical_answer': normalized['answer'], 'final_answer': secondary.get('answer'),
                                'restoration_status': secondary['status'], 'restoration_error': secondary.get('error')}
                row['inference_counts'] = detector.delta(before)
                pending.append((row, story, records, prepared))
                rows.append(row)
                save(output/'rows.json', rows)
                if progress:
                    progress({'completed': len(rows), 'expected': 200, 'story': sid, 'arm': arm,
                              'prepare': row['prepare_status'], 'scored': False})
    if (len(rows) != 200
            or file_sha(corpus/'development/evaluation.json') != plan['evaluation_sha256']
            or file_sha(corpus/'development/runtime.json') != plan['runtime_sha256']):
        raise ValueError('study_matrix_or_evaluation_changed')
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
    save(output/'evaluation.json', evaluation)
    save(output/'rows.json', rows)
    after_files = list(package.glob('*.py'))+[Path(__file__), ROOT/'scripts/run_boundary_transfer_diagnostic.py']
    if hashes != {str(p.relative_to(ROOT)): file_sha(p) for p in after_files}:
        raise ValueError('implementation_changed_during_study')
    transport_path = output/'request_transport.jsonl'
    events = [json.loads(line) for line in transport_path.read_text(encoding='utf-8').splitlines()] if transport_path.exists() else []
    request_events = [e for e in events if e['phase'] == 'request']
    response_events = [e for e in events if e['phase'] == 'response']
    report = {'version': VERSION, 'registered_rows': 200, 'recorded_rows': len(rows), 'source_stories': len(runtime),
        'template_families': len({s['template_family'] for s in runtime}), 'arms': aggregate(rows, builds, ARMS),
        'generation_calls_observed': observer.attempts,
        'builder_generations': sum(b['generation_calls_observed'] for b in builds),
        'answer_generations': sum(r['answer_calls'] for r in rows),
        'build_encoder_calls': sum(b['inference_counts']['local_encoder'] for b in builds),
        'migration_encoder_calls': sum(r['inference_counts']['local_encoder'] for r in rows),
        'request_wire_json_bytes': sum(e['wire_json_utf8_bytes'] for e in request_events),
        'prompt_eval_count_sum': sum(e['response'].get('prompt_eval_count', 0) for e in response_events
                                     if type(e['response'].get('prompt_eval_count')) is int),
        'eval_count_sum': sum(e['response'].get('eval_count', 0) for e in response_events
                              if type(e['response'].get('eval_count')) is int),
        'construction_bytes_by_arm': {arm: {
            'candidate_pool_json_bytes': sum(b['candidate_pool_json_bytes'] for b in builds if b['builder'] == arm),
            'construction_result_json_bytes': sum(b['construction_result_json_bytes'] for b in builds if b['builder'] == arm)}
            for arm in ARMS},
        'detector_call_accounting_complete': detector.complete, 'implementation_unchanged': True,
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
    def audit(event, values):
        if event == 'socket.connect':
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {'127.0.0.1', '::1'}:
                network['external_attempts_blocked'] += 1
                raise RuntimeError('external_network_disabled')
            network['loopback_connections'] += 1
    sys.addaudithook(audit)
    config_path = ROOT/'configs/local_privacy_detector.json'
    config = json.loads(config_path.read_bytes())
    observer = StageTransport(output, LocalSensitivityAgent._transport)
    completed, started = False, time.monotonic()
    try:
        with observer.installed():
            run(ROOT/'examples/privacy_semantics_v1', output, ROOT/'.runtime/github_ner', config, observer,
                progress=lambda row: print(json.dumps(row), flush=True))
        completed = True
    finally:
        if output.exists():
            summary = dict(observer.summary(), completed=completed, elapsed_seconds=time.monotonic()-started,
                python_executable=sys.executable, python_version=sys.version, network=network,
                registered_protocol=VERSION)
            save(output/'transport_audit.json', summary)
            save(output/'network_audit.json', network)
            print(json.dumps({'output': str(output), 'audit': summary}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
