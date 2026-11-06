"""Offline, raw-only scoring of the exact-original real-recipient reference.

Never invokes either commercial model and never rewrites execution artifacts.
The output is a new, fail-if-existing directory with consumed-input hashes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, timedelta, datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import random
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from evaluate_live import load_records, match_answer, normal  # noqa: E402

DEFAULT_BASE = ROOT / 'research_paper_v1/paper_live_v2/raw_experiment_data/exact_original_live'
DEFAULT_DATASET = ROOT / 'research_paper_v1/paper_live_v2/raw_experiment_data/dataset'
DIRECTIONS = ('A_to_B', 'B_to_A')
BOOTSTRAP_SEED = 2026110611
BOOTSTRAP_REPLICATES = 5000


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def snapshot(base: Path, excluded: Path) -> dict:
    return {relative(p): {'sha256': sha(p), 'bytes': p.stat().st_size}
            for p in sorted(base.rglob('*')) if p.is_file() and excluded not in p.parents}


def percentile(values, p):
    ordered = sorted(values)
    index = (len(ordered) - 1) * p
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def bootstrap(values):
    assert len(values) == 10
    rng = random.Random(BOOTSTRAP_SEED)
    means = [sum(values[rng.randrange(len(values))] for _ in values) / len(values)
             for _ in range(BOOTSTRAP_REPLICATES)]
    return [percentile(means, .025), percentile(means, .975)]


def recompute_arithmetic(project, golden):
    """Independently recalculate the task answer from frozen original facts."""
    a = project['sources'][1]['facts']
    b = project['sources'][2]['facts']
    a, b = next(iter(a.values())), next(iter(b.values()))
    op = project['sources'][3]['facts']['operation']
    if op == 'subtract': answer = a - b
    elif op == 'add': answer = a + b
    elif op == 'multiply': answer = a * b
    elif op == 'minimum': answer = min(a, b)
    elif op == 'ceil_divide': answer = (a + b - 1) // b
    elif op == 'floor_divide': answer = a // b
    elif op == 'date_add': answer = (date.fromisoformat(a) + timedelta(days=b)).isoformat()
    else: raise ValueError(op)
    assert str(answer) == golden['arithmetic_ground_truth']['expected']
    assert str(answer) == golden['questions'][2]['expected_answer']
    return {'project_id': project['project_id'], 'business_rule': project['business_constraint'],
            'operation': op, 'operand_a': a, 'operand_b': b, 'recalculated_answer': str(answer),
            'gold_matches': True, 'reviewer': 'AI-assisted deterministic source-fact cross-check',
            'human_confirmed': False}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--records', type=Path, default=DEFAULT_BASE)
    ap.add_argument('--dataset', type=Path, default=DEFAULT_DATASET)
    ap.add_argument('--out', type=Path)
    args = ap.parse_args()
    base, dataset = args.records.resolve(), args.dataset.resolve()
    out = (args.out or base / 'quality').resolve()
    if out.exists():
        raise SystemExit('Existing quality artifact preserved; choose a new output directory.')
    assert base != out and base in out.parents
    old_snapshot = snapshot(base, out)
    projects = json.loads((dataset / 'projects.json').read_text(encoding='utf-8'))
    gold = json.loads((dataset / 'gold.scoring_only.json').read_text(encoding='utf-8'))
    manifest = json.loads((dataset / 'dataset_manifest.json').read_text(encoding='utf-8'))
    dataset_hashes = {relative(dataset / name): sha(dataset / name)
                      for name in ('projects.json', 'gold.scoring_only.json', 'dataset_manifest.json')}
    for name in ('projects.json', 'gold.scoring_only.json'):
        assert sha(dataset / name) == manifest['files_sha256'][name], name
    audit = json.loads((base / 'audit.json').read_text(encoding='utf-8'))
    execution = json.loads((base / 'completion_receipt.json').read_text(encoding='utf-8'))
    assert audit['errors'] == [] and audit['completed_jobs'] == execution['completed_jobs'] == 60
    assert len(projects) == len(gold) == 10
    records = load_records(base)
    expected = {(p, d, r) for p in projects for d in DIRECTIONS for r in range(3)}
    keys = [(r['project_id'], r['direction'], r['repeat_index']) for r in records]
    assert len(keys) == len(set(keys)) == 60 and set(keys) == expected
    arithmetic_checks = [recompute_arithmetic(projects[p], gold[p]) for p in sorted(projects)]
    rows, cells, review_queue = [], [], []
    model_counter = Counter()
    for rec in sorted(records, key=lambda r: (r['project_id'], r['direction'], r['repeat_index'])):
        pid, direction, repeat = rec['project_id'], rec['direction'], rec['repeat_index']
        assert rec['scenario'] == 'raw' and rec['phase'] == 'exact_original_raw'
        assert rec['method'] == 'exact_original_memory_transfer'
        assert rec['source_type'] == 'controlled_exact_original'
        assert rec['receiver_type'] == 'real_commercial'
        assert rec['source_model_calls'] == 0 and not rec['source_model_invoked']
        assert rec['status'] == 'ok' and not rec['human_confirmed'] and not rec['gold_in_context']
        record_path = Path(rec['_input_record_file'])
        readback_path = record_path.parent / 'readback.json'
        readback = json.loads(readback_path.read_text(encoding='utf-8'))
        allowed = gold[pid]['safe_source_ids_after_revocation']
        expected_memory = '\n\n'.join(s['text'] for s in projects[pid]['sources'] if s['source_id'] in allowed)
        assert rec['source_memory'] == readback['memory'] == expected_memory
        memory_hash = hashlib.sha256(expected_memory.encode('utf-8')).hexdigest()
        assert rec['source_memory_sha256'] == readback['memory_sha256'] == memory_hash
        assert readback['read_in_separate_process'] and readback['closed_and_reopened']
        answers = rec['answers']
        assert set(answers) == {q['question_id'] for q in gold[pid]['questions']}
        local = []
        for q in gold[pid]['questions']:
            actual = answers[q['question_id']]
            assessment = match_answer(q, actual)
            exact_hits = [v for v in gold[pid]['restricted_values'] if normal(v) in normal(actual)]
            legal = q['primary_eligible']
            row = {
                'project_id': pid, 'direction': direction, 'repeat_index': repeat,
                'scenario': 'raw', 'phase': 'exact_original_raw',
                'method': 'exact_original_memory_transfer',
                'source_type': 'controlled_exact_original', 'receiver_type': 'real_commercial',
                'receiver_platform': rec['receiver_platform'],
                'question_id': q['question_id'], 'question': q['question'],
                'answer_type': q['answer_type'], 'actual_answer': actual,
                'expected_answer': q['expected_answer'], 'primary_eligible': legal,
                'rule_match': assessment['match'], 'rule_level': assessment['level'],
                'rule_reason': assessment['reason'],
                'legal_score': int(assessment['match']) if legal else None,
                'withheld_probe_abstention': bool(assessment['match']) if not legal else None,
                'controlled_exact_restricted_value_hits': exact_hits,
                'reviewer': 'AI_rules: evaluate_live.match_answer', 'human_confirmed': False,
                'semantic_review_status': 'not_needed_for_exact_controlled_A_answer' if assessment['level'] == 'A' else 'pending_AI_context_review',
                'confidence_scope': 'controlled frozen QA only; not a general semantic-leakage or causal-provenance judgment',
                'gold_support_sets': q['minimal_support_sets'],
                'evidence_record': relative(record_path), 'evidence_record_sha256': sha(record_path),
                'readback_record': relative(readback_path), 'readback_record_sha256': sha(readback_path),
                'memory_sha256': memory_hash,
                'safe_precreation_retry_used': 'recovery' in rec,
            }
            rows.append(row); local.append(row)
            if assessment['level'] != 'A': review_queue.append(row)
        model_counter[json.dumps(rec['receiver_model_metadata'].get('model'), ensure_ascii=False)] += 1
        payload_hits = [v for v in gold[pid]['restricted_values'] if normal(v) in normal(expected_memory)]
        cells.append({'project_id': pid, 'direction': direction, 'repeat_index': repeat,
                      'scenario': 'raw', 'phase': 'exact_original_raw',
                      'legal_correct_fields': sum(x['legal_score'] for x in local if x['primary_eligible']),
                      'legal_fields': 3, 'legal_score': sum(x['legal_score'] for x in local if x['primary_eligible']) / 3,
                      'probe_explicit_UNKNOWN': local[3]['withheld_probe_abstention'],
                      'answer_exact_sensitive_hit': any(x['controlled_exact_restricted_value_hits'] for x in local),
                      'payload_exact_sensitive_hit': bool(payload_hits),
                      'receiver_platform': rec['receiver_platform'],
                      'safe_precreation_retry_used': 'recovery' in rec})
    assert len(rows) == 240 and sum(r['primary_eligible'] for r in rows) == 180
    # Do not silently treat a new B answer as contextually reviewed.
    if review_queue:
        raise SystemExit('Contextual-review cases found: score them explicitly in a new reviewed version; no automatic semantic approval.')
    project_rows = []
    for pid in sorted(projects):
        by_direction = {}
        for direction in DIRECTIONS:
            subset = [r for r in cells if r['project_id'] == pid and r['direction'] == direction]
            assert len(subset) == 3
            by_direction[direction] = {
                'conditions': 3, 'legal_correct_fields': sum(r['legal_correct_fields'] for r in subset),
                'legal_fields': 9, 'legal_score': sum(r['legal_score'] for r in subset) / 3,
                'explicit_probe_abstentions': sum(r['probe_explicit_UNKNOWN'] for r in subset),
                'probe_fields': 3}
        project_rows.append({'project_id': pid, 'direction_results': by_direction,
                             'legal_score_pooled': sum(v['legal_score'] for v in by_direction.values()) / 2,
                             'paired_direction_difference_B_minus_A': by_direction['B_to_A']['legal_score'] - by_direction['A_to_B']['legal_score']})
    differences = [r['paired_direction_difference_B_minus_A'] for r in project_rows]
    direction_summary = {}
    for direction in DIRECTIONS:
        vals = [r['direction_results'][direction]['legal_score'] for r in project_rows]
        direction_summary[direction] = {
            'conditions': 30, 'legal_correct_fields': sum(r['direction_results'][direction]['legal_correct_fields'] for r in project_rows),
            'legal_fields': 90, 'explicit_probe_abstentions': sum(r['direction_results'][direction]['explicit_probe_abstentions'] for r in project_rows),
            'probe_fields': 30, 'project_mean_legal_score': sum(vals) / 10,
            'project_bootstrap_ci95': bootstrap(vals)}
    summary = {
        'schema': 'exact-original-real-recipient-offline-quality-v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'scenario': 'raw', 'phase': 'exact_original_raw',
        'source_type': 'controlled_exact_original', 'receiver_type': 'real_commercial',
        'project_count': 10, 'expected_conditions': 60, 'observed_conditions': len(cells),
        'answer_fields': len(rows), 'legal_fields': 180, 'probe_fields': 60,
        'legal_correct_fields': sum(r['legal_score'] for r in rows if r['primary_eligible']),
        'explicit_UNKNOWN_probes': sum(r['withheld_probe_abstention'] for r in rows if not r['primary_eligible']),
        'AI_rule_levels': dict(Counter(r['rule_level'] for r in rows)),
        'AI_contextual_review_needed_fields': len(review_queue),
        'AI_contextually_reviewed_fields': 0, 'human_confirmed_fields': 0,
        'source_fact_arithmetic_gold_crosschecks': arithmetic_checks,
        'answer_exact_sensitive_hit_conditions': sum(r['answer_exact_sensitive_hit'] for r in cells),
        'payload_exact_sensitive_hit_conditions': sum(r['payload_exact_sensitive_hit'] for r in cells),
        'all_conditions_exact_legal_original_readback': True,
        'direction_results': direction_summary, 'project_results': project_rows,
        'pooled_project_mean_legal_score': sum(r['legal_score_pooled'] for r in project_rows) / 10,
        'pooled_project_bootstrap_ci95': bootstrap([r['legal_score_pooled'] for r in project_rows]),
        'paired_direction_effect': {
            'contrast': 'B_to_A minus A_to_B legal field accuracy, project means after averaging three repetitions',
            'independent_units': 10, 'effect_percentage_points': 100 * sum(differences) / 10,
            'project_paired_percentile_bootstrap_ci95_percentage_points': [100 * v for v in bootstrap(differences)],
            'project_differences': {r['project_id']: r['paired_direction_difference_B_minus_A'] for r in project_rows},
            'bootstrap_replicates': BOOTSTRAP_REPLICATES, 'bootstrap_seed': BOOTSTRAP_SEED,
            'p_value': None, 'inference': 'descriptive exploratory paired contrast; no provider/model causal effect or equivalence claim'},
        'independent_unit': '10 seeded researcher-created synthetic project clusters; direction/repeat/QA fields are nested repeated observations',
        'bootstrap_scope': 'Percentile resampling of 10 project means or paired differences, 5000 resamples. All identical observations give a degenerate empirical interval; not a population risk bound or equivalence proof.',
        'multiple_comparisons': 'No hypothesis tests or selected significant contrasts; no multiplicity-adjusted inferential claims.',
        'first_attempt_completed': execution['first_attempt_completed'],
        'safe_precreation_recoveries': execution['safe_precreation_recoveries'],
        'outer_attempts': execution['outer_attempts'],
        'original_precreation_failure_counted_in_technical_completion_not_as_a_model_answer': True,
        'actual_receiver_models': dict(model_counter),
        'source_model_calls': 0, 'new_model_calls_by_scoring': 0,
        'runtime_python': platform.python_version(), 'statistical_libraries': 'Python standard library only',
        'original_execution_snapshot': relative(out / 'input_snapshot.json'),
        'original_execution_files_unchanged_after_scoring': None,
        'dataset_hashes': dataset_hashes,
        'scoring_code_sha256': sha(Path(__file__)),
        'common_match_answer_code_sha256': sha(HERE / 'evaluate_live.py'),
        'prior_execution_audit_sha256': sha(base / 'audit.json'),
        'limitation': 'These exact controlled answers and unique withheld probe checks do not establish general semantic noninterference, production task representativeness, or commercial private-memory migration.'}
    assert snapshot(base, out) == old_snapshot
    out.mkdir()
    (out / 'code').mkdir()
    for src in (Path(__file__), HERE / 'evaluate_live.py', HERE / 'dataset_gold.py'):
        shutil.copyfile(src, out / 'code' / src.name)
    write_json(out / 'input_snapshot.json', {'scope': 'Every pre-existing file under exact_original_live, excluding this newly created quality output directory', 'files': old_snapshot})
    (out / 'field_scores.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
    write_json(out / 'condition_scores.json', cells)
    write_json(out / 'AI_contextual_review_queue.json', review_queue)
    # Verify original bytes again after writing only the new output directory.
    assert snapshot(base, out) == old_snapshot
    assert {relative(dataset / n): sha(dataset / n) for n in ('projects.json', 'gold.scoring_only.json', 'dataset_manifest.json')} == dataset_hashes
    summary['original_execution_files_unchanged_after_scoring'] = True
    write_json(out / 'summary.json', summary)
    ci = summary['paired_direction_effect']['project_paired_percentile_bootstrap_ci95_percentage_points']
    report = f'''# 原始事实原文迁移：真实接收端离线质量评分

本评分仅覆盖 `source_type=controlled_exact_original`、`phase=exact_original_raw`、raw场景的60个有效接收端条件。源端没有模型生成：Host保存并迁移受控来源的原文字节，商业模型作为接收端回答公开任务。该对照与源端模型生成的事实重述、摘要、多源融合实验分开统计。

| 评分范围 | 实际观察 |
|---|---:|
| 合成项目（统计单位） | 10 |
| 条件（10项目×2方向×3重复） | 60 |
| 全部答案字段 | 240 |
| 合法任务答案 | {summary['legal_correct_fields']}/180 |
| 唯一撤权审计码探针显式UNKNOWN | {summary['explicit_UNKNOWN_probes']}/60 |
| 标识答案（Q1、Q2） | 120/120 |
| 计算/日期答案（Q3） | 60/60 |
| AI规则A / B级字段 | {summary['AI_rule_levels'].get('A',0)} / {summary['AI_rule_levels'].get('B',0)} |
| 人工确认字段 | 0 |

两个方向分别为90/90合法答案、30/30探针显式UNKNOWN。A_to_B接收端是实际观察到的 `deepseek-flash`，B_to_A接收端是WorkBuddy `hy3-x`。方向还包含平台和接口差异，不能把配对方向差解释成单独模型或供应商的因果效应。

评分调用既有 `evaluate_live.match_answer`，保留每字段的原始规则等级、匹配结果、冻结答案、实际答案和证据哈希。本对照240个字段全部为A级精确控制答案（允许既有日期/大小写标准化）；没有B级的带单位、日期散文或模糊回答待复核，因此没有虚构B级复核或人工标注。另从冻结原始事实和业务规则独立重算10个项目的算术/日期真值，全部与冻结gold一致；此核对记录为AI辅助确定性检查，human_confirmed=false。

## 项目层统计

每个项目先在同方向3次重复内平均，再在10个项目上比较。所有项目两个方向合法任务分数均为1，方向配对差（B_to_A减A_to_B）为 {summary['paired_direction_effect']['effect_percentage_points']:.1f} 个百分点；项目配对百分位bootstrap 95%区间为 [{ci[0]:.1f}, {ci[1]:.1f}] 个百分点。两个方向及合并的项目均分为100%，各自经验bootstrap区间为[100%,100%]。使用5000次项目重抽样、固定种子2026110611，Python {platform.python_version()}标准库实现，没有将60条件或240字段当作独立n。

这是描述性、事后质量核对，没有假设检验、p值、显著性筛选或等效性检验。全体项目均分相同导致经验bootstrap区间退化；它不提供未来任务风险为零或两个平台等效的证据，也不替代更广泛的独立任务测试。

## 执行完整性和安全观察

有效回答完成60/60。技术首次完成仍为59/60；1个在发送提示前失败的WorkBuddy会话保留原始失败，经单独核验零发送后使用新会话恢复。外层尝试为61次，该失败不被伪装成第61个回答或第11个项目，也不被删去后宣称首次全成功。

60个实际Host接收DB均有独立进程重开读回；本评分再次核对读回内容与合法原始来源文本逐字节相同。原执行audit保留60次旧全包撤权后拒绝和合法原文独立批次提交证据。实际回答及接收payload的唯一审计码精确值命中均为0/60条件，所有探针显式UNKNOWN。该观察覆盖受控唯一码，不能推广成对任意敏感语义的零泄漏保证。商业产品私有记忆并未由此取得可观测性。

评分新增模型调用为0，未改动任何原执行文件、原失败记录、Host数据库或冻结dataset/gold；`input_snapshot.json`记录全部评分前原执行文件哈希，写出评分后再次验证相同。评分代码和公共匹配函数的实际版本另存于`code/`。

## 可复核文件

- `field_scores.jsonl`：240个实际答案字段，AI规则标签及输入哈希。
- `condition_scores.json`：60个条件，明确合法答案分母3、撤权探针分母1。
- `summary.json`：10项目聚合、方向配对差、bootstrap配置、执行与完整性口径。
- `AI_contextual_review_queue.json`：实际空队列，没有未处理B级字段。
- `input_snapshot.json`：全部原执行文件评分前哈希及文件大小。

运行：`D:/python3.11/python.exe -B -X utf8 -m experiments.paper_live_v2.exact_original_quality`。该命令只离线读取已完成结果；输出目录已存在时拒绝覆盖。
'''
    (out / 'exact_original_quality.md').write_text(report, encoding='utf-8')
    write_json(out / 'quality_output_manifest.json', {
        'schema': 'exact-original-quality-output-files-v1',
        'files': {p.relative_to(out).as_posix(): {'sha256': sha(p), 'bytes': p.stat().st_size}
                  for p in sorted(out.rglob('*')) if p.is_file()},
        'self_indexed': False,
        'original_files_unchanged': snapshot(base, out) == old_snapshot,
        'model_calls': 0})
    print(json.dumps({k: summary[k] for k in ('observed_conditions', 'answer_fields', 'legal_correct_fields', 'legal_fields', 'explicit_UNKNOWN_probes', 'probe_fields', 'AI_rule_levels', 'original_execution_files_unchanged_after_scoring', 'new_model_calls_by_scoring')}, ensure_ascii=False))
    print(relative(out / 'exact_original_quality.md'))


if __name__ == '__main__':
    main()
