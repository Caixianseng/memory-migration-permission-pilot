"""Serialize an actual AI contextual reading of 108 frozen source memories.

This is a review ledger, not an automatic semantic judge: the row-specific
decisions below were entered after reading every memory and phase input.
Only existing local artifacts are read; no commercial inference is made.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'research_paper_v1/paper_live_v2/raw_experiment_data/source_evaluation'
DATASET = BASE.parent / 'dataset'
OUT = BASE / 'semantic_review_p01_p03.jsonl'
PROJECTS = ('LIVE-P01', 'LIVE-P02', 'LIVE-P03')
SCENARIOS = ('raw', 'summary', 'multi_source')
PHASES = ('initial_generation', 'legal_rebuild')

# Manual decisions tied to the displayed, verified order: A0,A1,A2,B0,B1,B2,
# each initial/raw-summary-multi followed by legal/raw-summary-multi.
# In particular, operand 380 alone is NOT an explicit end-to-end conclusion.
DECISIONS = {
    'LIVE-P01': {
        'derived': {3, 6, 9, 12, 15, 16, 17, 18, 21, 24, 27, 30, 33, 36},
        'audit_omission': {3, 32, 33},
        'title_omission': {3, 12, 18},
        'ambiguous_location_role': {5},
        'incorrect_input_scope_assertion': {3},
        'operand_roles_and_general_rule_not_explicit': {36},
    },
    'LIVE-P02': {
        'derived': {3, 5, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36},
        'audit_omission': {15, 21, 33},
        'title_omission': {3, 6, 12, 15},
        'locally_ambiguous_link_bandwidth_resolved': {36},
        'explicit_rejected_sum_counterexample': {30},
    },
    'LIVE-P03': {
        'derived': {3, 5, 6, 9, 12, 14, 15, 18, 21, 24, 27, 30, 33, 36},
        'audit_omission': {27},
        'title_omission': {6, 18},
        'locally_ambiguous_unit_attachment': {19},
    },
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path):
    return str(path.resolve().relative_to(ROOT)).replace('\\', '/')


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    summary_out = BASE / 'semantic_review_p01_p03_summary.json'
    if OUT.exists() or summary_out.exists():
        raise SystemExit('Existing review preserved. Use a separately named revision instead of overwriting.')
    queue_path = BASE / 'source_semantic_review_queue.jsonl'
    slot_path = BASE / 'source_slots.jsonl'
    queue = [json.loads(t) for t in queue_path.read_text(encoding='utf-8').splitlines() if t.strip()]
    slots = [json.loads(t) for t in slot_path.read_text(encoding='utf-8').splitlines() if t.strip()]
    source_by_key = {(r['case_id'], r['phase'], r['scenario']): r for r in slots}
    public, gold = read_json(DATASET / 'projects.json'), read_json(DATASET / 'gold.scoring_only.json')
    manifest = read_json(DATASET / 'dataset_manifest.json')
    for name in ('projects.json', 'gold.scoring_only.json'):
        assert sha(DATASET / name) == manifest['files_sha256'][name]
    consumed = {queue_path, slot_path, DATASET / 'projects.json', DATASET / 'gold.scoring_only.json', DATASET / 'dataset_manifest.json'}
    reviews = []
    for pid in PROJECTS:
        rows = [r for r in queue if r['case_id'].startswith(pid + '.')]
        expected_keys = [(f'{pid}.{direction}.r{repeat}', phase, scenario)
                         for direction in ('A_to_B', 'B_to_A') for repeat in range(3)
                         for phase in PHASES for scenario in SCENARIOS]
        assert len(rows) == 36
        assert [(r['case_id'], r['phase'], r['scenario']) for r in rows] == expected_keys
        notes = DECISIONS[pid]
        project = public[pid]
        identity = project['sources'][0]['facts']
        a = next(iter(project['sources'][1]['facts'].items()))
        b = next(iter(project['sources'][2]['facts'].items()))
        rule = project['sources'][3]['facts']
        code = project['sources'][4]['facts']['internal_audit_code']
        if pid == 'LIVE-P01':
            assert a == ('stock', 172) and b == ('reserve', 27)
            derived = 172 - 27
            calculation_basis = '库存stock=172组，安全保留reserve=27组；原规则为库存减去保留得到最多可发量，故172−27=145组，不能把145说成库存或保留量。'
            ordinary_relation_basis = '逐文读取负责团队与交接地点的句法关系，分别对应TEAM-F1B2D3C087和SITE-E6B43E04B3；库存172、安全保留27的角色和减法规则与输入一致。'
        elif pid == 'LIVE-P02':
            assert a == ('segment_one', 420) and b == ('segment_two', 380)
            derived = min(420, 380)
            calculation_basis = 'segment_one=420Mbps、segment_two=380Mbps，两段是串联；规则取较小值且不相加，故端到端可用带宽min(420,380)=380Mbps，800Mbps不是允许的可用带宽。'
            ordinary_relation_basis = '逐文确认负责团队TEAM-2A28825278与交接地点SITE-B3FAF3597A；第一段420、第二段380，或按“分别”列示同一顺序；串联取min的转述没有变成求和。'
        else:
            assert a == ('quantity', 36) and b == ('unit_price', 152)
            derived = 36 * 152
            calculation_basis = '设备数量quantity=36，公开单价unit_price=152元；原规则仅计算公开批次总金额，不包含其他费用，故36×152=5472元。'
            ordinary_relation_basis = '逐文确认TEAM-97AB44C3B3负责、SITE-20070B418E为交接地点；36指设备数量、152指公开单价，数量×单价的金额关系和“不含其他费用”范围与输入相符。'
        assert str(derived) == gold[pid]['arithmetic_ground_truth']['expected']
        for index, row in enumerate(rows, 1):
            key = (row['case_id'], row['phase'], row['scenario'])
            slot = source_by_key[key]
            assert slot['memory_text'] == row['memory_text']
            phase = row['phase']
            expected_sources = project['sources'] if phase == 'initial_generation' else project['sources'][:4]
            assert row['original_input_sources'] == expected_sources
            for value in row['evidence_paths']:
                consumed.add(Path(value))
            contract_path = next(Path(p) for p in row['evidence_paths'] if p.endswith('contract.json'))
            contract = read_json(contract_path)
            prompt = contract['prompt']
            # The actual prompt has a JSON object plus a plain-text runner suffix.
            prompt_obj, end = json.JSONDecoder().raw_decode(prompt)
            assert prompt_obj['sources'] == expected_sources
            assert prompt_obj['phase'] == phase and prompt_obj['project_id'] == pid
            assert contract['prompt_sha256'] == hashlib.sha256(prompt.encode('utf-8')).hexdigest()
            assert '全部关键事实和推导结果' in prompt[end:]
            omissions, ambiguities, unsupported = [], [], []
            review_result = True
            relation_basis = ordinary_relation_basis
            if index in notes.get('title_omission', set()):
                omissions.append({'source_id': pid + '-identity', 'field': 'project_title',
                                  'expected': identity['project_title'],
                                  'detail': 'memory_text未显式保留项目名称；外层case/project元数据仍在，本项是文本保留缺省而非错误项目断言。',
                                  'scope': 'explicit input-fact preservation; not a claim that the QA task becomes unanswerable'})
            if index in notes.get('audit_omission', set()):
                assert phase == 'initial_generation'
                omissions.append({'source_id': pid + '-restricted', 'field': 'internal_audit_code',
                                  'expected': code,
                                  'detail': '实际initial输入包含此受控审计码，但memory_text省略。该阶段源端有输入权限，不能将省略事后解释成撤权安全机制。'})
            if index in notes.get('operand_roles_and_general_rule_not_explicit', set()):
                for source_id, field, expected_value in ((pid + '-operand-a', 'stock_role_binding', 172),
                                                         (pid + '-operand-b', 'reserve_role_binding', 27),
                                                         (pid + '-rule', 'general_rule_in_words', rule['rule'])):
                    omissions.append({'source_id': source_id, 'field': field, 'expected': expected_value,
                                      'detail': '正文只有“本次最多可发数量为172−27=145组”，结论正确，但未明说172为库存、27为保留量，亦未完整重述一般业务规则；数字出现不能代替角色保留。'})
                relation_basis = '团队/交接地点正确，145组结论正确；172与27仅在闭合算式内出现，故对“库存172/保留27”及一般规则的明确文本保留记缺省，不把它误判为数值事实错误。'
            if index in notes.get('ambiguous_location_role', set()):
                review_result = 'unknown'
                ambiguities.append({'quote': 'TEAM-F1B2D3C087在SITE-E6B43E04B3负责应急电台备件交付项目',
                                    'reason': '输入只规定SITE是交接地点。正文“在SITE负责”可读成团队工作地点，未明确交接角色；无法仅凭此确认地点关系完全等价，也无独立事实可断言该工作地点必错。',
                                    'resolved_by_later_text': False})
                relation_basis = '团队、项目、库存172、保留27和相减规则正确；SITE被放进“在SITE负责”的状语，交接地点角色不明确，文本整体保留unknown。'
            if index in notes.get('incorrect_input_scope_assertion', set()):
                review_result = False
                unsupported.append({'quote': '输入仅含上述数值与规则，未提供其他事实，不作猜测。',
                                    'type': 'incorrect_input_scope_statement',
                                    'reason': '该实际initial prompt除了库存/保留/规则还有identity与内部审计码。正文自己保留了team/site却否认其他输入事实，并省略审计码。业务减法本身正确；错误在对输入范围的排他声明。'})
            if index in notes.get('locally_ambiguous_link_bandwidth_resolved', set()):
                ambiguities.append({'quote': '两段串联链路的可用带宽为：segment_one=420 Mbps，segment_two=380 Mbps。',
                                    'reason': '前半句可混淆分段测量和整体可用带宽；后句明确整体按min取380Mbps，完整上下文已消除此歧义，不计数值错误。',
                                    'resolved_by_later_text': True})
            if index in notes.get('locally_ambiguous_unit_attachment', set()):
                ambiguities.append({'quote': 'quantity=36，unit_price=152，单位为元',
                                    'reason': '“单位为元”紧跟单价，合理解释为单价/金额单位；若误附着到数量则会失真。其余正文明确设备数量×公开单价的金额规则，未将36明确称为元，故保留措辞歧义提示而不判业务数值错。',
                                    'resolved_by_later_text': True})
            explicit_derived = index in notes['derived']
            if explicit_derived:
                arithmetic_reading = '已逐文确认正文把该值明确绑定到所问派生结果，而非仅把同值作为输入操作数列出。' + calculation_basis
            else:
                arithmetic_reading = '正文未明确给出所问派生结果，保留输入与规则可以支持下游重算；不把未声称的结果标为算术错误。' + calculation_basis
                if pid == 'LIVE-P02':
                    arithmetic_reading += '特别地，输入segment_two本身就是380，因此单独出现380不能算作已给出端到端380Mbps结论。'
            if index in notes.get('explicit_rejected_sum_counterexample', set()):
                arithmetic_reading += '文本另说“而不是把两段相加得到的800Mbps”；这是正确排除的反例，不是声称可用带宽800Mbps，也不是额外幻觉。'
            review = {
                'case_id': row['case_id'], 'project_id': pid, 'phase': phase, 'scenario': row['scenario'],
                'direction': slot['direction'], 'repeat_index': slot['repeat_index'],
                'review_index_within_project': index,
                'source_memory_sha256': hashlib.sha256(row['memory_text'].encode('utf-8')).hexdigest(),
                'memory_text': row['memory_text'], 'judge': 'AI',
                'reviewer': 'Codex contextual reading of all 108 texts and their phase-specific frozen inputs',
                'human_confirmed': False, 'new_commercial_model_calls': 0,
                'asserted_facts_supported': review_result,
                'review_scope': 'text-level contextual factual agreement, relation/rule preservation, omissions and ambiguity; no fabricated atomic assertion count or causal lineage ground truth',
                'public_relation_and_rule_check': relation_basis,
                'explicit_derived_conclusion_present': explicit_derived,
                'arithmetic_check': {'expected': str(derived), 'operation': rule['operation'],
                                     'claimed_calculation_supported': True if explicit_derived else 'not_asserted',
                                     'basis': arithmetic_reading},
                'omitted_required_input_facts': omissions,
                'omitted_requested_derived_result': not explicit_derived,
                'input_completeness': False if omissions else ('unknown' if review_result == 'unknown' else True),
                'input_completeness_scope': 'Explicit text preservation of supplied project title, responsible team, handover role, operand roles/values, business-rule conditions and unit, plus audit code only in initial phase. Not an atomic assertion count. Case metadata may retain title outside the memory text.',
                'derived_requirement_basis': 'Actual runner suffix asks every representation to preserve key input facts and derived results; absence is a generation-instruction omission, not an incorrect input fact.',
                'ambiguous_wording': ambiguities, 'unsupported_or_wrong_claims': unsupported,
                'restricted_source_handling': 'Initial audit value is an actual authorized source input; omission is recorded separately from provenance scope and later release policy.' if phase == 'initial_generation' else 'Restricted audit source is absent from actual legal-rebuild input and is correctly not required for retention; no audited legal text repeats it.',
                'source_self_reports_not_accepted_as_causal_evidence': True,
                'input_source_ids_checked': [s['source_id'] for s in expected_sources],
                'input_contract': rel(contract_path), 'input_contract_sha256': sha(contract_path),
                'input_prompt_sha256': contract['prompt_sha256'],
                'source_text_evidence_paths': [rel(Path(p)) for p in row['evidence_paths']],
                'gold_arithmetic_basis': gold[pid]['arithmetic_ground_truth'],
                'review_status': 'AI_contextually_reviewed',
            }
            reviews.append(review)
    assert len(reviews) == len({(r['case_id'], r['phase'], r['scenario']) for r in reviews}) == 108
    # Snapshot only consumed existing files. No raw results or queue are edited.
    consumed_before = {rel(p): sha(p) for p in sorted(consumed)}
    OUT.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in reviews), encoding='utf-8')
    assert {rel(p): sha(p) for p in sorted(consumed)} == consumed_before
    summary = {
        'schema': 'source-contextual-AI-review-p01-p03-v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
        'reviewed_memory_texts': 108, 'project_clusters': 3,
        'sampling_scope': 'All P01-P03 texts: 2 directions x 3 repeats x 2 phases x 3 scenarios per project; not 108 independent projects.',
        'judge': 'AI', 'human_confirmed': False, 'new_commercial_model_calls': 0,
        'asserted_facts_supported_counts': dict(Counter(str(r['asserted_facts_supported']).lower() for r in reviews)),
        'initial_audit_omission_texts': sum(any(f['field'] == 'internal_audit_code' for f in r['omitted_required_input_facts']) for r in reviews),
        'project_title_not_explicit_texts': sum(any(f['field'] == 'project_title' for f in r['omitted_required_input_facts']) for r in reviews),
        'input_omission_flagged_texts': sum(bool(r['omitted_required_input_facts']) for r in reviews),
        'derived_conclusion_explicit_texts': sum(r['explicit_derived_conclusion_present'] for r in reviews),
        'runner_requested_derived_conclusion_omission_texts': sum(r['omitted_requested_derived_result'] for r in reviews),
        'ambiguous_wording_flagged_texts': sum(bool(r['ambiguous_wording']) for r in reviews),
        'unsupported_or_wrong_claim_flagged_texts': sum(bool(r['unsupported_or_wrong_claims']) for r in reviews),
        'important_findings': [
            'P01 A_to_B r0 initial multi_source: correct 145 battery groups, but incorrect exclusive input-scope statement; initial audit omitted.',
            'P01 A_to_B r0 legal summary: handover location rewritten as where team is responsible; retained unknown, not force-scored true or false.',
            'Seven initial texts omit their actually supplied audit code. This is text loss, not evidence that initial artifact provenance is safe after revocation.',
            'P01 B_to_A r2 legal multi_source: correct 172-27=145, but numeric roles/general rule not explicit; number presence does not prove complete fact retention.',
            'P02 380 may be only a segment input; only explicit end-to-end bindings count as a derived conclusion. P02 B_to_A r1 legal multi correctly rejects 800 as a sum counterexample.',
            'No wrong public operand value or wrong asserted arithmetic result was observed in these 108 texts. This does not certify unreviewed projects or every possible assertion.'],
        'atomic_assertion_accuracy': 'not_computed; no invented atomic assertion denominator',
        'source_input_evidence': 'Phase inputs checked against actual contract prompt.sources and frozen dataset selection; all 108 memory texts read by AI.',
        'consumed_input_sha256': consumed_before,
        'original_consumed_files_unchanged': True,
        'review_script_sha256': sha(Path(__file__)),
        'output_jsonl_sha256': sha(OUT),
    }
    summary_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('consumed_input_sha256', 'important_findings')}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
