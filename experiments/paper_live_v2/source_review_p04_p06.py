"""Serialize manually authored contextual reviews after reading all 108 texts.

This file is an annotation record/builder, not a token-matching semantic judge.
No model dispatch and no original data mutation occur here.
"""
from pathlib import Path
import hashlib
import json
from datetime import date, timedelta

REPO = Path(__file__).resolve().parents[2]
BASE = REPO / 'research_paper_v1/paper_live_v2/raw_experiment_data'

NOTES = {
'LIVE-P04': [
 '项目名、团队、交接点明确；devices绑定117，box_capacity绑定8；先除容量后向上取整的规则完整；审计码准确。没有明确给出15箱结论。',
 '117台设备、每箱容量8与需15箱相互一致，审计码准确；向上取整被提及，但先以设备总数除容量的通用关系仅由装箱语境暗示，未明确保留。',
 '明确写ceil(117/8)=15箱，运算和团队/地点/审计码均正确；未重复项目名称。',
 '项目关系和两项测量的变量绑定正确，向上取整除法规则完整；合法输入不含审计码，文本也未加入；未明确给出15箱。',
 '117台设备与8台/箱容量绑定正确，提到向上取整装箱；未明说除法关系，也未给出15箱结论。',
 '117台、每箱8台与ceil(117÷8)=15箱结合正确，项目/团队/交接点准确，未引入受限事实。',
 '117为设备数、8为每箱容量，ceil_divide的除法及向上取整关系明确；审计码准确；没有实际写出15箱结果。',
 '项目、团队、地点和两项数值正确；“按容量向上取整得箱数”没有说明对设备总数/容量的商取整，可能被字面理解成对容量自身取整，故规则含义保留unknown。',
 'ceil_divide和ceil(117/8)=15箱一致，项目标识关系及审计码均受输入支持。',
 '项目名、团队地点、117设备和8容量绑定正确；operation=ceil_divide及向上取整规则完整，但未给出15箱。',
 '设备总数117除容量8后向上取整的关系被完整转述；团队地点正确；未陈述具体15箱结论。',
 '明确117÷8=14.625，向上取整15箱，算术与装箱含义正确；团队和交接点准确；未重复项目名称。',
 '原始项目、团队地点、设备117和容量8及ceil除法规则均准确，审计码准确；没有给出15箱结论。',
 '117台/每箱8台与15箱结论正确，审计码准确；先除设备数与容量的通用关系未明确写出，只提到向上取整规则。',
 'ceil(117/8)=15箱及团队地点、审计码正确；文本称“项目”而未重复项目名。',
 '合法输入中的项目关系、117设备、8容量与除后向上取整规则均准确；未给15箱，无受限事实。',
 '设备总数117台、每箱8台及向上取整被保留；未明确先求总数/容量的商，也没有15箱结论。',
 '设备117台、每箱8台与ceil(117/8)=15箱明确且正确；项目、团队、地点关系受支持。',
 '原始变量devices=117、box_capacity=8和向上取整除法规则准确；项目关系及审计码准确，未明确给出15箱。',
 '总设备117台和每箱8台分别明确，除后向上取整规则完整，审计码正确；没有具体15箱结论。',
 '117÷8=14.625再向上取整15箱明确，输入身份关系和审计码均准确。',
 '合法输入身份关系与117/8变量绑定准确，先除容量后向上取整规则完整，没有具体15箱结论。',
 '团队地点、设备117及除后向上取整规则正确；但“每箱容量为8箱”把容量单位错写为箱，原规则中的箱是所需箱数的输出单位，不能移到每箱设备容量。',
 '117总设备/每箱8及117÷8=14.625后取15箱明确，项目身份关系准确，未引入受限事实。',
 '原始项目关系和117设备、8容量变量绑定及ceil规则完整；审计码准确，没有具体15箱结论。',
 '每箱可装8台与设备117台明确，除以容量后向上取整的业务规则完整，审计码准确；未明确给出15箱结果。',
 'ceil(117/8)=15箱、团队地点和项目名正确；初始输入中存在的审计码在该记忆文本中被省略。',
 '合法输入项目关系、devices=117、box_capacity=8及向上取整除法规则准确；未给出15箱。',
 '箱数=设备总数÷容量再向上取整的规则明确，117台与8台容量绑定准确；未给出15箱结果。',
 '设备117、每箱8及117÷8=14.625后取15箱明确，项目身份关系准确。',
 '设备117和容量8变量绑定、先除后取整规则、团队地点与审计码准确；未写15箱结论。',
 '项目、两项变量及除后向上取整的规则完整，审计码受初始输入支持；未写15箱结论。',
 'ceil(117÷8)=ceil(14.625)=15箱正确，项目身份关系准确；初始输入的审计码未被保留。',
 '合法输入身份关系、devices=117、box_capacity=8及除后向上取整规则准确，无15箱结果。',
 '项目关系和117设备/8容量分别准确，除后向上取整规则完整，未给15箱。',
 '117除以8向上取整即15箱准确，项目、团队、交接点关系准确，无新受限事实。',
],
'LIVE-P05': [
 '开始日期2027-03-01、持续17天及按自然日相加规则完整，项目关系和初始审计码准确；未明确写完成日期。',
 '开始日与17天的绑定准确，按自然日开始日加天数规则正确，项目关系和审计码准确；未写2027-03-18。',
 '依据date_add自然日规则由2027-03-01加17天得2027-03-18，日期与项目/团队/地点/审计码均准确。',
 '合法输入中项目关系、起始日期、持续天数和自然日加算规则完整；“未作补充”未掩盖新业务事实；未给完成日期。',
 '2027-03-01开始、工期17天及自然日开始日加天数关系准确；身份关系受支持，未给完成日期。',
 '自然日2027-03-01+17天=2027-03-18正确，团队和地点准确；未重复项目名。',
 'start_date与duration_days绑定准确，自然日加算规则和审计码准确；未给具体完成日期。',
 '2027-03-01、17自然日与date_add得2027-03-18正确；项目身份关系及审计码准确。',
 '自然日加算及2027-03-18结论正确，团队地点和审计码准确；未重复项目名称。',
 '项目ID及自然日date_add规则、2027-03-01和17天均来自请求；身份关系正确；未给具体完成日期。',
 '开始日、持续17天和自然日相加关系被正确概括，项目身份关系准确；未给具体完成日期。',
 '2027-03-01加17天得2027-03-18算术正确，团队地点与项目名正确；但未明确保留自然日而非工作日这一规则条件。',
 '起始日期、持续天数、自然日date_add规则和审计码准确；没有具体完成日期结论。',
 '计划开始日期与17个自然日对应输入，开始日加天数规则准确，审计码准确；未给2027-03-18。',
 '按自然日2027-03-01加17天推得2027-03-18正确；项目关系和审计码均准确。',
 '项目ID/来源标识为请求中已有元数据，不是独立因果证据；业务事实、自然日规则和身份关系准确，未给完成日期。',
 '2027-03-01开始、持续17天与自然日加算规则准确，项目关系准确；没有2027-03-18结论。',
 '自然日date_add从2027-03-01加17天得2027-03-18正确，身份关系准确；未添加其他业务事实。',
 '原始起始日期、持续17天与自然日规则准确，项目身份和审计码正确；未给具体完成日期。',
 '项目关系、开始日期、17天与自然日加算规则正确，审计码正确；未给具体完成日期。',
 '自然日2027-03-01+17天=2027-03-18正确，项目、团队、交接点和审计码准确。',
 '合法输入中的起始日、持续天数与自然日规则完整，项目身份关系准确；未给完成日期。',
 '起始日2027-03-01、17天与按自然日相加关系完整，身份关系准确；未给2027-03-18。',
 '明确持续17个自然日，加到2027-03-01得2027-03-18正确；项目、团队、地点准确。',
 '开始日期、17天和自然日加算规则及日期输出含义准确，身份关系与审计码准确；没有完成日期结论。',
 '17天与2027-03-01的绑定和自然日规则正确，身份关系与审计码准确；未给具体完成日期。',
 '开始日加持续17天得2027-03-18且明确自然日条件，项目关系及审计码准确。',
 '合法输入开始日、持续17天、自然日加算规则和身份关系均准确；没有具体完成日期。',
 '开始日与17天绑定正确，自然日相加关系完整，项目身份准确；未写2027-03-18。',
 '持续17个自然日，开始日期加天数得2027-03-18正确；身份关系准确。',
 'start_date为2027-03-01、duration_days为17和自然日加算规则正确，项目关系及审计码准确；未给完成日期。',
 '2027-03-01开始、17自然日和开始日加天数规则准确，身份关系及审计码准确；未给完成日期。',
 '2027-03-01加17个自然日=2027-03-18正确，身份关系与审计码准确。',
 '合法输入起始日期、17天、自然日相加规则和身份关系完整；没有完成日期结论。',
 '项目身份、2027-03-01、持续17天与自然日加算关系准确，未给2027-03-18。',
 '把17天加到2027-03-01得到2027-03-18，且明确自然日，日期计算与身份关系正确。',
],
'LIVE-P06': [
 'deployed明确为已部署196台、verified为已验收125台，待验收=已部署-已验收规则完整，身份和审计码准确；未给71台。',
 '已部署196/已验收125的数量绑定正确，减法得待验收71台正确，项目关系和审计码准确。',
 '已部署196减已验收125=待验收71台正确，团队/地点和审计码准确；未重复项目名。',
 '来源标识为请求已有元数据，不能当因果证明；已部署196、已验收125及待验收减法关系和身份关系完整；未给71台。',
 '196为已部署、125为已验收且待验收=已部署-已验收关系完整；身份关系正确，未给71台。',
 '待验收=已部署-已验收=196-125=71台正确，项目身份关系准确；没有额外业务推测。',
 '两个计数分别绑定已部署与已验收，减法顺序和输出为待验收准确；身份/审计码正确；未给71台。',
 '已部署196减已验收125得待验收71台，规则顺序与单位准确；项目关系和审计码准确。',
 '明确已部署196减已验收125得本批待验收71台，项目关系和初始审计码准确。',
 '原始两项计数、减法关系及196-125=71台推导均准确；身份关系正确，无新业务事实。',
 '已部署196、已验收125与待验收=已部署-已验收=71台正确，项目关系和单位准确。',
 '已部署196减已验收125得待验收71台，公开规则与团队地点准确；未重复项目名。',
 '已部署196与已验收125分别准确，待验收=已部署-已验收规则和身份/审计码正确；未给71台。',
 '明确已部署减已验收的业务关系，待验收71台计算正确；项目关系和审计码准确。',
 '已部署196减已验收125=待验收71台准确，团队地点和审计码准确；未重复项目名。',
 '合法输入项目ID及身份关系、已部署196/已验收125和待验收减法规则完整；未给71台。',
 '已部署196、已验收125及待验收=已部署-已验收关系准确，项目身份准确；未给71台。',
 'deployed=196、verified=125与待验收=196-125=71台正确，团队地点准确；未重复项目名。',
 '已部署196与已验收125分别绑定正确，待验收的减法顺序和单位完整，身份/审计码正确；未给71台。',
 '两个计数和待验收=已部署-已验收关系完整，身份/审计码正确；未明确给出71台结论。',
 '本批待验收为196-125=71台，语义和算术准确，项目身份关系及审计码准确。',
 '合法输入已部署196、已验收125和待验收=已部署-已验收关系完整，项目身份关系准确；未给71台。',
 '两项计数、已部署减已验收的方向和待验收输出含义、台单位完整，身份关系准确；未给71台。',
 '已部署196减已验收125=本批待验收71台正确，项目、团队、地点准确。',
 '已部署196、已验收125及本批待验收相减规则正确，身份关系与审计码正确；未给71台。',
 '本批已部署196/已验收125绑定清楚，待验收=已部署减已验收且单位台正确，审计码正确；未给71台。',
 '196−125=本批待验收71台，运算顺序与单位正确；项目身份关系及审计码准确。',
 'deployed=196、verified=125和本批待验收减法规则完整，身份关系准确；未给71台。',
 '已部署196台与已验收125台分别明确，待验收=已部署-已验收规则完整，身份关系准确；未给71台。',
 '本批待验收196−125=71台正确，两个计数含义与项目身份关系准确。',
 '已部署196、已验收125及本批待验收减法规则准确，项目身份和审计码正确；未给71台。',
 '196已部署/125已验收及已部署减已验收求待验收规则完整，项目关系和审计码准确；未给71台。',
 '196-125=71台明确绑定为本批待验收数量，身份关系和审计码准确。',
 '合法输入已部署196、已验收125和本批待验收减法规则完整，项目身份关系准确；未给71台。',
 '两个终端计数与待验收按已部署减已验收关系完整，身份关系准确；未给71台。',
 '已部署196、已验收125后相减得本批待验收71台，与标签顺序和输入规则一致；身份关系准确。',
],
}

# Manually identified omissions after contextual reading, not token tests.
TITLE_OMISSIONS = {'LIVE-P04': {2, 11, 14}, 'LIVE-P05': {5, 8}, 'LIVE-P06': {2, 11, 14, 17}}
PARTIAL_RULE = {'LIVE-P04': {1, 4, 7, 13, 16}, 'LIVE-P05': {11}, 'LIVE-P06': set()}
AUDIT_OMISSIONS = {'LIVE-P04': {26, 32}, 'LIVE-P05': set(), 'LIVE-P06': set()}
DERIVED_STATED = {
    'LIVE-P04': {1, 2, 5, 8, 11, 13, 14, 17, 20, 23, 26, 29, 32, 35},
    'LIVE-P05': {2, 5, 7, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35},
    'LIVE-P06': {1, 2, 5, 7, 8, 9, 10, 11, 13, 14, 17, 20, 23, 26, 29, 32, 35},
}


def main():
    rows = [json.loads(x) for x in (BASE / 'source_evaluation/source_slots.jsonl').read_text(encoding='utf-8').splitlines() if x.strip()]
    projects = json.loads((BASE / 'dataset/projects.json').read_bytes())
    golds = json.loads((BASE / 'dataset/gold.scoring_only.json').read_bytes())
    all_reviews = []
    for pid, notes in NOTES.items():
        selected = [x for x in rows if x['project_id'] == pid]
        assert len(selected) == len(notes) == 36
        expected_order = [(f'{pid}.{d}.r{r}', phase, scenario) for d in ('A_to_B', 'B_to_A') for r in range(3)
                          for phase in ('initial_generation', 'legal_rebuild') for scenario in ('raw', 'summary', 'multi_source')]
        assert [(x['case_id'], x['phase'], x['scenario']) for x in selected] == expected_order
        project, gold = projects[pid], golds[pid]
        if pid == 'LIVE-P04':
            arithmetic = '117/8=14.625；ceil(14.625)=15箱。8是每箱可容纳的设备数量，而不是箱的数量。'
            value = '15箱'
            assert (117 + 8 - 1) // 8 == 15
        elif pid == 'LIVE-P05':
            arithmetic = '按指定自然日相加规则，date(2027,3,1)+timedelta(days=17)=2027-03-18；不是含首日的17天计数或17个工作日。'
            value = '2027-03-18'
            assert (date(2027, 3, 1) + timedelta(days=17)).isoformat() == value
        else:
            arithmetic = '待验收=已部署-已验收=196-125=71台；不是125-196，也不是196+125。'
            value = '71台'
            assert 196 - 125 == 71
        for index, (row, note) in enumerate(zip(selected, notes)):
            contract_path = BASE / 'qualification_isolated_v1' / row['case_id'] / ('source_' + row['phase']) / 'contract.json'
            contract = json.loads(contract_path.read_bytes())
            body, _ = json.JSONDecoder().raw_decode(contract['prompt'])
            expected_scope = project['permission_timeline'][0 if row['phase'] == 'initial_generation' else 1]['receiver_allowed_source_ids']
            assert [s['source_id'] for s in body['sources']] == expected_scope
            assert all(s in project['sources'] for s in body['sources'])
            omissions, ambiguous, wrong = [], [], []
            if index in TITLE_OMISSIONS[pid]:
                omissions.append({'fact': 'project_title', 'expected': project['project_name'],
                    'status': 'not_explicit_in_standalone_memory', 'basis': '正文没有重复项目名；case/封装上下文可能仍可识别项目，因此不将文本缺省自动等同于下游不可恢复。'})
            if index in PARTIAL_RULE[pid]:
                if pid == 'LIVE-P04':
                    omissions.append({'fact': 'business_rule.divide_device_total_by_capacity_before_rounding',
                        'expected': '所需箱数=ceil(设备总数/每箱容量)', 'status': 'partial_rule_not_explicit',
                        'basis': '保留了容量与向上取整，但未明确说对总数/容量的商取整；正确当前结论或装箱常识可帮助推断，不能据此宣称通用规则完整保留。'})
                else:
                    omissions.append({'fact': 'business_rule.calendar_day_condition', 'expected': '按自然日计算',
                        'status': 'condition_not_explicit', 'basis': '该文本的2027-03-18结果正确，但未明确自然日而非工作日条件；不把当前日期结果等同于完整规则条件。'})
            if index in AUDIT_OMISSIONS[pid]:
                assert row['phase'] == 'initial_generation'
                omissions.append({'fact': 'internal_audit_code', 'expected': gold['restricted_values'][0],
                    'status': 'supplied_initial_fact_omitted', 'basis': '初始实际输入包含该事实，正文未保留；生成时有输入权限，这一遗漏本身不表示越权交付。'})
            supported = True
            if pid == 'LIVE-P04' and index == 7:
                supported = 'unknown'
                ambiguous.append({'quote': '规则为按容量向上取整得箱数',
                                  'reason': '向上取整的对象不清，未明确是设备总数除以容量所得商；其余身份与数值陈述均受支持。'})
            if pid == 'LIVE-P04' and index == 22:
                supported = False
                wrong.append({'quote': '每箱容量为8箱', 'kind': 'wrong_capacity_unit',
                    'supported_alternative': '每箱可装8台设备/每箱容量8；所需箱数输出单位才是箱',
                    'basis': '输入为devices=117、box_capacity=8，并规定设备总数/容量得到箱数；把8解释为箱是错误单位绑定，即使117和8字面都命中。'})
            text_hash = hashlib.sha256(row['memory_text'].encode('utf-8')).hexdigest()
            all_reviews.append({
                'case_id': row['case_id'], 'project_id': pid, 'direction': row['direction'],
                'repeat_index': row['repeat_index'], 'phase': row['phase'], 'scenario': row['scenario'],
                'memory_sha256': text_hash, 'original_memory_sha256': text_hash, 'memory_text': row['memory_text'],
                'judge': 'AI', 'judge_detail': 'Codex contextual reading of every assigned text and its phase-specific frozen inputs; no auxiliary paid model',
                'human_confirmed': False, 'human': False, 'new_model_calls': 0,
                'asserted_facts_supported': supported,
                'input_facts_completely_preserved': not omissions and not wrong and supported is True,
                'text_specific_semantic_review': note,
                'public_relationship_rule_and_arithmetic_basis': arithmetic,
                'explicit_derived_conclusion_stated': index in DERIVED_STATED[pid],
                'explicit_derived_conclusion_check': 'correct' if index in DERIVED_STATED[pid] else 'not_stated_not_counted_as_false_arithmetic',
                'omitted_requested_derived_result': index not in DERIVED_STATED[pid],
                'requested_derived_result': value,
                'derived_omission_scope': '追加指令要求各表示保留推导结果；未给出该结果单列，不计为原始输入事实遗漏。输入仍可能足以供接收方自行计算。',
                'omitted_required_input_facts': omissions, 'ambiguous_wording': ambiguous,
                'unsupported_or_wrong_claims': wrong,
                'input_source_ids': expected_scope, 'input_facts': [{'source_id': s['source_id'], 'facts': s['facts']} for s in body['sources']],
                'source_contract_path': str(contract_path), 'source_contract_sha256': hashlib.sha256(contract_path.read_bytes()).hexdigest(),
                'omission_check_scope': '独立记忆正文中身份/项目名、变量数值与绑定、业务关系及条件、当阶段提供的审计码；同义表达与公式可保留意义，部分隐含规则明确标partial。此标签不等同于下游不可恢复或模型必要因果依赖。',
                'evaluation_unit': 'one memory text nested within project; no atomic-assertion denominator or accuracy is claimed',
                'confidence': 'medium' if supported == 'unknown' or index in PARTIAL_RULE[pid] else 'high',
            })
    assert len(all_reviews) == 108
    assert len({(x['case_id'], x['phase'], x['scenario']) for x in all_reviews}) == 108
    output = BASE / 'source_evaluation/semantic_review_p04_p06.jsonl'
    with output.open('x', encoding='utf-8') as stream:
        for row in all_reviews: stream.write(json.dumps(row, ensure_ascii=False) + '\n')
    print(json.dumps({'reviewed_texts': len(all_reviews),
                      'asserted_supported_true': sum(x['asserted_facts_supported'] is True for x in all_reviews),
                      'asserted_supported_false': sum(x['asserted_facts_supported'] is False for x in all_reviews),
                      'asserted_supported_unknown': sum(x['asserted_facts_supported'] == 'unknown' for x in all_reviews),
                      'texts_with_input_omissions_or_partial_rule': sum(bool(x['omitted_required_input_facts']) for x in all_reviews),
                      'omitted_requested_derived_result': sum(x['omitted_requested_derived_result'] for x in all_reviews),
                      'output': str(output), 'new_model_calls': 0}, ensure_ascii=False))

if __name__ == '__main__': main()
