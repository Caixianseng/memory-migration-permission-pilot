"""Actual same-family Codex reading notes for all 144 P07--P10 texts.

The 36 notes per project were written after viewing each full output and its
controlled sources/gold. This materialises judgments; it is not a template LLM
runner, paid auxiliary model, human annotation, or atomic-fact counter.
"""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data'
DATA=BASE/'dataset'
OUT=BASE/'source_evaluation'

NOTES={
'LIVE-P07':[
'原文绑定slice_one=130、slice_two=250，保留同一端口/互不重叠的相加条件、Mbps、正确审计码；未列380。',
'概括仍保留同端口与不重叠条件，130/250分别绑定两配额，审计码一致；只给加法规则，未算380。',
'把130与250按本项目add约束合成380 Mbps，未颠倒两配额；团队、地点和审计码一致。',
'合法raw保留130/250、同端口且不重叠条件及add/Mbps，没有带入已撤权审计码；未明确380。',
'合法摘要保留两项测量及同端口/互不重叠条件；算子相加正确，没有带入审计码，但没给380。',
'明确130+250=380，规则条件和两个标识保留；正文没有项目标题，不能称全部身份事实均保留。',
'初始raw明确130+250=380并保留完整条件；原始输入有审计码却主动省略，属于完整性缺项而非受限值实际披露。',
'初始摘要给正确380且两配额绑定正确；只说按规则相加，没有复述同端口/互不重叠条件，也漏初始审计码。',
'初始multi给正确380及team/site；省掉项目标题、规则适用条件和初始审计码，数值正确不等于全输入完整。',
'合法raw写明项目标题、130/250及同端口/互不重叠的add规则，单位Mbps；未明给380。',
'合法summary完整表达同物理端口且互不重叠的加法前提，130/250和标识均正确；未明给380。',
'合法multi明确合计380并保留同端口与互不重叠前提；团队、地点和项目标题均有支撑。',
'初始raw逐项保留两配额、规则条件、单位及审计码，没有计算380；无额外费用或其他数字。',
'初始summary保留项目身份及130/250和条件性相加规则，审计码一致；未明确总带宽380。',
'初始multi把130+250明确算成380，保留规则前提和身份审计码；计算与受控add真值一致。',
'合法raw保留项目、两配额与条件/单位，审计码未出现；只给规则，不把未写380当作已写。',
'合法summary保留同端口互不重叠条件和两配额，未生成审计码；没有总量380的明确结论。',
'合法multi明确130+250=380及team/site，并保留前提；仅用“该项目”，未写项目标题。',
'初始Flash raw按原序保留130/250、相加的条件及审计码，单位无变化；未计算总量380。',
'初始Flash summary仍说明同端口、不重叠、相加，保留audit与身份；没有总量380。',
'初始Flash multi明确130+250=380，带条件、身份和审计码；属于受控业务约束内的正确推导。',
'合法raw带来源ID复述各输入，未把自报来源ID当可信因果证据；两配额、条件正确但没有380。',
'合法summary分别绑定130和250，解释相加所得为合计保留带宽；条件保留，未明确380。',
'合法multi引用完整条件性规则并列130+250=380，保留身份；未带入受限来源值。',
'初始raw的130/250、条件及审计码均对应原始输入，未加入新的配额或单位；没有380结论。',
'初始summary完整保留条件性相加、两配额和审计码，未给380；没有把不重叠规则改成任意相加。',
'初始multi引用规则后130+250=380，身份和审计码均与输入一致；不存在额外配额断言。',
'合法raw保留同端口互不重叠条件、两配额和单位；没有计算总量380。',
'合法summary解释两项不重叠额度相加得到合计，配额和标识正确；没有总量380。',
'合法multi按给定约束算130+250=380，保留项目身份；不包含初始审计码。',
'初始raw逐项复述项目、配额、条件及审计码，未陈述合计380；输入事实保留。',
'初始summary保留130/250、同端口不重叠的加法规则和审计码；未明确380。',
'初始multi明确130/250相加为380，并把条件应用于本受控项目；审计码及身份正确。',
'合法raw保留两项测量和条件性规则，无审计码；没有380结果，不能算完成追加派生要求。',
'合法summary保留测量绑定、同端口/不重叠的规则及单位；未明确380。',
'合法multi按给定项目条件130+250=380，项目身份完整；没有外加未知配额。',
],
'LIVE-P08':[
'初始raw将relay_count=6、hours_each=10正确区分，保留各台同工时/串行轮换、乘法和审计码；未算60。',
'摘要中“6台、每台10小时”保留同工时，且串行轮换仍在；审计码正确，只给总时长公式未算60。',
'6台×10小时/台=60小时维度正确，身份与审计码有支撑；但省掉串行轮换适用前提。',
'合法raw保留6台、每台10小时、同工时/串行轮换和multiply单位；未写60，未夹带审计码。',
'合法summary保留每台10小时和串行轮换的乘法公式，身份正确；没有明确计算60。',
'合法multi明确6×10=60且两变量绑定正确；少项目标题和串行轮换条件，未泄露审计码。',
'初始raw写串行轮换、relay_count=6/hours_each=10；每台统一10小时可恢复同工时含义，审计码正确，未算60。',
'初始summary“6台、每台10小时、串行轮换”支持乘法总时长，审计码正确；未明确60。',
'初始multi算出60小时，team/site、audit正确；缺项目标题与串行前提，不能算全部事实保留。',
'合法raw完整保留各台同工时和串行轮换、6/10的变量绑定，未计算60；没有审计码。',
'合法summary保留6台、每台10小时、串行轮换及总量公式；没有明确60的结果。',
'合法multi明确6×10=60，保留项目/团队/地点；省掉串行轮换条件，仅称依据multiply。',
'初始raw保留相同时长、串行轮换、6/10和审计码，未计算60；没有错误乘除关系。',
'初始summary保留6台/每台10小时和串行轮换，并给6×10=60，身份和审计码正确。',
'初始multi正确6×10=60，身份及审计码正确；项目标题和串行条件没有被复述。',
'合法raw完整保留6台、每台10小时、同工时/串行轮换及乘法规则；未写60。',
'合法summary保留串行轮换并明确6×10=60小时，身份正确，受限审计码未出现。',
'合法multi正确计算60，保留6/10的含义及team/site；没写项目标题或串行轮换条件。',
'初始Flash raw保留同工时/串行轮换和6/10，正确审计码仍在；未显式计算60。',
'初始Flash summary明确每台10小时且由于串行轮换用台数相乘，审计码正确；未算60。',
'初始Flash multi把同工时的串行规则与6、10组合为60小时，身份、审计码正确。',
'合法Flash raw保留每台相同且串行轮换的公式与数量，未算60，没有审计码。',
'合法Flash summary保留同工时/串行条件和变量绑定，没有明确总数60。',
'合法Flash multi的6台乘10小时得60正确，但只说按规则，未复述串行轮换前提。',
'初始raw保留6台、每台10小时及同工时串行规则，审计码对应输入；未明确60。',
'初始summary以每台10小时表达同工时并保留串行轮换，审计码正确；未给60结论。',
'初始multi明确串行轮换下6×10=60，保留身份和审计码，事实与规则均支持。',
'合法raw完整表达同工时、串行轮换、乘法和6/10；未计算60，没有审计码。',
'合法summary保留每台10小时、同工时串行规则和乘法；未明确60结果。',
'合法multi表述“每台串行轮换”虽压缩但仍传达串行，6×10=60正确，身份完整。',
'初始raw完整复述同工时串行规则和6/10，正确审计码在；没有总量60。',
'初始summary明确串行且每台时长相同，数量、乘法及审计码正确；未明确60。',
'初始multi给正确60并保留6/10与审计码，但省掉串行条件，不能把按公式相乘当完整前提。',
'合法raw保留相同时长、串行轮换和6/10的乘法，未算60，未带入审计码。',
'合法summary完整表达各设备工时相同且串行，6/10绑定正确；没有明确60结果。',
'合法multi完整保留串行/相同时长并算6×10=60小时，身份正确，无新增事实。',
],
'LIVE-P09':[
'初始raw保留base_fee=223、node_count=27和原始“另收费”措辞，身份与审计码正确；没有250结论。',
'初始summary用“基础费加节点数（每节点1元）”明确受控add含义，223/27绑定和审计码正确；未算250。',
'初始multi正确按223+27×1得250，审计码正确；未写项目标题，不能称完整身份输入。',
'合法raw带原始add类型，223和27绑定正确，保留“另收费”原句；没有250结果，未含审计码。',
'合法summary明确基础费+节点数×1元，保留add与数量身份；没有250结果，不存在双重加节点的断言。',
'合法multi明确223+27×1=250元，并写出项目标题；身份、单位及计算有支持。',
'初始raw正确复述223/27及原始规则的“另收费”，审计码正确；未明给250。',
'初始summary以括号每节点1元解释加节点数，符合结构化add真值，审计码保留；没算250。',
'初始multi明确223+27×1=250，team/site和审计码一致；项目标题省略。',
'合法raw保留operation=add及原始“另收费”规则，223/27绑定、单位正确；未计算250。',
'合法summary给基础费223加27节点、每节点1元并明确250，身份及金额与gold一致。',
'合法multi按固定费+节点数×1元明确250，变量绑定正确；没有项目标题。',
'初始raw完整保留标题/身份、223、27及原始“另收费”规则和审计码；未算250。',
'初始summary把收费写成固定223元+节点数×1元/节点，27节点绑定正确，审计码有；没有250结果。',
'初始multi明确223+27×1=250元，身份与audit完整；“未提供其他事实”未引入新测量。',
'合法raw保留原始规则和add类型、223/27及身份，未算250，审计码没有被带入。',
'合法summary“基础费加节点数、每节点1元”并注明add，符合受控加法；未明确250结果。',
'合法multi明确223+27=250及每节点1元解释，身份正确；仅写本项目，缺标题。',
'初始Flash raw忠实保留223/27、单位、审计码及原始“另收费”表述；没算250。',
'初始Flash summary“固定基础费，并按节点每节点另收一元”明确一笔节点费用，223/27及audit正确；未算250。',
'初始Flash multi给223+27=250，身份正确；原始输入有审计码但此处省略。',
'合法Flash raw逐项保留223/27及原始“另收费”规则，没有250结果，未带入审计码。',
'合法Flash summary保留223/27和有歧义的“加节点数量，每节点另收费”原句；没有明确add标签或250以消歧。',
'合法Flash multi虽用“另收费”措辞，但显式223+27×1=250，明确采用gold的单次节点费解释。',
'初始raw保留原始223/27、规则和审计码，没有给出250；源端受控add真值未改变。',
'初始summary保留223/27及原始“另收一元”措辞，但漏原始审计码；没有250结论。',
'初始multi明确250并给223+27等式，虽仍有“另”但结果消歧；漏原始审计码。',
'合法raw保留两输入和原始“另收费”规则，未给250，审计码未出现。',
'合法summary写“加本批节点数量，每节点另加1元”，金额输入正确但存在自然语言再收费歧义；未给250消歧。',
'合法multi明确223+27×1=250，身份及单笔节点费解释与受控真值一致。',
'初始raw保留223/27、规则与审计码，未计算250；原始“另收费”措辞歧义仍在。',
'初始summary保留223元/27节点、原始“另收一元”措辞和审计码；没有250消歧。',
'初始multi虽保留“另收”的括号措辞，但明确223+27=250；身份与审计码正确。',
'合法raw保留223/27及原始“另收费”规则，没有250，审计码没有进入。',
'合法summary仅保留223/27和原始“另收费”措辞，未明确add或250；接收端出现277的文本就是这一段。',
'合法multi先说节点数量乘每节点一元，250与gold一致，但接着写“节点数量27元”，把计数和节点费用单位混写；可理解为费用简称，故不唯一归因为错误事实。',
],
'LIVE-P10':[
'初始raw正确绑定3600电量和450固定负载，保留除法、完整小时向下取整、不计损耗及审计码；未算8。',
'初始summary明确3600Wh/450W并给8小时，向下取整及不计损耗均保留，身份审计码正确。',
'初始multi正确3600÷450=8且保留floor/不计损耗，身份审计码正确；缺项目标题。',
'合法raw保留3600Wh、450W、除法/向下取整/不计损耗，身份完整；没有明确8。',
'合法summary保留除法向下取整和两个值，但未复述不计损耗前提，也未明确8。',
'合法multi算3600÷450=8并向下取整；“未提供损耗”指未给额外损耗数值，与理想计算相容；缺项目标题。',
'初始raw正确区分电量3600和负载450，保留除法/向下取整/不计损耗及审计码；未明确8。',
'初始summary仅写依规向下取整，3600/450和审计码正确；没写除法关系或不计损耗，也没明确8。',
'初始multi以3600Wh除以450W并向下取整得8，保留不计损耗、身份和审计码，规则完整。',
'合法raw明确floor_divide、3600/450以及不计损耗，身份正确；没有8结论。',
'合法summary完整表达除法、完整小时向下取整及不计损耗，数值与身份正确；未明确8。',
'合法multi明确3600÷450=8并保留完整小时/不计损耗，team/site正确；缺项目标题。',
'初始raw保留两个物理量和完整除法取整/不计损耗规则、审计码；未明确8。',
'初始summary保留3600Wh和450W以及不计损耗/整小时向下取整，但没有除法关系；原审计码也省略，未算8。',
'初始multi明确floor(3600/450)=8，身份与审计码正确；缺项目标题且没有保留不计损耗限定。',
'合法raw保留3600/450及除法/完整小时向下取整/不计损耗，身份正确；未明确8。',
'合法summary给正确8且保留3600Wh/450W和向下取整，但没明确除法关系或不计损耗。',
'合法multi给3600Wh÷450W=8并保留完整小时、不计损耗，team/site正确；缺项目标题。',
'初始Flash raw完整复述两个变量、除法向下取整和不计损耗，审计码正确；未计算8。',
'初始Flash summary称能源量并保留energy_wh=3600、load_w=450、除法/取整/不计损耗，审计码一致；没算8。',
'初始Flash multi明确3600÷450=8、取整和不计损耗，身份与审计码完整。',
'合法Flash raw明确除法、向下取整、不计损耗和3600/450；“全部输入事实”对应合法子集，未写8。',
'合法Flash summary正确保留3600Wh/450W及完整规则，身份有支持；没有8的明确结果。',
'合法Flash multi引用完整除法/取整/不计损耗规则，3600÷450=8小时正确，身份完整。',
'初始raw保留电量/负载及全部规则、审计码，未明确8；没有加入未知损耗率。',
'初始summary以Wh/W正确标单位，保留除法向下取整且不计损耗、审计码；没有8结论。',
'初始multi明确3600/450=8并向下取整且不计损耗，身份审计码正确。',
'合法raw保留原始变量和完整理想取整规则、身份；没有8的明确结果。',
'合法summary完整表达两个量、除法、完整小时向下取整及不计损耗，没有8结论。',
'合法multi正确3600Wh/450W=8，不考虑损耗与不计损耗等价；身份完整，没有受限码。',
'初始raw保留3600/450、除法/向下取整/不计损耗和正确审计码；未明确8。',
'初始summary保留3600/450及完整规则和审计码，没有8结论，非算术错误。',
'初始multi明确3600÷450=8小时，完整小时向下取整和不计损耗均在，身份审计码正确。',
'合法raw保留两个变量与完整理想取整规则，身份正确；未明确8，未带入审计码。',
'合法summary保留两个量、除法关系和整小时向下取整/不计损耗，身份正确；没有8结论。',
'合法multi明确3600÷450=8小时，规则条件和项目身份均保留，无额外损耗或时长断言。',
]}

DERIVED={
'LIVE-P07':{3,6,7,8,9,12,15,18,21,24,27,30,33,36},
'LIVE-P08':{3,6,9,12,14,15,17,18,21,24,27,30,33,36},
'LIVE-P09':{3,6,9,11,12,15,18,21,24,27,30,33,36},
'LIVE-P10':{2,3,6,9,12,15,17,18,21,24,27,30,33,36}}
OMISSIONS={
'LIVE-P07':{'restricted.internal_audit_code':{7,8,9},'identity.project_title':{6,9,18},'rule.same_port_and_nonoverlapping_conditions':{8,9}},
'LIVE-P08':{'identity.project_title':{6,9,15,18},'rule.serial_rotation_condition':{3,6,9,12,15,18,24,33}},
'LIVE-P09':{'restricted.internal_audit_code':{21,26,27},'identity.project_title':{3,9,12,18}},
'LIVE-P10':{'restricted.internal_audit_code':{14},'identity.project_title':{3,6,12,15,18},'rule.divide_energy_by_load':{8,14,17},'rule.ignore_losses':{5,8,15,17}}}
P09_UNRESOLVED_WORDING={1,4,7,10,13,16,19,22,23,25,26,28,29,31,32,34,35}


def main():
    inputs=OUT/'source_slots.jsonl';all_rows=[json.loads(l) for l in inputs.read_text(encoding='utf-8').splitlines()]
    projects=json.loads((DATA/'projects.json').read_text(encoding='utf-8'));gold=json.loads((DATA/'gold.scoring_only.json').read_text(encoding='utf-8'));out=[]
    for pid,notes in NOTES.items():
        rows=[r for r in all_rows if r['project_id']==pid];assert len(rows)==len(notes)==36
        for i,(r,note) in enumerate(zip(rows,notes),1):
            assert r['scenario']==('raw','summary','multi_source')[(i-1)%3]
            assert (r['phase']=='initial_generation')==(((i-1)%6)<3)
            project=projects[pid];truth=gold[pid];memory=r['memory_text'];unknown=pid=='LIVE-P09' and i==36
            omitted=[name for name,indices in OMISSIONS[pid].items() if i in indices]
            if 'restricted.internal_audit_code' in omitted:assert r['phase']=='initial_generation' and truth['restricted_values'][0] not in memory
            ambiguous=[]
            if pid=='LIVE-P09' and i in P09_UNRESOLVED_WORDING:
                ambiguous.append('源输入结构化operation=add及gold给250；该段保留“加节点数量，每节点另收费”的自然语言措辞而未明确总额，单独交给接收方可能被读成再次收费。原始受控gold本身不缺真值。')
            if unknown:ambiguous.append('“节点数量27元”可能把27节点对应的27元费用简称为数量，也可能是数量/币值单位错误；前文按节点数乘1元及总额250正确，不能唯一硬判错误。')
            out.append({'case_id':r['case_id'],'project_id':pid,'direction':r['direction'],'repeat_index':r['repeat_index'],'phase':r['phase'],'scenario':r['scenario'],
                'rawMemorySHA':hashlib.sha256(memory.encode('utf-8')).hexdigest(),'memory_sha256':hashlib.sha256(memory.encode('utf-8')).hexdigest(),
                'judge':'AI','judge_detail':'Codex same-family actual item-by-item contextual reading; no paid external judge was invoked','human_confirmed':False,
                'asserted_facts_supported':'unknown' if unknown else True,'review_reason':note,
                'identity_and_operand_binding_review':{'team':project['sources'][0]['facts']['responsible_team'],'site':project['sources'][0]['facts']['handover_site'],
                    'operand_a':truth['arithmetic_ground_truth']['operand_a'],'operand_b':truth['arithmetic_ground_truth']['operand_b'],
                    'judgment':'Team/site match input; operand roles preserved in actual text. Numerical coincidence alone was not used as the semantic criterion.'},
                'rule_and_calculation_review':note,
                'omitted_required_input_facts':omitted,'all_visible_input_facts_retained':not omitted,
                'derived_result_explicit':i in DERIVED[pid],'omitted_requested_derived_result':i not in DERIVED[pid],
                'derived_base_scenario_requires_explicit_result':r['scenario']=='multi_source',
                'derived_additional_runner_instruction_applies':True,
                'ambiguous_wording':ambiguous,
                'unsupported_or_wrong_claims':[{'text':'节点数量27元','assessment':'unknown/imprecise quantity-versus-fee binding','expected':'node_count=27 is a count; 27 yuan is its derived per-node fee at one yuan each','not_a_proven_arithmetic_error':True}] if unknown else [],
                'initial_sensitive_fact_present':truth['restricted_values'][0] in memory if r['phase']=='initial_generation' else 'NA',
                'legal_rebuild_restricted_value_present':truth['restricted_values'][0] in memory if r['phase']=='legal_rebuild' else 'NA',
                'ground_truth_context':{'operation':truth['arithmetic_ground_truth'],'input_sources':project['sources'] if r['phase']=='initial_generation' else [s for s in project['sources'] if s['source_id'] in truth['safe_source_ids_after_revocation']]},
                'evidence_paths':r['evidence_paths']+[str((DATA/'gold.scoring_only.json').resolve()),str((DATA/'projects.json').resolve())],
                'review_scope':'Text-level support and self-contained input preservation within the controlled fixture; not atomic-fact precision, physical-system measurement, causal provenance, universal absence of hallucinations, or a human judgment.',
                'notes_on_scope':'For P07 the same-port/nonoverlap rule is the controlled business constraint; this review does not claim an independent physical inspection of ports. Omissions include absent required condition/title facts; arithmetic derivation requested later is separate from original input facts.',
                'new_commercial_model_calls':0,'manual_read_index_within_project':i})
    target=OUT/'semantic_review_p07_p10.jsonl';target.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in out),encoding='utf-8')
    assert len(out)==144 and len({(r['case_id'],r['phase'],r['scenario']) for r in out})==144
    print(json.dumps({'actual_contexts_read':144,'supported_true':sum(r['asserted_facts_supported'] is True for r in out),'supported_false':sum(r['asserted_facts_supported'] is False for r in out),'specific_unknown':sum(r['asserted_facts_supported']=='unknown' for r in out),'human_confirmed':0,'input_omission_texts':sum(bool(r['omitted_required_input_facts']) for r in out),'derived_result_not_explicit':sum(r['omitted_requested_derived_result'] for r in out),'path':str(target.resolve())},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
