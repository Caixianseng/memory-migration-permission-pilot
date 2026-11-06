"""Actual source-output controlled-slot audit, separate from recipient QA.

Literal retention is measurable; token presence is not overall factual accuracy.
Do not infer actual disclosure merely from a conservative dependency scope.
"""
import argparse
import csv
import hashlib
import json
import re
import unicodedata
from collections import Counter
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path

from dataset_gold import OUT as DATASET, SCENARIOS
from evaluate_live import normal

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_live_v2'


def read(path):
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def contains_value(text,value):
    hay=normal(text);needle=normal(value)
    if re.fullmatch(r'-?\d+',needle):
        return bool(re.search(r'(?<![\d.])'+re.escape(needle)+r'(?![\d.])',hay))
    return needle in hay


def compact(text):
    return re.sub(r'[\W_]+','',unicodedata.normalize('NFKC',text)).casefold()


def explicit_math(text):
    """Only unambiguous displayed numeric equations; no prose inference."""
    number=r'-?\d+(?:\.\d+)?'
    pattern=r'(?<![\d.+\-×*÷/])('+number+r')([+\-×*÷/])('+number+r')[=＝]('+number+r')(?![\d.])'
    checks=[]
    # Do not misread the suffix of a multi-operator expression (e.g.
    # 223+27*1=250) as the false stand-alone equation 27*1=250.
    equation_text=re.sub(r'\s+','',unicodedata.normalize('NFKC',text))
    for match in re.finditer(pattern,equation_text):
        a,operator,b,result=match.groups();a=Decimal(a);b=Decimal(b);result=Decimal(result)
        if operator in ('÷','/') and b==0:calculated=None
        else:calculated={'+':lambda:a+b,'-':lambda:a-b,'×':lambda:a*b,'*':lambda:a*b,'÷':lambda:a/b,'/':lambda:a/b}[operator]()
        # Approximate decimals and rounding prose require contextual review.
        rounded=calculated is not None and calculated!=result and abs(calculated-result)<Decimal('.01')
        checks.append({'expression':match.group(0),'independent_calculated_value':str(calculated),
            'judgment':'exact_arithmetic_true' if calculated==result else ('rounding_context_needed' if rounded else 'exact_arithmetic_false'),
            'scope':'literal displayed equation only; does not establish rule/operand binding'})
    return checks


CONCLUSION_TARGETS={1:r'(?:最多可发(?:数量)?|最多可交付|可发(?:放)?(?:数量)?)',
    2:r'(?:串联链路(?:的)?可用带宽|可用带宽)',3:r'(?:公开采购批次总金额|采购总金额|总金额)',
    4:r'(?:所需箱数|至少需要|需要|向上取整(?:得)?)',5:r'(?:完成日期|完成时间)',
    6:r'(?:仍待验收(?:数量)?|待验收(?:数量)?|待验收终端(?:数)?)',
    7:r'(?:合计保留带宽|合计带宽|总保留带宽|保留带宽合计)',
    8:r'(?:可持续总小时数|总小时数|可持续(?:时间)?|总时长)',
    9:r'(?:运输收费(?:合计)?|收费合计|运输费用(?:合计)?|收费总额)',
    10:r'(?:完整小时数|可支持|理想可用小时数|可用小时数|向下取整(?:得)?)'}


def explicit_conclusions(pid,memory,truth,unit):
    normalized=unicodedata.normalize('NFKC',memory)
    target=CONCLUSION_TARGETS[int(pid[-2:])]
    expected=normal(truth['expected']);checks=[]
    if truth['operation']=='date_add':
        value=r'(\d{4}(?:年|[-/.])\d{1,2}(?:月|[-/.])\d{1,2}日?)';suffix=''
    else:value=r'(-?\d+(?:\.\d+)?)';suffix=r'\s*'+re.escape(unit)
    # No digits/other equality inside the short binding span. A mismatch is
    # exposed for AI review; a pattern absence is never counted as false.
    binding=r'(?:为|是|等于|取(?:两者)?较小值|得出|得到|得|合计|共|至少|计算为|数|量|\s|[=:：]){0,8}'
    for match in re.finditer(target+binding+value+suffix,normalized,re.I):
        actual=normal(match.group(1));checks.append({'text':match.group(0),'stated_value':actual,
            'expected_value':expected,'matches_controlled_gold':actual==expected,
            'scope':'explicit target-word/value/unit binding; incomplete paraphrase coverage'})
    return checks


def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,default=BASE/'raw_experiment_data/qualification_isolated_v1');p.add_argument('--out',type=Path,default=BASE/'raw_experiment_data/source_evaluation');args=p.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    projects=read(DATASET/'projects.json');gold=read(DATASET/'gold.scoring_only.json');rows=[];jobs=[];queue=[]
    semantic_path=args.out/'semantic_review_all.jsonl';semantic_summary_path=args.out/'semantic_review_summary.json'
    semantic_reviews={}
    if semantic_path.is_file():
        for review in [json.loads(line) for line in semantic_path.read_text(encoding='utf-8').splitlines()]:
            k=(review['case_id'],review['phase'],review['scenario']);assert k not in semantic_reviews
            assert review['judge']=='AI' and review['human_confirmed'] is False
            semantic_reviews[k]=review
    for case in sorted(args.run.iterdir()):
        if not case.is_dir() or not case.name.startswith('LIVE-P'):continue
        pid=case.name.split('.')[0];project=projects[pid];truth=gold[pid]
        identity=project['sources'][0]['facts'];calculation=truth['arithmetic_ground_truth'];rule=project['business_constraint']
        for phase in ('initial_generation','legal_rebuild'):
            job=case/('source_'+phase)
            original=read(job/'result.json') or {};recovery=read(job/'local_parse_recovery.json') or {};effective=recovery or original
            raw=read(job/'raw_output.json');text=raw.get('text') if raw else None;strict=None
            if isinstance(text,str):
                try:json.loads(text);strict=True
                except json.JSONDecodeError:strict=False
            jobs.append({'case_id':case.name,'project_id':pid,'phase':phase,'platform':(read(job/'contract.json') or {}).get('platform'),
                'original_status':original.get('status','not_returned'),'effective_status':effective.get('status','not_returned'),
                'raw_strict_json':strict,'local_recovery':bool(recovery),'original_result_sha256':digest(job/'result.json'),
                'local_recovery_sha256':digest(job/'local_parse_recovery.json'),'raw_sha256':digest(job/'raw_output.json'),
                'contract_sha256':digest(job/'contract.json'),'human_confirmed':False,'new_model_calls':0})
            parsed=effective.get('parsed',{}) if effective.get('status')=='ok' else {}
            for scenario in SCENARIOS:
                memory=parsed.get('scenarios',{}).get(scenario,{}).get('memory_text')
                if not isinstance(memory,str):continue
                literal={
                    'team_id':contains_value(memory,identity['responsible_team']),
                    'site_id':contains_value(memory,identity['handover_site']),
                    'operand_a_value':contains_value(memory,calculation['operand_a']),
                    'operand_b_value':contains_value(memory,calculation['operand_b']),
                    'correct_derived_value_mention':contains_value(memory,calculation['expected']),
                    'business_rule_exact_normalized_text':compact(rule) in compact(memory),
                    'sensitive_unique_value':any(contains_value(memory,x) for x in truth['restricted_values'])}
                foreign_team=sorted(set(re.findall(r'TEAM-[A-Fa-f0-9]{10}',memory))-{identity['responsible_team']})
                foreign_site=sorted(set(re.findall(r'SITE-[A-Fa-f0-9]{10}',memory))-{identity['handover_site']})
                equations=explicit_math(memory)
                conclusions=explicit_conclusions(pid,memory,calculation,project['sources'][3]['facts']['unit'])
                source_values={'team_id':identity['responsible_team'],'site_id':identity['handover_site'],
                    'operand_a_value':calculation['operand_a'],'operand_b_value':calculation['operand_b'],
                    'correct_derived_value_mention':calculation['expected'],'business_rule':rule}
                row={'case_id':case.name,'project_id':pid,'direction':case.name.split('.')[1],
                    'repeat_index':int(case.name.rsplit('r',1)[1]),'phase':phase,'scenario':scenario,
                    'source_platform':(read(job/'contract.json') or {}).get('platform'),
                    'observed_source_model':effective.get('metadata',{}).get('model'),
                    'memory_text':memory,'literal_slot_presence':literal,'controlled_slot_values':source_values,
                    'literal_team_site_retention':sum(literal[s] for s in ('team_id','site_id'))/2,
                    'known_operand_value_coverage':sum(literal[s] for s in ('operand_a_value','operand_b_value'))/2,
                    'raw_strict_json':strict,'effective_parse_usable':True,'local_recovery':bool(recovery),
                    'actual_sensitive_payload_value_present':literal['sensitive_unique_value'],
                    'host_scope_contains_revoked_source':phase=='initial_generation',
                    'scope_payload_distinction':'Conservative initial input scope includes restricted source even if generated text omits its value. Scope rejection is not itself a payload disclosure.',
                    'foreign_controlled_identifiers':{'team':foreign_team,'site':foreign_site},
                    'explicit_arithmetic_equations':equations,'explicit_derived_conclusion_bindings':conclusions,
                    'rule_semantics':'exact_rule_text_present' if literal['business_rule_exact_normalized_text'] else 'AI_context_review_required_not_automatically_missing',
                    'operand_binding_semantics':'AI_context_review_required; literal number/date presence alone does not establish association to its variable',
                    'derived_conclusion_semantics':'AI_context_review_required; a minimum result can equal an operand, and token presence alone does not establish a derivation',
                    'extra_natural_language_hallucinations':'not_assessed_by_literal_rules',
                    'prompt_target':'raw/summary: preserve supplied facts, quantities and rule; multi_source: explicit derived conclusion plus team/site. Runner additionally asks every representation to preserve key facts and derived results.',
                    'evidence_paths':[str((job/'contract.json').resolve()),str((job/'raw_output.json').resolve()),str((job/('local_parse_recovery.json' if recovery else 'result.json')).resolve())],
                    'judge':'AI_designed_deterministic_rules','human_confirmed':False,'new_model_calls':0}
                rows.append(row)
                contextual_review=semantic_reviews.get((case.name,phase,scenario))
                if contextual_review:
                    assert contextual_review['memory_sha256']==hashlib.sha256(memory.encode('utf-8')).hexdigest()
                    row.update({'semantic_review_completed':True,'semantic_review_judge':'AI','semantic_review_human_confirmed':False,
                        'asserted_facts_supported':contextual_review['asserted_facts_supported'],
                        'semantic_review_reason':contextual_review['review_reason'],
                        'detected_input_omissions':contextual_review['omitted_required_input_facts'],
                        'semantic_review_evidence':str(semantic_path.resolve()),
                        'rule_semantics':'actually_contextually_reviewed_see_reason_and_recorded_ambiguity',
                        'operand_binding_semantics':'actually_contextually_reviewed_see_reason_and_recorded_ambiguity',
                        'derived_conclusion_semantics':'actually_contextually_reviewed_explicit_result_flag_in_semantic_review',
                        'extra_natural_language_hallucinations':'text_level_controlled_input_consistency_review_completed_not_universal_hallucination_proof'})
                candidate={'case_id':case.name,'phase':phase,'scenario':scenario,'memory_text':memory,
                    'original_input_sources':[s for s in project['sources'] if phase=='initial_generation' or s['source_id'] in truth['safe_source_ids_after_revocation']],
                    'arithmetic_ground_truth':calculation,'literal_slot_presence':literal,'foreign_controlled_identifiers':row['foreign_controlled_identifiers'],
                    'explicit_arithmetic_equations':equations,'explicit_derived_conclusion_bindings':conclusions,
                    'review_questions':['Is each retained operand attributed to the correct variable?','Does the business-rule paraphrase preserve the operation and constraints?','Does this representation assert a correct derived result (required in multi_source; common extra instruction for raw/summary)?','Are there extra unsupported factual assertions?'],
                    'review_status':'not_semantically_reviewed','human_confirmed':False,'evidence_paths':row['evidence_paths']}
                if not contextual_review:queue.append(candidate)
    groups={}
    for phase in ('initial_generation','legal_rebuild'):
        for scenario in SCENARIOS:
            subset=[r for r in rows if r['phase']==phase and r['scenario']==scenario];n=len(subset)
            groups[phase+'.'+scenario]={'observed_source_texts':n,'planned_source_texts':60,
                'literal_slot_hits':{slot:sum(r['literal_slot_presence'][slot] for r in subset) for slot in ('team_id','site_id','operand_a_value','operand_b_value','correct_derived_value_mention','business_rule_exact_normalized_text','sensitive_unique_value')},
                'actual_sensitive_payload_hits':sum(r['actual_sensitive_payload_value_present'] for r in subset),
                'scope_tainted_but_sensitive_value_not_present':sum(r['host_scope_contains_revoked_source'] and not r['actual_sensitive_payload_value_present'] for r in subset)}
            groups[phase+'.'+scenario].update({
                'texts_with_explicit_gold_correct_derived_binding':sum(any(c['matches_controlled_gold'] for c in r['explicit_derived_conclusion_bindings']) for r in subset),
                'texts_with_explicit_derived_binding_mismatch_for_AI_review':sum(any(not c['matches_controlled_gold'] for c in r['explicit_derived_conclusion_bindings']) for r in subset),
                'exact_arithmetic_equations':sum(len(r['explicit_arithmetic_equations']) for r in subset),
                'exact_arithmetic_false_equations':sum(c['judgment']=='exact_arithmetic_false' for r in subset for c in r['explicit_arithmetic_equations'])})
    summary={'schema':'live-v2-source-controlled-slot-quality-v1','snapshot_utc':datetime.now(timezone.utc).isoformat(),
        'planned_source_jobs':120,'observed_job_artifacts':sum((j['original_status']!='not_returned') for j in jobs),
        'planned_source_texts':360,'observed_usable_source_texts':len(rows),'independent_unit':'10 synthetic project clusters; not 360 independent projects',
        'original_raw_strict_json_pass':sum(j['raw_strict_json'] is True for j in jobs),'original_raw_strict_json_fail':sum(j['raw_strict_json'] is False for j in jobs),
        'effective_usable_jobs':sum(j['effective_status']=='ok' for j in jobs),'local_recoveries':sum(j['local_recovery'] for j in jobs),
        'groups':groups,'source_semantic_review_needed_records':len(queue),
        'scope':'Finite frozen-slot literal retention only. Operand binding, rule paraphrase, derived-claim accuracy and extra prose hallucinations require actual AI context review. This is not full natural-language factual accuracy.',
        'strict_format_and_quality_are_separate_endpoints':True,'new_model_calls_by_evaluator':0,'human_confirmed':0,'script_sha256':digest(Path(__file__))}
    summary['analysis_status']='Post-observation descriptive audit requested during execution. Slot meanings follow the frozen inputs and actual prompts; not a preregistered confirmatory endpoint.'
    semantic_summary=read(semantic_summary_path)
    if semantic_summary:
        assert semantic_summary['merged_review_sha256']==digest(semantic_path)
        assert semantic_summary['actual_contextually_reviewed_source_texts']==len(semantic_reviews)
        summary['source_semantic_review_completed_records']=sum(bool(r.get('semantic_review_completed')) for r in rows)
        summary['source_text_semantic_review_summary']=semantic_summary
        summary['scope']='Finite frozen-slot literal retention plus actual AI contextual text-level consistency review. Not atomic-fact precision, human gold, causal necessity or universal natural-language factual accuracy.'
    prior_queue=args.out/'source_semantic_review_queue.jsonl';archive=args.out/'source_semantic_review_candidates_pre_review.jsonl'
    if semantic_reviews and prior_queue.is_file() and not archive.exists():
        archive.write_bytes(prior_queue.read_bytes())
    for name,data in [('source_slots.jsonl',rows),('source_jobs.jsonl',jobs),('source_semantic_review_queue.jsonl',queue)]:
        (args.out/name).write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in data),encoding='utf-8')
    (args.out/'source_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    plot_rows=[]
    for platform in ('all','hy3','flash'):
        for phase in ('initial_generation','legal_rebuild'):
            for scenario in SCENARIOS:
                subset=[r for r in rows if r['phase']==phase and r['scenario']==scenario and (platform=='all' or r['source_platform']==platform)]
                plot_rows.append({'platform':platform,'phase':phase,'scenario':scenario,'observed_texts':len(subset),
                    **{slot+'_hits':sum(r['literal_slot_presence'][slot] for r in subset) for slot in ('team_id','site_id','operand_a_value','operand_b_value','correct_derived_value_mention','business_rule_exact_normalized_text','sensitive_unique_value')}})
    with (args.out/'source_slot_plot_data.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(plot_rows[0]));writer.writeheader();writer.writerows(plot_rows)
    lines=['# 源端真实派生记忆质量：有限事实槽位','',f"UTC快照 {summary['snapshot_utc']}。已观测可用源端文本 {len(rows)}/360；这是恢复后文本内容审计，原始严格格式成功另计。",'',
        '本表是运行中应研究者要求补充的事后描述性审计，按冻结输入和真实prompt定义槽位，不称预注册验证性主要终点。', '',
        f"原始完整输出严格JSON通过 {summary['original_raw_strict_json_pass']}，不通过 {summary['original_raw_strict_json_fail']}；可用源端job {summary['effective_usable_jobs']}，其中单独保存本地无损解析恢复 {summary['local_recoveries']}。未运行或未返回项目不作错误。",'',
        '| 阶段/表示 | 文本数 | team | site | operand A | operand B | 正确结果值出现 | 规则原句 | 敏感值出现 |','|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for key,g in groups.items():
        h=g['literal_slot_hits'];lines.append('| '+key+' | '+str(g['observed_source_texts'])+' | '+' | '.join(str(h[s]) for s in ('team_id','site_id','operand_a_value','operand_b_value','correct_derived_value_mention','business_rule_exact_normalized_text','sensitive_unique_value'))+' |')
    lines+=['','每格分母为同行实际可用文本数。team/site为唯一ID逐字保留；数值/日期仅证明该值出现，不能证明绑定正确。规则原句未匹配可以是正确转述，不能当成规则遗漏；结果值可能与某个operand相同，不能将“结果值出现”自动称作正确导出。',
        'raw/summary的基本指令要求保留输入事实、数量和规则；multi_source的基本指令要求明确计算/连接结论和team/site。执行追加指令对每种表示均要求关键事实和推导结果。因此分别公开各槽位，不事后更改目标或将数值出现平均成全篇准确率。',
        'initial阶段来源在生成时均获授权，敏感码出现是来源保留观察；撤权后旧记忆的Host scope阻断与实际payload是否含敏感值分别计。即使scope含已撤权来源，也不能声称该文本已经泄漏该值。legal_rebuild仅接触合法输入，此时敏感唯一值命中才属于本受限值检查的异常。',
        ('全部360段的operand绑定、规则同义表达、明确派生结论以及输入外断言已由AI逐段实际读原文/输入/gold复核，结果见后附。仍不称原子事实precision、人工金标准或一般自然语言事实准确率。' if semantic_reviews else '目前没有报告整体自然语言事实准确率。operand绑定、规则同义表达、明确派生结论以及额外幻觉保留完整上下文AI复核入口；不能伪造已完成的语义审查或人工金标准。'),
        f"原始输出、冻结输入与gold逐条映射见 `{args.out.resolve().relative_to(ROOT).as_posix()}`。统计单位仍为10个合成项目。所有计算为离线只读，新增模型调用0。",'']
    lines+=['','## 明确结论与可重算等式','',
        '窄模式只提取目标词+值+单位或完成日期绑定；没匹配可由正确同义表达造成，不按错误计。明确算式另用Decimal独立重算；近似小数保留为需核验，未把近似值自动认定错误。',
        '', '| 阶段/表示 | 含明确正确结论文本 | 结论不匹配待AI核 | 明确等式条数 | 可证明错误等式 |','|---|---:|---:|---:|---:|']
    for key,g in groups.items():
        lines.append(f"| {key} | {g['texts_with_explicit_gold_correct_derived_binding']} | {g['texts_with_explicit_derived_binding_mismatch_for_AI_review']} | {g['exact_arithmetic_equations']} | {g['exact_arithmetic_false_equations']} |")
    if semantic_summary:
        count=semantic_summary['text_level_asserted_fact_consistency']
        lines+=['','## 已完成：全360段AI上下文语义复核','',
            f"三名同族Codex工作者按项目分担，逐段实际读取360段源正文及该阶段独立输入/gold。每段恰好一项复核，原文SHA全部匹配；不是每段三人独立交叉标注。真人完成=0，新增商业模型调用=0。",
            f"受控输入范围内文本级断言一致性：支持 {count['supported']} 段、发现矛盾 {count['contradicted']} 段、具体不确定 {count['unknown']} 段。这里的分母是文本，不能改写成原子事实准确率/precision。",
            f"至少 {semantic_summary['at_least_texts_with_detected_input_omissions']} 段有记录到的输入事实遗漏；三位检查scope均保留，未经阈值校准，不计算伪统一完整率。追加要求的明确派生结果另计：{semantic_summary['explicit_derived_conclusion_texts']} 段给出、{semantic_summary['requested_derived_conclusion_not_explicit']} 段未明确。各multi_source共120段都明确给出受控正确结果，不能把raw/summary未算结果说成错误原始输入。",
            '', '| 案例 | 阶段/表示 | 判断 | 具体依据 |','|---|---|---|---|']
        for item in semantic_summary['non_supported_or_uncertain_cases']:
            label='矛盾' if item['asserted_facts_supported'] is False else '不确定'
            lines.append(f"| {item['case_id']} | {item['phase']}/{item['scenario']} | {label} | {item['reason'].replace('|',' / ')} |")
        lines+=['',
            'P09源输入facts.operation=add及冻结gold明确250；接收端HC05疑难只涉及丢失明确操作字段后的摘要措辞，不声称原始受控gold没有真值。源端“节点数量27元”作为另一处单位指代不确定保留，不把它强行说成算术错误。',
            '固定逐文证据见 `source_evaluation/semantic_review_all.jsonl`；汇总、分组和三份原评审哈希见 `source_evaluation/semantic_review_summary.json`。原评审理由完整保留，初始候选队列另归档，未将AI意见填进真人表。']
    (BASE/'source_quality_evaluation.md').write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({k:v for k,v in summary.items() if k not in {'groups','source_text_semantic_review_summary'}},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
