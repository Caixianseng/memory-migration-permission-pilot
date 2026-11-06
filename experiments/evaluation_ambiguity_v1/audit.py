"""Append-only evaluation audit. Offline; never changes frozen inputs or scores."""
import argparse
import csv
import hashlib
import json
import random
import shutil
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'research_paper_v1/evaluation_ambiguity_audit_20261106'
HIST = ROOT / 'research_paper_v1/paper_final/evidence'
LIVE = ROOT / 'research_paper_v1/paper_live_v2/raw_experiment_data'
PUB = ROOT / 'benchmarks/persistent_exchange_v1_public_20261105'
NEW_LABELS = ['Ambiguous Instruction', 'Ground Truth Conflict', 'Insufficient Information', 'Defensible Alternative Interpretation']


def load(p):
    return json.loads(p.read_text(encoding='utf-8-sig'))


def lines(p):
    return [json.loads(s) for s in p.read_text(encoding='utf-8-sig').splitlines() if s.strip()]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write_json(p, x):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(x, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def write_lines(p, rows):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')


def write_csv(p, rows, fields=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    fields = fields or list(rows[0])
    with p.open('w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k,v in row.items()})


def snapshot():
    """Hash old evaluations, source exports, model records, contracts and outputs."""
    dest = OUT / 'input_manifest_before.json'
    if dest.exists():
        raise SystemExit('Existing baseline preserved; do not overwrite it.')
    paths = set((ROOT/'research_paper_v1/paper_final').rglob('*'))
    paths |= set(PUB.rglob('*'))
    for folder in ['dataset', 'evaluation', 'source_evaluation']:
        paths |= set((LIVE/folder).rglob('*'))
    for case in (LIVE/'qualification_isolated_v1').glob('LIVE-P*'):
        for name in ['evaluation_records.json', 'delivery_records.json', 'permission_events.json', 'complete.json']:
            p = case/name
            if p.is_file(): paths.add(p)
        for job in case.iterdir():
            if not job.is_dir() or job.name == 'persistent': continue
            for name in ['contract.json', 'raw_output.json', 'result.json', 'local_parse_recovery.json']:
                p = job/name
                if p.is_file(): paths.add(p)
    data = {str(p.relative_to(ROOT)).replace('\\','/'): sha(p) for p in sorted(paths) if p.is_file() and '__pycache__' not in p.parts}
    write_json(dest, {'date_local':'2026-11-06','files':data,'paid_calls':0})
    print(json.dumps({'snapshot_files':len(data),'output':str(dest)},ensure_ascii=False))


def ci(values):
    if len(values)<2:
        return None
    rng = random.Random(2026110609)
    samples = sorted(statistics.fmean(rng.choices(values, k=len(values))) for _ in range(5000))
    def quantile(p):
        pos = (len(samples)-1)*p
        a = int(pos); b = min(a+1,len(samples)-1)
        return samples[a] + (samples[b]-samples[a])*(pos-a)
    return [quantile(.025),quantile(.975)]


def rates(rows, score_key, project_key, condition_keys=()):
    groups = defaultdict(list)
    if condition_keys:
        cells=defaultdict(list)
        for r in rows: cells[(r[project_key],*(r[k] for k in condition_keys))].append(float(r[score_key]))
        for key,values in cells.items(): groups[key[0]].append(statistics.fmean(values))
    else:
        for r in rows: groups[r[project_key]].append(float(r[score_key]))
    values = [statistics.fmean(v) for v in groups.values()]
    return {'correct':sum(float(r[score_key]) for r in rows),'fields':len(rows),
            'field_weighted_accuracy':statistics.fmean(float(r[score_key]) for r in rows) if rows else None,
            'project_macro_accuracy':statistics.fmean(values) if values else None,
            'project_bootstrap_ci95':ci(values) if values else None,
            'project_count':len(groups),'bootstrap_draws':5000,'seed':2026110609,
            'within_project_condition_keys':list(condition_keys),
            'inference_scope':'exploratory descriptive project-cluster bootstrap; pointwise, not simultaneous'}


def historical():
    instrument = load(HIST/'human/items.blinded.json')
    old = {r['item_id']:r for r in lines(HIST/'ai_evaluation/final.jsonl')}
    original = load(PUB/'evaluation_report.public.json')
    frozen = {(r['case_id'],r['direction'],r['arm'],r['question_id']):r for r in original['per_question']}
    reviews = []
    for name in ['a','b','c']:
        reviews.extend(lines(OUT/f'reviews/partition_{name}.jsonl'))
    assert len(reviews)==768 and len({r['item_id'] for r in reviews})==768
    byid = {r['item_id']:r for r in reviews}
    assert set(byid)==set(old)=={r['item_id'] for r in instrument['items']}
    rows = []
    for item in instrument['items']:
        ident = item['item_id']; prior = old[ident]; review = byid[ident]
        f = frozen[tuple(prior[k] for k in ['case_id','direction','arm','question_id'])]
        labels = review.get('labels',review.get('new_labels',review))
        new = {k:labels[k] for k in NEW_LABELS}
        rows.append({'cohort':'historical_768','item_id':ident,'project_id':prior['case_id'],
          'direction':prior['direction'],'method_or_representation':prior['arm'],'question_id':prior['question_id'],
          'question':item['question'],'actual_answer':item['answer'],'frozen_reference_answer':item['reference_answer'],
          'frozen_expected_at_delivery':item['reference_expected_at_delivery'],'primary_eligible':item['primary_eligible'],
          'frozen_reference_value_coverage':f['legal_value_coverage'],
          'prior_AI_semantic_fact_coverage':prior['legal_score'],'original_labels':prior['labels'],
          'final_labels':{**prior['labels'],**new},
          **new,'definite_model_error':review['definite_model_error'],
          'attribution_status': 'UNKNOWN' if prior['labels'].get('Unverifiable')==1 else 'not_reopened',
          'confidence':prior['confidence'],'reason':review['reason'],'evidence_paths':review['evidence_paths'],
          'judge':'Codex AI; three disjoint partitions, one AI review per item',
          'human_confirmed':False,'needs_human':review['needs_human'],
          'historical_cause_question_pending':prior['labels'].get('Unverifiable')==1,
          'alternative_interpretations':review.get('alternative_interpretations',[])})
    write_csv(OUT/'revised_evaluation_results.csv',rows)
    write_lines(OUT/'revised_evaluation_results.jsonl',rows)
    # Old endpoint is normalized required-value coverage, not literal-string or arithmetic accuracy.
    legal = [r for r in rows if r['primary_eligible']]
    stats = {'items':768,'projects':12,'numeric_computation_questions':0,
             'new_labels':{k:sum(r[k]==1 for r in rows) for k in NEW_LABELS},
             'definite_model_errors':sum(r['definite_model_error']==1 for r in rows),
             'old_Unverifiable_retained':sum(r['original_labels'].get('Unverifiable')==1 for r in rows),
             'new_ambiguity_human_questions':sum(bool(r['needs_human']) for r in rows),'human_confirmed':0,
             'frozen_legal_value_coverage':rates(legal,'frozen_reference_value_coverage','project_id',('direction','method_or_representation')),
             'old_project_weighted_legal_utility':{k:v['legal_utility'] for k,v in original['summary'].items()},
             'by_arm':{arm:rates([r for r in legal if r['method_or_representation']==arm],
                               'frozen_reference_value_coverage','project_id',('direction','method_or_representation')) for arm in original['summary']}}
    for arm,value in stats['by_arm'].items():
        assert abs(value['project_macro_accuracy']-original['summary'][arm]['legal_utility'])<1e-12
    write_json(OUT/'historical_summary.json',stats)
    return rows, stats


def live():
    gold = load(LIVE/'dataset/gold.scoring_only.json')
    scores = lines(LIVE/'evaluation/question_scores.jsonl')
    contexts = {}
    for f in sorted((LIVE/'qualification_isolated_v1').glob('LIVE-P*/evaluation_records.json')):
        for r in load(f):
            if r['phase']=='legal_successor':
                contexts[(r['project_id'],r['direction'],r['repeat_index'],r['scenario'])] = (r,f)
    assert len(contexts)==180 and len(scores)==720
    # Explicit case registration follows actual reading of all 180 contexts / 720 fields.
    # "add" alone does not specify whether the Chinese "另" repeats a surcharge;
    # only an explicit single-charge formula/result is treated as disambiguation here.
    ambiguous = {('LIVE-P09','A_to_B',rep,'raw') for rep in range(3)}
    ambiguous |= {('LIVE-P09','B_to_A',rep,scenario) for rep in range(3) for scenario in ['raw','summary']}
    human_key = ('LIVE-P09','B_to_A',2,'summary','LIVE-P09-Q3')
    confirmation = {
      'schema':'researcher-adjudication-v1','date_local':'2026-11-06',
      'source':'User reply to request_user_input_async call_b52102d77ed84885ba6c4840e48545c5',
      'scope':'Only LIVE-P09.B_to_A.r2 / legal_successor / summary / LIVE-P09-Q3',
      'original_rule':'每批固定基础费加本批节点数量，每节点另收费一元',
      'frozen_ground_truth':'250','actual_answer':'277','frozen_score':0,
      'researcher_confirmed':'该规则存在合理的重复收费解释；277并非毫无依据；不明确认定为模型计算错误。',
      'interpretation_A':'223 + 27 × 1 = 250元',
      'interpretation_B':'223 + 27 + 27 × 1 = 277元',
      'constraints':['原始数据不得修改','数值精确匹配保持0','不将此人工确认推广为其他案例的人工标签',
                     '合理替代解释不自动等于模型回答正确','模型实际计算过程未输出，不能推断其内部推导']}
    write_json(OUT/'live_confirmation/researcher_confirmation.json',confirmation)
    rows=[]; reviewed_contexts=[]
    for r in scores:
        key=(r['project_id'],r['direction'],r['repeat_index'],r['scenario'])
        raw,f=contexts[key]; q=next(q for q in gold[r['project_id']]['questions'] if q['question_id']==r['question_id'])
        is_q3=r['question_id'].endswith('-Q3'); amb=is_q3 and key in ambiguous
        human=(*key,r['question_id'])==human_key
        alternative=bool(human and r['actual_answer']=='277')
        labels={k:0 for k in NEW_LABELS}
        labels['Ambiguous Instruction']=int(amb)
        labels['Defensible Alternative Interpretation']=int(alternative)
        reason='已实际核对题目、接收记忆、冻结原始事实/规则和回答；未发现新增四类评价问题。'
        if amb:
            reason=('实际收到文字同时含“基础费加节点数量”和“每节点另收费/另加”，没有明确单次计费公式或250元结论。'
              '可读为223+27×1或223+27+27×1。add标记仅指加法，单独不能证明只计费一次。'
              '本记录经AI逐项核对，非将一条人工判断扩展为人工标签。')
        if human:
            reason='研究者已确认实际接收措辞存在合理重复收费解释；277是可辩护替代解释。冻结250及score=0不变，不认定明确计算错误，也不自动认定277正确。'
        old_labels=dict(r['labels']); final_labels=dict(old_labels)
        if human:
            # Retain uncertainty about unique correctness; close only the answered human question.
            final_labels['FactualError']='UNKNOWN'
            final_labels['LegalInformationOmission']='UNKNOWN'
            final_labels['Unverifiable']=1
        row={'cohort':'live_720_legal_phase','item_id':'.'.join(map(str,(*key,r['question_id']))),
             'project_id':r['project_id'],'direction':r['direction'],'repeat_index':r['repeat_index'],
             'method_or_representation':r['scenario'],'question_id':r['question_id'],'question':r['question'],
             'actual_answer':r['actual_answer'],'frozen_reference_answer':r['expected_answer'],
             'answer_type':q['answer_type'],'primary_eligible':r['primary_eligible'],
             'frozen_score':r['score'],'original_labels':old_labels,'final_original_categories':final_labels,
             **labels,'definite_model_error':int(old_labels.get('FactualError')==1 and not human),
             'unique_answer_correctness':'UNKNOWN_due_to_ambiguous_received_rule' if human else 'not_reopened',
             'confidence':'human_confirmed_ambiguity_only' if human else 'AI_contextually_assessed',
             'reason':reason,'judge':'Researcher confirmation + AI evidence linkage' if human else 'Codex AI',
             'human_confirmed':human,'needs_human':False,
             'received_evidence_unit_error':int(is_q3 and key==('LIVE-P04','B_to_A',0,'summary')),
             'evidence_paths':[str(f.relative_to(ROOT)).replace('\\','/'),
                               'research_paper_v1/paper_live_v2/raw_experiment_data/dataset/gold.scoring_only.json'],
             'alternative_interpretations':[confirmation['interpretation_A'],confirmation['interpretation_B']] if amb else []}
        if human: row['evidence_paths'].append('live_confirmation/researcher_confirmation.json')
        rows.append(row)
        if is_q3:
            reviewed_contexts.append({'condition':list(key),'received_memory':raw['source_memory'],
               'memory_sha256':hashlib.sha256(raw['source_memory'].encode()).hexdigest(),
               'frozen_rule':gold[r['project_id']]['arithmetic_ground_truth'],
               'answers_read':raw['answers'],'Ambiguous Instruction':int(amb),'reason':reason,
               'source_record_sha256':sha(f),'human_confirmed':human})
    assert sum(r['human_confirmed'] for r in rows)==1
    assert sum(r['Ambiguous Instruction'] for r in rows)==9
    assert len(reviewed_contexts)==180
    write_csv(OUT/'live_confirmation/revised_live_evaluation_results.csv',rows)
    write_lines(OUT/'live_confirmation/revised_live_evaluation_results.jsonl',rows)
    write_lines(OUT/'reviews/live_180_context_reviews.jsonl',reviewed_contexts)
    legal=[r for r in rows if r['primary_eligible']]
    def describe(cells):
        return {group:rates([r for r in cells if predicate(r)],'frozen_score','project_id') for group,predicate in [
          ('all_legal',lambda r:True),('integer_numeric',lambda r:r['answer_type']=='integer'),
          ('date',lambda r:r['answer_type']=='date'),
          ('quantitative_integer_and_date',lambda r:r['answer_type'] in ['integer','date'])]}
    policies={
      'primary_no_exclusion':legal,
      'matched_question_level_P09_Q3_excluded':[r for r in legal if r['question_id']!='LIVE-P09-Q3'],
      'context_specific_9_ambiguous_fields_excluded':[r for r in legal if r['Ambiguous Instruction']!=1]}
    stats={'items':720,'projects':10,'actual_AI_read_contexts':180,'actual_AI_read_answer_fields':720,
      'new_labels':{k:sum(r[k]==1 for r in rows) for k in NEW_LABELS},
      'human_confirmed':1,'AI_only_ambiguity_labels':8,'new_human_questions':0,
      'definite_receiver_factual_errors':sum(r['definite_model_error']==1 for r in rows),
      'unique_correctness_unknown_fields':sum(r['unique_answer_correctness'].startswith('UNKNOWN') for r in rows),
      'received_evidence_unit_errors_not_frozen_GT_conflicts':1,
      'sensitivity_policies':{k:describe(v) for k,v in policies.items()},
      'old_sensitivity_policy_preserved':load(LIVE/'evaluation/quality_summary.json')['ambiguity_sensitivity']['rule'],
      'context_specific_exclusion_ids':[r['item_id'] for r in rows if r['Ambiguous Instruction']==1],
      'matched_exclusion_ids':[r['item_id'] for r in rows if r['question_id']=='LIVE-P09-Q3']}
    write_json(OUT/'live_confirmation/summary.json',stats)
    return rows,stats


def pct(v):
    return 'NA' if v is None else f'{v*100:.4f}%'


def result_line(name,s):
    return f"|{name}|{int(s['correct'])}/{s['fields']}|{pct(s['field_weighted_accuracy'])}|{s['project_count']}|{pct(s['project_macro_accuracy'])}|"


def reports(hist,hs,live_rows,ls):
    passport=('## Material Passport\n\n- 日期：2026-11-06（北京时间）。\n'
      '- 模式：ARS experiment-agent validate；Nature Statistics。\n'
      '- 输入：历史768字段＋单独的新批次720字段；均为保存的真实运行记录。\n'
      '- 本次新增商业/辅助模型调用：0；判断主体：Codex AI与1条研究者确认。\n'
      '- 原始回答、冻结GT、旧评价只读；新评价为追加版本。\n\n')
    intro='# 指令歧义审计\n\n'+passport
    intro+='## 结果与样本边界\n\n'
    intro+=(f"历史768字段全部重新阅读，来自12个合成项目、96个运行条件；新增四标签阳性均0，"
      f"可确定无新增题目歧义768条，新增歧义人工问题0。明确的接收回答事实/计算/理解错误0；"
      f"这不否认已有合法遗漏、输出/交付协议问题。H0661、H0637的上游归因UNKNOWN继续保留。\n\n"
      '223元/27节点案例经原始记录确认属于另一批720字段，不能计入768。另行阅读其全部180个合法接收上下文及720个回答字段，'
      '发现9个字段具有同类接收规则歧义：6个raw、3个summary；其中1条为研究者已确认，8条为AI逐项核对。'
      '人工结论只适用于明确指定的一条，不将其他8条记为人工确认。\n\n')
    intro+='## 分类规则\n\n'
    intro+=('新增四标签与原五类并存：Ambiguous Instruction要求实际收到的题目/规则支持不同合理解释；'
      'Ground Truth Conflict要求原始题目/规则与冻结答案不能同时成立；Insufficient Information要求题目自身缺必要条件；'
      'Defensible Alternative Interpretation要求实际回答符合有依据的另一种解释。'
      '同义日期、单位后缀、ID前缀翻译不是规则替代解释。因撤权/过滤/生成遗漏而缺接收记忆，与原题缺必要条件分别记录。\n\n')
    intro+='## 九个上下文逐项记录\n\n|记录|回答|判断主体|解释与证据|\n|---|---|---|---|\n'
    for r in live_rows:
        if r['Ambiguous Instruction']==1:
            intro+=f"|{r['item_id']}|{r['actual_answer']}|{'研究者确认' if r['human_confirmed'] else 'AI核验'}|223+27×1=250 或 223+27+27×1=277；见逐条CSV与原receiver contract|\n"
    intro+=('\nA_to_B三个raw保留了add标签，但未给出参数个数或单次计费表达式；因此不把add一词当作完整消歧。'
      '另9个P09字段已给出明确250/单次公式，或没有“另”语义，不标为已确认歧义。反方AI核验见reviews/live_p09_countercheck.json。\n\n'
      '277只证明可构造合理推导，原回答要求最简值且未输出推导，不能声称观察到模型采用了该推导。'
      '不把277自动计为正确；冻结数值评分仍0。唯一答案正确性保留UNKNOWN，但研究者已回答的歧义问题关闭。\n\n'
      '新增歧义人工队列为空；旧两条因观测不足的归因问题继续UNKNOWN，不重复要求人类猜测。\n')
    (OUT/'ambiguous_instruction_audit.md').write_text(intro,encoding='utf-8')

    conflict='# Ground Truth 冲突审计\n\n'+passport
    conflict+=('历史768字段的参考答案、来源事实和权限资格均核对，未发现冻结GT冲突。'
      '768字段主要是身份/库位/日期检索及二跳连接，数值运算题为0，不能把该批数据报告为768次数值计算。\n\n'
      '新720字段未发现原始受控题目与冻结GT的确定冲突。P09原始事实显式operation=add，两个操作数223与27，冻结250一致；'
      '接收端部分自然语言规则不唯一，250仍是合理答案，因此标Ambiguous Instruction而非Ground Truth Conflict。\n\n'
      '发现并复核一个接收证据单位错误：LIVE-P04.B_to_A.r0 / legal_successor / summary写“每箱容量为8箱”。'
      '原始事实为117台设备、每箱容量8，ceil(117/8)=15；接收回答15。该错误来自生成记忆的单位表述，'
      '已单列received_evidence_unit_error=1，不能据此修改冻结GT，也不能把答题正确当作生成记忆完全准确。\n\n'
      'P05 A_to_B r0 summary仍是明确回答错误：实际收到“开始日期2027-03-01，工期17天……开始日加持续天数为完成日”，'
      '日历相加是2027-03-18，原回答2027-03-17。该规则已明确加法，不能通过设想含首日计数而选择性豁免。\n\n'
      '参考support非穷尽、撤权后不允许作答、接收记忆缺字段、允许集中的其他推导路径均未自动标GT冲突。'
      '所有原始truth与原始回答均保留，审计前后哈希见verification_receipt.json。\n')
    (OUT/'ground_truth_conflict_audit.md').write_text(conflict,encoding='utf-8')

    sensitivity='# 评价敏感性分析\n\n'+passport
    sensitivity+=('## 主要评分与分母\n\n'
      '历史768中有484个合法主终点字段，原有计分是日期/标识规范化后的“全部所需值覆盖”，并非字面字符串完全相同。'
      '其余284个非主终点字段不混入合法准确率；原有权限探针继续按各自政策判定。数值计算准确率为NA（0道数值计算题）。\n\n'
      '|历史合法主终点|匹配/字段|字段加权准确率|项目数|项目等权准确率|\n|---|---|---|---|---|\n')
    sensitivity+=result_line('原冻结标准；无排除',hs['frozen_legal_value_coverage'])+'\n'
    sensitivity+=result_line('排除明确歧义；0条排除',hs['frozen_legal_value_coverage'])+'\n'
    sensitivity+='\n原论文项目等权方法结果原样保留：'+ '；'.join(f'{k}={pct(v)}' for k,v in hs['old_project_weighted_legal_utility'].items())+'。\n\n'
    sensitivity+=('新批次合法主终点540字段，包含360个身份/地点字段、162个整数运算字段与18个日期运算字段；'
      '180个受限探针另计。整数数值精确匹配允许去除明确单位后比较单个数值；不把250元判成250之外的数值。'
      '所有原始score完全保留，不把合理替代解释改判1。\n\n'
      '## 原始准确率与两种排除口径\n\n'
      '主敏感性沿用此前已保存的完整题组排除：删除P09-Q3在全部3表示×2方向×3重复的18字段，'
      '包括17条参考匹配回答和1条不匹配回答；其中只有9条实际上下文标歧义，另外9条因维持同题可比性一并排除。'
      '该口径未变，不把18条都称“歧义案例”。另加上下文分析仅删除逐项核验的9条，含8条匹配和1条不匹配。'
      '两者均为观察结果后开展的探索性敏感性分析，不是预注册确认性分析。\n\n'
      '|新批次终点/口径|匹配/字段|字段加权准确率|项目数|项目等权准确率|\n|---|---|---|---|---|\n')
    for policy,group in ls['sensitivity_policies'].items():
        for endpoint,s in group.items(): sensitivity+=result_line(policy+' / '+endpoint,s)+'\n'
    sensitivity+=('\n## 不确定性与统计审查\n\n'
      '以合成项目为聚类单位；历史数据先算每个方法/方向条件合法题均值，再项目内等权合并条件，严格复现旧计分层级。'
      '新批次在项目内汇总重复字段，再对项目重抽样5000次，种子2026110609；'
      '所有点估计和95%点置信区间见两个summary.json。重复字段不是独立项目。整数终点原有9项目（不含日期题P05），'
      '整组去P09后仅8；整数＋日期终点10→9；全部合法终点仍10，因为P09的身份/地点题保留。'
      '日期终点仅1项目，不生成可推断的聚类置信区间。'
      '不对不同项目数的两个平均数作简单配对显著性宣称。未进行新假设检验，因此无新增P值或多重检验显著性结论。\n\n'
      '11/11谬误检查：分组方向/表示表保留，聚合率不推出单条机制（Simpson/生态）；'
      '排除两种口径与原始主结果并列（选择/碰撞/分叉路径）；报告各类分母（基础率）；'
      '无新模型重跑，无回归均值前后因果比较；失败和错配全保留（幸存偏差）；'
      '无显著性筛选（多重搜索）；不从准确率变化推断算法改进或模型内部因果/反向因果。'
      '区间只描述当前合成项目，不能证明总体零错误、安全等价或商业内部行为。\n')
    (OUT/'evaluation_sensitivity_analysis.md').write_text(sensitivity,encoding='utf-8')

    pending=[]
    for r in hist:
        if r['needs_human']:
            pending.append({'cohort':r['cohort'],'case_id':r['item_id'],'question':r['question'],
               'actual_answer':r['actual_answer'],'ground_truth':r['frozen_reference_answer'],
               'recommended_labels':{k:r[k] for k in NEW_LABELS},'reason':r['reason'],
               'alternatives':r['alternative_interpretations'],'specific_question':'请确认哪种解释符合原始措辞。'})
    write_csv(OUT/'ambiguous_cases_for_review.csv',pending,fields=['cohort','case_id','question','actual_answer','ground_truth','recommended_labels','reason','alternatives','specific_question'])
    (OUT/'review_queue_status.md').write_text('新增指令歧义待人审：'+str(len(pending))+'条。CSV空队列只有表头，并非遗漏。\nH0661/H0637旧归因UNKNOWN保留；无法通过主观判断弥补未观测记录。\n',encoding='utf-8')

    change='# 评价变更日志\n\n'+passport
    change+=('版本：evaluation-ambiguity-v1；新建独立目录，不覆盖旧评价。\n\n'
      '1. 实际重新阅读历史768字段，3个Codex AI工作单元各读不同256条，不是3名真人/3个独立模型交叉评价。'
      '全部附加四标签和证据路径；旧五标签、原始评分、UNKNOWN归因保留。\n'
      '2. 主Codex实际读取新批次180个接收上下文及720字段，针对P09另由AI读取18份完整receiver contract反方核验。'
      '该核验来自同一模型家族，不能冒充跨模型或真人一致性。\n'
      '3. 研究者确认只链接LIVE-P09.B_to_A.r2 / legal_successor / summary / LIVE-P09-Q3。'
      '冻结250、回答277、score=0不变；新增Ambiguous Instruction=1、Defensible Alternative Interpretation=1，'
      'definite_model_error=0（未证实明确运算错误），唯一正确性与旧事实/遗漏维度保持UNKNOWN。'
      '关闭该条“等待人类判歧义”状态，不声称它已成为唯一正确答案。\n'
      '4. 另8个实际同类上下文由AI逐条判断，仅新增Ambiguous Instruction，human_confirmed=false。'
      '含add但无完整计费式的3条raw也纳入；证据和两种解释分别保存。\n'
      '5. 原有按P09-Q3整组排除18字段的敏感性规则未改变；新增上下文排除9字段的次要分析。'
      '主评分无任何提高/重写，两个排除集合均含正确和不匹配回答，完整ID列表见live_confirmation/summary.json。\n'
      '6. 不修改旧768盲化真人表格，不填真人声明，不产生真人一致性统计。历史768真人确认0；新720人工确认1。\n'
      '7. 无商业调用、无原实验重跑、无GitHub主分支操作。保存代码、输入哈希和核验回执。\n\n'
      '本次涉及：768条新增评价列；新720条另存修订版本，其中9条新增歧义标签、1条新增替代解释及真实人类确认。'
      '旧文件和旧评分的修改数量均为0。此前各报告的human_confirmed=0是旧快照，最新裁决以本目录为准。\n')
    if (OUT/'revision_01_snapshot').exists():
        change+=('\n内部核验修正：首版新分析曾直接混合历史项目内题目计算macro，未完全沿用旧条件等权层级。'
          '正式交付前修正为原有条件→项目层级，并逐方法断言与冻结报告一致；首版新分析及其核验回执保存在revision_01_snapshot，'
          '不曾改动历史原数据、历史评价或字段评分。单项目日期终点的退化bootstrap区间也改为NA。\n')
    (OUT/'evaluation_change_log.md').write_text(change,encoding='utf-8')


def verify(hist,live_rows):
    baseline=load(OUT/'input_manifest_before.json')['files']
    changed=[p for p,h in baseline.items() if not (ROOT/p).is_file() or sha(ROOT/p)!=h]
    assert not changed, f'Frozen input changed: {changed}'
    original_live=lines(LIVE/'evaluation/question_scores.jsonl')
    assert [r['frozen_score'] for r in live_rows]==[r['score'] for r in original_live]
    assert all(r['frozen_reference_answer']==old['expected_answer'] and r['actual_answer']==old['actual_answer']
               for r,old in zip(live_rows,original_live))
    h=next(r for r in live_rows if r['human_confirmed'])
    assert h['actual_answer']=='277' and h['frozen_reference_answer']=='250' and h['frozen_score']==0
    assert h['definite_model_error']==0 and not h['needs_human']
    assert sum(r['Ambiguous Instruction']==1 for r in live_rows)==9
    assert sum(r['human_confirmed'] for r in live_rows)==1 and not any(r['human_confirmed'] for r in hist)
    required=['ambiguous_instruction_audit.md','ground_truth_conflict_audit.md','revised_evaluation_results.csv',
              'ambiguous_cases_for_review.csv','evaluation_sensitivity_analysis.md','evaluation_change_log.md']
    assert all((OUT/f).is_file() and (OUT/f).stat().st_size>0 for f in required)
    snapshots=OUT/'code_version'; snapshots.mkdir(exist_ok=True)
    (snapshots/'audit.py').write_bytes(Path(__file__).read_bytes())
    receipt={'schema':'ambiguity-audit-verification-v1','date_local':'2026-11-06',
      'verified_utc':datetime.now(timezone.utc).isoformat(),'historical_fields':len(hist),'separate_live_fields':len(live_rows),
      'immutable_input_files_checked':len(baseline),'changed_immutable_inputs':changed,
      'all_720_scores_answers_and_GT_unchanged':True,'historical_scores_copied_from_frozen_report':True,
      'human_confirmed_historical':0,'human_confirmed_live':1,'paid_model_calls':0,'github_writes':0,
      'legacy_experiment_reruns':0,'script_sha256':sha(Path(__file__)),
      'required_outputs':{f:sha(OUT/f) for f in required},'reviewers':'Codex AI disjoint historical partitions; root live review; one human confirmation'}
    write_json(OUT/'verification_receipt.json',receipt)
    print(json.dumps(receipt,ensure_ascii=False))


def build(revision=False):
    if (OUT/'verification_receipt.json').exists() and not revision:
        raise SystemExit('Completed audit version preserved; choose a new version for another revision.')
    hist,hs=historical(); lr,ls=live(); reports(hist,hs,lr,ls); verify(hist,lr)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('command', choices=['snapshot','build','revise'])
    args = p.parse_args()
    if args.command == 'snapshot': snapshot()
    elif args.command == 'build': build()
    elif args.command == 'revise':
        backup=OUT/'revision_01_snapshot'
        if backup.exists(): raise SystemExit('Prior correction preserved; use another named version.')
        backup.mkdir()
        for folder in [OUT,OUT/'live_confirmation',OUT/'code_version']:
            for f in folder.iterdir():
                if f.is_file() and f.name!='input_manifest_before.json':
                    dest=backup/f.relative_to(OUT); dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f,dest)
        build(revision=True)
