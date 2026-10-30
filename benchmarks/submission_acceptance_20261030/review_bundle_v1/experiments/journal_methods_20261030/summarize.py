"""Recompute closed deterministic evidence; never opens task answer references."""
from collections import Counter
from datetime import datetime, timezone
import html
import json
from pathlib import Path

from .run_paired_acceptance import ROOT, HERE, sha, write


def summarize(out):
    out = Path(out)
    closure = json.loads((out/'prediction_closure.json').read_text(encoding='utf-8'))
    if closure['status'] != 'deterministic_predictions_closed' or sha(out/'plan.json') != closure['plan_sha256']:
        raise ValueError('prediction_not_closed')
    for name, expected in closure['output_sha256'].items():
        if sha(out/name) != expected:
            raise ValueError('closed_output_changed')
    matrix, flows, baselines, restoration = [json.loads((out/(name+'.json')).read_text(encoding='utf-8'))
                                            for name in ('requests','flows','baselines','restoration')]
    unique = {(x['case_id'],x['fact_id'],json.dumps(x['request'],sort_keys=True)) for x in matrix}
    metrics = {
        'W_plus': sum(x['reference']['decision']=='Deny' and x['observed']['decision']=='allow' for x in matrix),
        'W_minus': sum(x['reference']['decision']=='Permit' and x['observed']['decision']=='deny' for x in matrix),
        'unknown_reference_allow': sum(x['reference']['decision']=='Indeterminate' and x['observed']['decision']=='allow' for x in matrix),
        'not_applicable_allow': sum(x['reference']['decision']=='NotApplicable' and x['observed']['decision']=='allow' for x in matrix),
        'obligation_failure_allow': sum(not x['reference']['deliver'] and x['observed']['decision']=='allow' for x in matrix),
        'execution_rows':len(matrix), 'distinct_requests':len(unique), 'duplicate_executions':len(matrix)-len(unique),
        'reference_unknown':sum(x['reference']['decision']=='Indeterminate' for x in matrix),
        'observed_unknown':sum(x['observed']['decision']=='unknown' for x in matrix),
        'observed_allow':sum(x['observed']['decision']=='allow' for x in matrix),
        'restore_scope':'matrix restore checks are prechecks; actual endpoint results separately below',
        'restore_precheck_allows':sum(x['observed'].get('scope')=='restore_gate_precheck' for x in matrix)}
    differing = [x for x in matrix if x['observed']['decision']=='allow' and not x['reference']['deliver'] or
                 x['reference']['decision']=='Permit' and x['observed']['decision']=='deny']
    write(out/'authorization_differences.json', differing)
    methods = []
    for split in ('dev','check'):
        for method in ('current_default','whole_block','per_fragment','existing_selective'):
            rows = [x for x in baselines if x['split']==split and x['method']==method]
            tasks = [t for x in rows for t in x['task_availability']]
            methods.append({'split':split,'method':method,'stories':len(rows),
                'ready_stories':sum(x['status']=='ok' for x in rows),
                'blocked_or_review_stories':sum(x['status']!='ok' for x in rows),
                'kept_facts':sum(len(x['kept_facts']) for x in rows),
                'legal_context_present':sum(t['kind']=='legal' and t['fact_present'] for t in tasks),
                'legal_tasks':sum(t['kind']=='legal' for t in tasks),
                'registered_raw_leaks':sum(len(x['registered_raw_leaks']) for x in rows),
                'legal_task_accuracy':None,'model_refusal_rate':None,
                'phase':'pre-revocation context availability; not model answering'})
    restore = {'actual_endpoint_probes':len(restoration),
        'declared_restore_allowed':sum(x.get('explicit_restore_allowed') is True for x in restoration),
        'legacy_endpoint_allowed':sum(x.get('raw_current_endpoint',{}).get('status')=='ok' for x in restoration),
        'opt_in_gate_allowed':sum(x.get('opt_in_gate',{}).get('status')=='ok' for x in restoration),
        'independent_permission_absent_but_legacy_restored':sum(x.get('explicit_restore_allowed') is False and
            x.get('raw_current_endpoint',{}).get('status')=='ok' for x in restoration),
        'explicitly_denied_and_opt_in_blocked':sum(x.get('explicit_restore_allowed') is False and
            x.get('opt_in_gate',{}).get('status')=='blocked' for x in restoration),
        'interpretation':'old API implements read-authorized restoration, not the new independent restore contract'}
    lifecycle = [x for x in flows if x['kind']=='lifecycle']
    counter = Counter((x['kind'],x['result']['status']) for x in flows)
    evidence = {'date':'2026-10-30','run':str(out.relative_to(ROOT)),
        'authorization':metrics,'methods':methods,'restoration':restore,
        'flow_checks':[{'kind':k,'status':s,'count':n} for (k,s),n in sorted(counter.items())],
        'lifecycle_probes':len(lifecycle),'new_model_calls':0,'new_client_calls':0,
        'human_review':None,'indirect_metrics':None,'paper_novelty_established':False,
        'reference_values_opened':False,'smoke_status':'prepared_not_executed_cost_unverified',
        'ABAC':'not_enabled_no_actual_policy_conversion_need','SMT':'not_enabled_finite_domain_sufficient'}
    write(out/'summary.json',evidence)
    labels={'current_default':'现有默认（请求级）','whole_block':'整条保守阻断（与默认等价）',
            'per_fragment':'标准逐片段核权与隔离','existing_selective':'已有选择性隔离'}
    table='\n'.join(f"| {m['split']} | {labels[m['method']]} | {m['ready_stories']}/{m['stories']} | {m['kept_facts']} | {m['legal_context_present']}/{m['legal_tasks']} | {m['registered_raw_leaks']} |" for m in methods)
    text=f'''# 期刊方法结合实施结果与继续条件

日期：2026-10-30。按用户提供的两版计划实施；本次完成了无模型资格阶段，真实客户端与检测效果阶段尚未执行。主要结果是：已有逐片段处理与选择性隔离等效；独立恢复权限需要显式宿主合同，现有读取权限不能替代它。尚未建立新算法贡献。

## 实际完成

新增隔离目录 `experiments/journal_methods_20261030`，复用现有 CurrentMemoryAuthority、NativeAgentBroker、脱敏与恢复、选择性隔离。生产默认未修改。独立权限参照不导入生产核权函数，四值组合冻结为 Deny > Indeterminate > Permit > NotApplicable；这是受限研究合同，不是完整 FACPL 复现。

4个开发故事与8个检查故事，每故事4条原文和4题，共48条事实、48题（检查32题）。全部是AI辅助合成研究控制；人工复核为null。检查评分参考未被执行或开发代理打开；读取案例文本、可信政策和控制检测标签不等于获取评分答案。尚未计算语义检测指标或模型任务正确率。

## 流程

```mermaid
flowchart TD
  A[冻结案例 原文与可信授权] --> B[独立四值参照]
  A --> C[已有主机读取与交接入口]
  B --> D[逐请求比较]
  C --> D
  C --> E[同信息内容保护对照]
  E --> F[来源 标签 受众和载荷检查]
  F --> G[真实恢复端点与独立恢复门禁]
  G --> H[撤权与旧包重放]
  H --> I[封存原始证据]
  I --> J[真实客户端四条件 尚未执行]
```

## 权限与传播结果

- {len(matrix)}次请求执行中有{len(unique)}个不同请求、{len(matrix)-len(unique)}次重复；实验单位仍为12个故事。重复调用不增加样本量。
- 新增越权W+={metrics['W_plus']}，合法访问损失W−={metrics['W_minus']}。参考未知{metrics['reference_unknown']}次，实际未知{metrics['observed_unknown']}次；未知下放行{metrics['unknown_reference_allow']}次，无适用规则下放行{metrics['not_applicable_allow']}次。未知没有算作正确业务拒绝。
- 这些统计针对“现有读取/交接入口＋显式宿主上下文门禁”；矩阵中的{metrics['restore_precheck_allows']}次恢复允许只是预检，不能当作真实恢复成功。
- 48条原文绑定、48条阳性标签投影、12条固定共同依赖交集检查均通过。交集只是已声明依赖的诊断性质，不是任意自然语言依赖推断。
- 2个准备后撤权探针均阻断实际恢复与旧签名包重放。已读客户端的明文无法因此遗忘；本轮没有实际客户端在线撤权实验。
- 静态适配器仍拒绝无法兑现的严格原生ACL/在线撤权模式；没有用capabilities字符串绕过。

## 同信息强基线对照

各条件使用相同可信授权、敏感位置与不确定结果，并显式声明事实独立。先核权筛选，再保护内容。默认与整条阻断在这个合同下是同一实现的等价对照，不能当作两种独立算法。

| 材料 | 条件 | 可交付故事 | 保留事实 | 合法题所需事实可用 | 交付载荷中的注册原值漏遮 |
|---|---|---:|---:|---:|---:|
{table}

表中“合法题所需事实可用”只检查事实是否进入受保护上下文，且处于撤权前阶段。它不是答案正确率或误拒率；阻断故事保留在分母中。只比较已交付载荷中的注册精确原值，不证明无语义或推断泄露。真实检测器没有参与，不能说检测召回率提高了。

标准逐片段与已有选择性隔离在检查集均为5/8故事可交付、13条事实保留、9/11合法题所需事实可用；相对默认保留更多内容，但没有超过已有强方法。按计划停止把这项等效适配包装为新算法。

## 独立恢复权限的具体边界

44次真实当前恢复端点控制探针中，42条明确允许恢复、2条只允许读取但没有恢复许可。旧端点44条都能恢复，因为原合同只核对当前读取；新增隔离宿主入口实际调用后保留42条、阻断2条。这里是新合同与既有接口语义的差异，不能倒推旧合同存在已证实漏洞，也不是新算法。源端迁出与复制仍由现有broker独立检查。

当前新增恢复门禁只服务本实验受控入口，尚未接入所有生产适配器、自由工具、摘要或任意业务任务。矩阵中的恢复预检与这44次真实端点探针分开计数。

## 端到端与预算状态

签名包已实际在本地主机验证；原文AGENTS.md仅在内存中渲染并解析核对。保护后载荷也做了本地一致性检查，但尚未实际加载Qoder/Harness。不能据此宣称新端到端客户端成功。

两新故事、8题、A源端原文/B源端保护/C目标保护/D无记忆的32次冒烟计划已冻结准备。当前账号客户端调用费用上界、项目累计可用余额仍未核实，因此未启动。旧10月29日账本生成200/200已用满，不重置为新额度。本轮新增提取、生成、客户端、付费云端调用均为0。模型正确率、误拒率、无记忆收益、人类语义指标均为null。

## 验证修订与保留失败

定向工程测试58项通过。首次接线测试55通过、2失败，定位为载荷源ID别名与代号前缀误用，修正后通过。run01保留了未触发撤权、33个整句格式探针被阻断以及自比较来源/受众等评价缺陷；run02修正这些问题；run03让独立恢复门禁通过真实函数调用而非结果投影。旧目录和冻结哈希未被覆盖。这些是评价工具问题，没有计成模型误拒或论文方法失败。

本次没有重跑2172项历史全套回归，58项仅对应新增参照、传播和接线测试，不与旧测试数相加。源端严格CUSTOMER适配器没有被冒充宽组织检测器。

## 后续裁决

1. 权限一致性：在有限登记域内未发现额外放行；这不是一般安全证明。
2. 合法信息保留：标准逐片段与现有选择性隔离已足够解决本批控制案例，尚无新算法必要性。
3. 独立恢复许可：已在隔离主机入口实现可验证补充，待正式合同确认及端到端接线，不作为论文创新。
4. ABAC挖掘：没有实际规则转换/复杂度需求，按计划不实现。SMT：有限域足以完成当前验证，按计划不安装。
5. 客户端和检测效果：冻结计划已准备，费用与可用授权核验后再决定是否执行32次冒烟；当前不扩大模型批次。

## 方法依据与适配范围

- [FACPL作者技术报告](https://arxiv.org/abs/1612.09339)：借鉴四值判决、义务与执行分离和独立验证；没有复制其完整语言、组合算法或证明。
- [DLM作者论文](https://www.cs.cornell.edu/andru/papers/iflow-tosem.pdf)：借鉴明确来源的限制传播、降低限制需要授权；本原型未实现Jif全程序信息流检查。
- [ABAC作者论文及勘误](https://www3.cs.stonybrook.edu/~stoller/abac-mining-TDSC.html)：确有策略转换需求时再适配，当前不启用。
- [Agent记忆综述](https://arxiv.org/abs/2404.13501)：借鉴直接与间接评价分离；真实客户端间接评价仍未执行。期刊条目见[DOI](https://doi.org/10.1145/3748302)。

## 复现

```powershell
python -m pytest tests/test_journal_policy_reference.py tests/test_journal_memory_flow.py tests/test_journal_acceptance.py -q
python -m experiments.journal_methods_20261030.run_paired_acceptance --out results/journal_methods_20261030/new_run
python -m experiments.journal_methods_20261030.summarize results/journal_methods_20261030/new_run
```

运行目录必须不存在。运行器禁止socket网络调用，不打开评分参考，不启动客户端；恢复映射只留内存。`plan.json`和`prediction_closure.json`记录输入/执行代码及原始证据哈希。历史原始结果位于本机results目录，未自动上传。
'''
    write(out/'report_metadata.json',{'summary_sha256':sha(out/'summary.json'),'written_at_utc':datetime.now(timezone.utc).isoformat()})
    (out/'report.md').write_text(text,encoding='utf-8')
    doc=ROOT/'docs/期刊方法结合实施与验证_2026-10-30.md'
    doc.write_text(text,encoding='utf-8')
    page='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>期刊方法结合实施结果</title><style>
body{margin:0;background:#f2f5f8;color:#15283b;font:16px/1.75 "Microsoft YaHei",sans-serif}main{max-width:1080px;margin:32px auto;background:white;padding:36px;border-radius:14px}h1{font-size:27px}h2{font-size:21px;margin-top:30px}table{width:100%;border-collapse:collapse;font-size:14px}td,th{border:1px solid #cbd5df;padding:10px}th{background:#e6eef5}pre{white-space:pre-wrap;background:#f5f7f9;padding:18px}.cards,.flow{display:flex;flex-wrap:wrap;gap:14px}.cards div,.flow span{flex:1;min-width:120px;background:#e9f2f9;padding:14px;border-radius:8px}.note{border-left:4px solid #cf8d2c;padding:12px;background:#fff5e6}a{color:#1265a3}</style><main>
<h1>期刊方法结合实施结果</h1><p>2026-10-30 · 无模型资格验证 · 生产默认未改</p>
<div class="cards"><div>12个合成故事<br>48条事实 / 48题</div><div>2360个不同请求<br>2496次执行</div><div>W+ 0 / W− 0<br>仅限当前宿主合同</div><div>模型与客户端调用<br>本轮均为0</div></div>
<h2>验证流程</h2><div class="flow"><span>冻结原文与授权 →</span><span>独立参照对照真实入口 →</span><span>同信息保护与恢复 →</span><span>撤权重放与证据封存</span></div>
<p class="note">没有建立新算法优势。逐片段处理与已有选择性隔离结果相同；检测准确率、模型正确率和误拒率均未测。</p>
<h2>检查集对照</h2><table><tr><th>条件</th><th>可交付故事</th><th>保留事实</th><th>合法题所需事实可用</th></tr>'''
    for m in methods:
        if m['split']=='check':
            page+=f"<tr><td>{labels[m['method']]}</td><td>{m['ready_stories']}/{m['stories']}</td><td>{m['kept_facts']}</td><td>{m['legal_context_present']}/{m['legal_tasks']}</td></tr>"
    page+='</table><p>可用性是撤权前上下文检查，不能当作模型回答正确率；未交付故事保留在分母。</p><h2>完整说明</h2><pre>'+html.escape(text)+'</pre></main></html>'
    (out/'index.html').write_text(page,encoding='utf-8')
    print(json.dumps({'summary':str(out/'summary.json'),'report':str(doc),'W_plus':metrics['W_plus'],
                      'W_minus':metrics['W_minus'],'novelty':False},ensure_ascii=False))


if __name__=='__main__':
    import sys
    summarize(Path(sys.argv[1]).resolve())
