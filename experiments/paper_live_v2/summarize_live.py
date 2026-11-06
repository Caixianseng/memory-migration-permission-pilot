"""Traceable aggregate of actual native/SDK jobs, including failed attempts."""
import collections,hashlib,json,time,shutil
from pathlib import Path
from .live_runtime import ROOT,OUT,save

def read(p):
    try:return json.loads(p.read_text(encoding='utf-8'))
    except (OSError,json.JSONDecodeError):return None
def main():
    base=OUT/'raw_experiment_data/qualification_isolated_v1';jobs=[];cases=[]
    for case in sorted(base.iterdir()):
        if not case.name.startswith('LIVE-') or not case.is_dir():continue
        done=read(case/'complete.json');blocked=read(case/'blocked.json')
        cases.append({'case':case.name,'status':'completed' if done else 'blocked' if blocked else 'running',
                      'original_blocked_retained':bool(blocked)})
        for folder in sorted(case.iterdir()):
            cp=read(folder/'contract.json') if folder.is_dir() else None
            if not cp:continue
            candidates=[folder]
            if (folder/'safe_predispatch_retry/contract.json').exists():candidates.append(folder/'safe_predispatch_retry')
            if (folder/'safe_precreation_retry/contract.json').exists():candidates.append(folder/'safe_precreation_retry')
            for job in candidates:
                original=read(job/'result.json');recovered=read(job/'local_parse_recovery.json');effective=recovered or original
                raw=read(job/'raw_output.json');strict=None
                if raw:
                    try:json.loads(raw['text']);strict=True
                    except json.JSONDecodeError:strict=False
                env=read(job/'native/envelope.json');pointer=read(job/'sdk_ledger_pointer.json')
                ledger=Path(pointer['path']) if pointer else job/'sdk.private'
                sdk=read(ledger/'job-inference/receipt.json') if cp['platform']=='flash' else None
                jobs.append({'job':str(job.relative_to(OUT)),'case':case.name,'role':cp['role'],'platform':cp['platform'],
                    'original_status':original.get('status') if original else 'pending',
                    'effective_status':effective.get('status') if effective else 'pending','strict_raw_json':strict,
                    'local_recovery':bool(recovered),'original_error':original.get('error') if original else None,
                    'native_prompts_submitted':(env.get('nativeExecution') or {}).get('modelPromptsSubmitted') if env else None,
                    'native_verified':env.get('status')=='verified_native_paid_one_shot' if env else False,
                    'actual_models':(env.get('actualModels') or []) if env else [sdk['actual_model']] if sdk and sdk.get('actual_model') else [],
                    'sdk_physical_requests':sdk.get('physical_request_count') if sdk else None,
                    'sdk_ledger':str(ledger) if sdk else None,
                    'sdk_estimated_peak_cny':sdk.get('estimated_peak_cost_cny') if sdk else None,
                    'latency_seconds':effective.get('inference_wall_seconds',effective.get('elapsed_seconds')) if effective else None,
                    'prompt_sha256':cp['prompt_sha256']})
    by_platform={}
    for platform in ('hy3','flash'):
        subset=[j for j in jobs if j['platform']==platform]
        by_platform[platform]={'reserved_jobs':len(subset),'effective_ok':sum(j['effective_status']=='ok' for j in subset),
            'failed_original':sum(j['original_status']=='failed' for j in subset),
            'strict_raw_json_valid':sum(j['strict_raw_json'] is True for j in subset),
            'strict_raw_json_invalid':sum(j['strict_raw_json'] is False for j in subset),
            'native_prompts_observed':sum(j['native_prompts_submitted'] or 0 for j in subset),
            'physical_requests_observed':sum(j['sdk_physical_requests'] or 0 for j in subset) if platform=='flash' else None,
            'actual_models':sorted({m for j in subset for m in j['actual_models']}),
            'actual_cost_cny':None}
    unique_ledgers={j['sdk_ledger']:j for j in jobs if j['sdk_ledger']}
    estimate=sum(float(j['sdk_estimated_peak_cny']) for j in unique_ledgers.values() if j['sdk_estimated_peak_cny'] is not None)
    counts=dict(collections.Counter(c['status'] for c in cases))
    summary={'observed_unix':time.time(),'planned_independent_synthetic_projects':10,'planned_cases':60,
        'case_counts':counts,'case_directories':len(cases),'observed_projects':sorted({c['case'].split('.')[0] for c in cases}),
        'platforms':by_platform,'sdk_known_usage_peak_estimate_cny':estimate,'estimate_is_supplier_invoice':False,
        'workbuddy_actual_fee_cny':None,'source_scenario_output_context_shared':True,'receiver_context_isolated_by_scenario':True,
        'cases':cases,'jobs':jobs}
    snapshots=OUT/'raw_experiment_data/aggregate_snapshots';snapshots.mkdir(exist_ok=True)
    save(snapshots/f'{time.time_ns()}.json',summary)
    (OUT/'raw_experiment_data/live_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# 真实模型配置与平台比较','',f'当前主资格已完成 {counts.get("completed",0)}/60 个项目内管线；独立统计单位是10个合成业务项目。',
        '每项目有双向×3次执行重复；raw/summary/multi_source为项目内记忆表示，不是独立项目。',
        '', '| 平台路径 | 实际模型元数据 | 已预留任务 | 有效解析结果 | 原始严格JSON有效/无效 | 可观测调用 |',
        '|---|---|---:|---:|---|---|']
    for p,name in [('hy3','WorkBuddy 5.9.3 原生 ask/零工具'),('flash','DeepSeek Harness 0.2.1-rc.3 官方SDK/零工具')]:
        x=by_platform[p];observed=f'{x["native_prompts_observed"]}个原生用户请求；物理供应商请求数未知' if p=='hy3' else f'{x["physical_requests_observed"]}个已记录物理SDK请求'
        lines.append(f'| {name} | {", ".join(x["actual_models"])} | {x["reserved_jobs"]} | {x["effective_ok"]} | {x["strict_raw_json_valid"]}/{x["strict_raw_json_invalid"]} | {observed} |')
    lines += ['', 'WorkBuddy `hy3-x` 是安装版本已验证的混元积分通道。本轮没有声称读取到了逐任务扣分。Harness SDK具有真实供应商请求/响应及用量回执，但桌面桥接离线，本轮未把它描述成桌面工具读写。',
        f'已知Harness用量的峰时公式估值合计 {estimate:.6f} CNY；并非账户实付账单。WorkBuddy费用与完整端到端实付费用为未知。',
        '', '模型端接收的是Host在独立进程关闭重开后读取的接收库正文。模型未直接访问SQLite；Trusted Host负责真实持久化与授权事务。WorkBuddy上游完整系统提示不可观测；提交的完整业务指令逐任务保存在contract.json/native/input.json。SDK业务system/user指令和实际HTTP请求体保存在回执指向的私有ledger。',
        '', '同族跨平台附加对照见 same_family_control.md；WorkBuddy与Harness的后端build不能完全核验为相同，不能把平台差异归因为模型差异。',
        '', '格式错误按原始输出统计；只对固定schema内未转义引号、完整对象之后多余闭括号进行另存的无损结构适配，不改事实、不覆盖失败。预检使用联合表示接收上下文的8个推理任务仅留在raw_experiment_data/live，排除主质量比较。',
        '', '证据入口：raw_experiment_data/live_summary.json；qualification_isolated_v1/*；harness_preflight.json；preflight/workbuddy/envelope.json。']
    (OUT/'llm_model_comparison.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    source_jobs=[j for j in jobs if j['role']=='source']
    text=['# 真实记忆生成与交付实验','',f'已经预留 {len(source_jobs)} 个源端生成任务；其中有效解析 {sum(j["effective_status"]=="ok" for j in source_jobs)} 个。所有回答来自真实平台，失败和未完成任务保留在明细中。',
        '', '10个项目分别采用库存差、瓶颈带宽、公开采购乘积、装箱上取整、日期加法、待验收差值、配额相加、轮值乘积、运输计费、供电下取整规则。事实和规则由独立gold冻结，不是复制同一项目作为新样本，也不是来自10家真实企业的随机抽样。',
        '', '每次源端独立生成三种表示；三表示共享这一源端调用上下文。最初可分享的内部审计码在生成后撤销。Host按所有实际输入source scope形成保守依赖，不用模型自报claims确定授权。旧初始记忆在首次受控交付时由C/D/E拒绝；基于合法输入的真实新调用产生安全后继，再持久化和问答。',
        '', '实现的实际时序：初始真实生成→建立/封装受控授权包→SQLite提交撤权→基于合法来源生成安全后继→隔离比较初始旧包及安全后继交付。安全后继的生成先于比较旧包的拒绝尝试；不能将这一轮描述成“拒绝触发了后继生成”的因果实验。',
        '', 'A普通文件、B初始静态ACL+hash、C当前来源/权限/版本预检查、D成熟事务+幂等+接收校验、E完整Host核心，使用相同实际生成正文和同一权限事件。D/E共享成熟事务实现；相同的已验证接收正文只做一次真实QA并映射到等价方法，未按方法复制成独立模型调用。',
        '', '本轮raw标签是模型对原事实的忠实重述，仍可能改写。真正逐字原始事实的kind=raw持久化及真实接收问答另在exact_original_live中执行，来源为controlled_exact_original，不能混称模型自主生成。',
        '', '本轮使用全量合法来源重新生成基线，并未声称选择性重建击败全量重建。主要结果是安全交付与合法功能的系统验证，不是新优化算法的优势证明。',
        '', '配置、源输入、权限/来源依赖、封包、磁盘库、接收重开回执、原始回答、格式恢复和失败均在raw_experiment_data保存。随机种子是执行标签和确定性数据种子；商业模型解码随机种子无法控制。']
    (OUT/'agent_memory_generation_experiments.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
    analysis=OUT/'analysis_scripts';analysis.mkdir(exist_ok=True)
    for name in ('summarize_live.py','evaluate_live.py','audit_live_attempts.py','format_adapter.py'):
        src=ROOT/'experiments/paper_live_v2'/name
        if src.exists():shutil.copyfile(src,analysis/name)
    print(json.dumps({'cases':counts,'platforms':by_platform,'sdk_estimate_cny':estimate},ensure_ascii=False))
if __name__=='__main__':main()
