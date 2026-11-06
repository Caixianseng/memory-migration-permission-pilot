# 第二阶段小规模资格实验结果

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


日期：2026-11-05。验证状态：已实际运行。本文件报告运行与描述性结果；正式项目配对效应、95%区间和多重比较由 [statistical_analysis.md](statistical_analysis.md) 单独给出。

## 实际运行

最终运行代码：`experiments/paper_v1/stage2_evidence_gap/runner.py`。最终数据 [dataset_v3.json](evidence/dataset_v3.json.gz)，配置 [config.json](evidence/config.json)，运行前SHA-256记录 [code_freeze_v4.json](evidence/code_freeze_v4.json)。所有预先生成项目、故障掩码、成本权重在主运行前固定；smoke修订保留旧版本，未使用留出结果调方法或权重。

| 运行 | 独立合成项目 | 场景单元 | 方法运行行 | 退出状态 |
|---|---:|---:|---:|---|
| 开发主批 | 12 | 480 | 3,360 | 完成 |
| 开发紧预算补充 | 同12项目中的前4个 | 32 | 224 | 完成 |
| 留出主批 | 12个新种子项目 | 480 | 3,360 | 完成 |
| 4版smoke | P00的同4场景复用 | 非独立样本 | 各56 | 全部保留 |
| 机制/评分器边界探针 | 手选例，不增加n | 9 | 独立记录 | 全部通过 |

开发运行退出0，主批加紧预算共3,584行，实际运行约7.93秒；留出退出0，共3,360行，约8.10秒。运行时间包含多方法和独立MILP参照，不当单方法时延。`failed_conditions`均为空；代码先写实际结果行再记录安全/定位违规，未删失败求好看结果。[开发日志](evidence/run_development.json)、[留出日志](evidence/run_heldout.json)

主数据共960场景的DP最小目录覆盖成本均与SciPy/HiGHS MILP一致；NetworkX在24个新项目的DAG中实际核对源祖先集合。它们是两项实际执行的成熟实现，不是新算法。精确优化针对公开目录的合成权重，不能预知故障真值或保证远端真实成本最优。

## 定位与安全

在完整受信requirement manifest和可信alias的可观察键范围内，主批所有方法共用简单差集定位器，MISSING false positive与false negative均为0。各方法共用它，不构成多个独立定位算法竞赛；H1在这一合同下被支持，不能把该定位包装为新贡献。

CONFLICT由Observed中的矛盾/损坏字节识别；只有从唯一可信权威库获得绑定和payload摘要均正确的正本才解除。已撤权源不允许重读；最终权限与证据检查后才实际写入SQLite交付表。主批真实权限越权和证据合同错误放行均为0；unknown不可提升为VERIFIED。这个0只覆盖声明的合成场景与本地Host，不是任意语义泄漏或商业平台安全率。

## 留出描述性汇总

以下是12留出项目、每项目40场景的**合并工作量**，不是项目配对统计或独立样本数。每方法共有2,208个参考可恢复记忆对象机会；不同场景包含同项目派生记忆重复。

| 方法 | 实际补证SQL请求 | 合成成本单位 | 恢复合法记忆/参考可恢复 |
|---|---:|---:|---:|
| Fail-Closed | 0 | 0 | 824/2,208 |
| Full Re-Audit | 1,552 | 4,960 | 2,208/2,208 |
| Simple Set-Difference＋全局去重 | 848 | 2,492 | 2,208/2,208 |
| Cheapest-Path Union | 694 | 1,885 | 2,208/2,208 |
| Simple Set-Difference＋可用批读 | 598 | 1,782 | 2,208/2,208 |
| 标准 Weighted Greedy | 665 | 1,803 | 2,208/2,208 |
| 小规模 Exact DP | 620 | 1,753 | 2,208/2,208 |

补证与无补证之间存在功能差异；定向补证也比全量复审少工作。但最简单的可用批读规则总请求少于Weighted Greedy；DP优化合成权重也没有在实际请求上超过简单批读。因此不能用对弱基线的降低直接支持开发新算法。

主统计显示预先规定的5个实际请求收益门槛均未达到，完整效应与不确定性见统计报告。本文不把合并总数替换成按项目平均效应，也不将微小本地时间差当真实平台速度收益。

## 数据与计量边界

- source_reads表示原始source-store重新读次数，主批0；历史回执携带源payload副本，实际返回行与字节另计，不能声称零数据读取。
- 人工审核未执行，时间字段null；商业模型调用0，实际新增付费API费用0，商业内部成本unknown。
- 本地时延包括诊断、计划、补证、最终校验/提交，扣除相同数据库夹具初始化；total_wall另含初始化。没有人为睡眠模拟远程延迟。
- 主stale_permission只是旧缓存权限快照刷新；额外9probe覆盖串行阶段注入的撤权/恢复，不是并发调度探索。读取ACL与payload不是同一事务，不主张不存在读时TOCTOU。
- 原有12业务项目和fresh40未作为本轮测试样本；本轮留出依然来自同一个合成生成器，不足以支持H4在真实独立业务中的普遍收益。

## 命令

在仓库根使用 `D:/python3.11/python.exe -B -X utf8` 执行：

```text
experiments/paper_v1/stage2_evidence_gap/runner.py development
experiments/paper_v1/stage2_evidence_gap/runner.py heldout
experiments/paper_v1/stage2_evidence_gap/boundary_probes.py
```

raw文件采用排他创建，避免重跑覆盖；复核应读现有raw与冻结manifest。若需要新计时重复，必须指定新输出标签并说明属于技术重复，不能混入项目n。
