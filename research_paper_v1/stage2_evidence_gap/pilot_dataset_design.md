# 受控资格数据与冻结执行合同

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


日期：2026-11-05。用户已确认两名学生各每周8—12小时。本阶段仅本地CPU，新增付费模型调用0；历史12项目及fresh40只作为背景，不进入此次新项目的统计分母。

## 数据构造与独立单位

配置为 [config.json](evidence/config.json)，最终冻结记录为 [code_freeze_v4.json](evidence/code_freeze_v4.json)，最终数据为 [dataset_v3.json](evidence/dataset_v3.json.gz)。在读取开发结果前已生成24个不同随机种子的合成项目，12开发、12留出。每项目8—12条候选来源、6条有共享和父子依赖的派生记忆；实际参与来源取受信清单并集。NetworkX实际检查每条派生物的祖先来源与独立构造的扁平清单一致。smoke审查期间修正真实绑定与冲突可恢复分母，原dataset、smoke和code_freeze均另存未覆盖；未改图种子、缺失掩码、成本分布或主比较。

每项目重复10种场景和4种接口能力，共960场景单元。它们是项目内相关重复测量，不是960个独立项目；24个项目也来自同一生成器，不能代表真实商业业务总体。留出集只检验同一生成器的新图/内容，不是跨域泛化。

场景为：单缺失、多缺失、高共享依赖、多层缺失、矛盾记录、重复与受信别名、过期权限快照、已撤权来源、历史回执不可取得、不可观测渠道。每种故障保留独立构造的truth，只有评分函数读取truth。

## Expected、Observed与补证接口

所有方法得到同样的Trusted Host requirement manifest：每条派生记忆的保守输入来源、历史run、来源版本/摘要、可信issuer。这个清单是实验明确的额外可信假设，不能由模型引用生成；也不表示来源是某句话的最小因果支撑。

源回执定义为Host共同来源读取的acquisition receipt，允许共享；每个派生节点另外有唯一node/attempt回执，绑定artifact摘要、直接acquisition ID和精确父node版本/摘要。节点产物确实由纯函数仅读取直接payload与父输出计算，避免把一次全源生成批次错误拆成子来源污染。node回执在主实验始终完整；多层缺失场景测的是多层DAG的叶acquisition回执缺失，未测中间node补证路径。缺node的拒绝另有边界探针。合法记忆恢复率是对象交付恢复率，不是LLM问答质量。

Observed是该历史回执集合的有损投影。纯缺失按清单与存在键的差集评价；同键错误digest/矛盾副本是CONFLICT，不先丢弃后伪装为MISSING。所有恢复方法可从唯一权威回执库重取并核验canonical正本解除缓存冲突，保留原Observed与resolution记录；fail_closed不补。多权威无法裁定冲突不在主恢复结果覆盖内。完全相同重复记录幂等；只使用显式可信alias表规范化。opaque场景标明覆盖不完整，不允许猜测隐藏来源，也不把它们算成可定位缺失。

实际补证操作从本地SQLite读取冻结的历史Host输入回执，取得同run/version/digest/issuer证据。另列当前原文重新读取路径，但其类型不能满足历史输入回执义务；方法不能用重新读到同文追认过去生成。不可取得场景在实际回执表中缺行，目录不预告失败，执行后的query_log保留请求和缺行。无付费服务或人工确认模拟成真实执行。

回执携带源payload副本用于hash核验，实际读取在returned_rows/evidence_bytes中计量。source_reads为原始source-store重读次数，主批为0，不等于零数据读取。human_review_time_seconds为null且performed=false，不把未执行人工审核当实测0秒。

最终交付使用本阶段的新受控SQLite提交表；各方法共同执行BEGIN IMMEDIATE、当前权限/来源版本检查、证据覆盖检查后才写入committed表并读回。这是可观察资格宿主，不是重新执行原WorkBuddy/Harness真实迁移，也不是跨机事务。

主stale_permission场景是缓存权限epoch过旧但当前授权仍合法的资格，不冒充并发实验。另有9项[边界probe](evidence/raw_boundary_probes.json)实际测试补证后提交前撤权、撤权后恢复、读取前撤权、缺node、payload篡改、当前重新读取不可替代历史、两个评分器坏决策对照及canonical冲突恢复。它们不增加独立项目n。

## 四种接口能力

| 能力 | 真实执行行为 | 研究含义与限制 |
|---|---|---|
| singleton | 每请求读一个历史回执 | 共享去重后简单差集已经避免重复读取；不人为给候选额外缓存 |
| partition | 按3个provider分区，允许请求分区内所需子集 | 简单分组批读是强基线；SQLite实现这个能力边界，未证明商业平台具有此API |
| overlap | 5个交叠固定回执包，外加单条路径 | 暴露多路径与代价选择；这是声明的合成架构，不冒充实测平台能力 |
| universal_batch | 一次IN查询取任意所需集合 | 必须保留这个简单强对照；如果它足够，不能限制接口来制造优化收益 |

所有方法可见相同目录、合法路径、权重、Observed、当前权限和预算。固定包不能为降低计费而偷偷过滤返回内容；可过滤路径按请求缺项返回。包含撤权来源的不可过滤包不允许读取，不能先取回再删除。

## 方法与预算

7项：fail_closed、full_reaudit、set_difference、cheapest_path_union、simple_setdiff_batch、weighted_greedy、exact_dp。末两项是成熟规划候选，不名为原创Proposed。Cheapest-Path Union为每个缺项独立选择最便宜合法路径，再合并相同调用；simple batch按新增覆盖数选可用批接口，破平局时参考成本，不享有不存在的任意批读能力。

主预算10000合成单位，足够完成目录可恢复义务。紧预算8只用于开发前4项目的single_missing和shared_dependency，各4接口，共32个额外场景单元。预算不是按oracle结果倒推。精确DP优化完成目标覆盖的合成成本；紧预算下截断计划不是最大化记忆恢复的最优背包解，不能把它称为预算下效用上界。

权重是预先随机的正合成单位（单条1—5、包2—9等），不是人民币、API账单或测得时延。主资源终点是实际SQLite获取请求数，次要为实际返回回执行数/UTF-8字节数/验证次数和墙钟；权重只用于检查路径规划机制。所有方法有全局已验证证据缓存和共享去重。

## 执行与版本

入口 `experiments/paper_v1/stage2_evidence_gap/runner.py`。依次prepare、smoke、development、heldout；输出使用排他创建，不覆盖已有raw。每条件方法顺序用预固定种子打乱。主控独立维护分析合同与统计脚本；本运行器不根据开发效果修改数据或主比较。

每个场景公开目录的精确DP成本用SciPy/HiGHS MILP独立核对，不提供隐藏真值。NetworkX与SciPy均使用本机已有环境，无新增安装。代码、配置、数据SHA-256在运行前保存；每个split记录raw哈希、版本与运行耗时。环境真实版本以run记录为准。
