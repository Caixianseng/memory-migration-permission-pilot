# 外部仓库复用审计（2026-11-05）

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


优先级采用 L1 已有实现 > L2 成熟库直接调用 > L3 必要适配。此次只在专用目录新增资格驱动和证据，没有将外部算法复制进旧工程。

## L1：现有工程比“重新造网关”更值得先复用

| 现有文件 | 可复用内容 | 已读出的边界 |
|---|---|---|
| experiments/persistent_exchange_v1/store.py | 独立 AgentStore、原始来源绑定、嵌套记忆依赖并集、导出封印、导入 nonce 消耗、SQLite ATTACH 事务、事件哈希链 | 本地可信单 Host；全局 epoch 失效范围保守；导入后的明文不会因撤权消失；哈希不证明来源完整 |
| experiments/revocation_grouping_v1/rebuild_cache.py | 默认 strict_epoch；显式 recheck_current_dependencies 路径；配置、来源版本与内容绑定 | 当前依赖完整且当次核验通过才可复用；普通缓存本身不新 |
| experiments/revocation_grouping_v1/lifecycle_host.py | 权限变更、授权、生成、交付前核验接口 | 自建 Host 结果不能外推商业 Agent 内部状态 |
| memory_migration_study/policy_projection_reference.py | 既有契约/策略参考判定 | 是工程参考与基线资产，不因重新命名成为新算法 |
| memory_migration_study/reference_memory.py | 事实池/片段验证支撑 | 其可观察范围需要与商业端严格区分 |

add_memory 已把 direct_sources 与所有 parent.dependencies 合并保存。若该声明完整且所有来源均为必要输入，撤权影响的扁平集合求交已与图可达性同义，不应为了使用 NetworkX 强行替换正确 L1 代码。

## L2：本轮实际复用、核验和未完成项

| 仓库 | 固定 revision | 本轮动作 | 改造必要性与许可证 |
|---|---|---|---|
| networkx/networkx | 7530809bfa1ea7ed6fdf918a4d1431488953cb1f | 调用本机 3.6.1 的 descendants；核心文件 blob 与官方一致；真实资格通过 | 不改库，只映射节点/边；BSD-3-Clause notices 保留 |
| Z3Prover/z3 | 745087e237e669d709ae35694728a0c479e572b3 | 先保存 MIT 原文，再尝试隔离 wheel；安装未完成，原型未运行 | 后续仅需 Python 建模适配；不能据此增加“自动发现隐藏来源”承诺 |
| HypothesisWorks/hypothesis | ad1c0b9745f5b9354b83c643b0f13f5fda361b8a | 先保存 MPL notice、核 pyproject，再安装；未取得包，状态机未运行 | 正常用公开 API；若修改 MPL 文件须核相应分发义务 |
| feldera/feldera | 8dc6b9a118f893deca0a4f329a15de0decf946d1 | 静态读 LICENSE、Cargo、integrate；未复制核心、未安装/构建 | Rust 与关系适配成本高；MIT 开源范围和 Enterprise 排除须核清 |
| cedar-policy/cedar | 66b4afebd944bc284cb486c32fa4dd54aa27e547 | 静态读 LICENSE、Cargo、Authorizer API；未构建 | Apache-2.0；需策略 schema 和调用接口，当前平面 ACL 无必要先替换 |

完整原始链接、许可证 blob、tag→commit、依赖版本记录于 final_source_verification.json。tag object 与 commit 分开记录；PyPI 版本与 Git revision 分开记录。仅核一个 core blob 不等于验证整个已安装 wheel。

## 实际新增文件

- experiments/paper_v1/external_candidates/qualify.py：第三方调用资格驱动。NetworkX 部分已执行；Z3/Hypothesis 部分尚未执行，不应列为已通过工程。
- research_paper_v1/evidence/external_candidates/networkx_raw.json：3200 次逐例输入/期望/实际结果。
- networkx_qualification_results.json：独立运行成功、环境、耗时与退出码。
- qualification_attempt_1_missing_modules.json 和 qualification_results.json：第一次缺模块失败，未覆盖。
- command_log.json：两次安装失败/中止、资格命令、退出码与尚未运行说明。
- source_manifest.json：安装前清单；final_source_verification.json：最终完整核验清单。
- licenses/：NetworkX、Z3、Hypothesis、sortedcontainers、Cedar、Feldera 官方 LICENSE 原文。

由于不满足运行环境，两项候选尚不能进入“已复现算法”清单。不得用自写布尔参照冒充跑过 Z3，也不得用手选事件冒充 Hypothesis 状态机。下载问题尚无充分诊断，不归因为候选算法不可用。

## 接口契约必须先于适配

NetworkX 只接收结构化图与撤权集合，返回受影响 ID；它不读自然语言来认证来源。Z3 只能在给定有限域与规则中返回 SAT/UNSAT/UNKNOWN；UNKNOWN、证据缺失和拒绝授权不能混成一个标签。Hypothesis 检验状态转换与 invariants，不能凭通过有限样本作全状态证明。DBSP 维护关系结果，Cedar 判定策略；两者都不能从不可见商业渠道补齐 Ground Truth。

强简单对照应保留：完整合法原文、完整授权源重建、已有扁平依赖交集、普通缓存加完整当前核验、单 Host 原子提交。外部工具必须解决这些基线覆盖不了的具体契约，再考虑接入。

