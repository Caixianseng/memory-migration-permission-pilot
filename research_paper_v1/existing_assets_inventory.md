# 现有工程资产清单

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


审计日期：2026-11-05（北京时间）。状态：第一阶段的工程资产审计已实际执行；本文件不代表整项研究的新颖性或正式实验已经通过。

## 范围与计数口径

采用“全量机械目录/符号索引＋关键交付路径深审”。机器证据为 [asset_index.json](evidence/asset_index.json.gz)，生成程序为 [audit_existing_assets.py](../experiments/paper_v1/audit_existing_assets.py)。程序禁止网络和子进程，未构造原生客户端，未发起模型调用。

扫描的是本机现有下载工程，不把它称为当前 GitHub 全量 checkout。GitHub 当前版本及 CI 核对由 [github_snapshot.json](evidence/github_snapshot.json) 独立记录。索引排除 `_local`、账户私有目录、`*.private`、`*-private-sdk`、环境缓存、新建 `paper_v1` 和当前研究文档，避免把本轮新增文件算作既有成果。

| 机械清点项目 | 数量 | 解释 |
|---|---:|---|
| 已索引文件 | 20,606 | 含结果、依赖与归档；不等于原创文件数 |
| Python 文件 | 3,896 | 其中 3,070 个属于 `.deps`/`reranker_vendor` 等运行依赖，未解析其函数 |
| 项目及归档 Python 文件 AST 解析 | 826 | 包括旧快照、基准副本和部分有出处的源码摘录；不宣称全部原创 |
| 类定义 / 函数定义 | 865 / 10,265 | 机械语法节点，包含嵌套函数和历史副本 |
| `test_` 命名函数 | 3,032 | 不是本轮运行测试数量，也不是去重后的可执行用例数 |
| AST 解析错误 | 0 | 只证明本轮所读文件可按 Python 语法解析 |

| 工程区域 | 非运行依赖 Python 文件 | 主要作用 |
|---|---:|---|
| `memory_migration_pilot/` | 4 | 早期身份映射、参考库、探针和预算审计 |
| `memory_migration_study/` | 101 | 权限、证据、来源卡、交付、当前状态见证、客户端适配 |
| `experiments/` | 200 | 原有实验，包含快照；本轮 `paper_v1` 已排除 |
| `scripts/` | 148 | 运行、结果复核、导出、发布及复现入口 |
| `tests/` | 197 | 单元与回归测试及夹具 |
| `benchmarks/` | 162 | 可复现基准和发布副本；不可与主源码重复计原创贡献 |

## 可以直接复用的核心资产

下表的“直接复用”指有实现和可识别接口；实际新实验仍要建立新数据、新配置、新运行目录，并保留本轮冻结字节。

| 层次 | 文件与主要入口 | 可复用内容 | 不包含的保证 |
|---|---|---|---|
| 独立持久化库 | `experiments/persistent_exchange_v1/store.py`：`AgentStore` | 原始事实/版本、派生正文、直接来源、父记忆、传递依赖、批次与事件链 | 不直接读写 WorkBuddy / Harness 私有记忆库 |
| 权限与首次交付 | 同文件：`TrustedPolicy`、`export_package`、`import_package` | grants、epoch、不可变封包、接收者绑定、nonce/seal、防重放、当前来源版本复查、SQLite ATTACH 原子导入 | 依赖可信本机控制器、权限库和写入者；不是跨机分布式事务或已披露明文撤回 |
| 原始输入与输出绑定 | `run_study.py`：`source_jobs`、来源登记调用；`source_registry.py` | 生成任务的完整业务输入 ID 与产物绑定、失败保留、恢复版本唯一选用 | 控制器可见输入不等于商业 Agent 上游完整上下文 |
| 接收后独立读取 | `read_receiver.py`、`receiver_runtime.py` | 关闭重开、指定批次、只读查询、结果绑定 | 不构成接收方今后不会复制或记住已见明文的保证 |
| 事故与晚到输出核验 | `source_registry_audit.py`、`receiver_recovery*.py`、`completion_failure.py` | 失败分母、未知执行状态、晚到产物独立列账、禁止静默换入 | 原始记录中的额外新 turn 不能重写为旧取消请求自动恢复 |
| 初始分组 D1 | `revocation_grouping_v1/group_planner.py`：`plan` | single/whole/fixed/acl/risk/semantic/joint 七种规划；历史撤权掩码＋词法相似度＋贪心合并代价 | Jaccard 是词法代理；估算成本不等于实测质量或最优性；不声称全新分组算法 |
| 共享重建缓存 | `revocation_grouping_v1/rebuild_cache.py`：`RebuildCache` | 内容、来源版本、配置绑定；strict_epoch 与重授权后重新核权两种复用模式 | 缓存命中不是授权；不会从旧正文中直接删依赖后宣布安全 |
| 公平生命周期执行 | `revocation_grouping_v1/lifecycle_host.py`、`lifecycle_runner.py` | 授权视图、按需重建、完整初建/重建/交付账本 | 历史故事规模小，不能据此证明普遍成本优势 |
| 合法上下文重建 | `permission_context_v1/authorized_expansion.py`；`memory_module_fusion_v1/context_adapter.py`、`support_index.py` | 父子/邻居扩展授权过滤、保守依赖、可替代支撑、合法原文强基线 | 上游片段隔离探针不等于供应商生产漏洞报告 |
| 检索证据修复 | `revocation_evidence_repair_v1/pipeline.py`：`RepairPipeline`；`retrieval.py` | 对当前合法视图重新检索；本地查询产物的内容/种子/配置绑定；原文和 BM25 对照 | 该模块重用的是确定性查询，不是 LLM 摘要；不节约来源生成模型调用 |
| 当前权限见证 | `memory_migration_study/authority_freshness.py`：`SQLiteStateWitness`、`SignedSnapshotStore` | 版本单调性、状态哈希、独立见证与提交检查 | HMAC 不能证明最新；见证与快照须处于独立可信失败域才能主张抗回滚 |
| 事实卡与证据回答 | `memory_migration_study/source_fact_cards.py`、`answer_evidence.py` | 原始事实映射、授权与出处绑定、受约束回答入口 | 模型自报支持不等于因果来源金标 |
| 结果评价与复现 | `persistent_exchange_v1/evaluate.py`；`revocation_evidence_repair_v1/analyze_native.py`；`scripts/export_persistent_exchange_public.py` | 项目/问题簇配对、完整失败与成本分母、冻结结果重评分 | 自动评分不能替代全面语义人工评价，费用估算不是账单 |

## 历史实验资产与统计单位

| 批次 | 已有证据 | 独立单位/当前用途 |
|---|---|---|
| D1 分组开发、短故事与长故事 | `results/revocation_grouping_v1/`；七批公开聚合包含三个分组批次 | 不同批次分别保留；开发与诊断用途，不合并伪造独立 n |
| 父子/邻居授权扩展 | `experiments/permission_context_v1/` | 440 个掩码视图来自两个内容簇；CPU 机制诊断，不是 440 个独立项目 |
| 19 臂融合比较 | `results/memory_module_fusion_v1/` 与公开聚合包 | 小批原生对比；228 行不能当 228 个独立样本 |
| fresh40 证据修复 | `results/revocation_evidence_repair_v1/fresh40-native-combined-20261105-v1-analysis/` | 40 问题簇，600 条请求记录；本轮完整重算 seven result sections |
| 双向持久化交换 | `results/persistent_exchange_v1/` 与公开 14 文件包 | 12 个合成项目、96 条件、768 答案；本轮公开核心结果完整重评分 |
| 多层/攻击机制测试 | 持久化交换的 `mechanisms/`、`security_probes.json` | 独立机制证据，不计入主研究 n=12 |

早期 D1 **已经实现且参加过真实运行**。`final_counts_and_equivalence.json` 显示两个长故事里 joint 与 single 的分区相同，18 个配对交付的业务输入也相同，不能把二者输出的随机差异归因于联合分组。11 月 5 日持久化交换采用的是来源 ID 哈希双块，属于另一方法，不能拿该批次替 D1 作直接结论。11 月 4 日历史计划中“尚未实施”的语句应按当时批次理解。

## 不宜继续扩建的部分与最小新增模块

1. 无需重写 Agent 框架、原生 SDK、SQLite 封包或再次堆叠摘要模块。保留上述宿主为强安全基线。
2. 若研究问题选择“可观察来源证据失效”，最小新增的是**执行边界的输入证据登记/核验适配器**：区分实际可见输入、声明依赖、未知通道；绑定执行尝试、正文、来源版本和撤权版本。必须与已有全输入保守污染、未知即拒绝、合法原文重读作公平比较。
3. 若问题选择增量维护，只增加失效索引与维护策略插件，在同一依赖图、同一合法信息与同一交付门槛下比较；不重写现有安全事务层。
4. 新增受控事件调度和参考 oracle，给遗漏来源、错误声明、迟到输出、撤权/重授权交错提供可观察真值；商业平台只作受限外部验证。
5. 目前尚缺新的独立正式测试项目、语义人工评估协议/评分、已冻结主比较与停止条件。不得用旧 12 项目改名替代新测试集。

这些是候选开发接口，不是已验证的论文贡献。最终选择仍需与文献审计和成熟算法试跑结果共同决定。
