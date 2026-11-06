# 任意ID批读假设：局部成立，不能代表全体来源

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


核验日期：2026-11-05。第二阶段的结果保持有效：同一可信SQLite回执库支持按缺失ID一次IN查询时，差集＋缓存＋批读是必须保留的强基线。当前调查检验其适用范围，没有通过剥夺基线能力重新宣称贪心胜出。

## 1. “批量”实际包含四件不同的事

1. 在同一存储后端按多个键读取：SQLite IN查询可做到。
2. 一个协议列举多个资源：分页resources/list或tools/list不是多源内容读取。
3. 调用一个自定义工具同时读取多个后端：需要该工具真实实现、逐后端授权与错误处理；协议封装不自动提供这一能力。
4. 获取同一历史生成尝试的完整输入证明：即使当前内容可批量下载，也不等于过去的读取回执完整。

MCP固定版本2025-06-18区分工具参数、URI资源和应用驱动的上下文纳入；没有规定所有工具必须支持一个统一的多ID内容读取或全局历史快照。[Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)、[Resources](https://modelcontextprotocol.io/specification/2025-06-18/server/resources)。这是协议能力范围的核验，不能外推成每个商业产品均不支持批读。

## 2. 八类来源的适用性

| 来源 | 已核验的实际接口/工程证据 | 任意批读是否成立 | 缺少的能力与最强简单处理 |
|---|---|---|---|
| 本地记忆文件 | model_runtime.py:61–95审查显式Read/Write路径；输出为本地文件 | 可以由Host逐文件或自定义批工具读；不是原生历史证明 | 固定清单＋文件摘要/版本＋同权限分组读取；仍要受信输入边界 |
| SQLite | stage2 runner.py中实际SELECT IN；原store以batch_id检索已提交记忆 | 同一库、权限已中介时成立 | 索引差集批读足够，保留为强基线 |
| 外部API | SDK调用与本地文件读取为不同路径；GitHub官方Contents接口按path/ref访问 | 取决于API契约，没有统一保证 | 适配器、限流/失败处理、版本固定；不能凭接口不同证明需要新优化算法 |
| 工具调用结果 | 原生会话function_call审计和SDK响应字段不同 | 可以汇总已收集记录，不能生成未采集的历史结果 | 受信工具回执、attempt绑定、覆盖声明 |
| 会话历史 | WorkBuddy本地session JSONL显式解析；Flash供应商请求总上下文不是同一证据 | 已存JSONL可批量读；隐藏上下文未知 | 记录可观察范围，完整性无法核验时保持unknown |
| 其他Agent记忆 | export_package/import_package，接收者与nonce、版本、内容绑定 | 单包可含多记忆；包间授权仍须重验 | 现有封装与原子导入即可处理已声明依赖 |
| 受限文件 | 原实验通过allowed_read_paths协议审查显式读；没有逐文件Windows ACL实测 | 不能据能打开一个文件推定可读/分享全部文件 | 分开读取许可与交付许可；OS中介与审计范围明确 |
| 版本化来源 | TrustedPolicy source_versions；GitHub对象SHA/ref | 当前版本可多键获取；能否取旧版本依赖保留策略 | 版本键、不可变历史、条件请求；当前重读不追认旧run |

代码行号、SHA与公开历史文件哈希见 [existing_evidence_capture.json](evidence/existing_evidence_capture.json)。没有新调用WorkBuddy/Harness，没有声称探测了其隐藏记忆库或所有工具API。

## 3. 权限和一致性不由批读解决

读取权限是“执行者现在可获得内容”；分享权限是“此接收者此次可收到哪些内容”。原Store的grants约束后者，allowed_read_paths协议审查关注前者，两者不应混同。MCP的HTTP资源受众验证和上游独立令牌也不赋予下游分享许可。[授权规范](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)

Host将多种来源复制到统一数据库后，通常可对**这些已经合法收集的副本**批读；复制过程的权限、费用、完整性和版本绑定不能因此略去。如果副本不包含合法历史回执，统一查询不会把它变成历史证据。这是数据入口和语义合同问题，不是集合差的计算缺陷。

SQLite跨附加库原子提交具有明确前提：非内存主库、非WAL日志等；它不提供跨外部API的统一提交。[ATTACH原子性](https://sqlite.org/lang_attach.html)。原persistent Store使用文件库和DELETE日志正是符合其本机合同。不能拿外部服务不参与SQLite事务，证明该本机强基线在自身合同内失效。

## 4. 读取失败和历史版本

GitHub官方API既有Contents端点限制也有限流规则；HTTP强ETag条件可判断当前表示是否匹配，不能证明某Agent过去实际读过该表示。[Contents](https://docs.github.com/en/rest/repos/contents)、[限流](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)、[RFC9110 If-Match](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match)。没有访问旧版本能力时，正确输出是无法恢复该类历史义务，不是让模型填补。

本项目已有工具协议关闭、队列执行未知、截断和接收端provider500的历史投影；这些事实说明读取/执行链会失败，但不能统称“缺一条来源回执可低成本挽救”。限流后自动重发也可能重复生成，因此现有代码将状态读取重试、显式恢复和模型重提交分开。

## 5. 对第二阶段负结果的影响

任意批读作为**唯一真实异构系统模型**偏理想化；作为**单Host回执库强基线**合理且必要。其他现实来源存在跨域授权、历史绑定和可观测性约束，但它们尚未提供加权贪心的新增优势证据。正确下一步是辨认安全合同与中介边界，不是去掉批读、把随机固定包改称商业现实后重新跑成本实验。

本报告不改第二阶段数据与结论，也不把接口适配工作自动升级为论文贡献。方向资格分别由A/B/C的成熟安全基线检验。
