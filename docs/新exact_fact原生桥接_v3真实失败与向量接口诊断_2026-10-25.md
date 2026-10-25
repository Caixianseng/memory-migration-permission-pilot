# exact-fact 原生桥接 v3：真实失败与向量接口诊断

本说明只记录已完成运行的只读核验及下一步诊断方案，不修改旧结果、不重启后端、不追加模型调用。

## 1. 真实运行结论

`results/native_exact_fact_bridge_20261025_v3` 的进程已结束，退出码 1。29 项功能检查中 **25 项通过、4 项失败，整体协议失败**。该向量子目标本轮实际失败一次，按 L0 记录；四个异常响应不能计作四次实验。

源本地 embedding 方法调用 2 次、目标本地 embedding 函数调用 21 次，生成和付费 API 调用均为 0，未出现被网络防护阻断的外联。64 份自有源码归档、15 项资产后验摘要及 8,875 个 SDK 文件核验通过。这些完整性证据不抵消功能失败。

四项失败为：

- `export_disable_does_not_revoke_already_delivered_copies`
- `native_copies_still_visible_before_explicit_cleanup`
- `all_old_ids_removed_resident_and_valid_control_preserved`
- `replay_left_target_matrix_unchanged`

不得把本次结果包装为“原生向量路径零泄漏验收通过”。未发现返回他人敏感数据，与向量接口已正确执行、合法正控可检索，是不同结论。

## 2. 原始响应不是空命中，而是 HTTP 200 + null

已逐字读取下列实际 `.bin` 响应文件，四份内容均为四个 ASCII 字节 `null`，SHA-256 均为 `74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b`，与 NativeRecorder 收据一致。

| 原生请求序号 / 响应文件 | 主体 | 阶段 | 实际状态和内容 |
|---|---|---|---|
| 71 / `target_state/responses/00071.bin` | assistant | 禁止新 export，已有副本应保留 | 200，`null` |
| 98 / `target_state/responses/00098.bin` | assistant | 源 read 撤权后、目标显式清理前 | 200，`null` |
| 136 / `target_state/responses/00136.bin` | outsider | 两个指定副本清理后 | 200，`null` |
| 163 / `target_state/responses/00163.bin` | outsider | 旧任务被拒绝重建后 | 200，`null` |

全部查询固定为 `Customer service and delivery status.`、`k=100`。首次迁移后的向量查询曾分别完整返回 owner 2、assistant 3、outsider 1 条记忆。后续 null 不能当作 `ids=[[]]`，也不能当作合格空账户观察。

## 3. 已确认的调用链和未确认的根因

本机固定版本为 OpenWebUI 0.12.3、Chroma 1.5.9。官方固定 tag 的代码与本机相关实现一致：

1. [`routers/memories.py` 的 `/query`](https://github.com/open-webui/open-webui/blob/v0.12.3/backend/open_webui/routers/memories.py#L327) 先读 SQL 记忆、计算查询向量，再调用原生 vector search。相关性阈值过滤即使清空全部结果，也会构造 `SearchResult(ids=[[]], documents=[[]], ...)`；其结果形态不是 JSON null。最后直接返回 `results`。
2. [`AsyncVectorDBClient.search`](https://github.com/open-webui/open-webui/blob/v0.12.3/backend/open_webui/retrieval/vector/async_client.py#L105) 通过 `asyncio.to_thread` 调用同步适配器；并非本脚本自行模拟向量结果。
3. [`ChromaClient.search`](https://github.com/open-webui/open-webui/blob/v0.12.3/backend/open_webui/retrieval/vector/dbs/chroma.py#L79) 将 get_collection、collection.query、距离转换和 SearchResult 构造放在同一 try 中，任一 Exception 均返回 None，且该 catch 没有记录异常。None 随后可被路由序列化为 HTTP 200 + null。
4. [`chromadb.api.rust.RustBindingsAPI._query`](https://github.com/chroma-core/chroma/blob/1.5.9/chromadb/api/rust.py#L553) 将查询交给 `bindings.query`。当前没有本次异常类型或堆栈，不能进一步确认究竟是哪条底层操作失败。

本次 child 的 stderr 被丢弃，适配器又不 log 被吞异常，因此**具体根因仍未知**。已证实的定位是“原生 vector 适配链未交付合格结果”，不是“已确认近似搜索漏召回”。不能未经新证据归因于机器环境、阈值、异步索引或特定 Chroma bug。

首次两个 null 发生在任何目标 delete 之前；这不支持用“本次删除把存活节点隔离”解释全部失败。官方仓库 [#7758](https://github.com/chroma-core/chroma/issues/7758) 有用户报告 1.5.9 经大量 delete/upsert 后 get 存在而 query 不返回的现象，但其规模、结果形态和操作顺序与本次不同，且不是本次根因的维护者确认，不能直接套用。

## 4. 集合和合法正控的只读核验

三个目标原生用户与 Chroma collection 名称一一对应：

| 主体 | 原生用户 ID | collection ID | 最终应保留 / SQL 正控数 |
|---|---|---|---:|
| owner | `39e06e2f-b24e-4fea-bf07-c72e9c07bb33` | `e7fb198c-0a52-4c6b-b9e8-c71d0ce67e3a` | 1 |
| assistant | `3db97b35-f59d-475c-8657-7ac87a337709` | `83639f0a-3dc2-45af-981f-1ac07f93e406` | 2 |
| outsider | `1571b6d5-9a8b-4f65-a890-9f40a333ad29` | `1b0ef382-57b2-4673-be49-40205077303e` | 1 |

collection 名称均为 `user-memory-<相应原生用户ID>`。实际 SQL list 仍显示各主体合法 resident，assistant 还保留独立合法源控制。另以 `mode=ro&immutable=1` 只读打开原 Chroma SQLite 主文件，核得 metadata segment 中最终仍为 1/2/1 个合法 ID，与这些正控相符；没有原地启动 ChromaClient。

这只证明已保存 SQL/metadata 正控存在及集合命名对应；不证明 HNSW 向量索引当时可用，也不证明全部物理介质或缓存已删除。未找到集合映射混淆的证据，但没有对底层运行时行为作排除性证明。只读主文件中没有持久化 relevance 配置项；由于 immutable 读取不重放 WAL，不将其当作运行时阈值的直接证明。

## 5. 下一步最小诊断方案：先方案，不执行

在新的隔离目录和 child 中进行定量受限的诊断，不重跑整个源→目标资格矩阵，不改 v3 工件、生产包、query、`k=100`、阈值或网络白名单。

首先可用相同 Chroma 1.5.9、三个 collection、固定非敏感 384 维合成向量复现 2/3/1 条记录、重复 query 和指定删除，完全不加载模型。保留真实 Chroma 返回及异常，不以 Python list 模拟索引。若不能复现，再用 target-only 原生 WebUI 小场景：三个用户、相同六条合成记忆，固定 query 各用户两轮，删除两份 main copy，再各用户两轮。此阶段最多 6 次写入 embedding 和 12 次查询 embedding，生成仍为 0。

只增加观测，不改变原函数的返回、异常处理或访问控制：

- 在实际 `ChromaClient.search` 工作线程捕获该固定函数收到且被吞的异常，保存 exception class、message hash、受控脱敏消息/代码行、collection 和场景 stage；不读取或记录认证凭据。
- 同时记录 collection 名称、ID、tenant/database、count/get 的合法 ID，查询向量维度、是否有限、范数和哈希，原生 SearchResult 或 null，以及实际生效的 relevance threshold。
- 将每次调用与 native HTTP 收据、原始响应和 embedding 计量关联，区分 adapter 异常、有效空结果、正控漏召回、读权拒绝及集合不存在。

不得静默回退 SQL、重新嵌入、清库重建、改阈值或把 null 默认成 empty。不得以重试后的成功覆盖首次失败。得到异常证据后再决定是否有明确、可复核的最窄修复；当前不声称原生向量资格已成立。
