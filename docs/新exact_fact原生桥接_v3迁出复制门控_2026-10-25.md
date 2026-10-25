# 原生 exact-fact 桥接 v3：复用既有迁出、复制强基线

本轮只补齐原项目已经要求的权限范围，不提出新授权算法。v2 的 17 项检查验证了受控源读取、目标原生用户隔离和显式清理；当时尚未独立检查迁出、复制许可，不将 v3 范围回填到 v2 结果。

## 权威输入与执行顺序

1. 源 child 使用真实 Mem0 2.2.1、研究 ACL 网关和本地 MiniLM。`infer=False`，禁止生成和外网。迁移策略放在独立 `TrustedMigrationControl` 中，不从记忆正文或模型输出提取。
2. 实际源读取返回 200 后，RPC 另附 `trusted_migration_control`：原生源 ID、原文 SHA-256、实时源读者及独立迁移策略。读取失败不交付该控制信息。
3. 可信 host 对本次返回的 ID、原文和摘要与签名事实包逐项绑定，继续调用原有 `MemoryLabelAuthority.validate_access` 核验事实内容、范围、用户、固定执行 Agent、策略版本和 epoch。
4. 复用 `memory_migration_study.policy.validate_case/decision/make_plan(method="reader_copies")`。三方读者分别来自实时源 ACL、签名事实包的读者以及本次要求建立的原生用户副本。`actor_mapping` 覆盖 owner/assistant/outsider，映射到目标初始化实际 whoami 核验的不同原生用户 ID。
5. 规划器中的逻辑 source ID 是签名 `record_id`，另记录它与实际原生 source ID、源摘要、事实摘要及精确 range 的对应关系。源全文仍不发给目标；目标仅收到 `{actor,text,path}` 中的有权 exact fact。
6. 所有目标读者均在写入前通过检查，整个批次读取的控制凭据一致，才调用原生 add。任一检查失败均不得提前写入已通过的部分受众。

`export_allowed` 和 `copy_allowed` 必须分别为真正的布尔 `True`。False、None、缺失按原规划器拒绝；数值 1 或字符串 true 是非法类型，不能充当 True。未知策略字段或不能由目标表达的能力在写入前拒绝。自身必须能力始终包括 `user_read_acl` 和 `fixed_application_worker`，源要求只能增加限制，空列表不能取消这些基础要求。

## 新受控对照

预写入对照保留原有内容、范围、用户、Agent 等负例，新增“源仍读 200，但 export/copy 禁止或未知”、非法布尔、未知约束和原生 per-Agent ACL 要求。单元测试还覆盖正文写着 allow 仍无迁出资格、完整/单射身份映射、实时源读者元数据、批次中途策略变化、全受众先规划，以及对原强基线函数的实际调用。

在已经建立合法副本后，另将 trusted export 置 False：源应继续返回 200，旧任务新迁出应在 add 前被拒绝，目标既有副本仍保留。恢复 export 后，继续原有源 read 撤权、清理前可见性观察、逐真实 copy-owner 删除全部指定副本、旧 ID/list/search 不可见、旧任务拒绝重建、resident 和独立合法控制保留。禁止新复制不表示已经交付的明文被撤回。

## 范围

v3 另补原生向量查询路径。固定 OpenWebUI 0.12.3 的 `/memories/search` 是词法/ID 查询；真正的向量查询为 `POST /api/v1/memories/query`，固定非机密 query、`k=100`。三个用户均由目标内部原生 add 建立无关 own-memory resident；这不是向 outsider 迁出源记忆。清理后所有账户仍非空，不能因“账户没有 SQL 记忆”跳过向量检索而掩盖残余。

每次 snapshot 保留原查询 JSON 的 ids/documents/metadatas/distances 和完整响应原文、摘要。小 fixture 下要求所有本用户合法 ID 均检出，不能存在已删 ID 或他人 ID；文档须严格等于该版本 `memory_vector_text(content,path)` 的规范路径、换行和原内容，元数据须与原生 SQL list 的四字段一致。只在实际 SQL list 也为空时，将精确 `404 {"detail":"No memories found for user"}` 单列为空账户合格观察；其他错误不能当 empty。已有 resident 时返回该 404、漏正控、索引残留、文档或元数据不符均失败。不会修改 relevance threshold 来获得成绩；检索正控不足是仪器不合格。

v3 的运行目录与协议版本独立；不修改任何 v1/v2 原始工件。继续归档当时全部自有 package 源码、四份 native 脚本和两个旧入口；执行前逐文件核 SDK 清单，执行后核代码和本地模型/DLL/配置资产摘要，新增固定本机 memories router、memory formatter 和 vector 契约文件的摘要。保留网络拒绝事件并将协议违规记为整体失败。

为独立验收，RPC 收据保留合成命令输入、结果、双方摘要及单调时间顺序；不包含源/目标凭据、签名密钥或恢复映射。另提供签名 grant 的公开载荷以复核 exact fact 范围，不包含签名，也不称为独立 HMAC 核验。whoami 只保存 actor、ID、role 和请求序号，完整认证响应继续省略。

目标只具备原生用户 ACL 和固定应用 worker。源 Agent 约束由可信 host 核验，不是 WebUI 原生 Agent 身份；任意委托、用途或派生约束并未通用表达。当前 fixture 也不证明并发原子迁移、检查后写入窗口消除、源撤权自动清理目标，或让已经获得明文的接收者遗忘。新增门控属于复用原有强基线的工程补齐，不能作为论文新算法效果。
