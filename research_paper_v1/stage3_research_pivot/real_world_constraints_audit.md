# 真实系统约束审计

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


日期：2026-11-05。证据等级：**H**为历史公开投影；**C**为当前拥有实现的代码；**D**为公开原始技术文档；**Q**为本阶段新受控测试；**U**为未验证。模拟能力边界只能记Q，不能变成商业平台H。引用版本和检索限制见 [技术来源表](evidence/public_constraint_sources.json)，代码定位/历史哈希见 [本地证据](evidence/existing_evidence_capture.json)。

## 1. 异构入口和授权

| 问题 | 真实系统是否存在 | 本项目是否出现/可验证 | 证据 | 简单批读能否解决；还缺什么 |
|---|---|---|---|---|
| 文件、SQLite、API接口不同 | 是，D | 是，C | model_runtime.py:43、61、101；sdk_adapter.py；store.py | 统一副本可批读，入口需适配器；接口差异不要求新算法 |
| 工具结果与会话历史来源不同 | 是，D | 是，C/H | 原生function_call与JSONL；SDK消息/结果回执 | 已采集内容可索引；未采集事件需受信中介 |
| 其他Agent提供的记忆 | 是，本地实际双向交付H | 48 A→B、48 B→A条件 | records.public.json；store.py:485、510 | 封装可批量，来源和接收者绑定不能省略 |
| 不同来源/主体权限不同 | MCP资源受众/上游授权分离，D | owner_id与recipient grants，C；独立多租户认证U | store.py:373、403、436；MCP授权 | 分主体授权、同域分批；集合差不验证授权 |
| 读取许可与分享许可不同 | 合同上不同；OAuth读令牌不等于分享授权，D | allowed_read_paths与recipient grants分开，C | model_runtime.py:61；store.py:403 | 两个判据分别中介；不能将“读到了”当“可转交” |
| 人工逐来源授权 | 协议允许用户授权交互，D | 尚无逐来源人工工作流计时，U | MCP授权；阶段2 human_review=null | 同意记录/状态机可实现；没有实测成本收益 |
| 撤权后不能重读 | 由来源/策略决定，不是统一产品定理 | 本地policy撤权可验证，C/Q；商业远端撤权未探测U | set_permissions；B测试 | 合法拒绝/新尝试；缓存不得绕过撤权 |
| 可读但禁传 | 明确分享策略可表达 | Host对接收者拒绝，C；OS文件ACL细分U | _validate_authority、read-path audit | 简单来源授权足够处理明确记录级策略 |
| 受限文件 | 现实OS/服务访问边界存在；部署细节U | 显式工具路径审计，非OS沙箱完整证明 | receiver_runtime.py:129附近；model_runtime.py | 中介所有通道；事后工具审计不能证明未知通道无读取 |

## 2. 时间、版本与并发

| 问题 | 真实系统依据 | 项目状态 | 证据 | 简单批读能否解决；所缺能力 |
|---|---|---|---|---|
| 读取期间权限变化 | 并发独立连接可更新，D | 第二阶段只串行注入；第三阶段B定向调度另记Q | SQLite隔离；B原始结果 | 批读不是检查/使用原子化；需事务或资源端fencing |
| 内容更新 | 版本化对象/API存在，D | 当前source_version/hash检查，C | register_sources、_validate_authority | 固定版本与提交重验；不应称新方法 |
| 旧版本缓存 | 可能发生，D | 存储不可变版本、当前登记版本，C | store.py:373–399 | 版本化cache key＋失效，成熟机制 |
| 多任务并发 | 网关队列/线程与独立DB连接，C | 旧H无全面调度覆盖；B新增受控Q | model_runtime.NATIVE_CREATION_LOCK；B测试 | 序列化/幂等/原子提交；不由差集解决 |
| 旧会话恢复 | 原生job状态/显式恢复模块，C/H | 7次登记有效恢复，H | source_registry；audit_summary | attempt身份与状态机；恢复不自动批准旧包 |
| 迟到生成结果 | H中1个续执行事件 | 明确未参与质量/选择，不是迟到越权交付 | source_recovery_registry | 单调attempt/fence和最终门控；既有实现已分类 |
| 检查至提交时间差 | 本地代码路径存在，C | 原Store最终ATTACH事务重验；stage2读ACL窗口未原子 | store.py:510–567；stage2 runner | 同一强基线原子边界内可解决；外部执行边界另有合同 |
| 已导入后权限撤销再读取 | 明文已经在接收库 | 当前读回不重查policy，明确首次交付合同 | read_receiver.py:1–10；check_dependencies | 属后续使用授权新目标，不是原首次交付缺陷；已披露内容不能被强制遗忘 |

## 3. 失败和证据完整性

| 问题 | 真实系统依据 | 项目状态 | 证据 | 简单批读能否解决；所缺能力 |
|---|---|---|---|---|
| 来源/生成结果不可用 | API/文件可失败，D | 7终端队列无产物、4截断、1无输出等H | source_attempts公开投影 | 失败关闭与显式恢复；不能猜证据 |
| 限流 | 官方API存在限流，D | 7登记quota恢复由旧审计报告支持；本轮不查实时额度 | source_registry._quota_binding/_pair | 限流退避与幂等；批读能减请求但不能取消配额 |
| 网络超时 | 传输/进程请求有超时，D/C | SDK和gateway明确timeout；历史是否网络超时未逐条独立定位U | sdk_adapter.py；model_runtime.py:43 | 超时后不确定执行状态需回执/查询，不盲重发 |
| 接口不支持跨域统一批查询 | MCP不规定统一业务读，D | 两平台不同入口C | MCP Tools/Resources；model_runtime | 适配器分域读取；无证据证明新优化器必要 |
| 不同验证方式 | 受众token、内容摘要、Host回执各证不同命题 | 摘要/原生模型身份/输入路径/接收读回分别审查C | runtime/store/read_receiver | 类型化验证和信任边界；哈希不等于来源完整 |
| 当前结果不能证明历史版本 | HTTP版本前提只验证表示，D | 显式历史证据与当前重读分离C | RFC9110；stage2证据模型 | 不可变日志/可信历史绑定；无法观察则unknown |
| 来源声明与实际读取不一致 | 完整中介前提失效会造成证据缺口 | 26项source protocol关闭H；不能全称恶意读取 | audit_summary.source_protocol_audit | 可信输入包络/IFC；批读集合本身无法补未记录输入 |
| 来源记录与交付不一致 | 可由篡改/错误绑定触发 | 旧72个拷贝攻击被拒H；新A/B另记Q | security_probes.public.json | host seal/nonce/recipient/artifact校验，成熟强基线 |
| 接收方已有知识和多次组合 | 传统推断控制有直接工作 | import历史存在，但未参与语义授权，C | policy schema与_validate_authority；C报告 | 需声明敏感命题及CQE合同；来源分享策略不包含这一目标 |

## 4. 审计结论

现实约束确实超出了集合差的职责，但这不是“集合差算法失效”的同义词。定位、授权、完整性、事务、推断保密是不同合同。应给每种合同最简单而足够的传统基线，再检验是否仍有Agent特有且可验证的剩余缺口。

现有历史证据显示协议关闭和执行不确定性，尚未给出原首次交付合同内的实际越权交付日志。对商业Agent完整内部上下文、隐藏工具、全供应商物理请求数仍为U。本阶段没有把模型声明、可读取JSONL或自洽哈希升级为完整远程证明。
