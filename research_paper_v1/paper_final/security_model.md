# 安全模型（冻结范围 v1）

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


冻结日期：2026-11-06，Asia/Shanghai。题目：Authorization-Preserving First Delivery of Persistent Memory Across Heterogeneous AI Agents: System Design and Empirical Evaluation。本文是单受信Host上的交付系统研究；成熟机制的职责、边界和可审计执行是研究对象。

## 1. 实体与可信边界

A为WorkBuddy混元/HY3，B为DeepSeek Harness DeepSeek/Flash；反方向交换采用相同Host合同。每个Agent有独立实验SQLite文件，共用一个TrustedPolicy文件。身份来自受信适配器与宿主配置，不采信模型在正文中的自报。模型生成文本不具有批准迁出权限的能力。

TCB包括Host控制器、生成输入登记、可信策略数据库、接收验证器、正确运行的SQLite/OS/本地文件系统。攻击者可修改/重算交付包公开哈希、错投接收者、重复/延迟提交、恢复旧任务，并与合法撤权事件并发；不能改写受信策略库、接收DB、宿主程序或独立评分真值。宿主被攻陷、恶意策略管理员、文件系统破坏不在安全定理内。

读取许可与向接收者分享许可分开。原始实验通过`grants(recipient_id,source_id)`表示后者，不是通用ABAC语言。完整影响依赖集合由可信控制器依据实际受控输入登记；这可保守包含非必要输入，不能称每句话的最小因果来源。商业服务内部隐藏上下文和隐式读取不在捕获保证内。

## 2. 生命周期与实际代码位置

|阶段|代码路径/动作|状态效应|
|---|---|---|
|Generation|`model_runtime.py`；`source_registry.py`绑定源任务尝试；`run_study.store_generated`|生成候选；不是已交付|
|Staging|`store.py:AgentStore.add_memory`|宿主存储正文、直接输入、父记忆及传递依赖|
|Provenance verification|`_check_artifact`、`_validate_lineage`|核对登记图/正文/身份；不发现隐藏渠道|
|Authorization validation|`TrustedPolicy.check_dependencies`与`_validate_authority`|核当前分享许可及来源版本|
|Delivery preparation|`export_package`|策略库登记绑定正文的seal、nonce、epoch、收者|
|Receiver verification|`import_package`结构/摘要/lineage，再进入事务|收到包不代表接纳|
|Persistent commit|同函数ATTACH策略库，BEGIN IMMEDIATE至COMMIT|正文、batches、导入event和seal消费共同提交|
|Acknowledgment|函数返回receipt；`run_study`在重开核验后写delivery.json|是提交结果的观察；ACK不定义交付时刻|
|Retry/recovery|旧源任务登记；本轮独立metadata回执适配|历史核心拒绝重放；新适配核对已提交包后确认原结果|

生命周期图见[架构](system_architecture.md)；PNG/PDF源于代码路径，不是模拟实验数据。

## 3. 首次持久交付定义

设P包含接收者r、来源版本集D(P)、正文绑定h、import身份i与nonce n。`Commit(P,r,t)`指接收库与authority共同事务在t成功提交，包括batches行、对应正文/依赖、导入审计event，以及seal一次消费。**t为成功COMMIT的线性化点**。包创建、传输、开始校验、返回ACK、模型答题均不是这个时刻。

撤权事件以策略库事务的COMMIT为生效顺序。若撤权先于首次导入COMMIT，则后者必须拒绝；若导入先提交，后续撤权不能追溯抹去已发生披露。并发调用的开始时间不能代替提交顺序。SQLite以DELETE journal、FULL synchronous、同Host文件提供该限定原子性；不宣称跨网络权限服务、WAL多文件或存储硬件失效下的同等保证。

全局epoch相等是本实现额外保守条件：即使无关权限更新也可使旧包失效。这种拒绝不能一律称越权攻击拦截，应相对更细的当前授权oracle计入合法误拒。来源版本改变、撤权再授权的ABA也不会使旧包自动有效。

## 4. 七项属性

|属性|精确定义与前提|原实现与证据状态|
|---|---|---|
|Authorization preservation|每次首次COMMIT，D中每个登记来源的版本/hash/owner为当前且允许r分享|原Store事务内重查；历史18撤权视图及Stage3B支持限定检查|
|Provenance integrity|接纳内容的登记依赖/父闭包/版本与seal绑定一致|原Store实现；不证明实际来源捕获完整或最小因果性|
|Replay resistance|同一seal不能产生第二次新接纳效果；相同batch不能绑定不同包|seal消费与batch唯一约束；历史3类型×24副本探针|
|Receiver acceptance integrity|只有指定receiver才能接纳且持久正文与核验的包一致|严格schema/recipient、hash、trusted seal和导入绑定|
|Revocation consistency|已先提交的撤权/来源版本变化阻止后到首次提交|最终共同事务；不是“撤权请求一开始就生效”|
|Idempotent delivery|同一已提交操作的重试只确认原结果，不新增正文/事件/nonce消费|旧核心仅at-most-once；新增隔离适配已在5/5已有提交确认场景及1个提交前fresh重试场景通过。尚未集成原商业驱动，不把CPU证据称新真实商业执行|
|Auditability|给定可信日志与持久状态可关联包、导入事件、批次和attempt记录|hash链可检测相对可信锚的篡改；管理员可重写全链，完整性不等于全渠道完整记录|

本轮各属性具体基线/故障/消融结果见对应报告。性质论证、实现检查、受控测试和真实模型证据分别报告，不把测试全通过称形式化完全验证。

## 5. 持久幂等确认合同

原`import_package`遇到已消费nonce抛错，是安全的至多一次写入，却无法直接完成ACK丢失后的成功确认。`run_study.deliver`在导入并重开之后才写delivery.json，这个文件缺失不能证明接收库尚未提交。

本轮轻量适配只允许两种分支：①未提交，按原最终验证执行新COMMIT；②已有与完整包摘要、import_id、recipient等完全相符的提交记录，只返回绑定的提交元数据。第二分支不会重新导入、返回正文或要求过去授权仍有效；它不能被当作新的分享许可。相同batch配不同digest、错误收者或篡改包不能得到成功确认。接收者身份由TCB调用环境保证，单靠知道batch_id不是身份认证。

源状态可能晚于接收提交更新；恢复通过接收库事实消除歧义，不宣称源状态文件与接收库分布式原子。两个方向分别有线性化点，不要求A→B与B→A同时全有全无。

## 6. 简短安全论证

在上述TCB和存储条件下，SQLite为authority写者与导入事务建立提交顺序。导入在保留写锁的同一事务内读取epoch、seal、当前来源与grant；若任一谓词不成立则ROLLBACK。COMMIT一旦发生，接收批次、正文/event与消费状态同生共灭，所以不能出现“消费成功但无接收批次”这一稳定提交状态。唯一键和消费谓词阻止两个并发重复请求均产生新效果。

包摘要必须同时匹配可信策略库seal，仅在包内重算hash不能伪造该匹配。依赖闭包检查保证登记对象内部自洽；来源真实覆盖来自TCB输入记录，不由hash推出。metadata恢复分支不产生新披露效应，因此不改变第一次提交时的授权判断；若无法证明曾正确提交就保持拒绝/未知，不猜测ACK。

## 7. 明确不作的保证

不保证模型遗忘、商业私有内存迁移、所有隐藏输入捕获、开放世界推断非干扰、恶意Host可审计完整性、网络分布式原子交付或任意宕机/硬件断电下的全部调度。真实进程崩溃测试只能验证所执行切点，不能替代存储模型证明。
