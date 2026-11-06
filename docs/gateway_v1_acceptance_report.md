# Agent Memory Gateway V1 工程验收报告

**最终状态：FeatureFrozen。固定核心工程门槛通过；现有接口测试仍保留13/14通过及1项精确错误码断言失败。**

日期：2026-11-06（北京时间）。固定campaign已经完成，独立只读verify为PASS。本报告只读取已停止写入的completion、verify、analysis summary和regression outcomes，以及此前保存的预检查证据；编写报告没有重跑测试、模型、统计分析或campaign，没有改动原始结果、核心代码或冻结脚本。

## 1. 验收对象与冻结范围

现有 `GatewayService`、HTTP API、`delivery.py`和成熟Store继续使用，仅增加显式JSON文件适配器及其合同测试。单机可信Host负责来源登记、最新授权、来源版本、首次持久交付、绑定回执与恢复；WorkBuddy/Harness的内部隐藏记忆不属于可观测或可控制范围。

冻结合同见 `docs/gateway_v1_scope_lock.json`：

|项目|冻结内容|
|---|---|
|现有工程基线commit|`16cbdc644f0bfaf6b35003a3bb0047b6cc1c812f`|
|历史main参照SHA|`23031a667396c43a1e7b89124136edc19184bd86`；不是本报告声称已重新远程核验的最新值|
|历史科研分支参照SHA|`d3a0c2f92533e070bfcca5e087b5c832eea7a331`|
|旧C新复现上限|3次；已使用1次|
|核心修复上限|2轮；当前0轮核心补丁|
|强基线完整比较|1次固定campaign已经完成；不追加比较轮次|
|故障范围|8个冻结时序×3方法＝24行，不扩充故障范围|
|性能范围|10个受控合成项目尺寸夹具×每方法每项目6次＝180行，不是180个独立真实项目|
|新增付费模型调用|0|
|不可改变的历史材料|历史原始数据、冻结768/720评价、Ground Truth与主分支|

### 新旧方法名称

|名称|含义与能力|本次角色|
|---|---|---|
|旧`source_dynamic_version_no_tx` / 旧C|检查后分别写接收端、消费seal；存在已提交效果与未消费seal分离的窗口|保留历史失败证据，不进入生产路径，不称为新Gateway的C|
|新A：ACL reference|普通ACL参考实现|能力差异诊断对照|
|新B：transaction reference|直接调用成熟的原子最新权限/版本、一次提交、持久回执与幂等核|公平强基线|
|新C：GatewayService|通过现成服务包装调用与B相同的成熟核|工程交付对象；允许与B安全结果完全相同|

B和C共享成熟实现是冻结设计，不是需要隐藏的重叠。比较不要求人为制造C优于B，也不能把旧静态ACL＋Hash的B标签挪作本次强B。

## 2. 已完成且有保存证据的工作

### 2.1 旧C故障已实际复现一次

依据：`docs/gateway_v1_C_fault_audit.md`、`docs/gateway_v1_execution_ledger.json`；详细只读审查保存在工作目录 `D:/agent安全论文/agent-memory-gateway-v1-work/evidence/c_fault_source_audit.md`。

- 原样旧worker在接收端autocommit INSERT后、seal消费前退出，退出码91。
- 已复现“接收效果存在、seal未消费”的状态；epoch变化后旧路径重试返回`stale_policy_epoch`。
- 重试前后效果数均为1；此现象不能直接报告成新的重复持久效果或越权首次交付。
- 使用新的工作目录，未对历史孤立效果伪造回执或自动迁移。
- 已保存的审查记录说明：相关12个接收/权限库为DELETE journal，未据此臆造WAL故障。

**处置：采用已有成熟D/E事务与绑定回执核替代旧C生产路径，不修补旧C比较器。当前核心修复轮数0。**

### 2.2 已有成熟核继续使用

`agent_memory_gateway/delivery.py`先核验完整身份/摘要绑定的已提交回执；首次提交仍调用成熟Store的单机SQLite ATTACH事务，将当前权限/版本检查、接收数据、事件、批次与seal消费一起提交。重复确认只返回元数据，不重新交付正文。

本次没有提出新的原子性算法。completion记录`B_C_same_core=true`、生产代码/验收代码哈希保持不变；成熟Store的SHA256仍为`36e8c5cb016c2d1bd2ffbded384633279e33d9eb5354b0267ea6f04604b34c40`。复用处置与固定验收分别有证据，不把两者合并成算法创新。

### 2.3 两个方向的存档业务记录重放

依据：`docs/gateway_v1_execution_ledger.json`中的`platform_archive_adapter_checks`。

|方向|当前保存的执行结论|解释边界|
|---|---|---|
|WorkBuddy导出记录→Harness方向上下文|通过；两方向检查之一|使用历史真实模型输出记录的文件导入、持久化和读回，不是新的商业推理|
|Harness导出记录→WorkBuddy方向上下文|通过；两方向检查之一|平台/模型标签是业务导出元数据，不能证明商业平台内部全部记忆或隐藏来源|

新增商业模型调用0。文件适配器不读取账号/原生会话目录，不自动授予分享权限，不自动准备/提交交付；模型/供应方声明明确未验证。原始来源只保存稳定的`source_type/registered_by`；导出文件SHA及方向绑定到本次记忆来源记录/回执，避免正常新派生导出改变同版本original metadata。

两方向计数来自已保存执行台账，其业务输入/输出与摘要由执行者归档；不虚构额外商业调用或运行文件名。

### 2.4 接口与适配器测试：13通过，1失败

实际日志：[接口与适配器测试日志](gateway_v1_results/interface_adapter_tests.txt)；本地原日志为`D:/agent安全论文/agent-memory-gateway-v1-work/evidence/api_adapter_tests.log`。共执行14项：5项现有API合同＋9项适配器合同，13通过、1条旧精确错误码断言失败。**不能写“14项全部通过”。**

失败项：`GatewayApiTests.test_spool_tampering_rejected`。

|保存的事实|实际结果|
|---|---|
|HTTP安全结果|篡改请求被HTTP409拒绝|
|旧测试期待错误码|`packet_content_hash_invalid`|
|实际提前拒绝错误码|`confirmation_packet_digest_invalid`|
|测试结论|精确错误码assert失败；不是未拒绝篡改|
|本次处理|保留失败日志，不改变生产校验顺序或安全门槛来强行获得PASS|

台账还记录两个执行前问题：点式测试导入被已安装`tests`包遮蔽，以及受限Windows通信条件下socketpair阻断。它们未被冒充已完成测试；最终14项日志独立保留。当前报告不因此追加测试轮次。

## 3. 固定8场景结果

本次实际保存24行故障结果。下表直接对应[regression outcomes](gateway_v1_results/regression_outcomes.csv)及[独立verify](gateway_v1_results/independent_verification_summary.json)的完整合同判定；效果数为故障与恢复流程结束后的持久效果数。

|冻结场景|A：ACL|B：transaction|C：Gateway|关键实际结果|
|---|---|---|---|---|
|R1 `before_receiver_write`|PASS|PASS|PASS|合法重试后均为1个效果|
|R2 `after_write_before_commit`|PASS|PASS|PASS|回滚/重试合同成立，均为1个效果|
|R3 `after_commit_before_ack`|FAIL|PASS|PASS|效果均为1；A不能完成保存合同要求的确认，B/C各成功确认1次|
|R4 `duplicate_after_ack`|FAIL|PASS|PASS|效果均为1；A缺少同包重复确认，B/C各确认1次|
|R5 `revoke_after_precheck_before_first_commit`|FAIL|PASS|PASS|撤权后A仍产生1个效果，B/C均0个效果并拒绝旧包|
|R6 `restart_repeat_recovery`|FAIL|PASS|PASS|效果均为1；来源升级/撤权后B/C两次扫描正确分类已提交与未提交任务，A未满足合同|
|R7 `concurrent_same_transfer`|FAIL|PASS|PASS|A产生2个效果（多出1个）；B/C均1个，返回一次新提交和一次既有确认|
|R8 `packet_tamper`|PASS|PASS|PASS|三方法均拒绝修改包，效果均0|

完整合同通过：A为3/8，B和C各8/8。A在固定时序中出现1次越权首次效果和1个额外重复效果；这些是8个指定时序的事件计数，不是商业总体发生率。A未通过的其他场景包含确认/恢复合同缺项，不能统称全部发生了越权或重复。

|冻结门槛|结果|实际证据|
|---|---|---|
|B/C无越权首次持久接收|PASS|固定结果各0；R5当前授权清空、旧包未产生接收效果|
|B/C无重复批次效果|PASS|固定结果各0；R7均只有1个持久效果|
|已提交后的回执恢复不含正文|PASS|B/C各5次成功元数据确认；verify核对不含正文，失败重试不混入成功确认耗时|
|B/C拒绝被改包|PASS|R8均拒绝且0效果；不要求相同校验首先返回|
|回滚后合法重试成功|PASS|R1/R2固定合同通过，最终一次接收|
|平台导出两个方向可持久化和读回|PASS（存档重放）|已保存台账2/2；新增商业调用0|
|固定行数/版本/原始文件完整性|PASS|completion保存24故障行、180性能行；verify完整性/记录一致性通过|

独立校验器使用标准库JSON/hashlib/sqlite3，不导入被测runner、Gateway或Store；实际只读检查136个receiver/policy库，数据库写入0、场景重新执行0，`verification_passed=true`。校验结论包含最终数据库独立观测；过去的故障顺序依据保存的进程、marker与快照，不声称重新观察了过去全部SQL执行。

## 4. 实测性能与存储

依据：[analysis summary](gateway_v1_results/summary.json)。10个受控合成尺寸夹具，每方法每夹具6次，三方法各60/60正常提交，共180行。耗时边界包括保存包解码、打开/校验、持久接收与关闭到元数据返回；不含进程启动、来源登记/记忆生成/prepare和ACK输出端fsync。

|方法|正常提交|交付均值ms|P95 ms|每次逻辑SQL均值|夹具结束receiver DB平均字节|
|---|---:|---:|---:|---:|---:|
|A ACL reference|60/60|80.076|30.407|53.0000|135168.0|
|B transaction reference|60/60|168.016|35.065|62.4167|127795.2|
|C GatewayService|60/60|334.085|3316.543|62.4167|127795.2|

P95采用`ceil(0.95*n)`的nearest-rank定义，全部观测保留。实际耗时有秒级长尾，均值高于P95也可能由分位点之外的少数大值造成；不能据此删值。本次没有定位长尾原因，不归因为某个数据库、平台、缓存或调度机制，不通过优化、重跑或剔除异常来重写结果。

B/C平均逻辑SELECT语句均19，平均逻辑写语句均13.4167；A分别为9和5。三方法夹具结束policy DB平均57344字节、spool平均17256.6字节。这里的存储量是夹具结束文件大小，不是每次交付新增空间或物理写入字节。SQL语句不是物理磁盘I/O；summary的`physical_io_operations`均为null。

本次C没有显示比成熟B更低的时延，逻辑SQL和接收库规模相同；安全结果也同为固定8/8。这支持既有成熟核的服务包装可用，不能包装成新算法安全性/效率超过强基线。耗时和存储只作本次固定环境的描述，不给显著性或总体性能优势结论。项目内重复不是独立自然项目，未新增bootstrap、检验或样本。

## 5. 保留的非核心问题与操作限制

1. **精确错误码断言尚有1项失败。** 安全拒绝已发生，但接口测试并非全绿。后续若维护测试合同，应另开明确范围的变更，不能改写本次原日志。
2. **已提交transfer的discard行为。** 已保存审查指出：`discard_transfer`可移除按transfer-ID定位的spool，并错误返回`seal_remains_unconsumed`标志。它不是本次固定提交/恢复流程的一步；当前运行合同为保留已提交spool，提交后不调用discard。本问题只登记，不打开新的核心修复轮次，也不宣称已修复。
3. **平台和来源边界。** 不能从文件导入、Host SQLite读回或哈希一致性推出商业Agent内部来源完整；不能将存档重放当作新商业模型运行。
4. **来源代码许可。** 现有项目开源许可与上游WorkBuddy网关许可的未确认范围见工作目录`evidence/reuse_and_adapter_audit.md`。本次不捆绑不明许可的外部执行器，不把内部复用授权变成整仓MIT声明。

## 6. 最终结果与停止点

**FeatureFrozen：固定核心工程门槛PASS，本轮按冻结范围停止。**

- 旧C复现1次，处置为复用现成成熟核；0核心补丁/修复轮次。
- 只完成1次固定强基线campaign：24故障行、180正常性能行；B/C各8/8和正常60/60。
- 独立verify PASS，136个receiver/policy库只读核验；没有通过重跑被测场景生成校验结果。
- 存档输出文件适配两个方向通过；新增商业模型调用0，历史768/720评价未重跑。
- 接口/适配器预检查仍是13/14，1个精确错误码断言失败；提交后discard限制与未知长尾原因继续登记。本结论不是“所有测试全通过”，不撤销这些缺项。

可用范围为单机可信Host、显式导出文件、已登记依赖、最新权限/版本的首次持久接收及绑定元数据恢复。它不保证商业Agent隐藏记忆、事后明文收回、跨机器原子事务或任意生产环境时延。B/C相等是公平且允许的结果，本轮不为制造算法优势延长开发、追加故障或调整门槛。

## 7. 已实际读取的证据与版本

- [冻结范围](gateway_v1_scope_lock.json)：事先冻结的8场景、方法、预算、门槛。
- [执行台账](gateway_v1_execution_ledger.json)：旧C复现、核心修复、平台重放、接口/适配器测试记录。
- [旧C故障处置](gateway_v1_C_fault_audit.md)：旧故障机制、成熟核处置和非核心问题。
- [完成回执](gateway_v1_results/campaign_completion.json)：`status=completed`、代码哈希保持不变、24/180行和新模型调用0。
- [独立校验](gateway_v1_results/independent_verification_summary.json)：标准库只读核对、136库、0数据库写入/重执行及PASS。
- [实测汇总](gateway_v1_results/summary.json)、[逐场景结果](gateway_v1_results/regression_outcomes.csv)：固定安全结果、正常提交、耗时、SQL和文件大小。
- [真实接口日志](gateway_v1_results/interface_adapter_tests.txt)：13通过＋1旧精确错误码assert失败。

上述结果的本地原始位置为`D:/agent安全论文/agent-memory-gateway-v1-work/runs/fixed_v1/`及`analysis/fixed_v1/`；公共文档副本统一放在`docs/gateway_v1_results/`。报告读取的是已经停止写入的本次最终结果，不改变这些结果或冻结脚本。

本地原始completion SHA256：`2d2e52a401cbdda441e76155ecfc89402b672a67cde6292efd90f50f0fd0b228`；verify SHA256：`8a5c40cf5c02e5af96b80d413eb0057cf362eecc4155d8a274024d2b6304d6f0`。本轮报告编写仅修改本文件；没有执行测试、模型或新的验收campaign。

公共目录保存独立校验摘要和完整本地校验文件的哈希，不包含完整商业模型交互档案；原始CPU数据库及worker证据在本地保留，可通过冻结runner重新生成。旧D/E与修复后网关复用同一成熟内核，本轮不把重复包装计作三个独立算法。
