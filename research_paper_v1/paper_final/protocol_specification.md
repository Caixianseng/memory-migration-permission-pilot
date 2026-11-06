# 首次持久交付协议与实现对应（v1）

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


冻结日期2026-11-06。该规范描述本项目已有Store和隔离的metadata恢复扩展，不命名新的密码或事务算法。

## 1. 数据与身份

来源引用`(source_id,version,sha256,owner_id)`；记忆含正文hash、origin/memory/version身份、直接来源、父记忆和传递依赖；包含schema、import_id、nonce、batch_id、sender_id、recipient_id、epoch、memories、lineage、sources、content_sha256。权威seal在策略库独立保存相同身份和包摘要。

同一memory_key绑定不可变版本；同一batch不能接纳不同import。nonce是一次seal消费索引，随机nonce本身不提供真实性。真实性来自受信authority的登记匹配，不能把本协议称公钥认证或签名协议。

## 2. 原始执行步骤

1. 适配器固定业务输入及源尝试，模型输出后将Host记录的输入来源传给`add_memory`。拒绝模型自报来源代替可信登记。
2. Host检查候选来源/协议状态。不可归属产物关闭并记账，不悄悄重跑替换。
3. `export_package`读出候选、递归登记父依赖并校验闭包。策略事务中核当前权限/版本，生成并保存seal。
4. 接收者检查完整schema、接收者身份、正文与lineagehash。包内hash被重算仍须与authority seal相同。
5. ATTACH authority；BEGIN IMMEDIATE；重读当前epoch、未消费seal、全部来源版本/owner/hash和分享grant。失败回滚。
6. 插入lineage、记忆、import事件、batch与顺序；同事务消费seal并COMMIT。至此首次交付完成。
7. 原`import_package`在COMMIT/DETACH后先返回Store receipt；外层`run_study.deliver`随后关闭接收连接、重开只读核内容/身份/event，并写delivery.json。Store返回、控制器核验与源端收到确认是不同层级；模型答题更在其后，是功能评价而非提交定义。

## 3. 已有恢复缺项与新增适配

历史`import_package`安全拒绝重复导入，不保证重复请求返回相同成功结果。ACK丢失或导入后进程崩溃时，外层delivery.json可能尚未写；不能仅凭文件不存在判断未交付。

本轮`durable_delivery.py`（见实验代码）采用已有幂等回执模式：

```text
validate exact packet identity and receiver binding
if trusted committed batch matches the full packet:
    verify persisted import/event/body bindings
    return metadata receipt of that existing commit
try original atomic import
on a duplicate-race rejection:
    re-read and verify the identical committed identity
    return existing metadata receipt only if it matches
otherwise reject or report unresolved
```

伪代码不说明实现已通过；执行证据在[failure_injection_results.md](failure_injection_results.md)。已有提交的确认不产生新正文接纳，也不会向撤权接收者再次返回明文。没有匹配持久提交的请求必须走当前授权检查；不能从缓存ACK猜测成功。

## 4. 安全属性的实现依赖

|属性|必须共同成立的机制|失去机制时的预期|
|---|---|---|
|分享权限保持|可信来源集合＋最终当前授权＋原子提交|预检查到提交间撤权可能被遗漏|
|正文/来源绑定|规范化正文hash＋闭包校验＋authority seal|包内自洽不能防改写/省略|
|至多一次新接纳|receiver唯一batch/import＋seal原子消费|单独nonce字段无阻止并发重复的能力|
|可恢复确认|可信持久提交记录＋完整身份比较＋metadata-only返回|ACK丢失可能导致安全但不可用的重放拒绝|
|审计关联|import event与batch绑定＋attempt账本＋可靠锚|无法将所有执行失败归成可补证缺项|

消融只在新的独立数据库/派生模块副本中运行，不影响历史receiver。对照3具有同样完整的版本、事务与幂等能力；本系统安全相同时如实报告。

## 5. 线性化与拒绝规则

revoke先提交→旧包拒绝；import先提交→交付有效、后撤权不回写历史。ABA重授权不让旧epoch复活。无关更新使全局epoch过期→本实现保守拒绝，可计合法误拒。相同包的已提交确认→恢复metadata；相同batch不同包/收者→拒绝。跨两个方向分别判断，不能把一方向失败称整个双向交换原子回滚。

## 6. 执行环境

同Host磁盘SQLite、DELETE journal、FULL synchronous、foreign_keys开启、busy_timeout 10s。原库`_connect`实际设置上述配置。多文件事务原子性依赖SQLite与文件系统的正常语义；进程终止实验不是断电或磁盘故障测试。锁等待可能导致合法timeout，必须保留，不把所有失败都标攻击拦截。
