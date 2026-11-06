# 新执行的A—E协议对照

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


日期2026-11-06。本轮在新隔离目录实际执行24个控制场景×11配置=264条协议记录。22个场景定义继承已冻结的CPU夹具，另加真实check/use撤权窗口F22及接收效果与seal消费之间的崩溃F23；不是将旧结果复制到新目录，亦不把24轨迹当独立真实业务项目。

## 五个主要配置

|组|具体实现|保留的强控制|
|---|---|---|
|A 普通文件|追加相同交付包，flush＋fsync|不宣称执行ACL、来源或去重|
|B 静态ACL＋hash|初始准备时保存ACL快照；核收者和包自哈希后写入|已登记主体的ACL不随撤权刷新；这与paper_final的动态basic不是同一配置|
|C 来源＋动态权限＋版本，无联合事务|核血缘、正文、来源版本、当前grant、epoch、可信seal；receiver单次autocommit后另外消费seal|保留operation/batch唯一键，**不删除去重制造稻草人**；检查和写入仍存在窗口|
|D 版本事务＋幂等＋接收验证|完整冻结Store核心＋身份/摘要绑定的metadata确认|当前权限/版本、seal、一次效果和接收事件同事务|
|E 完整Host交付核心|与D相同成熟核心和同样确认适配|CPU层不额外独享信息、cache或权限；原生Agent执行层由另一批真实运行评价|

双向场景新引入的接收主体会初始化自己的静态策略；已存在B的初始策略不会在撤权后偷偷刷新。D/E共用已核实现，所以等价是预期控制，不冒称两个独立实现或新算法胜出。

## 实际结果

|组|预期持久效果数匹配/24|联合不合规首次接纳|撤权来源接纳/5|额外重复效果|已有提交metadata确认/6|安全恢复/7|保守拒绝|状态不一致|
|---|---:|---:|---:|---:|---:|---:|---:|---:|
|A|5|8|5|9|0|1|0|未承诺seal原子性|
|B|6|7|5|9|0|1|0|未承诺seal原子性|
|C|23|1|1|0|0|1|2|1|
|D|24|0|0|0|6|7|2|0|
|E|24|0|0|0|6|7|2|0|

联合不合规包括撤权、旧来源版本、错收者和伪造正文，不全等于敏感值泄漏。A为5撤权＋1旧来源＋1错收者＋1伪造；B为5撤权＋1旧来源＋1伪造；C仅F22撤权窗口。D/E仍有F13撤销又重授权、F18无关策略更新造成的2项全局epoch保守拒绝，不能写零误拒。

七个安全恢复场景中，六个已经产生持久效果（F05/06/07/08/17/23），另F19在提交前退出后fresh重试。D/E的6/6 metadata确认及1/1 fresh恢复合计7/7；C/去恢复配置没有已有提交确认能力，只有F19 fresh重试成功。`safe_recovery`与`existing_commit_confirmation`字段明确区分。

继承字段`strict_oracle_matches`实际只比较磁盘效果数，不能称完整协议通过率：例如C在F23的效果数1符合，但nonce未消费且恢复失败。这些状态/恢复属性在后续列分别判定，不用一个数字掩盖。

额外重复效果采用[编码勘误](raw_experiment_data/protocol/protocol_run_20261106_v1/metric_coding_erratum.json)后的派生口径。原始F22 helper把零预期时的违规首效果也记为`duplicate_effects=1`，它不是重复；raw与真实效果保留，分析只在预期已有合法效果时累计重复。没有改gold或重跑协议。

## 证据

代码：`experiments/paper_live_v2/protocol_experiment.py`。冻结代码/配置：[config](raw_experiment_data/protocol/protocol_run_20261106_v1/config.json)、[代码](raw_experiment_data/protocol/protocol_run_20261106_v1/code/protocol_experiment.py)。[264行raw](raw_experiment_data/protocol/protocol_run_20261106_v1/raw.jsonl.gz)、[属性分析](raw_experiment_data/protocol/protocol_run_20261106_v1/analysis.json)。这些是纯CPU真实磁盘操作，不是商业模型的新增回答。
