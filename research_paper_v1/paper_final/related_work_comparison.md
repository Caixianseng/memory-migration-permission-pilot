# 冻结主线的近邻比较与主张边界

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


核验日：2026-11-06（Asia/Shanghai）。本轮沿用11月5日已核材料，再打开下列原始论文的当前元数据和相关章节。范围是首次持久导入，不转向新课题。没有运行文献算法、模型、商业客户端或远程写入。专用academic-search MCP未挂载，使用nature-academic-search的引文核验流程及原始出版社/作者全文；不是系统综述。

## 1. 比较合同

本项目记忆存储由Trusted Host拥有，客户端分别调用WorkBuddy HY3和DeepSeek Harness Flash。已有 `store.py` 在接收库与策略库的同一SQLite附加数据库事务中核验版本/许可/可信seal，写入正文和批次并消费nonce；成功提交是本地首次持久导入边界。原入口对同包重试返回replay拒绝，具有至多一次效果，**不能仅据此称ACK丢失后的结果回放已经实现**。新增恢复适配与其运行状态以[故障报告](failure_injection_results.md)为准。

比较项中的“已描述”表示原文明确提供设计或实验，不等于其全部实现经本项目复现；“不同对象”表示保护目标/执行边界不同；“未报告”只限已读文本，不能推断作者系统完全没有该能力。

## 2. 八维能力比较

|工作|来源追踪|敏感依赖|动态许可/状态|跨Agent交付|接收端持久验证|重试/恢复|双向异构执行|真实模型实验|
|---|---|---|---|---|---|---|---|---|
|LAMG|SQL血缘已描述|门控全部**已登记敏感依赖列**|按部门权限查询；我们的提交前撤权序列未报告|跨部门共享缓存复用；不同于导入协议|共享AMU检索；接收库导入提交未报告|本稿ACK/崩溃合同未报告|9个跨部门round-trips；非本稿双适配器合同|真实与demo-mode canned SQL混合PoC，不能计为9次全部真实LLM|
|When Evidence Changes (WEC)|父版本/来源引用已描述|任务allowed-source与事实合规分别计分|文档撤销/替换及读集校验已描述|生成—使用管线；不同于两个客户端接收库首次交付|Appendix A有立即事务的动作记录提交；未把它称无事务|失败保留、重读及恢复有报告；本稿ACK语义未报告|两7B模型不等于双向客户端迁移|公开ICU记录上的模型试验|
|Audience-Bound Persistent Memory (ABM)|来源、派生、受众闭规则|按完整来源的受众交集/分区|授权快照与grant变更，sealed attempt后变化管后续attempt|多方/多会话context准入；不同于首次导入endpoint|**两套独立SQLite架构**，另有native持久实现|native描述重启/并发；保留physical attempts与恢复账本|native及多种架构，不等于本稿两品牌方向|有大规模记录的模型回答；不能声称此前无真实验证|
|MemoRepair|influence/semantic两类边|完整influence下的撤回闭包|删除/更正/接口迁移，不等同受众分享撤权|可作用于持久产物；本稿导入协议未报告|发布validated successor；不同于接收库授权提交|重建失败保持withdrawn；ACK恢复未报告|不是本稿互通合同|ToolBench/MemoryArena等；数值与实际生成层级须按文中定义|
|CONTINUITY|字段来源和上下文承诺|typed release/taint及transform关系|finality时当前policy/revocation校验|显式memory–gateway–adapter组合边界|有独立sink验证；**原型ledger/effects是内存模拟**|nonce与幂等结果回执已描述；不能称其没有幂等|4应用域，非商业双向产品实测|§12明确conformance suite未调用LLM|
|MemTX|记录证据/权限/来源|派生权限与级联撤回|暂存—验证—提交及retraction|共享持久记忆驱动多Agent行动|有transactional commit；对象为belief/action safety|并发、abort/cascade及性质测试；ACK故障持久恢复未报告|五backbones/三families不等于本稿双向客户端导入|有真实模型比较，domain tools为确定性mock|
|PlanFence|精确派生父版本|scope是应用声明的依赖，不是一般语义因果发现|当前owner head与派生版本对照|明确测量inherited-plan handoff|在protected action前验证；非接收库首次写入|允许一次replan、保留启动timeout；本稿ACK结果恢复未报告|live五Agent工作流，不能说以前没有跨Agent|有30个live五Agent工作流及匹配replay|
|本项目已有Host|可信调用者登记＋已知父闭包|全部登记来源的当前接收者许可|源版本、global epoch、导出及导入时重查|同Host拥有的独立发送/接收库|正文、lineage、batch、seal消费共同提交|原入口至多一次；原生attempt恢复另有登记；ACK适配另列|历史两个方向各48条件，共12合成项目|源/接收真实客户端；所有内部上下文不可见|

## 3. 精读定位、发表状态和不能继承的保证

|BibTeX key|原始来源、状态|本轮核验定位与结论|
|---|---|---|
|Sangaraju2026LAMG|[IEEE正式文章](https://ieeexplore.ieee.org/abstract/document/11677041)，IEEE Access14:139683–139693，2026-09-03，DOI10.1109/ACCESS.2026.3730363；[作者接受稿](https://arxiv.org/html/2610.07258v1)|III–VII，Table V和VI-E：门控敏感注册集内的列；SQLGlot实际查询解析是已有可信采集设计；完整血缘是假设。不能靠漏登记来源把LAMG做弱对照。代码仓库先前返回404，许可未取得，不称已复现。|
|Chu2026Evidence|[arXiv2610.03902v1](https://arxiv.org/abs/2610.03902)，无期刊记录；当前页所列DOI10.48550/arXiv.2610.03902标pending registration|§2、§3–6、Appendix A：明确不把cascade、选择器或commit验证称原创；完整费用和强source-filtered re-reading已经覆盖。A的事务门仅核读集版本，不检查一般来源许可或事实支撑。|
|Liu2026Audience|[arXiv2609.36373v1](https://arxiv.org/abs/2609.36373)，DOI10.48550/arXiv.2609.36373，无期刊记录|§3.4–4.2、6及附录E：snapshot/sealed attempt与next-attempt撤销语义，持久架构、native重启并发和执行分母已有直接证据。不能以“SQLite持久化/恢复/真实模型”单项作首创。|
|Zhao2026MemoRepair|[arXiv2605.07242v1](https://arxiv.org/abs/2605.07242)，DOI10.48550/arXiv.2605.07242，无期刊记录|§2–3/5：先撤回、再构建和验证、按predecessor closure发布。max-weight closure到min-cut为既有算法上的明确归约。我们固定两块不代表它或所有选择性算法。|
|Zheng2026Continuity|[arXiv2609.05269v1](https://arxiv.org/abs/2609.05269)，所列DOI10.48550/arXiv.2609.05269标pending registration，无期刊记录|§6.7/7.4/9.6/12：finality独立核验、原子nonce/幂等效果已有明确方案；原型内存态不等于理论忽略持久性。MIT代码前期核commit59cfe60930d247d1890b366ded686c718020a11e，本轮未执行。|
|Li2026MemTX|[arXiv2607.23929v2](https://arxiv.org/abs/2607.23929)，DOI10.48550/arXiv.2607.23929，明确preprint|§3.5/3.6/4：可执行manager与独立重算的oracle，真实模型和mock工具分开。bounded invariants不是全局unbounded证明；action-safe某些保证是存在性，不保证任意动作自身输入正确。|
|Chen2026PlanFence|[arXiv2609.03340v2](https://arxiv.org/abs/2609.03340)，DOI10.48550/arXiv.2609.03340，无期刊记录|§6.2等：强中央lineage与PlanFence同样安全，差异在跨handoff传输什么、在哪里核验；正是“不必让所有强基线失效”的近邻。scope等于全量时成本可相同，不能把读集优化单列首创。|

另补一项直接期刊上下文：[Anbiaee等，Security threat modeling for emerging AI-agent protocols](https://www.sciencedirect.com/science/article/pii/S2214212626002759)，JISA103,104645，DOI10.1016/j.jisa.2026.104645。作者[arXiv2602.11327v2](https://arxiv.org/abs/2602.11327)和出版社条目均有期刊关联。出版社卷期标December2026，精确首次online日期本轮未核实，不称12月卷期已经过去。其贡献为协议生命周期威胁评估和MCP provider绑定测量，非记忆导入原子协议；不能把“协议完整生命周期第一次有人研究”作为本稿主张。

## 4. 本稿贡献应该怎样收缩

### 直接继承的机制

来源闭包、敏感依赖门控、权限交集、对象/策略版本、读集核验、nonce、事务、持久回执、fail-closed、幂等和审计均有成熟来源或直接近邻。不能写为各自的新算法，也不能靠多装组件计贡献。

### 可以作为本稿的具体系统适配

将客户端**物理尝试的可归属输出**、登记的来源/正文版本、接收者、sealed package和本地持久导入效应绑定；把最终授权与接收库接纳放在同一可测试提交点。对未产生合格artifact、迟到continuation、已提交但确认未知等状态使用明确恢复规则。以上属于范围限定的系统适配，不宣称通用互操作标准或新事务理论。

### 需要由本项目实验承担的新增实证

以共同ground truth比较文件交接、基础门控、完整成熟事务参考和Host；对ACK/进程终止/并发/迟到等状态联合核对**授权、一次效应和可确认性**。将Host机制结论与两个真实客户端的质量/失败账本分开，再按固定ID关联。旧12项目的重建效用负结果支持设计选择，不作为唯一新发现；相关新结果必须来自本轮原始输出，不据这份文献表预先成立。

## 5. 主张验收

目前没有单篇已读近邻被确认覆盖“本稿这一具体接收库导入边界＋本项目实际双客户端失败链测量”的全部材料。但这是**有界阅读下的比较结论，不是不存在先例或新颖性证书**。泛称“端到端安全控制链”“首次持久记忆授权”“首次幂等恢复”已被近邻覆盖，应删除。

因此本轮不改变冻结主题；论文重点是可检验的单Host交付合同和独立实证。安全结果即使与完整成熟事务参考相同也照实报告；消融用于验证机制作用，不单独证明论文新颖性。若最终只剩品牌不同、SQLite落盘和相同机制重演，而没有可复核测量/适配发现，应暂停贡献定稿并向作者报告，不能以文字包装补足。

## 6. 引用/材料纪律

主源、版本、DOI状态和查询失败见[evidence/literature/source_checks.json](evidence/literature/source_checks.json)。正式文献引用LAMG的IEEE版本；其他arXiv工作保持preprint状态；pending DOI不在BibTeX作为已注册DOI输出。题目相同的接受稿/期刊稿计同一工作。未定位或许可未知的代码不声称已复制、运行或复现。

本稿传统机制背景可引用Kung–Robinson的OCC、Green等的provenance semirings、Zanzibar和UCONABC；这些并不提供LLM真实因果来源完整证明。SQLite多文件原子性条件以[官方ATTACH说明](https://www.sqlite.org/lang_attach.html)和[atomic commit](https://www.sqlite.org/atomiccommit.html)为准，仅单Host、符合journal与磁盘/VFS前提，不延伸为跨商业平台原子性。
