# 方向B：动态权限下的交付生命周期一致性

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


日期：2026-11-05。状态：已读取原工程、核验5篇最接近机制论文并执行10项最小资格检查。**B目前适合保留为工程安全底座，不足以批准独立新算法。** 没有新付费模型调用，没有修改原Store、历史数据或GitHub主分支。

## 独立假设与反方判断

在检索近邻和查看测试结果前，方向B独立判断是：Agent生成慢、任务恢复和迟到结果会扩大旧授权继续使用的窗口，但这些现象通常仍是传统stale-worker、重放、TOCTOU与资源端原子提交问题。要证明新贡献，必须有正确事务/版本/fencing基线仍失败的额外约束，不能只击败先检查后裸交付。

本轮未用总分选胜者。工程问题真实、验证容易与论文差异存在是三个不同条件。以下资格结果没有推翻上述反方判断。

## 统一比较表

| 比较项目 | 方向B具体定义与证据 |
|---|---|
| 研究对象 | 已生成并封存的记忆包，从发送端导出到接收端首次持久化导入；包含恢复、重试、并发撤权和重复提交。 |
| 真实问题 | 长任务存在迟到/恢复，历史汇总明确单列迟到事件而未用于选取；原工程显式实现seal、epoch和事务。现有日志没有证明发生过迟到越权提交。 |
| 攻击者能力 | 可延迟/重放旧包、调度两个合法任务竞争；不控制TrustedPolicy数据库、宿主源码或SQLite实现。来源内容/任务元数据不能伪造受信seal。 |
| 安全目标 | 当前合同下仅授权且版本匹配的旧包可首次导入；单use seal不得产生第二次效应；提交前已撤权拒绝。提交先于撤权的合法线性化允许。 |
| 现有方法 | 事务隔离、版本检查、资源端fencing、nonce消费、幂等结果；Zanzibar、Chubby、UCON、CONTINUITY已有直接依据。 |
| 最强基线 | 现有 `persistent_exchange_v1/store.py` 的SQLite ATTACH＋BEGIN IMMEDIATE＋当前epoch/来源/授权核验＋同事务seal消费。不能将“差集批读”当此安全问题的完整基线。 |
| 现有方法缺陷 | Stage2资格读取图样的ACL查询与payload读取分开，可在中间撤权；B10复现这一模式。普通共享事务已使其正确排序。原持久化Store的首次导入强基线在B01—B09未出现失效。跨远程商用provider没有被测，保持未验证。 |
| 创新候选（最多一项） | 接收端最终效应与授权见证绑定的提交门控；当前只是成熟机制适配，CONTINUITY也已描述。不另命名成新算法。 |
| 验证实验 | 10个固定真值手选案例，含实际双线程/独立SQLite连接，比较撤权先赢与导入先赢、并发同seal重放及分离检查/事务图样。 |
| 停止条件 | 成熟强基线覆盖全部现有可观察失败；只发现缺检查或缺事务的实现问题；无法控制/观测最终外部效应；或与CONTINUITY差别仅“持久化SQLite代替内存”。满足时不作为主算法方向扩样。 |

## 原工程核心路径：已经做了什么

所有引用针对未修改的 [store.py](../../experiments/persistent_exchange_v1/store.py)，测试前后哈希记录在 [B_config.json](evidence/B_config.json)、[B_run.json](evidence/B_run.json)。

| 路径 | 文件行与实际行为 | 能证明/不能证明 |
|---|---|---|
| 权限变化 | store.py:403–418，更新grants、递增全局epoch并写事件，在事务内提交 | 原实现全局保守失效；无关对象变化也可能拒旧包，不是每来源细粒度fencing。 |
| 导出封存 | :485–507，生成随机import_id/nonce，将recipient、epoch和包摘要写受信seals | 有实际受信封包绑定；不是Agent自签来源证明。 |
| 交付前/实际导入 | :510–567，ATTACH策略库，BEGIN IMMEDIATE后核epoch、seal、来源当前版本与grants，再导入对象并消费seal | 策略和首次本地接收表在相同受控提交边界；不是两个商业产品之间的分布式原子提交。 |
| 接收端验证 | :528–557，当前权限、版本、来源链与包摘要，consumed_by条件更新 | 同seal重放与并发消费受控；不能证明真实隐藏输入完整。 |
| 缓存/后续读取 | :280–320，fresh readonly连接核本地batch及事件绑定，读取已导入内容；不连接policy当前状态 | 保证导入绑定，未撤回已交付明文。把它改称“撤权后不能再用”的保证会超出原合同。 |
| 可选使用时检查 | :431–433，独立 `check_dependencies`，文档明示不撤回已披露文本 | 调用方是否在商用后续使用前强制调用尚未证明，不能据函数存在宣称全路径中介。 |
| 事件日志 | :80–100，哈希链验证次序和内容 | Trusted Host内一致性检查，不是独立外部日志锚定或全部历史完备性证明。 |

历史公开汇总中，source recovery单列1条迟到continuation、`late_output_used_for_quality_or_selection=false`，7项effective recovery；receiver记录2项provider 500无答案、98次outer attempt、2项controlled new attempt。这些证明异步失败/恢复真实存在；它们没有证明已被旧任务越权导入。全局原日志出处由主控的 `existing_failure_evidence.md` 提供，不能用日志计数推导漏洞率。

## 已执行的10项最小资格

入口 [qualify.py](../../experiments/paper_v1/stage3_research_pivot/direction_b/qualify.py)，原始行 [B_raw.jsonl](evidence/B_raw.jsonl)。每项真值来自写在配置中的事件顺序和独立计数，不由被测方法成功率倒推。新建数据库位于独立临时目录，运行后关闭清理。没有复跑Stage2数据集。

| ID | 固定输入与事件 | 实际观察 | 判断 |
|---|---|---|---|
| B01 | seal后关闭、重开进程连接，授权不变 | 允许，1个batch | 正常恢复可用。 |
| B02 | seal后撤权，随后导入 | stale_policy_epoch拒绝，0batch | 撤权先提交，旧包不能交付。 |
| B03 | 撤权再重授，使用旧seal | stale_policy_epoch拒绝，0batch | 当前布尔权限恢复不复活旧尝试。 |
| B04 | seal后注册来源新版本 | stale_policy_epoch拒绝，0batch | 旧版本封包不直接导入；全局epoch先于细来源检查拒绝。 |
| B05 | 一次成功后重开连接重放同包 | 首次允许，第二次transfer_replay_rejected，仍1batch | 不能把重试拒绝算误拒；合同是单次效应。 |
| B06 | 撤权后迟到产物才入发送库 | export因source_not_currently_authorized_for_recipient拒绝 | 本地生成允许不意味着向B分享允许。 |
| B07 | 导入线程完成预检查后暂停，独立策略连接先撤权提交，再恢复导入 | stale_policy_epoch拒绝，0batch | 真实线程调度，没有仅改初始快照冒充race。 |
| B08 | 两独立连接同时导入同seal，Barrier对齐预检查完成点 | 1成功、1transfer_replay_rejected，只有1batch | 原事务强基线通过并发重放。 |
| B09 | 导入持有跨库事务后，让另一连接发起撤权 | 撤权在导入锁期间未完成；导入成功后撤权提交 | 合法线性化，不能记为“撤权调用已开始所以导入必越权”。 |
| B10 | 同样的两连接：ACL读后先完成撤权，再读payload；与共同读事务比较 | 分离图样在撤权已commit后仍按cached allow读到payload；共同事务把读取排序在撤权commit之前 | Stage2图样存在已知TOCTOU窗口；普通事务足够，不构成新算法需求。 |

B01—B09实际10次导入操作：按原全局epoch/单次交付合同应允许4次、应拒绝6次，均符合；另B06应拒绝导出也符合。B10两个图样分别显示一次陈旧检查读取与一次合法事务序列化。不能将B10算商业系统实际泄漏，或据10项手选例给生产安全率置信区间。

整批实际5.351秒，包括临时数据库准备、同步等待及清理。B09故意等待0.2秒选择时序，所以其耗时不是性能结果。SQLite3.40.1，新模型调用0，来源文件哈希未变。初版测量连接未close导致WinError32清理失败，已留存初版、空raw和修正记录，见 [B_execution_log.md](evidence/B_execution_log.md)。未将测量器问题归因原Store。

## 五篇近邻与发表/代码核验

逐条作者、元数据、查询、失败和代码状态在 [B_literature.json](evidence/B_literature.json)。没有付费数据库查询；近邻选择依据机制相关性，不以期刊名称替代相关性。

| 近邻 | 已核验状态与读取范围 | 对B的约束 |
|---|---|---|
| Zheng、Yang，2026，CONTINUITY | [arXiv v1](https://arxiv.org/abs/2609.05269)，DOI10.48550/arXiv.2609.05269页面标pending，不称正式刊载；读6.7/7.4/9.6。代码[commit](https://github.com/zast-ai/continuity/commit/59cfe60930d247d1890b366ded686c718020a11e)，MIT，由A方向实际核验；B未运行其评估。 | 已有finality时当前授权、撤权、单次nonce及幂等绑定。它明确内存模拟ledger/provider边界，不能将“加持久化或最终检查”单独说成空白。 |
| Pang等，2019，Zanzibar | [USENIX ATC正式论文](https://www.usenix.org/conference/atc19/presentation/pang)，33–46；官方BibTeX未列DOI，未编造。读2.2/2.4；原生产代码本轮未找到。 | ACL变化与内容变化的因果次序、版本token已有直接机制。缓存能否用依赖授权快照，不由缓存存在自动保证。 |
| Burrows，2006，Chubby | [OSDI正式全文](https://www.usenix.org/legacy/event/osdi06/tech/full_papers/burrows/burrows_html/)，335–350；检查元数据未找到DOI，原代码未定位。读2.4。 | 外部资源端应验证generation sequencer；锁持有者失联、恢复后旧消息不是新问题。资源端不校验时，token本身不保护效应。 |
| Park、Sandhu，2004，UCONABC | [ACM TISSEC 7(1):128–174](https://doi.org/10.1145/984334.984339)，DOI已在官方检索记录核验；直接打开403，限摘要/元数据。未找到论文绑定代码。 | 持续授权与属性可变早有形式模型；“生成后再撤权”不足以自动产生新理论贡献。 |
| Dean、Hu，2004，Fixing Races for Fun and Profit: How to use access(2) | [USENIX Security正式页](https://www.usenix.org/legacy/publications/library/proceedings/sec04/tech/dean.html)，195–206；官方页未列DOI。读正文1–2；未核验可复用代码。 | 先检查再使用是经典竞态；该文特定Unix接口结论不能泛化为SQLite事务不可能，B10已用普通事务正确排序。 |

另筛查目标期刊近邻：Qi、Zheng的Crypt-DAC，TDSC18(2):765–779，2021，DOI10.1109/TDSC.2019.2908164，由[作者机构](https://research.polyu.edu.hk/en/publications/crypt-dac-cryptographically-enforced-dynamic-access-control-in-th/)核验；Dixit等的IIoT usage-controlled exchange，Computers & Security146:104050，2024，DOI10.1016/j.cose.2024.104050，由[机构记录](https://openaccess.city.ac.uk/id/eprint/33516/)核验，PDF获取超时。两者分别研究加密撤权和跨方使用控制，不直接证明本地旧任务提交缺口。JISA加密撤权结果也列入结构化筛查，未完整核验作者的记录不计入上述5篇。TIFS未取得足够贴近的核验记录，不声称没有相关工作。

## 资格决定与下一入口

**方向B未通过独立算法开发资格。** 已确认的真实工程约束包括异步恢复、旧包重放、来源版本更新以及检查/使用时间差。简单集合差和批量读取单独不能解决这些问题，但正确事务、受资源端执行的版本/fencing、单次效应记录已经解决本轮受控目标。发现一个分离查询窗口并用普通事务修好，是工程价值，不等于新的论文算法。

若后续确实观察到不能进入同一受控事务的远程接收端，应先测该provider是否支持事务、条件写入、幂等键与最终授权验证；缺少接口时可能只能提供受限保证。CONTINUITY已经指出这一边界，不能只因它没部署商业平台就宣布独立研究空白。本轮没有观测商用Agent内部全部读写、双向远程原子交换或网络断连后effect状态，因此不据这些未知范围启动新机制。

若需要保留B作为最小工程验收，其范围应是“受信Host首次导入的线性化授权与一次性效应一致性”，用B01—B10等有界对照作为回归。论文主线还需能击败正确强基线的额外实质性问题；目前没有该证据。
