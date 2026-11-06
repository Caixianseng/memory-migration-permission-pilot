# 三方向相关工作与机制映射

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


日期：2026-11-05。使用nature-academic-search与academic-research-suite。三个方向独立做初始判断，再检索、最小运行和反方复核。共享旧项目背景可能造成锚定，已披露；不是三个人类盲评。此为有界选题资格检索，不是系统综述或全球新颖性证明。

每方向至少5篇最近邻的逐项元数据、作者、发表状态、DOI、读取范围、代码URL/许可证与访问失败分别存于 [A_literature.json](evidence/A_literature.json)、[B_literature.json](evidence/B_literature.json)、[C_literature.json](evidence/C_literature.json)。同一篇跨方向相关不冒充多篇独立研究；预印本与最终发表同一工作不重复计数。没有使用订阅WoS/Scopus，检索不到实现记为未找到，不推导代码不存在。

## 1. A：证据真实性、完整性与受信中介

| 近邻 | 原始出处/发表与DOI | 对本项目的直接限制 |
|---|---|---|
| Xu等，Data-Provenance Verification For Secure Hosts，2012 | TDSC9(2):173–183，[DOI10.1109/TDSC.2011.50](https://doi.org/10.1109/TDSC.2011.50) | 证据真实性与受信宿主已有研究；来源哈希不说明没有漏采 |
| Pasquier等，Practical Whole-System Provenance Capture（CamFlow），2017 | ACM SoCC，[项目](https://camflow.org/)，DOI10.1145/3127479.3129249；许可核验见A记录 | 完整中介/内核来源采集是强对照，不能只对比模型自报 |
| Securing AI Agents with Information-Flow Control（Fides），2025 | [arXiv2505.23643](https://arxiv.org/abs/2505.23643)，预印本v2，DOI10.48550/arXiv.2505.23643，未核实正式期刊发表 | taint/来源跟踪接入Agent需要明确被中介的通道；跟踪记录不是必要因果解释 |
| Palumbo等，Formal Policy Enforcement for Agentic Systems（FORGE） | [arXiv2602.16708](https://arxiv.org/abs/2602.16708)，2026-10-12 v4；预印本DOI10.48550/arXiv.2602.16708 | Datalog、事件图和运行时行动监控已经直接面向Agent；旧题名PCAS不是新的另一篇 |
| Zheng、Yang，CONTINUITY | [arXiv2609.05269](https://arxiv.org/abs/2609.05269)，2026 v1；DOI页面标pending registration | 来源、身份、任务、策略与最终效应的绑定已有直接近邻；不能重新包装通用证据包 |

A的关键反例是同观测、不同隐藏历史。传统受信attempt输入包络在已中介通道内足够；超出观测边界不能通过更复杂分类器无条件恢复。内核采集、协议审计和商业隐藏上下文的信任范围各不相同。

## 2. B：版本、恢复与最终效应

| 近邻 | 原始出处/发表与DOI | 对本项目的直接限制 |
|---|---|---|
| Zanzibar，2019 | [USENIX ATC](https://www.usenix.org/conference/atc19/presentation/pang)，正式发表，官方书目未列DOI | 授权/内容因果次序与一致性token已有机制 |
| Chubby，2006 | [USENIX OSDI全文](https://www.usenix.org/legacy/event/osdi06/tech/full_papers/burrows/burrows_html/)，正式发表，未确认DOI | 旧worker恢复与sequencer须由最终资源验证，单有锁或token不够 |
| UCONABC，2004 | ACM TISSEC，[DOI10.1145/984334.984339](https://doi.org/10.1145/984334.984339) | 持续授权、属性变化和使用控制不是Agent新增概念 |
| Dean、Hu，2004 | [USENIX Security](https://www.usenix.org/legacy/publications/library/proceedings/sec04/tech/dean.html)，未确认DOI | 先检查再使用的竞态是经典问题，普通事务修复不构成新算法 |
| CONTINUITY，2026 | 同上预印本，代码固定版本与MIT许可见A/B记录 | 最终效应、撤权、nonce、幂等与跨层安全上下文已有直接定义；其provider边界本身也有披露 |

目标期刊补筛见B记录：Crypt-DAC（TDSC，DOI10.1109/TDSC.2019.2908164）、跨方usage-controlled exchange（Computers & Security，DOI10.1016/j.cose.2024.104050）及JISA候选。加密撤权/跨方使用控制的安全目标不能直接套到本机首次导入；未完整核验的记录不算五篇核心近邻。

## 3. C：披露历史与推断控制

| 近邻 | 原始出处/发表与DOI | 对本项目的直接限制 |
|---|---|---|
| Biskup、Bonatti，CQE，2004 | IJIS，[DOI10.1007/s10207-004-0032-1](https://link.springer.com/article/10.1007/s10207-004-0032-1) | 先验知识与既往答案合并已是原问题 |
| Yang等，Shifting inference control to user side，2010 | TDSC7(2):189–202，[机构全文/元数据](https://ink.library.smu.edu.sg/sis_research/4919/)，DOI10.1109/TDSC.2008.70 | 分布式可信接收端的推断控制不是空白 |
| Cuenca Grau等，Datalog/OWL2 CQE，2015 | IJCAI，[作者全文](https://arxiv.org/html/1504.06529v1)，会议DOI未定位 | 视图/censor、逻辑闭包与合法信息保留已有成熟算法 |
| Cima等，Epistemic Policies，2024 | [IJCAI正式页](https://www.ijcai.org/proceedings/2024/366)，DOI10.24963/ijcai.2024/366 | 知识策略与联合属性约束已有明确表达 |
| Bonatti等，Enhancing cooperativity in CQE，2025 | Artificial Intelligence348:104402，DOI10.1016/j.artint.2025.104402，作者出版PDF见C记录 | 动态查询流和协作性/可用性不是仅缺一份history表 |

C另核验Bonatti2022的安全语义批判及ICLR2026 CIMemories。后者真实记忆上下文违规/累计评估与“各次均满足记录分享策略但组合推断受禁事实”并非相同标签，不能借其标题证明本轮新威胁。CIMemories代码为CC BY-NC4.0，不混同MIT，也未执行收费模型评估。

## 4. 代码复用与实际执行分开

本轮实际执行的是自有Store与独立CPU资格Harness、标准库SQLite和逻辑枚举参照，没有执行FORGE、CONTINUITY或CIMemories整套评估。可访问仓库、许可证、论文作者代码、第三方复现必须分别标记。CONTINUITY已核固定commit和MIT；CIMemories核作者库CC BY-NC4.0；CamFlow/FORGE/Fides的详细状态见A，不对未确认许可的代码做复制。

## 5. 比较后的候选处置原则

三条路线分别对应来源可信中介、事务/fencing和CQE。它们能处理集合差职责之外的真实安全问题，但**证明问题真实**与**证明现有成熟方法存在可改善缺口**是两道门槛。只加传统模块可以是工程改进；作为论文融合创新还需相对完整强近邻的新增约束和实证差异。本轮没有把多个已知模块连接起来就自动判定创新。

最终判断须结合 [最小实验](minimal_qualification_experiments.md) 与 [决策](final_research_direction_decision.md)。期刊偏好用于检索路由，没有据历史分区或领域热度给录用概率。
