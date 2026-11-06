# 第一阶段：相关工作核验矩阵

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


核验日期：2026-11-05（Asia/Shanghai）。状态：完成本轮有界近邻检索；不是系统综述或全球穷尽检索。使用 nature-academic-search 的多源搜索流程；未挂载该技能所列 academic-search MCP，采用原始论文网页、作者主页 PDF、会议/出版社官方资源核验。未调用付费检索或模型服务。

## 核验范围和证据分级

本轮检查已有本地文献笔记，再直接重开相关原始论文，定位方法、假设和限制。“本轮定位”列说明取得文本的位置；标为目录、摘要或概览的部分未完成整章精读。全文可访问不等于全文每页精读、作者实现复现或结论独立复算。没有把搜索摘要、第三方 AI 摘要或未检索到某工作当作创新证明。论文版本固定为链接的 v1；没有为所有预印本核验最终刊载状态。

已有用户 PDF 的提取文本位于 `[WORKSPACE]/.tmp/assumption_local_lit/`，沿用原件 SHA 标识，不重复下载或改动原件。两份记忆综述副本不计作独立论文。`3510416.pdf` 是 transcert 证书差分测试论文，不能误写成 Agent 记忆论文。

## 直接近邻

| ID、原始来源与状态 | 本轮定位 | 已覆盖的机制 | 对本项目的约束/可迁移点 |
|---|---|---|---|
| L01 Zhao等，2026，[MemoRepair: Barrier-First Cascade Repair in Agentic Memory](https://arxiv.org/html/2605.07242v1)，预印本 | §2.1–2.4、§3.4、§5 | 影响依赖闭包、先撤下后修复、合法前驱闭包的发布选择，单次最小割；缺边退化实验 | 依赖传播、选择性重建、最小割不能声称首次。安全条件是完整影响来源；作者已披露缺边风险。我们要比较完整合法原文重读，并核算实际总成本。 |
| L02 Chu，2026，[When Evidence Changes](https://arxiv.org/html/2610.03902v1)，预印本 | §2–4、§6.2、附录A/B | 修复/重建/缓存与来源过滤重读；全生命周期计费；逐文档版本和提交读集验证 | 极近的研究与评价基线。附录A的H2明确无关写入不阻断提交，H1相关更新阻断。将全局epoch改为读集验证只是机制移植；本文自己也不把提交门控当新算法。 |
| L03 Sangaraju、Vissa，2026，[Lineage-Aware Memory Governance](https://arxiv.org/html/2610.07258v1)，作者录用稿，关联DOI [10.1109/ACCESS.2026.3730363](https://doi.org/10.1109/ACCESS.2026.3730363) | 摘要、§V、VI-B及方法目录 | 以参与派生的列集授权缓存值；定义冲突检测；完整血缘条件与缺失退化 | 用户已有复现可复用。不能只增加“来源权限交集”称创新；T4/T6明确不覆盖未声明来源的推断及跨次聚合推断。期刊最终版未在本轮另行复核。 |
| L04 Liu，2026，[Audience-Bound Persistent Memory](https://arxiv.org/html/2609.36373v1)，预印本 | §3.2–3.5、附录E.1/E.2 | 按受众拆分或取交集、未知来源隔离、当前状态/授权检查、物理尝试封存与生命周期授权 | 按权限分组、来源不完整则拒绝、封存尝试和重试不能单独算新贡献。其保证有完整中介与来源捕获可信条件；换两个客户端不是新安全问题。 |
| L05 Shen、Toyoda、Leung，2026，[Revoked but Still Authoritative](https://arxiv.org/html/2609.08258v1)，预印本 | 摘要/引言、§3/5与附录C目录 | 测量软撤销记录仍被检索并影响行动，读取时撤销/冲突过滤；含后续多Agent传播场景 | “撤销标签不等于强制执行”已有直接实证。本文的失效事实与本项目“事实仍真但对B转交许可撤回”要分别定义。作者代码链接见正文，不在本轮声称复现。 |
| L06 Li等，2026，[MemTX](https://arxiv.org/html/2607.23929v1)，预印本 | §2、§3.1、协议概览及实验目录 | 证据/权限/来源/有效性状态、事务暂存与验证提交、不可逆动作门控、类型化级联修复 | 事务性记忆、动作前核验、性质测试均已有直接近邻。其论文报告不是我们的测试结果；只复用状态机框架不构成算法首创。 |
| L07 [PCM: A Proof-Carrying Message Protocol for Verifiable Multi-Agent Communication](https://arxiv.org/html/2610.39109v1)，2026预印本 | 方法目录、§12结果/限制、附录C | 可信执行记录/签名与三值裁决、防重放；实测仍接受10条陈旧证据；附录C提出签名head与连续后续记录避免省略 | 回执/证明携带和“真实证据不等于当前有效”已有方案。附录C是提出的后续设计，不能说已实现。其四类工具声明不是派生记忆完整历史因果；扩展来源/权限语义仍需证明额外价值。 |
| L08 Wang，2026，[Proof-Carrying Agent Actions](https://arxiv.org/html/2606.04104v1)，预印本 | §4.3、§6.3–6.4、§7–8.5 | 异构运行时覆盖分级、可携带动作证书、预算约束选择性审查、回执完整度 | “观察到哪里就保证到哪里”、证据缺口与选择性审查本身已有论述。论文的架构目标与实现/验证程度需分开，不能据其宽泛目标断言所有窄算法均解决。 |
| L09 Lin、Zeighami、Parameswaran，2026，[BLIP: Bolt-on, Verifiable Provenance for LLM-Powered Data Processing](https://arxiv.org/html/2608.25210v1)，PVLDB19(11):2992–3005，[DOI](https://doi.org/10.14778/3836663.3836668) | §2.1、策略概览与方法目录 | 寻找可重现同一答案的小输入子集，多种策略与自适应选择，支持多个最小来源 | 可作为授权来源重新生成/验证的参考；“子集能重现答案”不等于“历史生成没有读过受限源”。不得用BLIP结果为旧污染产物追认迁出权限。 |
| L10 Oracle，[Agent Memory SDK 26.8 Security Considerations](https://docs.oracle.com/en/database/oracle/agent-memory/26.8/guide/security.html)，官方产品文档，非论文 | persistence/data minimization、retrieval scope | 明确单消息删除不删除所有派生产物；背景工作等待并非跨实例全局屏障 | 说明实际系统存在粒度/并发边界，给场景设计线索；不是本机漏洞验证，更不能外推WorkBuddy/Harness也有同样缺陷。 |
| L11 Chen、Wang、Brinton，2026，[PlanFence / Fresh Memory, Stale Plans](https://arxiv.org/html/2609.03340v1)，预印本 | §2、§3.1–3.3、§4/5目录及摘要 | 应用代码声明相关键、追溯精确父版本、只查这些键的当前所有者版本；缺证阻断或一次重规划 | 直接覆盖“相关范围＋父版本＋外部动作前验证”。§5.4明确比较同样安全的全键批验证。不能以全局epoch弱基线衬托重命名后的方案。 |
| L12 Rezazadeh等，2025，[Collaborative Memory](https://arxiv.org/html/2505.18279v1)，预印本版本，未核最终录用 | 摘要、§1、§3.1及方法目录 | 动态用户-Agent-资源访问图、来源标记的私有/共享片段与读写策略 | 原始问题已有直接先例，不能把“多用户动态权限记忆共享”作为独占的新问题。 |

## 传统机制及用户已有文献

| ID、来源 | 本轮核验位置 | 适用映射及防止重复的要点 |
|---|---|---|
| T01 Sabelfeld、Myers，2003，Language-Based Information-Flow Security，[DOI](https://doi.org/10.1109/JSAC.2002.806121) | 用户PDF提取p1，PDF页1–6 | 区分存取许可与端到端信息流、隐式/时序等渠道。精确字符串无命中不能充当非干扰证明；这不是新近才发现的假设问题。 |
| T02 Xu、Stoller，2015，Mining Attribute-Based Access Control Policies，[DOI](https://doi.org/10.1109/TDSC.2014.2369048) | 用户PDF提取p0，PDF页1–2 | 从已有关系挖掘政策，目标是单个当前低层政策，不解决本项目首次交付前时序撤回；适合政策构造参照而非主修复算法。 |
| T03 Margheri等，A Rigorous Framework for Specification, Analysis and Enforcement of Access Control Policies，[DOI](https://doi.org/10.1109/TSE.2017.2765640) | 用户PDF提取p2，PDF页1–6 | FACPL已定义permit/deny/not-app/indet和形式化策略分析。来源unknown单独建状态是合理移植，不是三值/四值逻辑创新。 |
| T04 Nie等，2023，Coverage-directed Differential Testing of X.509 Certificate Validation in SSL/TLS Implementations，[DOI](https://doi.org/10.1145/3510416) | 用户PDF提取p3，首页 | 可迁移覆盖引导变异与独立实现差分测试到记忆交付证据。必须有独立规范裁决；实现分歧不自动等于漏洞。不是把证书验证器直接当记忆权限算法。 |
| T05 Green、Karvounarakis、Tannen，2007，[Provenance Semirings](https://www.cs.ucdavis.edu/~green/papers/pods07.pdf)，PODS，DOI10.1145/1265530.1265535 | 首页贡献定义、§2开头（未逐页精读全部推导） | 正关系代数中的组合依赖/替代支持与不完整数据库已有形式框架。AND/OR来源图不能单独算新算法；不能把关系查询语义自动推广为LLM真实因果。 |
| T06 Budiu等，2023，[DBSP](https://www.vldb.org/pvldb/vol16/p1601-budiu.pdf)，PVLDB16(7):1601–1614，DOI10.14778/3587136.3587137 | §1、§4/8目录及算法说明 | 授权表、依赖表的增量视图维护是成熟迁移方向。只在相关变更规模小于全量且维护收益超过索引成本时有工程价值；不创造语义修复正确性。2025扩展版[期刊页](https://doi.org/10.1007/s00778-025-00922-y)另有不同作者表，不能混合引用。 |
| T07 Bates、Butler、Moyer，2015，[Take Only What You Need](https://www.usenix.org/system/files/conference/tapp15/tapp15-bates.pdf)，TaPP | §3.1–3.2，PDF页2–3 | 用MAC允许流图约束选择性来源捕获并论述selective completeness。已覆盖可信上界下只记录相关子域的概念。文中是设计提案，不应称成熟部署或完整实测算法。 |
| T08 Chan、Gehani、Irshad、Cheney，2020，[Integrity checking and abnormality detection of provenance records](https://www.usenix.org/system/files/tapp2020-paper-chan.pdf)，TaPP | §2–4，PDF页1–4 | 用ProvMark控制图/比较识别缺失与异常；依赖专家认可的完整参照图。本文为手工案例与自动化扩展建议；证明缺证定位不是全新问题，不等于任何新定位算法均被覆盖。 |
| T09 Kung、Robinson，1981，[On Optimistic Methods for Concurrency Control](https://www.eecs.harvard.edu/~htk/publication/1981-tods-kung-robinson.pdf)，TODS6(2):213–226，DOI10.1145/319566.319567 | §2–5 | 读/验证/写阶段与冲突相关的读写集是经典OCC。可解决全局版本造成的无关冲突，需原子最终验证、单调事件版本与正确冲突集合；不能宣称为新事务算法。 |

## 本轮直接否定的宽泛创新表述

- “第一次在Agent记忆中加入来源追踪、权限交集、撤销闭包、选择性修复”：L01/L03/L04/L06直接重叠。
- “第一次提出证据回执、新鲜度或在部分可观察环境下分级控制”：L07/L08直接重叠。
- “首次按需求只核查有关来源”：T07已有概念；具体算法仍要与普通可达性和缓存比较。
- “用SMT、哈希或签名即可证明隐藏来源不存在”：没有这样的推论；工具只能验证给定编码/被承诺内容。
- “全局epoch替换为读集即是论文创新”：T09及L02附录A的H1/H2/H6直接重叠。

上述是本轮近邻对具体主张的否证，不是证明本项目不可能发表。可以贡献新的问题刻画、可复用模块适配或严谨实证，但必须有相对于这些直接近邻的可区分证据。研究问题卡和通过条件见 [research_gap_analysis.md](research_gap_analysis.md)。

## 检索边界

新增有界检索集中于agent memory/revocation/provenance/partial evidence/verification/optimistic commit与选择性完整性。检索词、原始URL、局部PDF来源和未完成项登记于 [evidence/literature_search.json](evidence/literature_search.json)。未查询付费WoS/Scopus，未审核所有文献最终刊载或引用数；GitHub源码许可证/运行适配由独立工程候选审计负责。下一轮只围绕试跑暴露的具体差异补检索，不按数量无限扩库。

