# 三个方案的最近邻：来源与发表状态

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


核验日2026-11-05。复用前三阶段已读章节，并在本轮重新打开核心arXiv/正式发表页检查标题、作者和状态。下表为有界核验，不等于全球穷尽检索，也不把可访问全文等同全部复现。方案差异在[三个候选](three_candidate_papers.md)逐项说明。

|ID|论文、作者、年份|发表状态与DOI|核验来源与阅读范围|
|---|---|---|---|
|N1|Venkata M. Sangaraju; Sudhir Vissa. Lineage-Aware Memory Governance: A Derivation-Gated Framework for Privacy-Preserving Column-Level Access Control in Enterprise AI Agents. 2026|IEEE Access14:139683–139693，2026-09-03正式发表；10.1109/ACCESS.2026.3730363|[IEEE](https://ieeexplore.ieee.org/abstract/document/11677041)、[作者接受稿](https://arxiv.org/html/2610.07258v1)；本轮方法、六组实验和PoC细节。代码位置/许可未取得，不冒称复现。|
|N2|Sibo Liu. Audience-Bound Persistent Memory: Authorization Across the Memory Lifecycle. 2026|arXiv2609.36373 v1，2026-09-28；10.48550/arXiv.2609.36373，所查页无期刊记录|[arXiv](https://arxiv.org/abs/2609.36373)、[正文](https://arxiv.org/html/2609.36373)；第一阶段§3/附录E，本轮摘要与限制及附件目录。|
|N3|Chris Zheng; Geng Yang. CONTINUITY: Security-Context Contracts for Composable LLM Agent Controls. 2026|arXiv2609.05269 v1；所列10.48550/arXiv.2609.05269仍标pending registration；无期刊记录|[元数据](https://arxiv.org/abs/2609.05269)、[正文](https://arxiv.org/html/2609.05269)；第三阶段及本轮§6.7/7.4/9.6/12，内存finality边界。代码MIT、第三阶段固定commit已核；本轮未运行。|
|N4|Nils Palumbo; Sarthak Choudhary; Jihye Choi; Guy Amir; Prasad Chalasani; Isil Dillig; Somesh Jha. Formal Policy Enforcement for Agentic Systems. 2026|arXiv2602.16708 v4，2026-10-12；10.48550/arXiv.2602.16708；无期刊记录|[arXiv](https://arxiv.org/abs/2602.16708)；第三阶段事件图/完整中介，本轮版本/摘要复核。旧名PCAS不是另一篇。|
|N5|Alireza Rezazadeh; Zichao Li; Ange Lou; Yuying Zhao; Wei Wei; Yujia Bao. Collaborative Memory: Multi-User Memory Sharing in LLM Agents with Dynamic Access Control. 2025|arXiv2505.18279 v1；10.48550/arXiv.2505.18279；所查页无正式刊载|[arXiv](https://arxiv.org/abs/2505.18279)；第一阶段§1/3.1，本轮摘要及元数据。|
|N6|Xiaoyang Li; Yiqi Wang; Haohui Lu; Zhi Chen; Mo Li; Pingan Song; Mingkai Zheng; Taotao Cai. MemTX: Transactional Belief Commit for Stateful Agent Memory. 2026|arXiv2607.23929 v2，2026-07-28；10.48550/arXiv.2607.23929；明确Preprint|[arXiv](https://arxiv.org/abs/2607.23929)；前期协议概览，本轮版本/摘要；作者枚举和基线成绩不是本项目复现。|
|N7|Evan Chen; Shiqiang Wang; Christopher G. Brinton. Fresh Memory, Stale Plans: Derivation Currency for Distributed LLM-Agent Memory. 2026|arXiv2609.03340 v2，2026-09-27；10.48550/arXiv.2609.03340；无期刊记录|[arXiv](https://arxiv.org/abs/2609.03340)、[v2正文](https://arxiv.org/html/2609.03340v2)；第二阶段定向复核与本轮同安全批量参照。PlanFence为其机制名。|
|N8|Ruoming Pang等14人. Zanzibar: Google's Consistent, Global Authorization System. 2019|USENIX ATC2019:33–46；官方BibTeX未列DOI，不编造|[正式会议页](https://www.usenix.org/conference/atc19/presentation/pang)；第三阶段§2.2/2.4，本轮沿用已核原始记录。不列入近三年期刊样例。|
|N9|Jaehong Park; Ravi Sandhu. The UCONABC usage control model. 2004|ACM TISSEC7(1):128–174；10.1145/984334.984339|[DOI](https://doi.org/10.1145/984334.984339)；第三阶段正式元数据及摘要，未取得全文。理论语义比较，不声称运行其代码。|
|N10|Wenhui Chu. When Evidence Changes: Evaluating Memory Repair and Re-reading in Language-Model Agents. 2026|arXiv2610.03902 v1；10.48550/arXiv.2610.03902；所查页无期刊记录|[arXiv](https://arxiv.org/abs/2610.03902)、[正文](https://arxiv.org/html/2610.03902)；前期§2–4/6/附录，本轮§2贡献声明与成本/限制。该文明确不将级联、选择和提交校验作为原创。|
|N11|Yang Zhao; Chengxiao Dai; Mengying Kou; Yue Xiu. MemoRepair: Barrier-First Cascade Repair in Agentic Memory. 2026|arXiv2605.07242 v1；10.48550/arXiv.2605.07242；所查页无期刊记录|[arXiv](https://arxiv.org/abs/2605.07242)、[正文](https://arxiv.org/html/2605.07242)；前期§2/3.4/5，本轮问题、最小割归约与基线概览。|
|N12|Yi Ting Shen; Kentaroh Toyoda; Alex Leung. Revoked but Still Authoritative: An Empirical Study of Revocation Enforcement in Agent-Memory Systems. 2026|arXiv2609.08258 v1；10.48550/arXiv.2609.08258；所查页无期刊记录|[arXiv](https://arxiv.org/abs/2609.08258)；前期§3/5，本轮摘要与正式状态。事实撤销与分享撤权不是同一政策。|
|N13|Niloofar Mireshghallah; Neal Mangaokar; Narine Kokhlikyan; Arman Zharmagambetov; Manzil Zaheer; Saeed Mahloujifar; Kamalika Chaudhuri. CIMemories: A Compositional Benchmark For Contextual Integrity In LLMs. 2026|ICLR2026正式论文；arXiv DOI10.48550/arXiv.2511.14937不称期刊DOI|[正式会议页](https://proceedings.iclr.cc/paper_files/paper/2026/hash/9a2bcfaf383638e166162a25b6dff125-Abstract-Conference.html)；第三阶段与本轮元数据/摘要。代码CC BY-NC4.0已在第三阶段核验，本轮未复制或运行。|

三套候选比较分别使用N1–5并额外纳入N10；N3/6/7/8/9；N10/11/12/13/1。重复论文只算一个来源。

传统算法和许可沿用[第一阶段候选清单](../external_algorithm_inventory.md)及[Stage3近邻表](../stage3_research_pivot/related_work_comparison.md)。合法可用的代码候选与已复现的算法不同：NetworkX已资格运行，SQLite已用于本项目；CONTINUITY等只做来源核验，LAMG代码未取到。不得以有GitHub链接推断许可兼容、实现正确或实验可一键复现。
