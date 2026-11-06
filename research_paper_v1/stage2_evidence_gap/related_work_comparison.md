# 第二阶段相关工作与可复用算法资格审查

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


核验日期：2026-11-05。使用 nature-academic-search；先读取第一阶段审计、方向决策和相关工作矩阵，再核验原始论文及软件源码。本报告筛查 12 篇研究论文，补充 1 篇软件出处，深比 5 篇最直接近邻。结构化字段、阅读范围、失败访问与版本固定见 [literature_verification.json](evidence/literature_verification.json)。

**文献侧判断：目前支持缩小问题，尚不支持宣称发现新算法。** 缺项集合差、依赖闭包、按需重验证、共享去重和成本覆盖均有成熟依据。值得资格验证的剩余问题是：合法补证动作确有多种可执行路径时，在同样权限、证据完整度、共享缓存和批处理能力下，简单方法是否仍留下可测量的成本缺口。此判断须与本阶段真实实验合并，不能代替 GO/REDUCE/PIVOT/STOP 的最终数据决策。

## 1. 检索范围与证据等级

检索围绕数据库溯源、缺失记录诊断、增量维护、依赖失效、证据授权、信息流边界、代价规划、选择性重验证和 Agent 交付展开。采用 arXiv 原始版本、作者全文、出版社/学会页面和 GitHub 原始源码；本轮未访问订阅 Web of Science，也没有商业平台内部轨迹。属于定向资格审查，不是系统综述，不声称遍历全球论文。

Missing Data Recovery 中的统计插补不能作为安全来源证据。这里的“补证”必须有可信事件、签名回执、合法来源重读或可复算操作；语言模型生成一条像原始记录的文本不构成补证。信息流安全也不能由“找到一份能复现答案的合法文本”自动推出。

元数据有三类边界：预印本 DOI 不等于同行评审发表；未找到 DOI 标记 unknown；原始页面写明 pending registration 的 DOI 保留该状态。SciPy 最新在线文档已可能超过本机版本，因此实现判断以固定版本源码为准。

## 2. 论文筛查矩阵

完整作者列表在 JSON；下表保留第一作者和直接相关性，避免将“筛查”写成全部精读。

| 编号 | 核验文献与发表状态 | 与本阶段的关系、采用边界 |
|---|---|---|
| P01 | Chen 等，2026，*Fresh Memory, Stale Plans*，arXiv v2（9月27日）；DOI 10.48550/arXiv.2609.03340。[原始页](https://arxiv.org/abs/2609.03340) | 精确继承输入、依赖前沿、按需重验证；不能重新把 read-set 或依赖范围检查命名为新机制。 |
| P02 | Ghosh，2026，*PCM: A Proof-Carrying Message Protocol for Verifiable Multi-Agent Communication*，arXiv v1；DOI 10.48550/arXiv.2610.39109。[原始页](https://arxiv.org/abs/2610.39109) | 可信日志与证据携带消息；完整性、时效、权限仍须分别判断。 |
| P03 | Lin、Zeighami、Parameswaran，2026，*Bolt-on, Verifiable Provenance for LLM-Powered Data Processing*；作者全文标示 PVLDB 19(11):2992–3005，DOI 10.14778/3836663.3836668。[全文](https://arxiv.org/html/2608.25210v2) | 最小可复现支持集合；“能复现”不是历史读取证明或必要因果支撑。 |
| P04 | Chu，2026，*When Evidence Changes: Evaluating Memory Repair and Re-reading in Language-Model Agents*，arXiv v1；DOI 10.48550/arXiv.2610.03902 **pending registration**。[原始页](https://arxiv.org/abs/2610.03902) | 来源过滤重读与全流程成本是必须保留的强基线。 |
| P05 | Chan、Gehani、Irshad、Cheney，2020，*Integrity Checking and Abnormality Detection of Provenance Records*，TaPP，工作进行中；DOI unknown。[学会页](https://www.usenix.org/conference/tapp2020/presentation/chan) | 独立参考图与异常记录定位；不是已经解决开放渠道完整性。 |
| P06 | Zhao 等，2026，*MEMOREPAIR: Barrier-First Cascade Repair in Agentic Memory*，arXiv v1；DOI 10.48550/arXiv.2605.07242。[原始页](https://arxiv.org/abs/2605.07242) | 完整影响依赖下先隔离后修复，以最大权闭包/最小割选后继；不是一般的缺证覆盖问题。 |
| P07 | Wang，2026，*Proof-Carrying Agent Actions: Model-Agnostic Runtime Governance for Heterogeneous Agent Systems*，arXiv v1；DOI 10.48550/arXiv.2606.04104。[原始页](https://arxiv.org/abs/2606.04104) | 异构运行时的行动证书、回执和可执行边界；不能把观察者模式当强制控制。 |
| P08 | Chvatal，1979，*A Greedy Heuristic for the Set-Covering Problem*，MOR 4(3):233–235；DOI 10.1287/moor.4.3.233。[出版社](https://pubsonline.informs.org/doi/abs/10.1287/moor.4.3.233) | 正成本覆盖的经典贪心与近似分析；只能称移植/基线。 |
| P09 | Golovin、Krause，2011，*Adaptive Submodularity: Theory and Applications in Active Learning and Stochastic Optimization*，JAIR 42:427–486；DOI 10.1613/jair.3278。[作者书目](https://www.cs.cmu.edu/~dgolovin/bibtex.htm) | 结果未知时的自适应信息获取。2017年 arXiv v5 修正了一个定理；当前资格实验不具备其概率和结构假设，暂不引入。 |
| P10 | Reiter，1987，*A theory of diagnosis from first principles*，AI 32(1):57–95；DOI 10.1016/0004-3702(87)90062-2。[出版社](https://www.sciencedirect.com/science/article/pii/0004370287900622) | 利用形式系统与矛盾观测做诊断；不能凭一个冲突选择自己喜欢的历史事实。本轮筛查元数据/摘要。 |
| P11 | Budiu、Chajed、McSherry、Ryzhyk、Tannen，2023，*DBSP: Automatic Incremental View Maintenance for Rich Query Languages*，PVLDB 16(7):1601–1614；DOI 10.14778/3587136.3587137。[出版社全文](https://www.vldb.org/pvldb/vol16/p1601-budiu.pdf) | 已知确定性查询和变化流的增量维护；不能自动补齐不可见的生成输入。 |
| P12 | Green、Karvounarakis、Tannen，2007，*Provenance Semirings*，PODS。[作者全文](https://www.cs.ucdavis.edu/~green/papers/pods07.pdf) | 区分并列支持与联合支持。DOI 10.1145/1265530.1265535 沿用首轮书目，本轮解析器不可访问，未宣称重新验证成功。 |

SciPy 出处另记 P13：Virtanen 等，2020，*SciPy 1.0: Fundamental Algorithms for Scientific Computing in Python*，Nature Methods 17:261–272，DOI 10.1038/s41592-019-0686-2。[项目官方引用](https://scipy.org/citing-scipy/)核对了完整作者与卷页，Nature 端点本轮访问失败。软件出处不冒充第 13 篇问题相关论文。

## 3. 五篇近邻正文级对比

这里的“深比”指阅读相关方法、假设与局限章节并映射到实验，不代表复现其全部实验或证明。

### 3.1 PlanFence：最强的范围重验证近邻

正文和附录 E–H 以应用提供的精确输入链接和动作范围为前提，沿依赖前沿查所有者的当前版本；保留继承证据本身可改善既有验证器。v2 还比较批量全键验证及连接复用。因此，把全局检查改成局部检查、把逐请求改成批处理，都不足以构成新贡献。[正文](https://arxiv.org/html/2609.03340v2)

本项目要增加的检验不是再次证明“局部访问更少”，而是可信预期清单存在、某些回执缺失时，定位与修复的额外代价。范围完整性不能由模型声明担保。公平近邻应使用相同缓存、批处理、连接策略和提交检查；只击败全局 epoch 或每条来源独立网络往返不够。

### 3.2 PCM：回执证明了发生，不证明没有遗漏

其可信执行方签发日志记录；接收方检验证明。正文 13.3–13.5 明确将签发方放在信任边界，并区分事件存在与未记录事件的不存在；还讨论证据元数据本身的隐私。[正文](https://arxiv.org/html/2610.39109v1)

本项目可将“日志已存在但迁移包缺回执”作为合法补证场景。Expected 清单仍须独立可信：一张有效包含证明不能说明集合完整。已撤权来源不可经审计接口泄露内容；补到旧回执也必须再次检查当前授权、接收方和版本。用哈希或签名替代来源完整性，无法与该论文拉开差异。

### 3.3 BLIP：替代支持不是恢复历史

第 2 节把可验证来源定义为能重现相同或等价答案的输入子集，并搜索较小的支持集合；第 2.6 节讨论非确定性等边界。[正文](https://arxiv.org/html/2608.25210v2)

本项目必须把两类动作分开：找回原生成事件的可信回执，是修复历史证据；从当前授权输入重新生成，是新派生物。后者不能把旧物品的来源链改写为“当时就没有用被撤权输入”。只有新物品独立生成、记录并重新提交，才可讨论另一条合法路径；不得让模型猜测缺失原文。

### 3.4 When Evidence Changes：完整成本比修复局部成本更难击败

该文比较修复、缓存、重建与来源过滤重读，计入摄取、修订和后续使用。正文也限定 read-set 提交检查所证明的是版本一致性，不能代替内容支撑或权限判断。[正文](https://arxiv.org/html/2610.03902v1)

因此本项目应将定位、规划、回执验证、失败后回退、最终提交检查全部计入成本；保留所有失败和被拒交付。若预期清单已足够小且有索引，直接查询缺项很可能最便宜。当前补证路径选择要先战胜这一简单实现，再讨论模型侧收益；不能以少几次模型调用推导不可观测的商业平台总成本。

### 3.5 ProvMark 完整性检查：独立参考图是关键

论文以可控系统调用生成参考行为图，对比采集图，并用图差异/匹配支持异常定位；示例包含人工丢失或改变记录。作者明确标为工作进行中。[全文](https://www.usenix.org/system/files/tapp2020-paper-chan.pdf)

它最接近“有独立真值的缺证定位”。本项目在统一可信 ID 后使用集合差，通常已足以识别缺项；别名、版本和图匹配是前置规范化问题，不能靠模糊匹配把不确定项放行为 VERIFIED。商业平台完全不可观测的通道仍应 UNVERIFIABLE，不能通过伪造 Expected 集合制造高定位召回率。

## 4. 三个首选成熟算法候选与淘汰条件

| 候选 | 精确定义与适用条件 | 必须怎样公平比较 | 资格结论 |
|---|---|---|---|
| C1 共享缓存 + 去重差集 + 逐项最便宜合法路径 | 对可信缺项集合去重；缓存键绑定证据类型、来源 ID/版本、主体、权限版本、签发域；独立来源且只有单项动作时逐项选最低实际成本 | 所有方法获得相同缓存和同样的批量读取机会；禁止给对手重复计共享证据 | 必须保留的强简单基线。若各项独立，这已能得到最优，不开发复杂算法 |
| C2 加权集合覆盖贪心 | 宇宙是尚缺的**同类型证据义务**；每个合法可执行动作覆盖一组义务，按成本/新增覆盖数选择 | 与 C1、按提供方批处理、全量单批读取、固定顺序去重比较；失败结果不得当已覆盖 | 来源 P08。覆盖集合已知、成本固定且可加时有成熟依据，当前只能评估迁移有效性 |
| C3 小规模精确 MILP 或状态 DP | 最小化总动作成本，要求每个必要证据义务被覆盖；不能覆盖的状态为不可行，不是便宜的允许结果 | 同一动作集合、预算、权限事件；核验最优状态和可行性；报告规划本身耗时 | 用 SciPy/HiGHS 作为资格 oracle，检查简单方法距离最优有多远；不是新算法 |

依赖图是上述方法的输入构造与独立验证工具；已有扁平原始来源集合足够时不必强行引入图。最小割适合特定闭包目标，不应因现成库可用就替代覆盖模型。自适应补证仅在真实的失败概率、条件结果和调用成本被采集后再考虑；当前不估造概率，也不援引不满足条件的近似保证。

## 5. 两个可运行开源实现与许可核验

| 实现 | 固定版本与用途 | 源码、许可证及本阶段状态 |
|---|---|---|
| NetworkX 3.6.1 | commit 7530809bfa1ea7ed6fdf918a4d1431488953cb1f；多层闭包 oracle | [dag.py](https://github.com/networkx/networkx/blob/7530809bfa1ea7ed6fdf918a4d1431488953cb1f/networkx/algorithms/dag.py)，[BSD-3-Clause](https://github.com/networkx/networkx/blob/7530809bfa1ea7ed6fdf918a4d1431488953cb1f/LICENSE.txt)。复用首轮已验证的安装和核心文件 blob，不重装、不重复 3200 组查询 |
| SciPy 1.17.1 | tag v1.17.1 peeled commit 527eb7fd7953a1de068f94bf8b322f249b9405ae；小规模整数覆盖 oracle | [_milp.py](https://github.com/scipy/scipy/blob/527eb7fd7953a1de068f94bf8b322f249b9405ae/scipy/optimize/_milp.py)，[BSD-3-Clause](https://github.com/scipy/scipy/blob/527eb7fd7953a1de068f94bf8b322f249b9405ae/LICENSE.txt)。源码调用 HiGHS；不把超时可行解称精确最优 |

本机版本已由主控检查。此文献子任务核验源码和许可，不独立冒称已经执行本阶段算法；实际运行结果以同目录 pilot_experiment_results.md、原始输出和运行日志为准。SciPy 发行版固定不等于已验证整个二进制供应链；目前未单独固定其打包 HiGHS 的运行时版本。保留第三方 notices，不复制未核许可论文代码。

## 6. 批量补证是否只是人为假设

发现一个现实接口例证：Google Trillian 的 [固定版本日志 API](https://github.com/google/trillian/blob/edf1faff855dc603704d75beb3cdbce9f1152049/trillian_log_api.proto) 提供 GetLeavesByRange(start_index, count)，可批取连续日志叶子，并返回签名根；源码标注 Apache-2.0。它可能返回少于请求的叶子。GetEntryAndProof 是另一单项证明接口；extra_data 不受叶子 Merkle 哈希保护。

这个例证只证明批量获取真实存在，**不证明任意来源子集都可以一次低价获取、验证、合法共享**。连续区间、页长、额外返回记录、权限域与证明费用均约束实际覆盖集合。不能把随机生成的重叠集合当成已发现的商业平台功能；WorkBuddy/DeepSeek Harness 是否提供对应内部历史回执，仍 unknown。

对本地 Trusted Host，可执行适配器应至少产生以下真实记录：

1. 查询了哪一条现有日志、哪一页或哪些索引，返回哪些证据。
2. 请求数、返回条目与字节数、验签/核验次数、数据库实际时间。
3. 哪些证据因权限、版本冲突、截断或不可读未被接受。
4. 共享缓存节约了什么，预热和建索引付出多少成本。

固定人为 cost weights 可以作为敏感性实验，必须标为模型代价。把调用次数乘自定金额，不能称真实 API 费用；未运行人审不能声称节省人审时间。调用数减少也不自动意味着 CPU 或端到端延迟降低。

## 7. 研究空白与停止判据

文献已覆盖本项目多数组成部分。剩余候选不是“Agent 中使用集合覆盖”，而是以下约束能否一起产生现成强基线未充分解决的**实际**问题：

- 历史读取证据、当前内容可读性、当前交付授权是不同义务；合法路径不能互相冒充。
- 多个派生物共享证据，缓存复用必须按版本、主体和权限域失效。
- 补证过程中可能撤权；补证成功不代表提交时仍合法，最后验证必须覆盖所有方法。
- 某些渠道不可观测；算法必须保留不可验证状态，不能靠优化器消除未知。
- 实际日志页/提供方批量接口约束了动作集合，而不是实验者任意画覆盖超边。

以上是需检验的组合约束，不是已经证明的新颖性。新机制若只降低人为加权成本、只赢无缓存或无批处理对手、不能给出可运行补证适配器，文献侧建议 REDUCE；若真实强基线已最优或差异小于规划开销，停止新算法开发。即使本地资格通过，也还没有独立项目 H4 或 SCI 论文贡献的证据。正式论文主线的成立，需要真实证据链与公平实测同时支持。

