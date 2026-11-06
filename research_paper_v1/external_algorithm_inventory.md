# 成熟外部算法资格清单（2026-11-05）

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


本轮保留 5 个候选。**1 项完成真实 CPU 资格运行，2 项未完成安装与运行资格，2 项只完成固定源码静态核验。** 这不是论文算法胜出记录。没有调用 WorkBuddy、DeepSeek Harness 或付费模型，没有修改原始数据与旧结果。

## 先确定各自解决的问题

| 候选 | 对应路线 | 实际角色 | 当前资格 | 公平的简单替代 |
|---|---|---|---|---|
| NetworkX 有向图可达性 | A 撤权 / C 失效传播 | 完整依赖图上的受影响节点基线 | **实际通过：3200/3200 oracle 一致** | 已有扁平依赖集合与 revoked 集合求交；普通 BFS |
| Z3 SMT | B 部分可观察证据 | 有限模型的一致性、反例与双模型诊断工具 | 安装未完成；未执行 solver | 小宇宙直接枚举；已知 AND 来源直接集合判断 |
| Hypothesis stateful / shrinking | D 生命周期验证 | 事件序列生成与反例缩减工具 | 包安装未成功；未执行状态机 | 手选边界、有限序列穷举、普通 pytest 参数化 |
| DBSP / Feldera 增量视图维护 | C 增量失效 | 关系化证据/授权视图的增量维护候选 | 仅静态核验 | SQLite 索引、反向依赖索引、仅重算受影响行 |
| Cedar 授权语言 / 引擎 | A 权限表达 / D 验证 | 复杂策略执行与分析参考 | 仅静态核验 | 当前来源集合 ACL 与单 Host 事务检查 |

这些角色不能混在一个“修复算法胜率”榜单里。图工具与修复器、验证工具、授权引擎应有各自的问题契约与评价指标。

## 1. NetworkX：立即可复用的直接基线

论文为 Hagberg、Schult、Swart 的 [Exploring Network Structure, Dynamics, and Function using NetworkX（SciPy 2008）](https://aric.hagberg.org/papers/hagberg-2008-exploring.pdf)。机构分别为 Los Alamos、Colgate、Los Alamos。这是库的出处，基本可达性算法不是该论文新发明，也不是我们的创新。本轮未核验 DOI，不补写猜测值。

固定版本：tag `networkx-3.6.1`，commit `7530809bfa1ea7ed6fdf918a4d1431488953cb1f`。[核心源码](https://github.com/networkx/networkx/blob/7530809bfa1ea7ed6fdf918a4d1431488953cb1f/networkx/algorithms/dag.py) 的 `descendants` 对应“来源 → 派生物”边方向的受影响集合，反向存边才需 ancestors。许可证 [BSD-3-Clause](https://github.com/networkx/networkx/blob/7530809bfa1ea7ed6fdf918a4d1431488953cb1f/LICENSE.txt)。

本机已有 NetworkX 3.6.1，不需安装。已将已安装 dag.py 的 Git blob SHA 与固定提交核对一致：`b7f07eca4f16c05391df34f0637132aae5da2866`。这只核对该核心文件，不是整轮子供应链认证。

实际资格：种子 20261105，100 个 DAG，每图 5 条原始来源与 25 个派生节点，枚举 32 个撤权集合，共 3200 个查询。独立 oracle 在生成 DAG 时递推每个节点的原始来源并集，判断并集是否与撤权集合相交；NetworkX 使用可达性计算，两者 **0 个不一致**。独立通过运行退出码 0，图构造和所有比较合计约 0.533 秒，含导入，不是性能基准，也不是模型修复总耗时。

另设删去 s1→d0 边的人工负对照，撤回 s1 时可达性漏掉 d0。它只验证测试能暴露缺边假设，不能称为发现现有工程漏洞。完整依赖与保守 AND 语义下，已有扁平来源集合求交同样正确；这里尚无 NetworkX 优势证据。

## 2. Z3：条件化诊断，不负责补齐不可见来源

[Z3: An Efficient SMT Solver](https://www.microsoft.com/en-us/research/publication/z3-an-efficient-smt-solver/)，Leonardo de Moura、Nikolaj Bjørner，Microsoft Research，TACAS 2008；[DOI 10.1007/978-3-540-78800-3_24](https://link.springer.com/chapter/10.1007/978-3-540-78800-3_24)。

tag `z3-4.15.4`，commit `745087e237e669d709ae35694728a0c479e572b3`；目标 Python 包 `z3-solver==4.15.4.0`。[MIT LICENSE](https://github.com/Z3Prover/z3/blob/745087e237e669d709ae35694728a0c479e572b3/LICENSE.txt)；[Python Solver 接口](https://github.com/Z3Prover/z3/blob/745087e237e669d709ae35694728a0c479e572b3/src/api/python/z3/z3.py)。底层还需原生 solver 动态库，Python 包版本不能冒充 Git commit。

资格脚本中已准备 3 来源、756 个有限布尔契约对照，以及允许/拒绝两种 completion witness，**本轮没有执行到 Z3**。轮子下载长时间无新增输出后被中止；首次运行明确报 ModuleNotFoundError。没有证据表明算法不适用，仅说明安装与运行验收未完成。

即使后续跑通，本脚本中的 AND 授权与版本/nonce 布尔条件，集合判断或穷举已经能解决。只有复杂约束及可审阅反例确有额外作用时才值得引入。若真实来源不在声明变量域中，solver 的“证明允许”只对错误输入模型成立，不能恢复隐藏因果依赖。双模型诊断可作为路线 B 的后续工具，但不构成新方法。

## 3. Hypothesis：测试工具，不是权限算法

[Hypothesis: A new approach to property-based testing](https://joss.theoj.org/papers/10.21105/joss.01891)，MacIver（Imperial College London）、Hatfield-Dodds（Australian National University）及贡献者，JOSS 4(43):1891，2019；DOI `10.21105/joss.01891`。

tag `hypothesis-python-6.151.9`，commit `ad1c0b9745f5b9354b83c643b0f13f5fda361b8a`；[stateful.py](https://github.com/HypothesisWorks/hypothesis/blob/ad1c0b9745f5b9354b83c643b0f13f5fda361b8a/hypothesis-python/src/hypothesis/stateful.py)，[MPL-2.0 notice](https://github.com/HypothesisWorks/hypothesis/blob/ad1c0b9745f5b9354b83c643b0f13f5fda361b8a/LICENSE.txt)，须保留单文件例外声明。固定 pyproject 要求 Python ≥3.10；运行依赖 sortedcontainers ≥2.1.0,<3.0.0；exceptiongroup 仅 Python<3.11。

为隔离安装选择 sortedcontainers 2.4.0（Apache-2.0），tag v2.4.0 的实际 commit 为 `a1f52d6713dd2c2713a881d4f4d86ed68ff71cab`，并非 tag object SHA。

本轮官方 PyPI 安装返回“from versions: none / No matching distribution found”。未确定是当前包可用性还是网络索引原因；Git tag 存在不等于所需 wheel 可取得。未执行 RuleBasedStateMachine 或 shrinking，不能将脚本设计写成已有测试结果。现有 SQLite Host 的状态机适配代码保留为未执行原型，不能据此声称 Host 已通过新覆盖测试。

## 4. DBSP：增量维护成熟，当前不宜直接扩建重系统

[Budiu 等，DBSP: Automatic Incremental View Maintenance for Rich Query Languages](https://www.vldb.org/pvldb/vol16/p1601-budiu.pdf)，PVLDB 16(7):1601–1614，2023，DOI `10.14778/3587136.3587137`。五位作者依次为 Budiu、Chajed、McSherry、Ryzhyk、Tannen；机构为 VMware Research、VMware Research、Materialize、VMware Research、UPenn。

论文指向 vmware/database-stream-processor；该地址 API 报移动，但本轮连接器拒绝数字仓库重定向路径，**没有核验原论文 artifact commit**。只核验现代延续项目 [feldera/feldera](https://github.com/feldera/feldera/tree/8dc6b9a118f893deca0a4f329a15de0decf946d1) 的 commit `8dc6b9a118f893deca0a4f329a15de0decf946d1`，workspace 0.378.0，Rust 1.96.1。不能将现代仓库静态阅读当成原论文复现。

[核心 integrate 运算](https://github.com/feldera/feldera/blob/8dc6b9a118f893deca0a4f329a15de0decf946d1/crates/dbsp/src/operator/integrate.rs) 与 Cargo manifest 已读取。[根 LICENSE](https://github.com/feldera/feldera/blob/8dc6b9a118f893deca0a4f329a15de0decf946d1/LICENSE) 将开源部分置于 MIT、排除 Enterprise；Cargo 元数据另写 MIT OR Apache-2.0，复用前仍须核对具体文件与 feature 范围。没有复制核心源码或安装 Rust 依赖。

适配对象应是关系化的来源边、证据状态、授权状态及其物化视图。任意自由文本 LLM 重写没有自动满足 DBSP 代数条件。现有规模先用 SQLite 索引与受影响项重算；只有计算开销实证成为瓶颈，才值得重型 IVM 引擎。

## 5. Cedar：策略表达强基线，不补来源证据

[Cutler 等，Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization](https://www.amazon.science/publications/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization)，PACMPL 8(OOPSLA1)，Article118，2024；DOI `10.1145/3649835`。作者团队主要来自 AWS，另有 UPenn、UMD 和无隶属研究者；第一作者 Joseph W. Cutler 为 UPenn。具体作者机构可由[会议原始页面](https://2024.splashcon.org/details/splash-2024-oopsla/25/Cedar-A-New-Language-for-Expressive-Fast-Safe-and-Analyzable-Authorization)逐一复核；没有把团队归为单一机构。

固定 commit `66b4afebd944bc284cb486c32fa4dd54aa27e547`，workspace 4.14.0，Rust 1.89；[Apache-2.0 LICENSE](https://github.com/cedar-policy/cedar/blob/66b4afebd944bc284cb486c32fa4dd54aa27e547/LICENSE)。[Authorizer / is_authorized 接口](https://github.com/cedar-policy/cedar/blob/66b4afebd944bc284cb486c32fa4dd54aa27e547/cedar-policy/src/api.rs) 位于约 987/1116 行。当前仅源码与许可核验，未构建、未运行、未做性能比较。

可在策略复杂化时接收主体/动作/资源/上下文，形成授权基线。它不能独立知道 Agent 真正读取了什么，也不能代替接收提交事务。当前来源集合 ACL 不需要先替换为复杂语言。

## 原始证据与复现

运行入口：`experiments/paper_v1/external_candidates/qualify.py --only-networkx`，使用 `D:\\python3.11\\python.exe`。完整环境、命令、退出码、失败与版本在 `evidence/external_candidates/command_log.json`、`final_source_verification.json`、`networkx_qualification_results.json`。3200 个逐例结果在 `networkx_raw.json`；第一次缺依赖错误保留于 `qualification_attempt_1_missing_modules.json`。许可证原文已保存到同目录 licenses/。

最终核验清单以 final_source_verification.json 为准；source_manifest.json 是安装前的初始清单。没有后台安装进程仍在运行。未通过运行资格的两项不作为已实现模块写入论文。

## 本阶段决定

立即保留 NetworkX 为审计/直接基线，继续复用既有 SQLite Host。Z3 与 Hypothesis 进入待环境验收工具队列，暂不追加安装；Cedar 与 DBSP 作为相关工作和扩展候选。没有从本次资格运行得到新算法优于强简单基线的证据。

