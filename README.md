# Agent 记忆迁移权限保持本地测试程序

这是根据 2026-10-18 v2 方案制作的简单、离线、可复查的程序。它读取现有数据，在两个自建 SQLite 参考执行器中实际配置权限，通过本地 HTTP 接口验证迁移前后的 `read` 和 `list`。

**它不调用大模型或收费 API，不需要 GPU，也没有安装或测试 Mem0、Letta、Cognee、Zep。结果属于受控参考后端测试，不能用于声称厂商漏洞、原始 GateMem 成绩或新算法优势。**

## 克隆后直接运行样例

需要 Python 3.10 或更高版本，仅用标准库。无需安装依赖、原始数据或 GPU。

```powershell
git clone https://github.com/Caixianseng/memory-migration-permission-pilot.git
cd memory-migration-permission-pilot
python -B run_pilot.py --data-root examples/data --dataset synthetic
```

Windows 也可以双击 **运行示例.cmd**。`examples/data` 是本仓库自行编写的小型虚构数据，只用于验证程序能否运行，不构成公开基准实验成绩。结果保存到 `results/时间_随机后缀/report.html`，可用浏览器离线打开。

代码验证：

```powershell
python -B -m unittest discover -s tests -v
```

## 使用已有本地数据

需要 Python 3.10 或更高版本，仅用标准库。当前机器已验证 Python 3.12.7。

在本文件所在目录运行：

```powershell
python -B run_pilot.py
```

也可以双击 **运行测试.cmd**。脚本会输出 `results/时间_随机后缀/report.html`，用浏览器打开即可。运行过程只监听本机回环地址，结束后关闭服务；不向外部服务发送数据。不覆盖旧结果或原始数据。

常用参数：

```powershell
# 只测公开 GateMem，每个域选两个 episode，最多抽取 120 条前缀记忆
python -B run_pilot.py --dataset gatemem --episodes-per-domain 2 --limit 120

# 只测已有合成数据，并更改人为配额和请求预算
python -B run_pilot.py --dataset synthetic --quota 1 --budgets 0 5 10 20

# 指定另一份本地数据根或新的输出目录
python -B run_pilot.py --data-root "path\to\datasets" --output "results\my_new_run"

# 工程验证
python -B -m unittest discover -s tests -v
```

`--limit 0` 表示使用全部合格记录，`--episodes-per-domain 0` 表示读取所选域的所有 episode。全量会增加主体×对象测试矩阵和运行时间；建议先用默认小样本。`--output` 只能指向尚不存在的目录。

## 已接入的数据

原始数据不随仓库分发。程序支持现有 `datasets/datasets` 布局，也可以通过 `--data-root` 指定数据根；其中合成数据位于 `synthetic/synthetic_corpus.json`，GateMem 位于 `benchmarks/migration_public_2026-10-18/gatemem/raw/bench/data`。缺少原始数据时，请使用前面的独立样例命令。

| 数据 | 使用方式 | 必须保留的边界 |
|---|---|---|
| GateMem Office / Household | 默认各选第一个 episode，以其首 checkpoint 的 `as_of_turn_id` 截断对话，从当时可见的对话中确定性抽样 | 每条对话只对其已核实的人类说话者开放，是**人为受控派生策略**，不是原基准权限或社会规范判断 |
| synthetic_corpus.json | 使用现有 R 参考字段和显式项目组成员配置 | 不把文字标签当成厂商 ACL；本程序把配置落实到自建源执行器后验证 |
| PrivacyLens | 只审计文件存在、记录数和哈希 | 未经审核的传播规范不能直接转换成读取 ACL |
| AgentLeak | 只审计文件存在、记录数和哈希 | 未经审核的渠道/字段规则不作为用户权限真值 |

GateMem 的 `expected_action`、`judge_spec`、`leak_targets`、`query_text` 不用于推导 ACL、迁移内容或生成回答，未来 turn 不导入。原始内容不改写；记录保留 episode/turn/checkpoint 来源。不同 episode 的身份分别限定，避免按同名 ID 无解释合并。

合成数据中 R 同时含用户和项目组。组成员由 `configs/pilot_groups.json` 明确指定，这是**实验控制条件**，不是从数据中推断的企业关系。可以复制该文件修改后，通过 `--groups 路径` 使用。未知用户、未知组或无效组成员导致整条记录排除并登记原因。`deleted`、`expired` 不进入本轮静态实验；没有测试删除、过期或动态撤销。

每次运行保存输入文件 SHA-256、源 ID、排除原因、受控 ACL 和抽样 seed。上游数据的使用应遵循各自原始许可和说明，仓库不重新分发上游数据。`datasets/`、`results/` 和本地实验数据库已加入 `.gitignore`；实验结果可能含原始内容，不应直接提交。

## 实际测试了什么

### K1：正确分组与部分保留

源执行器逐条存储 ACL，目标执行器通过 dataset 成员关系执行权限，读取身份由随机 Bearer token 绑定。缺失或碰撞的身份映射、跨目标租户映射被拒绝；请求参数不能覆盖认证主体。另建一个无权限主体进行检查。

比较三个简单基线：

1. `acl_grouping`：按完全相同的允许主体集合分组；资源不足则整批阻断。
2. `per_item_reject`：按输入顺序保留能配置的条目，共享相同 ACL 的容器。
3. `selective_groups`：按每组可保留的合法读取数量排序，选择资源预算内的组。

**第三个方法只是简单排序。在“组成本相同、合法读取价值可加”的模型中它已经足够，不是新的优化算法。** 无配额时三个正确基线应打平，全部保留且零新增越权。若确实如此，应据此认识到当前静态模型不需要复杂算法。

`--quota` 只在第二组实验中设置**人为 dataset 数量限制**。它不是任何产品已经核实的限制，不能作为真实部署难题的证据。

源端先通过实际 HTTP 原文读取和列表执行核验控制配置。目标先暂存，普通主体此时不可读；隔离副本经过有限域完整读取验收后，绑定的原对象才发布，再复查列表。内容、身份映射、策略版本、目标部署或容器权限不匹配时拒绝发布。这些只是本地参考实现的行为，不构成真实厂商的并发发布或密码学认证保证；当前绑定使用 SHA-256，不是数字签名。

### K2：同预算跨接口验证

比较 `fixed`、`random`、`rule_coverage`、`read_only`、`migration_relation`、`enumerate`。后者在预算内也只做相同数量的请求；另有足够预算的全量 oracle，单列其成本。

每个选择器获得相同控制面策略，只能使用已观察的响应，不读取故障标签或全量 oracle。每次实际 HTTP 调用计一个预算；一次列表返回多个对象仍只算一次调用，覆盖单元数另计。

诊断中包含正常模式和 `list_acl_bypass`：后者是**人为注入的列表权限旁路**，用于检查测试器是否工作。它不是自然发现或厂商漏洞。此定制故障更容易被检查列表的策略发现，不能据此断言迁移启发式优于其他策略。

预算耗尽或传输错误记为 `unknown`，不记为拒绝或安全通过。仅在本地已登记主体×对象×两种操作都已完成测试时，才报告有限域中未发现反例，绝不报告全空间安全。

## 输出文件

| 文件 | 内容 |
|---|---|
| `report.html` | 中文可视化结果总表，可离线打开 |
| `summary.json` / `run_manifest.json` | 参数、运行状态、环境、代码哈希和各组结果 |
| `data_qualification.json` | 辅助数据状态与未直接构造 ACL 的原因 |
| `<数据集>/data_audit.json` | 可用、已选、排除、留待未选记录的统计 |
| `<数据集>/controlled_policy.json` | 施加的受控权限、内容哈希、源引用和身份映射 |
| `<数据集>/input_manifest.json` | 原始输入文件和配置的哈希 |
| `<数据集>/k1_results.csv` | 权限适配、功能损失、容器成本 |
| `<数据集>/matrix_*.csv` | 实际读取/列表响应及反例，不保存 token |
| `<数据集>/k2_results.csv` | 请求预算、首次反例成本、未知比例 |
| `<数据集>/probes_*.csv` | 按实际探测顺序保存的证据 |
| `<数据集>/*.sqlite3` | 本地源、目标、隔离验收副本和诊断库 |

“合法访问保留率”的分母包含所有源端合法读取，包括没有迁移的对象；不会靠删掉困难对象提高分数。未知状态或错误时不伪造零风险。公开条目不稀释未授权读取分母。内容完整性通过字节哈希核验，**不是语义隐私评价**。

## 当前没有实现

- 真实产品间的权限迁移、产品原生认证与版本能力核验；
- 搜索索引和上下文装配；
- 动态授权、旧包重放、删除传播（K3）；
- 用途、接收者和导出/发送控制（K4）；
- 大模型问答或人工语义裁定。

这些指标保持未实现或 `null`，不计入结果。这个程序用于验证数据接入、权限模型、指标、计费和测试器，下一步可以把参考后端替换成经资格核验的真实适配器。
