# 前序实验聚合结果公开包

本包保存七个前序批次的聚合投影，补充最新双向持久化交换实验。它按明确字段白名单导出状态、独立单位、方法指标、token 与费用估算，不包含原始回答、第三方对话或问答正文、原生日志、账户信息、会话标识或本机绝对路径。

这是**聚合结果公开**，不是完整原始执行材料发布。从本包可以检查公开文件完整性、读取既有聚合指标；不能独立重新验证模型实际输入、原生日志、权限执行或原始回答的评分。源报告的 SHA-256 用于标识本地保留的原件，不代表这些原件已经公开，也不是数字签名或第三方验真。

## 七个批次

| 文件 | 内容与独立单位 | 解释范围 |
| --- | --- | --- |
| [permission_context.json](permission_context.json) | 两个内容簇下的权限与上下文扩展离线探针 | 原报告模型调用为零；重复权限掩码不是新增独立故事，覆盖率不是模型答题质量 |
| [memory_module_fusion.json](memory_module_fusion.json) | 四个问题簇、十九臂的两次原生运行聚合 | 两次运行顺序执行；不是一个十九臂交错随机实验；提供原报告的官方词面指标与方法级费用估算 |
| [evidence_repair_fresh40.json](evidence_repair_fresh40.json) | 四十个问题簇、五臂的合并分析 | `all_planned_requests=600` 保持“计划请求”原义；不能由此推定六百次均成功；两块先合并再 bootstrap |
| [prefix_quotient64.json](prefix_quotient64.json) | 两个既有内容簇组成的一个规模桥接案例 | 原报告有十二次模型调用尝试；属于开发桥接，不是十二个独立案例；词面检查不等同人工语义金标 |
| [grouping_development-20261104-v1.json](grouping_development-20261104-v1.json) | 两个开发故事簇的 D1 早期对照 | 人工 gold 保持 null；方法与故事簇级指标保留，原始请求标识移除 |
| [grouping_reserved-20261104-v2.json](grouping_reserved-20261104-v2.json) | 四个短故事簇的探索性检查 | 保留修订后检查的批次身份，不与开发样本合并为独立大样本 |
| [grouping_long-workload-20261104-v2.json](grouping_long-workload-20261104-v2.json) | 两个长故事簇的 D1 对照 | 早期 D1 已实现、已经运行；这不代表本轮固定哈希分块就是 D1，也不自动证明联合机制优势 |

不同批次的内容、问题、模型设置、指标与成本边界不同，不能将其请求数或逐题数相加，当作一个统计样本量或总体成功率。这里的方法、质量值和审核状态都是对已存在报告的字段投影，没有重新做语义裁定。

## 费用、失败与来源

各文件保留原字段中的估算价格和可见 token。`actual_supplier_bill_cny` 统一为 null：估算价格不是实际供应商账单。保留的 `saved_physical_calls`、`all_cost_requests`、`model_calls_attempted` 和 `all_planned_requests` 各有不同含义，不互相改名。缺失字段不补零，不把 `status=completed` 当作每次请求均成功的证明。

D1 三批保留完整性、未决/失败计数和修正后的用量字段；原生日志、供应商凭据、每次模型回答及其独立复核材料仍未进入本包。此处的原报告审核状态不是本次公开导出的独立原生复验结论。

第三方材料来源为 [PersonaMem-v2](https://huggingface.co/datasets/bowen-upenn/PersonaMem-v2)（既有材料标注 CC BY 4.0）和 [HotpotQA](https://hotpotqa.github.io/)（既有准备脚本标注 CC BY-SA 4.0）。本包只发布聚合指标，不重新分发这些语料正文或模型权重。准备脚本与来源说明保存在对应实验目录，取得原始材料时仍须遵守各自来源许可。本包没有为项目自有代码新增未经确认的许可证。

## 离线完整性检查

在仓库根目录运行，不需要模型、API 密钥或第三方数据：

```powershell
python -B -X utf8 -S benchmarks/prior_experiments_public_20261105/verify.py
```

检查七份 JSON 的长度、SHA-256 和公开范围声明，**不重新验证原生模型执行**。`manifest.json` 绑定这些公开 JSON；各 JSON 的 `source_files` 另记录本地原报告的仓库相对位置与 SHA-256。

`export_aggregates.py` 是确定性白名单导出器，没有网络或模型调用。它需要本地原报告才能重新导出，并拒绝覆盖不同内容；公共仓库没有分发这些本地原报告，因而不能把它当作公开的一键原始实验复现入口。
