# 完整消息的来源与角色轮转强基线

日期：2026-11-02。独立实验组件，不改生产默认，不读取模型账户，不运行模型。**本模块是本项目自行编写的简单对照，不是 Knowledge Triage 的复现，也不声称算法创新。** 默认单位为整个原始消息；没有实现通用切句、用户意图识别或语义类型检测。

## 机制与输入

`selector.select`只接收已由可信主机授权的`SourceBlob`、原始结构化`MessageEvidence`、授权范围和长度上限。来源内容哈希、消息原始Unicode位置、说话者一并记录。`boundary_verifier`必须根据主机保存的原始消息记录核对身份与边界；如果只有整段source字符串、或角色来自模型生成标签，则没有合格证明，返回`needs_review`，不猜测角色。

两个策略共享同一候选池：

- `source_first`：按输入来源顺序、消息原始位置选择。
- `source_role_round_robin`：按来源和说话者分桶，轮流选取完整消息。

后者不区分“用户请求”和“用户陈述”，也不保证请求一定被保留；它是便宜的角色覆盖基线。原句不改写，文本相同但来源不同的消息不合并。放不下的完整单位列入`omitted`，原因区分整单位超限或剩余预算不足；不会截断消息来塞满预算。

`AuthorizedScope`是调用方已经核验的主机判断，不会认证调用方或产生授权。执行前全部输入必须获准，实际交付前还必须按最新政策重新检查**主机登记的全部真实输入依赖**，保持现有driver的真实输入AND规则。`selected_source_ids`只描述被选原句的来源，不能据此缩小真实依赖或放宽权限。本组件不给混合生成摘要重新标来源。

## 长度与公平性

当前只有`LengthMetric(utf8-bytes-v1)`合格，对**完整序列化payload**重新计量，包含source、speaker、offset、哈希及JSON包装成本。结果明确`token_budget_qualified=false`；不存在使用`len(text)//4`冒充真实token的路径。

相同字节上限不等于相同真实模型token，也不保证两臂实际输入长度相等。真实模型实验前必须另接收端实际tokenizer，并对两臂同一完整请求正文计量；在此之前这里只能报告字节预算诊断，不称正式token预算效果对照。两臂使用同一候选池、授权快照与包装格式，并保留实际长度；不复制无意义填充来制造相同长度。若另比较生成器提示中的角色配额，必须另报生成调用和费用，不将本确定性抽取器冒称真实HY3生成。

## Knowledge Triage 最小接入审查

来源：Zerhoudi、Mitrović、Granitzer，2026，Knowledge Triage，[论文](https://arxiv.org/html/2608.22752v1)，[官方仓库](https://github.com/searchsim-org/cikm26-knowledge-triage/tree/a6ceb01a3368cee25ef7ebcf05ebdab8c9be24a4)。

已读固定提交`a6ceb01a3368cee25ef7ebcf05ebdab8c9be24a4`：

- `knowledge_triage/operators.py:type_compact`，blob `00c8517a7138d72e413e964a17390b47b66cbf37`：固定保留constraint、规范空格/小写去重procedural，其他类别按余预算配额选；必要部分超预算返回`COMPACTION_UNSAFE`。
- `knowledge_triage/kb.py:Item.token_estimate`，blob `287f1b2bf8b51d4407ea5df09ad4cebff8c729ff`：`max(1,len(text)//4)`粗估。
- `classifier.py:classify_instruction`为按正则优先级分类，未核实能直接适用于本项目对话角色归属；不得把论文类型检测成绩当成项目成绩。

正式B3若接入，应另隔离运行原始type_compact＋原始classifier，并在之前做与其他臂相同的当前权限过滤；之后以完整真实payload计量。粗估过关但实际超长应单列`length_overflow`，不静默截断、不替原方法修改答案。若把真实计数注入替代Item粗估，应标为“type_compact计量适配”，与未改原版区分；不能仍冒称字节级复现。类型标签不能来自评分金标，除非所有方法同享且单列oracle条件。跨来源文本去重后必须保留实际原对象及独立授权证据，不能从同文反推来源独立。

许可核查：上游Apache-2.0，LICENSE blob `546f563b68d0cdc1b134eb1b8913873ab0c460c5`，固定tree无NOTICE文件。本目录没有复制上游代码，故不包含伪造的上游NOTICE或声称已分发原实现；仅引用其类型保护思想。如果后续vendoring，必须保留原版权及完整Apache许可证、固定版本/原件哈希、注明修改文件与差异；若未来该版本分发带NOTICE，应一并保留。现在不下载模型或大依赖。

## 离线验证

在仓库根目录运行：

```powershell
python -B -X utf8 -S -m unittest experiments.source_role_baseline_20261102.test_selector -v
```

这些是输入身份/边界、整消息保留、预算和答案隔离的工程检查。不是语义评测、不是模型效果，也不是新论文结论。本轮接口只服务未来开发诊断；需要新的独立材料与真实模型对照才能判断是否减少合法信息遗漏。

## 四故事诊断与公开复核边界

干净克隆中可独立运行的是上述 **9项自编合成材料工程测试**。`adapt_existing.py`是本机冻结开发材料的适配器，依赖未承诺公开的`source_materials.json`、`experiments/pre_delivery_revocation/frozen01/`，以及`experiments/permission_personamem_source_20261101/materials.py`和`experiments/permission_task_target_20261101/native_transport.py`。仅下载本目录和公开汇总，不能直接重跑四故事诊断；不要为运行它自行补造这些输入或修改固定哈希。

`results/innovation_search_20261102/role_baseline_diagnostic01/summary.json`中的公开元数据可复算已登记的条数、长度和两臂是否相同；缺少对应原始材料时，不能独立核验原句、角色语义或目标回答，也不能称为完整语义复现。该批四个既有开发故事每源恰有一条user消息和一条assistant消息，两种选择顺序相同，全部原始消息也都能放进登记的记忆文件字节上限；因此没有证立新方法优势。完整SDK请求与模型token未在本诊断计量。
