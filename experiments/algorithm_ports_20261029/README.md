# 三项算法的逐项移植实验

本目录对应“一个个移植到我们的场景，看看效果”。执行顺序和预算见
`results/algorithm_ports_20261029/plan.json`。三个方法分别评价，不将组合效果归给某一个方法。

| 方法 | 在项目中的位置 | 评价问题 |
|---|---|---|
| LTT（Learn Then Test） | 已核权记忆的检索配置选择 | 简单配置能否通过预先登记的任务风险检验，是否节省上下文？ |
| B/F（Backward/Forward） | 明确来源依赖的增量失效维护 | 撤销一个来源后，能否删除失效派生物，同时保留独立合法支持？ |
| ACORN | 带可信权限过滤条件的向量检索 | 在指定规模与过滤条件下，能否维持检索召回并降低查询开销？ |

三个算法都不能赋予权限。`dual_gate.py` 将既有签名记忆、当前读取授权、独立传播授权和恢复检查连接到受控实验；它不是 Qoder/Harness 原生权限系统。B/F 的来源独立性由可信夹具明确声明，ACORN 的过滤条件须来自宿主授权，LTT 的失败风险阈值不是允许泄露的阈值。

## 已执行入口

从仓库根目录运行，Python 使用项目已有环境：

```powershell
.\.runtime\ci-test-venv\Scripts\python.exe -B -m unittest tests.test_algorithm_ports_ltt tests.test_algorithm_ports_bridge tests.test_algorithm_ports_bf -v
.\.runtime\ci-test-venv\Scripts\python.exe -B -m experiments.algorithm_ports_20261029.run_bf_handoff --output results/algorithm_ports_20261029/bf_handoff_NEW
```

新输出目录必须不存在，以免覆盖历史结果。具体基准命令和执行证据见各方法结果目录及汇总报告。

LTT 的 `predict` 和 `score` 是不同入口。预测只读运行材料；所有预测封存后才评分。评分会同时解封校准和检查参考，选参代码仅使用校准损失，因此不宣称选参完成前检查标签仍物理盲化。已有正式80次预测和4次预检已用完原200次生成总预算；再次调用模型需要另行调整预算，不应重跑本地生命周期入口。

## 解释边界

- 记忆标注采用已签名的受控真值，未新增NER调用，不能据此声称减少自然语言敏感检测漏检。
- 精确原值匹配的零披露只覆盖登记字段；没有评价推断、关系泄露或匿名性。
- 当前迁移包和有效授权仍由原项目接口决定；算法候选不能绕过它们。
- 合成任务和机械依赖图用来验证接口、算法与开销，不替代真实业务任务、人工标注和原生多Agent实验。
- 正确性参照、性能基线、失败记录与收益分别报告。已有算法的适配不自动构成论文创新。

LTT来源：[论文](https://arxiv.org/abs/2110.01052)；B/F来源：[AAAI论文](https://www.cs.ox.ac.uk/people/ian.horrocks/Publications/download/2015/MNPH15b.pdf)；ACORN来源：[论文](https://arxiv.org/abs/2403.04871)、[固定作者代码](https://github.com/guestrin-lab/ACORN/tree/c259f11cdbec880671658eaa0d8747e2cc9de79d)。固定实现、版本和本机兼容处理均在实验结果中记录。
