# 期刊方法结合的有限资格验证

2026-10-30。按用户上传的详细实施计划执行。此目录为隔离实验，不修改生产默认，不启动真实客户端或模型，不实现完整FACPL、Jif、ABAC挖掘或SMT。

## 组件

- `policy_semantics_reference.py`：独立四值求值，不导入生产授权函数。
- `reference_contract.py`：从可信合成声明编译有限参照与登记请求域。
- `controlled_host.py`：复用当前读取、原生交接和恢复入口；显式绑定接收者，并增加独立恢复许可门禁。
- `verify_memory_flow.py`：原文、来源、位置、标签、受众与明确依赖的传播检查。
- `run_paired_acceptance.py`：同案例执行、禁止网络、封存预测；不打开评分参考。
- `summarize.py`：核验关闭证据哈希后独立重算统计和报告。
- `data/`：4开发+8检查故事、48条事实与48题，全部AI辅助合成控制，人工复核未完成。
- `smoke_plan.json`：32次真实客户端冒烟的未执行计划；费用与剩余额度未核实，不自动启用。

## 运行

```powershell
python -m pytest tests/test_journal_policy_reference.py tests/test_journal_memory_flow.py tests/test_journal_acceptance.py -q
python -m experiments.journal_methods_20261030.run_paired_acceptance --out results/journal_methods_20261030/new_run
python -m experiments.journal_methods_20261030.summarize results/journal_methods_20261030/new_run
```

运行目录必须不存在。不要把`check_references.json`交给开发、预测或并行执行代理；当前无模型资格运行和汇总均不打开它。冻结材料不可用修改参考答案的方式提高成绩。若后续修改规则，旧检查故事应转为已暴露材料，新效果验证需要重新冻结材料。

## 分母和边界

最终run03为2496次请求执行、2360个不同请求，独立实验单位为12个故事。当前默认与整条阻断在所用合同下为等价实现；逐片段与已有选择性隔离同样没有形成新方法差异。事实保留不是答题正确率，空输出不是安全且有用的交付，控制标签不是模型检测准确率。

矩阵恢复允许只是预检，44个恢复端点探针另外报告。原文渲染核对与受保护载荷检查为两个本地检查，未证明保护后客户端实际加载。静态客户端不具备原生ACL和即时撤权，严格模式仍明确拒绝。

原始结果与本地恢复状态位于忽略的results目录。恢复映射不序列化，不将宿主内存控制声称为任意客户端信息流安全。
