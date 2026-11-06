# 英文论文框架与段落任务

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


Title: Authorization-Preserving First Delivery of Persistent Memory Across Heterogeneous AI Agents: System Design and Empirical Evaluation

稿件类型：系统与实证研究；预备投稿候选，不声称新基础算法或预先保证某分区接收。

1. **Abstract**：问题是生成时许可不能替代首次持久提交时许可；方法为可信登记、当前核权、原子接纳与metadata恢复；给核心实证和边界。
2. **Introduction**：持久复用与交付授权需求；从产物存在到成功接纳之间的空隙；最接近论文已有何能力；列三项具体贡献。
3. **Related Work**：血缘记忆治理（LAMG/ABM/Collaborative Memory）；修复与重读（MemoRepair/WEC）；上下文/事件与最终许可（CONTINUITY/FORGE/MemTX/PlanFence）；成熟一致性。明确继承和本研究测量对象。
4. **System Model and Threat Model**：Agent适配器、Host、来源/权限、sender/receiver库，攻击者和TCB；完整登记与商业可观测边界。
5. **Security Requirements**：七属性，精确首次COMMIT和ACK区别，授权/epoch真值、保守误拒。
6. **Proposed Architecture and Protocol**：按实际代码给staging/seal/verify/commit/ack路径；原实现与本轮轻量恢复分别说明；状态机与双向独立提交。
7. **Security Analysis**：事务提交顺序、seal与正文/来源绑定、nonce唯一消费、metadata恢复不新增接纳；条件性推导，测试不冒充完全形式验证。
8. **Experimental Setup**：历史真实12合成项目/96条件/768题级字段；新受控脚本/四基线/消融/故障；性能设计；人工方法；统计单位与失败分母。
9. **Experimental Results**：安全与恢复→成熟强参照一致/差异→合法任务效用→失败链→性能；真人结果未到保留明显状态，不填写虚构指标。
10. **Discussion and Limitations**：首次提交和确认是不同研究对象；同等安全不需要复杂算法；观测/合成任务/单Host/未覆盖调度/成本未知对结论的影响。
11. **Conclusion**：给已有实证支持的结论，不承诺任意Agent或全部语义安全。

## 图表分配

Fig1架构、Fig2生命周期、Fig3权限时序来自实际代码合同；Fig4属性/威胁矩阵、Fig5受控攻击结果、Fig6历史项目效用、Fig7恢复结果、Fig8本地性能来自原始结果或明确的规范。概念图不使用示意数值；每张数值图带来源、聚合、分母和缺失说明。

## 起草前的论证边界

主张对应关系见contribution_evidence_matrix.md。Results保留强参照持平、合法原文较好、epoch保守拒绝这些会改变解释的结果；Stage2/3不同安全目标的资格实验不拼入主结果。稿件不以“实验数量多”当学术贡献。
