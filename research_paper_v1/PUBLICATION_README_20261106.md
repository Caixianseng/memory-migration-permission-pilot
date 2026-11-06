# 研究成果公开入口（2026-11-06）

当前完成真实平台资格实验，正式确认性实验和最新英文稿整合未完成；尚未证明完整Host超过强事务基线的新算法优势。

- [研究现状](RESEARCH_STATUS_20261106.md)
- [聚合实验结果](RELEASE_RESULTS_20261106.json)
- [真实平台实验报告](paper_live_v2/EXPERIMENT_COMPLETION_REPORT.md)
- [协议对照](paper_live_v2/protocol_baseline_comparison.md)
- [消融与故障注入](paper_live_v2/attack_and_failure_injection.md)
- [科研图表与数字源表](paper_live_v2/paper_figures/)
- [评价敏感性分析](evaluation_ambiguity_audit_20261106/evaluation_sensitivity_analysis.md)
- [第二阶段负结果](stage2_evidence_gap/go_no_go_decision.md)
- [原始资料待批准范围](PUBLICATION_APPROVAL_PENDING_20261106.md)

本轮公开代码、报告、聚合数值与图表；新增原始模型/逐条记忆资料没有纳入发布。部分旧报告链接是本地审计定位，不能据此认定原始数据已公开。冻结数据和历史评价没有修改。

离线检查：`python scripts/verify_research_release_20261106.py`。该命令只校验公开文件及聚合一致性，不联网、不调用模型，也不声称已独立重算未公开的模型原文。

Data availability: Reports, authored experiment code, aggregate results and scientific figures are included in this branch. Previously public historical datasets remain in the repository base. The new raw-model export and compressed research payloads are held for specific publication approval. Aggregate verification is distinct from re-scoring the withheld raw evidence.
