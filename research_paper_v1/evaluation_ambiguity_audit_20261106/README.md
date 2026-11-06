# 评价修订交付索引（2026-11-06）

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


历史768字段与新批次720字段严格分开。历史768新增歧义0、GT冲突0、题目条件不足0、明确接收回答事实/运算错误0；旧2条归因UNKNOWN保留。新720中收费歧义9（8 AI、1研究者确认）、明确接收日期错误1、GT冲突0、题目条件不足0；新增歧义待人审0。277元保留原冻结250及score=0，不认定明确计算错误，也不自动算正确。

## 用户要求的六份文件

1. [指令歧义审计](ambiguous_instruction_audit.md)
2. [Ground Truth冲突审计](ground_truth_conflict_audit.md)
3. [历史768条修订CSV](revised_evaluation_results.csv.gz)
4. [新增歧义人审队列](ambiguous_cases_for_review.csv)（0条，只有表头）
5. [原始与敏感性分析](evaluation_sensitivity_analysis.md)
6. [评价变更日志](evaluation_change_log.md)

## 新批次与证据

- [新720字段修订CSV](live_confirmation/revised_live_evaluation_results.csv.gz)
- [唯一研究者确认的记录与范围](live_confirmation/researcher_confirmation.json)
- [新批次统计与排除ID](live_confirmation/summary.json)
- [历史统计](historical_summary.json)
- [原始输出字段对应核验](raw_output_equivalence_receipt.json)
- [原始资料未变化核验](verification_receipt.json)
- [统计独立复核](reviews/final_statistical_crosscheck.json)
- [P09反方复核](reviews/live_p09_countercheck.json)
- [评价规则](evaluation_rules.json)
- [运行日志](run_log.json)

新增付费模型调用0。3713个原始资料和旧评价文件哈希未变化。修订前新分析内部聚合层级问题及其快照保留在revision_01_snapshot，不覆盖此前历史评价。所有AI复核均如实标记为AI，不冒充真人独立评价。
