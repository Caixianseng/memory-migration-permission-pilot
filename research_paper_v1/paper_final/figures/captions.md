# Figure captions

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


**fig01_architecture**. Actual code-derived architecture. Both commercial endpoints use Host-owned stores.

**fig02_lifecycle**. Code-derived lifecycle. Recovery is the current extension; the legacy core only rejects replay.

**fig03_revocation_timing**. Contract sequence diagram, not simulated timing measurements.

**fig04_property_coverage**. Mapping of bounded properties to tests. This is a coverage specification; no empirical percentage or general proof is implied.

**fig05_security_results**. Observed targeted case counts, not production rates. The first metric combines revoked access, stale sources, wrong receivers and forged content; it is not solely a sensitive-disclosure metric. Mature reference and Host have equal safeguards.

**fig06_legal_utility**. All 12 project points per method are shown; no independent n=768 claim or semantic-human accuracy is implied. Existing paired contrast intervals are reported in the manuscript.

**fig07_recovery**. Five cases require confirmation of an existing commit; one requires a fresh retry after a precommit crash. Safe recovery requires correct disk effects, not only a success response. The raw field recovery_confirmed encodes this six-case composite.

**fig08_overhead**. All 12 technical repetitions and medians at each size/method. Logarithmic y-axis preserves long-tail observations. Connections are preopened and packets prepared before timing; provider time excluded. Phase timings and absent-phase zero codes are defined in performance report.
