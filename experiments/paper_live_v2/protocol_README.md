# A--E protocol experiments (model-free)

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


`protocol_experiment.py` loads frozen paper_final fixture definitions and runs
new isolated effects for A file, B **static** ACL/hash, C checked-but-nonatomic
delivery, D mature transactional/idempotent verification and E complete Host
delivery core. Six ablations are explicit receiver/control capability cuts.

This is not an invocation of the parent's paid commercial model orchestrator.
Do not infer real-client exchange from these controlled inputs.

Recorded output:

- `protocol_run_20261106_v1`:264 actual protocol rows, exact config/code snapshots,
  isolated SQLite files, instrumentation error and metric coding erratum.
- `protocol_perf_20261106_v2`:120 actual first-operation timing rows and their
  retries, corrected expected rejection recording, exit0.
- `analysis.json` in the first run explicitly references the second performance
  file; no raw or frozen source bytes were replaced by analysis corrections.

Reproduce derived summaries without model calls or repeated experiments:

```
D:/python3.11/python.exe -B -X utf8 experiments/paper_live_v2/protocol_analyze.py research_paper_v1/paper_live_v2/raw_experiment_data/protocol/protocol_run_20261106_v1 research_paper_v1/paper_live_v2/raw_experiment_data/protocol/protocol_perf_20261106_v2
D:/python3.11/python.exe -B -X utf8 experiments/paper_live_v2/protocol_crosscheck.py
D:/python3.11/python.exe -B -X utf8 experiments/paper_live_v2/protocol_exact_memory_check.py
D:/python3.11/python.exe -B -X utf8 experiments/paper_live_v2/protocol_figures.py
```

New experiment execution must use a new run ID; existing run directories refuse
overwrite. The current source corrects F22 duplicate coding for future runs.
The actual v1 source is frozen in its code/ directory, and the raw coding erratum
is applied only in descriptive analysis. Do not sum all raw duplicate_effects
without this correction. Joint invalid admission is also not synonymous with
sensitive-disclosure events.

Six recovery traces contain an existing commit and one F19 trace needs a fresh
retry; separate6/6 metadata confirmations from7/7 total safe recoveries.
No-source/no-explicit-nonce checks can be masked by seals, unique keys and the
outer confirmation adapter; null effects remain in the reports.

`exact_original_memory_transfer_check.json` confirms only byte preservation of
the controlled generated memory in F00. This is distinct from sending original
source facts and does not replace a real-model original-memory baseline.
