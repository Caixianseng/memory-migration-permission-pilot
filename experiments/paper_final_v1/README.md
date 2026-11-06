# Model-free paper supplement

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


This directory adds isolated validation and metadata confirmation around the
existing frozen single-Host Store. It does not modify the historical Store or
dispatch WorkBuddy, Harness or any model.

- `durable_delivery.py`: committed identity/digest/event lookup and metadata-only
  retry confirmation; legacy import remains the fresh-delivery gate.
- `runner.py`: 22 controlled lifecycle cases, ten configurations, and optional
  repeated local performance operations. Each new run ID must not exist.
- `summarize_qualification.py`: reads a fully completed raw matrix after the v2
  RSS instrumentation failure; never reruns a case.
- `analyze.py`: descriptive attribute and performance summaries; no p-values.
- `test_durable_delivery.py`: eight safety-relevant adapter tests, all passed;
  log under the CPU evidence directory. These are not eight business samples.

Recorded evidence is in `research_paper_v1/paper_final/evidence/cpu/`:

1. `qualification_smoke_v1`: initial 210 qualification rows, retained; metric and
   naming corrections make it a development run, not pooled primary data.
2. `run_20261106_v2`: 220 frozen main qualification rows. All 22 cases completed;
   the subsequent RSS measurement failed. The error and exact code/config remain.
   `qualification_summary.json` records completion without repeating cases.
3. `run_20261106_perf_v3`: corrected, performance-only run, 144 operations and
   144 same-packet retries. No new qualification cases. All original long tails
   are retained.

The mature transaction reference intentionally shares the frozen verifier with
the complete Host core, and has the same metadata confirmation. This is not an
independent implementation or an external-paper reproduction. Independent truth
comes from the scenario event order and disk effects. Commercial source-attempt
or tool-protocol checks are assessed through historical native evidence, not by
pretending these CPU tests are commercial end-to-end executions.

Reproduce summaries without I/O experiments:

```
D:/python3.11/python.exe -B -X utf8 experiments/paper_final_v1/summarize_qualification.py research_paper_v1/paper_final/evidence/cpu/run_20261106_v2
D:/python3.11/python.exe -B -X utf8 experiments/paper_final_v1/analyze.py
```

To actually rerun experiments, use a **new** run ID (not required for reading the
recorded evidence):

```
D:/python3.11/python.exe -B -X utf8 experiments/paper_final_v1/runner.py --run-id my_new_run --skip-performance
D:/python3.11/python.exe -B -X utf8 experiments/paper_final_v1/runner.py --run-id my_new_perf_run --performance-only
```

The main raw field `unauthorized_first_delivery` is a **joint** invalid-admission
indicator (revoked source, stale source version, wrong receiver, forged body).
Use `attribute_breakdown.json` instead of calling all these events information
leaks. Current-source eligibility and strict old-packet epoch validity are kept
separate. No-provenance/no-explicit-nonce ablations have redundant safeguards and
show no additional failures here; do not manufacture positive effects.

SQLite databases are newly created under each evidence run. Process crash tests
use `os._exit`, not power failures. Bidirectional commits are independent, not a
distributed all-or-nothing exchange. Recovery returns metadata, never memory
plaintext. Adapter integration into the historical paid-model driver is pending.

Metric terminology correction: the frozen raw name `recovery_confirmed` encodes
safe recovery across six cases, not six confirmations of an existing commit.
Five cases already committed (adapter metadata confirmation5/5, legacy0/5); F19
crashed before committing and succeeds through one fresh retry for both. Thus
joint safe recovery is6/6 versus1/6. See evidence/cpu/METRIC_CODEBOOK.md; raw and
frozen source bytes are unchanged.
