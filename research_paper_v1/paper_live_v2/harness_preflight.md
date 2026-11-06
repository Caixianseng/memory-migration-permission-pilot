# DeepSeek Harness preflight — 2026-11-06

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


## Observed outcome

The installed official Harness **0.2.1-rc.3** packaged SDK route succeeded in one bounded arithmetic request: `17 + 8` produced `{"answer":25}`. The returned model is **deepseek-flash**, provider **deepseek-account**. This is the official application's SDK profile in an isolated child process, **not the desktop bridge or a direct OpenAI-compatible API replacement**.

The desktop MCP gateway is registered but `deepseek_health` returned `hosts: []` and `No Harness bridge is registered`. Thus no desktop Host/session is available through that bridge at this observation. This does not imply that the installed application or its official SDK is unavailable.

The first restricted-environment attempt stopped at `account_metadata_unavailable`. Its guard recorded zero agent attempts, zero streams and zero allowed requests; the failed receipt reports `physical_request_count: 0`. The authorized unrestricted retry used a new directory and succeeded. Neither attempt modified the original account credential; the SDK wrapper handles an opaque isolated copy and verifies cleanup. Credential values were not inspected or printed.

## Reproducible records

- Runner: `run_harness_preflight.py` (no automatic retry; repeated job IDs are rejected).
- Initial failed attempt: `raw_experiment_data/preflight/harness/job-arithmetic-20261106/`.
- Successful attempt: `raw_experiment_data/preflight/harness/escalated/job-arithmetic-20261106/`.
- Success files: `input.json`, `actual_request.json`, `response.json`, `receipt.json`, `usage.json`, `guard.json`, `runtime.json`, `reservation.json`.
- Public summary: `raw_experiment_data/preflight/harness/escalated/preflight_result.json`.
- **Private/non-public files:** `account_metadata.private.json` and `home.private/`. They are not research outputs and must be excluded from publication/repository upload. The copied credential is removed after the subprocess finishes.

Runtime executable: `D:/deekseek harness/DeepSeek Harness.exe`.

Packaged CLI: `D:/deekseek harness/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js`.

CLI SHA-256: `ed8bd3ca840d67599bde74f940cdb1714f7b7a98cecd166705a42a661e5cd1b7`.

## Usage and cost boundary

| Observation | Value |
|---|---:|
| Successful physical model requests | 1 |
| Input cache misses | 331 tokens |
| Cache reads/writes | 0 / 0 tokens |
| Output | 6 tokens |
| SDK total | 337 tokens |
| SDK child round trip | 2.922 seconds |
| Conservative peak-rate estimate | CNY 0.00071 |
| Supplier bill / exact balance decrement | Unknown |

The successful request's reservation was below the per-run **CNY 0.9 internal conservative cap**. The reservation and formula are controls and estimates, not actual paid fees. Official pricing was checked on 2026-11-06: Flash peak rates are CNY 2/million input cache misses, CNY 0.04/million cache hits and CNY 8/million output; off-peak rates are half. The existing receipt labels its underlying rate-check date 2026-11-04; this additional preflight checked that the same published rates still apply. The official model page maps `deepseek-flash` to **DeepSeek-V4.1-Flash-1017**; the receipt itself verifies the alias only, not an independently exposed backend build identifier. [Official pricing](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/).

## Exact currently callable SDK interface

Reuse the existing adapter without changing old code:

```python
from experiments.revocation_grouping_v1.sdk_adapter import FlashSDKClient

client = FlashSDKClient(
    root=NEW_ISOLATED_LEDGER_PATH,
    budget_cap_cny="0.9",  # estimated upper-bound ledger, not supplier fee
    max_jobs=1,
)
result = client.generate(
    messages=[
        {"role": "system", "content": "Return only a JSON object with integer key answer. Do not use tools."},
        {"role": "user", "content": "Compute 17 + 8."},
    ],
    job_id="UNIQUE_IMMUTABLE_JOB_ID",
    max_tokens=64,
    role="target",  # source or target
)
```

Underlying SDK JSON-RPC methods are `initialize`, `session/working-directory/set`, `session/prompt`, `session/wait` and `shutdown`. The client pins `provider=deepseek-account`, `model=deepseek-flash`, `reasoningEffort=off`, `retryPolicy.maxRetries=0`, one physical request, no tools and one fresh session per job. `SDKPeer` prompt counts alone are not a physical-request limit; the stream guard supplies the stronger evidence.

The registered desktop MCP alternative, currently offline, accepts:

```json
{"hostId":"EXPLICIT_HOST","workspace":"EXISTING_ABSOLUTE_WORKSPACE","title":"Dedicated research task"}
```

for `deepseek_create_session`, followed by `deepseek_send_task` with:

```json
{
  "taskId":"PERSISTED_UNIQUE_TASK_ID",
  "hostId":"EXPLICIT_HOST",
  "sessionId":"CREATED_SESSION_ID",
  "workspace":"EXISTING_ABSOLUTE_WORKSPACE",
  "objective":"Use this Harness session's own tools on the authorized files; report actual paths and checks.",
  "constraints":["Only edit the dedicated experiment directory"],
  "timeoutSeconds":180,
  "detail":"brief"
}
```

This is documentation, not an executed desktop dispatch. Continue/recover the same task after uncertain transport; do not resend another task ID blindly.

## Persistence boundary for the upcoming experiment

The arithmetic check proves current official SDK model availability. **It does not prove native file reads, native SQLite access, memory persistence, cross-platform migration, or reopened-session use.** The reused `FlashSDKClient` explicitly disables filesystem and shell tools and rejects any tool schema, so merely sending database text in the prompt would not meet a native read/write claim.

To obtain that evidence, use either a connected native desktop Host or an explicitly authorized official SDK tool profile scoped to a dedicated workspace. Preserve actual tool-call/result events, require the Harness model to invoke the read tool on the delivered memory/database, and validate any write/import via a separate reopen. Resume the same dedicated home/session only when testing session persistence; use a fresh session when testing persistent memory independently of chat history. SQLite import/commit performed by Codex/Trusted Host must be attributed to that actor even when a Harness-generated payload is used.

Current official SDK documentation describes persistent `sessions/` and tool-enabled profiles, but it is newer than the installed packaged runtime and must not be treated as proof that a particular plugin/profile exists in version 0.2.1-rc.3. No package was installed and no account/model configuration was changed. [Official SDK guide](https://deepseek-harness.github.io/deepseek-harness/guide/python-sdk).
