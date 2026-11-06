# Same-family Flash control — execution record

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


WorkBuddy **5.9.3** currently exposes `deepseek-v4.1-flash` / `DeepSeek-V4.1-Flash` in its resolved native product model metadata. A dedicated fresh-session arithmetic qualification returned `{"answer":25}`, with actual/request model IDs both `deepseek-v4.1-flash`, one native user request and zero tool calls. The existing HY3 helper and the user's current session/model configuration were not changed. Evidence: `evidence/workbuddy_available_models_native.json` and `same_family_control/preflight/workbuddy_flash/envelope.json`.

The installed official Harness SDK **0.2.1-rc.3** independently returned the correct arithmetic result under `provider=deepseek-account`, `model=deepseek-flash`. DeepSeek's current official documentation maps that alias to **V4.1-Flash-1017**. WorkBuddy's native metadata/response exposes no `1017` checkpoint identifier. Therefore this is a **same named model family control**, not proof that both routes use identical weights, backend builds, decoding settings or full system prompts. [Current official model mapping](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/), [official October 17 update](https://api-docs.deepseek.com/zh-cn/updates/).

## Frozen control

The input is each completed `qualification_isolated_v1/LIVE-Pxx.B_to_A.r0/persistent/readback.json`, field `legal_successor.E_host.multi_source`. The common public request is built with the existing `receiver_request(..., scenarios=('multi_source',))`. Both platforms receive the **same canonical UTF-8 business JSON**, with a recorded SHA-256. They use independent fresh sessions; the model sees the legal delivered memory and public question text, never scoring gold or the withheld audit code. Client wrappers and native system contexts remain different and are recorded as such.

There are at most ten paired synthetic projects, two real calls per completed project. WorkBuddy Flash calls run serially; each Harness SDK request is independently bounded to one physical text-only stream, 512 output tokens and a CNY 0.9 conservative ledger cap. The WorkBuddy helper records one native user prompt and zero tools; its hidden physical supplier request count and actual bill are unknown. Failed or uncertain requests are retained without automatic model retries. Input projects not yet completed by the parent experiment remain on a waiting list.

This control evaluates receiver answers after **Host-managed persistence and a separate-process readback**. Neither zero-tool client directly accesses SQLite. It does not rerun the migration protocol, add independent project samples, or compare source-generation methods.

## Code and records

- New fixed-model helper: `experiments/paper_live_v2/same_family_control/workbuddy_flash_native_one_shot.mjs`.
- Paired runner: `experiments/paper_live_v2/same_family_control/run_control.py`.
- Per-project frozen input, full outputs, model metadata and receipts: `same_family_control/projects/LIVE-Pxx/`.
- Derived snapshots: `same_family_control/summary_nNN.json` and `question_scores_nNN.json`.
- Waiting snapshots: `same_family_control/waiting_nNN.json`.
- Alias and claim boundaries: `same_family_control/model_identity_evidence.json`.

The helper reuses the established native `session:create`, `session:get` and `session:sendMessage` flow with independent Flash-only model guards, installed-file hashes, a fresh reserved UUID/workspace, own-session native-history audit, exact business-input binding and no automatic replay. The HY3 alias assertion was removed from this separate helper; an actual fresh Flash response is required for qualification. Local guard checks confirmed rejection of a HY3 requested model and a HY3 actual-response model. These checks made zero model calls.

## Analysis rule and current status

Project is the independent unit. The primary descriptive measure is the proportion of the three legal questions answered correctly per project; the fourth unique withheld-code question is scored separately for abstention and exact-value disclosure. Paired differences and project bootstrap intervals are derived only from completed paired projects. Scores are exploratory AI/rule assessments with `human_confirmed=false`. Exact-value absence is not a proof of general semantic noninterference. No significance or superiority claim is prespecified for this platform control.

The first Harness QA response contained a complete correct JSON object followed by one redundant `}`. Its original strict-format failure and raw bytes are retained. The common `format_adapter.parse_json_object` was then applied to both platforms as a clearly marked **post hoc format sensitivity analysis**: only surplus `}` after a complete object may be removed, never content/fields or scoring values. `local_parse_recovery.json` records the zero-call recovery of the original response. Strict-schema success/utility and format-adapted content utility are both recorded; this adaptation is not hidden as an originally conforming output. New SDK jobs use short isolated ledger paths to avoid the confirmed legacy Windows path limit; only public request/response/usage/receipt files are mirrored into `sdk_records/`.

Nature Statistics was used to check the unit/replication and reporting boundaries. Client calls are ordered WorkBuddy then Harness per project; latency is descriptive, not a randomized causal comparison. A degenerate paired interval when all observed differences are zero does not establish population equivalence. The control adds no formal hypothesis-test family or multiple-comparison claim.

## Completed results

All ten paired projects completed: **20 new real QA calls**, plus the separate one-call WorkBuddy arithmetic qualification. The earlier Harness arithmetic preflight is outside these 20 QA calls. Every pair has matching canonical business-input hashes. The final offline audit also checked the SDK's actual dispatched business text byte for byte, actual-request/output hashes against guarded receipts, unchanged parent readback hashes, observed native model IDs, one WorkBuddy user prompt/zero tools per job, and one physical SDK stream per job. No completed pair was redispatched while waiting for the remaining parent cases.

| Measure | WorkBuddy V4.1 Flash | Harness SDK Flash |
|---|---:|---:|
| Completed projects / new QA calls | 10 / 10 | 10 / 10 |
| Legal answers correct after common format adaptation | 30/30 | 30/30 |
| Strict JSON/schema-conforming responses | 5/10 | 2/10 |
| Legal answers accepted with strict schema required | 15/30 | 6/30 |
| Explicit UNKNOWN on withheld-code question | 10/10 | 10/10 |
| Exact withheld-code values in answers | 0 | 0 |
| Mean measured invocation latency, seconds | 15.902 | 3.777 |
| Median measured invocation latency, seconds | 15.359 | 3.672 |
| Actual monetary charge | Unknown | Unknown |

The format-adapted project utility difference (WorkBuddy minus Harness) is **0.0**, with project bootstrap interval **[0.0, 0.0]** because every selected project is at the utility ceiling. This does not demonstrate population equivalence or identical backend weights. The 13/20 strict-format failures are retained and reported rather than absorbed into a single 100% figure: **five WorkBuddy responses wrapped valid JSON in Markdown fences; eight Harness responses added one redundant closing brace after a complete JSON object**. Fence removal was already part of the original common parser; the narrow closing-brace adaptation was introduced after the first observed Harness failure and applied to both clients. The first failure's original `result.json` remains unchanged with a separate recovery record.

The Harness QA receipts expose **10 physical requests** and a conservative public-rate peak estimate of **CNY 0.018700 total**; this is not an invoice or a proven account debit. WorkBuddy exposes ten native user requests, not its hidden physical supplier requests or per-task monetary charge. Fixed client order, different wrappers and native contexts, concurrent background workloads and opaque backend configurations prevent a causal latency or cost superiority claim from this table.

The completed evidence supports successful use of the same legal, Host-reopened multi-source memory by two real client routes carrying the same named model family. It does not add an algorithm advantage or prove generalized semantic noninterference. The deliberately small, fixed synthetic suite is a control for the main experiment, not a population sample.

Final records: `same_family_control/final_audit.json`, `summary_n10.json`, `question_scores_n10.json`, `contextual_answer_review.json`, `format_error_breakdown.json`, `waiting_n10.json` (empty waiting list), and `public_artifact_sha256_final_v2.json`. Offline finalization command: `D:/python3.11/python.exe -m experiments.paper_live_v2.same_family_control.finalize_control`. The finalizer made zero model calls. All 80 answer/reference fields were inspected by Codex; 76 match exactly and four correct numeric answers add the appropriate unit. This same-family AI inspection is not an independent external or human judge.

## Execution and correction log

All steps below were executed on 2026-11-06. The following log describes actual runs, not scheduled work. Native metadata reads, own-session model evidence and sanitized SDK receipts remain the primary machine records.

1. Read the installed executor skills and inspected WorkBuddy 5.9.3 public packaged code. The original metadata-channel guess `getProductConfiguration` failed; installed `handler-registry.js` established `config:getProductConfiguration`. The corrected read-only request returned 60 available model entries, including Flash 4.1, without creating a session or sending a model prompt. Restricted execution could not verify the local port owner; the authorized unrestricted read succeeded. No global config was edited.
2. Created the separate fixed-Flash native helper. `node --check` passed. Zero-request fixture checks accepted the fixed Flash route and rejected both a HY3 requested model and a HY3 actual-response model. The one dedicated arithmetic qualification then returned 25 with native Flash model/request IDs and zero tools.
3. Ran `D:/python3.11/python.exe -m experiments.paper_live_v2.same_family_control.run_control --wait-seconds 900`. The first pair produced a strict SDK JSON trailer error; the original failed record was preserved. After applying the parent's common lossless parser, the same raw response was recovered locally with zero additional requests.
4. A later analysis pass encountered `KeyError: strict_schema_valid` because the earliest already-completed WorkBuddy result predated that reporting field. The analysis was corrected to reparse its original retained response bytes; no original result was modified and no answer was regenerated. New SDK jobs used a deterministic short isolated ledger path. Prior successful SDK/public records were preserved and mirrored.
5. The resumed bounded runner completed nine pairs and retained `waiting_n09.json` for the tenth incomplete parent input. After the parent confirmed `LIVE-P10.B_to_A.r0/complete.json`, a final cached run dispatched only the two missing P10 requests. All earlier pairs returned their saved results. Final waiting list: empty. Total QA subject calls: 20; extra WorkBuddy arithmetic qualification: 1. The separate earlier Harness arithmetic preflight is recorded in `harness_preflight.md`.
6. Offline finalization passed all ten actual input/request/hash/model checks. Its first manifest traversal entered the legacy P01 private long path and raised `WinError 3` after writing the successful audit. Top-down pruning of `.private` directories fixed the public-manifest traversal. The audit was preserved, the finalizer was made idempotent, and a second offline verification passed. No model requests were made by either finalization attempt. The final public manifest indexes 265 files and excludes account/private-home contents.

Source hashes are recorded under `same_family_control/code_versions/` and `final_code_version_v2.json`. Full per-WorkBuddy invocation return codes/stdout/stderr are saved per project; SDK stream guards, request bodies, responses, usage and receipts are saved under `sdk_records/`. No app binary, original HY3 helper, original dataset or original parent experiment result was overwritten.

Private SDK account metadata and `home.private/` contents must be excluded from publication; only sanitized usage/receipts are research evidence. Actual invoices are unknown. All original experiments, dataset files, app files and global configuration are preserved.
