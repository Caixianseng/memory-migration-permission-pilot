# Fixed long-input, multiple-handoff workload

Dataset owner: **bowen-upenn/PersonaMem-v2**, revision `ed956dea41521fc4499acbc63f966e0fd3c053ba`, licensed CC BY 4.0. [Original dataset](https://huggingface.co/datasets/bowen-upenn/PersonaMem-v2/tree/ed956dea41521fc4499acbc63f966e0fd3c053ba). The unmodified upstream README is saved under `upstream/README.md`. The public mirror is only a transport route; every original file must match its Git blob ID from the fixed dataset tree. No author endorsement is implied.

This workload is newly fixed persona IDs 6 and 7, independent of IDs 0–5 used in the preceding workload. `cluster_id` retains persona identity; all exchanges and questions from a persona are correlated. There are **two persona clusters**, not 16 independent stories or 128 independent message experiments. The public material is synthetic; all permission events are external controlled study simulation, not native PersonaMem permissions.

Each persona uses exactly the first 32 complete adjacent user/assistant exchanges in the `250911_213118` release, grouped chronologically into eight sources of four consecutive exchanges each. It is not a collage, repeated filler, shortened document, or eight independent natural conversations. If either fixed persona has fewer than 32 such exchanges the preparer fails instead of substituting another persona. The full text of all 64 selected messages per persona is retained, including attribution, drafts, suggestions, times and qualifications. Original system-persona messages are not included. Origins contain raw-file hashes, message indices, JSON pointers, exchange numbers, content hashes and exact rendered character offsets.

`cases.jsonl` contains the two complete source stories. `upstream_manifest.json` fixes selection, revision and source paths; `data_validation.json` records raw file verification and text lengths. Persona 6 has 40,990 source characters and persona 7 has 50,212 source characters, including role and locating headers. Those are measured characters, not model tokens. No source text was truncated to satisfy an artificial capacity limit.

`questions.json` is evaluator-side material. Each case has nine AI-drafted questions, split into three different batches: questions 1–3, 4–6, 7–9. Each batch has a question requiring facts from two source blocks, an ordinary factual question, and a source-dependent question that can become unanswerable after a permission change. The nine questions ask different concrete facts; nine identical questions were not repeated to manufacture demand. Drafts and assistant explanations are queried as those texts, not as independently verified user or scientific facts. `human_gold` remains null throughout.

The schedule dispatches batch A at ticks 0/6/12, batch B at 1/7/13, and batch C at 2/8/14. The 15 demand ticks represent five basic permission periods: ticks 0–2 use base period 0, 3–5 use base period 1, 6–8 use base period 2, 9–11 use base period 3, and 12–14 use base period 4. Actual policy events remain host-provided and are frozen separately; the schedule itself does not grant permissions. Each scoring request gets a fresh target context. Cache existence, invalidation and all real build/rebuild work remain sequential over the full lifecycle.

At each query, a complete current support set is required for a complete answer. If its support is currently absent, `UNKNOWN`, or authorized partial facts plus explicit missing information, is required. `support_sets` can express any independently complete alternative set; the frozen questions here do not require alternatives after checking their particular event, role and timing qualifiers. Similar subject matter elsewhere is not enough to attribute an event-specific fact to another event. `required_phrases` are lexical diagnostics only; nested lists express alternative wording. They are not semantic gold or independent human judgments.

Keep questions, schedules, references and support annotations away from source generation and from the fixed v2 planner. Targets receive only the current three question texts plus the actual authorized memory; references remain evaluator-side. Do not modify v2 prompts or planner weights based on this workload's results. The earlier `data/` sources and references are not edited by this preparer.

Offline provenance recheck, with no model calls:

```powershell
python -B -X utf8 experiments/revocation_grouping_v1/prepare_long_workload.py --offline
```

Changes to frozen source or question materials require a new workload version with the reason recorded and old results retained.
