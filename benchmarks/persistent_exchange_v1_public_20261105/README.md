# Persistent bidirectional memory exchange public results 2026-11-05

This bundle publishes synthetic task data, actual model answer text, actual
received memory text, source-output projections, and reported audit summaries
from 12 independent projects, 96 conditions and four comparison arms. It does
not contain commercial-client native histories, account/session identifiers,
queue leases, credentials, provider-private directories, or SQLite databases.

The full frozen offline scorer can be rerun without model access:

```sh
python scripts/export_persistent_exchange_public.py --verify
```

Run this from the repository root. Python 3.11 or newer and the standard library
are sufficient for verification. It imports the unchanged scorer at
`experiments/persistent_exchange_v1/evaluate.py`. No network, client login,
database or model call occurs. The verifier compares every core report field,
including all per-question/per-project scores, resources and paired-bootstrap
intervals, with `evaluation_report.public.json`.

## Files and evidence boundaries

- `records.public.json`: 96 parsed answers, exact original answer UTF-8 text and
  hashes, received payload text, and minimal reported readback fields. Source
  references are public attempt identifiers, not executable file paths.
- `source_attempts.public.json`: all 132 source-result attempts, including
  failed/closed outputs, source IDs and original local result-file hashes.
  Provider-private partial streams are not included. A reported model identity
  remains unknown when the archived attempt had no verified identity.
- `cases.public.jsonl`, `evaluation_only.json`, `contract.json`, and
  `mechanism_spec.json`: byte-preserved synthetic fixtures and frozen scoring
  definitions. Evaluation references are public now; they were not supplied to
  source/receiver models during the experiment.
- `evaluation_report.public.json`: complete offline task scores. The
  source-protocol-clean supplement is an archived local-audit result; rerunning
  the public scorer verifies the core comparison, not that native audit.
- `audit_summary.public.json`: whitelist cost/failure/protocol counters. There
  are 132 source-result attempts and 98 receiver outer attempts, representing
  96 completed main conditions. A separate late continuation is not a new
  source-result record and its text was not adopted. Local rechecks are not new
  model calls. WorkBuddy fees and supplier physical requests remain unknown;
  Flash price-derived estimates are not supplier bills.
- `security_probes.public.json`: 24 old-whole permission views and 72 isolated
  packet-copy attack outcomes, with no real extra model invocation or delivery.
- `mechanism_probes.public.json`: two real multilayer return probes, reported
  independently from the twelve-project primary comparison.
- `fixed_chunk_impact.public.json`: post-hoc descriptive invalidation counts,
  not a pre-registered replacement algorithm result.
- `provenance_manifest.json`: public artifact hashes, frozen evaluator/fixture
  hashes, original local archive hashes, availability and exclusion notes.
- `verification.json`: export-time comparison and bounded sensitive-pattern
  checks. This does not replace an independent native execution audit.

## Result and statistical scope

Project-weighted lawful-task scores were raw 100%, whole-drop 20.83%, full
rebuild 86.46%, selective 77.72%. The fixed two-hash-chunk candidate failed the
predeclared engineering screen; the proposed permission/semantic joint D1
grouping was not evaluated. All four arms had zero exact withheld-value hits
in the observed payloads and answers. That is not a semantic noninterference
proof. Lexical required-value coverage is not a full hallucination audit.
The independent unit is twelve projects, not 96 conditions or 768 answers.

Native-client evidence, private transport traces and databases remain local
because they can contain account- or execution-specific metadata. Hashes bind
the public projection to that archive but do not make the omitted evidence
publicly re-auditable. This bundle supports transparent offline re-scoring,
not a claim that fresh WorkBuddy/Harness runs are byte-identical or available
without the documented client setup.

These task fixtures are project-generated synthetic materials. No third-party
private corpus, publisher PDF, model weight, or new third-party licence is
bundled. No additional licence grant is inferred by this export; consult the
repository's stated licensing terms before reuse.
