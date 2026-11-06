# Engineering roadmap: Agent Memory Gateway

This is an engineering plan, not a paper-writing checklist.

## Product target

A reproducible local service that accepts source facts and derived memories
from heterogeneous Agent adapters, enforces dynamic sharing permissions, and
delivers only currently authorized artifacts to a recipient's persistent store.

## Implemented in gateway v1

- Local HTTP service with explicit bearer-token authentication.
- Separate SQLite database per Agent and one trusted policy database.
- Immutable source registration and source-bound derived memories.
- Grant changes advance a policy epoch.
- Sealed canonical transfer packet in a private local spool.
- Authorization recheck at first persistent receiver commit.
- Metadata-only idempotent confirmation after lost acknowledgement.
- Receiver readback and hash-chain audit endpoint.
- Synthetic API tests for revocation, restart, retry and tamper rejection.

## Engineering acceptance gates

1. Core lifecycle: source -> memory -> grant -> prepare -> commit -> readback.
2. Dynamic revocation: revoke after prepare but before commit; no receiver batch
   or memory row is created.
3. Same-packet retry creates one persistent batch and a metadata-only receipt.
4. Restart recovers from spool, receiver DB and policy DB without process state.
5. Modified spool, packet, body, dependency binding or event chain is rejected.
6. Receiver reads only its own imported batch, not sender originals.
7. WorkBuddy and DeepSeek adapters use one common contract; model calls remain
   outside the trusted authorization decision.
8. Structured logs, bounded requests, storage permissions, backup/restore and
   Windows/Linux CI.

## Next implementation order

- v1.1: harden spool concurrency; add lifecycle event export and diagnostics.
- v1.2: adapter interface and real WorkBuddy/Harness integration, preserving
  all frozen historical results.
- v1.3: optional container deployment, operator CLI, backup/restore and
  migration tooling.
- v2: multi-host only after a distributed authorization and consistency model.

## Explicit non-goals

- Do not add evaluation data just to increase counts.
- Do not rewrite or re-score frozen historical data.
- Do not draft paper sections while engineering acceptance gates remain open.
- Do not claim that already disclosed information can be revoked or that hidden
  model context can be reconstructed from incomplete logs.
