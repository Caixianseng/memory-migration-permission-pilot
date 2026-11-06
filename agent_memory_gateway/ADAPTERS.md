# Explicit WorkBuddy / DeepSeek Harness exchange

These adapters use files explicitly exported by a user or an authorized platform
workflow. They do not read private application folders or call a supplier API.
They neither import native hidden memory nor prove complete model provenance.
The receiving persistent store in this version is the Host SQLite Agent store.

## Run a local file workflow

Run Python 3.11+ from the repository root. The versions actually used for this
acceptance are preserved separately from the repository's older requirements:

```powershell
python -m pip install -r requirements-gateway-v1-tested.txt
```

Use a **new** gateway data directory. Do not point it at an old experimental C
database directory. Source IDs are globally unique within one Host; prefix new
original facts with their owner or project. Imported original bindings retain
their original owner and version.

Create an explicit `sender-export.json`:

```json
{
  "schema": "agent-memory-gateway-export-v1",
  "source_platform": "workbuddy",
  "target_platform": "deepseek_harness",
  "model": "user-supplied-label-unverified",
  "sources": [
    {"source_id": "A-P1-public", "text": "Delivery is on Monday.", "source_type": "human_supplied"},
    {"source_id": "A-P1-private", "text": "Internal token is CONTROLLED-EXAMPLE.", "source_type": "human_supplied"}
  ],
  "memories": [
    {"memory_id": "mixed", "content": "Monday delivery; internal token CONTROLLED-EXAMPLE.", "source_ids": ["A-P1-public", "A-P1-private"]},
    {"memory_id": "legal", "content": "Delivery is on Monday.", "source_ids": ["A-P1-public"]}
  ]
}
```

The example is hand-authored controlled data, not a model output. For real
exports preserve the exact supplied memory text; label source types explicitly
(for example `platform_export`, `host_observed_input`, `human_supplied`, or
`system_inferred`). These labels are assertions by the trusted importer, not
cryptographic proof. An inferred source is not independent Ground Truth. Prefer
conservative closure of all recorded generation inputs when causal use is unknown.

```python
from agent_memory_gateway.service import GatewayService
from agent_memory_gateway.adapters import import_memory_export, export_receiver_context
from experiments.persistent_exchange_v1.store import StoreError

gateway = GatewayService(".agent-memory-gateway-demo")
imported = import_memory_export(gateway, "sender-export.json", sender_id="agent-a")
gateway.set_permissions("agent-b", ["A-P1-public", "A-P1-private"])
old = gateway.prepare_transfer("agent-a", "agent-b", ["mixed"], "old-mixed")
gateway.set_permissions("agent-b", ["A-P1-public"])
try:
    gateway.commit_transfer(old["transfer_id"])
except StoreError:
    print("Old mixed packet blocked after revocation")
new = gateway.prepare_transfer("agent-a", "agent-b", ["legal"], "legal")
receipt = gateway.commit_transfer(new["transfer_id"])
restarted = GatewayService(".agent-memory-gateway-demo")
print(restarted.commit_transfer(new["transfer_id"])["status"])  # already_committed
export_receiver_context(restarted, recipient_id="agent-b", batch_id="legal",
    output="receiver-context.json", source_platform="workbuddy",
    target_platform="deepseek_harness")
```

The context file can be explicitly supplied to Harness by an authorized user or
existing execution workflow. Creating it is not recorded as native platform
memory ingestion or a fresh model call. Reverse the platform labels and agent
roles for DeepSeek Harness → WorkBuddy, using globally distinct IDs for new
originals. The same contract, authority and persistence mechanisms apply.

No permission is automatically granted during import. Validation precedes
registration; registration is atomic per source/memory, not an all-file
transaction. A later conflicting object can leave earlier valid registrations.
No transfer is prepared or delivered by import alone. Re-exporting unchanged
sources with a new derived memory preserves source identity and gives the new
memory its own export-file hash.

## Recovery and limits

Retain the transfer ID and the private spool. Call `commit_transfer` again after
restart. An exact committed packet receives a metadata-only receipt, including
after later revocation; this confirms history and does not produce another
persistent acceptance or retransmit plaintext. An uncommitted stale packet is
rejected. This version uses explicit IDs; the test Harness's recovery manifest
does not imply a product-wide autonomous retry scheduler.

Do not discard an already committed spool required for transfer-ID lookup.
`discard_transfer` has a documented non-core status-flag limitation for committed
objects. Keep gateway storage under the trusted account. Bearer authentication
protects the loopback HTTP API; it is not a multi-user tenant authorization model.
Back up all SQLite databases and spools while the service is stopped.

## Repeatable engineering checks

The fixed acceptance runner has no supplier credentials and makes zero model
calls. Every invocation requires a fresh output directory:

```powershell
python -B -X utf8 experiments/gateway_v1_acceptance/runner.py --run --output .gateway-check-NEW
python -B -X utf8 experiments/gateway_v1_acceptance/verify.py --run-dir .gateway-check-NEW --output .gateway-check-NEW/verification.json
python -B -X utf8 experiments/gateway_v1_acceptance/summarize.py --run-dir .gateway-check-NEW --output .gateway-check-NEW-analysis
```

Unit discovery avoids collision with an unrelated installed `tests` package:

```powershell
python -B -X utf8 -m unittest discover -s tests -p test_gateway_adapters.py -v
python -B -X utf8 -m unittest discover -s tests -p test_agent_memory_gateway.py -v
```

The preserved API suite has one known exact-error-code assertion mismatch on a
correctly rejected tampered packet. See the acceptance report and original test
log; the fixed safety regression uses unchanged integrity/no-persistence gates.

On restricted Windows runners, TestClient may be unable to create the local
socket pair required by its event loop. Permit local communication to run that
HTTP interface suite; the CPU acceptance runner does not open a network server.
