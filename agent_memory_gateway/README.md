# Agent Memory Gateway

A local, model-agnostic gateway for permission-checked persistent memory
delivery between separate Agent stores.

## Capabilities

- Immutable original sources and derived memories with source dependencies.
- Recipient grants with a monotonically increasing policy epoch.
- Sealed transfer packets stored in a private local spool.
- Authorization recheck at the receiver's first persistent commit.
- Single-host SQLite transaction for receiver data and one-use seal consumption.
- Metadata-only idempotent confirmation after a lost acknowledgement.
- Receiver-side readback and hash-chained audit events.
- Explicit bearer-token authentication; server binds to loopback.

## Security boundaries

This is a single-host trusted gateway, not a distributed transaction protocol.
It cannot retract plaintext already delivered to a recipient, prove that a
commercial Agent exposed every hidden input, or prove that declared dependencies
include every fact actually used by a model. The trusted writer must register
complete inputs.

## Run locally

From the repository root, use Python 3.11+:

    python -m pip install -r requirements-dev.txt
    python -m pip install -r requirements-gateway.txt
    set AGENT_MEMORY_GATEWAY_TOKEN=replace-with-a-random-secret-of-at-least-32-characters
    python -m agent_memory_gateway --data-dir .agent-memory-gateway --port 8765

PowerShell users can set the variable with:
$env:AGENT_MEMORY_GATEWAY_TOKEN = "replace-with-a-random-secret-of-at-least-32-characters"

Open http://127.0.0.1:8765/docs. Health is public; all /v1 routes require
Authorization: Bearer <token>.

## Workflow

1. POST /v1/agents/{agent}/sources — register original facts.
2. PUT /v1/recipients/{recipient}/permissions — grant source IDs.
3. POST /v1/agents/{agent}/memories — create a derived memory with source_ids.
4. POST /v1/transfers — create a sealed transfer packet.
5. POST /v1/transfers/{transfer_id}/commit — check permission and persist.
6. GET /v1/agents/{recipient}/batches/{batch_id} — read the recipient's batch.
7. Revoke by updating permissions. A prepared but uncommitted transfer must fail.

## Offline tests

    python -B -X utf8 -m unittest tests.test_agent_memory_gateway -v

Tests use synthetic facts and local SQLite files. No model calls or API keys
are required.
