# C recovery fault: disposition

The old `source_dynamic_version_no_tx` comparator is preserved as historical
negative evidence. It is not the new comparison's C Gateway service.

The original C performs a receiver-local autocommit INSERT, then consumes the
seal in a separate policy operation. Its injected process exit is between these
operations. On restart it checks current policy before trying to identify an
existing effect; therefore an epoch change prevents historical confirmation.

The original J03/J04 artifacts contained a committed receiver effect and an
unconsumed seal. A new bounded reproduction used the unchanged original worker
once, exited with code 91, reproduced this state, and received
`stale_policy_epoch` on retry. There was one effect before and after retry; this
does not establish unauthorized first delivery or a new duplicate effect.

Read-only inspection of the 12 related receiver/policy databases found DELETE
journal mode, file header read/write versions 1/1, and no present WAL/SHM/journal
files. Database hashes and directory listings were unchanged by inspection.
No WAL failure was assumed or diagnosed.

## Minimal disposition

Reuse the existing `agent_memory_gateway/delivery.py` adapter and unchanged
`experiments/persistent_exchange_v1/store.py`, already shared by mature D/E.
They commit the receiver artifacts, batch/event bindings and seal consumption
in one single-host SQLite ATTACH transaction with DELETE journals and FULL
synchronization. The adapter first confirms an identity/digest-bound existing
batch, including stored artifact validation; an old committed packet returns
metadata only. A never-committed stale packet must still pass current authority
checks and is rejected.

No new atomicity algorithm is introduced. New B invokes this same mature core;
new C invokes it through GatewayService. Equality is the fair expected result.
The candidate's Store bytes match the historical mature Store. No core repair
patch was needed before fixed regression execution.

Use a new data directory. Historical C orphan rows lack the batch/event bindings
needed for authenticated recovery; no automatic migration fabricates these.
The local full source/SQLite audit and exact new reproduction remain in the
project evidence directory. Original archives, evaluations and scores are unchanged.

## Non-core findings retained

The pre-existing API tamper test expects a later validator's error code. Actual
HTTP409 rejection occurs earlier in the committed-receipt validator. Its safety
behavior is correct, but the original exact-error assertion fails. The failed
test log is retained; no acceptance criterion is changed to conceal it.

Discarding an already committed spool can remove transfer-ID lookup material
and returns a misleading unconsumed-seal flag. The fixed workflow retains
committed spools and never invokes discard after commit. This operator interface
limitation is registered without opening a new repair cycle.
