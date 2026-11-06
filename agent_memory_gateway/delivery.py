"""Durable, metadata-only retry confirmation for a committed transfer."""

from __future__ import annotations

import json

from experiments.persistent_exchange_v1 import store


def committed_receipt(receiver, packet):
    """Return a receipt only when this exact packet was already committed.

    The receiver's persisted body and audit bindings are revalidated. Plaintext
    is never included in the returned receipt.
    """
    if not isinstance(packet, dict):
        raise store.StoreError("packet_object_required")
    if packet.get("recipient_id") != receiver.agent_id:
        raise store.StoreError("confirmation_receiver_mismatch")

    claimed = packet.get("content_sha256")
    actual = store.digest({key: value for key, value in packet.items()
                           if key != "content_sha256"})
    if claimed != actual:
        raise store.StoreError("confirmation_packet_digest_invalid")

    row = receiver.db.execute(
        "SELECT * FROM batches WHERE import_id=? OR batch_id=?",
        (packet.get("import_id"), packet.get("batch_id")),
    ).fetchone()
    if row is None:
        return None

    for column in ("batch_id", "import_id", "sender_id", "recipient_id", "epoch"):
        if row[column] != packet.get(column):
            raise store.StoreError("confirmation_identity_conflict")
    if row["packet_sha256"] != claimed:
        raise store.StoreError("confirmation_committed_digest_conflict")

    event = receiver.db.execute(
        "SELECT * FROM events WHERE event_hash=?", (row["import_event_hash"],)
    ).fetchone()
    if event is None or event["kind"] != "import_committed":
        raise store.StoreError("confirmation_event_missing")

    payload = json.loads(event["payload_json"])
    for column in ("batch_id", "import_id", "sender_id", "recipient_id", "epoch"):
        if payload.get(column) != row[column]:
            raise store.StoreError("confirmation_event_identity_conflict")
    if payload.get("packet_sha256") != claimed:
        raise store.StoreError("confirmation_event_digest_conflict")

    validated = receiver.retrieve(row["batch_id"])
    if validated["query_receipt"]["import_id"] != row["import_id"]:
        raise store.StoreError("confirmation_retrieve_identity_conflict")

    return {
        "status": "already_committed",
        "batch_id": row["batch_id"],
        "import_id": row["import_id"],
        "sender_id": row["sender_id"],
        "recipient_id": row["recipient_id"],
        "policy_epoch_at_import": row["epoch"],
        "packet_sha256": claimed,
        "import_event_hash": row["import_event_hash"],
        "metadata_only": True,
        "new_persistent_acceptance": False,
        "ack_contains_plaintext": False,
    }


def deliver(receiver, policy, packet):
    """Commit once; on a lost acknowledgement, confirm the same packet."""
    receipt = committed_receipt(receiver, packet)
    if receipt is not None:
        return receipt
    try:
        result = store.import_package(receiver, policy, packet)
        return {
            **result,
            "status": "committed",
            "metadata_only": True,
            "new_persistent_acceptance": True,
            "ack_contains_plaintext": False,
        }
    except store.StoreError:
        # A concurrent importer may have committed this exact packet.
        receipt = committed_receipt(receiver, packet)
        if receipt is not None:
            return receipt
        raise
