"""Metadata-only confirmation for an already committed, identity-bound packet.

The legacy import remains unchanged. This adapter adds retry confirmation, not
new plaintext release or a distributed exactly-once claim. Same batch ID alone
is never sufficient. Recovery authenticates the packet against its committed
digest, receiver identity and durable import event, and verifies stored bindings.
"""
from __future__ import annotations
import json
from experiments.persistent_exchange_v1 import store as legacy


def committed_receipt(receiver, packet, module=legacy):
    if not isinstance(packet, dict):
        raise module.StoreError('packet_object_required')
    if packet.get('recipient_id') != receiver.agent_id:
        raise module.StoreError('confirmation_receiver_mismatch')
    claimed = packet.get('content_sha256')
    actual = module.digest({k: v for k, v in packet.items() if k != 'content_sha256'})
    if claimed != actual:
        raise module.StoreError('confirmation_packet_digest_invalid')
    row = receiver.db.execute('SELECT * FROM batches WHERE import_id=? OR batch_id=?',
                              (packet.get('import_id'), packet.get('batch_id'))).fetchone()
    if row is None:
        return None
    for column in ('batch_id', 'import_id', 'sender_id', 'recipient_id', 'epoch'):
        if row[column] != packet.get(column):
            raise module.StoreError('confirmation_identity_conflict')
    if row['packet_sha256'] != claimed:
        raise module.StoreError('confirmation_committed_digest_conflict')
    event = receiver.db.execute('SELECT * FROM events WHERE event_hash=?',
                                (row['import_event_hash'],)).fetchone()
    if event is None or event['kind'] != 'import_committed':
        raise module.StoreError('confirmation_event_missing')
    payload = json.loads(event['payload_json'])
    for column in ('batch_id', 'import_id', 'sender_id', 'recipient_id', 'epoch'):
        if payload[column] != row[column]:
            raise module.StoreError('confirmation_event_identity_conflict')
    if payload['packet_sha256'] != claimed:
        raise module.StoreError('confirmation_event_digest_conflict')
    # retrieve checks actual durable artifact/event bindings. Its plaintext stays
    # internal to the trusted Host and is never included in this return value.
    validated = receiver.retrieve(row['batch_id'])
    if validated['query_receipt']['import_id'] != row['import_id']:
        raise module.StoreError('confirmation_retrieve_identity_conflict')
    return {'status': 'already_committed', 'batch_id': row['batch_id'],
            'import_id': row['import_id'], 'sender_id': row['sender_id'],
            'recipient_id': row['recipient_id'], 'policy_epoch_at_import': row['epoch'],
            'packet_sha256': claimed, 'import_event_hash': row['import_event_hash'],
            'metadata_only': True, 'new_persistent_acceptance': False,
            'ack_contains_plaintext': False}


def deliver(receiver, policy, packet, module=legacy):
    receipt = committed_receipt(receiver, packet, module)
    if receipt is not None:
        return receipt
    try:
        result = module.import_package(receiver, policy, packet)
        return {**result, 'status': 'committed', 'metadata_only': True,
                'new_persistent_acceptance': True, 'ack_contains_plaintext': False}
    except module.StoreError:
        # Another same-packet importer can have committed between the initial
        # lookup and import. A different packet or stale uncommitted task fails.
        receipt = committed_receipt(receiver, packet, module)
        if receipt is not None:
            return receipt
        raise
