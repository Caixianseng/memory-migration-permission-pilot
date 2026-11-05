"""Read one imported batch from an independent persistent receiver database.

This executable accepts no source text, sender database, question answer, or
in-memory context. SQLite is opened through a read-only URI and only fixed SQL
statements are used. It never opens the originals table or another batch's
memory content. A receiver restart is therefore a real on-disk readback.

The database is an experiment Agent memory store, not either product's hidden
built-in memory database. Authorization is checked at import/first delivery;
this reader does not erase plaintext delivered under earlier permissions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time

SCHEMA_VERSION = 'persistent-exchange-v1'
READER_VERSION = 'receiver-batch-readback-v1'
_HASH = re.compile(r'^[0-9a-f]{64}$')
_ALLOWED_TABLES = {'metadata', 'batches', 'batch_memories', 'memories',
                   'memory_dependencies', 'events'}

QUERIES = {
    'metadata': 'SELECT key,value FROM metadata WHERE key IN (?,?) ORDER BY key',
    'batch': ('SELECT batch_id,import_id,sender_id,recipient_id,epoch,packet_sha256,'
              'import_event_hash,imported_at FROM batches WHERE batch_id=?'),
    'memories': ('SELECT bm.position,m.memory_key,m.memory_id,m.version,m.origin_agent,'
                 'm.content,m.content_sha256,m.kind,m.artifact_sha256 '
                 'FROM batch_memories bm JOIN memories m USING(memory_key) '
                 'WHERE bm.batch_id=? ORDER BY bm.position'),
    'dependencies': ('SELECT d.memory_key,d.source_id,d.source_version,d.source_sha256,d.owner_id '
                     'FROM memory_dependencies d JOIN batch_memories bm USING(memory_key) '
                     'WHERE bm.batch_id=? ORDER BY bm.position,d.source_id'),
    'event': ('SELECT seq,kind,previous,payload_json,event_hash '
              'FROM events WHERE event_hash=?'),
}


class ReceiverReadError(ValueError):
    """Stable public error without native private metadata or database content."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def need(value, code):
    if not value:
        raise ReceiverReadError(code)


def _hash(value, code):
    need(isinstance(value, str) and _HASH.fullmatch(value) is not None, code)
    return value


def _storage_bindings(database):
    result = {}
    for suffix in ('', '-wal', '-journal'):
        path = Path(str(database)+suffix)
        if path.exists():
            need(not path.is_symlink() and path.is_file(), 'unsafe_database_storage_file')
            raw = path.read_bytes()
            result[suffix or 'main'] = {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw)}
    need('main' in result, 'receiver_database_missing')
    return result


def _authorizer(action, first, second, database, trigger):
    if action == sqlite3.SQLITE_READ:
        return sqlite3.SQLITE_OK if first in _ALLOWED_TABLES else sqlite3.SQLITE_DENY
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _event_binding(event, batch, records):
    need(event is not None and event['kind'] == 'import_committed', 'import_commit_event_missing')
    need(type(event['seq']) is int and event['seq'] >= 1, 'invalid_import_event_sequence')
    _hash(event['previous'], 'invalid_previous_event_hash')
    try:
        payload = json.loads(event['payload_json'])
    except (TypeError, ValueError):
        raise ReceiverReadError('invalid_import_event_payload') from None
    need(isinstance(payload, dict), 'invalid_import_event_payload')
    expected = digest({'seq': event['seq'], 'kind': event['kind'],
                       'previous': event['previous'], 'payload': payload})
    need(event['event_hash'] == expected == batch['import_event_hash'], 'import_event_hash_mismatch')
    for key in ('batch_id', 'import_id', 'sender_id', 'recipient_id', 'epoch', 'packet_sha256'):
        need(payload.get(key) == batch[key], 'import_event_batch_binding_mismatch')
    need(payload.get('memory_keys') == [r['memory_key'] for r in records], 'import_event_memory_keys_mismatch')
    bindings = payload.get('artifact_bindings')
    need(isinstance(bindings, dict) and set(bindings) == {r['memory_key'] for r in records},
         'import_artifact_bindings_missing')
    for record in records:
        binding = bindings.get(record['memory_key'])
        need(isinstance(binding, dict), 'import_artifact_binding_invalid')
        need(binding.get('content_sha256') == record['content_sha256']
             and binding.get('artifact_sha256') == record['artifact_sha256']
             and binding.get('dependencies_sha256') == digest(record['dependencies']),
             'import_artifact_binding_mismatch')
        for key in ('origin_agent', 'memory_id', 'version', 'kind'):
            need(binding.get(key) == record[key], 'import_artifact_identity_mismatch')
    return expected


def read_batch(receiver_db, batch_id):
    """Return ``{'payload':..., 'receipt':...}`` from a new read-only connection.

    ``payload.memory`` is the only business context for the receiving model.
    Receipt metadata has source hashes/IDs but contains no ancestor source text.
    Fixed exact-batch lookup is used; no semantic retrieval claim is made.
    """
    began = time.perf_counter()
    supplied = Path(receiver_db)
    need(not supplied.is_symlink(), 'receiver_database_symlink_not_allowed')
    try:
        database = supplied.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise ReceiverReadError('receiver_database_missing') from None
    need(database.is_file(), 'receiver_database_must_be_file')
    need(isinstance(batch_id, str) and 0 < len(batch_id) <= 256 and '\0' not in batch_id,
         'nonempty_batch_id_required')
    before = _storage_bindings(database)
    connection = None
    try:
        connection = sqlite3.connect(database.as_uri()+'?mode=ro', uri=True,
                                     timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA query_only=ON')
        connection.set_authorizer(_authorizer)
        connection.execute('BEGIN')
        meta = dict(connection.execute(QUERIES['metadata'], ('agent_id', 'schema_version')).fetchall())
        need(meta.get('schema_version') == SCHEMA_VERSION, 'receiver_store_schema_mismatch')
        agent_id = meta.get('agent_id')
        need(isinstance(agent_id, str) and bool(agent_id), 'receiver_agent_identity_missing')
        row = connection.execute(QUERIES['batch'], (batch_id,)).fetchone()
        need(row is not None, 'imported_batch_not_in_this_receiver')
        batch = dict(row)
        need(all(isinstance(batch[k], str) and batch[k] for k in
                 ('batch_id', 'import_id', 'sender_id', 'recipient_id')), 'invalid_import_identity')
        need(batch['recipient_id'] == agent_id and batch['sender_id'] != agent_id,
             'batch_not_bound_to_receiver_agent')
        need(type(batch['epoch']) is int and batch['epoch'] >= 0, 'invalid_import_epoch')
        _hash(batch['packet_sha256'], 'invalid_packet_hash')
        _hash(batch['import_event_hash'], 'invalid_import_event_hash')
        memories = [dict(r) for r in connection.execute(QUERIES['memories'], (batch_id,)).fetchall()]
        need(len(memories) <= 10000, 'receiver_batch_too_many_memories')
        need([m['position'] for m in memories] == list(range(len(memories))), 'batch_positions_not_contiguous')
        keys = [m['memory_key'] for m in memories]
        need(len(set(keys)) == len(keys), 'duplicate_memory_in_receiver_batch')
        dependencies = {key: [] for key in keys}
        for dep in connection.execute(QUERIES['dependencies'], (batch_id,)).fetchall():
            need(dep['memory_key'] in dependencies, 'dependency_outside_batch')
            need(type(dep['source_version']) is int and dep['source_version'] >= 1, 'invalid_dependency_version')
            _hash(dep['source_sha256'], 'invalid_dependency_source_hash')
            need(isinstance(dep['source_id'], str) and dep['source_id']
                 and isinstance(dep['owner_id'], str) and dep['owner_id'], 'invalid_dependency_identity')
            dependencies[dep['memory_key']].append({'source_id': dep['source_id'],
                'version': dep['source_version'], 'sha256': dep['source_sha256'], 'owner_id': dep['owner_id']})
        total_bytes = 0
        for memory in memories:
            need(all(isinstance(memory[k], str) and memory[k] for k in
                     ('memory_key', 'memory_id', 'origin_agent', 'kind')), 'invalid_imported_memory_identity')
            need(isinstance(memory['content'], str), 'memory_content_not_text')
            need(memory['content_sha256'] == digest(memory['content'].encode('utf-8')), 'memory_content_hash_mismatch')
            _hash(memory['artifact_sha256'], 'invalid_artifact_hash')
            need(type(memory['version']) is int and memory['version'] >= 1, 'invalid_memory_version')
            memory['dependencies'] = dependencies[memory['memory_key']]
            need(bool(memory['dependencies']), 'imported_memory_missing_original_dependencies')
            need(len({d['source_id'] for d in memory['dependencies']}) == len(memory['dependencies']),
                 'duplicate_original_dependency')
            total_bytes += len(memory['content'].encode('utf-8'))
        need(total_bytes <= 16*1024*1024, 'receiver_batch_content_too_large_no_truncation')
        event = connection.execute(QUERIES['event'], (batch['import_event_hash'],)).fetchone()
        event_hash = _event_binding(event, batch, memories)
        connection.execute('COMMIT')
    except ReceiverReadError:
        raise
    except (sqlite3.DatabaseError, OSError, ValueError, KeyError, TypeError):
        raise ReceiverReadError('receiver_database_contract_failed') from None
    finally:
        if connection is not None:
            connection.close()
    after = _storage_bindings(database)
    need(before == after, 'receiver_database_changed_during_read')
    context = '\n\n'.join(m['content'] for m in memories)
    payload = {'schema': READER_VERSION, 'batch_id': batch_id,
               'recipient_id': agent_id, 'memory': context}
    receipt_records = [{k: v for k, v in m.items() if k != 'content'} for m in memories]
    receipt = {'schema': READER_VERSION+'-receipt', 'receiver_database': str(database),
        'database_storage_bindings': after, 'sqlite_uri_mode': 'ro', 'query_only': True,
        'query_type': 'exact_imported_batch_lookup', 'batch_id': batch_id, 'agent_id': agent_id,
        'import_id': batch['import_id'], 'sender_id': batch['sender_id'], 'recipient_id': batch['recipient_id'],
        'import_epoch': batch['epoch'], 'packet_sha256': batch['packet_sha256'],
        'import_event_hash': event_hash, 'import_event_binding_verified': True,
        'queries': {name: {'sql': sql, 'parameters': ('agent_id', 'schema_version') if name == 'metadata'
                         else [batch['import_event_hash']] if name == 'event' else [batch_id]}
                    for name, sql in QUERIES.items()},
        'records': receipt_records, 'presented_memory_keys': keys,
        'memory_count': len(memories), 'complete_content_utf8_bytes': total_bytes,
        'rendered_memory_sha256': digest(context.encode('utf-8')), 'payload_sha256': digest(payload),
        'logical_snapshot_sha256': digest({'batch': batch, 'records': receipt_records,
                                            'content_hashes': [m['content_sha256'] for m in memories]}),
        'read_ms': (time.perf_counter()-began)*1000,
        'sender_database_or_original_text_read': False, 'other_batch_content_read': False,
        'claim_scope': 'persistent experiment store and import-time authorization; no remote-model input attestation or earlier-plaintext erasure',
        'external_signature_or_hardware_attestation': False}
    return {'payload': payload, 'receipt': receipt}


def export_batch(receiver_db, batch_id, output):
    """Write a fresh payload/receipt pair after a successful closed/reopened read."""
    target = Path(output).absolute()
    receipt_path = target.with_name(target.name+'.receipt.json')
    need(target.parent.is_dir(), 'existing_output_parent_required')
    need(not target.exists() and not receipt_path.exists(), 'fresh_readback_output_required')
    database = Path(receiver_db).resolve()
    protected = {Path(str(database)+suffix) for suffix in ('', '-wal', '-shm', '-journal')}
    need(target.resolve() not in protected and receipt_path.resolve() not in protected,
         'output_cannot_replace_receiver_database_storage')
    result = read_batch(receiver_db, batch_id)
    payload_bytes = canonical(result['payload'])+b'\n'
    receipt = {**result['receipt'], 'payload_file': str(target),
               'payload_file_sha256': digest(payload_bytes)}
    created = False
    try:
        with target.open('xb') as stream:
            stream.write(payload_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        created = True
        with receipt_path.open('xb') as stream:
            stream.write(canonical(receipt)+b'\n')
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if created and target.exists() and digest(target.read_bytes()) == digest(payload_bytes):
            target.unlink()
        raise
    return {'payload_path': str(target), 'receipt_path': str(receipt_path),
            'batch_id': batch_id, 'recipient_id': result['payload']['recipient_id'],
            'memory_count': receipt['memory_count'], 'payload_file_sha256': digest(payload_bytes)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receiver-db', required=True, type=Path)
    parser.add_argument('--batch-id', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = export_batch(args.receiver_db, args.batch_id, args.output)
    except ReceiverReadError as error:
        parser.exit(2, str(error)+'\n')
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
