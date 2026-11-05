"""Serial trusted-host gating; reuses the project's NativeAgentBroker.

Only this object updates grants. It controls first delivery to a fresh receiver,
not erasure of earlier disclosures or distributed/concurrent atomicity.
"""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import secrets
import time

from memory_migration_study.native_agent_protocol import NativeAgentBroker, NativeProtocolError


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)


class LifecycleHost:
    def __init__(self, sources, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=False)
        self.sources = {s['source_id']: deepcopy(s) for s in sources}
        if not self.sources or len(self.sources) != len(sources):
            raise ValueError('unique_nonempty_sources_required')
        self._permissions = {sid: True for sid in self.sources}
        self._versions = {sid: 1 for sid in self.sources}
        self.revision, self.counter, self.previous = 0, 0, '0' * 64
        self._transfer = 0
        actors = [{'actor_id': a, 'user_id': 'controlled-user', 'agent_id': 'controlled-' + a,
                   'workspace_id': 'controlled-' + a} for a in ('sender', 'receiver')]
        self.broker = NativeAgentBroker({'case_id': 'grouping-lifecycle', 'actors': actors,
            'records': [self._record(sid, True) for sid in self.sources]},
            key=secrets.token_bytes(32), policy_version='grouping-v1')
        self.log('registered', {'sources': {sid: digest(s['text'].encode()) for sid, s in self.sources.items()}})

    def _record(self, sid, allow):
        text = self.sources[sid]['text']
        return {'record_id': sid, 'source_id': sid, 'text': text,
                'source': {'source_id': 'origin-' + sid, 'text': text},
                'source_start': 0, 'source_end': len(text),
                'source_readers': ['sender', 'receiver'], 'recipient_readers': ['sender', 'receiver'],
                'target_readers': ['sender', 'receiver'], 'copy_allowed': True, 'export_allowed': allow}

    def log(self, kind, data):
        row = {'seq': self.counter + 1, 'previous': self.previous, 'kind': kind,
               'revision': self.revision, 'monotonic_ns': time.monotonic_ns(), 'data': deepcopy(data)}
        row['hash'] = digest(row)
        with (self.root / 'events.jsonl').open('ab') as stream:
            stream.write(canonical(row) + b'\n')
        self.counter, self.previous = row['seq'], row['hash']
        return row

    def set_permissions(self, allowed_ids):
        allowed = set(allowed_ids)
        if not allowed <= self.sources.keys():
            raise ValueError('unknown_permission_source')
        changed = []
        for sid in self.sources:
            permit = sid in allowed
            if permit != self._permissions[sid]:
                self.broker.replace_record(self._record(sid, permit))
                self._permissions[sid] = permit
                self._versions[sid] += 1
                changed.append(sid)
        self.revision += 1
        self.log('permission_committed', {'allowed': sorted(allowed), 'changed': changed})

    def authorize(self, ids, purpose):
        ids = sorted(set(ids))
        if not ids:
            return None
        self._transfer += 1
        packet = self.broker.export(ids, sender_actor_id='sender', recipient_actor_id='receiver',
            transfer_id=f'{purpose}-{self._transfer}', ttl_seconds=3600)
        self.broker.validate(packet, sender_actor_id='sender', actor_id='receiver')
        return packet

    def allowed_sources(self):
        result = []
        for sid, source in self.sources.items():
            try:
                self.authorize([sid], 'probe')
            except NativeProtocolError:
                continue
            result.append({**deepcopy(source), 'version': source.get('version', 1),
                           'permission_version': self._versions[sid], 'allow': True})
        return result

    def generate(self, sources, messages, call):
        ids = [s['source_id'] for s in sources]
        packet = self.authorize(ids, 'generate')
        revision = self.revision
        event = self.log('generation_registered', {'sources': sorted(ids), 'messages_sha256': digest(messages)})
        result = call()
        if self.revision != revision:
            raise ValueError('permission_changed_during_generation')
        self.broker.validate(packet, sender_actor_id='sender', actor_id='receiver')
        self.log('generation_sealed', {'input_event': event['hash'], 'sources': sorted(ids),
                                      'output_sha256': digest(result['output'].encode()), 'receipt': result['receipt']})
        return result

    def deliver(self, memory, dependencies, messages, call, *, before_commit=None):
        ids = sorted(set(dependencies))
        packet = self.authorize(ids, 'delivery')
        revision = self.revision
        prepared = self.log('delivery_prepared', {'sources': ids, 'memory_sha256': digest(memory.encode()),
                                                'messages_sha256': digest(messages)})
        if before_commit:
            before_commit()
        if self.revision != revision:
            raise ValueError('permission_changed_before_delivery')
        if packet:
            self.broker.validate(packet, sender_actor_id='sender', actor_id='receiver')
        self.log('delivery_committed', {'prepared': prepared['hash'], 'sources': ids})
        try:
            result = call()
        except BaseException:
            self.log('delivery_outcome_unknown_no_retry', {'prepared': prepared['hash']})
            raise
        self.log('delivery_receipt', {'prepared': prepared['hash'], 'receipt': result['receipt']})
        return result
