"""Opt-in source-context projection using existing complete authorization gates.

Titles are separately granted exact excerpts, never reconstructed from queries.
This component does not infer semantic dependence or relax recovery checks.
The ordinary context baseline is intentionally equivalent to this projection.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import secrets

from memory_migration_study.authority_freshness import SQLiteStateWitness, SignedSnapshotStore
from memory_migration_study.current_authority import (
    CurrentMemoryAuthority, CurrentReadDecision, prepare_current_transfer, restore_current_answer,
)
from memory_migration_study.native_agent_protocol import NativeAgentBroker, NativeProtocolError
from memory_migration_study import privacy

VERSION = 'authorized_exact_context_projection_v1'
POLICY_VERSION = 'context-closure-v1'
_DOMAIN = 'authorized_context_projection_manifest_v1'


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


def _hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _span(start, end, text):
    return type(start) is int and type(end) is int and 0 <= start < end <= len(text)


def _flags(row, names):
    # A known false conjunction is a business denial even if another necessary
    # attribute is absent; unknown is retained only without a decisive false.
    for name in names:
        if row.get(name) is False:
            return 'deny', name + '_denied'
    for name in names:
        if row.get(name) is not True:
            return 'unknown', name + '_unknown'
    return 'allow', None


def ordinary_context_view(safe_prepared, relations):
    """Simple independently written title-join baseline from the same safe input.

    This is a plain positional join, not a policy solver or a new algorithm.
    Relation authorization/binding belongs to ContextSession's signed manifest.
    """
    payload = safe_prepared.get('payload', safe_prepared)
    _require(isinstance(payload, dict) and isinstance(payload.get('query'), str)
             and isinstance(payload.get('memories'), list) and isinstance(relations, list),
             'invalid_safe_payload_or_relations')
    memories = payload['memories']
    joined = []
    for relation in relations:
        f_index, c_index = relation['fact_payload_index'], relation['context_payload_index']
        _require(type(f_index) is int and type(c_index) is int
                 and 0 <= f_index < len(memories) and 0 <= c_index < len(memories)
                 and f_index != c_index, 'invalid_context_relation_index')
        fact, context = memories[f_index], memories[c_index]
        joined.append({'source_id': fact['source_id'], 'text': fact['text'],
                       'source_context': context['text']})
    return {'query': payload['query'], 'memories': joined}


class ContextSession:
    """Trusted finite fixture and exact source spans; no models or credentials.

    Both views retain the same complete prepared record set at recovery. The
    session does not consume a logical request; the native runner supplies a
    separate one-use capability per condition/workspace.
    """
    def __init__(self, case, state_dir, agent_id='qoder'):
        _require(agent_id in {'qoder', 'harness'}, 'unsupported_execution_agent')
        _require(isinstance(case, dict) and isinstance(case.get('sources'), list)
                 and bool(case['sources']) and isinstance(case.get('facts'), list)
                 and bool(case['facts']), 'invalid_context_case')
        self.case = deepcopy(case)
        self._case_hash = _digest(self.case)
        self.agent_id = agent_id
        self.recipient_actor_id = 'sender' if agent_id == 'qoder' else 'recipient'
        self.unknown = False
        self.live_denied_sources = set()
        self.sources = {}
        self.facts = {}
        for source in self.case['sources']:
            sid = source.get('source_id')
            _require(isinstance(sid, str) and sid and sid not in self.sources
                     and isinstance(source.get('text'), str)
                     and _span(source.get('context_start'), source.get('context_end'), source['text']),
                     'invalid_source_context')
            self.sources[sid] = source
        for fact in self.case['facts']:
            fid, sid = fact.get('fact_id'), fact.get('source_id')
            _require(isinstance(fid, str) and fid and fid not in self.facts and sid in self.sources,
                     'invalid_fact_source_binding')
            source = self.sources[sid]
            _require(isinstance(fact.get('text'), str) and _span(fact.get('start'), fact.get('end'), source['text'])
                     and source['text'][fact['start']:fact['end']] == fact['text'], 'fact_source_span_mismatch')
            _require(not (fact['start'] < source['context_end'] and source['context_start'] < fact['end']),
                     'context_overlaps_fact')
            _require(isinstance(fact.get('privacy_spans'), list), 'missing_control_privacy_annotations')
            self.facts[fid] = fact
        categories = {'EMAIL', 'PERSON'}
        for fact in self.facts.values():
            for span in fact['privacy_spans']:
                _require(isinstance(span, dict) and _span(span.get('start'), span.get('end'), fact['text'])
                         and span.get('category') in privacy.CATEGORIES, 'invalid_control_privacy_annotation')
                categories.add(span['category'])
        for source in self.sources.values():
            context = source['text'][source['context_start']:source['context_end']]
            for span in source.get('context_privacy_spans', []):
                _require(isinstance(span, dict) and _span(span.get('start'), span.get('end'), context)
                         and span.get('category') in privacy.CATEGORIES, 'invalid_context_privacy_annotation')
                categories.add(span['category'])
        self.policy = {'version': POLICY_VERSION, 'protected_categories': sorted(categories)}
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=False)
        self.authority = CurrentMemoryAuthority.provision(secrets.token_bytes(32),
            namespace='context-' + self._case_hash[:20] + '-' + secrets.token_hex(4),
            witness=SQLiteStateWitness(state_dir/'current.sqlite', create=True),
            snapshot_store=SignedSnapshotStore(state_dir/'snapshots'), live_authorizer=self._live)
        self.anchor_records, self.fact_records, self.records = {}, {}, {}
        self._requests = {}
        native = []
        for sid, source in self.sources.items():
            start, end = source['context_start'], source['context_end']
            record = self._build(source, source['text'][start:end], start, end,
                source.get('context_privacy_spans', []), source.get('context_read'))
            self.anchor_records[sid] = record
            self.records['context:' + sid] = record
            native.append(self._native_record(record, source.get('context_read'),
                source.get('context_export'), source.get('context_copy')))
        for fid, fact in self.facts.items():
            record = self._build(self.sources[fact['source_id']], fact['text'], fact['start'], fact['end'],
                fact['privacy_spans'], fact.get('recipient_read'))
            self.fact_records[fid] = record
            self.records['fact:' + fid] = record
            native.append(self._native_record(record, fact.get('recipient_read'),
                fact.get('export_allowed'), fact.get('copy_allowed')))
        actors = [{'actor_id': 'sender', 'user_id': 'alice', 'agent_id': 'qoder', 'workspace_id': 'context-source'}]
        if agent_id != 'qoder':
            actors.append({'actor_id': 'recipient', 'user_id': 'alice', 'agent_id': agent_id,
                           'workspace_id': 'context-target'})
        self.broker = NativeAgentBroker({'case_id': 'context-projection', 'actors': actors,
            'records': native, 'actor_mapping': {a['actor_id']: a['actor_id'] for a in actors}},
            key=secrets.token_bytes(32), policy_version=POLICY_VERSION)

    def __repr__(self):
        return '<ContextSession: local grants and maps redacted>'

    def __getstate__(self):
        raise TypeError('context_session_contains_process_local_authority')

    def _live(self, request):
        state = 'unknown' if self.unknown else 'deny' if request.source_id in self.live_denied_sources else 'allow'
        return CurrentReadDecision.for_request(request, state)

    def _build(self, source, text, start, end, findings, recipient_read):
        principals = [{'user_id': 'alice', 'agent_id': 'qoder'}]
        if recipient_read is True:
            principals.append({'user_id': 'alice', 'agent_id': 'harness'})
        return self.authority.build_record({'source_id': source['source_id'], 'text': source['text']},
            {'text': text, 'source_start': start, 'source_end': end, 'findings': deepcopy(findings)}, self.policy,
            owner_id='synthetic-controller', agent_id='context-builder', builder_version=VERSION,
            allowed_principals=principals)

    def _native_record(self, record, recipient_read, export, copy):
        readers = ['sender'] + (['recipient'] if recipient_read is True and self.agent_id != 'qoder' else [])
        return {'record_id': record['record_id'], 'source_id': record['record_id'],
            'text': record['text'], 'source': record['source'],
            'source_start': record['source_start'], 'source_end': record['source_end'],
            'source_readers': readers, 'recipient_readers': readers, 'target_readers': readers,
            'export_allowed': export, 'copy_allowed': copy}

    def _access(self, record, agent_id=None):
        return self.authority.access_decision(record, actor_id='alice', agent_id=agent_id or self.agent_id,
                                              policy_version=POLICY_VERSION)

    def _binding(self, result, request_id):
        mapping = result['prepared']['mapping']
        mapping_material = {'nonce': mapping._nonce,
            'memories': mapping._memories,
            'entries': {token: {'value': e.value, 'categories': list(e.categories), 'sources': list(e.sources)}
                        for token, e in mapping._entries.items()},
            'protected_values': mapping._protected_values, 'sensitive_spans': mapping._sensitive_spans}
        return {'version': VERSION, 'case_sha256': self._case_hash,
            'principal': {'user_id': 'alice', 'agent_id': self.agent_id}, 'request_id': request_id,
            'policy_sha256': _digest(self.policy), 'records_sha256': _digest(result['records']),
            'selected_fact_ids': list(result['selected_fact_ids']), 'excluded_sha256': _digest(result['excluded']),
            'relations_sha256': _digest(result['relations']), 'packet_sha256': _digest(result['packet']),
            'prepared_payload_sha256': _digest(result['prepared']['payload']),
            'prepared_principal_binding_sha256': _digest(result['prepared']['principal_binding']),
            'mapping_nonce_sha256': _hash(result['prepared']['mapping']._nonce),
            # Only a digest enters this public manifest. The source values and
            # restoration entries are never returned or persisted by this hash.
            'mapping_material_sha256': _digest(mapping_material),
            'flat_view_sha256': _digest(result['flat_view']), 'context_view_sha256': _digest(result['context_view']),
            'origins': [{'record_id': r['record_id'], 'source_id': r['source']['source_id'],
                'source_sha256': r['source']['sha256'], 'start': r['source_start'], 'end': r['source_end'],
                'content_sha256': _hash(r['text'])} for r in result['records']]}

    def prepare(self, query, request_id):
        excluded = []
        def block(code, decision='invalid'):
            return {'status': 'needs_review' if decision == 'unknown' else 'blocked',
                'error': code, 'authorization': {'decision': decision}, 'flat_view': None,
                'context_view': None, 'prepared': None, 'records': [], 'selected_fact_ids': [],
                'excluded': deepcopy(excluded), 'relations': [], 'packet': None, 'manifest': None}
        try:
            _require(_digest(self.case) == self._case_hash, 'trusted_case_changed')
            _require(isinstance(query, str) and isinstance(request_id, str) and request_id
                     and request_id not in self._requests, 'invalid_or_reused_request')
            selected = []
            for fid, fact in self.facts.items():
                source = self.sources[fact['source_id']]
                d, reason = _flags(source, ('context_read', 'context_export', 'context_copy'))
                if d == 'allow':
                    d, reason = _flags(fact, ('recipient_read', 'export_allowed', 'copy_allowed'))
                if d != 'allow':
                    excluded.append({'fact_id': fid, 'source_id': fact['source_id'], 'decision': d, 'reason': reason})
                else:
                    selected.append(fid)
            if not selected:
                return block('no_authorized_context_fact_pair',
                    'unknown' if any(x['decision'] == 'unknown' for x in excluded) else 'deny')
            active_sources = [sid for sid in self.sources if any(self.facts[f]['source_id'] == sid for f in selected)]
            records = [self.anchor_records[s] for s in active_sources] + [self.fact_records[f] for f in selected]
            for record in records:
                for agent in {'qoder', self.agent_id}:
                    access = self._access(record, agent)
                    if access['decision'] != 'allow':
                        return block(access.get('code') or 'current_authorization_failed', access['decision'])
            packet = self.broker.export([r['record_id'] for r in records], sender_actor_id='sender',
                recipient_actor_id=self.recipient_actor_id, transfer_id=request_id, ttl_seconds=3600)
            self.broker.validate(packet, sender_actor_id='sender', actor_id=self.recipient_actor_id)
            prepared = prepare_current_transfer(records, query, self.policy, authority=self.authority,
                actor_id='alice', agent_id=self.agent_id, request_id=request_id, mode='generation',
                agent=lambda **_: {'status': 'ok', 'findings': [], 'local_calls': 0, 'elapsed_seconds': 0.0})
            if prepared['status'] != 'ok':
                return block(prepared.get('error') or 'preparation_failed',
                             prepared.get('authorization', {}).get('decision', 'invalid'))
            _require(prepared['payload']['query'] == query, 'query_transformation_requires_new_contract')
            indices = {r['record_id']: i for i, r in enumerate(records)}
            relations = [{'fact_id': fid, 'source_id': self.facts[fid]['source_id'],
                'fact_record_id': self.fact_records[fid]['record_id'],
                'context_record_id': self.anchor_records[self.facts[fid]['source_id']]['record_id'],
                'fact_payload_index': indices[self.fact_records[fid]['record_id']],
                'context_payload_index': indices[self.anchor_records[self.facts[fid]['source_id']]['record_id']]}
                         for fid in selected]
            safe = prepared['payload']['memories']
            flat = {'query': query, 'memories': []}
            contextual = {'query': query, 'memories': []}
            for relation in relations:
                fact = safe[relation['fact_payload_index']]
                anchor = safe[relation['context_payload_index']]
                flat['memories'].append({'source_id': fact['source_id'], 'text': fact['text']})
                contextual['memories'].append({'source_id': fact['source_id'], 'text': fact['text'],
                                              'source_context': anchor['text']})
            _require(contextual == ordinary_context_view(prepared, relations), 'ordinary_context_baseline_mismatch')
            result = {'status': 'ok', 'error': None, 'request_id': request_id, 'flat_view': flat,
                'context_view': contextual, 'prepared': prepared, 'records': records,
                'selected_fact_ids': selected, 'excluded': excluded, 'relations': relations, 'packet': packet}
            binding = self._binding(result, request_id)
            result['manifest'] = {'binding': binding, 'signature': self.authority._sign(_DOMAIN, binding)}
            self._requests[request_id] = _digest(result['manifest'])
            return result
        except NativeProtocolError as exc:
            return block(exc.code, 'deny')
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            return block(str(exc) if isinstance(exc, ValueError) else 'invalid_context_preparation')

    def restore(self, answer, prepared_request, request_id, actor_id='alice', agent_id='qoder'):
        def block(code, decision='invalid'):
            return {'status': 'blocked', 'answer': None, 'error': code,
                    'authorization': {'decision': decision}}
        try:
            _require((actor_id, agent_id) == ('alice', self.agent_id), 'context_principal_mismatch')
            _require(_digest(self.case) == self._case_hash, 'trusted_case_changed')
            _require(isinstance(prepared_request, dict) and prepared_request.get('status') == 'ok', 'context_request_not_ready')
            _require(prepared_request.get('request_id') == request_id and request_id in self._requests,
                     'context_request_mismatch')
            manifest = prepared_request['manifest']
            _require(isinstance(manifest, dict) and set(manifest) == {'binding', 'signature'}
                     and self.authority._valid_signature(_DOMAIN, manifest['binding'], manifest['signature'])
                     and _digest(manifest) == self._requests[request_id], 'context_manifest_invalid')
            _require(manifest['binding'] == self._binding(prepared_request, request_id), 'context_manifest_binding_changed')
            self.broker.validate(prepared_request['packet'], sender_actor_id='sender', actor_id=self.recipient_actor_id)
            for relation in prepared_request['relations']:
                _require(self.facts[relation['fact_id']].get('restore_allowed') is True,
                         'explicit_fact_restore_not_allowed')
            # Keep the complete anchor+fact dependency set. No token-only
            # shortcut, partial map rewrite, OR-source grant or relaxed UNKNOWN.
            return restore_current_answer(answer, prepared_request['prepared'], prepared_request['records'],
                self.policy, authority=self.authority, actor_id=actor_id, agent_id=agent_id, request_id=request_id)
        except NativeProtocolError as exc:
            return block(exc.code, 'deny')
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            return block(str(exc) if isinstance(exc, ValueError) else 'invalid_context_restoration')

    def revoke_context(self, source_id):
        record = self.anchor_records[source_id]
        self.authority.revoke(record['record_id'], event_id='context-revoke-' + source_id)
        self.broker.revoke(record['record_id'])

    def revoke_fact(self, fact_id):
        record = self.fact_records[fact_id]
        self.authority.revoke(record['record_id'], event_id='fact-revoke-' + fact_id)
        self.broker.revoke(record['record_id'])
