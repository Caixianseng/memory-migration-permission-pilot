"""Bounded adapter around existing enforcement, using trusted fixture grants.

No evaluation reference or model is reachable from this module. Added recipient
and restore constraints are explicit opt-in host contracts, not native client ACLs.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import secrets

from memory_migration_study.authority_freshness import SQLiteStateWitness, SignedSnapshotStore
from memory_migration_study.current_authority import CurrentMemoryAuthority, CurrentReadDecision, restore_current_answer
from memory_migration_study.native_agent_protocol import NativeAgentBroker, NativeProtocolError
from memory_migration_study import privacy

VERSION = 'journal-bounded-host-v1'
POLICY_VERSION = 'journal-v1'
PRINCIPALS = {'sender': ('alice', 'qoder'), 'receiver': ('alice', 'harness'),
              'rogue': ('alice', 'rogue'), 'other': ('bob', 'harness')}
MODEL_RECIPIENT = 'harness-model-provider'


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


class ControlledHost:
    def __init__(self, case, state_dir):
        self.case = deepcopy(case)
        self.rows = {f['fact_id']: f for f in case['facts']}
        self.revoked = set()
        self.unknown = False
        self.clock = [100]
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=False)
        self.policy = {'version': POLICY_VERSION, 'protected_categories': ['EMAIL', 'PERSON']}
        self.authority = CurrentMemoryAuthority.provision(secrets.token_bytes(32),
            namespace='journal-' + case['case_id'],
            witness=SQLiteStateWitness(state_dir/'witness.sqlite', create=True),
            snapshot_store=SignedSnapshotStore(state_dir/'snapshots'), live_authorizer=self._live)
        self.records = {}
        native = []
        for row in case['facts']:
            source = dict(case['source'], source_id=row.get('declared_origin_source_id', case['source']['source_id']))
            record = self.authority.build_record(source,
                {'text': row['text'], 'source_start': row['start'], 'source_end': row['end'],
                 'findings': deepcopy(row['privacy_spans'])}, self.policy,
                owner_id='synthetic-controller', agent_id='fixture-builder',
                builder_version='declared-control-v1', allowed_principals=row['allowed_principals'])
            self.records[row['fact_id']] = record
            readers = [name for name, pair in PRINCIPALS.items()
                       if {'user_id': pair[0], 'agent_id': pair[1]} in row['allowed_principals']]
            native.append({'record_id': record['record_id'], 'source_id': record['record_id'],
                'text': record['text'], 'source': record['source'],
                'source_start': record['source_start'], 'source_end': record['source_end'],
                'source_readers': readers, 'recipient_readers': readers, 'target_readers': readers,
                'export_allowed': row.get('export_allowed'), 'copy_allowed': row.get('copy_allowed')})
        self.broker = NativeAgentBroker({'case_id': case['case_id'],
            'actors': [{'actor_id': name, 'user_id': p[0], 'agent_id': p[1],
                        'workspace_id': 'source' if name == 'sender' else 'target'}
                       for name, p in PRINCIPALS.items()], 'records': native,
            'actor_mapping': {name: name for name in PRINCIPALS}},
            key=secrets.token_bytes(32), policy_version=POLICY_VERSION, clock=lambda: self.clock[0])

    def _live(self, request):
        decision = 'unknown' if self.unknown else 'allow'
        return CurrentReadDecision.for_request(request, decision)

    def read(self, fact_id, user='alice', agent='harness', version=POLICY_VERSION):
        return self.authority.access_decision(self.records[fact_id], actor_id=user,
            agent_id=agent, policy_version=version)

    def _context(self, request):
        required = ('user_id', 'agent_id', 'operation', 'resource_id', 'source_id',
                    'audience', 'model_recipient', 'policy_version', 'now')
        if any(key not in request for key in required):
            return {'decision': 'unknown', 'code': 'required_attribute_missing'}
        if any(not isinstance(request[k], str) or not request[k] for k in required if k != 'now'):
            return {'decision': 'unknown', 'code': 'invalid_attribute'}
        if type(request['now']) is not int:
            return {'decision': 'unknown', 'code': 'invalid_time'}
        row = self.rows.get(request['resource_id'])
        source_id = row.get('declared_origin_source_id', self.case['source']['source_id']) if row else None
        if (row is None or request['source_id'] != source_id
                or request['policy_version'] != POLICY_VERSION or not 0 <= request['now'] < 200
                or request['audience'] != 'harness' or request['model_recipient'] != MODEL_RECIPIENT):
            return {'decision': 'deny', 'code': 'bound_context_mismatch'}
        if request['operation'] not in {'read', 'handoff', 'restore'}:
            return {'decision': 'deny', 'code': 'unsupported_operation'}
        return None

    def execute(self, request):
        """Actual calls, never invokes the independent reference evaluator."""
        error = self._context(request)
        if error:
            return error
        fid, op = request['resource_id'], request['operation']
        user, agent = request['user_id'], request['agent_id']
        if op in {'handoff', 'restore'} and (user, agent) != PRINCIPALS['receiver']:
            return {'decision': 'deny', 'code': 'recipient_scope_mismatch'}
        observed = self.read(fid, user, agent, request['policy_version'])
        if observed['decision'] != 'allow':
            return observed
        if op == 'read':
            return observed
        if op == 'restore':
            if self.rows[fid].get('restore_allowed') is not True:
                return {'decision': 'deny', 'code': 'explicit_restore_not_allowed'}
            # The real restore endpoint is exercised separately with a live map.
            return {'decision': 'allow', 'code': None, 'scope': 'restore_gate_precheck'}
        try:
            packet = self.export([fid], 'matrix-' + fid)
            response = self.broker.validate(packet, sender_actor_id='sender', actor_id='receiver')
            return {'decision': 'allow', 'code': None, 'response': response}
        except NativeProtocolError as exc:
            return {'decision': 'deny', 'code': exc.code}

    def export(self, fids, transfer_id):
        return self.broker.export([self.records[f]['record_id'] for f in fids],
            sender_actor_id='sender', recipient_actor_id='receiver', transfer_id=transfer_id,
            ttl_seconds=100, issued_at=100)

    def authorize_map(self, record_id, actor_id, version):
        fid = next((fid for fid, record in self.records.items() if record['record_id'] == record_id), None)
        return (fid is not None and actor_id == 'alice' and
                self.read(fid, actor_id, 'harness', version)['decision'] == 'allow')

    def revoke(self, fid):
        self.revoked.add(fid)
        self.authority.revoke(self.records[fid]['record_id'], event_id='revoke-' + fid)
        self.broker.revoke(self.records[fid]['record_id'])

    def restore(self, answer, prepared, fids, request_id, *, enforce_restore=True):
        # All selected memory objects are current; no partial outdated map reuse.
        if enforce_restore and any(self.rows[f].get('restore_allowed') is not True for f in fids):
            return {'status': 'blocked', 'answer': None, 'error': 'explicit_restore_not_allowed'}
        for fid in fids:
            if self.read(fid)['decision'] != 'allow':
                return {'status': 'blocked', 'answer': None, 'error': 'current_read_not_allowed'}
        return restore_current_answer(answer, prepared, [self.records[f] for f in fids], self.policy,
            authority=self.authority, actor_id='alice', agent_id='harness', request_id=request_id)


class DeclaredReplay:
    """Synthetic detector control, not a real detector or scoring answer input."""
    max_local_calls = 1

    def __init__(self, host):
        self.rows = {host.records[fid]['record_id']: row for fid, row in host.rows.items()}
        self.invocations = 0

    def __call__(self, *, text, source_id, policy, rule_findings):
        self.invocations += 1
        row = self.rows.get(source_id)
        if row and text != row['text']:
            raise ValueError('replay_text_binding_mismatch')
        review = bool(row and row.get('detection_status') == 'needs_review')
        findings = [] if review or not row else [dict(span,
            quote=text[span['start']:span['end']]) for span in row['privacy_spans']]
        return {'status': 'needs_review' if review else 'ok', 'findings': findings,
            'errors': ['semantic_uncertainty'] if review else [],
            'local_calls': 0, 'local_calls_complete': True, 'elapsed_seconds': 0.0}
