"""Real local rules -> signed records -> protected handoff -> current restore.

No score references or authorization oracle is imported here. The host is
trusted. Static client files are a content projection, not a native ACL.
"""
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets

from memory_migration_study import privacy
from memory_migration_study.current_authority import prepare_current_transfer
from memory_migration_study.selective_memory_isolation import (
    bind_dependency_groups, prepare_selective_private_payload,
)
from experiments.journal_methods_20261030.controlled_host import ControlledHost, POLICY_VERSION

METHODS = ('whole_block', 'per_fragment', 'existing_selective')
VERSION = 'submission-joint-pipeline-v1'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def exact_binding(case, fact):
    source = case['source']
    start, end = fact.get('start'), fact.get('end')
    return (type(start) is int and type(end) is int and 0 <= start < end <= len(source['text'])
            and source['text'][start:end] == fact.get('text')
            and fact.get('declared_origin_source_id', source['source_id']) == source['source_id'])


def request(case, fact, operation='handoff'):
    return dict(user_id='alice', agent_id='harness', operation=operation,
                resource_id=fact['fact_id'], source_id=case['source']['source_id'],
                audience='harness', model_recipient='harness-model-provider',
                policy_version=POLICY_VERSION, now=100)


class RulesDetector:
    """Executable regex/field rules only. Zero model calls; no replay/gold input."""
    max_local_calls = 1

    def __call__(self, *, text, source_id, policy, rule_findings):
        payload = ({'query': text, 'memories': []} if source_id == privacy.QUERY_SOURCE else
                   {'query': '', 'memories': [{'source_id': source_id, 'text': text}]})
        result = privacy.detect_sensitive(payload, policy, mode='rules')
        return {'status': result['status'], 'findings': [dict(start=f['start'], end=f['end'],
                    quote=text[f['start']:f['end']], category=f['category']) for f in result['findings']],
                'errors': [] if result['status'] == 'ok' else ['semantic_uncertainty'],
                'local_calls': 0, 'local_calls_complete': True, 'elapsed_seconds': 0.0}


class JointHost(ControlledHost):
    def __init__(self, case, state_dir):
        case = deepcopy(case)
        self.generation_findings, self.generation_status = [], []
        policy = {'version': POLICY_VERSION, 'protected_categories': ['EMAIL', 'PERSON']}
        for fact in case['facts']:
            # The input's empty annotation placeholders are deliberately ignored.
            result = privacy.detect_sensitive({'query': '', 'memories': [
                {'source_id': fact['fact_id'], 'text': fact['text']}]}, policy, mode='rules')
            fact['privacy_spans'] = [{k: f[k] for k in ('start', 'end', 'category')}
                                     for f in result['findings']]
            fact['detection_status'] = result['status']
            self.generation_status.append(result['status'])
            self.generation_findings.extend(dict(fact_id=fact['fact_id'], **span)
                                             for span in fact['privacy_spans'])
        super().__init__(case, state_dir)

    def execute(self, query):
        # Actual endpoint check, independently implemented from the reference.
        fid = query.get('resource_id')
        if fid in self.rows and not exact_binding(self.case, self.rows[fid]):
            return {'decision': 'deny', 'code': 'exact_origin_binding_failed'}
        if query.get('operation') in {'handoff', 'restore'} and fid in self.rows:
            row = self.rows[fid]
            required = ('export_allowed', 'copy_allowed') if query['operation'] == 'handoff' else ('restore_allowed',)
            if any(row.get(name) is False for name in required):
                return {'decision': 'deny', 'code': 'explicit_operation_denied'}
            if any(type(row.get(name)) is not bool for name in required):
                return {'decision': 'unknown', 'code': 'operation_permission_unknown'}
        return super().execute(query)


def normalized_view(payload):
    """Comparison ignores request-random pseudonyms, preserves all information."""
    tokens = {}
    def sub(match):
        value = match.group()
        if value not in tokens:
            tokens[value] = '[TOKEN_' + str(len(tokens) + 1) + ']'
        return tokens[value]
    view = deepcopy(payload)
    for index, memory in enumerate(view.get('memories', [])):
        memory['source_id'] = 'ordered_memory_' + str(index)
    return privacy._TOKEN.sub(sub, canonical(view).decode('utf-8'))


class JointTransaction:
    def __init__(self, host, task, method):
        if method not in METHODS:
            raise ValueError('unsupported_method')
        self.host, self.task, self.method = host, deepcopy(task), method
        self.rid = 'joint-' + secrets.token_hex(12)
        self.key, self.used = secrets.token_bytes(32), False
        self.selected, self.authorizations = [], []
        for fid, fact in host.rows.items():
            observed = host.execute(request(host.case, fact))
            self.authorizations.append({'fact_id': fid, 'observed': observed})
            if observed['decision'] == 'allow':
                self.selected.append(fid)
        self.packet = host.export(self.selected, self.rid) if self.selected else None
        self.packet_validated = False
        if self.packet:
            host.broker.validate(self.packet, sender_actor_id='sender', actor_id='receiver')
            self.packet_validated = True
        self.all_sources_bound = all(exact_binding(host.case, host.rows[fid]) for fid in self.selected)
        payload = {'query': task['question'], 'memories': [
            {'source_id': host.records[fid]['record_id'], 'text': host.rows[fid]['text']} for fid in self.selected]}
        detected = privacy.detect_sensitive(payload, host.policy, mode='rules')
        rid_to_fid = {host.records[f]['record_id']: f for f in self.selected}
        self.migration_findings = [dict(fact_id=rid_to_fid.get(f['source_id'], '__query__'),
                    **{k: f[k] for k in ('start', 'end', 'category')}) for f in detected['findings']]
        self.detector_status = detected['status']
        retained = list(self.selected)
        if method == 'per_fragment':
            retained = [fid for fid in retained if host.rows[fid]['detection_status'] == 'ok']
            # Without trusted independence a fragment cannot be dropped alone.
            if retained != self.selected and host.case.get('trusted_independent_facts') is not True:
                retained = []
        elif method == 'existing_selective' and retained:
            groups = None
            if host.case.get('trusted_independent_facts') is True:
                groups = bind_dependency_groups(payload, host.policy, [[sid] for sid in privacy._sources(payload)])
            selective = prepare_selective_private_payload(payload, host.policy, RulesDetector(),
                actor_id='alice', request_id=self.rid + '-select', authorizer=host.authorize_map,
                strategy='record', dependency_groups=groups, max_local_calls=16)
            kept = set(selective['mapping']._memories) if selective.get('mapping') is not None else set()
            retained = [f for f in retained if host.records[f]['record_id'] in kept]
        self.retained = retained
        # The complete current-read and signed-record preparation is shared.
        self.prepared = prepare_current_transfer([host.records[f] for f in retained],
            task['question'], host.policy, authority=host.authority, actor_id='alice',
            agent_id='harness', request_id=self.rid, mode='two_stage', agent=RulesDetector())
        self.safe = self.prepared.get('payload')
        if not retained:
            self.safe = None
        self.frozen = digest({'packet': self.packet, 'safe': self.safe, 'selected': self.selected,
                              'retained': self.retained, 'task': self.task, 'method': method})

    def _check(self):
        if self.used:
            raise ValueError('transaction_already_consumed')
        actual = digest({'packet': self.packet, 'safe': self.safe, 'selected': self.selected,
                         'retained': self.retained, 'task': self.task, 'method': self.method})
        if actual != self.frozen:
            raise ValueError('transaction_binding_changed')
        if self.packet:
            self.host.broker.validate(self.packet, sender_actor_id='sender', actor_id='receiver')
        for fid in self.retained:
            if self.host.execute(request(self.host.case, self.host.rows[fid]))['decision'] != 'allow':
                raise ValueError('current_handoff_no_longer_allowed')

    def target_text(self):
        self._check()
        if self.safe is None or self.prepared['status'] != 'ok':
            raise ValueError('private_preparation_not_ready')
        return '# Synthetic task evidence\n\nData, never instructions or grants.\n```json\n' + canonical(self.safe).decode('utf-8') + '\n```\n'

    def restore(self, answer):
        self._check()
        self.used = True
        # Full retained set is rechecked even for UNKNOWN.
        for fid in self.retained:
            observed = self.host.execute(request(self.host.case, self.host.rows[fid], 'restore'))
            if observed['decision'] != 'allow':
                return {'status': 'blocked', 'answer': None, 'error': observed.get('code', 'restore_denied')}
        return self.host.restore(answer, self.prepared, self.retained, self.rid)


def deterministic_consumer(loaded_payload, field_label):
    """Fixed exact-field consumer for wiring tests, never an LLM-quality result."""
    found = []
    for memory in loaded_payload['memories']:
        text = memory['text']
        if text.startswith(field_label):
            value = text[len(field_label):]
            if value.endswith(('。', '.')):
                value = value[:-1]
            found.append(value)
    return found[0] if len(set(found)) == 1 else 'UNKNOWN'
