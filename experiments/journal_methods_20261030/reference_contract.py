"""Compile trusted fixture declarations into an independent finite policy.

This translation never calls the host. The reference is an acceptance oracle,
not a provider of extra authorization to the executor.
"""
from itertools import product


def eq(field, value):
    return {'op': 'eq', 'field': field, 'value': value}


def policy_for(case, fact):
    pairs = [[p['user_id'], p['agent_id']] for p in fact['allowed_principals']]
    target = ['alice', 'harness']
    sid = fact.get('declared_origin_source_id', case['source']['source_id'])
    shared = [eq('resource_id', fact['fact_id']), eq('source_id', sid),
              eq('policy_version', 'journal-v1'), eq('audience', 'harness'),
              eq('model_recipient', 'harness-model-provider'),
              {'op': 'time_window', 'field': 'now', 'start': 0, 'end': 200}]
    rules = []
    all_pairs = [list(p) for p in product(['alice', 'bob'], ['qoder', 'harness', 'rogue'])]
    for op in ['read', 'handoff', 'restore']:
        valid_pairs = pairs if op == 'read' else [target] if target in pairs else []
        rights = True if op == 'read' else (
            fact.get('export_allowed') is True and fact.get('copy_allowed') is True
            and ['alice', 'qoder'] in pairs) if op == 'handoff' else fact.get('restore_allowed') is True
        allowed = valid_pairs if rights else []
        denied = [p for p in all_pairs if p not in allowed]
        for effect, ps in [('Permit', allowed), ('Deny', denied)]:
            if ps:
                rules.append({'id': op + '-' + effect, 'effect': effect,
                    'target': [eq('operation', op)],
                    'conditions': shared + [{'op': 'principal', 'pairs': ps}],
                    'obligations': ['source_binding'] if effect == 'Permit' else []})
    for field, value in [('source_id', 'wrong-source'), ('policy_version', 'stale-v0'),
                         ('audience', 'other-agent'), ('model_recipient', 'other-provider'),
                         ('operation', 'delete'), ('now', 200)]:
        rules.append({'id': 'deny-' + field, 'effect': 'Deny',
            'target': [eq('resource_id', fact['fact_id'])], 'conditions': [eq(field, value)]})
    return {'schema': 'finite_policy_v1', 'version': 'journal-v1',
            'combining': 'deny_overrides_strict', 'rules': rules, 'required_obligations': []}


def requests_for(case, fact):
    """Finite named mutation domain, not a claim about arbitrary contexts."""
    base = {'user_id': 'alice', 'agent_id': 'harness', 'operation': 'read',
            'resource_id': fact['fact_id'],
            'source_id': fact.get('declared_origin_source_id', case['source']['source_id']),
            'audience': 'harness', 'model_recipient': 'harness-model-provider',
            'policy_version': 'journal-v1', 'now': 100}
    # Enumerate every user-Agent-operation combination; mutate boundaries singly.
    for user, agent, op in product(['alice', 'bob'], ['qoder', 'harness', 'rogue'], ['read', 'handoff', 'restore']):
        yield dict(base, user_id=user, agent_id=agent, operation=op)
    for op in ['read', 'handoff', 'restore']:
        for key, value in [('source_id', 'wrong-source'), ('policy_version', 'stale-v0'),
                           ('audience', 'other-agent'), ('model_recipient', 'other-provider'),
                           ('now', 200), ('operation', 'delete')]:
            yield dict(base, operation=op, **{key: value}) if key != 'operation' else dict(base, operation=value)
        for key in ['user_id', 'agent_id', 'source_id', 'policy_version', 'model_recipient']:
            row = dict(base, operation=op)
            row.pop(key)
            yield row
