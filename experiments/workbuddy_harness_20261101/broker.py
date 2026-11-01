"""Small WorkBuddy/Harness trusted-host replay; no model or account access.

Caller must authenticate complete input traces before passing output text.
This function does not authenticate a client, infer semantic dependencies,
prove event timing during generation, or implement native online revocation.
"""
from copy import deepcopy
import hashlib
import secrets

from memory_migration_study.native_agent_protocol import (
    NativeAgentBroker, NativeProtocolError, render_agents_md,
)
from memory_migration_study.policy import decision

SOURCE_IDS = ('S01', 'S02', 'S03', 'S04')
SENDER, RECEIVER = 'workbuddy-owner', 'harness-owner'
DEPENDENCIES = {'M': SOURCE_IDS, 'R': SOURCE_IDS[1:]}


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _record(rid, text, export=True):
    return {'record_id':rid, 'source_id':rid, 'text':text,
        'source':{'source_id':'origin-'+rid, 'text':text},
        'source_start':0, 'source_end':len(text),
        'source_readers':[SENDER, RECEIVER], 'recipient_readers':[SENDER, RECEIVER],
        'target_readers':[SENDER, RECEIVER], 'export_allowed':export, 'copy_allowed':True}


def _state(records):
    return {rid:{'text_sha256':hashlib.sha256(r['text'].encode()).hexdigest(),
        'source_read':decision(r,SENDER,source_only=True),
        'recipient_read':decision(r,RECEIVER), 'copy_allowed':r['copy_allowed'],
        'export_allowed':r['export_allowed']} for rid,r in records.items()}


def build_handoff(sources, mixed_text, rebuilt_text):
    """Replay registered complete-input AND grants using caller-authenticated text.

    Both outputs already exist on entry. The local order is an authorization
    replay and does not prove that R was generated after a live revocation.
    """
    _require(type(sources) is list and len(sources)==4, 'four_original_sources_required')
    _require(all(type(s) is dict and set(s)=={'source_id','text'} for s in sources), 'source_fields_invalid')
    _require(tuple(s['source_id'] for s in sources)==SOURCE_IDS, 'ordered_source_inventory_invalid')
    texts=[s['text'] for s in sources]+[mixed_text,rebuilt_text]
    _require(all(type(t) is str and t.strip() and '\0' not in t and len(t)<=12000 for t in texts), 'invalid_record_text')
    records={s['source_id']:_record(s['source_id'],s['text']) for s in sources}
    records.update(M=_record('M',mixed_text), R=_record('R',rebuilt_text))
    actors=[{'actor_id':SENDER,'user_id':'alice','agent_id':'workbuddy','workspace_id':'source'},
            {'actor_id':RECEIVER,'user_id':'alice','agent_id':'deepseek-harness','workspace_id':'target'}]
    broker=NativeAgentBroker({'case_id':'workbuddy-harness-local-replay','actors':actors,
        'records':list(records.values())},key=secrets.token_bytes(32))
    def export(ids,transfer):
        return broker.export(ids,sender_actor_id=SENDER,recipient_actor_id=RECEIVER,transfer_id=transfer)
    def validate(packet):
        return broker.validate(packet,sender_actor_id=SENDER,actor_id=RECEIVER)
    before=_state(records)
    initial_sources=export(list(SOURCE_IDS),'wb-sources-before')
    initial_mixed=export(['M'],'wb-mixed-before')
    initial_validation=validate(initial_mixed)
    records['S01']={**records['S01'],'export_allowed':False}
    broker.replace_record(records['S01'])
    for artifact,deps in DEPENDENCIES.items():
        permitted=all(records[sid]['export_allowed'] is True for sid in deps)
        if records[artifact]['export_allowed'] is not permitted:
            records[artifact]={**records[artifact],'export_allowed':permitted}
            broker.replace_record(records[artifact])
    after=_state(records)
    for rid in records:
        _require(all(before[rid][k]==after[rid][k] for k in ('text_sha256','source_read','recipient_read','copy_allowed')),
                 'non_export_state_changed')
    errors={}
    for label,action in [('old_mixed_packet_validate',lambda:validate(initial_mixed)),
                         ('new_mixed_export',lambda:export(['M'],'wb-mixed-after'))]:
        try:
            action()
        except NativeProtocolError as exc:
            errors[label]=exc.code
        else:
            raise ValueError('revoked_mixed_unexpectedly_allowed')
    legal_sources=export(list(SOURCE_IDS[1:]),'wb-legal-sources-after')
    packet=export(['R'],'wb-rebuilt-after'); validation=validate(packet)
    memory=render_agents_md(packet)
    _require(packet['items'][0]['text']==rebuilt_text, 'rebuilt_text_changed')
    return {'schema':'workbuddy-harness-trusted-replay-v1', 'scope':'local_sequential_trusted_host_replay',
        'sender':deepcopy(packet['sender']), 'audience':deepcopy(packet['audience']),
        'state_before':before, 'state_after':after, 'revocation_errors':errors,
        'initial_source_packet':initial_sources, 'initial_mixed_packet':initial_mixed,
        'initial_mixed_validation':initial_validation, 'legal_source_packet':legal_sources,
        'packet':packet, 'validation':validation, 'memory':memory,
        'memory_sha256':hashlib.sha256(memory.encode()).hexdigest(),
        'dependency_semantics':{'M':list(SOURCE_IDS),'R':list(SOURCE_IDS[1:]),
            'rule':'conjunction_of_complete_actual_generation_input_export_grants'},
        'source_trace_authenticated_by_caller':True,
        'trace_authentication_scope':'caller precondition, not verified by build_handoff',
        'native_client_acl_or_online_revocation_claim':False, 'generation_event_timing_proven':False}
