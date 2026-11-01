"""Metadata-only offline checks. Does not authenticate omitted raw evidence."""
import argparse, copy, hashlib, json
from decimal import Decimal
from pathlib import Path

ROOT=Path(__file__).resolve().parent
def canonical(v):
    return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def validate_files(files,seal):
    assert set(files)==set(seal['files']), 'unexpected or missing file'
    for name,b in files.items():
        assert sha(b)==seal['files'][name]['sha256'] and len(b)==seal['files'][name]['bytes'],name
def run(v):
    rows=v['events_public_projection'];previous='0'*64;last=-1
    for i,e in enumerate(rows,1):
        assert e['seq']==i and e['previous_projection_sha256']==previous
        body={k:x for k,x in e.items() if k!='projection_sha256'}
        assert sha(canonical(body))==e['projection_sha256']
        assert e['monotonic_ns']>=last;last=e['monotonic_ns'];previous=e['projection_sha256']
    key=['sources_registered','M_sealed','S01_export_revoked','old_M_denied','R_sealed','delivery_committed','target_callback_returned']
    assert [e['kind'] for e in rows if e['kind'] in key]==key
    before,after=v['policy_before'],v['policy_after'];assert set(before)==set(after)
    for rid in before:
        for field in before[rid]:
            if field not in ('export_allowed','record_version'):assert before[rid][field]==after[rid][field]
        assert after[rid]['export_allowed']==(False if rid in ('S01','M') else before[rid]['export_allowed'])
    assert v['pre_revocation_validation_status']=='ok' and v['old_memory_was_unexpired'] is True
    assert v['old_memory_remaining_seconds']>0
    assert v['old_memory_denials']=={'old_packet':'export_not_allowed','new_export':'export_not_allowed'}
    m,r=v['source_generations']['M'],v['source_generations']['R']
    assert m['source_ids']==['S01','S02','S03','S04'] and r['source_ids']==['S02','S03','S04']
    assert m['session_pseudonym']!=r['session_pseudonym']
    assert all(s['model_id']=='hy3' and s['logical_submissions']==1 and s['runtime_source']=='desktop_queue' for s in (m,r))
    t=v['target'];g=t['guard'];req=g['requests'][0];u=t['usage']
    assert t['status']=='ok' and t['native_memory_loaded'] is True
    assert g['dry_run'] is False and g['reject_code'] is None
    assert g['agent_attempt_count']==g['stream_attempt_count']==g['allowed_stream_count']==len(g['requests'])==1
    assert 0<req['bytes']<=24000 and req['maxTokens']==256 and req['memory_exact_present'] is True
    assert g['shape']['tool_count']==0 and g['shape']['reasoning_off'] is True
    assert u['inputTokens']+u['outputTokens']+u['cacheReadTokens']+u['cacheWriteTokens']==u['totalTokens']
    assert t['usage_integrity']['complete'] is True
    b=v['budget'];estimate=(Decimal(u['inputTokens']+u['cacheReadTokens'])*4+Decimal(u['outputTokens'])*8)/1000000
    assert estimate==Decimal(b['estimate_cny'])
    assert b['historical_registered_slots']==177 and Decimal(b['historical_gross_reservation_cny'])==Decimal('22.624576')+Decimal('0.198144')
    assert b['new_slot_refunded'] is False and b['actual_cost_cny'] is None
    legal=v['recorded_AI_legal_summary'];control=v['recorded_AI_control_summary']
    assert sum(legal[k] for k in legal if k!='denominator')==legal['denominator']
    assert control['exact_UNKNOWN']<=control['denominator']
    assert v['human_gold'] is False and v['full_sdk_body_saved'] is False and v['method_advantage'] is None
    assert v['raw_source_question_answer_memory_distributed'] is False
    return {'schema':'public-metadata-reproduction-v1','mechanical_status':'pass','public_events':len(rows),
        'independent_stories':v['independent_stories'],'recorded_AI_legal':legal,'recorded_AI_control':control,
        'request_bytes':req['bytes'],'memory_bytes':req['memory_bytes'],'usage':u,'estimate_cny':str(estimate),
        'actual_cost_cny':None,'complete_payload_exclusion':v['complete_payload_exclusion'],
        'semantic_truth_recomputed':False,'omitted_original_files_authenticated':False,'human_gold':False,'method_advantage':None}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--self-test',action='store_true');args=p.parse_args()
    seal=json.loads((ROOT/'seal.json').read_bytes())
    files={x.name:x.read_bytes() for x in ROOT.iterdir() if x.is_file() and x.name!='seal.json'}
    validate_files(files,seal);result=run(json.loads(files['metadata.json']))
    if args.self_test:
        altered=dict(files);altered['metadata.json']=altered['metadata.json']+b' '
        try:validate_files(altered,seal)
        except AssertionError:pass
        else:raise AssertionError('tamper accepted')
        altered=dict(files);altered['unexpected.txt']=b'test'
        try:validate_files(altered,seal)
        except AssertionError:pass
        else:raise AssertionError('unexpected file accepted')
        result['tamper_self_test']='pass'
    print(json.dumps(result,ensure_ascii=False,indent=2))
