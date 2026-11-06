"""Bounded source-trust qualification. No LLM, network or new algorithm.

The imported sender/receiver gate is unchanged. Reference envelopes are small
implementations of conventional complete mediation and context-sensitive taint.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import time

ROOT=Path(__file__).resolve().parents[4]
OUT=ROOT/'research_paper_v1/stage3_research_pivot/evidence'
STORE=ROOT/'experiments/persistent_exchange_v1/store.py'
CASES=[
 {'id':'A01_public','reads':[('public','current','file',True)],'declared':['public']},
 {'id':'A02_honest_restricted','reads':[('private','current','sqlite',True)],'declared':['private']},
 {'id':'A03_cross_tool_omission','reads':[('public','current','file',True),('private','current','sqlite',True)],'declared':['public']},
 {'id':'A04_fabricated_support','reads':[('private','current','sqlite',True)],'declared':['public']},
 {'id':'A05_unregistered_tool','reads':[('public','current','file',True),('external-private','current','local_tool',True)],'declared':['public']},
 {'id':'A06_foreign_receipt','reads':[('public','old-attempt','file',True),('private','current','sqlite',True)],'declared':['public'], 'fake_receipt':True},
 {'id':'A07_sibling_task','reads':[('public','current','file',True),('private','sibling','sqlite',True)],'declared':['public']},
 {'id':'A08_opaque_private','reads':[('public','current','file',True),('private','current','sqlite',False)],'declared':['public']},
 {'id':'A09_opaque_legal','reads':[('public','current','file',True),('public2','current','file',False)],'declared':['public']},
]
POLICY={'public':True,'public2':True,'private':False}
METHODS=('existing_declared_store','process_wide_trusted_envelope','attempt_scoped_trusted_envelope')


def save_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False,indent=2)


def prepare_view(case,folder):
    bodies={'public':'Public task data','public2':'Other public input','private':'Restricted fixture input',
            'external-private':'Unregistered local tool result'}
    for sid in ('public','public2'):(folder/(sid+'.txt')).write_text(bodies[sid],encoding='utf-8')
    db=sqlite3.connect(folder/'source.sqlite')
    db.execute('CREATE TABLE data(source_id TEXT PRIMARY KEY, body TEXT)')
    db.execute('INSERT INTO data VALUES(?,?)',('private',bodies['private']));db.commit()
    truth=[];observed=[]
    for sid,attempt,channel,visible in case['reads']:
        if channel=='file':body=(folder/(sid+'.txt')).read_text(encoding='utf-8')
        elif channel=='sqlite':body=db.execute('SELECT body FROM data WHERE source_id=?',(sid,)).fetchone()[0]
        else:body=bodies[sid] # controlled local tool callback; not a real external API
        event={'source_id':sid,'attempt_id':attempt,'channel':channel,
               'source_version':1,'payload_sha256':hashlib.sha256(body.encode()).hexdigest(),
               'issuer':'fixture-trusted-host'}
        truth.append(event)
        if visible:observed.append(event)
    db.close()
    view={'attempt_id':'current','declared':case['declared'],'host_events':observed,
          'coverage_complete':all(r[3] for r in case['reads']), 'share_permissions':POLICY,
          'content':'Controlled derived artifact',
          'agent_provided_receipt':{'source_id':'public','attempt_id':'old-attempt','issuer':'model-claim'} if case.get('fake_receipt') else None}
    gold_sources={e['source_id'] for e in truth if e['attempt_id']=='current'}
    gold=all(POLICY.get(s,False) for s in gold_sources)
    return view,truth,gold,bodies


def reference(view,method):
    if not view['coverage_complete']:
        return {'allowed':False,'status':'UNVERIFIABLE','sources':[], 'verification_operations':len(view['host_events'])}
    events=view['host_events']
    if method=='attempt_scoped_trusted_envelope':events=[e for e in events if e['attempt_id']==view['attempt_id']]
    sources=sorted({e['source_id'] for e in events})
    allowed=bool(sources) and all(view['share_permissions'].get(s,False) for s in sources)
    return {'allowed':allowed,'status':'VERIFIED' if allowed else 'RESTRICTED_SOURCE',
            'sources':sources,'verification_operations':len(view['host_events'])}


def existing(view,bodies,folder,module):
    sender=module.AgentStore(folder/'sender.sqlite','source-agent')
    receiver=module.AgentStore(folder/'receiver.sqlite','receiver-agent')
    policy=module.TrustedPolicy(folder/'policy.sqlite')
    try:
        refs=[sender.add_original(s,bodies[s]) for s in POLICY]
        policy.register_sources(refs)
        policy.set_permissions('receiver-agent',[s for s,a in POLICY.items() if a])
        sender.add_memory('derived',view['content'],source_ids=view['declared'],
                          provenance={'agent_receipt':view['agent_provided_receipt']})
        try:
            packet=module.export_package(sender,policy,'receiver-agent',['derived'],batch_id='controlled-transfer')
            receipt=module.import_package(receiver,policy,packet)
            assert receipt['status']=='imported'
            result={'allowed':True,'status':'IMPORTED','sources':[r['source_id'] for r in packet['sources']]}
        except module.StoreError as exc:
            result={'allowed':False,'status':str(exc),'sources':view['declared']}
        result['verification_operations']=None # old implementation does not expose a comparable counter
        return result
    finally:sender.close();receiver.close();policy.close()


def main():
    cfg={'date':'2026-11-05','cases':CASES,'methods':METHODS,
         'policy':'Conservative input-use sharing rule: all inputs provided to current attempt must be share-authorized.',
         'primary':'false allow under independent actual-input trace; false rejects counted separately',
         'artifact':'fixed controlled artifact; no claim about semantic necessary causes or LLM utility',
         'unit':'9 designed scenario probes, not independent randomly sampled projects',
         'no_model_calls':True,'no_real_external_api':True,
         'strong_baseline':'trusted complete mediation + attempt-scoped conservative input envelope',
         'stop_rule':'No algorithm qualification if mature strong baseline safely handles observable cases and abstains at unobservable boundary.'}
    save_new(OUT/'A_config.json',cfg)
    save_new(OUT/'A_code_freeze.json',{'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                      'existing_store_sha256':hashlib.sha256(STORE.read_bytes()).hexdigest(),
                                      'config_sha256':hashlib.sha256((OUT/'A_config.json').read_bytes()).hexdigest()})
    spec=importlib.util.spec_from_file_location('stage3_original_store',STORE)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    results=[];truths=[];views=[]
    with tempfile.TemporaryDirectory(prefix='stage3_A_') as temporary:
        for case in CASES:
            folder=Path(temporary)/case['id'];folder.mkdir()
            view,trace,gold,bodies=prepare_view(case,folder)
            truths.append({'case_id':case['id'],'actual_trace':trace,'gold_allowed':gold})
            views.append({'case_id':case['id'],'view':view})
            for method in METHODS:
                start=time.perf_counter()
                result=existing(view,bodies,folder,module) if method=='existing_declared_store' else reference(view,method)
                results.append({'case_id':case['id'],'method':method,**result,'elapsed_seconds':time.perf_counter()-start,
                                'gold_allowed':gold,'false_allow':int(result['allowed'] and not gold),
                                'false_reject':int(not result['allowed'] and gold),'new_model_calls':0})
    # The two hidden histories produce the same observer projection but different truth.
    assert views[-1]['view']==views[-2]['view']
    assert truths[-1]['gold_allowed']!=truths[-2]['gold_allowed']
    save_new(OUT/'A_views.json',views);save_new(OUT/'A_ground_truth.json',truths)
    save_new(OUT/'A_raw_results.json',results)
    summary={method:{'scenarios':9,'false_allow':sum(r['false_allow'] for r in results if r['method']==method),
                     'false_reject':sum(r['false_reject'] for r in results if r['method']==method),
                     'allowed':sum(r['allowed'] for r in results if r['method']==method),
                     'unverifiable':sum(r['status']=='UNVERIFIABLE' for r in results if r['method']==method)} for method in METHODS}
    save_new(OUT/'A_summary.json',{'methods':summary,'same_observation_opposite_truth':['A08_opaque_private','A09_opaque_legal'],
                                'existing_store_unchanged':hashlib.sha256(STORE.read_bytes()).hexdigest()==json.loads((OUT/'A_code_freeze.json').read_text())['existing_store_sha256'],
                                'paid_model_calls':0,'note':'A09 false rejection is unavoidable by these observations under fail-closed; it is not a missing-record localization failure.'})
    print(json.dumps(summary))


if __name__=='__main__':main()
