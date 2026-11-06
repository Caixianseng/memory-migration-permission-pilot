"""Separate deterministic guard probes, excluded from project inference."""
import copy
import json
import sqlite3
from pathlib import Path
import runner

def main():
    data=json.loads((runner.OUT/'dataset_v3.json').read_text())
    def case(s):return copy.deepcopy(next(c for c in data['cases'] if c['view']['project_id']=='P00' and c['view']['scenario']==s and c['view']['regime']=='universal_batch'))
    probes=[]
    for event in ('revoke','revoke_regrant','before_read_revoke'):
        c=case('shared_dependency')
        result=runner.run_method(c,'weighted_greedy',10000,test_only_commit_event=event)
        sid=c['view']['requirements'][0]['sources'][0]
        affected={m['memory_id'] for m in c['view']['requirements'] if sid in m['sources']}
        assert not affected&set(result['delivered'])
        if event=='before_read_revoke':
            assert not any(sid in q['returned_sources'] for q in result['query_log'])
        probes.append({'probe':event,'passed':True,'affected':sorted(affected),'result':result})
    c=case('single_missing');node=c['view']['requirements'][0]['memory_id']
    del c['view']['node_receipts'][node]
    result=runner.run_method(c,'weighted_greedy',10000)
    assert node not in result['delivered'] and node in result['unverifiable_memory_ids']
    probes.append({'probe':'missing_intermediate_node_receipt','passed':True,'result':result})
    c=case('single_missing');row=c['view']['observed'][0];sid=row['source_id'];row['payload']+='tampered'
    d=runner.diagnose(c['view']);assert sid in d['conflict']
    result=runner.run_method(c,'fail_closed',10000)
    assert not {m['memory_id'] for m in c['view']['requirements'] if sid in m['sources']}&set(result['delivered'])
    probes.append({'probe':'tampered_payload_with_unchanged_digest','passed':True,'result':result})
    c=case('single_missing');sid=c['truth']['actually_missing'][0]
    db=sqlite3.connect(':memory:');db.execute('CREATE TABLE current_sources(id,text)')
    original=c['receipt_database_rows'][sid]
    db.execute('INSERT INTO current_sources VALUES(?,?)',(sid,original['payload']))
    reread=db.execute('SELECT text FROM current_sources WHERE id=?',(sid,)).fetchone()[0];db.close()
    current=copy.deepcopy(original);current['payload']=reread;current['receipt_kind']='current_source_content'
    c['view']['observed'].append(current)
    c['view']['operations']=[o for o in c['view']['operations'] if o['kind']=='current_source_content']
    result=runner.run_method(c,'weighted_greedy',10000)
    assert not {m['memory_id'] for m in c['view']['requirements'] if sid in m['sources']}&set(result['delivered'])
    assert result['tool_requests']==0
    probes.append({'probe':'actual_current_reread_cannot_replace_historical_receipt','passed':True,
                   'current_source_sql_reads':1,'result':result})
    for scenario in ('revoked','opaque'):
        c=case(scenario);row=runner.run_method(c,'fail_closed',10000)
        row['delivered']=[m['memory_id'] for m in c['view']['requirements']]
        scored=runner.score(row,c['truth'],c['view']['requirements'])
        assert scored['false_allows']>0
        assert (scored['unauthorized_releases']>0)==(scenario=='revoked')
        probes.append({'probe':'scorer_negative_control_'+scenario,'passed':True,
                       'false_allows':scored['false_allows'],'unauthorized_releases':scored['unauthorized_releases'],
                       'note':'Forced bad decision tests the scorer; not an actual experimental method or committed release.'})
    c=case('conflict');result=runner.run_method(c,'weighted_greedy',10000)
    assert result['resolved_conflicts']==c['truth']['conflicts'] and len(result['delivered'])==6
    probes.append({'probe':'canonical_receipt_resolves_conflicting_cache','passed':True,'result':result})
    runner.write_new(runner.OUT/'raw_boundary_probes.json',{'schema':'stage2-boundary-probes-v1','probes':probes,
                       'scope':'Nine hand-crafted guard/scorer probes; not additional independent projects.',
                       'paid_calls':0})
    print('boundary probes passed',len(probes))

if __name__=='__main__':main()
