"""Independent saved-evidence native timing audit; no backend/model execution.

Rechecks original writes, native raw HTTP bytes, clocks, vector pairing and
scope budgets using the standard library only. Both producer arms used trace.
Original untraced/multi-snapshot/deletion failure remains open.
"""
from __future__ import annotations
import argparse
import json,pathlib,hashlib,math,collections


def verify(run, original_run, output):
    root=pathlib.Path(__file__).resolve().parents[1]
    run=pathlib.Path(run).resolve()
    original_run=pathlib.Path(original_run).resolve()
    checks=[]
    def check(name,value):
     checks.append({'check':name,'passed':bool(value)})
    def load(path):
     def unique(pairs):
      o={}
      for k,v in pairs:
       if k in o:raise ValueError('duplicate_json_key')
       o[k]=v
      return o
     return json.loads(path.read_bytes(),object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))
    def sha(data):return hashlib.sha256(data).hexdigest()
    def file_sha(path):
     digest=hashlib.sha256()
     with path.open('rb') as stream:
      for part in iter(lambda:stream.read(1024*1024),b''):digest.update(part)
     return digest.hexdigest()
    def equal(a,b):return json.dumps(a,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)==json.dumps(b,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
    plan=load(run/'plan.json');report=load(run/'report.json');rows=load(run/'rows.json')
    original=load(original_run/'report.json')
    original_plan=load(original_run/'plan.json')
    fixture=[]
    for x in original['target_rpc_receipts']:
     if x['command']=='add':
      d=x['input'];label=('valid-assistant' if d['path'].endswith(original['sidecar']['valid_control']['record_id']) else 'main-'+d['actor'])
      fixture.append(dict(logical_id=label,**d))
    fixture += [dict(logical_id='resident-'+x['actor'],actor=x['actor'],text=x['content'],path=x['path']) for x in original['resident_controls']]
    check('fixture_exact_original_six_writes_and_order',equal(fixture,plan['fixture']))
    expected_schedule=[{'pair':i,'actor':('assistant','owner','outsider')[i%3],'arms':['immediate','delay500'] if i%2==0 else ['delay500','immediate']} for i in range(6)]
    check('balanced_preregistered_schedule',equal(plan['schedule'],expected_schedule))
    check('original_failure_assets_unchanged_contract',equal(plan['asset_sha256'],original_plan['asset_sha256']))
    check('generation_query_write_budget',plan['max_queries']==12 and plan['max_writes']==72 and plan['max_embeddings']==84 and plan['generations']==0 and plan['cloud_calls']==0 and plan['retries']==0 and plan['extra_count_get']==0)
    for path,expected in plan['code_sha256'].items():
     spec=plan['code_archive'][path];arch=run/spec['archive_path']
     check('code_current_'+spec['project_relative_path'],file_sha(pathlib.Path(path))==expected)
     check('code_archive_'+spec['project_relative_path'],file_sha(arch)==expected==spec['sha256'])
    for i,(path,expected) in enumerate(plan['asset_sha256'].items()):
     check('original_asset_current_'+str(i),file_sha(pathlib.Path(path))==expected)
    for name,part in report['postflight'].items():
     check('producer_postflight_'+name,part['status']=='passed')
    flattened=[(x['pair'],x['actor'],a) for x in expected_schedule for a in x['arms']]
    check('row_schedule_prefix_and_budget',len(rows)<=12 and [(x['pair'],x['actor'],x['arm']) for x in rows]==flattened[:len(rows)])
    all_users=set();all_target_ids=set();actual_queries=0;actual_writes=0;actual_embeddings=0;stats=[];scores=[]
    for ordinal,row in enumerate(rows):
     prefix='row_'+str(ordinal)+'_'
     cell=run/('pair_'+str(row['pair'])+'_'+row['arm'])
     check(prefix+'saved_observation_same',equal(row,load(cell/'observation.json')))
     rpc=load(cell/'rpc_receipts.json')
     check(prefix+'rpc_exact_sequence',[x['command'] for x in rpc]==['init']+['timing_add']*6+['timing_query','close'])
     check(prefix+'rpc_no_error',all('error' not in x for x in rpc))
     check(prefix+'rpc_strict_order',all(x['started_ns']<=x['finished_ns'] for x in rpc) and all(a['finished_ns']<=b['started_ns'] for a,b in zip(rpc,rpc[1:])))
     ids=row['runtime']['native_user_ids'];expected_users=set(ids.values())
     check(prefix+'independent_users',set(ids)=={'assistant','owner','outsider'} and len(expected_users)==3 and not all_users.intersection(expected_users));all_users.update(expected_users)
     check(prefix+'native_identity_and_model_discovery',row['runtime']['open_webui_version']=='0.12.3' and row['runtime']['anonymous_denied'] is True and row['runtime']['model_discovery_disabled'] is True)
     final=row['final'];query=row['query'];timing=final['timing'];requests=final['native_requests']
     writes=[x for x in requests if x['native_path']=='/api/v1/memories/add']
     queries=[x for x in requests if x['native_path']=='/api/v1/memories/query']
     check(prefix+'exact_native_operations',len(writes)==6 and len(queries)==1 and not any(x['native_path']=='/api/v1/memories/search' for x in requests))
     actual_queries+=len(queries);actual_writes+=len(writes);actual_embeddings+=final['native_embedding_function_invocations']
     check(prefix+'zero_external_or_credential_events',all(x['allowed'] is True for x in final['network_events']) and final['credential_values_persisted'] is False)
     check(prefix+'exact_wrapped_embedding_count',final['native_embedding_function_invocations']==7 and query['embedding_delta']==1 and final['generation_attempts']==0)
     owned={}
     for index,(item,receipt,write) in enumerate(zip(fixture,writes,row['writes'])):
      p=prefix+'write_'+str(index)+'_'
      raw=receipt['native_raw_body'].encode('utf-8');rawpath=pathlib.Path(receipt['native_response_file']).resolve()
      check(p+'raw_file_binding',rawpath.is_relative_to((cell/'state').resolve()) and rawpath.read_bytes()==raw and sha(raw)==receipt['native_body_sha256'])
      body=json.loads(raw)
      check(p+'original_request_binding',receipt['native_method']=='POST' and receipt['actor_id']==item['actor'] and receipt['authorization_present'] is True and receipt['cookie_present'] is False and receipt['status']==200 and receipt['response_checked'] is True and receipt['execution_error'] is None and equal(receipt['native_request_json'],{'content':item['text'],'path':item['path'],'type':'context'}))
      check(p+'native_response_binding',body['user_id']==ids[item['actor']] and body['id']==write['target_id'] and body['content']==item['text'] and body['path']==item['path'].strip('/') and body['type']=='context' and type(body['created_at']) is int and type(body['updated_at']) is int)
      check(p+'metadata_from_post',equal(write['native_item'],{k:body[k] for k in ('id','content','path','type','created_at','updated_at')}))
      check(p+'target_id_not_reused',body['id'] not in all_target_ids);all_target_ids.add(body['id'])
      if item['actor']==row['actor']:owned[body['id']]=body
     upserts=timing['upserts'];trace=query['trace']
     check(prefix+'exact_original_search_upserts',len(upserts)==6 and timing['query_attempts']==timing['search_calls']==1 and len(trace)==1 and not timing['observer_errors'])
     for index,(item,upsert) in enumerate(zip(fixture,upserts)):
      expected_text=item['path'].strip('/')+'\n'+item['text']
      check(prefix+'upsert_'+str(index),upsert['original_calls']==1 and upsert.get('returned') is True and upsert['collection_name']=='user-memory-'+ids[item['actor']] and upsert['text_sha256']==[sha(expected_text.encode())] and upsert['vectors']['shape']==[1,384] and upsert['vectors']['finite'] is True and upsert['started_ns']<=upsert['finished_ns'])
     check(prefix+'sequential_upserts',all(a['finished_ns']<=b['started_ns'] for a,b in zip(upserts,upserts[1:])))
     obs=trace[0];http=queries[0]
     raw=http['native_raw_body'].encode('utf-8');rawpath=pathlib.Path(http['native_response_file']).resolve()
     check(prefix+'query_raw_binding',rawpath.is_relative_to((cell/'state').resolve()) and rawpath.read_bytes()==raw and sha(raw)==http['native_body_sha256'] and raw.decode()==query['semantic_row']['native_raw_body'] and equal(json.loads(raw),query['semantic_row']['vector_result']))
     check(prefix+'query_request_binding',http['native_method']=='POST' and http['actor_id']==row['actor'] and http['authorization_present'] is True and http['cookie_present'] is False and equal(http['native_request_json'],{'content':'Customer service and delivery status.','k':100}))
     check(prefix+'search_scope',obs['actor']==row['actor'] and obs['collection_name']=='user-memory-'+ids[row['actor']] and obs['original_calls']==1 and obs['trace_restored'] is True and obs['limit']==100 and obs['filter'] is None and obs['query_vectors']['shape']==[1,384] and obs['query_vectors']['finite'] is True)
     check(prefix+'worker_clock_order',upserts[-1]['finished_ns']==query['last_upsert_finished_ns'] and upserts[-1]['finished_ns']<=query['scheduled_ns']<=query['http_started_ns']<=obs['started_ns']<=obs['finished_ns']<=query['http_finished_ns'])
     delay=(query['http_started_ns']-query['scheduled_ns'])/1e6
     check(prefix+'declared_delay',delay>=500 if row['arm']=='delay500' else delay<500)
     rawvalue=json.loads(raw);semantic=False;foreign=False
     if http['status']==200 and isinstance(rawvalue,dict) and set(rawvalue)=={'ids','documents','metadatas','distances'} and all(isinstance(rawvalue[k],list) and len(rawvalue[k])==1 and isinstance(rawvalue[k][0],list) for k in rawvalue):
      returned,documents,metadata,distances=(rawvalue[k][0] for k in ('ids','documents','metadatas','distances'))
      foreign=bool(set(returned)-set(owned))
      semantic=len(returned)==len(set(returned)) and set(returned)==set(owned) and len(returned)==len(documents)==len(metadata)==len(distances)
      for rid,doc,meta,distance in zip(returned,documents,metadata,distances):
       if rid not in owned:semantic=False;continue
       source=owned[rid];expected_meta={k:source[k] for k in ('created_at','updated_at','type','path')}
       semantic=semantic and doc==source['path']+'\n'+source['content'] and equal(meta,expected_meta) and type(distance) in (int,float) and math.isfinite(distance)
     check(prefix+'semantic_full_original_fields',semantic)
     check(prefix+'no_foreign_id_or_source_canary',not foreign and original['trusted_fixture']['source_only_canary'] not in raw.decode())
     check(prefix+'no_swallowed_or_outward_exception',not obs['exception_events'] and obs.get('outward_exception') is None and obs['return_kind']=='SearchResult')
     score={'semantic_complete':semantic,'null':raw==b'null','foreign_id':foreign,'exception_events':len(obs['exception_events']),'passed':semantic and not obs['exception_events']}
     scores.append(score)
     check(prefix+'producer_semantic_and_null_score',row['score']['semantic_complete']==semantic and row['score']['null']==score['null'] and row['score']['foreign_id']==foreign and row['score']['exception_events']==score['exception_events'])
     stats.append({'pair':row['pair'],'actor':row['actor'],'arm':row['arm'],'delay_scheduled_to_http_ms':delay,'last_upsert_to_http_ms':(query['http_started_ns']-upserts[-1]['finished_ns'])/1e6,'last_upsert_to_search_ms':(obs['started_ns']-upserts[-1]['finished_ns'])/1e6,'query_http_ms':(query['http_finished_ns']-query['http_started_ns'])/1e6})
    for pair in range(len(rows)//2):
     left,right=rows[2*pair:2*pair+2]
     check('pair_'+str(pair)+'_all_write_vector_stats_identical',equal([x['vectors'] for x in left['final']['timing']['upserts']],[x['vectors'] for x in right['final']['timing']['upserts']]))
     check('pair_'+str(pair)+'_query_vector_stats_identical',equal(left['query']['trace'][0]['query_vectors'],right['query']['trace'][0]['query_vectors']))
     check('pair_'+str(pair)+'_producer_alignment',report['pair_alignment'][pair]['all_six_write_vectors_and_query_identical'] is True)
    check('final_full_bounded_run',len(rows)==12 and actual_queries==12 and actual_writes==72 and actual_embeddings==84 and len(all_users)==36 and len(all_target_ids)==72)
    check('stop_rule_full_run_no_failure',all(x['passed'] for x in scores) and report['stop_reason'] is None)
    check('reported_totals_and_limited_interpretation',report['rows']==12 and report['queries']==12 and report['passed']==12 and report['embeddings']==84 and report['generations']==report['cloud_calls']==report['new_api_cost_cny']==0 and report['interpretation']=='not_reproduced_in_12_fixed_queries' and report['original_v3_failure_closed'] is False)
    receipt={'version':'independent_native_vector_timing_saved_evidence_v1','status':'passed' if all(x['passed'] for x in checks) else 'failed','checks':checks,'timing_ms':stats,'read_only_verification':True,'new_native_calls':0,'new_model_calls':0,'source_v3_failure_closed':False,'scope':'Saved HTTP bytes, original write fixture, clocks, pair geometry, finite vectors, identities, exact operation budget and current/archive code/assets. Both native arms used trace observer; no untraced root cause or full migration acceptance inference.','source_report_sha256':file_sha(run/'report.json'),'source_plan_sha256':file_sha(run/'plan.json')}
    receipt['verifier_sha256']=file_sha(pathlib.Path(__file__))
    out=pathlib.Path(output).resolve()
    if out.exists() or not out.is_relative_to(root/'results'):raise ValueError('new_workspace_results_receipt_required')
    with out.open('x',encoding='utf-8') as stream:json.dump(receipt,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps({'status':receipt['status'],'checks':len(checks),'failed':[x['check'] for x in checks if not x['passed']],'receipt_sha256':file_sha(out),'model_calls':0,'native_calls':0,'timing_ms':stats},ensure_ascii=False))

    return receipt


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",type=pathlib.Path,required=True)
    parser.add_argument("--original-run",type=pathlib.Path,required=True)
    parser.add_argument("--output",type=pathlib.Path,required=True)
    args=parser.parse_args()
    result=verify(args.run,args.original_run,args.output)
    raise SystemExit(0 if result["status"]=="passed" else 1)
