"""Offline consistency verification of recorded synthetic source/target events."""
from contextlib import ExitStack
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
from unittest.mock import patch

PUB=Path(__file__).resolve().parent
REPO=PUB.parents[1]
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def need(test,code):
    if not test:raise ValueError(code)

def path(base,name):
    need(isinstance(name,str) and bool(name) and chr(92) not in name and ':' not in name
        and not name.startswith('/') and all(s not in {'','.','..'} for s in name.split('/')),'unsafe_manifest_path')
    p=base.joinpath(*PurePosixPath(name).parts)
    need(p.resolve(strict=True).is_relative_to(base),'path_outside_base')
    for item in (p,*p.parents):
        a=item.lstat()
        need(not stat.S_ISLNK(a.st_mode) and not getattr(a,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024),'linked_path')
        if item==base:break
    need(p.is_file(),'not_file')
    return p

def verify():
    m=read(path(PUB,'manifest.json'))
    need(m['schema']=='qoder_source_publication_v1','wrong_schema')
    for name,digest in m['files'].items():need(sha(path(PUB,name))==digest,'published_hash_mismatch:'+name)
    actual=set()
    for p in PUB.rglob('*'):
        a=p.lstat()
        need(not stat.S_ISLNK(a.st_mode) and not getattr(a,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024),'linked_inventory')
        if p.is_file():actual.add(p.relative_to(PUB).as_posix())
    need(actual==set(m['files'])|{'manifest.json'},'unregistered_or_missing_file')
    for name,digest in m['repository_source_sha256'].items():
        need(sha(path(REPO,name))==digest,'repository_source_changed:'+name)
    return m

def blocked(*a,**k):raise RuntimeError('offline_network_and_subprocess_forbidden')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    m=verify()
    if args.out:need(not args.out.exists() and not args.out.resolve().is_relative_to(PUB),'new_output_outside_publication_required')
    final=PUB/'final'; summary_hash=sha(final/'summary.json')
    sys.dont_write_bytecode=True;sys.path.insert(0,str(REPO))
    with ExitStack() as stack:
        for target in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect','socket.socket.connect_ex','subprocess.Popen'):
            stack.enter_context(patch(target,side_effect=blocked))
        from experiments.qoder_source_generation_20261030 import joint_handoff
        stack.enter_context(patch.object(joint_handoff,'save',side_effect=RuntimeError('frozen_write_forbidden')))
        scored=joint_handoff.score(final)
    need(scored==read(final/'summary.json') and sha(final/'summary.json')==summary_hash,'summary_changed')
    spec=read(final/'input.json'); source=final/'source/workspace/AGENTS.md'; raw=source.read_bytes()
    need(raw==('\n'.join(spec['facts'])+'\n').encode('utf-8'),'source_not_exact_input')
    generation=read(final/'source_generation.json'); receipt=read(final/'source/generation_receipt.json')
    evidence=read(final/'source/execution_evidence.json'); binding=read(final/'source_binding.json'); case=read(final/'case.json')
    need(generation==receipt and generation['status']=='ok' and generation['tool_result_success'] is True,'generation_not_qualified')
    need(sha(source)==generation['native_file_sha256']==binding['source_file_sha256']==binding['source_text_sha256'],'source_hash_binding')
    need(sha(final/'source/execution_evidence.json')==generation['execution_evidence_sha256'],'source_execution_hash')
    need(case['source']['text'].encode('utf-8')==raw,'case_not_native_source')
    for fact in case['facts']:need(case['source']['text'][fact['start']:fact['end']]==fact['text'],'source_span')
    f3=next(f for f in case['facts'] if f['fact_id']=='source-f3')
    need(f3['recipient_read'] is True and f3['export_allowed'] is False,'read_not_export_control')
    events=evidence['events']; writes=[e for e in events if e.get('type')=='tool_use']; results=[e for e in events if e.get('type')=='tool_result']
    need(len(writes)==len(results)==1 and writes[0]['name']=='Write' and writes[0]['target_matches'] is True,'write_inventory')
    need(writes[0]['tool_use_id']==results[0]['tool_use_id']==generation['tool_use_id']
        and results[0]['is_error'] is False and writes[0]['content_sha256']==sha(source),'write_result_binding')
    need(sum(e.get('type')=='prompt_sent' for e in events)==evidence['user_prompts_sent']==generation['model_prompts_sent']==1,'source_prompt_count')
    inits=[e for e in events if e.get('type')=='init']
    need(len(inits)==generation['native_init_count']==2 and all(e['accepted'] and e['tools']==['Write'] for e in inits),'native_init_inventory')
    guard=[json.loads(x) for x in (final/'source/guard_events.jsonl').read_text(encoding='utf-8').splitlines() if x]
    need(len(guard)==1 and guard[0]['tool_use_id']==writes[0]['tool_use_id'] and guard[0]['content_sha256']==sha(source)
        and guard[0]['decision']=='continue_native_permission','source_guard_binding')
    need(generation['reported_output_tokens']==0 and generation['actual_output_tokens'] is None
        and generation['actual_output_tokens_verified'] is False,'usage_unknown_boundary')
    rows=read(final/'predictions.json'); actual=[r for r in rows if not r.get('shared_actual_call_with')]
    linked=[r for r in rows if r.get('shared_actual_call_with')]
    need(len(actual)==4 and len(linked)==8,'target_call_inventory')
    for row in rows:need(sha(final/'targets'/row['slot']/'AGENTS.md')==row['target_file_sha256'],'target_file_hash')
    for row in actual:
        target=final/'targets'/row['slot']/'AGENTS.md'; r=read(final/(row['slot']+'_receipt.json'))
        need(r['status']=='ok' and r['native_instruction_loaded'] is True
            and r['agent_memory_file_sha256']==sha(target),'target_load_receipt')
        memory=target.read_bytes().decode('utf-8')
        need(any(b.get('source',{}).get('kind')=='agent-instructions' and b.get('source',{}).get('baseline') is True
            and ''.join(x.get('text','') for x in b.get('content',[]))==memory
            and any(x.get('digest')==hashlib.sha1(memory.encode('utf-8')).hexdigest() for x in b.get('source',{}).get('changes',[]))
            for b in r['native_instruction_baselines']),'target_load_event')
        need(r.get('answer')==row['raw_answer'],'target_raw_response_binding')
    verify()
    result={'schema':'qoder_source_offline_verification_v1','passed':True,
        'public_files_verified':len(m['files']),'repository_files_verified':len(m['repository_source_sha256']),
        'manifest_sha256':sha(PUB/'manifest.json'),'summary_sha256_unchanged':summary_hash,
        'source_write_tasks_final':1,'source_user_prompts_all_three_batches':3,'source_stories':1,
        'source_actual_http_requests':None,'source_reported_output_tokens':0,'source_actual_output_tokens':None,
        'harness_actual_calls':4,'linked_rows':8,'source_and_target_events_verified':True,
        'new_model_calls':0,'new_network_calls':0,'new_client_calls':0,'formal_external_review':False,
        'scope':'Recorded synthetic evidence consistency, not a fresh live run, Auto-Memory, native ACL or general semantic privacy proof.'}
    text=json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n'
    if args.out:
        with args.out.open('x',encoding='utf-8',newline='\n') as f:f.write(text)
    print(text,end='')

if __name__=='__main__':main()
