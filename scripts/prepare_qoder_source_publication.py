"""Copy only safe, fixed Qoder-source evidence; never start clients or models."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.prepare_submission_publication import checked, inspect_bytes, read, safe_relative, save, sha

SOURCE=ROOT/'results/qoder_source_generation_20261030'
FINAL=SOURCE/'joint_run03'
OUT=ROOT/'benchmarks/qoder_source_generation_20261030'
TOP=('plan.json','input.json','evaluation_reference.json','predictions.json','prediction_phase_closed.json',
     'summary.json','source_generation.json','source_binding.json','accounting.json','authorization_matrix.json','case.json',
     'independent_joint_audit.json')
SOURCE_FILES=('metadata_qualification.json','execution_evidence.json','generation_receipt.json','guard_events.jsonl')


def failure(name):
    run=SOURCE/name
    generation=read(checked(run/'source_generation.json',ROOT))
    evidence=read(checked(run/'source/execution_evidence.json',ROOT))
    closed=read(checked(run/'prediction_phase_closed.json',ROOT))
    if sha(run/'predictions.json')!=closed['predictions_sha256']:
        raise ValueError('failed_prediction_hash_changed')
    rows=read(run/'predictions.json')
    if generation['status']!='failed' or any(r.get('client_status')=='ok' for r in rows):
        raise ValueError('failed_batch_has_qualified_target')
    events=evidence['events']; path=run/'source/workspace/AGENTS.md'
    prompts=sum(e.get('type')=='prompt_sent' for e in events)
    count_source='explicit_prompt_sent_events'
    if 'user_prompts_sent' not in evidence and prompts==0:
        if type(evidence.get('prompt_sent')) is not bool:
            raise ValueError('legacy_prompt_send_state_unknown')
        prompts=int(evidence['prompt_sent'])
        count_source='legacy_explicit_prompt_sent_boolean_under_single_prompt_contract'
    if 'user_prompts_sent' in evidence and evidence['user_prompts_sent']!=prompts:
        raise ValueError('failed_prompt_evidence_disagrees')
    cache=run/'source/workspace/%SystemDrive%'
    return {'run':name,'status':generation['status'],'error':generation.get('error'),
        'execution_error':evidence.get('error'),'source_user_prompts':prompts,'prompt_count_evidence':count_source,
        'write_events':sum(e.get('type')=='tool_use' and e.get('name')=='Write' for e in events),
        'successful_tool_results':sum(e.get('type')=='tool_result' and e.get('is_error') is False for e in events),
        'source_file_present':path.is_file(),'source_file_sha256':sha(path) if path.is_file() else None,
        'extra_literal_SystemDrive_db_count':sum(p.is_file() for p in cache.rglob('*.db')) if cache.exists() else 0,
        'harness_model_calls':0,'registered_rows':len(rows),
        'client_status_counts':dict(Counter(r.get('client_status') for r in rows)),
        'source_generation_sha256':sha(run/'source_generation.json'),
        'execution_evidence_sha256':sha(run/'source/execution_evidence.json'),
        'predictions_sha256':sha(run/'predictions.json'),
        'used_as_success':False,'source_actual_http_requests':None,
        'scope':'Failed source qualification; names of accidental cache files counted without reading/copying database content. No account, runtime, state or claim copied.'}


VERIFY=r'''"""Offline consistency verification of recorded synthetic source/target events."""
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
'''


README='''# Qoder原生Write来源 → 权限迁移 → Harness使用

本补证公开一条真实来源链：Qoder通过唯一原生Write把明确给出的四条合成事实写入实际AGENTS.md；可信主机依据独立外附授权处理并迁入Harness；回答后再次核权恢复。源文件不是主机代写或根据评分答案事后重建。它仍是给定内容的精确写入，没有证明Auto-Memory、自由事实抽取或产品原生ACL跨平台迁移。

源端Qoder提示实际收到原始四行合成内容，包括example.invalid邮箱和虚构私有口令；这是注册许可的源端处理。source-f3禁迁只限制向目标Harness交付，不禁止本轮源端Qoder处理。目标Harness出站保护不等于生成阶段原文从未离开本机，也不证明对所有模型供应商的端到端隐私保护。本批没有发送真实私人数据。

## 零模型离线复核

从本仓库运行，标准库即可：

~~~text
python -I -B -S benchmarks/qoder_source_generation_20261030/offline_verify.py
~~~

脚本核验全部公开文件及仓库固定源码哈希，调用joint_handoff.score重算且不改变原摘要；另独立核对源原文/区间、Write/tool_result/guard事件及4个Harness加载收据/实际文件哈希。--out可写到本目录之外的新JSON。正式外部人员验收仍未完成，哈希支持一致性，不能替代可信分发与一般安全证明。

## 分母与结果边界

- 最终joint_run03：Qoder用户提示1次、唯一原生Write成功、1个合成故事；Harness实际模型调用4次、关联重放8行，共12行方法记录。
- 实际4题含合法2题、禁迁事实1题、缺失事实1题；合法均正确且UNKNOWN为0，两道控制均UNKNOWN。关联重放不是新增调用或独立样本。
- 三方法输入等价，共享实际调用，不能据此声称新算法优于强基线。
- case.json保留真实AGENTS字节构造的source span和独立外附授权：source-f3可读但禁迁。原生写入产生内容，不产生授权。
- 源端reported_output_tokens=0，但actual_output_tokens=null、未独立核验；0不证明免费或实际token为0，源端具体HTTP请求数未知。

## 失败与环境口径

failed_runs01_02.json保留两个失败摘要：v1重复初始化，未写出源文件；v2唯一Write与工具结果成功，但工作区额外出现字面%SystemDrive%目录下4个缓存db，整体资格仍失败。两批Harness均0调用。
源端三批累计3次用户提示，仍是同一故事。旧失败没有修改为成功，未发送位置不计入安全观测。
恢复标准Windows路径变量后，最终新批次无额外文件；零模型探针尚未完全复现缓存创建组件，不能把环境修正夸大为已严格证明的因果根因。

final/只含明确白名单的原字节安全文件。source/workspace只含AGENTS.md，不包含运行home、账户快照、.git、数据库、guard_state或claim。12个target文件用于核对实际与关联视图；4份原生receipt提供独立加载证据。
failed_versions/提供v1/v2四份冻结源码及原始哈希清单，不应作为新生产入口执行。42项新增源码测试仅支撑工程可靠性，不是42个独立病例。
旧149文件复核包保持原状；不同批次不合并为总体成功率。该目录须使用Git -text保留原字节。
'''


def build(out):
    out=Path(out).absolute()
    if out.exists() or out.parent.resolve(strict=True)!=(ROOT/'benchmarks').resolve(strict=True):
        raise ValueError('new_direct_benchmarks_output_required')
    safe_relative(out.name)
    selected={'final/'+name:FINAL/name for name in TOP}
    selected.update({'final/source/'+name:FINAL/'source'/name for name in SOURCE_FILES})
    selected['final/source/workspace/AGENTS.md']=FINAL/'source/workspace/AGENTS.md'
    for task in read(FINAL/'input.json')['tasks']:
        for method in ('whole_block','per_fragment','existing_selective'):
            slot=task['task_id']+'-'+method;safe_relative(slot)
            selected['final/targets/'+slot+'/AGENTS.md']=FINAL/'targets'/slot/'AGENTS.md'
        slot=task['task_id']+'-whole_block'
        selected['final/'+slot+'_receipt.json']=FINAL/(slot+'_receipt.json')
    for name in ('joint_run01','joint_run02'):
        folder=SOURCE/name/'source/frozen_source'
        expected={Path(x['original_path'].replace(chr(92),'/')).name:x['expected_sha256'] for x in read(folder/'manifest.json')['files']}
        for module in ('__init__.py','guard.py','joint_handoff.py','writer.py'):
            if sha(checked(folder/module,ROOT))!=expected[module]:raise ValueError('old_frozen_source_changed')
            selected['failed_versions/'+name+'/'+module]=folder/module
        selected['failed_versions/'+name+'/manifest.json']=folder/'manifest.json'
    for name,source in selected.items():safe_relative(name);inspect_bytes(source)
    original={p.relative_to(ROOT).as_posix():sha(p) for p in selected.values()}
    failures=[failure(name) for name in ('joint_run01','joint_run02')]
    if sum(x['source_user_prompts'] for x in failures)+read(FINAL/'source/execution_evidence.json')['user_prompts_sent']!=3:
        raise ValueError('cumulative_prompt_inventory_changed')
    modules=list((ROOT/'memory_migration_study').glob('*.py'))
    for name in ('qoder_source_generation_20261030','submission_acceptance_20261030','journal_methods_20261030'):
        modules+=list((ROOT/'experiments'/name).glob('*.py'))
    repo_hash={p.relative_to(ROOT).as_posix():sha(checked(p,ROOT)) for p in modules}
    for name,expected in read(FINAL/'plan.json')['implementation_sha256'].items():
        if repo_hash.get(name)!=expected:raise ValueError('final_frozen_source_changed:'+name)
    out.mkdir()
    for name,source in selected.items():
        destination=out.joinpath(*safe_relative(name).parts);destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open('xb') as stream:stream.write(inspect_bytes(source))
        if sha(destination)!=sha(source):raise ValueError('copy_hash_mismatch')
    save(out/'failed_runs01_02.json',{'schema':'qoder_source_failed_runs_v1','failures':failures,
        'source_prompts_total_including_final':3,'source_stories':1,'source_actual_http_requests':None})
    (out/'README.md').write_text(README,encoding='utf-8',newline='\n')
    (out/'offline_verify.py').write_text(VERIFY,encoding='utf-8',newline='\n')
    if any(sha(ROOT/name)!=expected for name,expected in original.items()):raise ValueError('original_changed_during_copy')
    manifest={'schema':'qoder_source_publication_v1','created_at_utc':datetime.now(timezone.utc).isoformat(),
        'original_files_changed':[],'copied_original_sha256':{name:sha(p) for name,p in selected.items()},
        'repository_source_sha256':repo_hash,'formal_external_review':False,'new_model_calls':0,
        'files':{p.relative_to(out).as_posix():sha(p) for p in sorted(out.rglob('*')) if p.is_file()}}
    save(out/'manifest.json',manifest)
    return {'directory':str(out),'files':len(manifest['files'])+1,'manifest_sha256':sha(out/'manifest.json'),
            'original_changes':0,'new_model_calls':0}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,default=OUT)
    args=parser.parse_args();print(json.dumps(build(args.out),ensure_ascii=False))


if __name__=='__main__':main()
