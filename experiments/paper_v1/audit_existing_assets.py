"""Read-only source inventory and offline historical result verification.

Only the named audit JSON is written. Private runtime directories are excluded
from inventory. No client is constructed; sockets and subprocesses are blocked.
"""
from __future__ import annotations
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

def denied(*args, **kwargs):
    raise RuntimeError('audit_forbids_network_and_subprocess')

socket.socket = denied
socket.create_connection = denied
subprocess.Popen = denied
os.system = denied

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read(path):
    return json.loads(Path(path).read_bytes())

def source_inventory():
    excluded = {'_local', '.git', '__pycache__', '.pytest_cache', 'node_modules',
                'sdk.private', 'home.private', 'private', '.venv', 'paper_v1'}
    files=[]; skipped=[]; symbols=[]; errors=[]
    for directory, dirs, names in os.walk(ROOT):
        for d in list(dirs):
            if d in excluded or d.startswith('.venv') or d.endswith('.private') or d.endswith('-private-sdk'):
                skipped.append(str((Path(directory)/d).relative_to(ROOT)))
                dirs.remove(d)
        for name in sorted(names):
            p=Path(directory)/name
            rel=p.relative_to(ROOT).as_posix()
            if rel.startswith('research_paper_v1/'):
                continue
            item={'path':rel,'bytes':p.stat().st_size,'suffix':p.suffix.lower()}
            # Source/report/fixture files only. Native logs are never parsed.
            runtime_vendor=any(part in {'.deps','reranker_vendor','site-packages','vendor','node_modules'} for part in p.parts)
            item['runtime_vendor']=runtime_vendor
            if p.suffix.lower()=='.py' and not runtime_vendor:
                item['sha256']=sha(p)
                try:
                    tree=ast.parse(p.read_text(encoding='utf-8-sig'),filename=rel)
                    for n in ast.walk(tree):
                        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                            symbols.append({'path':rel,'line':n.lineno,'name':n.name,
                                'kind':type(n).__name__,'test_named':n.name.startswith('test_')})
                except (SyntaxError,UnicodeError) as exc:
                    errors.append({'path':rel,'error_type':type(exc).__name__})
            files.append(item)
    return {'scope':'all non-private files mechanically inventoried; Python AST only; not a full semantic review',
        'exclusion_names':sorted(excluded),'exclusion_suffixes':['.private','-private-sdk'],
        'excluded_directories':sorted(skipped),
        'files':sorted(files,key=lambda x:x['path']),'symbols':symbols,'parse_errors':errors,
        'counts':{'files':len(files),'by_top_directory':dict(Counter(f['path'].split('/')[0] for f in files)),
            'by_extension':dict(Counter(f['suffix'] for f in files)),
            'python_files':sum(f['suffix']=='.py' for f in files),
            'runtime_vendor_python_files_not_ast_parsed':sum(f['suffix']=='.py' and f['runtime_vendor'] for f in files),
            'project_and_archive_python_files_ast_parsed':sum(f['suffix']=='.py' and not f['runtime_vendor'] for f in files),
            'class_nodes':sum(s['kind']=='ClassDef' for s in symbols),
            'function_nodes':sum(s['kind']!='ClassDef' for s in symbols),
            'test_named_function_nodes_not_executed_tests':sum(s['test_named'] and s['kind']!='ClassDef' for s in symbols)}}

def verify_persistent():
    path=ROOT/'scripts/export_persistent_exchange_public.py'
    spec=importlib.util.spec_from_file_location('public_verify',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    result=module.verify(ROOT/'benchmarks/persistent_exchange_v1_public_20261105')
    result['verifier_sha256']=sha(path)
    return result

def verify_fresh40():
    from experiments.revocation_evidence_repair_v1 import analyze_native as a
    base=ROOT/'results/revocation_evidence_repair_v1'
    partition=read(base/'fresh40-batch-inputs/partition.json')
    order=[cid for name in ('block1','block2') for cid in partition['blocks'][name]]
    assert len(order)==len(set(order))==40 and partition['method_or_prompt_changed'] is False
    parts=[]
    for name in ('block1','block2'):
        run=base/f'fresh40-native-{name}-20261105-v1'
        data=base/'fresh40-batch-inputs'/name
        manifest=read(run/'manifest.json')
        a.require_completed(manifest,read(run/'status.json'))
        assert [c['case_id'] for c in manifest['cases']]==partition['blocks'][name]
        assert manifest['max_calls']==300 and 'fresh' in manifest['stage']
        parts.append(a.load_completed_part(run,data,Path(str(run)+'-evaluated'),manifest))
    rows,evaluated,manifest,labels=a.merge_blocks(parts,case_order=order)
    result=a.analyze(rows,evaluated,manifest,labels)
    # Restore the frozen CLI's phase metadata before exact comparisons.
    result['summary'].update(phase='fresh_confirmation',fresh40_answers_read=True,
        blocks_combined_before_bootstrap=2,block_intervals_averaged=False)
    result['gate'].update(phase='fresh_confirmation',automatic_launch_performed=False,
        next_stage_launch_recommendation=None,
        fresh_point_thresholds_and_simple_review_pass=result['gate']['worth_fresh40_native_screening'])
    result['gate']['worth_fresh40_native_screening']=None
    result['gate']['decision']=('fresh_point_thresholds_pass_with_simple_control_review'
        if result['gate']['fresh_point_thresholds_and_simple_review_pass']
        else 'fresh_point_thresholds_or_simple_control_review_fail')
    initial=[row for row in rows if row['step']==0]
    result['summary']['initial_cache_isolation']={'initial_calls':len(initial),
        'READ':[row['initial_cache_isolation']['initial_cache_read_tokens'] for row in initial],
        'flags':dict(Counter(row['initial_cache_isolation']['status'] for row in initial))}
    plans={plan['case_id']:plan for plan in manifest['plans']}
    nonces=[nonce for plan in manifest['plans'] for nonce in plan['nonces'].values()]
    assert len(set(nonces))==len(nonces) and len(set(map(len,nonces)))==1
    for row in rows:
        assert row['messages'][0]['content']=='Qualification tag: '+plans[row['case_id']]['nonces'][row['arm']]+'\n'+manifest['target_prompt']
    old=base/'fresh40-native-combined-20261105-v1-analysis'
    matches={key:read(old/(key+'.json'))==value for key,value in result.items()}
    assert all(matches.values()),matches
    unchanged=all(sha(path)==expected for part in parts for path,expected in part['provenance']['row_sha256'].items())
    assert unchanged
    return {'status':'verified','rows':len(rows),'independent_question_clusters':40,
        'full_result_sections_equal':matches,'source_rows_unchanged':unchanged,
        'partition_sha256':sha(base/'fresh40-batch-inputs/partition.json'),
        'analyzer_sha256':sha(a.__file__),'gate':result['gate'],
        'arm_summary':result['summary']['arms'],
        'fixed_candidate_vs_raw':result['contrasts_against_raw']['repair_selective'],
        'fixed_candidate_against_strong_simple':result.get('fixed_candidate_against_strong_simple'),
        'native_calls_reexecuted':0,'strict_native_evaluation_rerun':False,
        'boundary':'uses existing strict evaluator outputs, verifies frozen evaluator hash and row accounting; does not reopen private native histories'}

def provenance_boundary_example():
    from experiments.persistent_exchange_v1.store import AgentStore, TrustedPolicy, export_package, import_package, StoreError
    # The hand-written text deliberately violates the trusted writer's truthful
    # complete-input declaration assumption. This is not an in-model exploit.
    with tempfile.TemporaryDirectory(prefix='paper-v1-boundary-') as td:
        root=Path(td)
        a=AgentStore(root/'a.sqlite','A');b=AgentStore(root/'b.sqlite','B');p=TrustedPolicy(root/'policy.sqlite')
        try:
            public=a.add_original('public','The project is named Cedar.')
            secret=a.add_original('secret','The synthetic confidential budget is 931742 units.')
            p.register_sources([public,secret]);p.set_permissions('B',['public'])
            bad=a.add_memory('omitted-edge','The project Cedar budget is 931742 units.',source_ids=['public'])
            packet=export_package(a,p,'B',[bad['memory_key']])
            accepted=import_package(b,p,packet)
            row=b.db.execute('SELECT content FROM memories WHERE memory_key=?',(bad['memory_key'],)).fetchone()
            actual_content=row[0] if row else ''
            honest=a.add_memory('complete-edge','The project Cedar budget is 931742 units.',source_ids=['public','secret'])
            blocked=None
            try:export_package(a,p,'B',[honest['memory_key']])
            except StoreError as exc:blocked=str(exc)
            assert accepted['status']=='imported' and '931742' in actual_content
            assert blocked=='source_not_currently_authorized_for_recipient'
            return {'status':'observed','synthetic_cases':2,'new_model_calls':0,
                'omitted_source_declaration':'accepted_and_receiver_contains_synthetic_secret',
                'complete_source_declaration':blocked,
                'original_databases_used':False,
                'classification':'trusted_writer_completeness_assumption_boundary_not_an_in_scope_vulnerability',
                'conclusion':'body hash and internally consistent dependency closure cannot certify unrecorded input provenance; commercial hidden context remains unobserved'}
        finally:a.close();b.close();p.close()

def main():
    result={'date_asia_shanghai':'2026-11-05','started_utc':datetime.now(timezone.utc).isoformat(),
        'command':'D:/python3.11/python.exe -I -B -S experiments/paper_v1/audit_existing_assets.py',
        'network_and_subprocess_blocked':True,'new_model_calls':0,
        'inventory':source_inventory(),'persistent_exchange':verify_persistent(),'fresh40':verify_fresh40(),
        'provenance_boundary_example':provenance_boundary_example()}
    result['finished_utc']=datetime.now(timezone.utc).isoformat()
    output=ROOT/'research_paper_v1/evidence/asset_index.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'status':'verified','inventory_counts':result['inventory']['counts'],
        'persistent_exchange':result['persistent_exchange'],'fresh40':{
            k:result['fresh40'][k] for k in ('status','rows','independent_question_clusters','full_result_sections_equal','source_rows_unchanged')},
        'output':str(output)},ensure_ascii=False))

if __name__=='__main__':main()
