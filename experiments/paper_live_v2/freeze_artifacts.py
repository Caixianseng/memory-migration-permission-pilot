"""Snapshot final code and hash public artifacts; never follows private ledgers."""
import hashlib,json,os,shutil,time
from pathlib import Path
from .live_runtime import ROOT,OUT,GATEWAY
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    exp=ROOT/'experiments/paper_live_v2';dst=OUT/'raw_experiment_data/code_final';dst.mkdir(exist_ok=True)
    versions=[]
    for src in sorted(exp.rglob('*')):
        if not src.is_file() or src.suffix not in ('.py','.mjs'):continue
        relative=src.relative_to(exp);target=dst/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target)
        versions.append({'path':str(src.relative_to(ROOT)),'sha256':sha(src),'snapshot':str(target.relative_to(OUT))})
    for name in ('summarize_live.py','evaluate_live.py','evaluate_sources.py','audit_live_attempts.py','merge_source_semantic_reviews.py','format_adapter.py','make_live_figures.py','verify_completion.py'):
        shutil.copyfile(exp/name,OUT/'analysis_scripts'/name)
    owning=[ROOT/'experiments/persistent_exchange_v1/store.py',ROOT/'experiments/paper_final_v1/durable_delivery.py',
        ROOT/'experiments/revocation_grouping_v1/sdk_adapter.py',ROOT/'experiments/revocation_grouping_v1/dsh_group_guard.mjs',
        ROOT/'memory_migration_study/deepseek_sdk.py',ROOT/'memory_migration_study/deepseek_native.py',
        GATEWAY/'scripts/hy3-native-paid-one-shot.mjs',GATEWAY/'scripts/create-hy3-worker.schema.json']
    code={'schema':'paper-live-v2-file-version-manifest','observed_unix':time.time(),
        'git_metadata_available':(ROOT/'.git').exists(),'versions':versions,
        'existing_owning_dependencies':[{'path':str(p),'sha256':sha(p)} for p in owning],
        'actual_new_inferences_created_by_freeze':0,'native_app_version_and_member_hashes':'per native envelope',
        'model_weight_builds':'not assumed observable','license_relicensing_claim':False}
    (OUT/'raw_experiment_data/code_versions_final.json').write_text(json.dumps(code,indent=2),encoding='utf-8')
    entries=[];private_skipped=[]
    for folder,dirs,files in os.walk(OUT,topdown=True):
        for d in list(dirs):
            if 'private' in d.casefold() or d=='__pycache__':dirs.remove(d);private_skipped.append(str((Path(folder)/d).relative_to(OUT)))
        for name in files:
            if name=='public_artifact_manifest_final.json' or 'private' in name.casefold() or 'credential' in name.casefold() or name.endswith('.pyc'):continue
            p=Path(folder)/name
            entries.append({'path':str(p.relative_to(OUT)),'bytes':p.stat().st_size,'sha256':sha(p)})
    manifest={'schema':'live-v2-public-artifact-hashes-v1','observed_unix':time.time(),
        'self_excluded':True,'public_files':entries,'private_directories_pruned':private_skipped,
        'published_or_uploaded':False,'contains_account_credentials':False,
        'scope':'Integrity/version manifest, not evidence of provenance completeness or academic novelty'}
    (OUT/'raw_experiment_data/public_artifact_manifest_final.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'source_code_snapshots':len(versions),'public_files_hashed':len(entries),'private_directories_pruned':len(private_skipped),'new_model_calls':0}))
if __name__=='__main__':main()
