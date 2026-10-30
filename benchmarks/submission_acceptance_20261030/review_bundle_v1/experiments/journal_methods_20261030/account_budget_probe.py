"""Read-only official-client quotas. No prompts, top-ups or credential output.

Qoder uses official get_usage_info control frames. Harness uses its installed
official credential parser and account-detail function in the Electron Node
runtime; the grant remains inside that subprocess. It is never copied or logged.
The caller owns the experiment's invocation and spending authorization.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CAPABILITIES = ROOT/'results/native_agent_probe_20261026/qoder_capabilities.json'
HARNESS = Path('C:/Users/CAI/AppData/Local/Programs/DeepSeek Harness/DeepSeek Harness.exe')


def _quota(value):
    if not isinstance(value, dict):
        return None
    allowed = {'total','used','remaining','percentage','unit','cap','available',
               'userType','userQuota','addOnQuota','orgResourcePackage',
               'totalUsagePercentage','isQuotaExceeded','total_credits'}
    return {k: _quota(v) if isinstance(v, dict) else v for k,v in value.items()
            if k in allowed and (isinstance(v,dict) or type(v) in (str,int,float,bool) or v is None)}


def query_qoder():
    caps = json.loads(CAPABILITIES.read_text(encoding='utf-8'))
    argv = caps['metadata_argv'][:-1] + ['--input-format','stream-json',
        '--output-format','stream-json','--no-session-persistence','--print']
    cwd = argv[argv.index('--cwd')+1]
    # Use the already audited environment allowlist, never log environment data.
    from memory_migration_study.qoder_native import _safe_environment
    reqs = [dict(type='control_request',request_id='budget-init',request={'subtype':'initialize'}),
            dict(type='control_request',request_id='budget-usage',request={'subtype':'get_usage_info'})]
    proc = subprocess.run(argv, input='\n'.join(json.dumps(x) for x in reqs)+'\n',
        cwd=cwd, env=_safe_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        encoding='utf-8', errors='replace', timeout=50,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    usage, session, inference_events = None, None, 0
    for line in proc.stdout.splitlines():
        try:
            value = json.loads(line)
        except (ValueError,TypeError):
            continue
        inference_events += value.get('type') in {'assistant','user'}
        response = value.get('response',{})
        if value.get('type') == 'control_response' and response.get('request_id') == 'budget-usage':
            if response.get('subtype') == 'success':
                body = response.get('response',{})
                usage, session = _quota(body.get('usage')), _quota(body.get('session'))
    remaining = None
    if usage:
        buckets = [usage.get(key,{}).get('remaining') for key in ('userQuota','addOnQuota','orgResourcePackage')]
        known = [x for x in buckets if type(x) in (int,float)]
        remaining = sum(known) if known else None
    return {'status':'ready' if usage is not None and not inference_events else 'unavailable',
        'usage':usage,'session':session,'quota_remaining_credits':remaining,
        'exit_code':proc.returncode,'inference_events_seen':inference_events,
        'no_user_messages_sent':True,'model_requests':0,'model_alias':caps['actual_cli_model_id'],
        'official_cli_entry':caps['cli_entry'],'official_cli_version':caps['package_version_verified'],
        'credential_values_returned':False}


_HARNESS_SCRIPT = r'''
import { pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const base='C:/Users/CAI/AppData/Local/Programs/DeepSeek Harness/resources/app.asar/dsh/node_modules/@deepseek-ai/';
const imp=(p)=>import(pathToFileURL(base+p).href);
try {
 const local=await imp('dsh-credentials-local/lib/index.js');
 const {credentialKey}=await imp('dsh-credentials/lib/index.js');
 const {readAccountDetail}=await imp('dsh-deepseek-account-platform/lib/types/details.js');
 const {platformClientHeaders}=await imp('dsh-deepseek-account/lib/index.js');
 const file='C:/Users/CAI/.dsh/.credentials.yaml';
 const raw=await readFile(file,'utf8');
 const hash=(s)=>createHash('sha256').update(s).digest('hex');
 const before=hash(raw);
 const doc=local.parseCredentialsDocument(raw,file);
 const rec=doc.records.get(credentialKey('deepseek-account-platform','default'));
 if(!rec || rec.kind!=='grant' || rec.payload?.issuer!=='https://platform.deepseek.com') {
  console.log(JSON.stringify({status:'no_matching_official_account_grant',credential_values_returned:false}));
 } else {
  // readAccountDetail does not expire/delete credentials on rejection. Do not
  // call PlatformAccount.getBalance, whose expired-token path can delete them.
  const result=await readAccountDetail('balance',rec.payload.issuer,rec.payload.token,
   AbortSignal.timeout(25000),platformClientHeaders('win32',
    {version:'0.2.1-rc.3',locale:'zh-CN',timezoneOffsetSeconds:28800}));
  const wallets=(a)=>Array.isArray(a)?a.filter(x=>['CNY','USD'].includes(x.currency)&&
   typeof x.balance==='string').map(x=>({currency:x.currency,balance:x.balance})):null;
  console.log(JSON.stringify({status:result?.status||'unavailable',normal_wallets:wallets(result?.value),
   bonus_wallets:wallets(result?.bonusWallets),credential_file_unchanged:before===hash(await readFile(file,'utf8')),
   credential_values_returned:false,credential_copied:false,model_requests:0,
   endpoint:'GET https://platform.deepseek.com/api/v0/users/get_user_summary',observed_at_utc:new Date().toISOString()}));
 }
} catch(e) {
 console.log(JSON.stringify({status:'metadata_query_failed',error_type:e?.code==='expired'?
  'account_expired':e?.code==='ERR_MODULE_NOT_FOUND'?'module_resolution_failed':'safe_runtime_error',
  credential_values_returned:false,model_requests:0}));
}
'''


def query_harness():
    env = {key:value for key,value in os.environ.items() if key.upper() in {
        'PATH','PATHEXT','SYSTEMROOT','WINDIR','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA',
        'HOMEDRIVE','HOMEPATH','PROGRAMFILES','PROGRAMFILES(X86)','COMMONPROGRAMFILES','OS','PROCESSOR_ARCHITECTURE'}}
    env.update(ELECTRON_RUN_AS_NODE='1',DSH_TELEMETRY_DISABLED='1')
    proc = subprocess.run([str(HARNESS),'--input-type=module','-'],input=_HARNESS_SCRIPT,
        cwd=str(ROOT),env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        text=True,encoding='utf-8',errors='replace',timeout=40,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    result = {'status':'metadata_query_failed','credential_values_returned':False,'model_requests':0}
    for line in proc.stdout.splitlines():
        try:
            value = json.loads(line)
        except (ValueError,TypeError):
            continue
        if isinstance(value,dict) and value.get('credential_values_returned') is False:
            result = value
    return {**result,'provider':'deepseek-account','model':'deepseek-flash',
            'exit_code':proc.returncode,'stderr_bytes':len(proc.stderr.encode('utf-8'))}


def probe():
    result = {'schema':'journal_account_snapshot_v1','checked_at_utc':datetime.now(timezone.utc).isoformat(),
              'model_requests':0,'user_prompts_sent':0,'credentials_copied':False}
    for name, fun in [('qoder',query_qoder),('harness',query_harness)]:
        try:
            result[name] = fun()
        except (OSError,ValueError,KeyError,subprocess.SubprocessError):
            result[name] = {'status':'metadata_query_failed','credential_values_returned':False,'model_requests':0}
    return result


if __name__=='__main__':
    print(json.dumps(probe(),ensure_ascii=False,indent=2))
