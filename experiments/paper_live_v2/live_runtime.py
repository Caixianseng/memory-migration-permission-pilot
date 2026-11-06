"""Explicit real native/official-SDK inference; each reservation is dispatched once."""
from __future__ import annotations
import hashlib,json,subprocess,time,uuid
from pathlib import Path
from threading import Semaphore
from experiments.revocation_grouping_v1.sdk_adapter import FlashSDKClient
from .format_adapter import parse_source,parse_json_object

ROOT=Path(__file__).resolve().parents[2]
GATEWAY=ROOT.parent/'codex-workbuddy-gateway-windows'
OUT=ROOT/'research_paper_v1/paper_live_v2'
QUAL=OUT/'raw_experiment_data/preflight/workbuddy/envelope.json'
LIMITS={'hy3':Semaphore(3),'flash':Semaphore(3)}
def sha(raw): return hashlib.sha256(raw if isinstance(raw,bytes) else raw.encode()).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as f: json.dump(value,f,ensure_ascii=False,indent=2)
def load(path): return json.loads(path.read_text(encoding='utf-8'))
def infer(platform,prompt,job_dir,role,scenarios=('raw','summary','multi_source'),sdk_ledger_dir=None):
    job_dir=Path(job_dir);job_dir.mkdir(parents=True,exist_ok=True)
    contract={'platform':platform,'role':role,'scenarios':list(scenarios),'prompt':prompt,'prompt_sha256':sha(prompt),
              'system_prompt':'Task instructions embedded in native user turn; full upstream system prompt unavailable.',
              'automatic_model_retry':False,'gold_in_context':False}
    cp=job_dir/'contract.json';rp=job_dir/'result.json'
    if cp.exists():
        if load(cp)!=contract: raise RuntimeError('frozen_live_input_changed')
    else: save(cp,contract)
    if rp.exists():
        previous=load(rp)
        recovered=job_dir/'local_parse_recovery.json'
        if recovered.exists():return load(recovered)
        if (job_dir/'safe_predispatch_retry/result.json').exists():
            retried=load(job_dir/'safe_predispatch_retry/result.json')
            if retried.get('status')=='ok':return retried
        if (job_dir/'safe_precreation_retry/result.json').exists():
            retried=load(job_dir/'safe_precreation_retry/result.json')
            if retried.get('status')=='ok':return retried
        if previous.get('status')=='failed':
            from .recover_records import recover
            recovered_result=recover(job_dir,role,scenarios)
            if recovered_result is not None:
                save(recovered,recovered_result);return recovered_result
            return previous
        return previous
    intent=job_dir/'intent.json'
    if intent.exists(): raise RuntimeError('reserved_live_request_no_replay')
    save(intent,{'reserved_unix':time.time(),'authority':'user explicit real-model experiment instruction 2026-11-06'})
    start=time.time()
    with LIMITS[platform]:
        queued=time.time()
        try:
            if platform=='hy3':
                native=job_dir/'native';native.mkdir()
                job={'schema':'workbuddy-hy3-paid-one-shot-job-v1','jobId':'lv2-'+uuid.uuid4().hex,
                    'jobType':'receiver','sessionId':str(uuid.uuid4()),'workspace':str(native),
                    'model':'hy3-x','instruction':prompt,'businessInput':{'data_boundary':'all experiment input is in the task instruction above'},
                    'quotaRestorationConfirmed':True,'qualificationEnvelope':str(QUAL),'timeoutSeconds':300,
                    'softOutputCharacters':13000 if role=='source' else 5000,'cdpPort':18491,
                    'cliElectronPath':'D:/workbuddy/WorkBuddy.exe','workbuddyConfigDir':'[USER_HOME]/.workbuddy'}
                save(native/'input.json',job)
                p=subprocess.run(['D:/node/node.exe',str(GATEWAY/'scripts/hy3-native-paid-one-shot.mjs'),
                    '--input',str(native/'input.json'),'--output',str(native/'envelope.json')],cwd=GATEWAY,
                    capture_output=True,text=True,encoding='utf-8',timeout=420)
                save(job_dir/'invocation.json',{'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
                envelope=load(native/'envelope.json') if (native/'envelope.json').exists() else {}
                if envelope.get('status')!='verified_native_paid_one_shot':
                    raise RuntimeError('native_execution_not_verified:'+envelope.get('status','no_envelope'))
                output=envelope['output']; metadata={'platform':'WorkBuddy native desktop ask session',
                    'model':envelope['actualModels'],'request_models':envelope['requestModelIds'],
                    'app_version':envelope['staticNativeCapability']['appVersion'],
                    'tool_calls':envelope['toolCallCount'],'physical_supplier_calls':None,
                    'actual_cost_cny':None,'session_id':job['sessionId'],'evidence_path':str(native/'envelope.json'),
                    'native_helper_job_type':'receiver (registered helper route for all zero-tool experiment turns)',
                    'experiment_role':role,'complete_upstream_system_input_observed':False}
            elif platform=='flash':
                ledger=Path(sdk_ledger_dir) if sdk_ledger_dir else Path('[WORKSPACE]/.tmp/live-v2-sdk')/sha(str(job_dir.resolve()))[:20]
                save(job_dir/'sdk_ledger_pointer.json',{'path':str(ledger),'reason':'short Windows path; original requests and receipts remain in the pointed private ledger'})
                client=FlashSDKClient(ledger,budget_cap_cny='1',max_jobs=1)
                r=client.generate([{'role':'system','content':'Follow the controlled research task. Use no tools. Return only requested JSON.'},
                                  {'role':'user','content':prompt}],'inference',2048,'source' if role=='source' else 'target')
                output=r['output'];metadata={'platform':'DeepSeek Harness official installed SDK',
                    'model':r['receipt']['actual_model'],'provider':r['receipt']['provider'],
                    'app_version':'0.2.1-rc.3','desktop_bridge_used':False,
                    'physical_supplier_calls':r['receipt']['physical_request_count'],
                    'actual_cost_cny':None,'usage':r['receipt']['usage'],
                    'estimated_cost_cny':r['receipt']['estimated_peak_cost_cny'],
                    'estimate_is_invoice':False,'receipt':r['receipt']}
            else: raise ValueError('platform')
            save(job_dir/'raw_output.json',{'text':output,'sha256':sha(output)})
            text=output.strip()
            if text.startswith('```'):
                text=text[text.find('\n')+1:];text=text[:text.rfind('```')]
            if role=='source':parsed,adapter=parse_source(text)
            else:parsed,adapter=parse_json_object(text)
            metadata['serialization_adapter']=adapter
            if set(parsed.get('scenarios',{}))!=set(scenarios):raise ValueError('scenario_schema')
            result={'status':'ok','output':output,'parsed':parsed,'metadata':metadata,
                    'started_unix':start,'queue_seconds':queued-start,'inference_wall_seconds':time.time()-queued,
                    'end_to_end_seconds':time.time()-start,'prompt_sha256':sha(prompt),'output_sha256':sha(output)}
        except Exception as e:
            result={'status':'failed','error':str(e) if isinstance(e,(RuntimeError,ValueError)) else type(e).__name__,
                    'started_unix':start,'elapsed_seconds':time.time()-start,'automatic_retry':False,
                    'raw_output_retained':(job_dir/'raw_output.json').exists()}
    save(rp,result)
    return result
