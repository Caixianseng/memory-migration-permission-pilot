"""Read-only output recovery; no model request or original result modification."""
import json,hashlib
from pathlib import Path
from .format_adapter import parse_source,parse_json_object
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def recover(job_dir,role,scenarios):
    f=job_dir/'raw_output.json'
    if not f.exists():return None
    raw=load(f);text=raw['text'].strip()
    if hashlib.sha256(raw['text'].encode()).hexdigest()!=raw['sha256']:raise ValueError('raw_output_changed')
    if text.startswith('```'):
        text=text[text.find('\n')+1:];text=text[:text.rfind('```')]
    try:parsed,adapter=parse_source(text) if role=='source' else parse_json_object(text)
    except (ValueError,json.JSONDecodeError):return None
    if set(parsed.get('scenarios',{}))!=set(scenarios):return None
    cp=load(job_dir/'contract.json');previous=load(job_dir/'result.json')
    if cp['platform']=='hy3':
        env=load(job_dir/'native/envelope.json')
        if env.get('status')!='verified_native_paid_one_shot' or env['output']!=raw['text']:return None
        metadata={'platform':'WorkBuddy native desktop ask session','model':env['actualModels'],
            'request_models':env['requestModelIds'],'app_version':env['staticNativeCapability']['appVersion'],
            'actual_cost_cny':None,'physical_supplier_calls':None,'tool_calls':env['toolCallCount'],
            'evidence_path':str(job_dir/'native/envelope.json')}
    else:
        ledger=Path(load(job_dir/'sdk_ledger_pointer.json')['path']) if (job_dir/'sdk_ledger_pointer.json').exists() else job_dir/'sdk.private'
        receipt=load(ledger/'job-inference/receipt.json')
        if receipt.get('status')!='ok' or receipt.get('response_sha256')!=raw['sha256']:return None
        metadata={'platform':'DeepSeek Harness official installed SDK','model':receipt['actual_model'],
            'provider':receipt['provider'],'app_version':'0.2.1-rc.3','desktop_bridge_used':False,
            'physical_supplier_calls':receipt['physical_request_count'],'actual_cost_cny':None,
            'usage':receipt['usage'],'estimated_cost_cny':receipt['estimated_peak_cost_cny'],
            'estimate_is_invoice':False,'receipt':receipt}
    metadata['serialization_adapter']=adapter
    return {**previous,'status':'ok','output':raw['text'],'parsed':parsed,'metadata':metadata,
        'original_failure_path':str(job_dir/'result.json'),'format_recovery':adapter,
        'inference_wall_seconds':previous['elapsed_seconds'],'local_recovery_new_model_calls':0}
