"""One hash-bound, independently AI-reviewed source artifact projection.

This is post-hoc adjudication, not a general permission to strip qualifiers.
The source's refusal/omission and strict format failure remain in the data.
"""
import hashlib,json,time
from .live_runtime import OUT,load,save

def main():
    job=OUT/'raw_experiment_data/qualification_isolated_v1/LIVE-P07.A_to_B.r1/source_initial_generation'
    raw=load(job/'raw_output.json');text=raw['text'];expected='347aedaf5ea0848038b311914da01ef37ce78e9d7b26a6e6a916652836a335e9'
    assert hashlib.sha256(text.encode()).hexdigest()==expected==raw['sha256']
    env=load(job/'native/envelope.json');assert env['status']=='verified_native_paid_one_shot' and env['output']==text
    position=text.index('{');prefix=text[:position];parsed=json.loads(text[position:])
    assert '{' not in prefix and '}' not in prefix
    assert set(parsed)=={'scenarios'} and set(parsed['scenarios'])=={'raw','summary','multi_source'}
    assert all(set(s)=={'memory_text','claims'} and s['claims']==[] for s in parsed['scenarios'].values())
    review={'raw_output_sha256':expected,'observed_unix':time.time(),'judge':'AI root, with separate same-family AI contextual check',
        'human_confirmed':False,'prefix_original_text':prefix,'body_original_text':text[position:],
        'finding':'Prefix explains deliberate omission of an internally tagged audit code; no qualifier making the public facts hypothetical or untrustworthy.',
        'scope':'only this hash-bound record; no general prose stripping enabled','strict_json':False,
        'original_format_failure_retained':True,'original_fact_omission_retained':True,
        'host_dependency_scope_unchanged':True,'new_model_calls':0}
    if not (job/'reviewed_preface_projection.json').exists():save(job/'reviewed_preface_projection.json',review)
    metadata={'platform':'WorkBuddy native desktop ask session','model':env['actualModels'],
        'request_models':env['requestModelIds'],'app_version':env['staticNativeCapability']['appVersion'],
        'actual_cost_cny':None,'physical_supplier_calls':None,'tool_calls':env['toolCallCount'],
        'evidence_path':str(job/'native/envelope.json'),'serialization_adapter':review}
    previous=load(job/'result.json')
    result={**previous,'status':'ok','output':text,'parsed':parsed,'metadata':metadata,
        'original_failure_path':str(job/'result.json'),'format_recovery':review,
        'inference_wall_seconds':previous['elapsed_seconds'],'local_recovery_new_model_calls':0}
    if not (job/'local_parse_recovery.json').exists():save(job/'local_parse_recovery.json',result)
    print(json.dumps({'case':'LIVE-P07.A_to_B.r1','hash':expected,'original_unchanged':True,'new_model_calls':0}))
if __name__=='__main__':main()
