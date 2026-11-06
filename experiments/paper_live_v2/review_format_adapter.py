"""Independent read-only check of the actual P01 source serialization repair."""
import hashlib,json,re
from pathlib import Path
from format_adapter import parse_source

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research_paper_v1/paper_live_v2'
p=BASE/'raw_experiment_data/qualification_isolated_v1/LIVE-P01.A_to_B.r0/source_initial_generation'
names=('raw_output.json','result.json','local_parse_recovery.json')
before={name:hashlib.sha256((p/name).read_bytes()).hexdigest() for name in names}
raw=json.loads((p/'raw_output.json').read_text(encoding='utf-8'))['text']
failed=json.loads((p/'result.json').read_text(encoding='utf-8'))
recovery=json.loads((p/'local_parse_recovery.json').read_text(encoding='utf-8'))
assert failed['status']=='failed'
parts=re.findall(r'"memory_text"\s*:\s*"(.*?)"\s*,\s*"claims"',raw,re.S)
assert len(parts)==3
names_s=('raw','summary','multi_source')
assert all(body==recovery['parsed']['scenarios'][name]['memory_text'] for body,name in zip(parts,names_s))
parsed,receipt=parse_source(raw)
assert parsed==recovery['parsed'] and receipt['strict_json'] is False and receipt['new_model_calls']==0
assert before=={name:hashlib.sha256((p/name).read_bytes()).hexdigest() for name in names}
report={'schema':'live-v2-format-adapter-independent-review-v1','date_local':'2026-11-06','case':'LIVE-P01.A_to_B.r0/source_initial_generation','actual_raw_json_failed':True,'three_actual_memory_text_segments_equal_after_repair':True,'raw_model_content_modified':False,'additional_model_calls':0,'original_failed_result_retained':True,'input_files_unchanged':True,'input_sha256':before,'scope':'Actual P01 three-string embedded-quote case only, not a theorem that every malformed JSON has a unique intended parse. No semantic or fact editing.','reporting_requirement':'Count original source strict-JSON failure and operational adapter recovery separately; mark post-observation format adaptation, apply identical rules to both platforms. Do not call the original model output schema-conforming.','adapter_code_sha256':hashlib.sha256(Path(__file__).with_name('format_adapter.py').read_bytes()).hexdigest()}
out=BASE/'raw_experiment_data/format_adapter_independent_review.json'
out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
