"""Verify public report/aggregate snapshot only; no raw-model re-scoring."""
import hashlib,json,os
from pathlib import Path
root=Path(__file__).resolve().parents[1]
if os.name=='nt' and not str(root).startswith('\\\\?\\'):root=Path('\\\\?\\'+str(root))
m=json.loads((root/'benchmarks/research_release_20261106_manifest.json').read_text(encoding='utf-8'))
for x in m['files']:
 p=root/x['path'];assert p.resolve().is_relative_to(root.resolve())
 assert hashlib.sha256(p.read_bytes()).hexdigest()==x['sha256'],x['path']
a=json.loads((root/'research_paper_v1/RELEASE_RESULTS_20261106.json').read_text(encoding='utf-8'))
assert a['main_qualification']['main_inference_jobs']==480
assert a['main_qualification']['legal_reference_matches']==538
assert a['main_qualification']['legal_answer_fields']==540
assert a['new_evaluation']['human_confirmed']==1
assert a['new_evaluation']['frozen_250_agent_277_score']==0
print(json.dumps({'status':'PASS','published_files_verified':len(m['files']),'model_calls':0,'raw_model_re_scoring':False,'scope':m['scope']},ensure_ascii=False))
