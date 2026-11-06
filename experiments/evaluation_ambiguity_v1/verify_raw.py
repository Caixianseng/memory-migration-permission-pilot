"""Read-only equivalence check back to all 96 historical raw JSON answers."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
AUDIT=ROOT/'research_paper_v1/evaluation_ambiguity_audit_20261106'
def load(p):return json.loads(p.read_text(encoding='utf-8-sig'))
raw=load(ROOT/'benchmarks/persistent_exchange_v1_public_20261105/records.public.json')
items=load(ROOT/'research_paper_v1/paper_final/evidence/human/items.blinded.json')['items']
old={r['item_id']:r for r in map(json.loads,(ROOT/'research_paper_v1/paper_final/evidence/ai_evaluation/final.jsonl').read_text(encoding='utf-8').splitlines())}
indexed={}
for r in raw:
    text=r['answers_raw_utf8']
    assert hashlib.sha256(text.encode('utf-8')).hexdigest()==r['answers_raw_sha256']
    parsed=json.loads(text)
    assert parsed==r['answers']
    for q,a in parsed.items():indexed[(r['case_id'],r['direction'],r['arm'],q)]=a
assert len(raw)==96 and len(indexed)==768
for i in items:
    key=old[i['item_id']]
    assert i['answer']==indexed[tuple(key[k] for k in ['case_id','direction','arm','question_id'])]
assert len(items)==768
result={'schema':'raw-output-equivalence-v1','historical_raw_output_envelopes':96,
        'strict_JSON_parsed':96,'raw_text_sha256_verified':96,'parsed_maps_equal_public_records':96,
        'answer_fields_equal_reviewed_items':768,'modified_source_files':0,'model_calls':0,
        'scope':'Checks raw output bytes and answer-field equivalence; AI semantic reading remains separately disclosed.'}
(AUDIT/'raw_output_equivalence_receipt.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
