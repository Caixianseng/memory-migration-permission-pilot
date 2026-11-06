"""Archive exact already-hashed builder bytes after runtime-only schema extension."""
import hashlib,json
from pathlib import Path

p=Path(__file__).with_name('dataset_gold.py')
s=p.read_text(encoding='utf-8')
s=s.replace('def bundle_schema(schema,scenarios=SCENARIOS):','def bundle_schema(schema):')
s=s.replace("'required':list(scenarios),'properties':{s:schema for s in scenarios}","'required':list(SCENARIOS),'properties':{s:schema for s in SCENARIOS}")
s=s.replace('生成所列记忆表示','生成三种记忆表示')
s=s.replace('bundle_schema(SOURCE_SCHEMA,scenarios)','bundle_schema(SOURCE_SCHEMA)')
s=s.replace('bundle_schema(RECEIVER_SCHEMA,scenarios)','bundle_schema(RECEIVER_SCHEMA)')
root=p.resolve().parents[2]
manifest=json.loads((root/'research_paper_v1/paper_live_v2/raw_experiment_data/dataset/dataset_manifest.json').read_text(encoding='utf-8'))
assert hashlib.sha256(s.encode()).hexdigest()==manifest['script_sha256'],'No archive written unless exact frozen-generation hash matches.'
target=p.with_name('dataset_gold_generation_snapshot.py')
if target.exists():assert target.read_bytes()==s.encode()
else:target.write_bytes(s.encode())
print('Exact generation snapshot archived:',manifest['script_sha256'])
