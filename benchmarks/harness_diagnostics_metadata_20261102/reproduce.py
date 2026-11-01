"""Validate only the public bundle's structure, hashes and aggregate counts.

Python standard library only. No model/account/network access. This does not
rerun models, authenticate private receipts, or reproduce semantic conclusions.
"""
from pathlib import Path
import hashlib,json,re

ROOT=Path(__file__).resolve().parent
FILES={'metadata.json','README.md','reproduce.py','seal.json'}
ROW_KEYS={'slot','batch_code','role','model_alias','reasoning_effort','max_tokens','status','error_class','single_allowed_stream','safe_usage','receipt_sha256','input_sha256'}
USAGE_KEYS={'inputTokens','cacheReadTokens','cacheWriteTokens','outputTokens','totalTokens'}
EXPECTED={'actual_calls':65,'verified_calls':60,'output_limit_failures':5,'max_calls':45,'off_calls':20,'generation_calls':28,'target_calls':37,'planned_not_executed':4}

def main():
 assert {p.name for p in ROOT.iterdir()if p.is_file()}==FILES,'unexpected_or_missing_public_file'
 m=json.loads((ROOT/'metadata.json').read_text(encoding='utf-8'))
 seal=json.loads((ROOT/'seal.json').read_text(encoding='utf-8'))
 assert set(seal)=={'schema','files'}and set(seal['files'])==FILES-{'seal.json'}
 assert seal['schema']=='harness-diagnostics-public-seal-v1'
 for name,digest in seal['files'].items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,('hash_mismatch',name)
 assert m['schema']=='harness-diagnostics-public-metadata-v1'
 rows=m['rows'];assert len(rows)==65
 assert [r['slot']for r in rows]==list(range(1,66))
 for r in rows:
  assert set(r)==ROW_KEYS
  assert r['batch_code']in('B01','B02','B03','B04')and r['role']in('generation','target')
  assert r['model_alias']=='deepseek-flash'and r['reasoning_effort']in('off','max')
  assert type(r['max_tokens'])is int and r['max_tokens']in(256,4096,12288)
  assert r['status']in('ok','error')and r['error_class']in('none','output_limit')
  assert (r['status']=='ok')==(r['error_class']=='none')and r['single_allowed_stream']is True
  u=r['safe_usage'];assert set(u)==USAGE_KEYS and all(type(v)is int and v>=0 for v in u.values())
  assert u['totalTokens']==u['inputTokens']+u['cacheReadTokens']+u['cacheWriteTokens']+u['outputTokens']
  assert u['outputTokens']<=r['max_tokens']
  if r['error_class']=='output_limit':assert u['outputTokens']==r['max_tokens']
  assert all(re.fullmatch('[a-f0-9]{64}',r[k])for k in ('receipt_sha256','input_sha256'))
 counts={'actual_calls':len(rows),'verified_calls':sum(r['status']=='ok'for r in rows),'output_limit_failures':sum(r['error_class']=='output_limit'for r in rows),
         'max_calls':sum(r['reasoning_effort']=='max'for r in rows),'off_calls':sum(r['reasoning_effort']=='off'for r in rows),
         'generation_calls':sum(r['role']=='generation'for r in rows),'target_calls':sum(r['role']=='target'for r in rows),
         'planned_not_executed':sum(b['planned_not_executed']for b in m['batches'])}
 assert counts==EXPECTED==m['counts']
 for b in m['batches']:
  n=sum(r['batch_code']==b['batch_code']for r in rows)
  assert n==b['actual_calls']and n+b['planned_not_executed']==b['planned_maximum']
 assert m['scope']['independent_stories']==4 and m['scope']['human_gold']is False
 assert m['scope']['semantic_reproducibility_claimed']is False and m['scope']['new_method_advantage_established']is False
 print(json.dumps({'status':'passed','scope':'public_metadata_internal_checks_only','counts':counts,'model_requests':0,'network_requests':0},ensure_ascii=False))

if __name__=='__main__':main()
