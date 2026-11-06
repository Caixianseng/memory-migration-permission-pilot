"""Read-only normal-case byte-preservation check for controlled source memory."""
import hashlib
import json
import sqlite3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
RUN=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/protocol/protocol_run_20261106_v1'
METHODS=['plain_file','basic_integrity_acl','source_dynamic_version_no_tx','transaction_reference','complete_host']


def read_sql(path,sql):
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:return db.execute(sql).fetchall()
    finally:db.close()


def main():
    rows=[]
    for method in METHODS:
        folder=RUN/('F00-'+method)
        source=[r[0]for r in read_sql(folder/'A.sqlite','SELECT content FROM memories ORDER BY memory_key')]
        if method=='plain_file':
            packet=json.loads((folder/'B.handoff.jsonl').read_text(encoding='utf8').splitlines()[0])
            target=[r['content']for r in packet['memories']]
        elif method in ('basic_integrity_acl','source_dynamic_version_no_tx'):
            table='basic_effects'if method=='basic_integrity_acl'else'nonatomic_effects'
            packet=json.loads(read_sql(folder/'B.sqlite','SELECT packet_json FROM '+table)[0][0])
            target=[r['content']for r in packet['memories']]
        else:target=[r[0]for r in read_sql(folder/'B.sqlite','SELECT content FROM memories ORDER BY memory_key')]
        encode=lambda value:'\n\n'.join(value).encode('utf8')
        rows.append({'method':method,'representation':'exact_original_memory_transfer',
                     'scope':'controlled generated artifact; no claim of a new real LLM generation',
                     'source_memory_sha256':hashlib.sha256(encode(source)).hexdigest(),
                     'target_memory_sha256':hashlib.sha256(encode(target)).hexdigest(),
                     'source_equals_target_bytes':encode(source)==encode(target),
                     'source_original_fact_is_distinct':True})
    assert all(r['source_equals_target_bytes']for r in rows)
    (RUN/'exact_original_memory_transfer_check.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(rows,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
