"""Independently read F22/F23 SQLite effects and grants in read-only mode."""
import hashlib
import json
import sqlite3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
RUN=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/protocol/protocol_run_20261106_v1'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    rows=[]
    for case in ('F22','F23'):
        for method in ('source_dynamic_version_no_tx','transaction_reference','complete_host'):
            folder=RUN/(case+'-'+method);files=[folder/'B.sqlite',folder/'policy.sqlite']
            before=[digest(p)for p in files]
            receiver=sqlite3.connect(files[0].resolve().as_uri()+'?mode=ro',uri=True)
            policy=sqlite3.connect(files[1].resolve().as_uri()+'?mode=ro',uri=True)
            try:
                table='nonatomic_effects'if method=='source_dynamic_version_no_tx'else'batches'
                row={'case':case,'method':method,
                     'receiver_effects':receiver.execute('SELECT count(*) FROM '+table).fetchone()[0],
                     'B_grants':policy.execute('SELECT count(*) FROM grants WHERE recipient_id=?',('B',)).fetchone()[0],
                     'seal_consumption':[r[0]for r in policy.execute('SELECT consumed_by FROM seals')],
                     'receiver_quick_check':receiver.execute('PRAGMA quick_check').fetchone()[0]}
            finally:receiver.close();policy.close()
            row['read_only_hashes_unchanged']=before==[digest(p)for p in files]
            rows.append(row)
    (RUN/'direct_sqlite_crosscheck.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(rows,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
