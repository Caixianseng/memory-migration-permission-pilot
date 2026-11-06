"""Read-only classification of a completed raw qualification matrix.

Used after the v2 performance-only instrumentation error; never reruns a case.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def main():
    path=Path(sys.argv[1]).resolve()
    config=json.loads((path/'config.json').read_text(encoding='utf8'))
    rows=[json.loads(s)for s in (path/'raw.jsonl').read_text(encoding='utf8').splitlines()]
    assert len(rows)==len(config['cases'])*len(config['methods'])
    assert len({(r['case_id'],r['method'])for r in rows})==len(rows)
    output=[]
    for method in config['methods']:
        selected=[r for r in rows if r['method']==method]
        output.append({'method':method,'cases':len(selected),'strict_oracle_matches':sum(r['matches_strict_frozen_oracle']for r in selected),
          'unauthorized_case_count':sum(r['unauthorized_first_delivery']for r in selected),
          'stale_epoch_case_count':sum(r['stale_epoch_admission']for r in selected),
          'duplicate_effects':sum(r['duplicate_effects']for r in selected),
          'legal_missing_case_count':sum(r['legal_commit_missing']for r in selected),
          'current_policy_legal_false_reject_case_count':sum(r['current_policy_legal_false_reject']for r in selected),
          'recovery_confirmed':sum(r['recovery_confirmed']is True for r in selected),
          'recovery_evaluable':sum(r['recovery_confirmed']is not None for r in selected)})
    sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
    result={'schema':'paper-final-qualification-completion-v2','finished_utc':datetime.now(timezone.utc).isoformat(),
      'targeted_cases':len(config['cases']),'method_rows':len(rows),'summary':output,
      'raw_sha256':sha(path/'raw.jsonl'),'config_sha256':sha(path/'config.json'),
      'runner_sha256':sha(path/'code/runner.py'),'adapter_sha256':sha(path/'code/durable_delivery.py'),
      'source_sha256':config['source_sha256'],
      'source_unchanged':sha(ROOT/'experiments/persistent_exchange_v1/store.py')==config['source_sha256'],
      'qualification_execution':'all cases completed; no case rerun by this summary',
      'performance_execution':'separate corrective performance-only run; original v2 failed on Windows RSS instrumentation',
      'new_paid_model_calls':0,'github_writes':0}
    (path/'qualification_summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
