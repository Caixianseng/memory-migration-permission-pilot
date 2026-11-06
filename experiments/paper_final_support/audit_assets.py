"""Read-only audit of frozen research code, aggregate results and actual databases."""
import ast
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'research_paper_v1/paper_final/evidence/core_asset_audit.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    modules = []
    base = ROOT/'experiments/persistent_exchange_v1'
    for name in ['store.py','source_registry.py','source_registry_audit.py','model_runtime.py',
                 'receiver_runtime.py','receiver_paid_runtime.py','read_receiver.py','run_study.py',
                 'evaluate.py','finalize.py','security_probes.py']:
        p = base/name
        tree = ast.parse(p.read_text(encoding='utf-8-sig'))
        modules.append({'path':str(p.relative_to(ROOT)), 'sha256':sha(p),
            'definitions':[{'name':n.name,'line':n.lineno} for n in ast.walk(tree)
                           if isinstance(n,(ast.FunctionDef,ast.ClassDef))]})
    docs = ['stage1_research_audit.md','stage2_evidence_gap/go_no_go_decision.md',
            'stage3_research_pivot/final_research_direction_decision.md',
            'publication_reassessment/publication_value_reassessment.md',
            'publication_reassessment/three_candidate_papers.md',
            'publication_reassessment/journal_publication_evidence.md']
    reviewed_docs = []
    for name in docs:
        p = ROOT/'research_paper_v1'/name
        text = p.read_text(encoding='utf-8-sig')
        reviewed_docs.append({'path':str(p.relative_to(ROOT)), 'sha256':sha(p),'characters_read':len(text)})
    frozen = ROOT/'results/persistent_exchange_v1'
    databases = []
    patterns = ['cases/*/*.sqlite','receiver_jobs/*/*/*/receiver.sqlite']
    for pattern in patterns:
        for p in sorted(frozen.glob(pattern)):
            before = sha(p)
            con = sqlite3.connect(p.resolve().as_uri()+'?mode=ro',uri=True)
            try:
                con.execute('PRAGMA query_only=ON')
                tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                permitted = tables.intersection({'originals','memories','batches','events','sources','source_versions','grants','seals','lineage_metadata'})
                counts = {t:con.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in sorted(permitted)}
                mode = con.execute('PRAGMA journal_mode').fetchone()[0]
                check = con.execute('PRAGMA quick_check').fetchone()[0]
            finally:
                con.close()
            assert sha(p) == before, 'historical database changed'
            databases.append({'path':str(p.relative_to(ROOT)), 'sha256':before,'bytes':p.stat().st_size,
                              'journal_mode':mode,'quick_check':check,'counts':counts})
    public = ROOT/'benchmarks/persistent_exchange_v1_public_20261105'
    data = []
    for name in ['cases.public.jsonl','records.public.json','source_attempts.public.json',
                 'security_probes.public.json','evaluation_report.public.json','audit_summary.public.json']:
        p = public/name
        body = p.read_text(encoding='utf-8-sig')
        value = [json.loads(line) for line in body.splitlines() if line] if p.suffix=='.jsonl' else json.loads(body)
        data.append({'path':str(p.relative_to(ROOT)),'sha256':sha(p),'top_level_type':type(value).__name__,
                     'top_level_count':len(value)})
    report={'schema':'paper-final-core-audit-v1','checked_utc':datetime.now(timezone.utc).isoformat(),
            'reading_scope':'full named core modules, six required reports, bounded public result files, actual databases through read-only connections',
            'modules':modules,'required_reports':reviewed_docs,'historical_data':data,'databases':databases,
            'database_count':len(databases),'all_database_quick_checks_ok':all(x['quick_check']=='ok' for x in databases),
            'historical_database_bytes_unchanged':True,'paid_model_calls':0,'experiment_reruns':0,
            'caveat':'No private native session or credentials inspected; existing reports supplement targeted semantic code review.'}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in {'modules','required_reports','historical_data','databases'}},ensure_ascii=False))


if __name__=='__main__': main()
