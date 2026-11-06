"""Read-only consistency checks plus a new stage-1 artifact manifest.

This checks local links, JSON readability and key reported counts, not scientific
novelty, full raw-native authenticity, or external publication status.
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / 'research_paper_v1'
OUT = DOCS / 'evidence/stage1_completion_receipt.json'


def read(name):
    return json.loads((DOCS / 'evidence' / name).read_text(encoding='utf-8'))


def main():
    bad_links = []
    for doc in DOCS.glob('*.md'):
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            target = target.strip('<>').split('#')[0]
            if not target or '://' in target:
                continue
            if not (doc.parent / target).exists():
                bad_links.append({'file': doc.name, 'target': target})
    assert not bad_links, bad_links
    checked_json = 0
    for file in (DOCS / 'evidence').rglob('*.json'):
        if file == OUT:
            continue
        json.loads(file.read_text(encoding='utf-8'))
        checked_json += 1
    bounds = read('evidence_bounds_qualification.json')
    assert len(bounds['rows']) == bounds['summary']['evidence_permission_cases'] == 1296
    assert bounds['summary']['disagreements'] == 0
    assert all(r['set_baseline'] == r['enumeration_oracle'] for r in bounds['rows'])
    assert sum(r['set_baseline'] == 'unknown' for r in bounds['rows']) == 369
    epoch = read('epoch_scope_probe.json')
    assert epoch['counts'] == {'cases': 7, 'eligible_cases': 4, 'availability_rejections': 3, 'unsafe_acceptances': 0}
    store = ROOT / 'experiments/persistent_exchange_v1/store.py'
    assert hashlib.sha256(store.read_bytes()).hexdigest() == epoch['frozen_store_sha256']
    catalog = read('existing_evidence_case_catalog.json')
    assert catalog['counts'] == {'source_result_attempts': 132, 'successful_status': 106, 'closed_status': 26}
    assert hashlib.sha256((ROOT / catalog['source_relative_path']).read_bytes()).hexdigest() == catalog['source_sha256']
    nx = read('external_candidates/networkx_qualification_results.json')
    assert nx['exit_code'] == 0
    assert nx['probes']['networkx']['cases'] == 3200
    assert nx['probes']['networkx']['mismatches'] == 0
    inventory = read('asset_index.json')
    assert inventory['persistent_exchange']['complete_core_scores_and_intervals_match'] is True
    assert inventory['fresh40']['source_rows_unchanged'] is True
    files = list(DOCS.glob('*.md')) + [p for p in (DOCS/'evidence').rglob('*') if p.is_file() and p != OUT]
    files += [p for p in (ROOT/'experiments/paper_v1').rglob('*.py') if 'deps' not in p.parts]
    manifest = [{'path': p.relative_to(ROOT).as_posix(), 'bytes': p.stat().st_size,
                 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(set(files))]
    report = {'schema': 'paper-v1-stage1-audit-receipt-v1', 'date': '2026-11-05',
              'artifact_checks': 'pass', 'json_files_parsed': checked_json,
              'broken_local_markdown_links': bad_links, 'files': manifest,
              'scientific_direction_gate': 'not_passed',
              'reason': 'No established differentiating contribution against verified close work and strong simple baselines.',
              'new_paid_model_calls': 0, 'github_writes': 0,
              'does_not_establish': ['Novelty or algorithm superiority.', 'Complete commercial-agent internal provenance.', 'Full private-native replay.']}
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k != 'files'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
