"""Count public historical attempt statuses without re-labelling outcomes.

Mapping to follow-up evidence needs is an audit interpretation, not new truth
labels, a proof that evidence can be obtained, or a claim of successful repair.
"""
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'benchmarks/persistent_exchange_v1_public_20261105/source_attempts.public.json'
OUT = ROOT / 'research_paper_v1/evidence/existing_evidence_case_catalog.json'

NEEDS = {
    'success': ('usable_recorded_output', 'Existing input/output and permission checks remain required; success is not hidden-source completeness.'),
    'tool_protocol_failed_closed': ('reported_protocol_violation', 'A local native scope audit is needed to diagnose the actual operation; a new receipt cannot erase an already violated execution protocol.'),
    'pre_model_creation_closed': ('no_generated_candidate', 'No old artifact can be restored by evidence alone; a separately authorized fresh generation would be required.'),
    'missing_output_tool_protocol_closed': ('no_usable_output_and_protocol_failure', 'Need an attributable complete artifact and a compliant execution; do not infer either from absence.'),
    'terminal_queue_no_artifact_closed': ('terminal_without_artifact_execution_unknown', 'Additional native status may clarify execution; no evidence here guarantees recovery, and late artifacts must obey attempt/version fencing.'),
    'output_truncated_closed': ('incomplete_candidate', 'More provenance does not complete truncated text; any regeneration is a new attempt, not relabelled historical success.'),
}


def main():
    before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    attempts = json.loads(SOURCE.read_text(encoding='utf-8'))
    assert set(r['source_attempt_status'] for r in attempts) <= set(NEEDS)
    groups = []
    for status, (category, need) in NEEDS.items():
        rows = [r for r in attempts if r['source_attempt_status'] == status]
        groups.append({'status': status, 'count': len(rows), 'diagnostic_category': category,
                       'case_ids': sorted({r['case_id'] for r in rows}),
                       'attempt_ids': [r['attempt_id'] for r in rows],
                       'platform_counts': dict(Counter(r['platform'] for r in rows)),
                       'followup_requirement_not_observed_outcome': need})
    after = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert before == after
    report = {'schema': 'paper-v1-historical-evidence-catalog-v1', 'date': '2026-11-05',
              'source_relative_path': str(SOURCE.relative_to(ROOT)), 'source_sha256': before,
              'source_unchanged': True, 'source_scope': 'public projection of historical source result attempts; no native history replay',
              'counts': {'source_result_attempts': len(attempts),
                         'successful_status': sum(r['source_attempt_status'] == 'success' for r in attempts),
                         'closed_status': sum(r['source_attempt_status'] != 'success' for r in attempts)},
              'groups': groups,
              'independent_units_note': 'Attempts and status counts are not independent business projects or population failure rates.',
              'result': 'The 26 closed attempts have heterogeneous causes. They are not 26 recoverable missing-provenance cases. This inventory alone does not demonstrate benefit from a new evidence-completion algorithm.',
              'new_model_calls': 0}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['counts']))


if __name__ == '__main__':
    main()
