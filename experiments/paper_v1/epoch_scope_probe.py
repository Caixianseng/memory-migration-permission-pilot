"""Audit global-epoch availability against the unchanged historical SQLite host.

Synthetic local diagnostic only; no model, provider, socket or original-data access.
An acceptance oracle here preserves invalidation after relevant revoke-and-regrant.
It is a specified application contract, not an implementation of a new protocol.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / 'experiments/persistent_exchange_v1/store.py'


def load_store():
    spec = importlib.util.spec_from_file_location('frozen_exchange_store', STORE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_case(name, expected_eligible):
    api = load_store()
    with tempfile.TemporaryDirectory(prefix='paper_v1_epoch_') as directory:
        folder = Path(directory)
        sender = api.AgentStore(folder / 'sender.sqlite', 'A')
        receiver = api.AgentStore(folder / 'receiver.sqlite', 'B')
        policy = api.TrustedPolicy(folder / 'policy.sqlite')
        try:
            relevant = sender.add_original('S-relevant', 'Synthetic delivery date: 2027-03-01.')
            unrelated = sender.add_original('S-unrelated', 'Synthetic other project: beta.')
            policy.register_sources([relevant, unrelated])
            policy.set_permissions('B', ['S-relevant'])
            memory = sender.add_memory('M-one', relevant['text'], source_ids=['S-relevant'], kind='raw')
            packet = api.export_package(sender, policy, 'B', [memory['memory_key']], batch_id='batch-one')
            seal_epoch = packet['epoch']
            if name == 'unrelated_recipient_grant':
                policy.set_permissions('C', ['S-unrelated'])
            elif name == 'unrelated_source_update':
                update = sender.add_original('S-unrelated', 'Synthetic other project: gamma.', version=2)
                policy.register_sources([update])
            elif name == 'same_permissions_written_again':
                policy.set_permissions('B', ['S-relevant'])
            elif name == 'relevant_revocation':
                policy.set_permissions('B', [])
            elif name == 'revoke_then_regrant':
                policy.set_permissions('B', [])
                policy.set_permissions('B', ['S-relevant'])
            elif name == 'relevant_source_update':
                update = sender.add_original('S-relevant', 'Synthetic delivery date: 2028-03-01.', version=2)
                policy.register_sources([update])
            elif name != 'no_change':
                raise ValueError(name)
            current_authority_valid = True
            current_authority_error = None
            try:
                policy.validate_dependencies('B', packet['sources'])
            except api.StoreError as exc:
                current_authority_valid = False
                current_authority_error = str(exc)
            accepted = False
            import_error = None
            try:
                api.import_package(receiver, policy, packet)
                accepted = True
            except api.StoreError as exc:
                import_error = str(exc)
            rows = receiver.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0]
            assert rows == int(accepted), (name, rows, accepted)
            # These assertions verify the historical behavior, not statistical evidence.
            assert accepted == (name == 'no_change'), (name, accepted)
            return {
                'case': name, 'eligible_under_declared_contract': expected_eligible,
                'source_and_grant_valid_now': current_authority_valid,
                'current_authority_error': current_authority_error,
                'seal_epoch': seal_epoch, 'final_epoch': policy.epoch,
                'accepted_by_frozen_host': accepted, 'import_error': import_error,
                'receiver_batches': rows,
                'availability_rejection_under_declared_contract': expected_eligible and not accepted,
                'unsafe_acceptance_under_declared_contract': not expected_eligible and accepted,
            }
        finally:
            sender.close()
            receiver.close()
            policy.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    before = hashlib.sha256(STORE.read_bytes()).hexdigest()
    cases = [(name, eligible) for name, eligible in (
        ('no_change', True), ('unrelated_recipient_grant', True),
        ('unrelated_source_update', True), ('same_permissions_written_again', True),
        ('relevant_revocation', False), ('revoke_then_regrant', False),
        ('relevant_source_update', False),
    )]
    rows = [run_case(name, eligible) for name, eligible in cases]
    after = hashlib.sha256(STORE.read_bytes()).hexdigest()
    assert before == after
    result = {
        'schema': 'paper-v1-epoch-scope-probe-v1', 'date': '2026-11-05',
        'mode': 'deterministic synthetic diagnostic; no model calls',
        'frozen_store_sha256': before, 'frozen_store_unchanged': before == after,
        'contract': 'A sealed attempt remains eligible only if its declared source version/content and recipient grant remain valid throughout the interval. Unrelated changes and identical permission rewrites do not invalidate it. A relevant revoke followed by regrant does invalidate the old attempt.',
        'contract_status': 'Diagnostic proposal, not silently substituted for the historical global-epoch contract.',
        'rows': rows,
        'counts': {'cases': len(rows),
                   'eligible_cases': sum(r['eligible_under_declared_contract'] for r in rows),
                   'availability_rejections': sum(r['availability_rejection_under_declared_contract'] for r in rows),
                   'unsafe_acceptances': sum(r['unsafe_acceptance_under_declared_contract'] for r in rows)},
        'limitations': ['Hand-selected boundary cases, not a representative workload or independent project sample.',
                       'Availability relative to an explicit narrower contract; not a vulnerability inside the original global-epoch design.',
                       'Current-state-only revalidation is insufficient for the revoke-then-regrant rule.',
                       'No improved implementation, cost advantage or novelty is established by this probe.'],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result['counts'], ensure_ascii=False))


if __name__ == '__main__':
    main()
