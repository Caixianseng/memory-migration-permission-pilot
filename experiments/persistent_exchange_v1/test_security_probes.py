"""MOCK-ONLY fixture prose; real SQLite/import guards, no model or SDK calls."""
from pathlib import Path
import json
import sqlite3
import tempfile
import unittest

from .prepare_data import build, permission_event
from .security_probes import run_security_probes, _ReadOnlyStore, _ReadOnlyPolicy
from .store import AgentStore, TrustedPolicy, export_package, import_package, digest


class SecurityProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Workspace-local temporary storage also exercises the actual Windows
        # paths used by the experiment. It is removed; no fixture is a result.
        cls.temp = tempfile.TemporaryDirectory(prefix='security-MOCK-ONLY-', dir=Path(__file__).resolve().parents[2])
        cls.root = Path(cls.temp.name)
        cases, cls.evaluation, _, _ = build()
        cls.manifest = {'root': str(cls.root), 'cases': [], 'main_records': []}
        for case in cases:
            cid = case['case_id']
            folder = cls.root/'cases'/cid
            stores, policy = {}, None
            try:
                policy = TrustedPolicy(folder/'policy.sqlite')
                artifacts = {}
                for agent in ('A', 'B'):
                    store = stores[agent] = AgentStore(folder/(agent+'.sqlite'), agent)
                    refs = [store.add_original(s['source_id'], s['text'], s['version'], s['origin'])
                            for s in case['agents'][agent]['sources']]
                    policy.register_sources(refs)
                    # Deliberately lossless fixture prose for deterministic
                    # exposure counts; this is never attributed to a model.
                    text = '\n'.join(s['text'] for s in case['agents'][agent]['sources'])
                    ids = [s['source_id'] for s in case['agents'][agent]['sources']]
                    artifact = store.add_memory('whole-initial', text, ids,
                                                provenance={'generator': 'MOCK-ONLY'})
                    artifacts[agent] = {'whole': artifact, 'chunks': []}
                    evidence = {'mock_only': True, 'source_protocol_conformance': True,
                                'actual_models': ['hy3']} if agent == 'A' else {
                                    'mock_only': True, 'source_protocol_conformance': True,
                                    'actual_model': 'deepseek-flash'}
                    if cid == cases[0]['case_id'] and agent == 'A':
                        evidence['source_protocol_conformance'] = False
                    source_file = cls.root/'source_jobs'/cid/agent/'initial'/'whole'/'result.json'
                    source_file.parent.mkdir(parents=True)
                    source_file.write_text(json.dumps({'memory': text, 'source_ids': ids, 'evidence': evidence},
                                                       ensure_ascii=False), encoding='utf-8')
                for direction in ('A_to_B', 'B_to_A'):
                    sender, recipient = direction.split('_to_')
                    own_ids = [s['source_id'] for s in case['agents'][recipient]['sources']]
                    policy.set_permissions(recipient, own_ids+permission_event(case, direction)['allowed'])
                cls.manifest['cases'].append({'case_id': cid, 'case_dir': str(folder),
                    'policy_epoch': policy.epoch, 'origins': case['agents'], 'artifacts': artifacts})
                for direction in ('A_to_B', 'B_to_A'):
                    sender, recipient = direction.split('_to_')
                    allowed = set(permission_event(case, direction)['allowed'])
                    source = next(s for s in case['agents'][sender]['sources'] if s['source_id'] in allowed)
                    raw = stores[sender].add_memory('approved-raw', source['text'], [source['source_id']], kind='raw')
                    packet = export_package(stores[sender], policy, recipient, [raw['memory_key']],
                                            batch_id=cid+'-'+direction+'-mock-approved')
                    job = cls.root/'receivers'/cid/direction
                    job.mkdir(parents=True)
                    packet_file = job/'transport.packet.json'
                    packet_file.write_text(json.dumps(packet, ensure_ascii=False), encoding='utf-8')
                    receiver = AgentStore(job/'receiver.sqlite', recipient)
                    try:
                        import_package(receiver, policy, packet)
                    finally:
                        receiver.close()
                    cls.manifest['main_records'].append({'case_id': cid, 'direction': direction, 'arm': 'raw',
                        'delivery': {'receiver_db': str(job/'receiver.sqlite'), 'batch_id': packet['batch_id'],
                            'packet_path': str(packet_file), 'packet_file_sha256': digest(packet_file.read_bytes()),
                            'policy_db': str(policy.path), 'policy_epoch': policy.epoch,
                            'memory_keys': [raw['memory_key']]}})
            finally:
                for resource in list(stores.values())+[policy]:
                    if resource is not None:
                        resource.close()
        cls.report = run_security_probes(cls.root, cls.manifest, cls.evaluation)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_actual_store_bindings_and_all_registered_offline_gates(self):
        summary = self.report['summary']
        self.assertEqual(summary['permission_views'], 24)
        self.assertEqual(summary['nonzero_old_whole_rejected'], 18)
        self.assertEqual(summary['zero_old_whole_allowed_by_permission_check'], 6)
        self.assertTrue(summary['all_available_whole_permission_results_as_expected'])
        self.assertEqual(summary['source_protocol_nonconformant_views'], 1)
        self.assertEqual(summary['mock_only_source_fixture_views'], 24)
        self.assertEqual(summary['unique_withdrawn_value_questions'], 42)
        self.assertEqual(summary['offline_potential_exposure_questions'], 42)
        self.assertFalse(summary['offline_potential_exposure_is_actual_delivery_leakage'])
        self.assertEqual(summary['copy_attack_attempts'], 72)
        self.assertEqual(summary['copy_attacks_rejected_as_expected'], 72)
        self.assertTrue(summary['all_main_inputs_byte_unchanged'])
        self.assertEqual(self.report['model_invocations'], 0)
        self.assertEqual(self.report['new_real_deliveries'], 0)
        self.assertTrue(all(not row['source_model_identity_verified']
                            for row in self.report['old_whole_permission_checks']))

    def test_read_only_adapters_reject_mutations(self):
        case = self.manifest['cases'][0]
        folder = Path(case['case_dir'])
        before = {p: digest(p.read_bytes()) for p in (folder/'A.sqlite', folder/'policy.sqlite')}
        store, policy = _ReadOnlyStore(folder/'A.sqlite', 'A'), _ReadOnlyPolicy(folder/'policy.sqlite')
        try:
            epoch = policy.epoch
            with self.assertRaises(sqlite3.DatabaseError):
                store.db.execute('DELETE FROM originals')
            with self.assertRaises(sqlite3.DatabaseError):
                policy.db.execute("UPDATE policy_metadata SET value='999' WHERE key='epoch'")
            with self.assertRaises(sqlite3.DatabaseError):
                policy.db.execute("ATTACH DATABASE ':memory:' AS forbidden")
            self.assertEqual(policy.epoch, epoch)
        finally:
            policy.close()
            store.close()
        self.assertEqual(before, {p: digest(p.read_bytes()) for p in before})

    def test_cached_report_is_stable_without_any_new_model_or_main_write(self):
        repeated = run_security_probes(self.root, self.manifest, self.evaluation)
        self.assertEqual(repeated, self.report)

    def test_changed_initial_whole_cannot_be_accepted_as_stored_model_artifact(self):
        case = self.manifest['cases'][0]
        path = self.root/'source_jobs'/case['case_id']/'A'/'initial'/'whole'/'result.json'
        original = path.read_bytes()
        altered = json.loads(original)
        altered['memory'] += '\nMOCK-ONLY altered source result'
        path.write_text(json.dumps(altered, ensure_ascii=False), encoding='utf-8')
        try:
            with self.assertRaisesRegex(RuntimeError, 'actual_whole_artifact_binding_mismatch'):
                run_security_probes(self.root, self.manifest, self.evaluation)
        finally:
            path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
