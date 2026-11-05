"""MOCK-only delivery integration tests; no model, native app, or study result.

Every source/result/repair below is explicitly MOCK and is written only below
a TemporaryDirectory, never the real results directory. The real store,
gateway export/import and receiver restart are exercised without model calls.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from . import run_study as study
from .prepare_data import permission_event
from .read_receiver import read_batch


class ProtocolFilteredDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MOCK-persistent-delivery-')
        self.root = Path(self.temp.name).resolve()
        self.assertFalse(self.root.is_relative_to((study.REPO/'results').resolve()))
        self.no_model = patch.object(study, 'generate_memory',
                                     side_effect=AssertionError('MOCK tests must never call a model'))
        self.model = self.no_model.start()

    def tearDown(self):
        self.no_model.stop()
        self.temp.cleanup()

    def mock_case(self, percent):
        case = {'case_id': 'MOCK-protocol-delivery-r'+str(percent), 'sources_per_agent': 4,
                'revocation_percent': percent, 'agents': {}, 'chunks': {}}
        for agent in ('A', 'B'):
            sources = [{'source_id': 'MOCK-'+agent+'-source-'+str(i),
                        'text': 'MOCK raw original '+agent+' '+str(i), 'version': 1,
                        'origin': {'case_id': case['case_id'], 'agent_id': agent,
                                   'record_type': 'MOCK', 'synthetic': True, 'MOCK_fixture': True}}
                       for i in range(4)]
            case['agents'][agent] = {'sources': sources, 'MOCK_fixture': True}
        for agent in ('A', 'B'):
            direction = agent+'_to_'+('B' if agent == 'A' else 'A')
            event = permission_event(case, direction)
            if percent:
                self.assertEqual(len(event['revoked']), 1)
                # Put the withdrawn source and one legal source in chunk0,
                # leaving chunk1 clean. This is only a controlled MOCK test.
                case['chunks'][agent] = [[event['revoked'][0], event['allowed'][0]],
                                         event['allowed'][1:]]
            else:
                ids = [s['source_id'] for s in case['agents'][agent]['sources']]
                case['chunks'][agent] = [ids[:2], ids[2:]]
        return case

    def mock_sources(self, case, failures=(), scope_failures=()):
        """Persist MOCK initial/repair artifacts without invoking generation."""
        failures = set(failures)
        scope_failures = set(scope_failures)
        saved = {}
        for phase in ('initial', 'repair'):
            for job in study.source_jobs(self.root, [case], phase):
                key = (job['agent'], phase, job['group'])
                conforms = key not in failures
                body = {'MOCK_fixture': True, 'platform': job['platform'], 'source_ids': job['source_ids'],
                        'memory': 'MOCK_MEMORY::'+'::'.join(key)+
                                  ('::CLEAN' if conforms else '::PROTOCOL_REJECTED_CANARY'),
                        'evidence': {'MOCK_fixture': True, 'platform': 'MOCK_NO_PROVIDER',
                                     'actual_model': 'MOCK_NOT_A_MODEL',
                                     'source_protocol_conformance': conforms,
                                     'session_id': 'MOCK-session-'+'-'.join(key),
                                     'task_id': 'MOCK-task-'+'-'.join(key),
                                     'protocol_issues': [] if conforms else ['MOCK_native_protocol_failure'],
                                     'MOCK_retained_cost_record': 'MOCK_NOT_REAL_MONEY'},
                        'wall_ms': 0, 'MOCK_generation_calls': 0}
                body['evidence']['artifact_sha256'] = study.digest(body['memory'])
                path = Path(job['job_dir'])/'result.json'
                self.assertTrue(path.resolve().is_relative_to(self.root))
                study.write_json(path, body)
                scope_path = path.parent/'native_source_shell_scope_audit.json'
                if job['platform'] == 'hy3':
                    scope_conforms = conforms and key not in scope_failures
                    study.write_json(scope_path, {
                        'schema': 'native-source-shell-scope-audit-v1',
                        'session_id': body['evidence']['session_id'],
                        'task_id': body['evidence']['task_id'],
                        'source_result_sha256': study.digest(path.read_bytes()),
                        'artifact_sha256': body['evidence']['artifact_sha256'],
                        'protocol_conformance': scope_conforms,
                        'issues': ([] if scope_conforms else ['prior_source_protocol_failure'] if not conforms
                                   else ['directory_metadata_outside_own_job']),
                        'command_counts': {'MOCK_commands': 0},
                        'full_remote_input_attestation': False, 'MOCK_fixture': True})
                saved[key] = {'path': path, 'body': body, 'bytes': path.read_bytes(), 'scope_path': scope_path}
        return saved

    def run_delivery(self, case):
        before = deepcopy(case)
        study.prepare_origins(self.root, [case])
        manifest = study.deliver(self.root, [case])
        self.assertEqual(case, before, 'delivery must not alter source facts or permission specification')
        self.assertEqual(manifest['main_invocations_planned'], 8)
        self.assertEqual(len(manifest['main_records']), 8)
        self.model.assert_not_called()
        return {(r['direction'], r['arm']): r for r in manifest['main_records']}

    def assert_imported(self, record, expected_contents):
        delivery = record['delivery']
        # Query the physical receiver database directly after delivery closed
        # and reopened it, rather than trusting manifest strings alone.
        path = Path(delivery['receiver_db'])
        db = sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True)
        try:
            db.execute('PRAGMA query_only=ON')
            imported = db.execute('SELECT memory_key,content FROM memories ORDER BY memory_key').fetchall()
            rows = db.execute('SELECT m.memory_key,m.content FROM batch_memories bm '
                              'JOIN memories m USING(memory_key) WHERE bm.batch_id=? '
                              'ORDER BY bm.position', (delivery['batch_id'],)).fetchall()
            self.assertEqual(db.execute('SELECT count(*) FROM originals').fetchone()[0], 4)
            self.assertEqual(db.execute('SELECT count(*) FROM batches').fetchone()[0], 1)
        finally:
            db.close()
        self.assertEqual([content for _, content in rows], expected_contents)
        self.assertEqual(set(imported), set(rows), 'no rejected artifact may remain outside the presented batch')
        self.assertEqual([key for key, _ in rows], delivery['memory_keys'])
        self.assertFalse(set(delivery['source_protocol_rejected_memory_keys']) & {key for key, _ in imported})
        packet = study.load(delivery['packet_path'])
        self.assertEqual([m['content'] for m in packet['memories']], expected_contents)
        self.assertEqual([m['memory_key'] for m in packet['memories']], delivery['memory_keys'])
        self.assertFalse(set(delivery['source_protocol_rejected_memory_keys']) &
                         {m['memory_key'] for m in packet['lineage']})
        readback = read_batch(path, delivery['batch_id'])
        self.assertEqual(readback['payload']['memory'], '\n\n'.join(expected_contents))
        self.assertEqual(readback['receipt']['presented_memory_keys'], delivery['memory_keys'])
        self.assertTrue(delivery['close_reopen_verified'])
        self.assertNotIn('PROTOCOL_REJECTED_CANARY', readback['payload']['memory'])

    def test_whole_failclosed_and_selective_keeps_other_clean_chunk(self):
        case = self.mock_case(0)
        saved = self.mock_sources(case, [('A', 'initial', 'whole'), ('A', 'initial', 'chunk0')])
        records = self.run_delivery(case)
        for arm in ('whole_drop', 'full_rebuild'):
            record = records['A_to_B', arm]
            self.assert_imported(record, [])
            self.assertFalse(record['delivery']['source_protocol_clean'])
            self.assertEqual(len(record['delivery']['source_protocol_rejected_memory_keys']), 1)
        record = records['A_to_B', 'selective']
        self.assert_imported(record, [saved['A', 'initial', 'chunk1']['body']['memory']])
        self.assertFalse(record['delivery']['source_protocol_clean'])
        self.assertEqual(len(record['delivery']['source_protocol_rejected_memory_keys']), 1)
        self.assert_imported(records['A_to_B', 'raw'], [s['text'] for s in case['agents']['A']['sources']])
        self.assertTrue(records['A_to_B', 'raw']['delivery']['source_protocol_clean'])
        # A's faulty generation must not taint independently generated B→A.
        self.assert_imported(records['B_to_A', 'full_rebuild'],
                             [saved['B', 'initial', 'whole']['body']['memory']])
        self.assertTrue(records['B_to_A', 'full_rebuild']['delivery']['source_protocol_clean'])
        for result in saved.values():
            self.assertEqual(result['path'].read_bytes(), result['bytes'],
                             'failed source, evidence and MOCK cost record must remain untouched')

    def test_clean_actual_repair_is_not_rejected_for_failed_unselected_initial(self):
        case = self.mock_case(25)
        saved = self.mock_sources(case, [('A', 'initial', 'whole'), ('A', 'initial', 'chunk0')])
        records = self.run_delivery(case)
        full = records['A_to_B', 'full_rebuild']
        self.assert_imported(full, [saved['A', 'repair', 'whole']['body']['memory']])
        self.assertTrue(full['delivery']['source_protocol_clean'])
        self.assertEqual(full['delivery']['source_protocol_rejected_memory_keys'], [])
        selective = records['A_to_B', 'selective']
        self.assert_imported(selective, [saved['A', 'repair', 'chunk0']['body']['memory'],
                                         saved['A', 'initial', 'chunk1']['body']['memory']])
        self.assertTrue(selective['delivery']['source_protocol_clean'])
        allowed = set(permission_event(case, 'A_to_B')['allowed'])
        for record in (full, selective):
            self.assertEqual({d['source_id'] for d in record['delivery']['dependencies']}, allowed)
        self.assert_imported(records['A_to_B', 'whole_drop'], [])

    def test_failed_actual_repair_is_filtered_while_clean_initial_chunk_survives(self):
        case = self.mock_case(25)
        saved = self.mock_sources(case, [('A', 'repair', 'whole'), ('A', 'repair', 'chunk0')])
        records = self.run_delivery(case)
        full = records['A_to_B', 'full_rebuild']
        self.assert_imported(full, [])
        self.assertFalse(full['delivery']['source_protocol_clean'])
        self.assertEqual(len(full['delivery']['source_protocol_rejected_memory_keys']), 1)
        selective = records['A_to_B', 'selective']
        self.assert_imported(selective, [saved['A', 'initial', 'chunk1']['body']['memory']])
        self.assertFalse(selective['delivery']['source_protocol_clean'])
        self.assertEqual(len(selective['delivery']['source_protocol_rejected_memory_keys']), 1)
        self.assertEqual({d['source_id'] for d in selective['delivery']['dependencies']},
                         set(case['chunks']['A'][1]))
        allowed = set(permission_event(case, 'A_to_B')['allowed'])
        legal_raw = [s['text'] for s in case['agents']['A']['sources'] if s['source_id'] in allowed]
        self.assert_imported(records['A_to_B', 'raw'], legal_raw)

    def test_both_rejected_chunks_produce_real_empty_import_not_missing_run(self):
        case = self.mock_case(0)
        self.mock_sources(case, [('A', 'initial', 'chunk0'), ('A', 'initial', 'chunk1')])
        records = self.run_delivery(case)
        selective = records['A_to_B', 'selective']
        self.assert_imported(selective, [])
        self.assertFalse(selective['delivery']['source_protocol_clean'])
        self.assertEqual(len(selective['delivery']['source_protocol_rejected_memory_keys']), 2)
        self.assertEqual(selective['delivery']['content_bytes'], 0)
        self.assertEqual(selective['delivery']['dependencies'], [])
        self.assertEqual(set(records), {(direction, arm) for direction in ('A_to_B', 'B_to_A')
                                       for arm in study.ARMS})

    def test_shell_scope_failure_filters_bad_chunk_without_dropping_clean_chunk(self):
        case = self.mock_case(0)
        saved = self.mock_sources(case, scope_failures=[('A', 'initial', 'chunk0')])
        self.assertTrue(saved['A', 'initial', 'chunk0']['body']['evidence']['source_protocol_conformance'])
        records = self.run_delivery(case)
        selective = records['A_to_B', 'selective']
        self.assert_imported(selective, [saved['A', 'initial', 'chunk1']['body']['memory']])
        self.assertFalse(selective['delivery']['source_protocol_clean'])
        self.assertEqual(len(selective['delivery']['source_protocol_rejected_memory_keys']), 1)
        self.assertEqual({ref['source_id'] for ref in selective['delivery']['dependencies']},
                         set(case['chunks']['A'][1]))
        self.assert_imported(records['A_to_B', 'full_rebuild'], [saved['A', 'initial', 'whole']['body']['memory']])
        for result in saved.values():
            self.assertEqual(result['path'].read_bytes(), result['bytes'])

    def test_shell_scope_result_hash_tampering_stops_affected_delivery(self):
        case = self.mock_case(0)
        saved = self.mock_sources(case)
        scope_path = saved['A', 'initial', 'chunk0']['scope_path']
        scope = study.load(scope_path)
        scope['source_result_sha256'] = '0'*64
        scope_path.write_text(json.dumps(scope, ensure_ascii=False), encoding='utf-8')
        study.prepare_origins(self.root, [case])
        # The intentional exception exits this CLI workflow before its ordinary
        # per-case close calls. Explicitly close the test's tracked handles so
        # Windows can remove its MOCK directory without changing frozen code.
        opened = []
        def track(factory):
            def create(*args, **kwargs):
                resource = factory(*args, **kwargs)
                opened.append(resource)
                return resource
            return create
        with patch.object(study, 'AgentStore', side_effect=track(study.AgentStore)), \
                patch.object(study, 'TrustedPolicy', side_effect=track(study.TrustedPolicy)):
            try:
                with self.assertRaisesRegex(RuntimeError, 'native_source_shell_scope_audit_binding_invalid'):
                    study.deliver(self.root, [case])
            finally:
                for resource in opened:
                    resource.close()
        self.assertFalse((self.root/'manifest.json').exists())
        self.assertFalse((self.root/'receiver_jobs'/case['case_id']/'A_to_B'/'selective'/'receiver.sqlite').exists())
        self.model.assert_not_called()


if __name__ == '__main__':
    unittest.main()
