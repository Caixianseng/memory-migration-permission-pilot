"""MOCK-ONLY source responses; real immutable registry and recovery files.

No test calls a model, gateway, session API or supplier SDK.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from . import run_quota_recovery as recovery
from .source_registry import resolve_source_result, source_attempt_paths


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_bytes(job):
    return json.dumps({'sources': job['sources'], 'parent_memories': [],
        'max_memory_characters': job['budget']*2,
        'length_limit_scope': 'native soft instruction; SDK additionally enforces max output tokens'},
        ensure_ascii=False, sort_keys=True, indent=2).encode('utf-8')


class QuotaRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='quota-recovery-MOCK-ONLY-',
                                               dir=Path(__file__).resolve().parents[2])
        self.root = Path(self.tmp.name)
        self.jobs = []
        for number in range(1, 4):
            cid = f'MOCK-ONLY-case-{number:02d}'
            folder = self.root/'source_jobs'/cid/'A'/'repair'/'whole'
            sources = [{'source_id': f'A-MOCK-{number}-{i}', 'text': f'MOCK-ONLY fact {number}/{i}.',
                'version': 1, 'source_kind': 'original',
                'origin': {'agent_id': 'A', 'case_id': cid, 'synthetic': True}} for i in (1, 2)]
            job = {'case_id': cid, 'agent': 'A', 'platform': 'hy3', 'phase': 'repair', 'group': 'whole',
                   'source_ids': [s['source_id'] for s in sources], 'sources': sources,
                   'budget': 2048, 'job_dir': str(folder)}
            self.jobs.append(job)
            task = 'pex-MOCK-ONLY-original-'+str(number)
            original = {k: v for k, v in job.items() if k != 'sources'}
            original.update(memory=None, wall_ms=10,
                evidence={'task_id': task, 'actual_models': [], 'request_model_ids': [],
                    'source_protocol_conformance': False, 'artifact_sha256': None,
                    'native_history_prefix_sha256': str(number)*64,
                    'protocol_issues': ['MOCK-ONLY HTTP429 terminal failure']})
            put(folder/'result.json', original)
            (folder/'sources.json').write_bytes(source_bytes(job))
            put(folder/'native_job.json', {'taskId': task,
                                           'sessionId': f'00000000-0000-0000-0000-{number:012d}'})
            put(folder/'provider_quota_evidence.json', {'error_code': 6004, 'http_status': 429,
                'reset_iso': '2026-11-05T14:53:41+08:00',
                'native_history_prefix_sha256': str(number)*64, 'source_job_id': task})
        self.cases = [{'case_id': job['case_id'], 'mock_only': True} for job in self.jobs]
        self.contract = {'schema': 'MOCK-ONLY-contract', 'seed': 1, 'artifact_sha256': {}}
        self.original_bytes = {path: path.read_bytes() for job in self.jobs
            for path in Path(job['job_dir']).iterdir() if path.is_file()}
        self.executed = []
        self.material_patch = patch.object(recovery, 'material', return_value=(self.cases, self.contract))
        self.jobs_patch = patch.object(recovery, 'source_jobs', side_effect=self.frozen_jobs)
        self.material_patch.start()
        self.jobs_patch.start()

    def tearDown(self):
        self.jobs_patch.stop()
        self.material_patch.stop()
        self.tmp.cleanup()

    def frozen_jobs(self, root, cases, phase):
        self.assertEqual(Path(root), self.root)
        return deepcopy([job for job in self.jobs if job['phase'] == phase])

    def child(self, number=0):
        return Path(self.jobs[number]['job_dir'])/'quota_recovery_01'

    def fake_result(self, job, *, conformance=True, quota=False, no_output=False):
        """Write only a temporary fixture equivalent to the normal source API."""
        folder = Path(job['job_dir'])
        self.assertEqual(folder.name, 'quota_recovery_01')
        parent = folder.parent
        self.assertEqual((folder/'sources.json').read_bytes(), (parent/'sources.json').read_bytes())
        self.assertEqual((folder/'sources.json').read_bytes(), source_bytes(job))
        identity = ('case_id', 'agent', 'platform', 'phase', 'group', 'budget', 'source_ids')
        original = json.loads((parent/'result.json').read_bytes())
        self.assertEqual({k: job[k] for k in identity}, {k: original[k] for k in identity})
        memory = None if quota or no_output else 'MOCK-ONLY normal paid Hy3 generated output.'
        artifact_hash = None
        if memory is not None:
            put(folder/'memory.json', {'memory': memory})
            artifact_hash = sha((folder/'memory.json').read_bytes())
        result = {k: v for k, v in job.items() if k != 'sources'}
        result.update(memory=memory, wall_ms=20, evidence={'mock_only': True,
            'runtime_source': 'desktop_queue', 'actual_models': ['hy3-x'] if memory else [],
            'request_model_ids': ['hy3-x'] if memory else [], 'canonical_model_family': 'Hy3',
            'source_protocol_conformance': conformance if memory else False,
            'artifact_sha256': artifact_hash, 'task_id': 'pex-MOCK-ONLY-recovery'})
        if quota:
            result['evidence']['http_status'] = 429
            put(folder/'provider_quota_evidence.json', {'http_status': 429, 'error_code': 6004,
                'reset_iso': '2026-11-06T14:53:41+08:00',
                'native_history_prefix_sha256': 'f'*64, 'source_job_id': 'pex-MOCK-ONLY-recovery'})
        put(folder/'result.json', result)
        return result

    def execute_ok(self, job):
        self.executed.append(deepcopy(job))
        return self.fake_result(job)

    def assert_originals_unchanged(self):
        self.assertEqual(self.original_bytes, {path: path.read_bytes() for path in self.original_bytes})

    def test_success_preserves_originals_exact_inputs_and_paid_raw_identity(self):
        with patch.object(recovery, 'execute_source', side_effect=self.execute_ok) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 3)
        self.assertEqual([o['status'] for o in outcomes], ['registered']*3)
        self.assertTrue((self.root/'quota_recovery_plan.json').is_file())
        self.assert_originals_unchanged()
        for job, row in zip(self.jobs, outcomes):
            cell = Path(job['job_dir'])
            self.assertEqual(Path(row['cell_dir']), cell)
            self.assertTrue(row['registered'])
            self.assertFalse(row['automatic_retry'])
            self.assertEqual(resolve_source_result(cell), cell/'quota_recovery_01/result.json')
            self.assertEqual(len(source_attempt_paths(cell)), 2)
            receipt = json.loads((cell/'source_recovery_receipt.json').read_bytes())
            self.assertEqual(receipt['response_model_binding']['canonical_model_family'], 'Hy3')
            self.assertEqual(receipt['response_model_binding']['raw_actual_models'], ['hy3-x'])
            self.assertEqual(receipt['response_model_binding']['raw_request_model_ids'], ['hy3-x'])

    def test_successful_resume_has_no_new_execute_calls(self):
        with patch.object(recovery, 'execute_source', side_effect=self.execute_ok) as execute:
            recovery.run_quota_recovery(self.root, workers=1)
            repeated = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 3)
        self.assertTrue(all(row['status'] == 'existing_registered' for row in repeated))
        self.assert_originals_unchanged()

    def test_preexisting_child_result_is_verified_and_adopted_without_model_dispatch(self):
        self.jobs = self.jobs[:1]
        child = self.child()
        child.mkdir()
        (child/'sources.json').write_bytes((child.parent/'sources.json').read_bytes())
        self.fake_result({**self.jobs[0], 'job_dir': str(child)})
        with patch.object(recovery, 'execute_source', side_effect=AssertionError('NO MODEL DISPATCH')) as execute:
            result = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 0)
        self.assertEqual(result[0]['status'], 'existing_registered')
        self.assertTrue(result[0]['registered'])

    def test_no_quota_or_existing_output_is_not_selected(self):
        (Path(self.jobs[0]['job_dir'])/'provider_quota_evidence.json').unlink()
        folder = Path(self.jobs[1]['job_dir'])
        value = json.loads((folder/'result.json').read_bytes())
        value['memory'] = 'MOCK-ONLY existing output must never be regenerated.'
        value['evidence']['source_protocol_conformance'] = False
        put(folder/'result.json', value)
        with patch.object(recovery, 'execute_source', side_effect=self.execute_ok) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(Path(outcomes[0]['cell_dir']), Path(self.jobs[2]['job_dir']))
        self.assertFalse(self.child(0).exists())
        self.assertFalse(self.child(1).exists())

    def test_existing_artifact_is_not_regenerated_even_if_result_memory_is_none(self):
        put(Path(self.jobs[0]['job_dir'])/'memory.json', {'memory': 'MOCK-ONLY existing artifact.'})
        with patch.object(recovery, 'execute_source', side_effect=self.execute_ok) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(len(outcomes), 2)
        self.assertFalse(self.child(0).exists())

    def test_explicit_bound_HTTP429_queue_code6020_is_an_eligible_first_recovery(self):
        self.jobs = self.jobs[:1]
        old_folder = Path(self.jobs[0]['job_dir'])
        folder = old_folder.parent.parent/'initial'/'whole'
        folder.mkdir(parents=True)
        for path in old_folder.iterdir():
            if path.is_file():
                (folder/path.name).write_bytes(path.read_bytes())
        self.jobs[0].update(phase='initial', job_dir=str(folder))
        original = json.loads((folder/'result.json').read_bytes())
        original.update(phase='initial', job_dir=str(folder))
        put(folder/'result.json', original)
        path = folder/'provider_quota_evidence.json'
        value = json.loads(path.read_bytes())
        value.update(error_code=6020, reset_iso=None)
        put(path, value)
        with patch.object(recovery, 'execute_source', side_effect=self.execute_ok) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(outcomes[0]['status'], 'registered')

    def test_new_quota_stops_later_dispatch_and_remains_counted_as_an_attempt(self):
        def rate_limited(job):
            self.executed.append(job)
            return self.fake_result(job, quota=True)
        with patch.object(recovery, 'execute_source', side_effect=rate_limited) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(outcomes[0]['status'], 'paused_new_quota')
            self.assertTrue(all(o['status'] == 'not_dispatched_after_pause' for o in outcomes[1:]))
            with self.assertRaisesRegex(recovery.QuotaRecoveryError, 'paused'):
                recovery.run_quota_recovery(self.root, workers=1)
            self.assertEqual(execute.call_count, 1)
        self.assertTrue((self.root/'quota_recovery_STOPPED.json').exists())
        self.assertFalse((self.child().parent/'source_recovery_receipt.json').exists())
        self.assertEqual(len(source_attempt_paths(self.child().parent)), 2)
        self.assert_originals_unchanged()

    def test_unknown_execution_error_is_not_retried_and_stops_queue(self):
        def unknown(job):
            put(Path(job['job_dir'])/'submission_intent.json', {'mock_only': True, 'outcome': 'unknown'})
            raise RuntimeError('MOCK-ONLY uncertain dispatch')
        with patch.object(recovery, 'execute_source', side_effect=unknown) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(outcomes[0]['status'], 'paused_execution_error')
            self.assertTrue(all(o['status'] == 'not_dispatched_after_pause' for o in outcomes[1:]))
            with self.assertRaisesRegex(recovery.QuotaRecoveryError, 'paused'):
                recovery.run_quota_recovery(self.root, workers=1)
            self.assertEqual(execute.call_count, 1)
        self.assert_originals_unchanged()

    def test_no_output_stops_without_registering_an_override(self):
        with patch.object(recovery, 'execute_source', side_effect=lambda job: self.fake_result(job, no_output=True)) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(outcomes[0]['status'], 'paused_no_output')
        self.assertFalse((self.child().parent/'source_recovery_receipt.json').exists())

    def test_protocol_failure_with_actual_output_is_registered_finally_not_regenerated(self):
        self.jobs = self.jobs[:1]
        with patch.object(recovery, 'execute_source', side_effect=lambda job: self.fake_result(job, conformance=False)) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
            repeated = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(outcomes[0]['status'], 'protocol_failed_registered')
        self.assertTrue(repeated[0]['registered'])
        receipt = json.loads((self.child().parent/'source_recovery_receipt.json').read_bytes())
        self.assertEqual(receipt['adoption_outcome'], 'final_protocol_failed_output_fail_closed')
        self.assertFalse(receipt['further_regeneration_authorized'])

    def test_existing_submission_intent_without_result_is_not_reexecuted(self):
        child = self.child()
        put(child/'submission_intent.json', {'mock_only': True, 'outcome': 'unknown'})
        with patch.object(recovery, 'execute_source', side_effect=AssertionError('NO REPLAY')) as execute:
            outcomes = recovery.run_quota_recovery(self.root, workers=1)
        self.assertEqual(execute.call_count, 0)
        self.assertTrue(outcomes[0]['status'].startswith('paused_'))
        self.assertFalse((self.child().parent/'source_recovery_receipt.json').exists())

    def test_frozen_plan_rejects_changed_workers_or_job_budget(self):
        with patch.object(recovery, 'execute_source', side_effect=self.execute_ok) as execute:
            recovery.run_quota_recovery(self.root, workers=1)
            with self.assertRaisesRegex(recovery.QuotaRecoveryError, 'frozen|changed'):
                recovery.run_quota_recovery(self.root, workers=2)
            self.jobs[0]['budget'] = 1024
            with self.assertRaisesRegex(recovery.QuotaRecoveryError, 'frozen|changed'):
                recovery.run_quota_recovery(self.root, workers=1)
            self.assertEqual(execute.call_count, 3)

    def test_frozen_original_source_bytes_cannot_be_changed(self):
        with patch.object(recovery, 'execute_source', side_effect=self.execute_ok) as execute:
            recovery.run_quota_recovery(self.root, workers=1)
            source = Path(self.jobs[0]['job_dir'])/'sources.json'
            source.write_bytes(source.read_bytes()+b' ')
            with self.assertRaisesRegex(recovery.QuotaRecoveryError, 'frozen|changed'):
                recovery.run_quota_recovery(self.root, workers=1)
            self.assertEqual(execute.call_count, 3)

    def test_maximum_two_mock_executions_in_flight(self):
        lock = threading.Lock()
        active = 0
        maximum = 0
        def execute(job):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            try:
                time.sleep(.03)
                return self.fake_result(job)
            finally:
                with lock:
                    active -= 1
        with patch.object(recovery, 'execute_source', side_effect=execute) as mocked:
            outcomes = recovery.run_quota_recovery(self.root, workers=2)
        self.assertEqual(mocked.call_count, 3)
        self.assertLessEqual(maximum, 2)
        self.assertTrue(all(row['registered'] for row in outcomes))

    def test_more_than_two_workers_is_rejected_before_dispatch(self):
        with patch.object(recovery, 'execute_source', side_effect=AssertionError('NO DISPATCH')) as execute:
            with self.assertRaises(recovery.QuotaRecoveryError):
                recovery.run_quota_recovery(self.root, workers=3)
        self.assertEqual(execute.call_count, 0)


if __name__ == '__main__':
    unittest.main()
