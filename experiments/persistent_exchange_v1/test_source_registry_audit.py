"""MOCK-only late native turns; every test runs without an App or model."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from . import source_registry_audit as audit
from .source_registry import SourceRegistryError, resolve_source_result
from . import test_source_registry as fixtures
from .test_source_registry import put, sha


def stamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class HistoricalSourceAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SourceRegistryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.cell, self.new = self.fixture.cell, self.fixture.new
        self.sid = 'MOCK-ONLY-original-session'
        self.projects = Path(self.fixture.tmp.name)/'mock-native-projects'
        self.history = self.projects/'own-workspace'/(self.sid+'.jsonl')
        self.history.parent.mkdir(parents=True)
        self.patcher = patch.object(audit, '_NATIVE_PROJECTS', self.projects.resolve())
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.old_line = json.dumps({'type': 'message', 'role': 'assistant', 'content': [],
                                    'timestamp': 900000, 'sessionId': self.sid}).encode()+b'\n'
        quota = {**self.fixture.quota, 'native_history_prefix_sha256': sha(self.old_line)}
        put(self.cell/'provider_quota_evidence.json', quota)
        put(self.cell/'native_job.json', {'taskId': 'pex-MOCK-ONLY-original', 'sessionId': self.sid})
        self.fixture.register()
        receipt = self.cell/'source_recovery_receipt.json'
        os.utime(receipt, (1000, 1000))
        put(self.cell/'memory.json', {'memory': 'MOCK-ONLY UNUSED late model content.'})
        late = (self.cell/'memory.json').read_bytes()
        os.utime(self.cell/'memory.json', (2000, 2000))
        query = '请继续完成未完成的任务。'
        full = '<system-reminder>MOCK-ONLY wrapper</system-reminder>\n<user_query>'+query+'</user_query>'
        self.rows = [json.loads(self.old_line),
            {'type': 'message', 'role': 'user', 'timestamp': 1500000, 'sessionId': self.sid,
             'providerData': {'startsNewUserRequest': True}, 'content': [{'type': 'input_text', 'text': full}]},
            {'type': 'function_call', 'name': 'Read', 'timestamp': 1600000, 'sessionId': self.sid,
             'providerData': {'model': 'hy3-x', 'requestModelId': 'hy3-x'},
             'arguments': json.dumps({'file_path': str(self.cell/'sources.json')})},
            {'type': 'function_call', 'name': 'Write', 'timestamp': 2000000, 'sessionId': self.sid,
             'providerData': {'model': 'hy3-x', 'requestModelId': 'hy3-x'},
             'arguments': json.dumps({'file_path': str(self.cell/'memory.json'), 'content': late.decode()})}]
        self.event = {
            'schema': 'late-original-source-artifact-event-v1', 'source_cell': str(self.cell),
            'frozen_recovery_receipt_path': str(receipt), 'frozen_recovery_receipt_sha256': sha(receipt.read_bytes()),
            'original_result_sha256': sha((self.cell/'result.json').read_bytes()),
            'original_sources_sha256': sha((self.cell/'sources.json').read_bytes()),
            'adopted_replacement_result_path': str(self.new/'result.json'),
            'adopted_replacement_result_sha256': sha((self.new/'result.json').read_bytes()),
            'frozen_bindings_still_match': {'original_result': True, 'original_sources': True, 'replacement_result': True},
            'late_artifact': {'path': str(self.cell/'memory.json'), 'sha256': sha(late), 'bytes': len(late),
                'filesystem_mtime_utc': stamp(2000), 'seconds_after_recovery_receipt_mtime': 1000},
            'recovery_receipt_filesystem_mtime_utc': stamp(1000),
            'original_session_id': self.sid, 'original_task_id': 'pex-MOCK-ONLY-original',
            'own_native_history_path': str(self.history), 'own_native_history_prefix_lines': 4,
            'new_user_turn': {'line': 2, 'timestamp_ms': 1500000, 'starts_new_user_request': True,
                'query_classification': 'official_rate_limit_continue_prompt', 'query_sha256': sha(query.encode()),
                'whole_user_text_sha256': sha(full.encode()), 'queue_wake_marker_present': False},
            'matching_native_write': {'line': 4, 'timestamp_ms': 2000000, 'target_path': str(self.cell/'memory.json'),
                'content_sha256': sha(late), 'exact_current_file_bytes_match': True,
                'model': 'hy3-x', 'request_model_id': 'hy3-x'},
            'new_turn_original_input_reads': [{'line': 3, 'timestamp_ms': 1600000,
                                              'business_path': str(self.cell/'sources.json')}],
            'new_turn_actual_models': ['hy3-x'], 'new_turn_request_model_ids': ['hy3-x'],
            'original_result_still_memory_none': True, 'late_artifact_adopted_for_study': False,
            'registered_replacement_selection_changed': False, 'original_results_or_receipts_modified': False,
            'extra_continuation_cost_evidence': {'input_tokens': None, 'native_additional_continuation_turns': 1,
                'native_turn_is_one_supplier_request': False, 'new_source_result_records': 0,
                'output_tokens': None, 'physical_supplier_calls': None,
                'qualified_study_source_results': 0, 'supplier_fee_cny': None}}
        self.write_history()

    def write_history(self):
        raw = self.old_line+b''.join(json.dumps(row).encode()+b'\n' for row in self.rows[1:])
        self.history.write_bytes(raw)
        self.event.update(own_native_history_prefix_bytes=len(raw), own_native_history_prefix_sha256=sha(raw),
                          own_native_history_prefix_lines=len(self.rows))
        self.write_event()

    def write_event(self):
        put(self.cell/audit.EVENT_NAME, self.event)

    def test_historical_audit_uses_same_recovery_without_changing_delivery_guard_or_files(self):
        before = {p: p.read_bytes() for p in Path(self.fixture.tmp.name).rglob('*') if p.is_file()}
        with self.assertRaisesRegex(SourceRegistryError, 'existing_source_artifact_forbidden'):
            resolve_source_result(self.cell)
        self.assertEqual(audit.resolve_source_result_for_audit(self.cell), self.new/'result.json')
        self.assertEqual(audit.source_attempt_paths_for_audit(self.cell),
                         [self.cell/'result.json', self.new/'result.json'])
        extra = audit.late_source_continuation_for_audit(self.cell)
        self.assertEqual(extra['native_additional_continuation_turns'], 1)
        self.assertIsNone(extra['supplier_fee_cny'])
        self.assertIsNone(extra['physical_supplier_calls'])
        self.assertEqual(extra['qualified_study_source_results'], 0)
        self.assertNotIn('memory', extra)
        self.assertFalse(extra['late_artifact_adopted_for_study'])
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_normal_cell_uses_original_registry_unchanged(self):
        (self.cell/audit.EVENT_NAME).unlink()
        (self.cell/'memory.json').unlink()
        self.assertEqual(audit.resolve_source_result_for_audit(self.cell), self.new/'result.json')
        self.assertEqual(len(audit.source_attempt_paths_for_audit(self.cell)), 2)
        self.assertIsNone(audit.late_source_continuation_for_audit(self.cell))

    def test_unacknowledged_late_output_still_fails(self):
        (self.cell/audit.EVENT_NAME).unlink()
        with self.assertRaises(SourceRegistryError):
            audit.resolve_source_result_for_audit(self.cell)

    def test_original_result_or_registered_receipt_changes_are_rejected(self):
        for name in ['result.json', 'source_recovery_receipt.json', 'quota_recovery_01/result.json']:
            path = self.cell/name
            old = path.read_bytes()
            path.write_bytes(old+b' ')
            with self.subTest(name=name), self.assertRaises(SourceRegistryError):
                audit.resolve_source_result_for_audit(self.cell)
            path.write_bytes(old)

    def test_source_input_bytes_and_native_generated_replacement_remain_bound(self):
        for name in ['sources.json', 'quota_recovery_01/sources.json', 'quota_recovery_01/memory.json']:
            path = self.cell/name
            old = path.read_bytes()
            path.write_bytes(old+b' ')
            with self.subTest(name=name), self.assertRaises(SourceRegistryError):
                audit.resolve_source_result_for_audit(self.cell)
            path.write_bytes(old)

    def test_native_prefix_or_late_output_drift_rejected(self):
        for path in [self.history, self.cell/'memory.json']:
            old = path.read_bytes()
            path.write_bytes(b' '+old)
            with self.subTest(path=path.name), self.assertRaises(SourceRegistryError):
                audit.resolve_source_result_for_audit(self.cell)
            path.write_bytes(old)

    def test_rehashed_false_write_and_wrong_model_are_rejected(self):
        old = deepcopy(self.rows)
        self.rows[3]['arguments'] = json.dumps({'file_path': str(self.cell/'elsewhere.json'), 'content': 'MOCK'})
        self.write_history()
        with self.assertRaisesRegex(SourceRegistryError, 'native_write_not_bound'):
            audit.resolve_source_result_for_audit(self.cell)
        self.rows = old
        self.rows[3]['providerData']['model'] = 'fast-model'
        self.write_history()
        with self.assertRaises(SourceRegistryError):
            audit.resolve_source_result_for_audit(self.cell)

    def test_original_quota_prefix_must_precede_new_turn(self):
        self.old_line = self.old_line.replace(b'900000', b'800000')
        self.write_history()
        with self.assertRaisesRegex(SourceRegistryError, 'quota_prefix_not_preserved'):
            audit.resolve_source_result_for_audit(self.cell)

    def test_unrelated_prompt_cannot_become_approved_late_event(self):
        full = '<user_query>MOCK-ONLY unrelated task</user_query>'
        self.rows[1]['content'][0]['text'] = full
        self.event['new_user_turn']['whole_user_text_sha256'] = sha(full.encode())
        self.event['new_user_turn']['query_sha256'] = sha(b'MOCK-ONLY unrelated task')
        self.write_history()
        with self.assertRaisesRegex(SourceRegistryError, 'not_official_later_continuation'):
            audit.resolve_source_result_for_audit(self.cell)

    def test_cost_zero_or_late_artifact_adoption_rejected(self):
        self.event['extra_continuation_cost_evidence']['supplier_fee_cny'] = 0
        self.write_event()
        with self.assertRaisesRegex(SourceRegistryError, 'cost_unknown_must_not_be_zero'):
            audit.late_source_continuation_for_audit(self.cell)
        self.event['extra_continuation_cost_evidence']['supplier_fee_cny'] = None
        self.event['late_artifact_adopted_for_study'] = True
        self.write_event()
        with self.assertRaisesRegex(SourceRegistryError, 'must_preserve_frozen_selection'):
            audit.resolve_source_result_for_audit(self.cell)


if __name__ == '__main__':
    unittest.main()
