"""MOCK-ONLY result fixtures; recovery registration makes zero model calls."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from .source_registry import (register_recovery, resolve_source_result,
                              source_attempt_paths, SourceRegistryError)


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class SourceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='registry-MOCK-ONLY-', dir=Path(__file__).resolve().parents[2])
        self.cell = Path(self.tmp.name)/'cell'
        self.new = self.cell/'quota_recovery_01'
        self.cell.mkdir()
        self.new.mkdir()
        self.identity = {'case_id': 'MOCK-ONLY-case', 'agent': 'A', 'platform': 'hy3',
                         'phase': 'repair', 'group': 'whole', 'budget': 2048,
                         'source_ids': ['A-source1', 'A-source2']}
        business = {'sources': [{'source_id': 'A-source1', 'text': 'MOCK-ONLY code 81736.'},
                                {'source_id': 'A-source2', 'text': 'MOCK-ONLY date 2027-02-18.'}],
                    'parent_memories': [], 'max_memory_characters': 4096,
                    'length_limit_scope': 'MOCK-ONLY same source interface'}
        put(self.cell/'sources.json', business)
        (self.new/'sources.json').write_bytes((self.cell/'sources.json').read_bytes())
        self.original = {**self.identity, 'job_dir': str(self.cell), 'memory': None,
                         'evidence': {'task_id': 'pex-MOCK-ONLY-original', 'actual_models': [],
                                      'source_protocol_conformance': False, 'artifact_sha256': None},
                         'wall_ms': 10}
        self.quota = {'http_status': 429, 'error_code': 6004,
                      'reset_iso': '2026-11-05T14:53:41+08:00',
                      'native_history_prefix_sha256': 'a'*64,
                      'source_job_id': 'pex-MOCK-ONLY-original'}
        put(self.cell/'native_job.json', {'taskId': 'pex-MOCK-ONLY-original'})
        put(self.cell/'result.json', self.original)
        put(self.cell/'provider_quota_evidence.json', self.quota)
        put(self.new/'memory.json', {'memory': 'MOCK-ONLY faithful model output.'})
        self.replacement = {**self.identity, 'job_dir': str(self.new),
                            'memory': 'MOCK-ONLY faithful model output.',
                            'evidence': {'runtime_source': 'desktop_queue', 'actual_models': ['hy3'],
                                         'request_model_ids': ['hy3-x'], 'source_protocol_conformance': True,
                                         'artifact_sha256': sha((self.new/'memory.json').read_bytes())},
                            'wall_ms': 20}
        put(self.new/'result.json', self.replacement)

    def tearDown(self):
        self.tmp.cleanup()

    def register(self):
        return register_recovery(self.cell, self.new/'result.json')

    def test_without_override_returns_original_and_counts_unregistered_attempt(self):
        self.assertEqual(resolve_source_result(self.cell), self.cell/'result.json')
        self.assertFalse((self.cell/'source_recovery_receipt.json').exists())
        self.assertEqual(source_attempt_paths(self.cell), [self.cell/'result.json', self.new/'result.json'])

    def test_register_once_preserves_original_and_resolves_frozen_replacement(self):
        originals = {p: p.read_bytes() for p in (self.cell/'result.json', self.cell/'sources.json',
                     self.cell/'provider_quota_evidence.json', self.cell/'native_job.json')}
        receipt = self.register()
        self.assertEqual(receipt['adoption_outcome'], 'usable_source_attempt')
        self.assertFalse(receipt['further_regeneration_authorized'])
        self.assertEqual(self.register(), receipt)
        self.assertEqual(resolve_source_result(self.cell), self.new/'result.json')
        self.assertEqual(originals, {p: p.read_bytes() for p in originals})
        self.assertEqual(len(source_attempt_paths(self.cell)), 2)

    def test_existing_original_model_text_cannot_be_regenerated(self):
        value = deepcopy(self.original)
        value['memory'] = 'MOCK-ONLY existing output, even if truncated or nonconformant.'
        put(self.cell/'result.json', value)
        with self.assertRaisesRegex(SourceRegistryError, 'existing_generated_memory_forbidden'):
            self.register()

    def test_existing_native_artifact_blocks_none_result_recovery(self):
        put(self.cell/'memory.json', {'memory': 'MOCK-ONLY existing artifact.'})
        with self.assertRaisesRegex(SourceRegistryError, 'existing_source_artifact_forbidden'):
            self.register()

    def test_provider_evidence_must_be_http429_and_bound_to_original_job(self):
        for delta in ({'http_status': 402}, {'source_job_id': 'another-job'},
                      {'native_history_prefix_sha256': 'not-a-sha'}):
            with self.subTest(delta=delta):
                put(self.cell/'provider_quota_evidence.json', {**self.quota, **delta})
                with self.assertRaises(SourceRegistryError):
                    self.register()
        put(self.cell/'provider_quota_evidence.json', self.quota)
        (self.cell/'provider_quota_evidence.json').unlink()
        with self.assertRaises(SourceRegistryError):
            self.register()

    def test_all_experiment_identity_and_source_order_must_match(self):
        changes = {'case_id': 'another-case', 'agent': 'B', 'platform': 'flash',
                   'phase': 'initial', 'group': 'chunk0', 'budget': 1024,
                   'source_ids': list(reversed(self.identity['source_ids']))}
        for key, changed in changes.items():
            with self.subTest(key=key):
                put(self.new/'result.json', {**self.replacement, key: changed})
                with self.assertRaisesRegex(SourceRegistryError, 'experiment_identity_changed'):
                    self.register()
        put(self.new/'result.json', self.replacement)

    def test_even_semantically_equal_changed_source_json_bytes_are_rejected(self):
        value = json.loads((self.cell/'sources.json').read_bytes())
        (self.new/'sources.json').write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaisesRegex(SourceRegistryError, 'sources_json_bytes_changed'):
            self.register()

    def test_second_429_pauses_adoption_but_remains_in_complete_cost_ledger(self):
        value = deepcopy(self.replacement)
        value['memory'] = None
        value['evidence'].update(source_protocol_conformance=False, http_status=429)
        put(self.new/'result.json', value)
        put(self.new/'provider_quota_evidence.json', {**self.quota, 'source_job_id': 'new-MOCK-ONLY'})
        with self.assertRaisesRegex(SourceRegistryError, 'again_rate_limited_pause'):
            self.register()
        self.assertFalse((self.cell/'source_recovery_receipt.json').exists())
        self.assertEqual(resolve_source_result(self.cell), self.cell/'result.json')
        self.assertEqual(source_attempt_paths(self.cell), [self.cell/'result.json', self.new/'result.json'])

    def test_protocol_failed_actual_model_output_is_final_fail_closed_attempt(self):
        value = deepcopy(self.replacement)
        value['evidence']['source_protocol_conformance'] = False
        value['evidence']['protocol_issues'] = ['MOCK-ONLY forbidden tool']
        put(self.new/'result.json', value)
        receipt = self.register()
        self.assertEqual(receipt['adoption_outcome'], 'final_protocol_failed_output_fail_closed')
        self.assertFalse(receipt['replacement_source_protocol_conformance'])
        self.assertEqual(resolve_source_result(self.cell), self.new/'result.json')
        self.assertEqual(self.register(), receipt)

    def test_ask_one_shot_or_unbound_native_output_cannot_replace_normal_source(self):
        for delta in ({'runtime_source': 'native_one_shot'}, {'actual_models': []},
                      {'artifact_sha256': 'f'*64}):
            with self.subTest(delta=delta):
                value = deepcopy(self.replacement)
                value['evidence'].update(delta)
                put(self.new/'result.json', value)
                with self.assertRaises(SourceRegistryError):
                    self.register()

    def test_receipt_binds_original_quota_inputs_and_replacement_bytes(self):
        self.register()
        for p in (self.cell/'result.json', self.cell/'provider_quota_evidence.json',
                  self.cell/'sources.json', self.new/'sources.json', self.new/'result.json'):
            with self.subTest(path=p.name):
                saved = p.read_bytes()
                p.write_bytes(saved+b' ')
                try:
                    with self.assertRaises(SourceRegistryError):
                        resolve_source_result(self.cell)
                finally:
                    p.write_bytes(saved)
        receipt_path = self.cell/'source_recovery_receipt.json'
        value = json.loads(receipt_path.read_bytes())
        value['replacement_result_sha256'] = '0'*64
        put(receipt_path, value)
        with self.assertRaisesRegex(SourceRegistryError, 'receipt_or_bound_evidence_changed'):
            source_attempt_paths(self.cell)

    def test_only_first_recovery_can_be_selected_but_extra_attempt_is_not_hidden_from_costs(self):
        second = self.cell/'quota_recovery_02'/'result.json'
        put(second, self.replacement)
        with self.assertRaisesRegex(SourceRegistryError, 'only_quota_recovery_01'):
            register_recovery(self.cell, second)
        self.assertEqual(source_attempt_paths(self.cell), [self.cell/'result.json', self.new/'result.json', second])
        self.assertEqual(resolve_source_result(self.cell), self.cell/'result.json')

    def test_zero_submit_creation_failure_without429_cannot_use_recovery_override(self):
        (self.cell/'provider_quota_evidence.json').unlink()
        value = deepcopy(self.original)
        value['evidence'].update(model_prompts_submitted=0, protocol_issues=['creation_failed_before_dispatch'])
        put(self.cell/'result.json', value)
        with self.assertRaises(SourceRegistryError):
            self.register()

    def test_paid_Hy3_route_records_canonical_family_and_preserves_raw_ids(self):
        value = deepcopy(self.replacement)
        value['evidence'].update(actual_models=['hy3-x'], request_model_ids=['hy3-x'])
        put(self.new/'result.json', value)
        raw_before = (self.new/'result.json').read_bytes()
        receipt = self.register()
        binding = receipt['response_model_binding']
        self.assertEqual(binding['canonical_model_family'], 'Hy3')
        self.assertEqual(binding['raw_actual_models'], ['hy3-x'])
        self.assertEqual(binding['raw_request_model_ids'], ['hy3-x'])
        self.assertEqual(binding['exact_route_whitelist'], ['hy3', 'hy3-x'])
        self.assertEqual((self.new/'result.json').read_bytes(), raw_before)

    def test_non_Hy3_actual_or_requested_model_is_rejected_even_for_failed_protocol(self):
        for field in ('actual_models', 'request_model_ids'):
            for model in ('fast-model', 'deepseek-flash', 'glm-5', 'HY3', 'hy3-unverified'):
                with self.subTest(field=field, model=model):
                    value = deepcopy(self.replacement)
                    value['evidence']['source_protocol_conformance'] = False
                    value['evidence'][field] = [model]
                    put(self.new/'result.json', value)
                    with self.assertRaisesRegex(SourceRegistryError, 'outside_exact_Hy3_route_whitelist'):
                        self.register()


if __name__ == '__main__':
    unittest.main()
