"""Instrument-only regression checks; never creates real research outcomes."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import time
import unittest

from .driver import DriverError, PreDeliveryRevocationDriver, canonical, digest, verify_event_trace
from .analyze import inspect_event_trace, nontriviality_gate

ROOT = Path(__file__).resolve().parents[2]


class DriverTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT/'tmp'; parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='pre-delivery-instrument-', dir=parent)
        self.sources = [{'source_id': f'S{i:02d}', 'text': f'Instrument fixture source {i}.'}
                        for i in range(1, 5)]
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def driver(self, **kwargs):
        return PreDeliveryRevocationDriver(Path(self.temp.name)/'run', self.sources,
                                           instrument_only=True, **kwargs)

    def seal(self, driver, artifact):
        payload = driver.begin_generation(artifact)
        output = f'Instrument fixture memory {artifact}.'
        observation = {'trace_id': payload['trace_id'],
                       'input_sha256': digest(canonical(payload)),
                       'output_sha256': digest(output),
                       'source_ids': [s['source_id'] for s in payload['sources']],
                       'session_id': 'fixture-'+artifact, 'model_id': 'fixture',
                       'trace_kind': 'fixture', 'receipt_sha256': '1'*64,
                       'real_model_trace': False}
        getattr(driver, 'seal_'+artifact)(output, observed_input=payload, observation=observation)
        return payload, observation

    def ready(self):
        d = self.driver(); self.seal(d, 'M')
        d.revoke_s01_export(); d.confirm_old_M_denied(); self.seal(d, 'R')
        return d

    def target(self, delivery):
        self.calls.append(delivery)
        return {'status': 'fixture', 'real_model_trace': False}

    def test_real_sequence_is_staged_and_fixtures_never_claim_research_pass(self):
        d = self.ready(); outcome = d.commit_delivery(self.target)
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn('memory M', self.calls[0]['memory'])
        self.assertEqual(self.calls[0]['source_ids'], ['S02', 'S03', 'S04'])
        self.assertEqual(outcome['stage'], 'delivery_committed')
        self.assertFalse(outcome['real_model_trace'])
        self.assertEqual(outcome['research_result'], 'not_evaluated')
        inspected = inspect_event_trace(d.out/'event_trace.jsonl')
        self.assertTrue(inspected['registered_event_sequence_complete'])
        self.assertEqual(inspected['target_callback_outcome'], 'returned_unverified')
        self.assertFalse(inspected['research_passed'])
        self.assertTrue(inspected['instrument_only'])
        rows = verify_event_trace(d.out/'event_trace.jsonl')
        commit = next(e for e in rows if e['kind'] == 'delivery_committed')
        self.assertEqual(commit['stage'], 'delivery_committed')
        self.assertEqual(commit['data']['callback_invocation_intent'], 1)
        self.assertNotIn('callback_invocations', commit['data'])
        self.assertIsNone(commit['data']['physical_request_count'])

    def test_placeholder_text_cannot_be_exported(self):
        d = self.driver()
        self.assertEqual(d.check_unsealed_artifact_denied('M'), 'export_not_allowed')
        self.assertEqual(d.check_unsealed_artifact_denied('R'), 'export_not_allowed')

    def test_reversed_order_cannot_request_R_or_revoke_before_M(self):
        d = self.driver()
        for action in (lambda: d.begin_generation('R'), d.revoke_s01_export,
                       lambda: d.commit_delivery(self.target)):
            with self.assertRaisesRegex(DriverError, 'stage_order_violation'):
                action()
        self.assertEqual(self.calls, [])

    def test_generic_input_has_no_test_questions_or_reference_fields(self):
        d = self.driver(); payload = d.begin_generation('M')
        self.assertEqual(set(payload), {'trace_id', 'template_id', 'template', 'sources'})
        self.assertEqual([s['source_id'] for s in payload['sources']], ['S01', 'S02', 'S03', 'S04'])

    def test_S01_cannot_be_injected_into_R_actual_input(self):
        d = self.driver(); self.seal(d, 'M'); d.revoke_s01_export(); d.confirm_old_M_denied()
        payload = d.begin_generation('R'); observed = deepcopy(payload)
        observed['sources'].append(self.sources[0])
        with self.assertRaisesRegex(DriverError, 'observed_input_differs'):
            d.seal_R('fixture R', observed_input=observed, observation={})

    def test_previous_hash_tampering_is_detected_before_policy_mutation(self):
        d = self.driver(); self.seal(d, 'M')
        p = d.out/'event_trace.jsonl'; rows = p.read_text(encoding='utf-8').splitlines()
        value = json.loads(rows[-1]); value['previous_sha256'] = 'f'*64
        rows[-1] = json.dumps(value)
        p.write_text('\n'.join(rows)+'\n', encoding='utf-8')
        with self.assertRaises(DriverError):
            d.revoke_s01_export()
        self.assertTrue(d.snapshot()['S01']['export_allowed'])

    def test_expiry_before_revoke_is_not_counted_as_revocation(self):
        d = self.driver(ttl_seconds=1); self.seal(d, 'M'); time.sleep(1.05)
        with self.assertRaisesRegex(DriverError, 'pre_revocation_old_M_packet_expired'):
            d.revoke_s01_export()
        self.assertEqual(d.stage, 'M_sealed')
        self.assertTrue(d.snapshot()['S01']['export_allowed'])

    def test_expiry_after_revoke_does_not_pass_old_packet_denial_evidence(self):
        d = self.driver(ttl_seconds=1); self.seal(d, 'M'); d.revoke_s01_export(); time.sleep(1.05)
        with self.assertRaisesRegex(DriverError, 'expired_not_revocation_evidence'):
            d.confirm_old_M_denied()
        self.assertEqual(d.stage, 'revoked')
        self.assertEqual(self.calls, [])

    def test_policy_change_between_check_and_send_blocks_callback(self):
        d = self.ready()
        with self.assertRaisesRegex(DriverError, 'policy_changed_between_check_and_send'):
            d.commit_delivery(self.target, before_send=lambda host: host.set_source_export('S02', False))
        self.assertEqual(self.calls, [])
        self.assertFalse(d.snapshot()['R']['export_allowed'])

    def test_target_exception_is_unknown_and_never_replayed(self):
        d = self.ready()
        def fail(delivery):
            self.calls.append(delivery)
            raise RuntimeError('instrument failure after possible send')
        with self.assertRaisesRegex(DriverError, 'outcome_may_be_unknown'):
            d.commit_delivery(fail)
        with self.assertRaisesRegex(DriverError, 'halted'):
            d.commit_delivery(self.target)
        self.assertEqual(len(self.calls), 1)

        inspected = inspect_event_trace(d.out/'event_trace.jsonl')
        self.assertTrue(inspected['registered_event_sequence_complete'])
        self.assertEqual(inspected['target_callback_outcome'], 'failed_or_unknown')
        self.assertFalse(inspected['research_passed'])

    def test_source_unknown_attempt_halts_instead_of_sealing_an_error_as_memory(self):
        d = self.driver(); d.begin_generation('M')
        with self.assertRaisesRegex(DriverError, 'source_generation_unknown'):
            d.generation_failed('M', outcome='unknown')
        with self.assertRaisesRegex(DriverError, 'halted'):
            d.begin_generation('M')
        self.assertFalse(d.snapshot()['M']['export_allowed'])

    def test_policy_mutation_during_M_generation_cannot_grant_artifact(self):
        d = self.driver(); payload = d.begin_generation('M')
        output = 'Instrument fixture M.'
        observation = {'trace_id': payload['trace_id'], 'input_sha256': digest(canonical(payload)),
                       'output_sha256': digest(output), 'source_ids': list(('S01','S02','S03','S04')),
                       'session_id': 'fixture-M', 'model_id': 'fixture', 'trace_kind': 'fixture',
                       'receipt_sha256': '1'*64, 'real_model_trace': False}
        d.set_source_export('S02', False)
        with self.assertRaisesRegex(DriverError, 'policy_changed_during_generation'):
            d.seal_M(output, observed_input=payload, observation=observation)
        self.assertFalse(d.snapshot()['M']['export_allowed'])

    def test_invalid_target_receipt_cannot_allow_a_second_delivery(self):
        d = self.ready()
        with self.assertRaisesRegex(DriverError, 'after_possible_send'):
            d.commit_delivery(lambda _: None)
        with self.assertRaisesRegex(DriverError, 'halted'):
            d.commit_delivery(self.target)
        self.assertEqual(self.calls, [])

    def test_no_clock_injection_or_resume_entry(self):
        with self.assertRaises(TypeError):
            self.driver(clock=lambda: 0)
        d = self.driver()
        with self.assertRaisesRegex(DriverError, 'no_resume'):
            PreDeliveryRevocationDriver(d.out, self.sources, instrument_only=True)


class StructuralGateTests(unittest.TestCase):
    def test_text_or_numeric_trust_flags_cannot_qualify_a_candidate(self):
        graph = {'u1': ['S01', 'S02'], 'u2': ['S03', 'S04']}
        for value in ('false', 'true', 0, 1, None, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'must_be_boolean'):
                    nontriviality_gate(graph, trusted_input_trace=value)

    def test_full_mixed_AND_and_independent_cache_are_conventional_degeneracies(self):
        mixed = {'u1': ['S01', 'S02', 'S03', 'S04'], 'u2': ['S01', 'S02', 'S03', 'S04']}
        cache = {'u1': ['S01'], 'u2': ['S02'], 'u3': ['S03'], 'u4': ['S04']}
        for graph, reason in ((mixed, 'full_rebuild'), (cache, 'independent_source_cache')):
            result = nontriviality_gate(graph, trusted_input_trace=True)
            self.assertEqual(result['nontriviality_gate'], 'stop_candidate')
            self.assertIn(reason, result['reason'])
            self.assertFalse(result['research_passed'])

    def test_partial_mixed_graph_only_eligible_not_an_algorithm_success(self):
        graph = {'u1': ['S01', 'S02'], 'u2': ['S03', 'S04']}
        self.assertEqual(nontriviality_gate(graph)['nontriviality_gate'], 'inconclusive')
        result = nontriviality_gate(graph, trusted_input_trace=True)
        self.assertEqual(result['nontriviality_gate'], 'structurally_eligible_only')
        self.assertIsNone(result['method_advantage'])


if __name__ == '__main__':
    unittest.main()
