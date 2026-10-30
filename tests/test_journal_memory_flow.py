"""Finite exact-propagation diagnostics; no model or network requests."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from experiments.journal_methods_20261030 import verify_memory_flow as flow
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study import privacy
from memory_migration_study import source_annotation
from memory_migration_study.sensitivity_contract import STRICT_CUSTOMER_RELATION, category_contract


class MemoryFlowTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch("socket.socket", side_effect=AssertionError("network_forbidden"))
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.policy = {"version": "v1", "protected_categories": ["CUSTOMER"]}
        self.principals = [{"user_id": "alice", "agent_id": "qoder"},
                           {"user_id": "alice", "agent_id": "harness"}]
        self.source = {"source_id": "original", "text": "客户为苔藓。公开展览也叫苔藓。"}
        self.fact = {"text": self.source["text"][:6], "source_start": 0,
                     "source_end": 6, "findings": [{"start": 3, "end": 5, "category": "CUSTOMER"}]}
        self.authority = MemoryLabelAuthority(b"controlled-test-key-only-0000000000")
        self.record = self.authority.build_record(self.source, self.fact, self.policy,
            owner_id="alice", agent_id="qoder", allowed_principals=self.principals,
            builder_version="fixed-exact-v1")

    def test_actual_signed_record_shape_passes_and_states_boundaries(self):
        result = flow.verify_exact_record(self.record, expected_source=self.source,
            expected_principals=self.principals, expected_policy_version="v1")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["privacy_completeness"], "not_established")
        self.assertEqual(result["signature_verification"], "not_performed")

    def test_content_source_and_policy_changes_fail(self):
        for path, value in [(('text',), '另一个事实'), (('source', 'sha256'), '0'*64),
                            (('label', 'policy_version'), 'v2')]:
            with self.subTest(path=path):
                item = deepcopy(self.record)
                target = item
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assertEqual(flow.verify_exact_record(item, expected_policy_version="v1")["status"], "failed")

    def test_private_label_cannot_supply_or_widen_authority(self):
        item = deepcopy(self.record)
        item['access']['principal_scope']['principals'] = [{"user_id": "bob", "agent_id": "harness"}]
        item['label']['access_sha256'] = flow._digest(item['access'])
        self.assertIn("trusted_principal_scope_mismatch", flow.verify_exact_record(item,
            expected_principals=self.principals)["errors"])

    def test_empty_privacy_labels_are_not_completeness_proof_or_new_grant(self):
        item = self.authority.build_record(self.source, {**self.fact, "findings": []}, self.policy,
            owner_id="alice", agent_id="qoder", allowed_principals=self.principals, builder_version="fixed-v1")
        result = flow.verify_exact_record(item, expected_principals=self.principals)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['authorization_evaluation'], 'not_performed')
        self.assertEqual(result['privacy_completeness'], 'not_established')

    def test_schema_epoch_and_scope_must_match_existing_contract(self):
        for path, value in [(('schema',), 'other'), (('label', 'status'), 'unknown'),
                            (('label', 'epoch'), 2), (('access', 'scope_version'), 'source-only')]:
            with self.subTest(path=path):
                changed = deepcopy(self.record)
                target = changed
                for key in path[:-1]: target = target[key]
                target[path[-1]] = value
                self.assertEqual(flow.verify_exact_record(changed)['status'], 'failed')

    def test_cartesian_or_mixed_principal_contract_is_not_silently_accepted(self):
        for mixed in (True, False):
            item = deepcopy(self.record)
            if not mixed:
                del item['access']['principal_scope']
            item['access']['readers'] = ['alice']
            self.assertIn('exact_principal_contract_required', flow.verify_exact_record(item)['errors'])

    def test_same_string_different_occurrence_is_not_independent_evidence(self):
        start = self.source['text'].rindex('苔藓')
        segment = {"source_start": start, "source_end": start+2, "output_start": 0, "output_end": 2}
        earlier = {**segment, 'source_start': 3, 'source_end': 5}
        self.assertEqual(flow.verify_projection(self.source, '苔藓', [segment], expected_segments=[segment])['status'], 'ok')
        self.assertIn('trusted_source_occurrence_mismatch', flow.verify_projection(
            self.source, '苔藓', [earlier], expected_segments=[segment])['errors'])

    def test_record_expected_occurrence_is_separate_from_matching_bytes(self):
        origin = {'source_id': 'original', 'source_start': 0, 'source_end': 6}
        self.assertEqual(flow.verify_exact_record(self.record, expected_origin=origin)['status'], 'ok')
        self.assertIn('trusted_source_occurrence_mismatch', flow.verify_exact_record(self.record,
            expected_origin={**origin, 'source_start': 7, 'source_end': 13})['errors'])

    def test_partial_unbound_output_or_model_summary_rejected(self):
        segment = {'source_start': 0, 'source_end': 6, 'output_start': 0, 'output_end': 6}
        self.assertEqual(flow.verify_projection(self.source, self.fact['text'], [segment])['status'], 'ok')
        self.assertIn('projection_output_not_fully_bound', flow.verify_projection(self.source,
            self.fact['text']+'补写', [segment])['errors'])
        self.assertIn('unsupported_semantic_transformation', flow.verify_projection(self.source,
            '该公司是一家客户', [], transform='summary')['errors'])

    def test_joint_dependencies_intersect_pairs_and_report_conservative_loss(self):
        alice_q = {'user_id': 'alice', 'agent_id': 'qoder'}
        alice_h = {'user_id': 'alice', 'agent_id': 'harness'}
        bob_h = {'user_id': 'bob', 'agent_id': 'harness'}
        result = flow.verify_joint_readers([[alice_q, alice_h], [alice_h, bob_h]], [alice_h])
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['permitted_pair_count'], 1)
        self.assertIn('joint_dependency_reader_widening', flow.verify_joint_readers(
            [[alice_q, alice_h], [alice_h, bob_h]], [alice_q])['errors'])
        self.assertEqual(flow.verify_joint_readers([[alice_q], [bob_h]], [])['status'], 'ok')
        self.assertEqual(flow.verify_joint_readers([], [])['status'], 'failed')

    def packet(self):
        item = self.record
        return {'schema': 'agent_memory_handoff_v1', 'audience': {'user_id': 'alice', 'agent_id': 'harness', 'workspace_id': 'target'},
            'issued_at': 100, 'expires_at': 200, 'items': [{'record_id': item['record_id'],
            'text': item['text'], 'content_sha256': flow._hash(item['text']),
            'origin': {'source_id': item['source']['source_id'], 'source_sha256': item['source']['sha256'],
            'source_start': item['source_start'], 'source_end': item['source_end']},
            'grant_ref': {'record_id': item['record_id'], 'policy_version': 'v1', 'version': 1}}]}

    def verify_packet(self, packet, **kwargs):
        return flow.verify_handoff(packet, [self.record], expected_audience=self.packet()['audience'],
            expected_policy_version='v1', **kwargs)

    def test_native_packet_fields_bind_audience_origin_policy_and_time(self):
        self.assertEqual(self.verify_packet(self.packet(), now=100)['status'], 'ok')
        for mutate in ('audience', 'origin', 'version', 'text', 'duplicate'):
            with self.subTest(mutate=mutate):
                packet = self.packet()
                if mutate == 'audience': packet['audience']['agent_id'] = 'qoder'
                if mutate == 'origin': packet['items'][0]['origin']['source_start'] = 1
                if mutate == 'version': packet['items'][0]['grant_ref']['policy_version'] = 'v2'
                if mutate == 'text': packet['items'][0]['text'] += '!'
                if mutate == 'duplicate': packet['items'].append(deepcopy(packet['items'][0]))
                self.assertEqual(self.verify_packet(packet)['status'], 'failed')
        self.assertIn('handoff_lifetime_mismatch', self.verify_packet(self.packet(), now=200)['errors'])
        self.assertIn('operation_contract_mismatch', self.verify_packet(self.packet(), expected_operation='restore')['errors'])

    def prepare(self):
        original = {'query': 'Who is the customer?', 'memories': [{'source_id': 'fact1', 'text': self.fact['text']}]}
        policy = {**self.policy, 'entity_registry': [{'value': '苔藓', 'category': 'CUSTOMER'}]}
        detected = privacy.detect_sensitive(original, policy, mode='rules')
        prepared = privacy.prepare_private_payload(original, detected, actor_id='alice', request_id='req1',
            policy_version='v1', authorizer=lambda *args: True, sensitivity_policy=policy)
        self.assertEqual(prepared['status'], 'ok')
        permit = {'policy_version': 'v1', 'allowed_transformations': ['fixed_pseudonymization'],
                  'allowed_recipients': ['harness-model-provider'], 'allowed_source_ids': ['fact1']}
        return original, prepared, permit

    def test_existing_pseudonymization_needs_explicit_recipient_and_transform_permission(self):
        original, prepared, permit = self.prepare()
        result = flow.verify_pseudonymized_view(original, prepared, recipient='harness-model-provider', disclosure_policy=permit)
        self.assertEqual(result['status'], 'ok')
        self.assertFalse(result['mapping_persisted'])
        self.assertNotIn('苔藓', json.dumps(result, ensure_ascii=False))
        for field in ('allowed_transformations', 'allowed_recipients', 'allowed_source_ids'):
            altered = {**permit, field: []}
            self.assertEqual(flow.verify_pseudonymized_view(original, prepared,
                recipient='harness-model-provider', disclosure_policy=altered)['status'], 'failed')
        self.assertEqual(flow.verify_pseudonymized_view(original, prepared,
            recipient='harness-model-provider', disclosure_policy={})['status'], 'failed')

    def test_payload_hash_recompute_does_not_hide_plaintext_reinsertion(self):
        original, prepared, permit = self.prepare()
        prepared['payload']['memories'][0]['text'] = self.fact['text']
        prepared['metadata']['payload_sha256'] = flow._digest(prepared['payload'])
        result = flow.verify_pseudonymized_view(original, prepared,
            recipient='harness-model-provider', disclosure_policy=permit)
        self.assertIn('view_memory_projection_mismatch', result['errors'])

    def test_mapping_fields_cannot_be_in_outbound_view(self):
        original, prepared, permit = self.prepare()
        prepared['payload']['mapping'] = {'private': 'not-a-real-map'}
        result = flow.verify_pseudonymized_view(original, prepared,
            recipient='harness-model-provider', disclosure_policy=permit)
        self.assertIn('restoration_mapping_exposed_in_view', result['errors'])

    def test_source_annotation_existing_exact_projection_ignores_other_occurrence(self):
        class FixedAgent:
            max_local_calls = 1
            def __call__(self, **kwargs):
                return {'status': 'ok', 'findings': [{'start': 3, 'end': 5, 'category': 'CUSTOMER', 'quote': '苔藓'}],
                    'errors': [], 'local_calls': 0, 'elapsed_seconds': 0.0}
        result = source_annotation.annotate_and_build_records(self.source, [{**self.fact, 'findings': []}],
            {**self.policy, 'category_contract': category_contract(STRICT_CUSTOMER_RELATION)},
            agent=FixedAgent(), authority=self.authority, owner_id='alice', agent_id='qoder',
            allowed_principals=self.principals, builder_version='exact-source-v1', detector_version='fixed-v1')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['records'][0]['label']['findings'], self.fact['findings'])
        self.assertEqual(flow.verify_exact_record(result['records'][0])['status'], 'ok')

    def test_declared_source_positive_must_survive_at_exact_location(self):
        finding = {'start': 3, 'end': 5, 'category': 'CUSTOMER', 'quote': '苔藓'}
        self.assertEqual(flow.verify_annotation_projection([finding], self.record)['status'], 'ok')
        changed = self.authority.build_record(self.source, {**self.fact, 'findings': []}, self.policy,
            owner_id='alice', agent_id='qoder', allowed_principals=self.principals, builder_version='exact-v1')
        self.assertIn('source_positive_lost_in_projection', flow.verify_annotation_projection([finding], changed)['errors'])
        position = self.source['text'].rindex('苔藓')
        outside = {**finding, 'start': position, 'end': position+2}
        result = flow.verify_annotation_projection([outside], changed)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['outside_positive_count'], 1)
        self.assertEqual(result['projected_positive_count'], 0)
        crossing = {'start': 4, 'end': 7, 'category': 'CUSTOMER'}
        self.assertIn('source_positive_crosses_excerpt_boundary', flow.verify_annotation_projection([crossing], self.record)['errors'])


if __name__ == '__main__':
    unittest.main()
