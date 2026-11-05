"""Raw-span fusion security tests; no SDK, network or answer-model calls."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.memory_module_fusion_v1 import context_adapter as adapter
from experiments.memory_module_fusion_v1.support_index import SupportIndex
from experiments.permission_context_v1 import authorized_expansion
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost
from experiments.revocation_grouping_v1.lifecycle_runner import target_messages


class ContextAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sources = [
            {'source_id': 'A', 'text': 'Original draft. The sponsor is Cedar. End of original.', 'version': 1},
            {'source_id': 'B', 'text': 'Separate original email. The legal review deadline is Friday.', 'version': 1},
            {'source_id': 'C', 'text': 'WITHDRAWN_CROSS_SOURCE_CANARY', 'version': 1},
            {'source_id': 'D', 'text': 'Independent original role-attribution record.', 'version': 1}]
        self.registry = {s['source_id']: s for s in self.sources}
        self.host = LifecycleHost(self.sources, Path(self.temp.name) / 'host')
        self.host.set_permissions(['A', 'B', 'D'])
        self.hierarchy = {
            'A': {'parent_id': 'P1', 'position': 0, 'prev_id': None, 'next_id': 'C'},
            'C': {'parent_id': 'P1', 'position': 1, 'prev_id': 'A', 'next_id': 'B'},
            'B': {'parent_id': 'P1', 'position': 2, 'prev_id': 'C', 'next_id': None},
            'D': {'parent_id': 'P2', 'position': 0, 'prev_id': None, 'next_id': None}}

    def supported(self, dependencies=('A', 'B', 'D'), span_ids=('A', 'B')):
        spans = []
        quotes = {'A': 'The sponsor is Cedar.', 'B': 'The legal review deadline is Friday.'}
        for sid in span_ids:
            text = self.registry[sid]['text']
            quote = quotes.get(sid, text)
            start = text.index(quote)
            spans.append({'source_id': sid, 'version': 1, 'source_sha256': adapter.digest(text),
                          'start': start, 'end': start + len(quote), 'excerpt': quote, 'quote': quote,
                          'quote_sha256': adapter.digest(quote), 'text_sha256': adapter.digest(quote)})
        return {'spans': spans, 'excerpts': spans, 'support_ids': list(dependencies),
                'source_ids': list(dependencies), 'source_hashes': {sid: adapter.digest(self.registry[sid]['text']) for sid in dependencies},
                'source_versions': {sid: 1 for sid in dependencies}, 'epoch': self.host.revision,
                'text': 'THIS FREEFORM DERIVED CLAIM MUST NOT BE FORWARDED'}

    @staticmethod
    def messages(prepared):
        return target_messages(prepared.context, [{'question_id': 'Q1', 'question': 'Who sponsors it and when is review?'}],
                               {'target_prompt': 'Answer only from current quoted evidence.'})

    @staticmethod
    def fixture_result():
        return {'output': '{}', 'receipt': {'instrument_only': True, 'physical_request_count': 0}}

    def test_cross_source_proof_only_sends_original_slices_and_keeps_all_dependencies(self):
        prepared = adapter.prepare_supported(self.host, self.supported(), max_source_bytes=128)
        self.assertEqual(prepared.source_ids, ('A', 'B', 'D'))
        self.assertEqual({s.source_id for s in prepared.span_witnesses}, {'A', 'B'})
        self.assertIn('The sponsor is Cedar.', prepared.context)
        self.assertIn('The legal review deadline is Friday.', prepared.context)
        self.assertNotIn('FREEFORM DERIVED CLAIM', prepared.context)
        self.assertNotIn(self.registry['D']['text'], prepared.context)
        self.assertNotIn(self.registry['C']['text'], prepared.context)
        self.assertEqual({w.source_id for w in prepared.witnesses}, {'A', 'B', 'D'})
        calls = []

        def call():
            events = [json.loads(line) for line in (Path(self.temp.name) / 'host/events.jsonl').read_bytes().splitlines()]
            self.assertEqual(events[-1]['kind'], 'delivery_committed')
            self.assertEqual(events[-1]['data']['sources'], ['A', 'B', 'D'])
            calls.append('local-fixture')
            return self.fixture_result()

        with patch.object(self.host, 'deliver', wraps=self.host.deliver) as host_delivery:
            adapter.deliver(prepared, self.host, self.messages(prepared), call)
            host_delivery.assert_called_once()
        self.assertEqual(calls, ['local-fixture'])

    def test_complete_unrendered_dependency_revocation_and_stale_policy_epoch_block(self):
        output = self.supported()
        prepared = adapter.prepare_supported(self.host, output)
        self.host.set_permissions(['A', 'B'])  # D has no printed slice, still a real proof dependency.
        with self.assertRaisesRegex(adapter.ContextError, 'stale_commit_epoch'):
            adapter.deliver(prepared, self.host, self.messages(prepared), lambda: self.fail('dispatch'))
        with self.assertRaisesRegex(adapter.ContextError, 'stale_commit_epoch'):
            adapter.prepare_supported(self.host, output)
        output['epoch'] = self.host.revision
        with self.assertRaisesRegex(adapter.ContextError, 'proof_depends_on_noncurrent'):
            adapter.prepare_supported(self.host, output)

    def test_epoch_change_in_host_commit_hook_never_invokes_call(self):
        prepared = adapter.prepare_supported(self.host, self.supported())
        with self.assertRaisesRegex(adapter.ContextError, 'stale_commit_epoch'):
            adapter.deliver(prepared, self.host, self.messages(prepared), lambda: self.fail('dispatch'),
                            before_commit=lambda: self.host.set_permissions(['A', 'D']))

    def test_messages_cannot_change_after_initial_validation(self):
        prepared = adapter.prepare_supported(self.host, self.supported())
        messages = self.messages(prepared)

        def replace_memory():
            payload = json.loads(messages[1]['content'])
            payload['memory'] += self.registry['C']['text']
            messages[1]['content'] = json.dumps(payload)

        with self.assertRaisesRegex(adapter.ContextError, 'target_memory_does_not_match'):
            adapter.deliver(prepared, self.host, messages, lambda: self.fail('dispatch'),
                            before_commit=replace_memory)
        messages = self.messages(prepared)
        with self.assertRaisesRegex(adapter.ContextError, 'target_messages_changed'):
            adapter.deliver(prepared, self.host, messages, lambda: self.fail('dispatch'),
                            before_commit=lambda: messages[0].update(content='Changed system task'))

    def test_actual_support_index_cross_source_rule_interoperates_and_retracts(self):
        index = SupportIndex(self.sources)
        self.addCleanup(index.close)
        for sid, fact, quote in [('A', 'sponsor', 'The sponsor is Cedar.'),
                                 ('B', 'deadline', 'The legal review deadline is Friday.')]:
            start = self.registry[sid]['text'].index(quote)
            index.register_exact_span(sid, start, start + len(quote), fact, expected_quote=quote)
        index.add_rule('PRIVATE_DERIVED_FACT_LABEL', ['sponsor', 'deadline'])
        index.set_allowed(['A', 'B', 'D'], epoch=self.host.revision,
                          versions={sid: 1 for sid in ('A', 'B', 'D')})
        rendered = index.render_supported(['PRIVATE_DERIVED_FACT_LABEL'])
        prepared = adapter.prepare_supported(self.host, rendered, max_source_bytes=128)
        self.assertEqual(prepared.source_ids, ('A', 'B'))
        self.assertEqual(len(prepared.span_witnesses), 2)
        self.assertNotIn('PRIVATE_DERIVED_FACT_LABEL', prepared.context)
        adapter.deliver(prepared, self.host, self.messages(prepared), self.fixture_result)
        self.host.set_permissions(['A', 'D'])
        index.set_allowed(['A', 'D'], epoch=self.host.revision, versions={'A': 1, 'D': 1})
        self.assertEqual(index.witnesses_for('PRIVATE_DERIVED_FACT_LABEL'), [])
        with self.assertRaisesRegex(adapter.ContextError, 'stale_commit_epoch'):
            adapter.deliver(prepared, self.host, self.messages(prepared), lambda: self.fail('dispatch'))

    def test_source_correction_invalidates_old_offsets_hashes_and_versions(self):
        output = self.supported()
        prepared = adapter.prepare_supported(self.host, output)
        self.host.sources['A'].update(text='Corrected original: sponsor is Maple.', version=2)
        with self.assertRaisesRegex(adapter.ContextError, 'stale_source_dependency'):
            adapter.deliver(prepared, self.host, self.messages(prepared), lambda: self.fail('dispatch'))
        with self.assertRaisesRegex(adapter.ContextError, 'support_source_hash_or_version_is_stale'):
            adapter.prepare_supported(self.host, output)

    def test_forged_offsets_and_cross_source_excerpt_are_rejected(self):
        forged = self.supported()
        forged['spans'][0]['start'] += 1
        with self.assertRaisesRegex(adapter.ContextError, 'nonoriginal_or_cross_source'):
            adapter.prepare_supported(self.host, forged)
        forged = self.supported()
        forged['spans'][0]['excerpt'] = self.registry['C']['text']
        with self.assertRaisesRegex(adapter.ContextError, 'nonoriginal_or_cross_source'):
            adapter.prepare_supported(self.host, forged)
        forged = self.supported()
        forged['spans'][0]['source_id'] = 'C'
        with self.assertRaisesRegex(adapter.ContextError, 'missing_from_complete_support'):
            adapter.prepare_supported(self.host, forged)

    def test_forged_prepared_span_context_and_hidden_message_payload_cannot_dispatch(self):
        prepared = adapter.prepare_supported(self.host, self.supported())
        changed = replace(prepared.span_witnesses[0], start=0)
        forged = replace(prepared, span_witnesses=(changed,) + prepared.span_witnesses[1:])
        with self.assertRaisesRegex(adapter.ContextError, 'span_offset_version_hash'):
            adapter.deliver(forged, self.host, self.messages(forged), lambda: self.fail('dispatch'))
        secret = prepared.context + '\n' + self.registry['C']['text']
        forged = replace(prepared, context=secret, context_sha256=adapter.digest(secret))
        with self.assertRaisesRegex(adapter.ContextError, 'outside_verified_original_slices'):
            adapter.deliver(forged, self.host, self.messages(forged), lambda: self.fail('dispatch'))
        messages = self.messages(prepared)
        payload = json.loads(messages[1]['content'])
        payload['hidden_context'] = self.registry['C']['text']
        messages[1]['content'] = json.dumps(payload)
        with self.assertRaisesRegex(adapter.ContextError, 'unbound_extra_target_payload'):
            adapter.deliver(prepared, self.host, messages, lambda: self.fail('dispatch'))
        messages = self.messages(prepared)
        messages.insert(1, {'role': 'user', 'content': self.registry['C']['text']})
        with self.assertRaisesRegex(adapter.ContextError, 'standard_target_memory'):
            adapter.deliver(prepared, self.host, messages, lambda: self.fail('dispatch'))

    def test_full_source_safe_expansion_and_optional_span_expansion_reuse_old_module(self):
        current = self.host.allowed_sources()
        full = adapter.prepare_sources(self.host, ['A'], current_sources=current, hierarchy=self.hierarchy,
                                       strategy='authorized_bundle', max_source_bytes=4096)
        self.assertEqual(full.source_ids, ('A', 'B'))
        self.assertEqual(full.render_format, 'full_sources_v1')
        self.assertEqual(full.context, 'A\n' + self.registry['A']['text'] + '\n\nB\n' + self.registry['B']['text'])
        output = self.supported(dependencies=('A',), span_ids=('A',))
        expanded = adapter.prepare_supported(self.host, output, hierarchy=self.hierarchy,
                    expansion_strategy='authorized_neighbor_window', neighbor_window=2, max_source_bytes=4096)
        self.assertEqual(expanded.source_ids, ('A', 'B'))
        self.assertEqual(expanded.span_witnesses[0].excerpt, 'The sponsor is Cedar.')
        self.assertEqual(expanded.span_witnesses[1].excerpt, self.registry['B']['text'])
        self.assertNotIn(self.registry['C']['text'], expanded.context)
        adapter.deliver(expanded, self.host, self.messages(expanded), self.fixture_result)

    def test_raw_proof_bundle_budget_is_atomic_and_naive_parent_is_never_adapted(self):
        output = self.supported()
        budget = sum(len(s['excerpt'].encode()) for s in output['spans']) - 1
        with self.assertRaisesRegex(adapter.ContextError, 'complete_raw_witness_bundle_exceeds'):
            adapter.prepare_supported(self.host, output, max_source_bytes=budget)
        with self.assertRaisesRegex(adapter.ContextError, 'naive_parent'):
            adapter.prepare_sources(self.host, ['A'], hierarchy=self.hierarchy, strategy='naive_parent_render')
        naive = authorized_expansion.prepare_context(self.host.allowed_sources(), ['A'], self.hierarchy,
            strategy='naive_parent_render', authorize=self.host.authorize, get_epoch=lambda: self.host.revision,
            max_source_bytes=4096, allow_unsafe_diagnostic=True,
            diagnostic_parent_renderer=lambda _: self.registry['A']['text'] + self.registry['C']['text'])
        with self.assertRaisesRegex(adapter.ContextError, 'unsafe_parent_or_unrecognized'):
            adapter.deliver(naive, self.host, self.messages(naive), lambda: self.fail('dispatch'))

    def test_legacy_summary_is_not_reinterpreted_as_a_raw_span_source(self):
        self.host.sources['A']['source_kind'] = 'legacy_llm_summary'
        with self.assertRaisesRegex(adapter.ContextError, 'summary_is_not_original_span_source'):
            adapter.prepare_sources(self.host, ['A'])


if __name__ == '__main__':
    unittest.main()
