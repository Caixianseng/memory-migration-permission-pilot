"""Offline safety/boundary tests, with real LifecycleHost gates and no SDK."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from experiments.permission_context_v1 import authorized_expansion as expansion
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost
from experiments.revocation_grouping_v1.lifecycle_runner import target_messages

FIXTURE = json.loads(Path(__file__).with_name('fixture_contract.json').read_bytes())


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = LifecycleHost(deepcopy(FIXTURE['sources']), Path(self.temp.name) / 'host')
        self.host.set_permissions(FIXTURE['allowed'])

    def prepare(self, strategy='authorized_bundle', **changes):
        options = dict(strategy=strategy, authorize=self.host.authorize,
                       get_epoch=lambda: self.host.revision,
                       max_source_bytes=FIXTURE['max_source_bytes'],
                       neighbor_window=FIXTURE['neighbor_window'])
        options.update(changes)
        return expansion.prepare_context(self.host.allowed_sources(), FIXTURE['seed_ids'],
                                         FIXTURE['hierarchy'], **options)

    @staticmethod
    def messages(prepared):
        return target_messages(prepared.context, [{'question_id': 'Q1', 'question': 'What is approved and when is its review?'}],
                               {'target_prompt': 'Use only delivered evidence.'})

    def test_parent_gap_reconstructed_from_legal_children_and_neighbor_baseline(self):
        def old_parent_must_not_be_read(_):
            raise AssertionError('safe expansion fetched old parent')
        child = self.prepare('child_only')
        secure = self.prepare(diagnostic_parent_renderer=old_parent_must_not_be_read)
        neighbor = self.prepare('authorized_neighbor_window')
        self.assertEqual(child.source_ids, ('C1',))
        self.assertNotIn('Friday', child.context)
        self.assertEqual(secure.source_ids, ('C1', 'C3'))
        self.assertIn('Friday', secure.context)
        self.assertNotIn(FIXTURE['canary'], secure.context)
        # The simple authorized window succeeds too; this fixture proves a
        # permission boundary, not superiority over another safe expansion.
        self.assertEqual(neighbor.source_ids, secure.source_ids)
        self.assertEqual(neighbor.context, secure.context)
        self.assertEqual({d['source_id'] for d in secure.diagnostics if d['kind'] == 'expansion_denied'}, {'C2', 'C4'})
        calls = []
        result = expansion.deliver(secure, self.host, self.messages(secure), lambda: (
            calls.append('fixture') or {'output': '{}', 'receipt': {'instrument_only': True, 'physical_request_count': 0}}))
        self.assertEqual(len(calls), 1)
        self.assertTrue(result['receipt']['instrument_only'])

    def test_naive_old_parent_exposes_canary_but_can_never_dispatch(self):
        def render_parent(parent):
            return '\n\n'.join(s['text'] for s in FIXTURE['sources']
                               if FIXTURE['hierarchy'][s['source_id']]['parent_id'] == parent)
        naive = self.prepare('naive_parent_render', allow_unsafe_diagnostic=True,
                             diagnostic_parent_renderer=render_parent)
        self.assertIn(FIXTURE['canary'], naive.context)
        self.assertFalse(naive.can_dispatch)
        calls = []
        with self.assertRaisesRegex(expansion.ExpansionError, 'cannot_dispatch'):
            expansion.deliver(naive, self.host, self.messages(naive), lambda: calls.append(1))
        self.assertEqual(calls, [])
        with self.assertRaisesRegex(expansion.ExpansionError, 'explicit_local_opt_in'):
            self.prepare('naive_parent_render', diagnostic_parent_renderer=render_parent)

    def test_epoch_change_after_prepare_and_during_commit_fails_closed(self):
        prepared = self.prepare()
        self.host.set_permissions(FIXTURE['allowed'])
        calls = []
        with self.assertRaises(expansion.ExpansionError) as caught:
            expansion.deliver(prepared, self.host, self.messages(prepared), lambda: calls.append(1))
        self.assertEqual(caught.exception.code, 'stale_commit_epoch')
        self.assertEqual(caught.exception.diagnostics[0]['kind'], 'stale_commit_epoch')
        fresh = self.prepare()
        with self.assertRaisesRegex(expansion.ExpansionError, 'stale_commit_epoch'):
            expansion.deliver(fresh, self.host, self.messages(fresh), lambda: calls.append(1),
                              before_commit=lambda: self.host.set_permissions(['C1']))
        self.assertEqual(calls, [])

    def test_source_mutation_and_forged_context_are_not_authorized_by_ids(self):
        prepared = self.prepare()
        forged = replace(prepared, context='injected old secret', context_sha256=expansion.digest('injected old secret'))
        with self.assertRaisesRegex(expansion.ExpansionError, 'not_verbatim_bound'):
            expansion.deliver(forged, self.host, self.messages(forged), lambda: self.fail('dispatch'))
        self.host.sources['C1']['text'] = 'changed without a revision'
        with self.assertRaisesRegex(expansion.ExpansionError, 'stale_source_version_or_content'):
            expansion.deliver(prepared, self.host, self.messages(prepared), lambda: self.fail('dispatch'))

    def test_budget_skips_whole_source_and_denied_callback_adds_no_body(self):
        texts = {s['source_id']: s['text'] for s in FIXTURE['sources']}
        budget = len(texts['C1'].encode()) + len(texts['C3'].encode()) - 1
        prepared = self.prepare(max_source_bytes=budget)
        self.assertEqual(prepared.source_ids, ('C1',))
        self.assertNotIn('Friday', prepared.context)
        self.assertTrue(any(d['kind'] == 'byte_budget_skipped_source' and d['source_id'] == 'C3' for d in prepared.diagnostics))

        def deny_c3(ids, purpose):
            if 'C3' in ids:
                raise ValueError('denied')
            return self.host.authorize(ids, purpose)
        denied = self.prepare(authorize=deny_c3)
        self.assertEqual(denied.source_ids, ('C1',))
        self.assertTrue(any(d.get('source_id') == 'C3' and d.get('reason') == 'host_authorization_denied' for d in denied.diagnostics))

    def test_bad_authorized_view_and_hierarchy_body_are_rejected(self):
        current = self.host.allowed_sources()
        with self.assertRaisesRegex(expansion.ExpansionError, 'only_current_authorized'):
            expansion.prepare_context([{**current[0], 'allow': False}], ['C1'], FIXTURE['hierarchy'],
                                      strategy='child_only', authorize=self.host.authorize,
                                      get_epoch=lambda: self.host.revision, max_source_bytes=4096)
        hierarchy = deepcopy(FIXTURE['hierarchy'])
        hierarchy['C1']['text'] = 'old parent body is not hierarchy metadata'
        with self.assertRaisesRegex(expansion.ExpansionError, 'only_parent_position_neighbor_ids'):
            expansion.prepare_context(current, ['C1'], hierarchy, strategy='authorized_bundle',
                                      authorize=self.host.authorize, get_epoch=lambda: self.host.revision,
                                      max_source_bytes=4096)

    def test_epoch_mutation_during_expansion_returns_no_prepared_context(self):
        def racing_authorize(ids, purpose):
            result = self.host.authorize(ids, purpose)
            self.host.set_permissions(FIXTURE['allowed'])
            return result
        with self.assertRaisesRegex(expansion.ExpansionError, 'stale_commit_epoch'):
            self.prepare(authorize=racing_authorize)


if __name__ == '__main__':
    unittest.main()
