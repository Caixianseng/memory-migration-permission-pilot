"""Current-source provenance, query invalidation and fair-cache integration."""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest

from .pipeline import ARMS, DEFAULT_CONFIG, RepairPipeline
from experiments.memory_module_fusion_v1.context_adapter import ContextError, deliver
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost


def fixture():
    texts = [
        'Alpha\nThe Alpha project launches on Friday with Beta.',
        'Alpha\nThe Alpha project deadline is Friday.',
        'Beta\nBeta manages the launch of Alpha.',
        'Gamma\nGamma organizes Alpha project transport.',
        'Delta\nDelta runs a separate garden.',
        'Epsilon\nEpsilon runs a separate factory.',
    ]
    sources = [{'source_id': f'S{index+1:03d}', 'text': text, 'version': 1}
               for index, text in enumerate(texts)]
    parents = ['A', 'A', 'B', 'C', 'D', 'E']
    hierarchy = {source['source_id']: {'parent_id': parents[index],
        'position': 1 if index == 1 else 0, 'prev_id': 'S001' if index == 1 else None,
        'next_id': 'S002' if index == 0 else None} for index, source in enumerate(sources)}
    return {'case_id': 'repair-fixture', 'question': 'When does Alpha project launch?',
            'sources': sources, 'hierarchy': hierarchy}


def messages(prepared, question):
    return [{'role': 'system', 'content': 'Use only supplied memory.'},
            {'role': 'user', 'content': json.dumps({'memory': prepared.context,
                'questions': [{'question_id': 'Q', 'question': question}]})}]


class RepairPipelineTests(unittest.TestCase):
    def test_all_five_methods_bind_presented_originals_and_complete_current_reads(self):
        case = fixture()
        ids = [source['source_id'] for source in case['sources']]
        with tempfile.TemporaryDirectory() as directory:
            for arm in ARMS:
                host = LifecycleHost(case['sources'], Path(directory)/arm)
                pipeline = RepairPipeline(case, arm, host)
                initial = pipeline.initialize()
                self.assertEqual(initial['generation_model_calls'], 0)
                self.assertFalse(initial['receiver_has_received_package'])
                for allowed in (ids, ids[:-1], ids):
                    host.set_permissions(allowed)
                    prepared, trace = pipeline.prepare()
                    self.assertEqual(set(prepared.source_ids), set(allowed))
                    self.assertTrue(set(trace['presented_source_ids']) <= set(allowed))
                    self.assertEqual([span.source_id for span in prepared.span_witnesses],
                                     trace['presented_source_ids'])
                    self.assertTrue(all(span.start == 0 and span.end == len(span.excerpt)
                                        for span in prepared.span_witnesses))
                    actual = {source['source_id']: source['text'] for source in host.allowed_sources()}
                    for span in prepared.span_witnesses:
                        self.assertEqual(span.excerpt, actual[span.source_id])
                    calls = []
                    deliver(prepared, host, messages(prepared, case['question']), lambda: calls.append(1) or
                            {'output': '{}', 'receipt': {'instrument_only': True}})
                    self.assertEqual(calls, [1])
                    self.assertEqual(prepared.render_format, 'full_sources_v1')
                    self.assertEqual(prepared.context, '\n\n'.join(span.source_id+'\n'+span.excerpt
                                     for span in prepared.span_witnesses))

    def test_selective_reuses_unchanged_seed_queries_only_on_new_view(self):
        case = fixture()
        ids = [source['source_id'] for source in case['sources']]
        with tempfile.TemporaryDirectory() as directory:
            pipelines = {}
            hosts = {}
            for arm in ('repair_rebuild', 'repair_selective'):
                hosts[arm] = LifecycleHost(case['sources'], Path(directory)/arm)
                pipelines[arm] = RepairPipeline(case, arm, hosts[arm])
                pipelines[arm].initialize()
            results = {}
            for phase, allowed in enumerate((ids, ids[:-1], ids)):
                for arm, pipeline in pipelines.items():
                    hosts[arm].set_permissions(allowed)
                    results[arm] = pipeline.prepare()
                left, right = results['repair_rebuild'], results['repair_selective']
                self.assertEqual(left[0].context, right[0].context)
                self.assertEqual(left[1]['fallback'], right[1]['fallback'])
                if phase == 1:
                    self.assertFalse(left[1]['exact_view_reuse'])
                    self.assertFalse(left[1]['query_reused'])
                    self.assertTrue(right[1]['query_reused'])
                else:
                    self.assertTrue(left[1]['exact_view_reuse'])
                    self.assertTrue(left[1]['query_reused'])
                    self.assertTrue(right[1]['query_reused'])

    def test_revoked_seed_invalidates_whole_query_artifact(self):
        case = fixture()
        with tempfile.TemporaryDirectory() as directory:
            host = LifecycleHost(case['sources'], Path(directory)/'selective')
            pipeline = RepairPipeline(case, 'repair_selective', host)
            initial = pipeline.initialize()
            revoked = initial['retrieval']['query_dependencies'][0]
            host.set_permissions([source['source_id'] for source in case['sources']
                                  if source['source_id'] != revoked])
            prepared, trace = pipeline.prepare()
            self.assertFalse(trace['query_reused'])
            self.assertGreater(trace['cache']['current_binding_invalidated_artifacts'], 0)
            self.assertIn(revoked, trace['cache']['invalidated_query_source_ids'])
            self.assertNotIn(revoked, prepared.source_ids)
            self.assertNotIn(revoked, trace['retrieval']['query_dependencies'])

    def test_fallback_is_predispatch_and_no_fallback_is_real_ablation(self):
        case = fixture()
        config = {**DEFAULT_CONFIG, 'minimum_question_coverage': 1.0,
                  'require_bridge_expansion': True}
        # The absent relation term ensures a heuristic fallback without using
        # labels or a model-generated answer as a trigger.
        case['question'] = 'When does Alpha project launch intergalactically?'
        with tempfile.TemporaryDirectory() as directory:
            packets = {}
            for arm in ('repair_selective', 'repair_no_fallback'):
                host = LifecycleHost(case['sources'], Path(directory)/arm)
                pipeline = RepairPipeline(case, arm, host, config)
                pipeline.initialize()
                packet, trace = pipeline.prepare()
                packets[arm] = packet, trace
            self.assertTrue(packets['repair_selective'][1]['fallback'])
            self.assertFalse(packets['repair_no_fallback'][1]['fallback'])
            self.assertEqual(len(packets['repair_selective'][0].span_witnesses), len(case['sources']))
            self.assertLess(len(packets['repair_no_fallback'][0].span_witnesses), len(case['sources']))

    def test_nonrendered_read_dependency_revocation_blocks_commit(self):
        case = fixture()
        with tempfile.TemporaryDirectory() as directory:
            host = LifecycleHost(case['sources'], Path(directory)/'gate')
            pipeline = RepairPipeline(case, 'repair_no_fallback', host)
            pipeline.initialize()
            prepared, trace = pipeline.prepare()
            invisible = set(prepared.source_ids)-set(trace['presented_source_ids'])
            self.assertTrue(invisible)
            revoked = sorted(invisible)[0]
            called = []
            with self.assertRaises((ContextError, ValueError)):
                deliver(prepared, host, messages(prepared, case['question']),
                    lambda: called.append(1), before_commit=lambda:
                    host.set_permissions([sid for sid in prepared.source_ids if sid != revoked]))
            self.assertEqual(called, [])

    def test_late_initialization_and_labelled_input_rejected(self):
        case = fixture()
        with tempfile.TemporaryDirectory() as directory:
            host = LifecycleHost(case['sources'], Path(directory)/'late')
            pipeline = RepairPipeline(case, 'repair_selective', host)
            host.set_permissions(['S001'])
            with self.assertRaises(ValueError):
                pipeline.prepare()
            polluted = deepcopy(case)
            polluted['support_ids'] = ['S001']
            with self.assertRaises(ValueError):
                RepairPipeline(polluted, 'repair_selective', host)


if __name__ == '__main__':
    unittest.main()
