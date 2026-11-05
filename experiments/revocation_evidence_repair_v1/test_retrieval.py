import copy
import hashlib
import json
import unittest

from .retrieval import RetrievalConfig, retrieve, validate_query_artifact
from experiments.memory_module_fusion_v1.bridge_repair import expand_authorized_links


def fixture():
    bodies = [
        ('A', 'Frostfield\nFrostfield designer Mira Voss designed the Frostfield vehicle.'),
        ('B', 'Frostfield review\nThe Frostfield designer reviewed Frostfield designer documentation.'),
        ('C', 'Frostfield design\nFrostfield designer specifications describe the Frostfield designer.'),
        ('D', 'Biographical records\nMira Voss was mentored by Nira Stone.'),
        ('E', 'Canal archive\nThe canal opened in 1900.'),
        ('F', 'Bird guide\nThese birds breed in coastal wetlands.'),
    ]
    sources = [{'source_id': sid, 'text': text, 'version': 1} for sid, text in bodies]
    hierarchy = {sid: {'parent_id': 'P'+sid, 'position': 0} for sid, _ in bodies}
    return sources, hierarchy, 'Who mentored the designer of Frostfield?'


class RetrievalTests(unittest.TestCase):
    def test_entity_relation_query_finds_bridge_without_exact_target_title(self):
        sources, hierarchy, question = fixture()
        result = retrieve(sources, question, hierarchy)
        seeds = result['stages'][0]['selected_source_ids']
        self.assertNotIn('D', seeds)
        self.assertIn('D', result['selected_source_ids'])
        self.assertEqual(result['stages'][1]['added_parent_ids'], ['PD'])
        old_ids, _ = expand_authorized_links(sources, seeds, hierarchy, question)
        self.assertNotIn('D', old_ids)
        self.assertTrue(any('Mira Voss' in q and 'mentored' in q for q in result['stages'][1]['queries']))
        self.assertFalse(result['needs_fallback'])
        self.assertTrue(result['fallback_is_heuristic_not_evidence_completeness_proof'])

    def test_selected_ids_are_whole_original_records_with_bounded_parent_count(self):
        sources, hierarchy, question = fixture()
        sources.insert(1, {'source_id': 'A2', 'text': 'Frostfield\nThe project began in 1999.', 'version': 1})
        hierarchy['A2'] = {'parent_id': 'PA', 'position': 1}
        original = copy.deepcopy(sources)
        result = retrieve(sources, question, hierarchy)
        self.assertEqual(sources, original)
        self.assertIn('A2', result['selected_source_ids'])
        self.assertEqual(len(result['selected_parent_ids']), 4)
        self.assertEqual(result['retrieval_round_limit'], 2)
        self.assertLessEqual(len(result['stages'][1]['queries']), 4)
        self.assertEqual(result['model_call_count'], 0)

    def test_input_order_and_extra_forbidden_hierarchy_metadata_do_not_change_output(self):
        sources, hierarchy, question = fixture()
        first = retrieve(sources, question, hierarchy)
        hierarchy['DENIED'] = {'parent_id': 'UNREAD', 'position': 0, 'answers': ['must not be read']}
        second = retrieve(list(reversed(sources)), question, hierarchy)
        self.assertEqual(first, second)
        self.assertNotIn('DENIED', second['actual_read_dependencies'])

    def test_missing_bridge_triggers_uncertainty_without_reintroducing_revoked_body(self):
        sources, hierarchy, question = fixture()
        current = [s for s in sources if s['source_id'] != 'D']
        result = retrieve(current, question, hierarchy)
        self.assertNotIn('D', result['selected_source_ids'])
        self.assertNotIn('D', result['actual_read_dependencies'])
        self.assertNotIn('Nira Stone', str(result))
        self.assertTrue(result['needs_fallback'])
        self.assertIn('no_additional_grounded_entity_parent', result['fallback_reasons'])

    def test_forbidden_record_rejected_before_ranking(self):
        sources, hierarchy, question = fixture()
        for key, value in [('allow', False), ('allowed', False), ('allow', None)]:
            candidate = copy.deepcopy(sources)
            candidate[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                retrieve(candidate, question, hierarchy)

    def test_rank_reads_all_current_sources_query_reads_only_ordered_seed_originals(self):
        sources, hierarchy, question = fixture()
        result = retrieve(sources, question, hierarchy)
        seeds = result['stages'][0]['selected_source_ids']
        self.assertEqual(result['query_dependencies'], seeds)
        self.assertEqual(result['actual_read_dependencies'], sorted(s['source_id'] for s in sources))
        self.assertNotIn('E', result['query_dependencies'])
        self.assertIn('E', [row['source_id'] for row in result['ranking_source_bindings']])
        self.assertEqual(result['query_source_bindings'], result['query_artifact']['ordered_seed_bindings'])
        for entity in result['query_artifact']['entities']:
            for quote in entity['quotes']:
                source = next(s for s in sources if s['source_id'] == quote['source_id'])
                self.assertEqual(source['text'][quote['start']:quote['end']], quote['quote'])

    def test_exact_query_reuse_still_recomputes_ranking(self):
        sources, hierarchy, question = fixture()
        first = retrieve(sources, question, hierarchy)
        second = retrieve(sources, question, hierarchy, query_artifact=first['query_artifact'])
        self.assertTrue(second['query_reused'])
        self.assertTrue(second['ranking_recomputed'])
        self.assertTrue(second['initial_ordered_seeds_rechecked'])
        self.assertEqual(first['selected_source_ids'], second['selected_source_ids'])
        self.assertEqual(first['stages'], second['stages'])
        self.assertEqual(first['query_artifact'], second['query_artifact'])
        # Mutation of returned artifact cannot modify the cached input object.
        second['query_artifact']['queries'].append('untrusted modification')
        self.assertNotEqual(first['query_artifact'], second['query_artifact'])

    def test_remove_nonseed_reuses_query_but_new_full_view_ranking_matches_rebuild(self):
        sources, hierarchy, question = fixture()
        first = retrieve(sources, question, hierarchy)
        # D was a ranking input and later bridge hit, but never a query seed.
        # Removing it preserves ordered initial seeds while changing ranking.
        current = [s for s in sources if s['source_id'] != 'D']
        repair = retrieve(current, question, hierarchy, query_artifact=first['query_artifact'])
        rebuild = retrieve(current, question, hierarchy)
        self.assertTrue(repair['query_reused'])
        self.assertNotEqual(repair['view_fingerprint'], first['view_fingerprint'])
        self.assertEqual(repair['stages'], rebuild['stages'])
        self.assertEqual(repair['selected_source_ids'], rebuild['selected_source_ids'])
        self.assertEqual(repair['needs_fallback'], rebuild['needs_fallback'])

    def test_surviving_old_seeds_are_insufficient_when_current_initial_ranking_changes(self):
        sources, hierarchy, question = fixture()
        first = retrieve(sources, question, hierarchy)
        current = [s for s in sources if s['source_id'] != 'E']
        self.assertTrue(set(first['query_dependencies']) <= {s['source_id'] for s in current})
        repair = retrieve(current, question, hierarchy, query_artifact=first['query_artifact'])
        self.assertFalse(repair['query_reused'])
        self.assertEqual(repair['query_reuse_reason'], 'current_ordered_initial_seeds_changed')
        self.assertEqual(repair['query_artifact'], retrieve(current, question, hierarchy)['query_artifact'])

    def test_seed_revocation_discards_entire_dependent_query_artifact(self):
        sources, hierarchy, question = fixture()
        first = retrieve(sources, question, hierarchy)
        revoked = first['query_dependencies'][0]
        current = [s for s in sources if s['source_id'] != revoked]
        repair = retrieve(current, question, hierarchy, query_artifact=first['query_artifact'])
        rebuild = retrieve(current, question, hierarchy)
        self.assertFalse(repair['query_reused'])
        self.assertEqual(repair['query_reuse_reason'], 'current_ordered_initial_seeds_changed')
        self.assertNotIn(revoked, repair['query_dependencies'])
        self.assertEqual(repair['query_artifact'], rebuild['query_artifact'])
        self.assertEqual(repair['selected_source_ids'], rebuild['selected_source_ids'])

    def test_current_seed_body_version_question_and_config_each_invalidate_query(self):
        sources, hierarchy, question = fixture()
        first = retrieve(sources, question, hierarchy)
        seed = first['query_dependencies'][0]
        body = copy.deepcopy(sources)
        next(s for s in body if s['source_id'] == seed)['text'] += ' Updated.'
        version = copy.deepcopy(sources)
        next(s for s in version if s['source_id'] == seed)['version'] += 1
        for current, q, config in [(body, question, None), (version, question, None),
                                    (sources, question+' Please answer.', None),
                                    (sources, question, {'minimum_question_coverage': .6})]:
            with self.subTest(q=q, config=config):
                result = retrieve(current, q, hierarchy, config, query_artifact=first['query_artifact'])
                self.assertFalse(result['query_reused'])
                self.assertEqual(result['selected_source_ids'], retrieve(current, q, hierarchy, config)['selected_source_ids'])

    def test_tampered_entity_query_is_not_executed(self):
        sources, hierarchy, question = fixture()
        first = retrieve(sources, question, hierarchy)
        damaged = copy.deepcopy(first['query_artifact'])
        damaged['queries'][0] = 'REVOKED SECRET CANARY'
        repaired = retrieve(sources, question, hierarchy, query_artifact=damaged)
        self.assertFalse(repaired['query_reused'])
        self.assertEqual(repaired['query_reuse_reason'], 'artifact_digest_mismatch')
        self.assertNotIn('REVOKED SECRET CANARY', str(repaired))

    def test_recomputed_digest_cannot_bind_arbitrary_query_or_relation_text(self):
        sources, hierarchy, question = fixture()
        original = retrieve(sources, question, hierarchy)['query_artifact']
        for mode in ('query', 'relation'):
            forged = copy.deepcopy(original)
            if mode == 'query':
                forged['queries'][0] += ' REVOKED SECRET CANARY'
            else:
                forged['relation_terms'].append('REVOKED SECRET CANARY')
            body = {key: value for key, value in forged.items() if key != 'artifact_sha256'}
            forged['artifact_sha256'] = hashlib.sha256(json.dumps(body, ensure_ascii=False,
                sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()
            result = retrieve(sources, question, hierarchy, query_artifact=forged)
            self.assertFalse(result['query_reused'])
            self.assertNotIn('REVOKED SECRET CANARY', str(result))

    def test_empty_no_match_and_full_current_view_are_explicit(self):
        empty = retrieve([], 'What happened?', {})
        self.assertEqual(empty['selected_source_ids'], [])
        self.assertTrue(empty['needs_fallback'])
        self.assertIn('empty_authorized_view', empty['fallback_reasons'])
        sources, hierarchy, _ = fixture()
        result = retrieve(sources, 'zzzzzzzz quuxquux?', hierarchy)
        self.assertTrue(result['needs_fallback'])
        self.assertIn('no_positive_initial_match', result['fallback_reasons'])
        full = retrieve(sources[:2], 'zzzzzzzz?', hierarchy)
        self.assertTrue(full['contains_all_current_sources'])
        self.assertFalse(full['needs_fallback'])

    def test_labels_unknown_config_and_invalid_parameters_rejected(self):
        sources, hierarchy, question = fixture()
        for cfg in ({'answer': 'SECRET'}, {'unknown': 1}, {'initial_parent_k': 2},
                    {'initial_parent_k': True}, {'initial_parent_k': 4, 'final_parent_k': 3},
                    {'max_entity_queries': 5}, {'minimum_question_coverage': float('nan')},
                    {'rrf_k': 0}, {'require_bridge_expansion': 1}):
            with self.subTest(config=cfg), self.assertRaises(ValueError):
                retrieve(sources, question, hierarchy, cfg)
        for q in ('', {'question': question, 'answer': 'SECRET'}, None):
            with self.subTest(question=q), self.assertRaises(ValueError):
                retrieve(sources, q, hierarchy)
        labelled = copy.deepcopy(sources)
        labelled[0]['origin'] = {'support_ids': ['A']}
        with self.assertRaises(ValueError):
            retrieve(labelled, question, hierarchy)

    def test_missing_hierarchy_duplicate_ids_and_invalid_versions_rejected(self):
        sources, hierarchy, question = fixture()
        for candidate in (sources + [sources[0]], [{**sources[0], 'version': False}]):
            with self.assertRaises(ValueError):
                retrieve(candidate, question, hierarchy)
        with self.assertRaises(ValueError):
            retrieve(sources, question, {})
        broken = copy.deepcopy(hierarchy)
        broken['A']['position'] = -1
        with self.assertRaises(ValueError):
            retrieve(sources, question, broken)


if __name__ == '__main__':
    unittest.main()
