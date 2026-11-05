"""First-delivery evidence packet repair over a trusted current source view.

All ranking is recomputed after permission changes. Selective reuse concerns
only a deterministic local query artifact; it is not an LLM-summary cache and
cannot save generation calls. Rendered originals and all query/ranking reads
remain bound to current authorization/version witnesses at the final gate.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import time

from .retrieval import RetrievalConfig, retrieve, validate_query_artifact
from experiments.memory_module_fusion_v1.context_adapter import prepare_supported
from experiments.memory_module_fusion_v1.strong_controls import select_control

ARMS = ('raw', 'parent_bm25_4', 'repair_rebuild', 'repair_selective', 'repair_no_fallback')
DEFAULT_CONFIG = asdict(RetrievalConfig())


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def _binding(source):
    return {'source_id': source['source_id'], 'version': source.get('version', 1),
            'text_sha256': digest(source['text'].encode('utf-8'))}


class RepairPipeline:
    def __init__(self, case, arm, host, config=None):
        if arm not in ARMS:
            raise ValueError('unknown_registered_repair_arm')
        if not isinstance(case.get('question'), str) or not case['question'].strip():
            raise ValueError('public_question_required')
        forbidden = {'answer', 'answers', 'support_ids', 'supporting_facts',
                     'evaluation', 'future_events', 'schedules', 'episodes'}
        if forbidden & set(case):
            raise ValueError('labels_or_future_events_in_case')
        self.question = case['question']
        self.case_id = case['case_id']
        self.hierarchy = deepcopy(case['hierarchy'])
        self.original_ids = tuple(source['source_id'] for source in case['sources'])
        if len(set(self.original_ids)) != len(self.original_ids):
            raise ValueError('duplicate_original_source_ids')
        self.arm, self.host = arm, host
        self.config = asdict(config) if isinstance(config, RetrievalConfig) else deepcopy(
            DEFAULT_CONFIG if config is None else config)
        self._artifact_by_view = {}
        self._selection_by_view = {}
        self._retrieval_by_view = {}
        self._latest_artifact = None
        self.initialization_trace = None
        self._state_index = 0

    @property
    def initialization_ms(self):
        return 0.0 if self.initialization_trace is None else self.initialization_trace['initialization_ms']

    def _view(self):
        epoch = self.host.revision
        current = self.host.allowed_sources()
        if self.host.revision != epoch:
            raise ValueError('permission_changed_during_current_view')
        by_id = {source['source_id']: source for source in current}
        if len(by_id) != len(current) or set(by_id) - set(self.original_ids):
            raise ValueError('current_view_not_original_registry')
        bindings = [_binding(by_id[sid]) for sid in sorted(by_id)]
        metadata = {sid: {'parent_id': self.hierarchy[sid]['parent_id'],
                          'position': self.hierarchy[sid]['position']} for sid in sorted(by_id)}
        return epoch, current, by_id, digest({'bindings': bindings, 'hierarchy': metadata,
            'question': self.question, 'config': self.config})

    def initialize(self):
        """Construct once at full-permission T0; this sends no model request."""
        if self.initialization_trace is not None:
            return deepcopy(self.initialization_trace)
        began = time.perf_counter()
        epoch, current, by_id, view_key = self._view()
        if set(by_id) != set(self.original_ids):
            raise ValueError('initial_full_permission_construction_required')
        retrieval = None
        if self.arm.startswith('repair_'):
            retrieval = retrieve(current, self.question, self.hierarchy, self.config)
            artifact = deepcopy(retrieval['query_artifact'])
            self._artifact_by_view[view_key] = artifact
            self._retrieval_by_view[view_key] = deepcopy(retrieval)
            self._latest_artifact = artifact
            selected = retrieval['selected_source_ids']
        elif self.arm == 'parent_bm25_4':
            selected, _ = select_control(self.question, current, self.hierarchy,
                                         'authorized_parent_bm25_top4')
        else:
            selected = [source['source_id'] for source in current]
        self._selection_by_view[view_key] = list(selected)
        if self.host.revision != epoch:
            raise ValueError('permission_changed_during_initial_construction')
        self.host.authorize(sorted(by_id), 'repair-t0-read')
        trace = {'phase': 'T0', 'arm': self.arm, 'prepared_epoch': epoch,
            'initial_read_dependencies': sorted(by_id), 'initial_selected_source_ids': selected,
            'retrieval': retrieval, 'initialization_ms': (time.perf_counter()-began)*1000,
            'generation_model_calls': 0, 'local_retrieval_executed': retrieval is not None,
            'not_an_llm_derived_summary': True, 'receiver_has_received_package': False}
        self.host.log('repair_initial_constructed', {'arm': self.arm,
            'dependencies': sorted(by_id), 'trace_sha256': digest(trace),
            'generation_model_calls': 0})
        self.initialization_trace = deepcopy(trace)
        return deepcopy(trace)

    def _cache_candidate(self, by_id, view_key):
        # Previously revoked artifacts remain inert in the private trusted
        # store. Regrant can reactivate only after current full bindings and
        # CURRENT ordered seeds are revalidated by retrieve().
        invalidated, retained = 0, 0
        invalidated_ids = set()
        unique = {artifact['artifact_sha256']: artifact
                  for artifact in self._artifact_by_view.values()}
        for artifact in unique.values():
            stale = [binding['source_id'] for binding in artifact['ordered_seed_bindings']
                     if binding['source_id'] not in by_id
                     or _binding(by_id[binding['source_id']]) != binding]
            if stale:
                invalidated += 1
                invalidated_ids.update(stale)
            else:
                retained += 1
        candidate = self._artifact_by_view.get(view_key, self._latest_artifact)
        return deepcopy(candidate), {'stored_unique_query_artifacts': len(unique),
            'current_binding_retained_artifacts': retained,
            'current_binding_invalidated_artifacts': invalidated,
            'invalidated_query_source_ids': sorted(invalidated_ids),
            'artifact_text_never_partially_sanitized': True}

    def _packet(self, selected, dependencies, current, epoch):
        by_id = {source['source_id']: source for source in current}
        if len(selected) != len(set(selected)) or set(selected)-set(by_id):
            raise ValueError('selected_source_not_current_authorized')
        dependencies = sorted(set(dependencies) | set(selected))
        if set(dependencies)-set(by_id):
            raise ValueError('query_or_ranking_dependency_not_current_authorized')
        rendered = {'epoch': epoch, 'source_ids': dependencies, 'support_ids': dependencies,
            'source_hashes': {sid: digest(by_id[sid]['text'].encode('utf-8')) for sid in dependencies},
            'source_versions': {sid: by_id[sid].get('version', 1) for sid in dependencies},
            'spans': [{'source_id': sid, 'version': by_id[sid].get('version', 1),
                'permission_version': by_id[sid]['permission_version'],
                'source_sha256': digest(by_id[sid]['text'].encode('utf-8')),
                'start': 0, 'end': len(by_id[sid]['text']), 'excerpt': by_id[sid]['text'],
                'quote_sha256': digest(by_id[sid]['text'].encode('utf-8'))} for sid in selected]}
        prepared = prepare_supported(self.host, rendered, current_sources=current, max_source_bytes=None)
        # Offsets and complete read dependencies remain internal witnesses.
        # The target model needs only original source IDs and whole text;
        # sending JSON audit headers per sentence would especially bloat raw.
        compact = '\n\n'.join(span.source_id + '\n' + span.excerpt
                              for span in prepared.span_witnesses)
        return replace(prepared, context=compact,
                       context_sha256=digest(compact.encode('utf-8')),
                       render_format='full_sources_v1')

    def prepare(self):
        began = time.perf_counter()
        if self.initialization_trace is None:
            self.initialize()  # Fails closed if first invoked after withdrawal.
        epoch, current, by_id, view_key = self._view()
        retrieval, control_trace, fallback = None, None, False
        exact_view_reuse = view_key in self._selection_by_view
        ranking_recomputed = False
        cache_trace = {'stored_unique_query_artifacts': len(self._artifact_by_view),
            'current_binding_retained_artifacts': 0, 'current_binding_invalidated_artifacts': 0,
            'invalidated_query_source_ids': [], 'artifact_text_never_partially_sanitized': True}
        if self.arm == 'raw':
            selected = [source['source_id'] for source in current]
            dependencies = list(selected)
        elif self.arm == 'parent_bm25_4':
            if exact_view_reuse:
                selected = list(self._selection_by_view[view_key])
                control_trace = {'exact_authorized_view_ID_metadata_reuse': True}
            else:
                selected, control_trace = select_control(self.question, current, self.hierarchy,
                                                         'authorized_parent_bm25_top4')
                ranking_recomputed = True
            dependencies = sorted(by_id)  # Its BM25 ranking also read all current parents.
        else:
            candidate, cache_trace = self._cache_candidate(by_id, view_key)
            if exact_view_reuse:
                retrieval = deepcopy(self._retrieval_by_view[view_key])
                seeds = [by_id[sid] for sid in retrieval['stages'][0]['selected_source_ids']]
                valid, reason = validate_query_artifact(retrieval['query_artifact'], seeds,
                                                        self.question, self.config)
                if not valid:
                    raise ValueError('trusted_exact_view_cache_corrupt:' + reason)
                retrieval.update(query_reused=True, query_build_performed=False,
                    query_reuse_reason='exact_authorized_view_metadata_rechecked',
                    ranking_recomputed=False, bm25_scoring_passes=0)
            else:
                if self.arm == 'repair_rebuild':
                    candidate = None
                retrieval = retrieve(current, self.question, self.hierarchy, self.config,
                                     query_artifact=candidate)
                ranking_recomputed = True
            dependencies = sorted(set(retrieval['actual_read_dependencies'])
                                  | set(retrieval['query_dependencies']))
            selected = retrieval['selected_source_ids']
            fallback = self.arm != 'repair_no_fallback' and retrieval['needs_fallback']
            if fallback:
                selected = [source['source_id'] for source in current]
            artifact = deepcopy(retrieval['query_artifact'])
            self._artifact_by_view[view_key] = artifact
            self._retrieval_by_view[view_key] = deepcopy(retrieval)
            self._latest_artifact = artifact
        self._selection_by_view[view_key] = list(selected)
        if self.host.revision != epoch:
            raise ValueError('permission_changed_during_retrieval')
        self.host.authorize(dependencies, 'repair-current-query-and-ranking')
        prepared = self._packet(selected, dependencies, current, epoch)
        self._state_index += 1
        trace = {'arm': self.arm, 'state_index': self._state_index,
            'initialization_ms': self.initialization_ms,
            'T0_cost_already_counted_once': True, 'initialization_trace': self.initialization_trace,
            'current_epoch': epoch, 'view_fingerprint': view_key,
            'presented_source_ids': list(selected), 'complete_read_dependencies': list(prepared.source_ids),
            'query_reused': bool(retrieval and retrieval['query_reused']),
            'exact_view_reuse': exact_view_reuse,
            'ranking_recomputed': ranking_recomputed, 'cache': cache_trace,
            'fallback': fallback,
            'fallback_reasons': retrieval['fallback_reasons'] if retrieval else [],
            'fallback_decided_before_generation': True,
            'fallback_is_not_evidence_completeness_proof': True,
            'retrieval': retrieval, 'control': control_trace,
            'prepared': asdict(prepared),
            'generation_model_calls': 0, 'local_query_generation_model_calls': 0,
            'full_selected_originals_retained': True, 'byte_cap': None,
            'total_prepare_ms': (time.perf_counter()-began)*1000}
        self.host.log('repair_context_prepared', {'arm': self.arm,
            'presented_source_ids': selected, 'complete_read_dependencies': list(prepared.source_ids),
            'context_sha256': prepared.context_sha256, 'query_reused': trace['query_reused'],
            'fallback': fallback, 'trace_sha256': digest(trace)})
        return prepared, trace

    def close(self):
        pass


__all__ = ['ARMS', 'DEFAULT_CONFIG', 'RepairPipeline']
