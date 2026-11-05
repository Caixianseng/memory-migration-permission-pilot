"""Three-module composition and registered ablations; no model call on import."""
from dataclasses import asdict
import hashlib
import time

from .context_adapter import prepare_sources, prepare_supported
from .retrieval_assurance import prepare_retrieval
from .support_index import SupportIndex
from experiments.revocation_grouping_v1.retrieval_baseline import select

FACTORIAL = {f'h{h}p{p}r{r}': {'hierarchy': bool(h), 'proof': bool(p), 'rerank': bool(r)}
             for h in (0, 1) for p in (0, 1) for r in (0, 1)}
ARMS = tuple(FACTORIAL) + ('raw', 'fixed_rerank', 'adaptive_bm25', 'neighbor', 'parent_bm25')


def fingerprint(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


class FusionPipeline:
    def __init__(self, case, arm, host, *, ranker=None, retrieval_config=None):
        started = time.perf_counter()
        if arm not in ARMS:
            raise ValueError('unknown_registered_fusion_arm')
        self.case, self.arm, self.host, self.ranker = case, arm, host, ranker
        self.features = FACTORIAL.get(arm, {'hierarchy': False, 'proof': False, 'rerank': False})
        self.config = dict(retrieval_config or {})
        self.registry = {s['source_id']: s for s in case['sources']}
        self.cache, self.last = {}, None
        self.fact_by_source = {}
        self.bundle_heads = {}
        self.index = None
        if self.features['proof']:
            # Default is deny-all but policy-unbound: the first actual host
            # revision binds grants. Passing [] would create a synthetic epoch.
            self.index = SupportIndex(case['sources'], db_path=host.root/'support.sqlite')
            for sid, source in self.registry.items():
                # The complete title+sentence is the fact identity. Bare equal
                # pronoun sentences under different titles are NOT equivalent.
                fid = 'F'+fingerprint(source['text'])
                self.fact_by_source[sid] = self.index.register_exact_span(sid, 0, len(source['text']), fid,
                                                                          expected_quote=source['text'])
        self.initialization_ms = (time.perf_counter()-started)*1000

    def prepare(self):
        started = time.perf_counter()
        host = self.host
        current = host.allowed_sources()
        by_id = {s['source_id']: s for s in current}
        allowed = set(by_id)
        state_key = tuple(sorted((sid, source.get('version',1), fingerprint(source['text']))
                                 for sid, source in by_id.items()))
        question = {'question_id': self.case['case_id'], 'question': self.case['question']}
        maintenance = None
        if self.index is not None:
            maintenance = self.index.set_allowed(sorted(allowed), epoch=host.revision)
        trace, selected, cached = {}, None, None
        if self.arm == 'raw':
            selected = [sid for sid in self.registry if sid in allowed]
        elif state_key in self.cache:
            selected = list(self.cache[state_key]['ids'])
            cached = 'exact_authorized_view'
        elif self.last is not None:
            if self.index is not None:
                facts = self.last['facts']
                proof_head = self.last.get('proof_head')
                if proof_head is not None and proof_head in self.index.active_facts():
                    rendered = self.index.render_supported([proof_head])
                    # This validates the actual finite proof as original spans,
                    # even though the main ablation uses equal full-source
                    # formatting to isolate cache repair from compression.
                    proof_check = prepare_supported(host, rendered, current_sources=current)
                    selected = list(proof_check.source_ids)
                    cached = 'surviving_exact_context_bound_proofs'
            elif set(self.last['ids']) <= allowed:
                selected = list(self.last['ids'])
                cached = 'current_dependencies_rechecked'
        if selected is None:
            if self.arm == 'parent_bm25':
                groups = {}
                for source in current:
                    parent = self.case['hierarchy'][source['source_id']]['parent_id']
                    groups.setdefault(parent, []).append(source)
                parent_sources = [{'source_id': parent,
                    'text': '\n'.join(s['text'] for s in sources), 'allow': True}
                    for parent, sources in sorted(groups.items())]
                chosen = select(parent_sources, [self.case['question']], top_k=2)
                selected = [s['source_id'] for parent in chosen for s in groups[parent['source_id']]]
                trace = {'method': 'authorized_parent_bm25', 'ranker_call_count': 0}
            else:
                method = ('adaptive_rerank' if self.features['rerank'] else 'bm25')
                if self.arm in ('fixed_rerank','adaptive_bm25'):
                    method = self.arm
                cfg = {**self.config, 'method': method}
                trace = prepare_retrieval(current, [question], ranker=self.ranker, config=cfg,
                    authorize=host.authorize, get_epoch=lambda: host.revision)
                selected = trace['selected_source_ids']
        if set(selected)-allowed:
            raise AssertionError('fusion_selected_forbidden_source')
        if self.index is not None:
            fact_ids = list(dict.fromkeys(self.fact_by_source[sid] for sid in selected))
            body = tuple(sorted(fact_ids))
            proof_head = None
            if body:
                if body not in self.bundle_heads:
                    head = 'B'+fingerprint(self.case['case_id']+'\0'+'\0'.join(body))
                    self.index.add_rule(head,list(body))
                    self.bundle_heads[body] = head
                proof_head = self.bundle_heads[body]
            # Include a real independently verified span-proof pass for every
            # P-enabled decision, not merely a feature flag in bookkeeping.
            rendered = self.index.render_supported([proof_head] if proof_head else [])
            proof_check = prepare_supported(host, rendered, current_sources=current)
            selected = list(proof_check.source_ids)
        else:
            fact_ids = []
            proof_head = None
        self.last = {'ids': list(selected), 'facts': fact_ids, 'proof_head': proof_head}
        self.cache[state_key] = dict(self.last)
        strategy = ('authorized_bundle' if self.features['hierarchy'] else 'child_only')
        if self.arm == 'neighbor':
            strategy = 'authorized_neighbor_window'
        # No artificial context-window limit. All lawful raw remains a full
        # baseline; expansion includes complete current original sentences.
        prepared = prepare_sources(host, selected, current_sources=current,
            hierarchy=self.case['hierarchy'], strategy=strategy, expected_epoch=host.revision)
        return prepared, {'arm': self.arm, 'features': self.features, 'initialization_ms': self.initialization_ms,
            'maintenance': maintenance, 'cache_reuse': cached, 'seed_source_ids': selected,
            'retrieval_bundle_AND_fact': proof_head,
            'retrieval': trace, 'total_prepare_ms': (time.perf_counter()-started)*1000,
            'prepared': asdict(prepared), 'proof_cache_does_not_relabel_old_LLM_outputs': True}

    def close(self):
        if self.index is not None:
            self.index.close()
