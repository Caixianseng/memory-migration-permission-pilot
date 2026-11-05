"""Bounded local evidence retrieval over an ALREADY-authorized source view.

This is an engineering adaptation of ordinary BM25 and entity query expansion,
not a new retrieval algorithm. It makes no claim of complete reasoning evidence.
Selected IDs always identify complete, unchanged original source records.

The first round ranks current authorized paragraphs. At most one additional
round combines up to four entity/relation queries and adds parents within a
fixed 3/4-parent output budget. No model, network, label file, or future event is
read. The caller must still run its trusted permission/version commit gate.

Query derivation reads only its ordered seed sources. Ranking reads the entire
current authorized view (including BM25 document frequencies). Reusing a query
therefore NEVER reuses a ranking after the view changes. Conservative cache
reuse additionally requires the same ordered CURRENT initial seeds, so a rebuild
and selective arm run the same retrieval rule. This saves local query-building
work only; it does not save model calls.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re

from experiments.revocation_grouping_v1.retrieval_baseline import score_sources, tokenize

VERSION = 'authorized-entity-two-round-bm25-v1'
_SCHEMA = 'trusted-local-query-artifact-v1'
_LABEL_KEYS = frozenset({'answer', 'answers', 'gold', 'gold_answer', 'support_ids',
                         'supporting_facts', 'evaluation_only', 'future_events'})
_FUNCTION_WORDS = frozenset(('who what which when where why how whose whom the a an '
                            'is was are were has have had do does did and or of in on '
                            'at to for by from with this that these those he she it '
                            'they his her its their there here during').split())
_ENTITY = re.compile(r"\b[A-Z][A-Za-z0-9'’\-]*(?:[ \t]+(?:[A-Z][A-Za-z0-9'’\-]*|(?:of|the|de|van|von|and)(?=[ \t]+[A-Z]))){0,5}")


@dataclass(frozen=True)
class RetrievalConfig:
    initial_parent_k: int = 3
    final_parent_k: int = 4
    max_entity_queries: int = 4
    rrf_k: int = 60
    minimum_question_coverage: float = .65
    minimum_distinct_parents: int = 2
    require_bridge_expansion: bool = True


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else _encoded(value)).hexdigest()


def _no_labels(value):
    if isinstance(value, dict):
        if _LABEL_KEYS & set(value):
            raise ValueError('evaluation_or_future_input_forbidden')
        for child in value.values():
            _no_labels(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _no_labels(child)


def _config(config):
    if config is None:
        result = RetrievalConfig()
    elif isinstance(config, RetrievalConfig):
        result = config
    elif isinstance(config, dict):
        _no_labels(config)
        if set(config) - set(asdict(RetrievalConfig())):
            raise ValueError('unknown_retrieval_config_key')
        result = RetrievalConfig(**config)
    else:
        raise ValueError('invalid_retrieval_config')
    for name in ('initial_parent_k', 'final_parent_k'):
        if type(getattr(result, name)) is not int or getattr(result, name) not in (3, 4):
            raise ValueError('parent_budget_must_be_three_or_four')
    if result.final_parent_k < result.initial_parent_k:
        raise ValueError('final_parent_budget_smaller_than_initial')
    if type(result.max_entity_queries) is not int or not 1 <= result.max_entity_queries <= 4:
        raise ValueError('invalid_entity_query_budget')
    if type(result.rrf_k) is not int or not 1 <= result.rrf_k <= 1000:
        raise ValueError('invalid_rrf_k')
    coverage = result.minimum_question_coverage
    if type(coverage) not in (int, float) or not math.isfinite(coverage) or not 0 <= coverage <= 1:
        raise ValueError('invalid_question_coverage_threshold')
    if type(result.minimum_distinct_parents) is not int or not 1 <= result.minimum_distinct_parents <= 4:
        raise ValueError('invalid_minimum_distinct_parents')
    if type(result.require_bridge_expansion) is not bool:
        raise ValueError('invalid_require_bridge_expansion')
    return result


def _sources(current_sources, hierarchy):
    if not isinstance(current_sources, (list, tuple)) or not isinstance(hierarchy, dict):
        raise ValueError('authorized_sources_and_hierarchy_required')
    _no_labels(current_sources)
    # Hierarchy entries outside the current authorization view are not read.
    sources, metadata = {}, {}
    for source in current_sources:
        if not isinstance(source, dict):
            raise ValueError('invalid_source')
        sid = source.get('source_id')
        if not isinstance(sid, str) or not sid.strip() or sid in sources:
            raise ValueError('invalid_or_duplicate_source_id')
        if not isinstance(source.get('text'), str):
            raise ValueError('source_text_required')
        for name in ('allow', 'allowed'):
            if name in source and source[name] is not True:
                raise ValueError('retrieval_received_forbidden_source')
        if type(source.get('version', 1)) is not int or source.get('version', 1) < 1:
            raise ValueError('invalid_source_version')
        row = hierarchy.get(sid)
        if not isinstance(row, dict):
            raise ValueError('source_hierarchy_missing')
        _no_labels(row)
        parent = row.get('parent_id')
        position = row.get('position', 0)
        if not isinstance(parent, str) or not parent.strip() or type(position) is not int or position < 0:
            raise ValueError('invalid_source_hierarchy')
        sources[sid] = source
        metadata[sid] = {'parent_id': parent, 'position': position}
    return sources, metadata


def _binding(source):
    return {'source_id': source['source_id'], 'version': source.get('version', 1),
            'text_sha256': _sha(source['text'].encode('utf-8'))}


def _query_tokens(question):
    return [term for term in dict.fromkeys(tokenize(question))
            if term.removeprefix('w:') not in _FUNCTION_WORDS]


def _build_query_artifact(seed_sources, question, config):
    """Read only seed originals; retain exact quote offsets for bridge entities."""
    qtokens = set(_query_tokens(question))
    title_tokens = set()
    entities = {}
    for order, source in enumerate(seed_sources):
        text = source['text']
        if '\n' in text:
            title, body = text.split('\n', 1)
            offset = len(title) + 1
            title_tokens.update(tokenize(title))
        else:
            body, offset = text, 0
        for match in _ENTITY.finditer(body):
            phrase = match.group().strip()
            terms = set(tokenize(phrase))
            if not terms or len(phrase) > 80 or all(t.removeprefix('w:') in _FUNCTION_WORDS for t in terms):
                continue
            # Repeating an entity wholly present in the initial question is not
            # evidence-guided bridge expansion.
            if terms <= qtokens:
                continue
            key = phrase.casefold()
            quote = {'source_id': source['source_id'], 'start': offset + match.start(),
                     'end': offset + match.end(), 'quote': text[offset+match.start():offset+match.end()]}
            entry = entities.setdefault(key, {'entity': phrase, 'terms': sorted(terms),
                                             'first_seed_order': order, 'quotes': []})
            entry['quotes'].append(quote)
    chosen = sorted(entities.values(), key=lambda item: (
        -len(item['quotes']), item['first_seed_order'], -len(item['terms']), item['entity'].casefold()
    ))[:config.max_entity_queries]
    # Remove initial paragraph title words from the relation query so the
    # question's named anchor does not swamp a newly observed bridge entity.
    relation_terms = [term.removeprefix('w:').removeprefix('c:') for term in _query_tokens(question)
                      if term not in title_tokens]
    queries = [item['entity'] + (' ' + ' '.join(relation_terms) if relation_terms else '')
               for item in chosen]
    artifact = {'schema': _SCHEMA, 'question_sha256': _sha(question.encode('utf-8')),
                'config_sha256': _sha(asdict(config)),
                'ordered_seed_bindings': [_binding(source) for source in seed_sources],
                'entities': chosen, 'relation_terms': relation_terms, 'queries': queries}
    artifact['artifact_sha256'] = _sha(artifact)
    return artifact


def validate_query_artifact(artifact, current_seed_sources, question, config=None):
    """Validate a trusted local cache against CURRENT ordered initial seeds.

    A content digest is an integrity check, not an authenticity signature or an
    authorization grant. The caller owns the trusted artifact store. The final
    source authorization/epoch gate remains mandatory.
    """
    cfg = _config(config)
    if not isinstance(question, str) or not question.strip():
        return False, 'invalid_question'
    if not isinstance(artifact, dict):
        return False, 'not_an_artifact'
    expected = {'schema', 'question_sha256', 'config_sha256', 'ordered_seed_bindings',
                'entities', 'relation_terms', 'queries', 'artifact_sha256'}
    if set(artifact) != expected or artifact.get('schema') != _SCHEMA:
        return False, 'artifact_schema_mismatch'
    body = {key: value for key, value in artifact.items() if key != 'artifact_sha256'}
    try:
        if _sha(body) != artifact['artifact_sha256']:
            return False, 'artifact_digest_mismatch'
    except (TypeError, ValueError):
        return False, 'artifact_not_serializable'
    if artifact['question_sha256'] != _sha(question.encode('utf-8')):
        return False, 'question_changed'
    if artifact['config_sha256'] != _sha(asdict(cfg)):
        return False, 'config_changed'
    if artifact['ordered_seed_bindings'] != [_binding(s) for s in current_seed_sources]:
        return False, 'current_ordered_initial_seeds_changed'
    if not isinstance(artifact['queries'], list) or len(artifact['queries']) > cfg.max_entity_queries:
        return False, 'invalid_query_count'
    if not all(isinstance(q, str) and q.strip() for q in artifact['queries']):
        return False, 'invalid_query_text'
    if not isinstance(artifact['entities'], list) or len(artifact['entities']) != len(artifact['queries']):
        return False, 'invalid_entity_count'
    titles = set(term for source in current_seed_sources if '\n' in source['text']
                 for term in tokenize(source['text'].split('\n', 1)[0]))
    relation_terms = [term.removeprefix('w:').removeprefix('c:') for term in _query_tokens(question)
                      if term not in titles]
    if artifact['relation_terms'] != relation_terms:
        return False, 'relation_query_not_bound_to_current_question'
    by_id = {s['source_id']: s for s in current_seed_sources}
    try:
        for entity in artifact['entities']:
            if not entity['quotes'] or sorted(set(tokenize(entity['entity']))) != entity['terms']:
                return False, 'entity_not_grounded'
            for quote in entity['quotes']:
                source = by_id[quote['source_id']]
                start, end = quote['start'], quote['end']
                if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(source['text']):
                    return False, 'entity_quote_bounds_invalid'
                if source['text'][start:end] != quote['quote'] or quote['quote'].casefold() != entity['entity'].casefold():
                    return False, 'entity_quote_changed'
    except (TypeError, KeyError, ValueError, AttributeError):
        return False, 'entity_binding_invalid'
    expected_queries = [entity['entity'] + (' ' + ' '.join(relation_terms) if relation_terms else '')
                        for entity in artifact['entities']]
    if artifact['queries'] != expected_queries:
        return False, 'query_not_bound_to_grounded_entity_and_relation'
    return True, 'same_current_ordered_seeds_question_and_config'


def retrieve(current_sources, question, hierarchy, config=None, *, query_artifact=None):
    """Return IDs, two-stage trace, provenance, and a heuristic fallback signal.

    ``question`` is a string, not a labelled record. ``current_sources`` must be
    the host-authorized view. Input order never changes the deterministic result.
    Complete current source records remain in the caller's original registry.
    """
    if not isinstance(question, str) or not question.strip():
        raise ValueError('nonempty_unlabelled_question_required')
    cfg = _config(config)
    sources, metadata = _sources(current_sources, hierarchy)
    groups = {}
    for sid in sorted(sources, key=lambda sid: (metadata[sid]['parent_id'], metadata[sid]['position'], sid)):
        groups.setdefault(metadata[sid]['parent_id'], []).append(sources[sid])
    parents = [{'source_id': pid, 'text': '\n'.join(s['text'] for s in members), 'allow': True}
               for pid, members in sorted(groups.items())]
    # The initial ranking is ALWAYS recomputed on the complete CURRENT view.
    initial_ranking = score_sources(parents, [question])
    initial_ids = [row['source_id'] for row in initial_ranking[:cfg.initial_parent_k]]
    seeds = [source for pid in initial_ids for source in groups[pid]]
    query_reused, reuse_reason = validate_query_artifact(query_artifact, seeds, question, cfg)
    artifact = json.loads(_encoded(query_artifact)) if query_reused else _build_query_artifact(seeds, question, cfg)
    rrf, maxima = {}, {}
    query_rankings = []
    parent_terms = {row['source_id']: set(tokenize(row['text'])) for row in parents}
    for query in artifact['queries']:
        ranking = score_sources(parents, [query])
        query_rankings.append({'query': query, 'ranking': ranking})
        for rank, row in enumerate(ranking, 1):
            if row['score'] <= 0:
                continue
            pid = row['source_id']
            rrf[pid] = rrf.get(pid, 0.0) + 1.0 / (cfg.rrf_k + rank)
            maxima[pid] = max(maxima.get(pid, 0.0), row['score'])
    bridge_ranking = []
    for pid, score in rrf.items():
        matched = [entity['entity'] for entity in artifact['entities']
                   if set(entity['terms']) <= parent_terms[pid]]
        if pid not in initial_ids and matched:
            bridge_ranking.append({'parent_id': pid, 'rrf_score': score,
                                   'max_bm25': maxima[pid], 'matched_entities': matched})
    bridge_ranking.sort(key=lambda row: (-row['rrf_score'], -row['max_bm25'], row['parent_id']))
    additions = [row['parent_id'] for row in bridge_ranking[:cfg.final_parent_k-len(initial_ids)]]
    selected_parents = initial_ids + additions
    selected = [source['source_id'] for pid in selected_parents for source in groups[pid]]
    qterms = set(_query_tokens(question))
    selected_terms = set(term for sid in selected for term in tokenize(sources[sid]['text']))
    coverage = len(qterms & selected_terms)/len(qterms) if qterms else 0.0
    all_selected = bool(sources) and set(selected) == set(sources)
    reasons = []
    if not sources:
        reasons.append('empty_authorized_view')
    elif not all_selected:
        if not initial_ranking or initial_ranking[0]['score'] <= 0:
            reasons.append('no_positive_initial_match')
        if coverage < cfg.minimum_question_coverage:
            reasons.append('question_term_coverage_below_threshold')
        if len(selected_parents) < cfg.minimum_distinct_parents:
            reasons.append('too_few_distinct_parents')
        if cfg.require_bridge_expansion and not additions:
            reasons.append('no_additional_grounded_entity_parent')
    rank_bindings = [{**_binding(sources[sid]), **metadata[sid]} for sid in sorted(sources)]
    result = {'version': VERSION, 'config': asdict(cfg), 'config_fingerprint': _sha(asdict(cfg)),
        'selected_source_ids': selected, 'selected_parent_ids': selected_parents,
        'query_artifact': artifact, 'query_reused': query_reused, 'query_reuse_reason': reuse_reason,
        'query_dependencies': [row['source_id'] for row in artifact['ordered_seed_bindings']],
        'query_source_bindings': artifact['ordered_seed_bindings'],
        'actual_read_dependencies': sorted(sources), 'ranking_source_bindings': rank_bindings,
        'view_fingerprint': _sha(rank_bindings), 'ranking_recomputed': True,
        'initial_ordered_seeds_rechecked': True,
        'query_build_performed': not query_reused,
        'bm25_scoring_passes': 1 + len(artifact['queries']),
        'stages': [
            {'round': 1, 'queries': [question], 'rankings': initial_ranking,
             'selected_parent_ids': initial_ids, 'selected_source_ids': [s['source_id'] for s in seeds]},
            {'round': 2, 'queries': artifact['queries'], 'query_rankings': query_rankings,
             'fused_new_parent_ranking': bridge_ranking, 'added_parent_ids': additions,
             'selected_parent_ids': selected_parents, 'selected_source_ids': selected}],
        'question_term_coverage': coverage, 'contains_all_current_sources': all_selected,
        'needs_fallback': bool(reasons), 'fallback_reasons': reasons,
        'fallback_is_heuristic_not_evidence_completeness_proof': True,
        'model_call_count': 0, 'retrieval_round_limit': 2,
        'query_reuse_saves_only_local_derivation_work': True}
    return result


__all__ = ['VERSION', 'RetrievalConfig', 'retrieve', 'validate_query_artifact']
