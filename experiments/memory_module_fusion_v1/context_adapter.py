"""Final raw-source / verified-span adapter for the three-module experiment.

Routing/reranking supplies source IDs; SupportIndex supplies finite original
span witnesses plus the COMPLETE proof dependency set. Neither generated claim
text nor an old LLM summary with unknown original dependencies is a payload.
All actual slices are reconstructed from LifecycleHost.allowed_sources(), then
source bodies, versions, permission epochs and slices are rechecked immediately
before LifecycleHost.deliver invokes the real caller. No SDK calls occur here.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from experiments.permission_context_v1 import authorized_expansion as expansion

ContextError = expansion.ExpansionError
SourceWitness = expansion.SourceWitness
digest = expansion.digest


@dataclass(frozen=True)
class SpanWitness:
    source_id: str
    version: int | str
    permission_version: int | str
    source_sha256: str
    start: int
    end: int
    excerpt: str
    quote_sha256: str


@dataclass(frozen=True)
class FusionContext:
    strategy: str
    context: str
    source_ids: tuple[str, ...]
    witnesses: tuple[SourceWitness, ...]
    span_witnesses: tuple[SpanWitness, ...]
    prepared_epoch: int
    source_bytes: int
    max_source_bytes: int
    context_sha256: str
    render_format: str
    can_dispatch: bool
    diagnostics: tuple[dict, ...]


def _ids(value, label):
    if (not isinstance(value, (list, tuple))
            or any(not isinstance(sid, str) or not sid for sid in value)
            or len(set(value)) != len(value)):
        raise ContextError(label + '_must_be_unique_source_id_sequence')
    return tuple(value)


def _original_witness(source):
    # An original assistant reply in a public dialogue is still an atomic raw
    # source. A stored derived-summary artifact is a different input class.
    kind = str(source.get('source_kind', source.get('artifact_kind', 'original'))).lower()
    if ('summary' in kind or source.get('is_llm_summary') is True or source.get('is_summary') is True
            or source.get('derived_summary') is True):
        raise ContextError('legacy_or_derived_summary_is_not_original_span_source')
    return expansion._source_witness(source)


def _view(host, current_sources=None, expected_epoch=None):
    epoch = expansion._epoch(lambda: host.revision)
    if expected_epoch is not None:
        if type(expected_epoch) is not int or expected_epoch != epoch:
            raise ContextError('stale_commit_epoch', ({'kind': 'stale_commit_epoch',
                               'prepared_epoch': expected_epoch, 'current_epoch': epoch},))
    actual, bindings = {}, {}
    for source in host.allowed_sources():
        witness = _original_witness(source)
        if witness.source_id in actual:
            raise ContextError('duplicate_host_source')
        actual[witness.source_id], bindings[witness.source_id] = source, witness
    if current_sources is not None:
        if not isinstance(current_sources, (list, tuple)):
            raise ContextError('current_sources_must_be_original_record_sequence')
        provided_ids = []
        for source in current_sources:
            sid = source.get('source_id')
            if sid not in actual or sid in provided_ids:
                raise ContextError('provided_source_is_duplicate_or_not_currently_authorized')
            given = _original_witness(source)
            live = bindings[sid]
            if (given.text_sha256 != live.text_sha256 or given.version != live.version
                    or ('permission_version' in source and given.permission_version != live.permission_version)):
                raise ContextError('provided_source_body_or_version_is_stale')
            provided_ids.append(sid)
        actual = {sid: actual[sid] for sid in provided_ids}
        bindings = {sid: bindings[sid] for sid in provided_ids}
    expansion._same_epoch(lambda: host.revision, epoch)
    return epoch, actual, bindings


def _budget(value, default):
    value = default if value is None else value
    if type(value) is not int or value < 0:
        raise ContextError('nonnegative_original_excerpt_byte_budget_required')
    return value


def _span(source, witness, start, end):
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(source['text']):
        raise ContextError('invalid_original_character_span_offsets')
    quote = source['text'][start:end]
    return SpanWitness(witness.source_id, witness.version, witness.permission_version,
                       witness.text_sha256, start, end, quote, digest(quote))


def _render(spans, render_format):
    if render_format == 'full_sources_v1':
        return '\n\n'.join(span.source_id + '\n' + span.excerpt for span in spans)
    if render_format != 'original_spans_v1':
        raise ContextError('unknown_context_render_format')
    return '\n\n'.join(json.dumps({'source_id': span.source_id, 'char_start': span.start,
                                   'char_end': span.end}, ensure_ascii=False, sort_keys=True)
                        + '\n' + span.excerpt for span in spans)


def _packet(strategy, spans, dependency_ids, bindings, epoch, budget, render_format, diagnostics):
    spans = tuple(spans)
    body_bytes = sum(len(span.excerpt.encode('utf-8')) for span in spans)
    if body_bytes > budget:
        raise ContextError('complete_raw_witness_bundle_exceeds_retrieval_budget')
    context = _render(spans, render_format)
    return FusionContext(strategy, context, tuple(dependency_ids), tuple(bindings[sid] for sid in dependency_ids),
                         spans, epoch, body_bytes, budget, digest(context), render_format, True, tuple(diagnostics))


def prepare_sources(host, selected_ids, *, current_sources=None, hierarchy=None,
                    strategy='child_only', max_source_bytes=None, neighbor_window=2,
                    expected_epoch=None):
    """Route original source IDs through the existing safe expansion module."""
    if strategy not in ('child_only', 'authorized_bundle', 'authorized_neighbor_window'):
        raise ContextError('naive_parent_or_unknown_strategy_cannot_be_adapted')
    epoch, current, bindings = _view(host, current_sources, expected_epoch)
    ids = _ids(selected_ids, 'selected_ids')
    if set(ids) - current.keys():
        raise ContextError('selected_source_not_in_current_authorized_view')
    if hierarchy is None:
        if strategy != 'child_only':
            raise ContextError('expansion_requires_body_free_hierarchy_metadata')
        hierarchy = {sid: {'parent_id': sid, 'position': 0, 'prev_id': None, 'next_id': None} for sid in current}
    budget = _budget(max_source_bytes, sum(w.source_utf8_bytes for w in bindings.values()))
    prepared = expansion.prepare_context(list(current.values()), ids, hierarchy,
        strategy=strategy, authorize=host.authorize, get_epoch=lambda: host.revision,
        max_source_bytes=budget, neighbor_window=neighbor_window)
    expansion._same_epoch(lambda: host.revision, epoch)
    if not prepared.can_dispatch:
        raise ContextError('unsafe_parent_diagnostic_cannot_be_adapted')
    spans = [_span(current[sid], bindings[sid], 0, len(current[sid]['text'])) for sid in prepared.source_ids]
    packet = _packet(strategy, spans, prepared.source_ids, bindings, epoch, budget,
                     'full_sources_v1', prepared.diagnostics)
    if packet.context != prepared.context:
        raise ContextError('full_source_adapter_changed_original_expansion_render')
    return packet


def prepare_supported(host, rendered, *, current_sources=None, max_source_bytes=None,
                      expansion_strategy=None, hierarchy=None, neighbor_window=2):
    """Accept SupportIndex's proof metadata, reconstructing every original slice.

    Top-level ``text``, claim labels and derived fact names are never forwarded.
    A finite proof may depend on extra sources not printed in a slice: all such
    support IDs retain full-source witnesses and remain delivery dependencies.
    A proof bundle is admitted atomically; it is never shortened to fit budget.
    """
    if not isinstance(rendered, dict) or rendered.get('can_dispatch') is False:
        raise ContextError('finite_original_span_support_output_required')
    if 'epoch' not in rendered:
        raise ContextError('support_policy_epoch_required')
    epoch, current, bindings = _view(host, current_sources, rendered['epoch'])
    deps = _ids(rendered.get('support_ids', rendered.get('source_ids')), 'support_ids')
    if 'source_ids' in rendered and set(_ids(rendered['source_ids'], 'source_ids')) != set(deps):
        raise ContextError('source_ids_do_not_match_complete_support_dependencies')
    if set(deps) - current.keys():
        raise ContextError('proof_depends_on_noncurrent_or_unprovided_source')
    hashes, versions = rendered.get('source_hashes'), rendered.get('source_versions')
    if not isinstance(hashes, dict) or not isinstance(versions, dict):
        raise ContextError('complete_support_source_hashes_and_versions_required')
    for sid in deps:
        if hashes.get(sid) != bindings[sid].text_sha256 or versions.get(sid) != bindings[sid].version:
            raise ContextError('support_source_hash_or_version_is_stale')
    host.authorize(deps, 'fusion-supported-proof')
    expansion._same_epoch(lambda: host.revision, epoch)
    requests = rendered.get('spans', rendered.get('excerpts'))
    if not isinstance(requests, (list, tuple)) or (deps and not requests):
        raise ContextError('finite_raw_span_witness_bundle_required')
    if 'spans' in rendered and 'excerpts' in rendered and rendered['spans'] != rendered['excerpts']:
        raise ContextError('span_and_excerpt_aliases_disagree')
    spans, seen = [], set()
    for request in requests:
        if not isinstance(request, dict) or request.get('source_id') not in deps:
            raise ContextError('span_source_missing_from_complete_support_dependencies')
        sid = request['source_id']
        witness = bindings[sid]
        if request.get('version') != witness.version or request.get('source_sha256') != witness.text_sha256:
            raise ContextError('span_source_version_or_hash_is_stale')
        if 'permission_version' in request and request['permission_version'] != witness.permission_version:
            raise ContextError('span_permission_version_is_stale')
        span = _span(current[sid], witness, request.get('start'), request.get('end'))
        for key in ('excerpt', 'quote'):
            if key in request and request[key] != span.excerpt:
                raise ContextError('span_contains_nonoriginal_or_cross_source_text')
        if 'excerpt' not in request and 'quote' not in request:
            raise ContextError('verbatim_excerpt_required')
        if request.get('quote_sha256', request.get('text_sha256')) != span.quote_sha256:
            raise ContextError('original_quote_hash_mismatch')
        if 'text_sha256' in request and request['text_sha256'] != span.quote_sha256:
            raise ContextError('span_text_sha256_must_bind_the_slice')
        identity = sid, span.start, span.end
        if identity not in seen:
            spans.append(span)
            seen.add(identity)
    budget = _budget(max_source_bytes, sum(len(s.excerpt.encode('utf-8')) for s in spans)
                     + sum(w.source_utf8_bytes for w in bindings.values()))
    needed_bytes = sum(len(s.excerpt.encode('utf-8')) for s in spans)
    if needed_bytes > budget:
        raise ContextError('complete_raw_witness_bundle_exceeds_retrieval_budget')
    diagnostics = [{'kind': 'finite_original_proof_bundle_reconstructed',
                    'top_level_text_and_freeform_claims_not_forwarded': True,
                    'all_proof_dependencies_preserved': True,
                    'dependency_ids_without_rendered_span': sorted(set(deps) - {s.source_id for s in spans}),
                    'legacy_unknown_dependency_summaries_used': False}]
    dependency_ids = list(deps)
    strategy = 'support_spans'
    if expansion_strategy not in (None, 'child_only'):
        if expansion_strategy not in ('authorized_bundle', 'authorized_neighbor_window') or hierarchy is None:
            raise ContextError('only_safe_expansion_with_body_free_hierarchy_is_allowed')
        seeds = list(dict.fromkeys(s.source_id for s in spans))
        expanded = expansion.prepare_context(list(current.values()), seeds, hierarchy,
            strategy=expansion_strategy, authorize=host.authorize, get_epoch=lambda: host.revision,
            max_source_bytes=sum(w.source_utf8_bytes for w in bindings.values()), neighbor_window=neighbor_window)
        diagnostics.append({'kind': 'optional_expansion_candidates_resolved',
                            'resolver_diagnostics': list(expanded.diagnostics)})
        represented = set(seeds)
        for sid in expanded.source_ids:
            if sid in represented:
                continue
            extra = _span(current[sid], bindings[sid], 0, len(current[sid]['text']))
            cost = len(extra.excerpt.encode('utf-8'))
            if needed_bytes + cost > budget:
                diagnostics.append({'kind': 'optional_expansion_skipped_for_byte_budget', 'source_id': sid})
                continue
            spans.append(extra)
            represented.add(sid)
            needed_bytes += cost
            if sid not in dependency_ids:
                dependency_ids.append(sid)
        strategy += '+' + expansion_strategy
    expansion._same_epoch(lambda: host.revision, epoch)
    host.authorize(dependency_ids, 'fusion-context-final-prepare')
    expansion._same_epoch(lambda: host.revision, epoch)
    return _packet(strategy, spans, dependency_ids, bindings, epoch, budget, 'original_spans_v1', diagnostics)


def prepare_context(host, selected_ids=(), *, support_output=None, **kwargs):
    """Convenience router: explicit original IDs or a finite supported bundle."""
    if support_output is not None:
        return prepare_supported(host, support_output, **kwargs)
    return prepare_sources(host, selected_ids, **kwargs)


def deliver(prepared, host, messages, call, *, before_commit=None):
    """Span-aware final gate; only LifecycleHost invokes the actual call once."""
    allowed_strategies = {'child_only', 'authorized_bundle', 'authorized_neighbor_window',
                         'support_spans', 'support_spans+authorized_bundle', 'support_spans+authorized_neighbor_window'}
    if not isinstance(prepared, FusionContext) or not prepared.can_dispatch or prepared.strategy not in allowed_strategies:
        raise ContextError('unsafe_parent_or_unrecognized_context_cannot_dispatch')
    expansion._same_epoch(lambda: host.revision, prepared.prepared_epoch)
    deps = _ids(prepared.source_ids, 'prepared_source_ids')
    if tuple(w.source_id for w in prepared.witnesses) != deps:
        raise ContextError('complete_dependency_witness_binding_mismatch')
    if (type(prepared.source_bytes) is not int or prepared.source_bytes < 0
            or type(prepared.max_source_bytes) is not int or prepared.source_bytes > prepared.max_source_bytes
            or prepared.source_bytes != sum(len(span.excerpt.encode('utf-8')) for span in prepared.span_witnesses)):
        raise ContextError('prepared_excerpt_byte_budget_binding_mismatch')
    if digest(prepared.context) != prepared.context_sha256:
        raise ContextError('prepared_context_hash_changed')
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate JSON key')
            obj[key] = value
        return obj

    def verify_messages():
        try:
            if (not isinstance(messages, (list, tuple)) or len(messages) != 2
                    or any(not isinstance(m, dict) or set(m) != {'role', 'content'}
                           or not isinstance(m['content'], str) for m in messages)
                    or [m['role'] for m in messages] != ['system', 'user']):
                raise ValueError('standard message pair required')
            payload = json.loads(messages[1]['content'], object_pairs_hook=unique_object)
        except (TypeError, KeyError, IndexError, ValueError):
            raise ContextError('standard_target_memory_message_required') from None
        if not isinstance(payload, dict) or set(payload) != {'memory', 'questions'}:
            raise ContextError('unbound_extra_target_payload_fields')
        if (not isinstance(payload['questions'], list)
                or any(not isinstance(q, dict) or set(q) != {'question_id', 'question'}
                       or not isinstance(q['question_id'], str) or not isinstance(q['question'], str)
                       for q in payload['questions'])):
            raise ContextError('only_public_question_id_and_text_allowed')
        if payload['memory'] != prepared.context:
            raise ContextError('target_memory_does_not_match_prepared_context')
        return tuple((message['role'], message['content']) for message in messages)

    frozen_messages = verify_messages()

    def verify():
        if verify_messages() != frozen_messages:
            raise ContextError('target_messages_changed_before_commit')
        epoch, current, bindings = _view(host, expected_epoch=prepared.prepared_epoch)
        for witness in prepared.witnesses:
            if witness.source_id not in bindings or bindings[witness.source_id] != witness:
                raise ContextError('stale_source_dependency_version_hash_or_permission')
        actual_spans = []
        for span in prepared.span_witnesses:
            if span.source_id not in deps:
                raise ContextError('span_source_is_not_a_delivery_dependency')
            actual = _span(current[span.source_id], bindings[span.source_id], span.start, span.end)
            if actual != span:
                raise ContextError('span_offset_version_hash_or_original_text_changed')
            if prepared.render_format == 'full_sources_v1' and (span.start != 0 or span.end != len(current[span.source_id]['text'])):
                raise ContextError('full_source_mode_cannot_claim_partial_source')
            actual_spans.append(actual)
        if _render(actual_spans, prepared.render_format) != prepared.context:
            raise ContextError('context_contains_text_outside_verified_original_slices')
        expansion._same_epoch(lambda: host.revision, epoch)

    verify()

    def commit_check():
        if before_commit:
            before_commit()
        verify()

    return host.deliver(prepared.context, deps, messages, call, before_commit=commit_check)
