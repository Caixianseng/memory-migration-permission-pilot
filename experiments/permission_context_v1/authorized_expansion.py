"""Permission-gated context expansion from current verbatim atomic sources.

Hierarchy metadata contains IDs/order only. Safe strategies never fetch an old
parent body: parents are partial bundles reassembled from whole current legal
children. This module is an independent prototype, not a default gateway change.
The deliberately unsafe local parent-render diagnostic cannot be dispatched.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Callable

STRATEGIES = ('child_only', 'naive_parent_render', 'authorized_bundle', 'authorized_neighbor_window')


class ExpansionError(ValueError):
    def __init__(self, code, diagnostics=()):
        super().__init__(code)
        self.code = code
        self.diagnostics = tuple(diagnostics)


@dataclass(frozen=True)
class SourceWitness:
    source_id: str
    version: int | str
    permission_version: int | str
    text_sha256: str
    source_utf8_bytes: int


@dataclass(frozen=True)
class PreparedContext:
    strategy: str
    context: str
    source_ids: tuple[str, ...]
    witnesses: tuple[SourceWitness, ...]
    prepared_epoch: int
    source_bytes: int
    max_source_bytes: int
    context_sha256: str
    can_dispatch: bool
    diagnostics: tuple[dict, ...]


def digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _epoch(get_epoch):
    epoch = get_epoch()
    if type(epoch) is not int or epoch < 0:
        raise ExpansionError('nonnegative_integer_host_epoch_required')
    return epoch


def _same_epoch(get_epoch, expected):
    current = _epoch(get_epoch)
    if current != expected:
        raise ExpansionError('stale_commit_epoch', ({'kind': 'stale_commit_epoch',
                             'prepared_epoch': expected, 'current_epoch': current},))


def _source_witness(source):
    sid, text = source.get('source_id'), source.get('text')
    version, permission_version = source.get('version', 1), source.get('permission_version', 1)
    if (not isinstance(sid, str) or not sid or not isinstance(text, str) or not text
            or source.get('allow', True) is not True or source.get('allowed', True) is not True):
        raise ExpansionError('only_current_authorized_nonempty_source_records_allowed')
    if any(isinstance(v, bool) or not isinstance(v, (int, str)) or v == '' for v in (version, permission_version)):
        raise ExpansionError('valid_source_and_permission_versions_required')
    fingerprint = digest(text)
    if source.get('sha256', fingerprint) != fingerprint:
        raise ExpansionError('source_body_hash_mismatch')
    return SourceWitness(sid, version, permission_version, fingerprint, len(text.encode('utf-8')))


def _hierarchy(metadata):
    if not isinstance(metadata, dict):
        raise ExpansionError('hierarchy_id_metadata_required')
    parents, positions = {}, set()
    for sid, row in metadata.items():
        if (not isinstance(sid, str) or not sid or not isinstance(row, dict)
                or set(row) - {'parent_id', 'position', 'prev_id', 'next_id'}
                or not isinstance(row.get('parent_id'), str) or not row['parent_id']
                or type(row.get('position')) is not int or row['position'] < 0):
            raise ExpansionError('hierarchy_must_contain_only_parent_position_neighbor_ids')
        position = row['parent_id'], row['position']
        if position in positions:
            raise ExpansionError('duplicate_position_inside_parent')
        positions.add(position)
        parents.setdefault(row['parent_id'], []).append(sid)
        for key in ('prev_id', 'next_id'):
            if row.get(key) is not None and row[key] not in metadata:
                raise ExpansionError('unknown_neighbor_id')
    return {parent: sorted(ids, key=lambda sid: (metadata[sid]['position'], sid))
            for parent, ids in parents.items()}


def prepare_context(authorized_sources, seed_ids, hierarchy, *, strategy,
                    authorize: Callable, get_epoch: Callable, max_source_bytes,
                    neighbor_window=1, diagnostic_parent_renderer=None,
                    allow_unsafe_diagnostic=False):
    """Prepare source witnesses and context, without sending a model request.

    ``authorize(ids, purpose)`` and ``get_epoch()`` can be LifecycleHost.authorize
    and a lambda reading its revision. ``max_source_bytes`` is a retrieval
    parameter charged to complete original source bodies, not a model-window
    restriction. Headers are counted separately by len(context.encode()).
    """
    if strategy not in STRATEGIES or type(max_source_bytes) is not int or max_source_bytes < 0:
        raise ExpansionError('valid_strategy_and_nonnegative_source_byte_budget_required')
    if type(neighbor_window) is not int or neighbor_window < 0:
        raise ExpansionError('nonnegative_neighbor_window_required')
    parents = _hierarchy(hierarchy)
    epoch = _epoch(get_epoch)
    records, witnesses = {}, {}
    for source in authorized_sources:
        witness = _source_witness(source)
        if witness.source_id in records or witness.source_id not in hierarchy:
            raise ExpansionError('duplicate_source_or_missing_hierarchy_id')
        records[witness.source_id], witnesses[witness.source_id] = source, witness
    if (not isinstance(seed_ids, (list, tuple)) or len(set(seed_ids)) != len(seed_ids)
            or any(sid not in records for sid in seed_ids)):
        raise ExpansionError('seeds_must_be_unique_current_authorized_source_ids')
    diagnostics = []

    def permitted(sid, seed=False):
        _same_epoch(get_epoch, epoch)
        if sid not in records:
            diagnostics.append({'kind': 'expansion_denied', 'source_id': sid,
                                'reason': 'not_in_current_authorized_view', 'body_fetched': False})
            return False
        try:
            authorize([sid], 'context-seed' if seed else 'context-expansion')
        except Exception as error:
            _same_epoch(get_epoch, epoch)
            diagnostic = {'kind': 'expansion_denied', 'source_id': sid,
                          'reason': 'host_authorization_denied', 'error_class': type(error).__name__,
                          'body_fetched': False}
            if seed:
                raise ExpansionError('seed_authorization_denied', (diagnostic,)) from None
            diagnostics.append(diagnostic)
            return False
        _same_epoch(get_epoch, epoch)
        return True

    for sid in seed_ids:
        permitted(sid, seed=True)
    if strategy == 'naive_parent_render':
        if not allow_unsafe_diagnostic or not callable(diagnostic_parent_renderer):
            raise ExpansionError('unsafe_parent_diagnostic_requires_explicit_local_opt_in')
        # External local-fixture callback only. This branch makes no claim that
        # the old blob has a valid current dependency set, and cannot dispatch.
        parent_ids = list(dict.fromkeys(hierarchy[sid]['parent_id'] for sid in seed_ids))
        texts, claimed_ids, used = [], [], 0
        for parent in parent_ids:
            text = diagnostic_parent_renderer(parent)
            if not isinstance(text, str):
                raise ExpansionError('diagnostic_renderer_must_return_text')
            cost = len(text.encode('utf-8'))
            if used + cost > max_source_bytes:
                diagnostics.append({'kind': 'byte_budget_skipped_parent', 'parent_id': parent})
                continue
            texts.append(text)
            claimed_ids.extend(parents[parent])
            used += cost
        _same_epoch(get_epoch, epoch)
        context = '\n\n'.join(texts)
        diagnostics.append({'kind': 'unsafe_parent_render_local_diagnostic_only',
                            'unverified_source_ids': sorted(set(claimed_ids) - set(records)),
                            'model_dispatch_forbidden': True})
        return PreparedContext(strategy, context, tuple(claimed_ids), (), epoch, used,
                               max_source_bytes, digest(context), False, tuple(diagnostics))

    candidates = list(seed_ids)
    if strategy == 'authorized_bundle':
        for sid in seed_ids:
            candidates.extend(parents[hierarchy[sid]['parent_id']])
    elif strategy == 'authorized_neighbor_window':
        for sid in seed_ids:
            for direction in ('prev_id', 'next_id'):
                neighbor = sid
                for _ in range(neighbor_window):
                    neighbor = hierarchy[neighbor].get(direction)
                    if neighbor is None:
                        break
                    candidates.append(neighbor)
    candidates = list(dict.fromkeys(candidates))
    selected, used = [], 0
    for sid in candidates:
        if not permitted(sid):
            continue
        cost = witnesses[sid].source_utf8_bytes
        if used + cost > max_source_bytes:
            diagnostics.append({'kind': 'byte_budget_skipped_source', 'source_id': sid,
                                'source_utf8_bytes': cost, 'partial_source_sent': False})
            continue
        selected.append(sid)
        used += cost
    _same_epoch(get_epoch, epoch)
    context = '\n\n'.join(sid + '\n' + records[sid]['text'] for sid in selected)
    diagnostics.append({'kind': 'current_authorized_children_reassembled',
                        'not_a_complete_original_parent_claim': True,
                        'old_parent_body_fetched': False, 'all_selected_sources_verbatim': True,
                        'rendered_context_utf8_bytes': len(context.encode('utf-8'))})
    return PreparedContext(strategy, context, tuple(selected), tuple(witnesses[sid] for sid in selected),
                           epoch, used, max_source_bytes, digest(context), True, tuple(diagnostics))


def deliver(prepared, host, messages, call, *, before_commit=None):
    """Final native dispatch gate remains LifecycleHost.deliver, with no retry."""
    if not prepared.can_dispatch or prepared.strategy == 'naive_parent_render':
        raise ExpansionError('unsafe_diagnostic_context_cannot_dispatch')
    _same_epoch(lambda: host.revision, prepared.prepared_epoch)
    if digest(prepared.context) != prepared.context_sha256:
        raise ExpansionError('prepared_context_hash_changed')
    if (prepared.source_bytes > prepared.max_source_bytes
            or prepared.source_bytes != sum(w.source_utf8_bytes for w in prepared.witnesses)
            or len(set(prepared.source_ids)) != len(prepared.source_ids)
            or tuple(w.source_id for w in prepared.witnesses) != prepared.source_ids):
        raise ExpansionError('prepared_source_witness_binding_invalid')
    try:
        payload = json.loads(messages[-1]['content'])
    except (KeyError, IndexError, TypeError, ValueError):
        raise ExpansionError('standard_target_memory_message_required') from None
    if payload.get('memory') != prepared.context:
        raise ExpansionError('target_memory_does_not_match_prepared_context')

    def check_witnesses():
        _same_epoch(lambda: host.revision, prepared.prepared_epoch)
        current = {source['source_id']: source for source in host.allowed_sources()}
        for witness in prepared.witnesses:
            if witness.source_id not in current or _source_witness(current[witness.source_id]) != witness:
                raise ExpansionError('stale_source_version_or_content_witness', ({
                    'kind': 'stale_source_version_or_content_witness', 'source_id': witness.source_id},))
        expected_context = '\n\n'.join(sid + '\n' + current[sid]['text'] for sid in prepared.source_ids)
        if expected_context != prepared.context:
            raise ExpansionError('context_is_not_verbatim_bound_to_current_sources')

    check_witnesses()

    def commit_check():
        if before_commit:
            before_commit()
        check_witnesses()

    return host.deliver(prepared.context, prepared.source_ids, messages, call, before_commit=commit_check)
