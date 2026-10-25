"""Optional business-value evidence tightening after ordinary preparation.

All original authentication, policy binding, authorization, masking, closure,
and egress behavior remains in force. A masked field key remains masked, but
its occurrence cannot alone support restoring a business fact supplied by the
question. A real same-name value occurrence, in the same or another memory,
still supplies evidence. Schema/header questions need a different evidence
type; this limited rule does not solve general semantic/query-only confusion.

No restoration map, token, value, or per-token source table is logged. Maps
remain process-local, nonserializable capabilities. The wrapper only removes
source relations and never adds a source or reduces a masking interval.
"""
from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType

from .candidate_proposals import _text_hash
from .privacy import (QUERY_SOURCE, RestorationMap, _Entry, _digest, _policy,
                      _sources, prepare_private_payload)
from .structured_candidates import propose_field_findings


PREPARATION_VERSION = "business_value_key_only_evidence_filter_v1"
FIELD_LIMIT = 4096
FIELD_VALUE_LIMIT = 6000


def prepare_boundary_payload(payload, detection, *, actor_id, request_id, policy_version,
                             authorizer, sensitivity_policy):
    """Run original prepare, then only remove proven key-only source evidence.

    Every original ``entry.sources`` source must have actual masking intervals
    for that entry's case-folded value. It is removed iff ALL such intervals
    are wholly within explicit parsed field-key spans. One non-key interval
    retains that source. Original bindings, protected values, memories, masking
    spans, nonce and prepared payload are preserved. Any parse/invariant failure
    returns no usable payload or mapping. Restore performs its old live checks.
    """
    def block(code):
        return {"status": "needs_review", "payload": None, "mapping": None,
                "error": code, "metadata": {"boundary_preparation": {"version": PREPARATION_VERSION}}}

    try:
        # Stable local inputs also prevent an authorization callback mutating
        # the caller's dictionaries from changing the post-prepare evidence.
        original_payload, original_detection, original_policy = deepcopy((payload, detection, sensitivity_policy))
        prepared = prepare_private_payload(original_payload, original_detection,
            actor_id=actor_id, request_id=request_id, policy_version=policy_version,
            authorizer=authorizer, sensitivity_policy=original_policy)
    except Exception:
        return block("original_preparation_failed")
    if not isinstance(prepared, dict):
        return block("invalid_original_preparation")
    if prepared.get("status") != "ok":
        # Retain ordinary fixed preparation error codes, never an unexpected
        # mapping/payload from a failed result.
        error = prepared.get("error")
        return block(error if isinstance(error, str) else "original_preparation_failed")
    try:
        mapping = prepared["mapping"]
        if not isinstance(mapping, RestorationMap) or not isinstance(prepared["payload"], dict):
            raise ValueError("invalid_original_preparation")
        sources, normalized = _sources(original_payload), _policy(original_policy)
        source_hashes = {sid: _text_hash(text) for sid, text in sources.items()}
        payload_hash, policy_hash, full_policy_hash = _digest(original_payload), _digest(normalized), _digest(original_policy)
        if ((mapping._actor_id, mapping._request_id, mapping._policy_version) != (actor_id, request_id, policy_version)
                or mapping._source_payload_sha256 != payload_hash or mapping._policy_sha256 != policy_hash
                or normalized["version"] != policy_version
                or prepared["metadata"]["payload_sha256"] != _digest(prepared["payload"])):
            raise ValueError("invalid_original_preparation")
        memories = {sid: text for sid, text in sources.items() if sid != QUERY_SOURCE}
        if dict(mapping._memories) != memories or set(mapping._sensitive_spans) != set(memories):
            raise ValueError("invalid_original_preparation")
        parsed = propose_field_findings(original_payload, original_policy,
            max_candidates=FIELD_LIMIT, max_value_chars=FIELD_VALUE_LIMIT)
        if (not isinstance(parsed, dict) or parsed.get("status") != "candidates_only" or parsed.get("complete") is not True
                or parsed.get("payload_sha256") != payload_hash or parsed.get("policy_sha256") != policy_hash
                or parsed.get("full_policy_sha256") != full_policy_hash or parsed.get("source_sha256") != source_hashes
                or not isinstance(parsed.get("field_key_spans"), list)):
            return block("field_evidence_parse_failed")
        keys_by_source = {sid: [] for sid in memories}
        for key in parsed["field_key_spans"]:
            sid, start, end = key["source_id"], key["start"], key["end"]
            if (sid not in sources or type(start) is not int or type(end) is not int
                    or not 0 <= start < end <= len(sources[sid]) or key["quote"] != sources[sid][start:end]
                    or key.get("kind") != "field_key"):
                raise ValueError("invalid_field_evidence")
            if sid in memories:
                keys_by_source[sid].append((start, end))

        # Use the actual merged masking intervals from original prepare. Mere
        # text occurrences do not establish or remove a restoration source.
        entries, by_value, actual = {}, {}, {}
        for token, entry in mapping._entries.items():
            if (not isinstance(token, str) or not isinstance(entry, _Entry) or not isinstance(entry.value, str)
                    or not entry.value or not isinstance(entry.categories, tuple) or not isinstance(entry.sources, tuple)
                    or any(category not in normalized["protected_categories"] for category in entry.categories)
                    or any(not isinstance(sid, str) or sid not in memories for sid in entry.sources)
                    or len(set(entry.sources)) != len(entry.sources) or entry.value.casefold() in by_value):
                raise ValueError("invalid_restoration_evidence")
            by_value[entry.value.casefold()] = token
            actual[token] = {}
        for sid, memory in memories.items():
            for start, end in mapping._sensitive_spans[sid]:
                if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(memory)):
                    raise ValueError("invalid_restoration_evidence")
                token = by_value.get(memory[start:end].casefold())
                if token is None or sid not in mapping._entries[token].sources:
                    raise ValueError("invalid_restoration_evidence")
                actual[token].setdefault(sid, []).append((start, end))
        before, after, removed, emptied = 0, 0, 0, 0
        for token, entry in mapping._entries.items():
            keep = []
            for sid in entry.sources:
                intervals = actual[token].get(sid)
                if not intervals:
                    raise ValueError("invalid_restoration_evidence")
                key_only = all(any(left <= start < end <= right for left, right in keys_by_source[sid])
                               for start, end in intervals)
                if key_only:
                    removed += 1
                else:
                    keep.append(sid)
            before += len(entry.sources)
            after += len(keep)
            emptied += int(not keep)
            entries[token] = _Entry(entry.value, entry.categories, tuple(keep))
            if not set(entries[token].sources).issubset(entry.sources):
                raise ValueError("restoration_evidence_widened")
        # Copy before wrapping so neither the old capability nor a retained
        # external dictionary alias can mutate the new capability's contents.
        tightened = RestorationMap(mapping._actor_id, mapping._request_id, mapping._policy_version,
            mapping._policy_sha256, mapping._source_payload_sha256, mapping._nonce,
            MappingProxyType(dict(entries)), MappingProxyType(dict(mapping._memories)),
            tuple((value, tuple(categories)) for value, categories in mapping._protected_values),
            MappingProxyType({sid: tuple((start, end) for start, end in spans)
                              for sid, spans in mapping._sensitive_spans.items()}))
        metadata = deepcopy(prepared["metadata"])
        metadata["boundary_preparation"] = {"version": PREPARATION_VERSION,
            "payload_sha256": payload_hash, "policy_sha256": policy_hash, "full_policy_sha256": full_policy_hash,
            "field_key_count": sum(len(items) for items in keys_by_source.values()), "entry_count": len(entries),
            "source_relations_before": before, "source_relations_after": after,
            "removed_key_only_source_relations": removed, "entries_without_memory_evidence": emptied,
            "field_limit": FIELD_LIMIT, "field_value_character_limit": FIELD_VALUE_LIMIT,
            "scope": "business_value_evidence_only_not_schema_or_general_semantic_evidence"}
        return {"status": "ok", "payload": prepared["payload"], "mapping": tightened,
                "error": None, "metadata": metadata}
    except Exception:
        return block("boundary_preparation_invariant_failed")
