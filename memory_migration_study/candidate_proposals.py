"""Bound, local candidate proposals; never privacy or authorization decisions.

Only current payload spans and balanced quotation/bracket interiors are used.
No model, files, scoring labels or secret-value registry is consulted. A
complete pool means this finite proposal procedure finished, not that every
entity was found or any proposed value is sensitive. Output is unsuitable as a
successful detection result and cannot authorize preparation or restoration.
"""
from __future__ import annotations

import hashlib
import unicodedata

from .privacy import CATEGORIES, _digest, _policy, _sources

PROPOSAL_VERSION = "bound_quoted_candidate_proposals_v1"
_PAIRS = {"“": "”", "‘": "’", "「": "」", "『": "』", "【": "】", "《": "》", "〈": "〉",
          "«": "»", "‹": "›", "（": "）", "(": ")", "[": "]", "{": "}", "<": ">",
          '"': '"', "'": "'", "`": "`"}
_AUTHORITY_FIELDS = frozenset({"authority", "authorization", "authorized", "permissions", "permission",
    "readers", "owner", "owner_id", "actor_id", "agent_id", "grants", "grant", "role", "allow", "acl"})
_FINDING_FIELDS = frozenset({"source_id", "start", "end", "quote", "category", "policy_id", "method", "provenance"})
_PROVENANCE_FIELDS = frozenset({"source_id", "start", "end", "quote", "method"})
_CANDIDATE_FIELDS = frozenset({"cid", "source_id", "start", "end", "quote", "proposed_category",
                             "allowed_categories", "source_sha256", "proposal_sources"})


def _text_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _authority_fields(value):
    pending, seen = [value], set()
    while pending:
        item = pending.pop()
        if isinstance(item, (dict, list, tuple)):
            if id(item) in seen:
                continue
            seen.add(id(item))
        if isinstance(item, dict):
            if _AUTHORITY_FIELDS.intersection(item):
                return True
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return False


def _paired_interiors(text):
    """Yield exact nonblank closed interiors; retain original escape characters.

    Symmetric ASCII quotes close only their matching stack frame. Inner word
    apostrophes are literals. Escaped delimiters are literals. Mismatched and
    unclosed delimiters do not invent a closing position or truncate a value.
    """
    def apostrophe_word_character(character):
        # Han prose commonly touches an opening/closing quotation directly;
        # isalnum() alone would mistake 是'客户' for an in-word apostrophe.
        name = unicodedata.name(character, "")
        return character == "_" or character.isdigit() or name.startswith(("LATIN ", "GREEK ", "CYRILLIC "))
    stack, unmatched_closers, pairs = [], 0, []
    closers = set(_PAIRS.values())
    backslashes = 0
    for index, character in enumerate(text):
        escaped = backslashes % 2 == 1
        backslashes = backslashes+1 if character == "\\" else 0
        if escaped:
            continue
        if (character in {"'", "’"} and index and index+1 < len(text)
                and apostrophe_word_character(text[index-1]) and apostrophe_word_character(text[index+1])):
            continue
        if stack and character == stack[-1][1]:
            start, _ = stack.pop()
            if text[start+1:index].strip():
                pairs.append((start+1, index))
        elif character in _PAIRS:
            stack.append((index, _PAIRS[character]))
        elif character in closers:
            unmatched_closers += 1
    return sorted(set(pairs)), len(stack), unmatched_closers


def _exact_reference(item, sources, *, category_required):
    if not isinstance(item, dict) or _authority_fields(item):
        raise ValueError("invalid_or_authority_finding")
    permitted = _FINDING_FIELDS if category_required else _PROVENANCE_FIELDS
    if set(item)-permitted:
        raise ValueError("unsupported_finding_fields")
    source_id, start, end = item.get("source_id"), item.get("start"), item.get("end")
    if not isinstance(source_id, str) or source_id not in sources:
        raise ValueError("unknown_finding_source")
    if (type(start) is not int or type(end) is not int
            or not 0 <= start < end <= len(sources[source_id])):
        raise ValueError("invalid_finding_span")
    quote = sources[source_id][start:end]
    if not quote.strip() or ("quote" in item and item["quote"] != quote):
        raise ValueError("finding_quote_not_exact")
    if category_required and (not isinstance(item.get("category"), str) or item["category"] not in CATEGORIES):
        raise ValueError("invalid_finding_category")
    if "provenance" in item:
        if not isinstance(item["provenance"], list):
            raise ValueError("invalid_finding_provenance")
        for provenance in item["provenance"]:
            _exact_reference(provenance, sources, category_required=False)
    return source_id, start, end, quote


def propose_candidates(payload, policy, existing_findings, max_candidates=128, max_quote_chars=256):
    """Generate a finite position-bound pool without deciding sensitivity.

    Different boundaries/categories are retained; only identical span/category
    duplicates merge. Quotation evidence may attach to an existing exact span.
    Out-of-scope old categories are validated then ignored. No registry value
    matching, rule-based field parsing, entity maximalization or propagation is
    performed. Overflow rejects the pool instead of returning a hidden prefix.
    """
    result = {"version": PROPOSAL_VERSION, "status": "needs_review", "complete": False,
              "candidates": [], "error": None, "payload_sha256": None, "policy_sha256": None,
              "full_policy_sha256": None,
              "source_sha256": {}, "pool_sha256": None,
              "scope": "existing_exact_spans_and_closed_pairs_only_not_exhaustive_entities",
              "candidate_budget": max_candidates if type(max_candidates) is int else None,
              "quote_character_budget": max_quote_chars if type(max_quote_chars) is int else None,
              "ignored_out_of_scope_findings": 0, "unmatched_openers": 0, "unmatched_closers": 0}
    def fail(code, minimum=None):
        result.update(error=code)
        if minimum is not None:
            result["minimum_required_candidates"] = minimum
        return result
    if (type(max_candidates) is not int or not 1 <= max_candidates <= 4096
            or type(max_quote_chars) is not int or not 1 <= max_quote_chars <= 6000):
        return fail("invalid_candidate_budget")
    if _authority_fields(payload) or _authority_fields(policy):
        return fail("authority_fields_not_allowed")
    try:
        sources, normalized = _sources(payload), _policy(policy)
        result.update(payload_sha256=_digest(payload), policy_sha256=_digest(normalized), full_policy_sha256=_digest(policy),
                      source_sha256={sid: _text_hash(text) for sid, text in sources.items()})
    except (ValueError, TypeError, UnicodeError):
        return fail("invalid_payload_or_policy")
    if any(len(text) > normalized["max_text_chars"] for text in sources.values()):
        return fail("source_character_budget_exceeded")
    if not isinstance(existing_findings, list):
        return fail("existing_findings_must_be_list")
    categories = list(normalized["protected_categories"])
    proposals = {}
    def add(source_id, start, end, quote, category, origin):
        if end-start > max_quote_chars:
            raise ValueError("quote_character_budget_exceeded")
        key = (source_id, start, end, category)
        if key not in proposals:
            if len(proposals) >= max_candidates:
                raise OverflowError(len(proposals)+1)
            proposals[key] = {"source_id": source_id, "start": start, "end": end, "quote": quote,
                              "proposed_category": category, "allowed_categories": list(categories),
                              "source_sha256": result["source_sha256"][source_id], "proposal_sources": []}
        if origin not in proposals[key]["proposal_sources"]:
            proposals[key]["proposal_sources"].append(origin)
    try:
        for finding in existing_findings:
            sid, start, end, quote = _exact_reference(finding, sources, category_required=True)
            category = finding["category"]
            if category not in categories:
                result["ignored_out_of_scope_findings"] += 1
                continue
            add(sid, start, end, quote, category, "existing_finding")
        if categories:
            for sid, text in sources.items():
                interiors, openers, closers = _paired_interiors(text)
                result["unmatched_openers"] += openers
                result["unmatched_closers"] += closers
                for start, end in interiors:
                    exact = [key for key in proposals if key[:3] == (sid, start, end)]
                    if exact:
                        for key in exact:
                            add(sid, start, end, text[start:end], key[3], "paired_value")
                    else:
                        add(sid, start, end, text[start:end], None, "paired_value")
    except OverflowError as exc:
        return fail("candidate_budget_exceeded", exc.args[0])
    except (ValueError, TypeError) as exc:
        code = exc.args[0] if type(exc) is ValueError and exc.args and isinstance(exc.args[0], str) else "invalid_existing_finding"
        return fail(code)
    source_order = {sid: index for index, sid in enumerate(sources)}
    ordered = sorted(proposals, key=lambda key: (source_order[key[0]], key[1], key[2], key[3] or ""))
    candidates = [dict(proposals[key], cid=f"C{index+1:04d}") for index, key in enumerate(ordered)]
    result.update(status="candidates_only", complete=True, candidates=candidates)
    result["pool_sha256"] = _digest({"version": result["version"], "payload": result["payload_sha256"],
        "policy": result["policy_sha256"], "full_policy": result["full_policy_sha256"],
        "sources": result["source_sha256"], "candidates": candidates})
    return result


def _validate_pool_candidates(pool, sources, categories, hashes):
    candidates = pool.get("candidates")
    capacity, quote_capacity = pool.get("candidate_budget"), pool.get("quote_character_budget")
    if (not isinstance(candidates, list) or type(capacity) is not int or not 1 <= capacity <= 4096
            or type(quote_capacity) is not int or not 1 <= quote_capacity <= 6000
            or len(candidates) > capacity or pool.get("error") is not None):
        raise ValueError("candidate_pool_schema_invalid")
    for index, item in enumerate(candidates):
        if not isinstance(item, dict) or set(item) != _CANDIDATE_FIELDS:
            raise ValueError("candidate_schema_invalid")
        if item["cid"] != f"C{index+1:04d}":
            raise ValueError("candidate_id_invalid")
        sid, start, end, quote = item["source_id"], item["start"], item["end"], item["quote"]
        if (not isinstance(sid, str) or sid not in sources or type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(sources[sid]) or not isinstance(quote, str)
                or not quote.strip() or len(quote) > quote_capacity or sources[sid][start:end] != quote):
            raise ValueError("candidate_location_changed")
        if item["source_sha256"] != hashes[sid]:
            raise ValueError("candidate_source_hash_mismatch")
        proposed, origins = item["proposed_category"], item["proposal_sources"]
        if (item["allowed_categories"] != categories
                or (proposed is not None and (not isinstance(proposed, str) or proposed not in categories))
                or not isinstance(origins, list) or not origins
                or any(not isinstance(origin, str) or origin not in {"existing_finding", "paired_value"} for origin in origins)
                or len(set(origins)) != len(origins)
                or (proposed is None and ("paired_value" not in origins or "existing_finding" in origins))
                or (proposed is not None and "existing_finding" not in origins)):
            raise ValueError("candidate_category_or_origin_invalid")


def _context_markers(text, pool, item):
    """Choose deterministic, source-absent markers; a public hash is no secret."""
    domain = _digest({"marker_protocol": "candidate_context_v1", "pool": pool["pool_sha256"],
                      "source": _text_hash(text), "cid": item["cid"],
                      "start": item["start"], "end": item["end"]})[:16].upper()
    # Finite source text cannot contain every distinct nonempty marker. The
    # search checks the entire source, including outside the requested window.
    for counter in range(len(text)+1):
        prefix = f"⟦CP:{domain}:{counter}:{item['cid']}:BEGIN⟧"
        suffix = f"⟦CP:{domain}:{counter}:{item['cid']}:END⟧"
        if prefix not in text and suffix not in text:
            return prefix, suffix
    raise ValueError("candidate_context_marker_unavailable")


def candidate_context(payload, policy, pool, candidate_id, *, window_chars=96):
    """Return a marked occurrence, verifying pool/source/scope against inputs.

    The returned context is local raw data for a future classifier. It is not a
    sanitized cloud payload. Original offsets never refer to the marked string.
    """
    if type(window_chars) is not int or not 0 <= window_chars <= 6000:
        raise ValueError("invalid_context_window")
    if _authority_fields(payload) or _authority_fields(policy) or _authority_fields(pool):
        raise ValueError("authority_fields_not_allowed")
    try:
        sources, normalized = _sources(payload), _policy(policy)
        hashes = {sid: _text_hash(text) for sid, text in sources.items()}
        if (not isinstance(pool, dict) or pool.get("status") != "candidates_only" or pool.get("complete") is not True
                or pool.get("version") != PROPOSAL_VERSION or pool.get("payload_sha256") != _digest(payload)
                or pool.get("policy_sha256") != _digest(normalized)
                or pool.get("full_policy_sha256") != _digest(policy)
                or pool.get("source_sha256") != hashes):
            raise ValueError("candidate_pool_binding_mismatch")
        _validate_pool_candidates(pool, sources, normalized["protected_categories"], hashes)
        expected = _digest({"version": pool["version"], "payload": pool["payload_sha256"], "policy": pool["policy_sha256"],
                            "full_policy": pool["full_policy_sha256"],
                            "sources": pool["source_sha256"], "candidates": pool["candidates"]})
        if expected != pool.get("pool_sha256"):
            raise ValueError("candidate_pool_changed")
        selected = [item for item in pool["candidates"] if item.get("cid") == candidate_id]
        if len(selected) != 1:
            raise ValueError("candidate_id_not_unique_or_found")
        item = selected[0]
        sid, start, end = item["source_id"], item["start"], item["end"]
    except (KeyError, TypeError, UnicodeError):
        raise ValueError("invalid_candidate_context_input") from None
    text = sources[sid]
    marker_start, marker_end = _context_markers(text, pool, item)
    left, right = max(0, start-window_chars), min(len(text), end+window_chars)
    before, quote, after = text[left:start], text[start:end], text[end:right]
    return {"cid": candidate_id, "source_id": sid, "start": start, "end": end,
            "window_start": left, "window_end": right, "before": before, "quote": quote, "after": after,
            "marker_start": marker_start, "marker_end": marker_end,
            "marked_text": before+marker_start+quote+marker_end+after,
            "payload_sha256": pool["payload_sha256"], "policy_sha256": pool["policy_sha256"],
            "full_policy_sha256": pool["full_policy_sha256"],
            "source_sha256": hashes[sid]}
