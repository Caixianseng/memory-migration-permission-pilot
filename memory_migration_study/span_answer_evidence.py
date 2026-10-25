"""Request-bound pointers into already-authorized, pseudonymized memories.

The caller must first perform the existing permission/privacy preparation.
This module cannot establish that arbitrary input is authorized or fully masked.
It selects exact current source bytes/codepoints, never repairs a model's text,
recovers private values or grants access. Every successful result must still be
passed through restore_labeled_answer with the original authenticated records.
The public token view inherits the memory permissions; it is not anonymous.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import unicodedata

from .answer_evidence import _canonical, _digest, _policy_binding, _source_hashes, _valid_scope
from .privacy import CATEGORIES, QUERY_SOURCE, _sources

SPAN_EVIDENCE_VERSION = "request_bound_source_span_evidence_v1"
_PRIVATE = re.compile(r"\[PVT_[A-F0-9]{24}_(?:"+"|".join(sorted(CATEGORIES | {"MIXED"}))+r")_[1-9][0-9]*\]")
_RESERVED = re.compile(r"PVT_", re.I)
_ALIAS = re.compile(r"E_[A-F0-9]{32}\Z")
_NUMBER = re.compile(r"[+-]?\d+(?:,\d{3})*(?:\.\d+)?(?:[eE][+-]?\d+)?")
_ASCII_WORD = re.compile(r"[A-Za-z0-9_]+(?:[-'’][A-Za-z0-9_]+)*")
_RAW_LIMIT = 4096
_ERRORS = (ValueError, TypeError, UnicodeError, OverflowError, RecursionError)


def _valid_limits(limits):
    return (isinstance(limits, tuple) and len(limits) == 4 and
        all(type(value) is int and 1 <= value <= cap for value, cap in zip(limits, (128, 8192, 32768, 100000))))


def _han(char):
    return unicodedata.name(char, "").startswith(("CJK UNIFIED IDEOGRAPH", "CJK COMPATIBILITY IDEOGRAPH"))


def _tokenize(text):
    """Cover every codepoint, including whitespace; complete PVTs are atomic."""
    result, position = [], 0
    while position < len(text):
        start = position
        token = _PRIVATE.match(text, position)
        if token:
            position = token.end()
        elif _RESERVED.match(text, position):
            raise ValueError("malformed_private_token")
        elif text[position].isspace():
            position += 1
            while position < len(text) and text[position].isspace():
                position += 1
        elif (text[position].isdecimal() or text[position] in "+-") and (number := _NUMBER.match(text, position)) and (
                not text[position].isascii() or number.end() == len(text) or not (
                    text[number.end()].isascii() and (text[number.end()].isalnum() or text[number.end()] == "_"))):
            position = number.end()
        elif text[position].isascii() and (text[position].isalnum() or text[position] == "_"):
            position = _ASCII_WORD.match(text, position).end()
        elif _han(text[position]):
            position += 1
        elif unicodedata.category(text[position]).startswith(("L", "M")):
            position += 1
            while position < len(text) and not _han(text[position]) and (
                    unicodedata.category(text[position]).startswith(("L", "M", "N")) or text[position] == "_"):
                position += 1
        else:
            position += 1
        result.append((start, position))
    # A marker buried in a word or otherwise bypassing a token start is unsafe.
    private_regions = [m.span() for m in _PRIVATE.finditer(text)]
    if any(not any(a <= m.start() < b for a, b in private_regions) for m in _RESERVED.finditer(text)):
        raise ValueError("malformed_private_token")
    return tuple(result)


class SpanEvidenceTable:
    """Immutable, in-process integrity object; an evidence table is not a grant."""
    __slots__ = ("_scope", "_policy_sha256", "_payload_sha256", "_query_sha256", "_source_hashes",
                 "_entries", "_limits", "_key", "_seal")

    def __init__(self, *, scope, policy_sha256, payload_sha256, query_sha256, source_hashes, entries, limits):
        values = {"_scope": tuple(scope), "_policy_sha256": policy_sha256, "_payload_sha256": payload_sha256,
                  "_query_sha256": query_sha256, "_source_hashes": tuple(source_hashes), "_entries": tuple(entries),
                  "_limits": tuple(limits), "_key": secrets.token_bytes(32)}
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_seal", hmac.new(self._key, _canonical(self._material()), hashlib.sha256).digest())

    def _material(self):
        return {"version": SPAN_EVIDENCE_VERSION, "scope": self._scope, "policy_sha256": self._policy_sha256,
                "payload_sha256": self._payload_sha256, "query_sha256": self._query_sha256,
                "source_hashes": self._source_hashes, "entries": self._entries, "limits": self._limits}

    def _intact(self):
        try:
            return hmac.compare_digest(self._seal, hmac.new(self._key, _canonical(self._material()), hashlib.sha256).digest())
        except (AttributeError, *_ERRORS):
            return False

    def __setattr__(self, name, value):
        raise AttributeError("span evidence tables are immutable")

    def __delattr__(self, name):
        raise AttributeError("span evidence tables are immutable")

    def __getstate__(self):
        raise TypeError("span evidence tables must remain in process memory")

    def __reduce_ex__(self, protocol):
        raise TypeError("span evidence tables must remain in process memory")

    def __repr__(self):
        return "<SpanEvidenceTable: request-scoped; contents redacted>"


def _build_error(code, status="blocked"):
    return {"status": status, "table": None, "view": {"sources": []}, "response_schema": None, "metadata": {}, "error": code}


def _schema(entries):
    unknown = {"type": "object", "additionalProperties": False, "required": ["decision"],
               "properties": {"decision": {"type": "string", "enum": ["UNKNOWN"]}}}
    selectable = [(alias, tokens) for alias, _, _, tokens in entries if tokens]
    branches = [unknown]
    if selectable:
        maximum = max(len(tokens) for _, tokens in selectable)-1
        branches.append({"type": "object", "additionalProperties": False,
            "required": ["decision", "source", "start_token", "end_token"], "properties": {
                "decision": {"type": "string", "enum": ["SPAN"]},
                "source": {"type": "string", "enum": [alias for alias, _ in selectable]},
                "start_token": {"type": "integer", "minimum": 0, "maximum": maximum},
                "end_token": {"type": "integer", "minimum": 0, "maximum": maximum}}})
    return {"anyOf": branches}


def build_span_evidence(payload, *, actor_id, agent_id, request_id, policy,
                        max_sources=16, max_tokens_per_source=512, max_total_tokens=2048, max_total_chars=12000):
    """Build source aliases and lossless token views; query never supplies spans.

    Token indices are zero-based; inclusive selections become exact half-open
    character ranges. Limits reject the whole build with needs_review, never a
    truncated prefix. Public views contain prepared text and inherit its ACLs.
    """
    if not _valid_scope(actor_id, agent_id, request_id):
        return _build_error("invalid_span_evidence_scope")
    limits = (max_sources, max_tokens_per_source, max_total_tokens, max_total_chars)
    if not _valid_limits(limits):
        return _build_error("invalid_span_evidence_limits")
    try:
        sources = _sources(payload)
        payload_hash, hashes = _digest(payload), _source_hashes(sources)
        normalized, policy_hash = _policy_binding(policy)
        query_hash = hashlib.sha256(payload["query"].encode("utf-8")).hexdigest()
    except _ERRORS:
        return _build_error("invalid_span_evidence_input")
    if (len(payload["memories"]) > max_sources or any(len(text) > normalized["max_text_chars"] for text in sources.values())
            or sum(len(text) for text in sources.values()) > max_total_chars):
        return _build_error("span_evidence_input_budget_exceeded", "needs_review")
    entries, view, aliases, total = [], [], set(), 0
    try:
        for memory in payload["memories"]:
            text, sid = memory["text"], memory["source_id"]
            tokens = _tokenize(text)
            total += len(tokens)
            if len(tokens) > max_tokens_per_source or total > max_total_tokens:
                return _build_error("span_evidence_token_budget_exceeded", "needs_review")
            for _ in range(16):
                alias = "E_"+secrets.token_hex(16).upper()
                if alias not in aliases and not any(alias in source for source in sources.values()):
                    break
            else:
                return _build_error("span_evidence_alias_collision", "needs_review")
            aliases.add(alias)
            entries.append((alias, sid, hashlib.sha256(text.encode("utf-8")).hexdigest(), tokens))
            view.append({"source": alias, "tokens": [{"index": i, "start": a, "end": b, "text": text[a:b]}
                                                    for i, (a, b) in enumerate(tokens)]})
        table = SpanEvidenceTable(scope=(actor_id, agent_id, request_id), policy_sha256=policy_hash,
            payload_sha256=payload_hash, query_sha256=query_hash, source_hashes=hashes, entries=entries, limits=limits)
        public = {"sources": view}
        metadata = {"version": SPAN_EVIDENCE_VERSION, "source_count": len(entries), "token_count": total,
            "total_characters": sum(len(t) for t in sources.values()), "payload_sha256": payload_hash,
            "query_sha256": query_hash, "policy_sha256": policy_hash, "source_hashes_sha256": _digest(hashes),
            "view_sha256": _digest(public), "scope_sha256": _digest((actor_id, agent_id, request_id, payload_hash, policy_hash)),
            "limits": dict(zip(("max_sources", "max_tokens_per_source", "max_total_tokens", "max_total_chars"), limits))}
        return {"status": "ok", "table": table, "view": public, "response_schema": _schema(entries), "metadata": metadata, "error": None}
    except _ERRORS as error:
        return _build_error("malformed_private_token" if error.args == ("malformed_private_token",) else "invalid_span_evidence_input")


def _resolve_error(code):
    return {"status": "blocked", "answer": None, "source_span": None, "error": code}


def _parse(raw):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _RAW_LIMIT:
        raise ValueError("invalid_span_answer_json")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_span_answer_key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("invalid_span_answer_json")
    try:
        data = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except json.JSONDecodeError:
        raise ValueError("invalid_span_answer_json") from None
    if not isinstance(data, dict):
        raise ValueError("invalid_span_answer_schema")
    if data == {"decision": "UNKNOWN"}:
        return data
    if (set(data) != {"decision", "source", "start_token", "end_token"} or data["decision"] != "SPAN"
            or not isinstance(data["source"], str) or not _ALIAS.fullmatch(data["source"])
            or type(data["start_token"]) is not int or type(data["end_token"]) is not int):
        raise ValueError("invalid_span_answer_schema")
    return data


def _bound_representation(table, payload):
    """Rebuild one table's exact source-ordered representation, without grants."""
    if type(table) is not SpanEvidenceTable or not table._intact():
        raise ValueError("invalid_span_evidence_table")
    if not isinstance(table._scope, tuple) or len(table._scope) != 3 or not _valid_scope(*table._scope):
        raise ValueError("invalid_span_evidence_table")
    sources = _sources(payload)
    if _source_hashes(sources) != table._source_hashes:
        raise ValueError("span_evidence_source_mismatch")
    if _digest(payload) != table._payload_sha256 or hashlib.sha256(payload["query"].encode()).hexdigest() != table._query_sha256:
        raise ValueError("span_evidence_payload_mismatch")
    if not _valid_limits(table._limits):
        raise ValueError("invalid_span_evidence_table")
    max_sources, per_source, total_limit, chars_limit = table._limits
    if len(payload["memories"]) > max_sources or sum(len(t) for t in sources.values()) > chars_limit:
        raise ValueError("invalid_span_evidence_table")
    if (not isinstance(table._entries, tuple) or len(table._entries) != len(payload["memories"])):
        raise ValueError("invalid_span_evidence_table")
    aliases, total, view = set(), 0, []
    for entry, memory in zip(table._entries, payload["memories"]):
        if not isinstance(entry, tuple) or len(entry) != 4:
            raise ValueError("invalid_span_evidence_table")
        alias, sid, text_hash, tokens = entry
        text = memory["text"]
        if (not isinstance(alias, str) or not _ALIAS.fullmatch(alias) or alias in aliases or sid != memory["source_id"]
                or sid == QUERY_SOURCE or text_hash != hashlib.sha256(text.encode()).hexdigest()
                or not isinstance(tokens, tuple) or any(not isinstance(t, tuple) or len(t) != 2
                    or any(type(i) is not int for i in t) for t in tokens)
                or tokens != _tokenize(text) or any(alias in source for source in sources.values())):
            raise ValueError("invalid_span_evidence_table")
        total += len(tokens)
        if len(tokens) > per_source or total > total_limit:
            raise ValueError("invalid_span_evidence_table")
        aliases.add(alias)
        view.append({"source": alias, "tokens": [{"index": i, "start": a, "end": b, "text": text[a:b]}
                                                for i, (a, b) in enumerate(tokens)]})
    return sources, {"sources": view}, _schema(table._entries)


def validate_span_view_binding(table, payload, view, schema):
    """Validate presentation against the opaque table before model execution.

    No caller scope or current authorization is inferred. This checks only
    representation integrity; resolver scope/auth and original restore remain
    mandatory. The table never belongs in a wire request or serialized log.
    """
    try:
        _, expected_view, expected_schema = _bound_representation(table, payload)
        if _canonical(view) != _canonical(expected_view):
            return {"status": "blocked", "error": "span_evidence_view_mismatch"}
        if _canonical(schema) != _canonical(expected_schema):
            return {"status": "blocked", "error": "span_evidence_schema_mismatch"}
        return {"status": "ok", "error": None}
    except (AttributeError, *_ERRORS) as error:
        code = error.args[0] if type(error) is ValueError and error.args and error.args[0] in {
            "invalid_span_evidence_table", "span_evidence_source_mismatch", "span_evidence_payload_mismatch"} else "invalid_span_evidence_input"
        return {"status": "blocked", "error": code}


def resolve_span_evidence(raw, table, payload, *, actor_id, agent_id, request_id, policy, authorizer):
    """Resolve current source/token indices; never restore values or authorize.

    authorizer(original_prepared_source_id, actor_id, policy_version) must return
    exactly True now. UNKNOWN has no selected source but still checks every
    table/context binding. The original restore_labeled_answer remains required.
    """
    if type(table) is not SpanEvidenceTable or not table._intact():
        return _resolve_error("invalid_span_evidence_table")
    if not _valid_scope(actor_id, agent_id, request_id) or table._scope != (actor_id, agent_id, request_id):
        return _resolve_error("span_evidence_scope_mismatch")
    if not callable(authorizer):
        return _resolve_error("invalid_span_evidence_authorizer")
    try:
        normalized, policy_hash = _policy_binding(policy)
        if policy_hash != table._policy_sha256:
            return _resolve_error("span_evidence_policy_mismatch")
        sources, _, _ = _bound_representation(table, payload)
        if any(len(t) > normalized["max_text_chars"] for t in sources.values()):
            return _resolve_error("invalid_span_evidence_table")
        data = _parse(raw)
    except (AttributeError, *_ERRORS) as error:
        code = error.args[0] if error.args and error.args[0] in {
            "invalid_span_answer_json", "invalid_span_answer_schema", "duplicate_span_answer_key", "invalid_span_evidence_table",
            "span_evidence_source_mismatch", "span_evidence_payload_mismatch"} else "invalid_span_evidence_input"
        return _resolve_error(code)
    if data["decision"] == "UNKNOWN":
        return {"status": "ok", "answer": "UNKNOWN", "source_span": None, "error": None}
    entry = next((entry for entry in table._entries if entry[0] == data["source"]), None)
    if entry is None:
        return _resolve_error("unknown_span_evidence_source")
    _, sid, _, tokens = entry
    start, end = data["start_token"], data["end_token"]
    if not 0 <= start <= end < len(tokens):
        return _resolve_error("invalid_span_token_range")
    a, b = tokens[start][0], tokens[end][1]
    answer = sources[sid][a:b]
    if not answer.strip():
        return _resolve_error("empty_span_answer")
    if _RESERVED.search(answer) and _PRIVATE.fullmatch(answer) is None:
        return _resolve_error("span_answer_not_single_value")
    try:
        allowed = authorizer(sid, actor_id, normalized["version"]) is True
    except Exception:
        allowed = False
    if not allowed:
        return _resolve_error("span_evidence_authorization_failed")
    return {"status": "ok", "answer": answer, "source_span": {"source_id": sid, "start": a, "end": b,
        "start_token": start, "end_token": end}, "error": None}
