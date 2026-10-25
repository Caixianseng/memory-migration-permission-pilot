"""Request-bound IDs for complete PVT tokens observed in prepared memories.

This optional module selects an existing opaque token, never restores a private
value or grants access. Callers must build from a successfully authorized privacy
preparation and pass the resolved token through the existing restoration layer.
Query text cannot create candidates. Source IDs here identify prepared memories;
the old restoration layer must still validate their original authenticated sources.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets

from .privacy import QUERY_SOURCE, _TOKEN, _policy, _sources

EVIDENCE_VERSION = "request_bound_answer_evidence_v1"
_UNKNOWN = "UNKNOWN"
_MAX_RAW_ANSWER_BYTES = 4096


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _valid_scope(actor_id, agent_id, request_id):
    return all(isinstance(value, str) and 0 < len(value) <= 256 and value.strip()
               for value in (actor_id, agent_id, request_id))


def _policy_binding(policy):
    normalized = _policy(policy)
    # Include all caller-supplied policy fields as well as validated defaults;
    # an extra same-version policy change must not silently reuse a table.
    return normalized, _digest({"full_input": policy, "normalized": normalized})


def _source_hashes(sources):
    return tuple(sorted((sid, hashlib.sha256(text.encode("utf-8")).hexdigest())
                        for sid, text in sources.items() if sid != QUERY_SOURCE))


class AnswerEvidenceTable:
    """Opaque local integrity object; not a serializable mapping or a grant."""
    __slots__ = ("_scope", "_policy_sha256", "_payload_sha256", "_source_hashes", "_entries", "_key", "_seal")

    def __init__(self, *, scope, policy_sha256, payload_sha256, source_hashes, entries):
        for name, value in (("_scope", tuple(scope)), ("_policy_sha256", policy_sha256),
                            ("_payload_sha256", payload_sha256), ("_source_hashes", tuple(source_hashes)),
                            ("_entries", tuple(entries)), ("_key", secrets.token_bytes(32))):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_seal", hmac.new(self._key, _canonical(self._material()), hashlib.sha256).digest())

    def _material(self):
        return {"version": EVIDENCE_VERSION, "scope": self._scope, "policy_sha256": self._policy_sha256,
                "payload_sha256": self._payload_sha256, "source_hashes": self._source_hashes,
                "entries": self._entries}

    def _intact(self):
        try:
            expected = hmac.new(self._key, _canonical(self._material()), hashlib.sha256).digest()
            return hmac.compare_digest(expected, self._seal)
        except (AttributeError, TypeError, ValueError, UnicodeError):
            return False

    def __setattr__(self, name, value):
        raise AttributeError("answer evidence tables are immutable")

    def __getstate__(self):
        raise TypeError("answer evidence tables must remain in process memory")

    def __reduce_ex__(self, protocol):
        raise TypeError("answer evidence tables must remain in process memory")

    def __repr__(self):
        return "<AnswerEvidenceTable: request-scoped; contents redacted>"


def _blocked_build(code):
    return {"status": "blocked", "table": None, "candidates": [], "response_schema": None,
            "metadata": {}, "error": code}


def build_answer_evidence(prepared_payload, *, actor_id, agent_id, request_id, policy, max_candidates=32):
    """Build token choices from memories only, with no raw-value recovery.

    Returns status/table/candidates/response_schema/metadata/error. ``candidates``
    is the cloud-safe list of {answer_id, token}; only already-masked PVT tokens
    are included. The local table is opaque and must never be logged/exported.
    Candidate overflow blocks rather than truncating the task's available facts.
    """
    if not _valid_scope(actor_id, agent_id, request_id):
        return _blocked_build("invalid_evidence_scope")
    if type(max_candidates) is not int or not 1 <= max_candidates <= 4096:
        return _blocked_build("invalid_evidence_candidate_limit")
    try:
        sources = _sources(prepared_payload)
        payload_hash = _digest(prepared_payload)
        source_hashes = _source_hashes(sources)
    except (ValueError, TypeError, UnicodeError):
        return _blocked_build("invalid_prepared_payload")
    try:
        normalized, policy_hash = _policy_binding(policy)
    except (ValueError, TypeError, UnicodeError):
        return _blocked_build("invalid_sensitivity_policy")
    if any(len(text) > normalized["max_text_chars"] for text in sources.values()):
        return _blocked_build("evidence_input_limit_exceeded")

    observed = {}
    for memory in prepared_payload["memories"]:
        for match in _TOKEN.finditer(memory["text"]):
            observed.setdefault(match.group(), set()).add(memory["source_id"])
            if len(observed) > max_candidates:
                return _blocked_build("evidence_candidate_limit_exceeded")

    # The display tag is a fresh request locator, not a shortened private-value
    # capability. The original complete long-nonce token stays unchanged.
    for _ in range(16):
        tag = secrets.token_hex(8).upper()
        ids = [f"E_{tag}_{index}" for index in range(1, len(observed) + 1)]
        if not any(identifier in text for identifier in ids for text in sources.values()):
            break
    else:
        return _blocked_build("evidence_id_namespace_collision")
    entries = tuple((identifier, token, tuple(sorted(observed[token])))
                    for identifier, token in zip(ids, observed))
    table = AnswerEvidenceTable(scope=(actor_id, agent_id, request_id), policy_sha256=policy_hash,
                                payload_sha256=payload_hash, source_hashes=source_hashes, entries=entries)
    candidates = [{"answer_id": identifier, "token": token} for identifier, token, _ in entries]
    schema = {"type": "object", "additionalProperties": False, "required": ["answer_id"],
              "properties": {"answer_id": {"type": "string", "enum": [_UNKNOWN] + ids}}}
    metadata = {"version": EVIDENCE_VERSION, "candidate_count": len(entries), "payload_sha256": payload_hash,
                "policy_sha256": policy_hash, "source_hashes_sha256": _digest(source_hashes),
                "scope_sha256": _digest({"actor_id": actor_id, "agent_id": agent_id, "request_id": request_id,
                                          "payload_sha256": payload_hash, "policy_sha256": policy_hash,
                                          "source_hashes_sha256": _digest(source_hashes)}),
                "candidate_view_sha256": _digest(candidates)}
    return {"status": "ok", "table": table, "candidates": candidates, "response_schema": schema,
            "metadata": metadata, "error": None}


def _blocked_resolve(code):
    return {"status": "blocked", "token": None, "error": code}


def _parse_answer(raw):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_RAW_ANSWER_BYTES:
        raise ValueError("invalid_evidence_answer_json")

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate_evidence_answer_key")
            obj[key] = value
        return obj

    def invalid_constant(_):
        raise ValueError("invalid_evidence_answer_json")

    try:
        answer = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except json.JSONDecodeError:
        raise ValueError("invalid_evidence_answer_json") from None
    if not isinstance(answer, dict) or set(answer) != {"answer_id"} or not isinstance(answer["answer_id"], str):
        raise ValueError("invalid_evidence_answer_schema")
    return answer["answer_id"]


def resolve_answer_evidence(raw, table, *, payload, actor_id, agent_id, request_id, policy, authorizer):
    """Resolve one current ID to its original PVT token, never to its real value.

    ``authorizer(source_id, actor_id, policy_version)`` must return exactly True
    for every associated prepared-memory source. Duplicate occurrences do not
    establish independent-source authority. UNKNOWN discloses no value and has
    no selected source to authorize; request/payload/policy validation still runs.
    Existing restore_answer/restore_labeled_answer remains mandatory afterwards.
    """
    if not isinstance(table, AnswerEvidenceTable) or not table._intact():
        return _blocked_resolve("invalid_evidence_table")
    if not _valid_scope(actor_id, agent_id, request_id) or table._scope != (actor_id, agent_id, request_id):
        return _blocked_resolve("evidence_scope_mismatch")
    if not callable(authorizer):
        return _blocked_resolve("invalid_evidence_authorizer")
    try:
        normalized, policy_hash = _policy_binding(policy)
    except (ValueError, TypeError, UnicodeError):
        return _blocked_resolve("invalid_sensitivity_policy")
    if policy_hash != table._policy_sha256:
        return _blocked_resolve("evidence_policy_mismatch")
    try:
        sources = _sources(payload)
        if _source_hashes(sources) != table._source_hashes:
            return _blocked_resolve("evidence_source_mismatch")
        if _digest(payload) != table._payload_sha256:
            return _blocked_resolve("evidence_payload_mismatch")
    except (ValueError, TypeError, UnicodeError):
        return _blocked_resolve("invalid_prepared_payload")
    try:
        identifier = _parse_answer(raw)
    except (ValueError, TypeError, UnicodeError) as exc:
        code = exc.args[0] if type(exc) is ValueError and exc.args and exc.args[0] in {
            "invalid_evidence_answer_json", "invalid_evidence_answer_schema", "duplicate_evidence_answer_key"} else "invalid_evidence_answer_json"
        return _blocked_resolve(code)
    if identifier == _UNKNOWN:
        return {"status": "ok", "token": _UNKNOWN, "error": None}
    entry = next(((token, ids) for key, token, ids in table._entries if key == identifier), None)
    if entry is None:
        return _blocked_resolve("unknown_answer_evidence_id")
    token, source_ids = entry
    if not source_ids:
        return _blocked_resolve("answer_evidence_source_missing")
    for sid in source_ids:
        if sid == QUERY_SOURCE or sid not in sources or token not in {m.group() for m in _TOKEN.finditer(sources[sid])}:
            return _blocked_resolve("answer_evidence_source_missing")
        try:
            permitted = authorizer(sid, actor_id, normalized["version"]) is True
        except Exception:
            permitted = False
        if not permitted:
            return _blocked_resolve("answer_evidence_authorization_failed")
    return {"status": "ok", "token": token, "error": None}
