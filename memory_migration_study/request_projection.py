"""Trusted source-card projection into an existing full privacy request.

Only this layer inspects original RestorationMap internals. It never crops the
map or returns original entries/values to a reader. Final original restoration
and current authorization checks remain mandatory.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
import secrets

from .answer_evidence import _canonical, _digest, _valid_scope
from .privacy import (QUERY_SOURCE, RestorationMap, _TOKEN, _close_and_propagate, _sources)
from .privacy_egress import validate_outbound
from .source_fact_cards import CardError, ERRORS, FIELDS, _check_source_table, _require

VERSION = "complete_request_source_card_projection_v1"
_KEY = secrets.token_bytes(32)


def _map_seal(mapping):
    """Keyed in-memory integrity only, not an exportable map representation."""
    _require(isinstance(mapping, RestorationMap), "projection_map_invalid")
    digest = hmac.new(_KEY, b"complete-original-restoration-map-v1", hashlib.sha256)

    def feed(value):
        data = value.encode("utf-8")
        digest.update(len(data).to_bytes(8, "big")); digest.update(data)

    for name in ("_actor_id", "_request_id", "_policy_version", "_policy_sha256", "_source_payload_sha256", "_nonce"):
        feed(getattr(mapping, name))
    for token, entry in sorted(mapping._entries.items()):
        feed(token); feed(entry.value)
        for value in entry.categories + entry.sources:
            feed(value)
    for sid, text in sorted(mapping._memories.items()):
        feed(sid); feed(text)
    for value, categories in mapping._protected_values:
        feed(value)
        for category in categories:
            feed(category)
    for sid, spans in sorted(mapping._sensitive_spans.items()):
        feed(sid)
        for a, b in spans:
            feed(str(a)); feed(str(b))
    return digest.digest()


def _intervals(findings, sid):
    result = []
    for item in sorted((f for f in findings if f["source_id"] == sid), key=lambda f: (f["start"], f["end"])):
        a, b, category = item["start"], item["end"], item["category"]
        if result and a < result[-1][1]:
            result[-1][1] = max(result[-1][1], b)
            result[-1][2].add(category)
        else:
            result.append([a, b, {category}])
    return result


def _align(raw, masked, intervals, sid, mapping):
    """Unique monotone exact alignment: unchanged text and whole replacements."""
    x = y = 0
    segments = []
    for a, b, categories in intervals:
        unchanged = raw[x:a]
        _require(masked[y:y+len(unchanged)] == unchanged, "projection_unchanged_text_mismatch")
        y += len(unchanged)
        token = _TOKEN.match(masked, y)
        _require(token is not None, "projection_whole_token_missing")
        entry = mapping._entries.get(token.group())
        _require(entry is not None, "projection_unregistered_token")
        original = raw[a:b]
        if sid == QUERY_SOURCE:
            _require(entry.value.casefold() == original.casefold(), "projection_query_value_changed")
        else:
            # A case-normalized/longer/merged entry is not an exact occurrence.
            _require(entry.value == original and sid in entry.sources, "projection_memory_value_changed")
        segments.append((a, b, y, token.end(), token.group(), tuple(sorted(categories))))
        x, y = b, token.end()
    _require(masked[y:] == raw[x:], "projection_trailing_text_mismatch")
    return tuple(segments)


def _protection_findings(prepared, records, normalized):
    """Both current detection and authenticated source labels remain mandatory."""
    sources = _sources(prepared["original_payload"])
    validated = []
    for finding in prepared["detection"]["findings"]:
        sid, a, b = finding["source_id"], finding["start"], finding["end"]
        _require(sid in sources and type(a) is int and type(b) is int and 0 <= a < b <= len(sources[sid])
                 and finding["category"] in normalized["protected_categories"]
                 and finding["policy_id"] == normalized["policy_id"], "projection_detection_changed")
        validated.append({"source_id": sid, "start": a, "end": b, "category": finding["category"],
                          "policy_id": finding["policy_id"], "method": "validated"})
    for record in records:
        for finding in record["label"]["findings"]:
            validated.append({"source_id": record["record_id"], **finding,
                              "policy_id": normalized["policy_id"], "method": "generation_label"})
    return _close_and_propagate(sources, validated, normalized["protected_categories"], normalized["policy_id"])


def _prepared_context(prepared, records, normalized, *, actor_id, request_id):
    _require(isinstance(prepared, dict) and prepared.get("status") == "ok", "projection_preparation_not_ready")
    original, payload = prepared.get("original_payload"), prepared.get("payload")
    sources, outbound_sources = _sources(original), _sources(payload)
    expected_memories = [{"source_id": r["record_id"], "text": r["text"]} for r in records]
    _require(original["memories"] == expected_memories, "projection_complete_records_changed")
    mapping = prepared.get("mapping")
    _require(isinstance(mapping, RestorationMap), "projection_map_invalid")
    _require((mapping._actor_id, mapping._request_id, mapping._policy_version) ==
             (actor_id, request_id, normalized["version"]), "projection_mapping_scope_changed")
    _require(mapping._policy_sha256 == _digest(normalized) and mapping._source_payload_sha256 == _digest(original),
             "projection_mapping_context_changed")
    _require(mapping._memories == {r["record_id"]: r["text"] for r in records}, "projection_mapping_records_changed")
    detection = prepared.get("detection")
    _require(validate_outbound(original, prepared, detection, normalized).get("status") == "ok", "projection_original_egress_failed")
    closed = _protection_findings(prepared, records, normalized)
    expected_spans = {sid: tuple((a, b) for a, b, _ in _intervals(closed, sid))
                      for sid in sources if sid != QUERY_SOURCE}
    _require(mapping._sensitive_spans == expected_spans, "projection_original_intervals_changed")
    _require(len(payload["memories"]) == len(records), "projection_memory_count_changed")
    aligned = {}
    observations = {}
    pairs = [(QUERY_SOURCE, original["query"], payload["query"], QUERY_SOURCE)]
    for index, (record, memory) in enumerate(zip(records, payload["memories"]), 1):
        _require(memory["source_id"] == f"m_{mapping._nonce}_{index}", "projection_memory_identity_changed")
        pairs.append((record["record_id"], record["text"], memory["text"], memory["source_id"]))
    for sid, raw, masked, outward_id in pairs:
        segments = _align(raw, masked, _intervals(closed, sid), sid, mapping)
        aligned[sid] = (outward_id, masked, segments)
        for _, _, _, _, token, categories in segments:
            observation = observations.setdefault(token, {"sources": set(), "categories": set()})
            observation["categories"].update(categories)
            if sid != QUERY_SOURCE:
                observation["sources"].add(sid)
    _require(set(mapping._entries) == set(observations), "projection_mapping_token_set_changed")
    for token, observation in observations.items():
        entry = mapping._entries[token]
        _require(set(entry.sources) == observation["sources"] and set(entry.categories) == observation["categories"],
                 "projection_complete_token_dependencies_changed")
    return aligned


def _boundary(position, segments):
    delta = 0
    for a, b, left, right, _, _ in segments:
        if a < position < b:
            raise CardError("projection_partial_support_boundary")
        if position == a:
            return left
        if position == b:
            return right
        if b < position:
            delta += (right-left)-(b-a)
    return position + delta


def _card_view(row, records_by_id, aligned):
    card = dict(zip(FIELDS, row))
    rid, a, b = card["record_id"], card["start"], card["end"]
    raw = records_by_id[rid]["text"]
    sid, masked, segments = aligned[rid]
    overlapping = [s for s in segments if s[0] < b and a < s[1]]
    if overlapping:
        _require(len(overlapping) == 1 and overlapping[0][:2] == (a, b), "projection_partial_or_merged_card_value")
        value = overlapping[0][4]
    else:
        left, right = _boundary(a, segments), _boundary(b, segments)
        value = masked[left:right]
        _require(value == raw[a:b] and card["role"] == "status", "projection_unmasked_organization_value")
    support_a, support_b = _boundary(card["support_start"], segments), _boundary(card["support_end"], segments)
    _require(0 <= support_a < support_b <= len(masked), "projection_support_invalid")
    return {"value": value, "source_id": sid, "role": card["role"], "support": masked[support_a:support_b]}


def _egress_view(view, prepared, normalized, records):
    # The actual extra card text is checked as part of its existing source,
    # without adding/deleting memories or modifying the original capability.
    checked = deepcopy(prepared["payload"])
    cards = view["fact_cards"]
    for memory in checked["memories"]:
        attached = [c for c in cards if c["source_id"] == memory["source_id"]]
        if attached:
            memory["text"] += "\n" + json.dumps(attached, ensure_ascii=False, separators=(",", ":"))
    projected = {**prepared, "payload": checked,
                 "metadata": {**prepared["metadata"], "payload_sha256": _digest(checked)}}
    protected_detection = {**prepared["detection"], "findings": _protection_findings(prepared, records, normalized)}
    _require(validate_outbound(prepared["original_payload"], projected, protected_detection, normalized).get("status") == "ok",
             "projection_extra_cards_egress_failed")


class RequestFactCardTable:
    """Complete original map and closed request-local choices; never serialize."""
    __slots__ = ("_source_table", "_mapping", "_binding", "_entries", "_views_blob", "_seal")

    def __init__(self, source_table, mapping, binding, entries, views):
        for name, value in (("_source_table", source_table), ("_mapping", mapping),
                            ("_binding", tuple(binding)), ("_entries", tuple(entries)),
                            ("_views_blob", _canonical(views))):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_seal", hmac.new(_KEY, self._material(), hashlib.sha256).digest())

    def _material(self):
        return (_canonical({"binding": self._binding, "entries": self._entries,
                            "source_seal": self._source_table._seal.hex(), "map_identity": id(self._mapping),
                            "views_sha256": hashlib.sha256(self._views_blob).hexdigest()}) + _map_seal(self._mapping))

    def _intact(self):
        try:
            return self._source_table._intact() and hmac.compare_digest(self._seal, hmac.new(_KEY, self._material(), hashlib.sha256).digest())
        except ERRORS:
            return False

    def __setattr__(self, name, value):
        raise AttributeError("request fact tables are immutable")

    def __delattr__(self, name):
        raise AttributeError("request fact tables are immutable")

    def __getstate__(self):
        raise TypeError("request fact tables must remain local")

    def __repr__(self):
        return "<RequestFactCardTable: complete original map; contents redacted>"


def _binding(prepared, *, actor_id, agent_id, request_id, policy_hash, record_hash, lifecycle_hash, authority):
    return (actor_id, agent_id, request_id, id(authority), policy_hash, record_hash, lifecycle_hash,
            _digest(prepared["payload"]), _digest(prepared["original_payload"]), _digest(prepared["detection"]))


def project_fact_cards(source_table, prepared, records, policy, *, authority, actor_id, agent_id, request_id, authorizer):
    try:
        _require(_valid_scope(actor_id, agent_id, request_id), "projection_scope_invalid")
        normalized, policy_hash, record_hash, lifecycle_hash = _check_source_table(source_table, records, policy,
            authority=authority, actor_id=actor_id, agent_id=agent_id, authorizer=authorizer)
        aligned = _prepared_context(prepared, records, normalized, actor_id=actor_id, request_id=request_id)
        by_id = {r["record_id"]: r for r in records}
        cards = [_card_view(row, by_id, aligned) for row in source_table._material["entries"]]
        # Short locators are not capabilities. A fresh request tag also rejects
        # accidental old-response IDs; full authorization remains independent.
        for _ in range(16):
            tag = secrets.token_hex(4).upper()
            ids = [f"C_{tag}_{i}" for i in range(1, len(cards)+1)]
            if not any(identifier in text for identifier in ids for text in _sources(prepared["payload"]).values()):
                break
        else:
            raise CardError("projection_id_collision")
        flat, rich, entries = [], [], []
        for identifier, card in zip(ids, cards):
            base = {"card_id": identifier, "value": card["value"], "source_id": card["source_id"]}
            flat.append(base); rich.append({**base, "role": card["role"], "support": card["support"]})
            entries.append((identifier, card["value"], card["source_id"]))
        views = {"flat": {**deepcopy(prepared["payload"]), "fact_cards": flat},
                 "source": {**deepcopy(prepared["payload"]), "fact_cards": rich}}
        for view in views.values():
            _egress_view(view, prepared, normalized, records)
        bound = _binding(prepared, actor_id=actor_id, agent_id=agent_id, request_id=request_id,
            policy_hash=policy_hash, record_hash=record_hash, lifecycle_hash=lifecycle_hash, authority=authority)
        table = RequestFactCardTable(source_table, prepared["mapping"], bound, entries, views)
        return {"status": "ok", "table": table, "views": views, "error": None,
                "response_schema": {"type": "object", "additionalProperties": False, "required": ["card_id"],
                    "properties": {"card_id": {"type": "string", "enum": ["UNKNOWN", *ids]}}},
                "metadata": {"version": VERSION, "card_count": len(cards), "record_scope_sha256": record_hash,
                    "flat_view_sha256": _digest(views["flat"]), "source_view_sha256": _digest(views["source"]),
                    "requires_original_restore": True, "local_calls": 0}}
    except CardError as exc:
        error = str(exc)
    except ERRORS:
        error = "projection_input_invalid"
    return {"status": "blocked", "table": None, "views": {}, "response_schema": None, "metadata": {}, "error": error}


def _validate_request(table, prepared, records, policy, *, authority, actor_id, agent_id, request_id, authorizer):
    _require(type(table) is RequestFactCardTable and table._intact(), "projection_table_invalid")
    _require(_valid_scope(actor_id, agent_id, request_id), "projection_scope_invalid")
    normalized, policy_hash, record_hash, lifecycle_hash = _check_source_table(table._source_table, records, policy,
        authority=authority, actor_id=actor_id, agent_id=agent_id, authorizer=authorizer)
    _require(prepared.get("mapping") is table._mapping, "projection_original_map_changed")
    _prepared_context(prepared, records, normalized, actor_id=actor_id, request_id=request_id)
    _require(table._binding == _binding(prepared, actor_id=actor_id, agent_id=agent_id, request_id=request_id,
        policy_hash=policy_hash, record_hash=record_hash, lifecycle_hash=lifecycle_hash, authority=authority),
        "projection_request_context_changed")
    return normalized


def validate_fact_card_view(view, table, prepared, records, policy, *, arm, authority,
                            actor_id, agent_id, request_id, authorizer):
    """Caller/reader must run this immediately before sending a model request."""
    try:
        normalized = _validate_request(table, prepared, records, policy, authority=authority,
            actor_id=actor_id, agent_id=agent_id, request_id=request_id, authorizer=authorizer)
        _require(arm in {"flat", "source"}, "projection_arm_invalid")
        _require(_digest(view) == _digest(json.loads(table._views_blob)[arm]), "projection_reader_view_changed")
        _egress_view(view, prepared, normalized, records)
        return {"status": "ok", "error": None, "local_calls": 0}
    except CardError as exc:
        error = str(exc)
    except ERRORS:
        error = "projection_view_invalid"
    return {"status": "blocked", "error": error, "local_calls": 0}


def resolve_fact_card_answer(response, table, prepared, records, policy, *, authority,
                             actor_id, agent_id, request_id, authorizer):
    try:
        _validate_request(table, prepared, records, policy, authority=authority,
            actor_id=actor_id, agent_id=agent_id, request_id=request_id, authorizer=authorizer)
        _require(isinstance(response, str) and len(response.encode("utf-8")) <= 4096, "projection_answer_invalid")

        def unique(items):
            value = {}
            for key, item in items:
                _require(key not in value, "projection_duplicate_answer_key")
                value[key] = item
            return value

        answer = json.loads(response, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(CardError("projection_answer_invalid")))
        _require(isinstance(answer, dict) and set(answer) == {"card_id"} and isinstance(answer["card_id"], str),
                 "projection_answer_schema_invalid")
        identifier = answer["card_id"]
        if identifier == "UNKNOWN":
            value = "UNKNOWN"
        else:
            selected = [value for cid, value, _ in table._entries if cid == identifier]
            _require(len(selected) == 1, "projection_unknown_card_id")
            value = selected[0]
        return {"status": "ok", "answer": value, "card_id": identifier, "error": None,
                "requires_original_restore": True, "local_calls": 0}
    except CardError as exc:
        error = str(exc)
    except ERRORS:
        error = "projection_answer_invalid"
    return {"status": "blocked", "answer": None, "error": error,
            "requires_original_restore": True, "local_calls": 0}
