"""Source-only role cards over currently authorized exact, signed facts.

No query, answer, restoration map or evaluation reference enters this module.
Cards are local evidence; their roles never grant access or lower sensitivity.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from types import MappingProxyType

from .answer_evidence import _canonical, _digest, _policy_binding
from .memory_labels import MemoryLabelAuthority
from .role_query import ALIASES, _pattern

VERSION = "authorized_source_fact_cards_v1"
GRAMMAR_SHA256 = _digest({role: list(words) for role, words in ALIASES.items()})
FIELDS = ("role", "record_id", "start", "end", "anchor_start", "anchor_end", "support_start", "support_end")
_KEY = secrets.token_bytes(32)
ERRORS = (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError)


class CardError(ValueError):
    pass


def _require(value, code):
    if not value:
        raise CardError(code)


def _current_records(records, policy, *, authority, actor_id, agent_id, authorizer):
    _require(isinstance(authority, MemoryLabelAuthority) and callable(authorizer), "current_authority_required")
    _require(all(isinstance(s, str) and s.strip() and len(s) <= 256 for s in (actor_id, agent_id)), "invalid_card_principal")
    _require(isinstance(records, list) and len(records) <= 16, "invalid_card_records")
    normalized, policy_hash = _policy_binding(policy)
    _require(sum(len(r.get("text", "")) for r in records if isinstance(r, dict)) <= 12000, "source_card_budget_exceeded")
    seen = set()
    # Validate every supplied fact, including facts that produce no role card.
    for record in records:
        error = authority.validate_access(record, actor_id=actor_id, agent_id=agent_id,
                                          authorizer=authorizer, policy_version=normalized["version"])
        _require(error is None, "source_access_" + str(error))
        error = authority.validate_label(record, normalized)
        _require(error is None, "source_label_" + str(error))
        _require(record["record_id"] not in seen, "duplicate_card_record")
        seen.add(record["record_id"])
        _require(len(record["text"]) <= normalized["max_text_chars"], "source_card_budget_exceeded")
    return normalized, policy_hash, _digest(records), _digest(authority.export_state())


def _rows(records):
    """Frozen source prefix grammar; coordinates are always fact-relative."""
    rows = {}
    for record in records:
        text, rid = record["text"], record["record_id"]
        anchors = [(m.start(), m.end(), role) for role, words in ALIASES.items() if role != "status"
                   for m in re.finditer(_pattern(words), text, re.I)]
        for finding in record["label"]["findings"]:
            if finding["category"] != "CUSTOMER":
                continue
            a, b = finding["start"], finding["end"]
            eligible = [(left, right, role) for left, right, role in anchors
                        if 0 <= a - right <= 32 and re.fullmatch(
                            r"[\s,:：，=＝|｜]*(?:(?:is|was|是|为)\s*)?", text[right:a], re.I)]
            if not eligible:
                continue
            nearest = max(right for _, right, _ in eligible)
            choices = [(left, role) for left, right, role in eligible if right == nearest]
            if len({role for _, role in choices}) != 1:
                continue
            left, role = choices[0]
            row = (role, rid, a, b, left, nearest, left, b)
            rows[(rid, role, a, b)] = row
        pattern = _pattern(ALIASES["status"]) + r"\s*(?::|：|=|＝|\bis\b|\bwas\b|登记为|是|为)\s*(?P<value>[^。；;\r\n.!?！？|｜]+)"
        for match in re.finditer(pattern, text, re.I):
            a, b = match.span("value")
            while a < b and text[a].isspace():
                a += 1
            while a < b and text[b-1].isspace():
                b -= 1
            if not a < b or b-a > 160:
                continue
            row = ("status", rid, a, b, match.start(), match.start("value"), match.start(), b)
            rows[(rid, "status", a, b)] = row
    order = {record["record_id"]: index for index, record in enumerate(records)}
    result = tuple(sorted(rows.values(), key=lambda row: (order[row[1]], row[2], row[3], row[0])))
    _require(len(result) <= 128, "source_card_budget_exceeded")
    return result


class SourceFactCardTable:
    """Private coordinates and hashes, not a grant or an exportable value table."""
    __slots__ = ("_material", "_seal")

    def __init__(self, material):
        object.__setattr__(self, "_material", MappingProxyType(dict(material)))
        object.__setattr__(self, "_seal", hmac.new(_KEY, _canonical(material), hashlib.sha256).digest())

    def _intact(self):
        try:
            return hmac.compare_digest(self._seal, hmac.new(_KEY, _canonical(dict(self._material)), hashlib.sha256).digest())
        except ERRORS:
            return False

    def __setattr__(self, name, value):
        raise AttributeError("source fact tables are immutable")

    def __delattr__(self, name):
        raise AttributeError("source fact tables are immutable")

    def __getstate__(self):
        raise TypeError("source fact tables must remain local")

    def __repr__(self):
        return "<SourceFactCardTable: local evidence; contents redacted>"


def _check_source_table(table, records, policy, *, authority, actor_id, agent_id, authorizer):
    _require(type(table) is SourceFactCardTable and table._intact(), "source_card_table_invalid")
    normalized, policy_hash, record_hash, lifecycle_hash = _current_records(records, policy,
        authority=authority, actor_id=actor_id, agent_id=agent_id, authorizer=authorizer)
    material = table._material
    _require(material["scope"] == (actor_id, agent_id, id(authority)), "source_card_scope_changed")
    _require(material["policy"] == policy_hash and material["records"] == record_hash
             and material["lifecycle"] == lifecycle_hash, "source_card_context_changed")
    _require(material["grammar"] == GRAMMAR_SHA256 and material["entries"] == _rows(records), "source_card_evidence_changed")
    return normalized, policy_hash, record_hash, lifecycle_hash


def build_source_fact_cards(records, policy, *, authority, actor_id, agent_id, authorizer):
    try:
        _, policy_hash, record_hash, lifecycle_hash = _current_records(records, policy,
            authority=authority, actor_id=actor_id, agent_id=agent_id, authorizer=authorizer)
        entries = _rows(records)
        material = {"version": VERSION, "grammar": GRAMMAR_SHA256,
                    "scope": (actor_id, agent_id, id(authority)), "policy": policy_hash,
                    "records": record_hash, "lifecycle": lifecycle_hash, "entries": entries}
        return {"status": "ok", "source_table": SourceFactCardTable(material), "error": None,
                "metadata": {"version": VERSION, "record_count": len(records), "card_count": len(entries),
                             "organization_card_count": sum(row[0] != "status" for row in entries),
                             "status_card_count": sum(row[0] == "status" for row in entries),
                             "record_scope_sha256": record_hash, "policy_sha256": policy_hash,
                             "grammar_sha256": GRAMMAR_SHA256}}
    except CardError as exc:
        error = str(exc)
    except ERRORS:
        error = "source_card_input_invalid"
    return {"status": "blocked", "source_table": None, "metadata": {}, "error": error}
