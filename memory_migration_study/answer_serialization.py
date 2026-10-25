"""Strict optional wire-format correction, never value recovery or authority.

Only the missing outer brackets of one whole current-payload PVT token can be
added. Callers supply the actual host-prepared request, not model-supplied data,
then pass the result through the original complete restoration/authorization
path. An observed query token does not acquire memory evidence here.
"""
from __future__ import annotations

import re

from .privacy import CATEGORIES, _TOKEN, _sources


SERIALIZATION_VERSION = "exact_current_pvt_outer_brackets_v1"
_CATEGORIES = "|".join(sorted(CATEGORIES | {"MIXED"}))
_BARE = re.compile(r"PVT_[A-F0-9]{24}_(?:" + _CATEGORIES + r")_[1-9][0-9]*\Z")


def canonicalize_answer(answer, payload):
    """Return only canonical/original answer and a fixed decision code.

    Whitespace may surround the bare answer. No nonce/category/index/case,
    source evidence, policy or permission is repaired, inferred, or normalized.
    Existing full tokens and ordinary literals remain byte-for-byte unchanged.
    Invalid inputs do not become successful UNKNOWN answers. Payload membership
    is a syntax condition, not authentication of that payload or a grant.
    """
    if not isinstance(answer, str):
        return {"answer": None, "decision": "invalid_answer"}
    try:
        sources = _sources(payload)
    except (TypeError, ValueError, KeyError):
        return {"answer": answer, "decision": "invalid_payload"}
    stripped = answer.strip()
    if _BARE.fullmatch(stripped):
        candidate = "[" + stripped + "]"
        if any(candidate == match.group() for text in sources.values() for match in _TOKEN.finditer(text)):
            return {"answer": candidate, "decision": "added_outer_brackets"}
    return {"answer": answer, "decision": "unchanged"}
