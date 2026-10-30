"""Exact, proposal-only completion of crossing currency/number amount spans.

No original finding is changed or removed.  A completion requires one prefix
span and one suffix span containing the *same numerical source interval*, and
their literal union must be a single supported amount expression.  Unsupported
formats remain original candidates; an empty result never declares them public.
This module does not inspect registries, scoring labels, permissions or models.
"""
from __future__ import annotations

import re

from .candidate_proposals import _authority_fields, _exact_reference, _text_hash
from .privacy import _digest, _policy, _sources


AMOUNT_VERSION = "crossing_literal_amount_completion_v1"
_MAX_INPUT_FINDINGS = 4096
# Aliases identify compatibility within this deliberately restricted grammar,
# not a financial currency inference.  In particular generic dollars/pounds and
# the ambiguous yen/yuan symbol alone are not used to guess a foreign currency.
_ALIASES = {
    "USD": ("USD", "US$", "$", "美元", "美金", "US dollar", "US dollars"),
    "CNY": ("CNY", "RMB", "人民币", "元", "yuan", "renminbi"),
    "EUR": ("EUR", "€", "欧元", "euro", "euros"),
    "GBP": ("GBP", "£", "英镑", "pound sterling", "pounds sterling", "British pound", "British pounds"),
}
_CURRENCIES = {alias.casefold(): currency for currency, aliases in _ALIASES.items() for alias in aliases}
_ALIAS = "(?:" + "|".join(re.escape(alias) for alias in sorted(
    _CURRENCIES, key=lambda value: (-len(value), value))) + ")"
# ASCII digits, correct comma groups and a nonempty decimal fraction only.
# Signs, exponent notation, fullwidth numbers and localized comma decimals are
# not rewritten/normalized; they simply do not produce a completion here.
_NUMBER = r"(?:[1-9][0-9]{0,2}(?:,[0-9]{3})+|0|[1-9][0-9]*)(?:\.[0-9]+)?(?:万|亿)?"
_SPACE = r"[ \t]*"
_FLAGS = re.IGNORECASE | re.ASCII
_PREFIX = re.compile(rf"(?P<currency>{_ALIAS}){_SPACE}(?P<number>{_NUMBER})", _FLAGS)
_SUFFIX = re.compile(rf"(?P<number>{_NUMBER}){_SPACE}(?P<currency>{_ALIAS})", _FLAGS)
_FULL = re.compile(rf"(?P<prefix>{_ALIAS}){_SPACE}(?P<number>{_NUMBER}){_SPACE}(?P<suffix>{_ALIAS})", _FLAGS)


def _outer_boundary(text, start, end):
    """Do not complete a currency fragment embedded inside an ASCII identifier."""
    if start and (text[start-1].isascii() and (text[start-1].isalnum() or text[start-1] == "_")):
        return False
    if end < len(text) and (text[end].isascii() and (text[end].isalnum() or text[end] == "_")):
        return False
    return not (end+1 < len(text) and text[end] in ".," and text[end+1].isdigit())


def complete_amount_findings(payload, policy, existing_findings, *, max_candidates=128):
    """Return only newly completed AMOUNT findings, with exact input provenance.

    ``complete`` describes this finite proposal procedure, not detection recall
    or authorization.  ``max_candidates`` limits new unique completions.  Raw
    findings remain the caller's responsibility, including unmerged conflicts.
    Hashes bind the full inputs but are not an authentication mechanism.
    """
    result = {"version": AMOUNT_VERSION, "status": "needs_review", "complete": False,
              "findings": [], "error": None, "payload_sha256": None, "policy_sha256": None,
              "full_policy_sha256": None, "source_sha256": {}, "existing_findings_sha256": None,
              "grammar_sha256": _digest({"version": AMOUNT_VERSION, "aliases": _ALIASES,
                                          "number": _NUMBER, "horizontal_space": _SPACE,
                                          "case_matching": "ascii_case_insensitive_only"}),
              "candidate_limit": max_candidates if type(max_candidates) is int else None,
              "input_limit": _MAX_INPUT_FINDINGS, "inspected_amount_findings": 0,
              "crossing_pairs": 0, "unmerged_crossing_pairs": 0, "unmerged_reasons": {},
              "scope": "literal_same_numeric_interval_crossing_amounts_only_not_sensitive_or_exhaustive"}

    def fail(code, minimum=None):
        result.update(status="needs_review", complete=False, findings=[], error=code)
        if minimum is not None:
            result["minimum_required_candidates"] = minimum
        return result

    if type(max_candidates) is not int or not 1 <= max_candidates <= 4096:
        return fail("invalid_candidate_budget")
    if _authority_fields(payload) or _authority_fields(policy) or _authority_fields(existing_findings):
        return fail("authority_fields_not_allowed")
    if not isinstance(existing_findings, list):
        return fail("invalid_existing_findings")
    if len(existing_findings) > _MAX_INPUT_FINDINGS:
        return fail("input_candidate_budget_exceeded")
    try:
        sources, normalized = _sources(payload), _policy(policy)
        result.update(payload_sha256=_digest(payload), policy_sha256=_digest(normalized),
                      full_policy_sha256=_digest(policy), existing_findings_sha256=_digest(existing_findings),
                      source_sha256={sid: _text_hash(text) for sid, text in sources.items()})
        for item in existing_findings:
            _exact_reference(item, sources, category_required=True)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return fail("invalid_payload_policy_or_finding")
    if any(len(text) > normalized["max_text_chars"] for text in sources.values()):
        return fail("source_character_budget_exceeded")
    if "AMOUNT" not in normalized["protected_categories"]:
        result.update(status="candidates_only", complete=True)
        return result

    by_source, existing_spans = {}, set()
    for item in existing_findings:
        if item["category"] != "AMOUNT":
            continue
        sid, start, end = item["source_id"], item["start"], item["end"]
        key = (sid, start, end)
        if key in existing_spans:
            continue
        existing_spans.add(key)
        by_source.setdefault(sid, []).append((start, end))
    result["inspected_amount_findings"] = len(existing_spans)
    completions = {}

    def unmerged(reason):
        result["unmerged_crossing_pairs"] += 1
        reasons = result["unmerged_reasons"]
        reasons[reason] = reasons.get(reason, 0)+1

    for sid, spans in by_source.items():
        text = sources[sid]
        spans.sort()
        for index, left in enumerate(spans):
            for right in spans[index+1:]:
                if right[0] >= left[1]:
                    break
                # Strict crossings, not duplicates, touching spans or containment.
                if not left[0] < right[0] < left[1] < right[1]:
                    continue
                result["crossing_pairs"] += 1
                prefix = _PREFIX.fullmatch(text[left[0]:left[1]])
                suffix = _SUFFIX.fullmatch(text[right[0]:right[1]])
                if prefix is None or suffix is None:
                    unmerged("unsupported_literal_fragments")
                    continue
                first_core = (left[0]+prefix.start("number"), left[0]+prefix.end("number"))
                second_core = (right[0]+suffix.start("number"), right[0]+suffix.end("number"))
                if first_core != second_core:
                    unmerged("different_numeric_intervals")
                    continue
                if _CURRENCIES[prefix["currency"].casefold()] != _CURRENCIES[suffix["currency"].casefold()]:
                    unmerged("incompatible_currencies")
                    continue
                start, end = left[0], right[1]
                full = _FULL.fullmatch(text[start:end])
                if (full is None or (start+full.start("number"), start+full.end("number")) != first_core
                        or not _outer_boundary(text, start, end)):
                    unmerged("incomplete_union_or_boundary")
                    continue
                key = (sid, start, end)
                if key in existing_spans or key in completions:
                    continue
                completions[key] = {"source_id": sid, "start": start, "end": end,
                    "quote": text[start:end], "category": "AMOUNT", "method": "literal_crossing_amount_completion",
                    "provenance": [{"source_id": sid, "start": a, "end": b,
                        "quote": text[a:b], "method": "amount_completion_input"} for a, b in (left, right)]}
                if len(completions) > max_candidates:
                    return fail("candidate_budget_exceeded", len(completions))
    order = {sid: index for index, sid in enumerate(sources)}
    result.update(status="candidates_only", complete=True,
                  findings=[completions[key] for key in sorted(completions, key=lambda key: (order[key[0]], key[1], key[2]))])
    return result
