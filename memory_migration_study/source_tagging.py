"""Lossless source-copy/tag grammar, not semantic recognition or authorization.

This independently implemented two-state-per-codepoint construction is an
engineering baseline related to Constrained Tagging for Span Labeling
(arXiv:2610.28922), not a new decoding algorithm. No author code is copied.
GBNF literals follow the llama.cpp GBNF guide. Backend grammar compatibility
and model quality must be qualified separately; this module invokes no model.

The grammar permits verbatim source characters and balanced, nonempty,
non-nested CUSTOMER tags. The host parser additionally limits the span count.
A legal tagged ordinary word is not thereby sensitive; an untagged document is
not thereby clean. This representation has no uncertainty or permission grant.
"""
from __future__ import annotations

import hashlib
import json
import re

VERSION = "lossless_source_copy_tag_v1"
CATEGORY = "CUSTOMER"
MAX_TEXT_CHARS = 6000
MAX_GRAMMAR_BYTES = 262144
MAX_SPANS = 32
_TAGLIKE = re.compile(r"</?M[0-9]+>")


class SourceTaggingError(ValueError):
    """Fixed host diagnostic code; failures must not become clean detections."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise SourceTaggingError(code)


def _text(value, code):
    _require(type(value) is str, code)
    _require(not any(0xD800 <= ord(char) <= 0xDFFF for char in value), "invalid_unicode_surrogate")
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _literal(value):
    """A GBNF string, with no JSON-only backspace/formfeed escape shortcuts."""
    escapes = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    pieces = []
    for char in value:
        code = ord(char)
        pieces.append(escapes[char] if char in escapes else
                      "\\x%02X" % code if code < 32 or code == 127 else char)
    return '"' + "".join(pieces) + '"'


def _delimiters(text):
    existing = {match.group() for match in _TAGLIKE.finditer(text)}
    for index in range(len(text) + 1):
        opening, closing = "<M%d>" % index, "</M%d>" % index
        if opening not in existing and closing not in existing:
            _require(opening not in text and closing not in text, "delimiter_collision")
            return opening, closing
    raise SourceTaggingError("delimiter_unavailable")


def build_contract(text):
    """Return deterministic text/grammar/hash bindings, or a fixed error.

    No truncation or normalization is allowed. A 6000-codepoint input may still
    exceed the independent 262144-byte grammar cap and must then be reviewed.
    The contract contains source text: it belongs only in the authorized local
    detector path, not ordinary logs or a public grant/capability.
    """
    _text(text, "invalid_source_text")
    _require(len(text) <= MAX_TEXT_CHARS, "source_text_limit_exceeded")
    opening, closing = _delimiters(text)
    op, cl = _literal(opening), _literal(closing)
    rules = ["root ::= out0"]
    for index, char in enumerate(text):
        literal = _literal(char)
        rules.append("out%d ::= %s out%d | %s %s in%d" %
                     (index, literal, index + 1, op, literal, index + 1))
        rules.append("in%d ::= %s in%d | %s out%d" %
                     (index, literal, index + 1, cl, index))
    rules.extend(('out%d ::= ""' % len(text), "in%d ::= %s" % (len(text), cl)))
    grammar = "\n".join(rules) + "\n"
    grammar_bytes = len(grammar.encode("utf-8"))
    _require(grammar_bytes <= MAX_GRAMMAR_BYTES, "source_grammar_limit_exceeded")
    result = {"version": VERSION, "category": CATEGORY, "text": text,
              "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
              "source_chars": len(text), "offset_unit": "unicode_codepoint_half_open",
              "normalization": "none", "open_tag": opening, "close_tag": closing,
              "grammar": grammar, "grammar_sha256": hashlib.sha256(grammar.encode("utf-8")).hexdigest(),
              "grammar_bytes": grammar_bytes, "rule_count": len(rules),
              "limits": {"max_text_chars": MAX_TEXT_CHARS, "max_grammar_bytes": MAX_GRAMMAR_BYTES,
                         "max_spans": MAX_SPANS}, "span_count_enforcement": "host_parser",
              "semantic_guarantee": False, "authorization_granted": False}
    result["contract_sha256"] = _digest(result)
    return result


def _bound_contract(text, contract):
    expected = build_contract(text)
    try:
        matches = type(contract) is dict and _canonical(contract) == _canonical(expected)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        matches = False
    _require(matches, "source_tag_contract_mismatch")
    return expected


def render_tagged(text, spans, contract=None):
    """Render ordered (start,end) pairs; a pure fixture/helper, never a detector."""
    bound = build_contract(text) if contract is None else _bound_contract(text, contract)
    _require(type(spans) in (list, tuple) and len(spans) <= MAX_SPANS, "invalid_tag_spans")
    pieces, cursor = [], 0
    for pair in spans:
        _require(type(pair) in (list, tuple) and len(pair) == 2
                 and all(type(value) is int for value in pair), "invalid_tag_spans")
        start, end = pair
        _require(cursor <= start < end <= len(text), "invalid_tag_spans")
        pieces.extend((text[cursor:start], bound["open_tag"], text[start:end], bound["close_tag"]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def parse_tagged(text, output, contract):
    """Validate complete copy and tags, returning exact source-position findings.

    Unknown insertions, edits and normalization fail. No strip, quote repair,
    source search, entity matching or sensitivity/authorization inference occurs.
    """
    bound = _bound_contract(text, contract)
    _text(output, "invalid_tag_output")
    opening, closing = bound["open_tag"], bound["close_tag"]
    _require(len(output) <= len(text) + MAX_SPANS * (len(opening) + len(closing)), "tag_output_limit_exceeded")
    source_pos, output_pos, start = 0, 0, None
    findings = []
    while output_pos < len(output):
        if output.startswith(opening, output_pos):
            _require(start is None, "nested_tag")
            start = source_pos
            output_pos += len(opening)
        elif output.startswith(closing, output_pos):
            _require(start is not None, "unexpected_close_tag")
            _require(start < source_pos, "empty_tag_span")
            findings.append({"start": start, "end": source_pos,
                             "quote": text[start:source_pos], "category": CATEGORY})
            _require(len(findings) <= MAX_SPANS, "tag_span_limit_exceeded")
            start = None
            output_pos += len(closing)
        else:
            _require(source_pos < len(text) and output[output_pos] == text[source_pos], "source_copy_mismatch")
            source_pos += 1
            output_pos += 1
    _require(start is None, "unclosed_tag")
    _require(source_pos == len(text), "source_copy_incomplete")
    return {"status": "ok", "findings": findings, "copy_verified": True,
            "semantic_verified": False, "authorization_granted": False,
            "source_sha256": bound["source_sha256"], "contract_sha256": bound["contract_sha256"],
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest()}
