"""Optional, zero-model proposals for typed seeds in open key/value lines.

Nothing imports this module into the default detector. A completion is only a
syntax candidate: neither quoting nor a single scalar-looking field proves one
semantic entity. Key occurrences are retained, never declared nonsensitive.
The module has no model, I/O, name dictionary, lexical propagation or authority.
"""
from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType
import re
import unicodedata

from .candidate_proposals import _exact_reference, _text_hash
from .privacy import _digest, _policy, _sources


VERSION = "typed_seeded_open_container_candidates_v1"
_LIMITS = (("max_containers", 128), ("max_key_chars", 80),
           ("max_value_chars", 256), ("max_input_chars", 4096))
DEFAULT_CONFIG = MappingProxyType(dict(_LIMITS))
MAX_INPUT_FINDINGS = 4096
_PAIRS = {'"': '"', "'": "'", "`": "`", "“": "”", "‘": "’", "「": "」", "『": "』",
          "«": "»", "‹": "›", "【": "】", "《": "》", "〈": "〉", "（": "）", "(": ")",
          "[": "]", "{": "}", "<": ">"}
_QUOTES = frozenset(('"', "'", "`", "“", "‘", "「", "『", "«", "‹"))
_SEPARATORS = frozenset(":：=")
_MULTIVALUE = frozenset(",，;；、|｜")


def _config(config):
    if config is None:
        config = {}
    if not isinstance(config, dict) or set(config)-set(DEFAULT_CONFIG):
        raise ValueError("invalid_config")
    result = dict(DEFAULT_CONFIG)
    for name, limit in _LIMITS:
        value = config.get(name, limit)
        if type(value) is not int or not 1 <= value <= limit:
            raise ValueError("invalid_config")
        result[name] = value
    return result


def _ref(item, sources):
    return {"source_id": item["source_id"], "start": item["start"], "end": item["end"],
            "quote": sources[item["source_id"]][item["start"]:item["end"]], "category": item["category"]}


def _contains(outer, inner):
    return outer[0] <= inner[0] < inner[1] <= outer[1]


def _overlaps(first, second):
    return max(first[0], second[0]) < min(first[1], second[1])


def _trim(text, start, end):
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end-1].isspace():
        end -= 1
    return start, end


def _word_character(character):
    name = unicodedata.name(character, "")
    return character == "_" or character.isdigit() or name.startswith(("LATIN ", "GREEK ", "CYRILLIC "))


def _scan(text, start, end):
    """Scan exact original positions; escaped punctuation is never decoded."""
    stack, pairs, delimiters, markers, nested_delimiters = [], {}, [], [], []
    backslashes = 0
    for index in range(start, end):
        character = text[index]
        escaped = backslashes % 2 == 1
        backslashes = backslashes+1 if character == "\\" else 0
        if escaped:
            continue
        if (character in {"'", "’"} and start < index < end-1
                and _word_character(text[index-1]) and _word_character(text[index+1])):
            continue
        if stack and stack[-1][2] == "quote":
            if character == stack[-1][1]:
                left, _, _ = stack.pop()
                pairs[left] = index
            continue
        if stack and character == stack[-1][1]:
            left, _, _ = stack.pop()
            pairs[left] = index
        elif character in _PAIRS:
            stack.append((index, _PAIRS[character], "quote" if character in _QUOTES else "bracket"))
        elif character in _PAIRS.values():
            return {"error": "unbalanced_quote_or_bracket"}
        elif character in _SEPARATORS:
            (nested_delimiters if stack else delimiters).append(index)
        elif character in _MULTIVALUE:
            markers.append(index)
    if stack or backslashes % 2:
        return {"error": "unbalanced_quote_or_bracket"}
    return {"error": None, "pairs": pairs, "delimiters": delimiters,
            "nested_delimiters": nested_delimiters, "markers": markers}


def _lines(text):
    # CRLF/CR/LF are the supported physical line endings. No normalization of
    # Unicode or positions is performed, including inside escaped strings.
    for match in re.finditer(r"[^\r\n]+", text):
        yield match.start(), match.end()


def _line_container(text, left, right):
    start, end = _trim(text, left, right)
    if start == end:
        return None, None
    if any(c in text[start:end] for c in "\v\f\x85\u2028\u2029"):
        return None, "unsupported_line_separator"
    scan = _scan(text, start, end)
    if scan["error"]:
        return None, scan["error"]
    # Whole JSON objects/arrays and pipe rows are outside this line-field
    # grammar; a balanced wrapper is not permission to parse their contents.
    if text[start] in "{[|｜" or scan["markers"]:
        return None, "unsupported_container_syntax"
    separators = scan["delimiters"]
    if not separators:
        return None, None
    if len(separators) != 1:
        return None, "multiple_outer_delimiters"
    delimiter = separators[0]
    key_start, key_end = _trim(text, start, delimiter)
    container_start, container_end = _trim(text, delimiter+1, end)
    if key_start == key_end or container_start == container_end:
        return None, "empty_key_or_value"
    value_start, value_end = container_start, container_end
    while value_start < value_end and scan["pairs"].get(value_start) == value_end-1:
        value_start, value_end = _trim(text, value_start+1, value_end-1)
    if value_start == value_end:
        return None, "empty_key_or_value"
    value_scan = _scan(text, container_start, container_end)
    if (value_scan["error"] or value_scan["delimiters"] or value_scan["nested_delimiters"]
            or value_scan["markers"] or text[container_start] == "{"):
        return None, "multiple_value_syntax"
    return {"line_start": left, "line_end": right, "key_start": key_start, "key_end": key_end,
            "delimiter_start": delimiter, "delimiter_end": delimiter+1,
            "value_container_start": container_start, "value_container_end": container_end,
            "value_start": value_start, "value_end": value_end,
            "syntax": "standalone_physical_line_key_value",
            "semantic_atomicity": "unverified"}, None


def propose_open_container_candidates(payload, policy, existing_findings, *, config=None):
    """Propose value boundaries without deleting seeds or deciding sensitivity.

    All budgets fail as a whole with no containers/completions returned. A
    syntax or conflicting-seed review may retain proposals from other lines,
    but sets status=needs_review and complete=False. Every validated input seed
    has one explicit retained decision; there is no final ``findings`` output.
    """
    result = {"version": VERSION, "kind": "syntax_candidates_only", "status": "needs_review",
              "complete": False, "containers": [], "completions": [], "decisions": [], "errors": [],
              "local_calls": 0, "inference_kind": "deterministic",
              "scope": "no_semantic_atomicity_sensitivity_or_authorization_decision"}
    seeds, sources = [], {}

    def fail(reason):
        result.update(status="needs_review", complete=False, containers=[], completions=[], errors=[reason])
        result["decisions"] = [dict(seed_id=f"S{i+1:04d}", seed=seed, action="needs_review",
            role="unparsed", reason=reason, retained=True, container_ids=[], completion_ids=[])
            for i, seed in enumerate(seeds)]
        return result

    try:
        cfg = _config(config)
        result.update(config=cfg, config_sha256=_digest(cfg))
    except (TypeError, ValueError):
        return fail("invalid_config")
    try:
        payload, policy, originals = deepcopy((payload, policy, existing_findings))
        sources, normalized = _sources(payload), _policy(policy)
        if not isinstance(originals, list):
            raise ValueError("invalid_findings")
        result.update(payload_sha256=_digest(payload), policy_sha256=_digest(normalized),
            full_policy_sha256=_digest(policy), existing_findings_sha256=_digest(originals),
            source_sha256={sid: _text_hash(text) for sid, text in sources.items()})
        if len(originals) > MAX_INPUT_FINDINGS:
            return fail("input_finding_budget_exceeded")
        for item in originals:
            _exact_reference(item, sources, category_required=True)
            if (item["category"] not in normalized["protected_categories"]
                    or ("policy_id" in item and item["policy_id"] != normalized["policy_id"])):
                raise ValueError("invalid_finding_binding")
            seeds.append(_ref(item, sources))
    except Exception:
        seeds = []
        return fail("invalid_payload_policy_or_findings")
    if (sum(map(len, sources.values())) > cfg["max_input_chars"]
            or any(len(t) > normalized["max_text_chars"] for t in sources.values())):
        return fail("input_character_budget_exceeded")

    parsed, syntax_reviews = [], []
    for sid, text in sources.items():
        for left, right in _lines(text):
            container, error = _line_container(text, left, right)
            if error:
                syntax_reviews.append((sid, left, right, error))
            if container is None:
                continue
            if container["key_end"]-container["key_start"] > cfg["max_key_chars"]:
                return fail("key_character_budget_exceeded")
            if container["value_container_end"]-container["value_container_start"] > cfg["max_value_chars"]:
                return fail("value_character_budget_exceeded")
            if len(parsed) == cfg["max_containers"]:
                return fail("container_budget_exceeded")
            parsed.append(dict(container, container_id=f"C{len(parsed)+1:04d}", source_id=sid,
                source_sha256=result["source_sha256"][sid], key_quote=text[container["key_start"]:container["key_end"]],
                value_quote=text[container["value_start"]:container["value_end"]]))
    result["containers"] = parsed
    decisions = [dict(seed_id=f"S{i+1:04d}", seed=seed, action="unchanged", role="unparsed",
        reason="no_supported_field_occurrence", retained=True, container_ids=[], completion_ids=[])
        for i, seed in enumerate(seeds)]
    for index, seed in enumerate(seeds):
        span = seed["start"], seed["end"]
        reviews = [r for r in syntax_reviews if r[0] == seed["source_id"] and _overlaps((r[1], r[2]), span)]
        if reviews:
            decisions[index].update(action="needs_review", reason=reviews[0][3])
        elif any(c in sources[seed["source_id"]][seed["start"]:seed["end"]] for c in "\r\n"):
            decisions[index].update(action="needs_review", reason="seed_crosses_physical_lines")

    for container in parsed:
        sid, cid = container["source_id"], container["container_id"]
        key = container["key_start"], container["key_end"]
        value = container["value_start"], container["value_end"]
        line = container["line_start"], container["line_end"]
        inside, crossing = [], False
        for index, seed in enumerate(seeds):
            if seed["source_id"] != sid or not _overlaps(line, (seed["start"], seed["end"])):
                continue
            decision = decisions[index]
            span = seed["start"], seed["end"]
            decision["container_ids"].append(cid)
            if _contains(key, span):
                decision.update(action="unchanged", role="key", reason="key_occurrence_retained")
            elif _contains(value, span):
                inside.append(index)
                decision.update(role="value")
            else:
                crossing = True
                decision.update(action="needs_review", role="crossing", reason="seed_crosses_container_boundary")
        categories = {seeds[i]["category"] for i in inside}
        non_nested = any(not (_contains((seeds[i]["start"], seeds[i]["end"]), (seeds[j]["start"], seeds[j]["end"]))
            or _contains((seeds[j]["start"], seeds[j]["end"]), (seeds[i]["start"], seeds[i]["end"])))
            for n, i in enumerate(inside) for j in inside[n+1:])
        review = ("seed_crosses_container_boundary" if crossing else "competing_categories" if len(categories) > 1
                  else "multiple_non_nested_seeds" if non_nested else None)
        if review:
            for index in inside:
                decisions[index].update(action="needs_review", reason=review)
            continue
        expandable = [i for i in inside if (seeds[i]["start"], seeds[i]["end"]) != value]
        for index in inside:
            if index not in expandable:
                decisions[index].update(action="unchanged", reason="already_exact_value")
        if not expandable:
            continue
        completion_id = f"P{len(result['completions'])+1:04d}"
        result["completions"].append({"completion_id": completion_id, "container_id": cid, "source_id": sid,
            "source_sha256": result["source_sha256"][sid], "start": value[0], "end": value[1],
            "quote": sources[sid][value[0]:value[1]], "category": seeds[expandable[0]]["category"],
            "seed_ids": [decisions[i]["seed_id"] for i in expandable], "semantic_atomicity": "unverified",
            "reason": "typed_seed_inside_syntactic_single_value"})
        for index in expandable:
            decisions[index].update(action="proposed_completion", reason="syntactic_boundary_only",
                                    completion_ids=[completion_id])
    result["decisions"] = decisions
    errors = sorted({r[3] for r in syntax_reviews} | {d["reason"] for d in decisions if d["action"] == "needs_review"})
    result.update(errors=errors, status="needs_review" if errors else "candidates_only", complete=not errors)
    return result


def validate_open_container_candidates(payload, policy, existing_findings, result, *, config=None):
    """Recompute the complete closed result; hashes alone are never evidence.

    Valid review/failure records may also be verified. No caller-supplied
    container, role, source hash or completion is trusted independently.
    """
    expected = propose_open_container_candidates(payload, policy, existing_findings, config=config)
    try:
        if not isinstance(result, dict) or _digest(result) != _digest(expected):
            raise ValueError("open_container_evidence_mismatch")
    except Exception:
        raise ValueError("open_container_evidence_mismatch") from None
    return deepcopy(expected)
