"""Finite schema-field candidates, not sensitive values or permission grants.

Only explicit key/value records and pipe-table cells are parsed. Category is a
field-schema proposal for later contextual adjudication, never a declaration
that a value is private. Free prose without an anchored field key is ignored;
ambiguous multi-sentence values are not shortened into an invented name. No
model, files, registry-value matching, or literal propagation is used.
"""
from __future__ import annotations

import re

from .candidate_proposals import _PAIRS, _authority_fields, _paired_interiors, _text_hash
from .privacy import _digest, _policy, _sources


FIELD_VERSION = "explicit_schema_field_candidates_v1"
FIELD_LABELS = {
    "EMAIL": ("email", "e-mail", "email address", "mail", "邮箱", "电子邮箱", "电子邮件", "邮箱地址"),
    "PHONE": ("phone", "phone number", "telephone", "telephone number", "tel", "mobile", "mobile number",
              "电话", "电话号码", "手机号", "手机号码", "联系电话", "手机"),
    "ID": ("id", "id number", "identity number", "identity document", "document number", "identity card",
           "passport", "passport number", "身份证", "身份证号", "身份证号码", "证件号", "证件号码", "护照", "护照号", "护照号码"),
    "PERSON": ("name", "person", "person name", "full name", "contact name", "姓名", "人员姓名", "联系人", "联系人姓名", "负责人", "负责人姓名"),
    "ADDRESS": ("address", "postal address", "street address", "mailing address", "地址", "住址", "联系地址", "邮寄地址", "通讯地址", "通信地址"),
    "CUSTOMER": ("customer", "client", "customer name", "client name", "customer organization", "client organization",
                 "客户", "客户名称", "客户名", "客户组织", "客户单位", "客户企业"),
    "PROJECT": ("project", "project name", "project code", "project identifier", "project id", "project reference",
                "项目", "项目名", "项目名称", "项目代号", "项目代码", "项目编号", "项目标识", "项目参考编号"),
    "AMOUNT": ("amount", "budget", "total amount", "contract value", "金额", "预算", "预算金额", "合同金额", "总金额"),
    "DATE": ("date", "business date", "deadline", "due date", "delivery date", "start date", "end date",
             "日期", "业务日期", "截止日期", "交付日期", "到期日期", "开始日期", "结束日期"),
}
# These keys only terminate fields or mark table headers. They never yield a
# sensitive category or affect authorization, including when called "owner".
_BOUNDARY_LABELS = ("status", "state", "stage", "phase", "notes", "note", "description", "purpose",
                    "currency", "owner", "permissions", "role", "scope", "reference", "状态", "阶段", "处理阶段", "业务状态", "处理状态",
                    "备注", "说明", "用途", "币种", "所有者", "权限", "角色", "范围", "参考", "引用")
_ABSENT_VALUES = frozenset({"none", "null", "n/a", "na", "not provided", "not supplied", "not specified",
    "not filled", "not filled in", "not available", "no value", "unknown", "tbd", "unfilled",
    "未填写", "尚未填写", "没有填写", "未提供", "尚未提供", "未指定", "未设置", "未录入", "暂无", "无", "不适用", "待定", "待填写", "未知"})
_ABBREVIATION = re.compile(r"(?:\b(?:Inc|Ltd|Co|Corp|Pty|Bros|Assoc|Dept|LLC|PLC|St|Mt|Dr|Prof)\.|\b(?:[A-Za-z]{1,4}\.){2,})$", re.IGNORECASE)
_TABLE_SEPARATOR = re.compile(r":?-{3,}:?\Z")


def _label_key(value):
    return re.sub(r"[\s_-]+", "", value).casefold()


_LABEL_CATEGORIES = {_label_key(label): category for category, labels in FIELD_LABELS.items() for label in labels}
_ALL_LABELS = {*_LABEL_CATEGORIES, *(_label_key(x) for x in _BOUNDARY_LABELS)}


def _label_pattern(label):
    return r"[\s_-]*".join(re.escape(piece) for piece in re.split(r"[\s_-]+", label))


_ALIASES = sorted({label for labels in FIELD_LABELS.values() for label in labels} | set(_BOUNDARY_LABELS), key=len, reverse=True)
_KEY = re.compile(r"(?<![A-Za-z0-9_])(?P<key>"+"|".join(_label_pattern(label) for label in _ALIASES)+r")\s*(?P<separator>[:：=])\s*", re.IGNORECASE)


def _trim(text, start, end):
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end-1].isspace():
        end -= 1
    return start, end


def _regions(text):
    interiors, unclosed, mismatched = _paired_interiors(text)
    mask = [False]*len(text)
    for start, end in interiors:
        mask[start-1:end+1] = [True]*(end-start+2)
    return interiors, mask, bool(unclosed or mismatched)


def _split_outside(text, start, end, separators, mask):
    previous, result = start, []
    for index in range(start, end):
        if text[index] in separators and not mask[index]:
            result.append((previous, index))
            previous = index+1
    result.append((previous, end))
    return result


def _cells(text, start, end, mask):
    spans = [_trim(text, *span) for span in _split_outside(text, start, end, "|｜", mask)]
    has_opening_bar = len(spans) > 1 and spans[0][0] == spans[0][1]
    if has_opening_bar:
        spans.pop(0)
    if len(spans) > 1 and spans[-1][0] == spans[-1][1] and (has_opening_bar or len(spans) > 2):
        spans.pop()
    return spans


def _value_span(text, start, end):
    """Use field/cell boundaries only; never guess an entity prefix in prose."""
    start, end = _trim(text, start, end)
    if start == end:
        return None, "empty"
    value = text[start:end]
    if len(value) >= 2 and _PAIRS.get(value[0]) == value[-1] and not value[1:-1].strip():
        return None, "empty"
    interiors, mask, unbalanced = _regions(value)
    if unbalanced:
        return None, "ambiguous"
    while end > start and text[end-1] in ",，。!?！？" and not mask[end-start-1]:
        end -= 1
    if end > start and text[end-1] == "." and not mask[end-start-1] and not _ABBREVIATION.search(text[start:end]):
        end -= 1
    start, end = _trim(text, start, end)
    if start == end:
        return None, "empty"
    value = text[start:end]
    interiors, mask, _ = _regions(value)
    if (1, len(value)-1) in interiors:
        # Exact enclosing quote/bracket, not a name rewritten by the parser.
        start, end = _trim(text, start+1, end-1)
        return ((start, end), None) if start < end else (None, "empty")
    # A quoted beginning followed by unbounded prose is not silently shortened.
    if any(left == 1 and right < len(value)-1 for left, right in interiors):
        return None, "ambiguous"
    for index, character in enumerate(value):
        if mask[index]:
            continue
        if character in "。!?！？":
            return None, "ambiguous"
        if (character == "." and index+1 < len(value) and value[index+1].isspace()
                and not _ABBREVIATION.search(value[:index+1])):
            return None, "ambiguous"
    if " ".join(value.casefold().split()) in _ABSENT_VALUES:
        return None, "absent"
    return (start, end), None


def _enclosing_evidence(text, start, end, span):
    if span is None:
        return None, None
    raw = text[start:end]
    interiors, _, _ = _regions(raw)
    for left, right in sorted(interiors, key=lambda item: (item[0], -item[1])):
        suffix = raw[right+1:].strip()
        if (not raw[:left-1].strip() and all(char in ",，。.!?！？" for char in suffix)
                and start+left <= span[0] < span[1] <= start+right):
            return start+left-1, start+right+1
    return None, None


def propose_field_findings(payload, policy, *, max_candidates=128, max_value_chars=256):
    """Propose exact field-value spans for ``propose_candidates`` to consume.

    Supported records start at a line, semicolon, or pipe cell. Colon/equals
    records also end at an explicit following schema key (including nonsensitive
    status/notes). Two-column/alternating key-value pipe rows are supported.
    Multi-column Markdown tables require a real ``---`` header separator and
    aligned cells; no header is guessed from ordinary prose. Counts describe
    this finite parser, not sensitive-entity recall. Empty/absent/ambiguous
    values are counted and skipped; budget overflow rejects the entire pool.
    ``field_key_spans`` are syntax evidence, including nonsensitive keys.
    Their is_protected flag means the FIELD CATEGORY is in current scope, not
    that the key text or its proposed value has been judged private. The same
    field limit bounds structural records as well as value candidates.
    """
    result = {"version": FIELD_VERSION, "status": "needs_review", "complete": False,
              "findings": [], "field_key_spans": [], "field_boundaries": [],
              "error": None, "payload_sha256": None, "policy_sha256": None,
              "full_policy_sha256": None, "source_sha256": {},
              "schema_sha256": _digest({"fields": FIELD_LABELS, "boundary_labels": _BOUNDARY_LABELS,
                                         "absent_values": sorted(_ABSENT_VALUES)}),
              "candidate_limit": max_candidates if type(max_candidates) is int else None,
              "value_character_limit": max_value_chars if type(max_value_chars) is int else None,
              "scope": "explicit_schema_field_values_only_not_sensitive_or_exhaustive",
              "skipped_empty": 0, "skipped_absent": 0, "skipped_ambiguous": 0,
              "ignored_out_of_scope": 0, "header_tables": 0}

    def fail(code, minimum=None):
        result.update(status="needs_review", complete=False, findings=[], field_key_spans=[], field_boundaries=[], error=code)
        if minimum is not None:
            result["minimum_required_candidates"] = minimum
        return result

    if (type(max_candidates) is not int or not 1 <= max_candidates <= 4096
            or type(max_value_chars) is not int or not 1 <= max_value_chars <= 6000):
        return fail("invalid_candidate_budget")
    if _authority_fields(payload) or _authority_fields(policy):
        return fail("authority_fields_not_allowed")
    try:
        sources, normalized = _sources(payload), _policy(policy)
        result.update(payload_sha256=_digest(payload), policy_sha256=_digest(normalized),
                      full_policy_sha256=_digest(policy),
                      source_sha256={sid: _text_hash(text) for sid, text in sources.items()})
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return fail("invalid_payload_or_policy")
    if any(len(text) > normalized["max_text_chars"] for text in sources.values()):
        return fail("source_character_budget_exceeded")
    findings, seen, key_ids, too_long, overflow = [], set(), {}, False, False

    def add(sid, text, label, key_start, key_end, start, end, syntax, termination):
        nonlocal too_long, overflow
        if overflow:
            return
        label_key = _label_key(label)
        if label_key not in _ALL_LABELS:
            return
        category = _LABEL_CATEGORIES.get(label_key)
        if len(result["field_boundaries"]) == max_candidates:
            overflow = True
            return
        key_identity = (sid, key_start, key_end, category)
        if key_identity not in key_ids:
            key_id = key_ids[key_identity] = f"K{len(key_ids)+1:04d}"
            result["field_key_spans"].append({"key_id": key_id, "source_id": sid, "start": key_start,
                "end": key_end, "quote": text[key_start:key_end], "category": category,
                "kind": "field_key", "is_protected": category in normalized["protected_categories"]})
        span, reason = _value_span(text, start, end)
        enclosing_start, enclosing_end = _enclosing_evidence(text, start, end, span)
        result["field_boundaries"].append({"field_id": f"F{len(result['field_boundaries'])+1:04d}",
            "key_id": key_ids[key_identity], "source_id": sid, "category": category,
            "syntax": syntax, "termination": termination, "key_start": key_start, "key_end": key_end,
            "value_container_start": start,
            "value_container_end": end, "value_start": span[0] if span else None,
            "value_end": span[1] if span else None, "value_parse_status": reason or "exact",
            "value_enclosed": enclosing_start is not None, "enclosing_start": enclosing_start,
            "enclosing_end": enclosing_end, "next_key_start": None, "next_key_end": None,
            "next_key_source_id": None})
        if category is None:
            return
        if category not in normalized["protected_categories"]:
            result["ignored_out_of_scope"] += 1
            return
        if reason:
            result["skipped_"+reason] += 1
            return
        start, end = span
        if end-start > max_value_chars:
            too_long = True
            return
        key = (sid, start, end, category)
        if key not in seen:
            if len(findings) == max_candidates:
                overflow = True
                return
            seen.add(key)
            findings.append({"source_id": sid, "start": start, "end": end, "quote": text[start:end],
                             "category": category, "method": "schema_field_candidate"})

    def colon_cell(sid, text, start, end, mask, terminal):
        for part_start, part_end in _split_outside(text, start, end, ";；", mask):
            raw_part_end = part_end
            part_start, part_end = _trim(text, part_start, part_end)
            first = _KEY.match(text, part_start, part_end)
            if first is None:
                continue
            anchors = [first]
            anchors.extend(match for match in _KEY.finditer(text, first.end(), part_end) if not mask[match.start()])
            for index, match in enumerate(anchors):
                stop = anchors[index+1].start() if index+1 < len(anchors) else part_end
                termination = "next_schema_key" if index+1 < len(anchors) else (
                    "semicolon" if raw_part_end < end else terminal)
                add(sid, text, match.group("key"), match.start("key"), match.end("key"),
                    match.end(), stop, "key_value_separator", termination)

    for sid, text in sources.items():
        _, mask, _ = _regions(text)
        lines, cursor = [], 0
        for line in text.splitlines(keepends=True):
            end = cursor+len(line.rstrip("\r\n"))
            lines.append((cursor, end, _cells(text, cursor, end, mask)))
            cursor += len(line)
        index = 0
        while index < len(lines):
            start, end, cells = lines[index]
            if index+1 < len(lines) and len(cells) >= 2:
                separator = lines[index+1][2]
                if (len(separator) == len(cells)
                        and all(_TABLE_SEPARATOR.fullmatch(text[a:b]) for a, b in separator)):
                    result["header_tables"] += 1
                    headers = [(text[a:b], a, b) for a, b in cells]
                    index += 2
                    while index < len(lines) and len(lines[index][2]) == len(headers):
                        row_start, row_end, row_cells = lines[index]
                        if row_start == row_end or (index+1 < len(lines) and all(
                                _TABLE_SEPARATOR.fullmatch(text[a:b]) for a, b in lines[index+1][2])):
                            break
                        for (header, key_start, key_end), (left, right) in zip(headers, row_cells):
                            add(sid, text, header, key_start, key_end, left, right,
                                "markdown_header_cell", "pipe_cell")
                        index += 1
                    continue
            for part_start, part_end in _split_outside(text, start, end, ";；", mask):
                part_cells = _cells(text, part_start, part_end, mask)
                labels = [text[a:b] for a, b in part_cells]
                if (len(part_cells) >= 2 and len(part_cells) % 2 == 0
                        and all(_label_key(label) in _ALL_LABELS for label in labels[::2])):
                    for label, (key_start, key_end), (left, right) in zip(labels[::2], part_cells[::2], part_cells[1::2]):
                        add(sid, text, label, key_start, key_end, left, right, "pipe_key_value", "pipe_cell")
                elif len(part_cells) > 1 and labels and _label_key(labels[0]) in _ALL_LABELS:
                    # A key/value pipe row with unexplained extra cells is not
                    # shortened to its first convenient value.
                    result["skipped_ambiguous"] += 1
                else:
                    for left, right in part_cells:
                        terminal = "pipe_cell" if len(part_cells) > 1 else (
                            "semicolon" if part_end < end else "line_end")
                        colon_cell(sid, text, left, right, mask, terminal)
            index += 1
    if too_long:
        return fail("value_character_budget_exceeded")
    if overflow:
        return fail("candidate_budget_exceeded", max_candidates+1)
    # A later explicit key is proof of a field boundary if a proposed span
    # crosses it. This does not make every newline an entity boundary, nor
    # claim that there is no unrecognized field between the two known keys.
    for boundary in result["field_boundaries"]:
        later = [key for key in result["field_key_spans"]
                 if key["source_id"] == boundary["source_id"]
                 and key["start"] >= boundary["value_container_end"]]
        if later:
            next_key = min(later, key=lambda key: key["start"])
            boundary.update(next_key_start=next_key["start"], next_key_end=next_key["end"],
                            next_key_source_id=next_key["source_id"])
    result.update(status="candidates_only", complete=True, findings=findings)
    return result
