"""Advisory offline value checks layered over the unchanged privacy detector.

Invalid/unsupported values remain sensitivity candidates. Syntax, checksum and
calendar checks neither establish identity/existence nor grant access or prove
privacy. This module was not used to make the frozen neural experiment's
decisions; saved detections can be annotated independently without inference.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import date
import re

from . import privacy as _core

VALIDATION_VERSION = "offline_sensitive_value_validation_v1"
VALIDATION_SCOPE = "offline_syntax_only_not_identity_existence_privacy_or_authorization"
STANDARD_SOURCES = (
    "https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=080D6FBF2BB468F9007657F26D60013E&refer=outter",
    "https://zjw.beijing.gov.cn/Portals/0/zhuanti/fazhan/%E8%BA%AB%E4%BB%BD%E8%AF%81GB11643-1999.pdf",
)
# GB11643-1999, tables 1/2. Region registration, real issuance and a real person
# are deliberately not checked; the checksum is only a mathematical property.
_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_CHECK = "10X98765432"
_MONTHS = {name.casefold(): index for index, name in enumerate((
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"), 1)}
_FINDING_KEYS = frozenset({"source_id", "start", "end", "category", "method", "policy_id", "provenance"})


def _states(format="not_applicable", checksum="not_applicable", calendar="not_applicable"):
    return {"format": format, "checksum": checksum, "calendar": calendar}


def _calendar(year, month, day):
    try:
        date(int(year), int(month), int(day))
        return "valid"
    except (ValueError, TypeError, OverflowError):
        return "invalid"


def _email_format(value):
    # Supported subset: ASCII dot-atom local part and a dotted DNS-shaped
    # domain. Quoted/EAI/address-literal forms are unchecked, not rejected as
    # globally invalid mailboxes. No DNS, delivery or account lookup is made.
    if not value.isascii() or value.startswith('"') or "[" in value or "]" in value:
        return "unchecked"
    if value.count("@") != 1 or value != value.strip():
        return "invalid"
    local, domain = value.split("@")
    if "." not in domain:
        return "unchecked"
    atom = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    if (not local or len(local) > 64 or len(domain) > 253 or len(value) > 254
            or re.fullmatch(rf"{atom}(?:\.{atom})*", local) is None):
        return "invalid"
    for label in domain.split("."):
        if (not 1 <= len(label) <= 63 or label.startswith("-") or label.endswith("-")
                or re.fullmatch(r"[A-Za-z0-9-]+", label) is None):
            return "invalid"
    return "valid"


def _phone_format(value):
    # A deliberately limited offline shape check: 7..15 digits, optional leading
    # plus and common visual separators. Country/carrier assignment, reachability
    # and ownership are unchecked even when this returns valid.
    if (value != value.strip() or re.fullmatch(r"\+?[0-9(). -]+", value) is None
            or value.count("(") != value.count(")") or value.count("(") > 1):
        return "invalid"
    if "(" in value and value.index("(") > value.index(")"):
        return "invalid"
    digits = re.sub(r"[^0-9]", "", value)
    return "valid" if 7 <= len(digits) <= 15 else "invalid"


def validate_value(value, category):
    """Return three fixed status enums, never a value or a safety decision.

    ``valid`` means only the supported local check passed. Unknown ID formats
    and date expressions remain unchecked. Bad checksums/dates are never a
    reason to remove or release a sensitive candidate.
    """
    if not isinstance(value, str) or not isinstance(category, str) or category not in _core.CATEGORIES:
        return _states("unchecked", "unchecked", "unchecked")
    if category == "ID":
        if re.fullmatch(r"[0-9]{17}[0-9Xx]", value) is None:
            # ID covers many document systems. Do not call an unfamiliar
            # passport invalid merely because it is not a Chinese CN18 value.
            return _states("unchecked", "unchecked", "unchecked")
        remainder = sum(int(digit)*weight for digit, weight in zip(value[:17], _CN_WEIGHTS)) % 11
        return _states("valid", "valid" if value[-1].upper() == _CN_CHECK[remainder] else "invalid",
                       _calendar(value[6:10], value[10:12], value[12:14]))
    if category == "DATE":
        numeric = re.fullmatch(r"([0-9]{4})([-/])([0-9]{1,2})\2([0-9]{1,2})", value)
        chinese = re.fullmatch(r"([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日", value)
        english = re.fullmatch(r"([A-Za-z]+)\s+([0-9]{1,2}),?\s+([0-9]{4})", value)
        if numeric:
            return _states("valid", "not_applicable", _calendar(numeric[1], numeric[3], numeric[4]))
        if chinese:
            return _states("valid", "not_applicable", _calendar(*chinese.groups()))
        if english and english[1].casefold() in _MONTHS:
            return _states("valid", "not_applicable", _calendar(english[3], _MONTHS[english[1].casefold()], english[2]))
        return _states("unchecked", "not_applicable", "unchecked")
    if category == "EMAIL":
        return _states(_email_format(value))
    if category == "PHONE":
        return _states(_phone_format(value))
    return _states()


def annotate_detection(payload, detection):
    """Deep-copy a detection and append non-authorizing offline annotations.

    The original status/findings/errors are preserved exactly. Source offsets
    must belong to the exact payload hash and declared protected categories.
    Malformed locations/scope produce explicit annotation errors with unchecked
    states; no original candidate is dropped. Only approved reference fields
    and fixed enums/error codes enter annotations, never the extracted values.
    """
    if not isinstance(detection, dict):
        raise ValueError("validation_requires_detection_object")
    result = deepcopy(detection)
    try:
        sources = _core._sources(payload)
        binding = _core._digest(payload)
        payload_error = None
    except (ValueError, TypeError):
        sources, binding, payload_error = {}, None, "invalid_payload"
    categories = detection.get("protected_categories")
    scope_ok = (isinstance(categories, list) and all(isinstance(c, str) and c in _core.CATEGORIES for c in categories))
    findings = detection.get("findings")
    if not isinstance(findings, list):
        findings = [None]
    annotations = []
    for finding in findings:
        fields = finding if isinstance(finding, dict) else {}
        source_id = fields.get("source_id") if isinstance(fields.get("source_id"), str) else None
        start = fields.get("start") if type(fields.get("start")) is int else None
        end = fields.get("end") if type(fields.get("end")) is int else None
        category = fields.get("category") if isinstance(fields.get("category"), str) and fields["category"] in _core.CATEGORIES else None
        error = payload_error
        if error is None and (not isinstance(finding, dict) or set(finding)-_FINDING_KEYS
                              or source_id is None or start is None or end is None or category is None):
            error = "invalid_finding"
        if error is None and not scope_ok:
            error = "policy_scope_unavailable"
        if error is None and category not in categories:
            error = "category_outside_policy"
        if error is None and not isinstance(detection.get("payload_sha256"), str):
            error = "payload_binding_unavailable"
        if error is None and detection["payload_sha256"] != binding:
            error = "payload_binding_mismatch"
        if error is None and source_id not in sources:
            error = "unknown_source"
        if error is None and not 0 <= start < end <= len(sources[source_id]):
            error = "invalid_location"
        values = _states("unchecked", "unchecked", "unchecked") if error else validate_value(sources[source_id][start:end], category)
        annotations.append({"source_id": source_id, "start": start, "end": end, "category": category,
                            "status": "validation_error" if error else "annotated", "validation_error": error, **values})
    result.update(validation_annotations=annotations, value_validation_version=VALIDATION_VERSION,
                  value_validation_scope=VALIDATION_SCOPE)
    return result


def detect_sensitive(payload, sensitivity_policy, *, mode="combined", agent=None):
    """Public validated-detection entry; inference and protection remain intact."""
    detected = _core.detect_sensitive(payload, sensitivity_policy, mode=mode, agent=agent)
    return annotate_detection(payload, detected)
