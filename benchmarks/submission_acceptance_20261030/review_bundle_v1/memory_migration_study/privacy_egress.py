"""Local egress checks for known values and payload integrity, not a privacy proof."""
from __future__ import annotations

import re

from .privacy import RestorationMap, _digest, _policy, _sources, _propagation_occurrences

TOKEN = re.compile(r"\[PVT_[A-F0-9]{24}_[A-Z]+_\d+\]")
OPAQUE_SOURCE = re.compile(r"m_[A-F0-9]{24}_\d+")


def validate_outbound(source_payload, prepared, detection, sensitivity_policy):
    """Check current policy, exact payload, token provenance and known raw values.

    Only independently supplied business registry entries and already detected
    spans are checked. Unregistered semantic misses can still escape this check.
    No evaluation labels, expected answers or scoring audit are accepted here.
    """
    def block(code):
        return {"status": "blocked", "code": code, "scope": "known_values_and_payload_integrity_only"}

    try:
        original = _sources(source_payload)
        policy = _policy(sensitivity_policy)
        if detection.get("status") != "ok" or prepared.get("status") != "ok":
            return block("preparation_not_ready")
        if detection.get("payload_sha256") != _digest(source_payload):
            return block("source_payload_changed")
        if detection.get("policy_sha256") != _digest(policy):
            return block("sensitivity_policy_changed")
        payload = prepared["payload"]
        _sources(payload)
        if prepared.get("metadata", {}).get("payload_sha256") != _digest(payload):
            return block("outbound_payload_changed")
        mapping = prepared.get("mapping")
        if not isinstance(mapping, RestorationMap):
            return block("invalid_mapping")
        if (mapping._policy_sha256 != detection["policy_sha256"]
                or prepared.get("metadata", {}).get("policy_sha256") != detection["policy_sha256"]):
            return block("mapping_policy_mismatch")
        if mapping._source_payload_sha256 != _digest(source_payload):
            return block("mapping_source_mismatch")
        if mapping._memories != {m["source_id"]: m["text"] for m in source_payload["memories"]}:
            return block("mapping_source_mismatch")
        if len(payload["memories"]) != len(source_payload["memories"]):
            return block("outbound_memory_count_changed")
        for index, memory in enumerate(payload["memories"], 1):
            if (not OPAQUE_SOURCE.fullmatch(memory["source_id"])
                    or memory["source_id"] != f"m_{mapping._nonce}_{index}"):
                return block("original_source_identifier_present")
        values = []
        for finding in detection["findings"]:
            sid, start, end = finding["source_id"], finding["start"], finding["end"]
            if sid not in original or type(start) is not int or type(end) is not int or not 0 <= start < end <= len(original[sid]):
                return block("invalid_detection_span")
            values.append((original[sid][start:end], finding["category"]))
        values.extend((item["value"], item["category"]) for item in policy.get("entity_registry", [])
                      if item["category"] in policy["protected_categories"])
        texts = [payload["query"], *(memory["text"] for memory in payload["memories"])]
        for text in texts:
            tokens = TOKEN.findall(text)
            if any(token not in mapping._entries for token in tokens):
                return block("unregistered_outbound_token")
            for match in TOKEN.finditer(text):
                if set(mapping._entries[match.group()].categories) & {"PROJECT", "CUSTOMER", "PERSON", "ADDRESS"}:
                    adjacent = text[max(0, match.start() - 1):match.start()] + text[match.end():match.end() + 1]
                    if re.search(r"[A-Za-z0-9_]", adjacent):
                        # A short known name masked inside a longer unrecognized
                        # name leaves an inferable suffix/prefix. Do not call it safe.
                        return block("ambiguous_entity_boundary")
            plaintext = TOKEN.sub("", text)
            if "[PVT_" in plaintext.upper():
                return block("malformed_outbound_token")
            if any(next(_propagation_occurrences(plaintext, value, category), None) is not None
                   for value, category in values):
                return block("known_sensitive_value_remains")
    except (TypeError, ValueError, KeyError, AttributeError):
        return block("invalid_egress_material")
    return {"status": "ok", "code": None, "scope": "known_values_and_payload_integrity_only",
            "payload_sha256": _digest(payload), "policy_sha256": _digest(policy)}
