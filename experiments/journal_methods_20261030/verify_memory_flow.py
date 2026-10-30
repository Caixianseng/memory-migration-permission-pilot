"""Bounded, read-only diagnostics for exact memory propagation.

This module grants no rights. It checks existing host-produced artifacts against
explicit trusted bindings. HMAC/current authorization and detector completeness
remain separate checks. It does not infer dependencies from natural language or
implement the full decentralized label model (DLM).
"""
from __future__ import annotations

import hashlib
import json

from memory_migration_study.privacy import RestorationMap

VERSION = "journal_exact_memory_flow_checks_v1"
PAIR_SCOPE = "exact_user_agent_pairs_v1"


def _hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _digest(value):
    return _hash(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _result(errors, **details):
    return {"schema": VERSION, "status": "failed" if errors else "ok",
            "errors": sorted(set(errors)), **details}


def _pairs(values):
    if not isinstance(values, list):
        raise ValueError("invalid_exact_principals")
    result = set()
    for value in values:
        if (not isinstance(value, dict) or set(value) != {"user_id", "agent_id"}
                or any(not isinstance(item, str) or not item or item != item.strip()
                       for item in value.values())):
            raise ValueError("invalid_exact_principals")
        result.add((value["user_id"], value["agent_id"]))
    return result


def _span(start, end, length):
    return type(start) is int and type(end) is int and 0 <= start < end <= length


def verify_exact_record(record, *, expected_source=None, expected_policy_version=None,
                        expected_principals=None, expected_origin=None):
    """Check the actual ``memory_labels`` record shape without evaluating ACLs.

    ``expected_origin`` fixes one registered occurrence, so identical strings at
    different positions cannot substitute for each other. Signature verification
    is deliberately not reported as performed by this diagnostic.
    """
    errors = []
    try:
        source, access, label = record["source"], record["access"], record["label"]
        text, rid = record["text"], record["record_id"]
        source_text, source_id = source["text"], source["source_id"]
        start, end = record["source_start"], record["source_end"]
        if record.get("schema") != "local_labeled_memory_v1" or record.get("status") != "ok":
            errors.append("unsupported_record_schema_or_status")
        if not (isinstance(text, str) and isinstance(source_text, str)
                and isinstance(source_id, str) and source_id
                and isinstance(rid, str) and rid):
            return _result(["invalid_record_fields"])
        if not _span(start, end, len(source_text)) or source_text[start:end] != text:
            errors.append("exact_source_projection_mismatch")
        if source.get("sha256") != _hash(source_text):
            errors.append("source_hash_mismatch")
        if expected_source is not None and (expected_source.get("source_id") != source_id
                or expected_source.get("text") != source_text
                or ("version" in expected_source and source.get("version") != expected_source["version"])):
            errors.append("trusted_source_mismatch")
        if expected_origin is not None and expected_origin != {
                "source_id": source_id, "source_start": start, "source_end": end}:
            errors.append("trusted_source_occurrence_mismatch")
        if record.get("source_id") != rid or access.get("record_id") != rid or label.get("record_id") != rid:
            errors.append("record_identity_mismatch")
        expected_binding = {"source_sha256": _hash(source_text), "source_start": start,
                            "source_end": end, "content_sha256": _hash(text)}
        if access.get("source_id") != source_id or any(access.get(k) != v for k, v in expected_binding.items()):
            errors.append("access_content_binding_mismatch")
        if any(label.get(k) != v for k, v in expected_binding.items()) or label.get("access_sha256") != _digest(access):
            errors.append("privacy_label_binding_mismatch")
        if (label.get("version") != "local_memory_labels_v1" or label.get("status") != "ok"
                or label.get("epoch") != access.get("epoch")
                or access.get("scope_version") != "exact_fact_source_span_v1"):
            errors.append("unsupported_label_or_access_binding")
        scope = access.get("principal_scope")
        if ("readers" in access or "allowed_agent_ids" in access or not isinstance(scope, dict)
                or set(scope) != {"version", "principals"} or scope["version"] != PAIR_SCOPE):
            errors.append("exact_principal_contract_required")
        else:
            principals = _pairs(scope["principals"])
            if not principals:
                errors.append("empty_authorization_scope")
            if expected_principals is not None and principals != _pairs(expected_principals):
                errors.append("trusted_principal_scope_mismatch")
        if expected_policy_version is not None and label.get("policy_version") != expected_policy_version:
            errors.append("privacy_policy_version_mismatch")
        findings = label.get("findings")
        if not isinstance(findings, list):
            errors.append("invalid_privacy_findings")
        else:
            for finding in findings:
                if (not isinstance(finding, dict) or set(finding) != {"start", "end", "category"}
                        or not _span(finding.get("start"), finding.get("end"), len(text))
                        or not isinstance(finding.get("category"), str) or not finding["category"]):
                    errors.append("invalid_privacy_finding")
        return _result(errors, signature_verification="not_performed",
                       authorization_evaluation="not_performed",
                       privacy_completeness="not_established")
    except (KeyError, TypeError, ValueError, AttributeError):
        return _result([*errors, "invalid_record_fields"])


def verify_projection(source, output, segments, *, transform="exact_excerpt",
                      expected_segments=None):
    """Check a complete explicit character projection, not semantic summaries.

    Each segment has source_start/source_end/output_start/output_end. Output
    ranges must cover the output exactly once in order. Repeated original text
    still needs its exact registered source occurrence in expected_segments.
    """
    errors = []
    if transform not in {"exact_excerpt", "exact_copy"}:
        return _result(["unsupported_semantic_transformation"])
    try:
        text = source["text"]
        if (not isinstance(text, str) or not isinstance(output, str) or not output
                or not isinstance(segments, list) or not segments):
            return _result(["invalid_projection_fields"])
        if source.get("sha256", _hash(text)) != _hash(text):
            errors.append("source_hash_mismatch")
        cursor = 0
        for item in segments:
            if not isinstance(item, dict) or set(item) != {"source_start", "source_end", "output_start", "output_end"}:
                return _result([*errors, "invalid_projection_segment"])
            a, b, c, d = (item[k] for k in ("source_start", "source_end", "output_start", "output_end"))
            if (not _span(a, b, len(text)) or not _span(c, d, len(output)) or c != cursor
                    or text[a:b] != output[c:d]):
                errors.append("exact_source_projection_mismatch")
            cursor = d
        if cursor != len(output):
            errors.append("projection_output_not_fully_bound")
        if transform == "exact_copy" and (output != text or segments != [{
                "source_start": 0, "source_end": len(text), "output_start": 0, "output_end": len(text)}]):
            errors.append("copy_contract_mismatch")
        if expected_segments is not None and expected_segments != segments:
            errors.append("trusted_source_occurrence_mismatch")
    except (KeyError, TypeError, ValueError):
        errors.append("invalid_projection_fields")
    return _result(errors)


def verify_annotation_projection(source_findings, record):
    """Check preservation of declared source positives at their exact positions.

    Findings outside the chosen excerpt are counted without moving them to an
    equal string inside it. Additional target positives are allowed; completeness
    or semantic correctness of either list is not established by this check.
    """
    errors, projected, outside = [], 0, 0
    try:
        if verify_exact_record(record)["status"] != "ok" or not isinstance(source_findings, list):
            return _result(["invalid_projection_record_or_source_findings"])
        text = record["source"]["text"]
        start, end = record["source_start"], record["source_end"]
        target = {(item["start"], item["end"], item["category"]) for item in record["label"]["findings"]}
        for finding in source_findings:
            if (not isinstance(finding, dict) or not _span(finding.get("start"), finding.get("end"), len(text))
                    or not isinstance(finding.get("category"), str) or not finding["category"]
                    or ("quote" in finding and finding["quote"] != text[finding["start"]:finding["end"]])):
                return _result(["invalid_source_positive"])
            a, b = finding["start"], finding["end"]
            if a < end and start < b:
                if not start <= a < b <= end:
                    errors.append("source_positive_crosses_excerpt_boundary")
                elif (a-start, b-start, finding["category"]) not in target:
                    errors.append("source_positive_lost_in_projection")
                else:
                    projected += 1
            else:
                outside += 1
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append("invalid_annotation_projection_fields")
    return _result(errors, projected_positive_count=projected, outside_positive_count=outside,
                   privacy_completeness="not_established")


def verify_joint_readers(source_principals, output_principals):
    """Explicit common dependence permits only the intersection of exact pairs.

    This is a diagnostic premise supplied by the trusted caller. It does not
    infer common dependence or independent alternative proofs from equal text.
    """
    try:
        if not isinstance(source_principals, list) or not source_principals:
            raise ValueError("missing_explicit_dependencies")
        scopes = [_pairs(scope) for scope in source_principals]
        permitted = set.intersection(*scopes)
        output = _pairs(output_principals)
        return _result(["joint_dependency_reader_widening"] if not output <= permitted else [],
                       input_sources=len(scopes), permitted_pair_count=len(permitted),
                       output_pair_count=len(output), lost_pair_count=len(permitted - output))
    except (ValueError, TypeError):
        return _result(["invalid_explicit_dependency_scope"])


def verify_handoff(packet, records, *, expected_audience, expected_policy_version,
                   expected_operation="handoff", now=None):
    """Cross-check native_agent_protocol items with exact labeled records.

    Caller must separately run broker.validate for HMAC/current ACL/TTL and the
    current authority for read/restore. This checker is neither of those gates.
    """
    errors = []
    try:
        if expected_operation != "handoff":
            errors.append("operation_contract_mismatch")
        if packet.get("schema") != "agent_memory_handoff_v1":
            errors.append("unsupported_handoff_schema")
        if packet.get("audience") != expected_audience:
            errors.append("handoff_audience_mismatch")
        if not isinstance(records, list) or not records:
            return _result([*errors, "invalid_handoff_records"])
        by_id = {record["record_id"]: record for record in records}
        if len(by_id) != len(records):
            errors.append("duplicate_record_identity")
        items = packet["items"]
        if not isinstance(items, list) or not items:
            return _result([*errors, "invalid_handoff_items"])
        seen = set()
        for item in items:
            rid = item["record_id"]
            if rid not in by_id or rid in seen:
                errors.append("handoff_record_identity_mismatch")
                continue
            seen.add(rid)
            record = by_id[rid]
            if verify_exact_record(record)["status"] != "ok":
                errors.append("handoff_source_record_invalid")
            origin = {"source_id": record["source"]["source_id"],
                      "source_sha256": _hash(record["source"]["text"]),
                      "source_start": record["source_start"], "source_end": record["source_end"]}
            if item.get("origin") != origin:
                errors.append("handoff_origin_mismatch")
            if item.get("text") != record["text"] or item.get("content_sha256") != _hash(record["text"]):
                errors.append("handoff_content_mismatch")
            grant = item.get("grant_ref", {})
            if grant.get("record_id") != rid or grant.get("policy_version") != expected_policy_version:
                errors.append("handoff_policy_version_mismatch")
        if seen != set(by_id):
            errors.append("handoff_record_set_mismatch")
        if now is not None and (type(now) is not int or type(packet.get("issued_at")) is not int
                or type(packet.get("expires_at")) is not int or not packet["issued_at"] <= now < packet["expires_at"]):
            errors.append("handoff_lifetime_mismatch")
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append("invalid_handoff_fields")
    return _result(errors, signature_verification="not_performed", current_authorization="not_performed")


def verify_pseudonymized_view(original, prepared, *, recipient, disclosure_policy):
    """Check explicit fixed-view permission plus the existing in-memory map.

    Recipient is a distinct trusted identifier (client/model service/etc.). This
    permission must be issued by the controller; an empty sensitivity label or
    successful masking never supplies it. No map, original, or token is returned.
    """
    errors = []
    try:
        if (not isinstance(disclosure_policy, dict) or not isinstance(recipient, str) or not recipient
                or not isinstance(disclosure_policy.get("allowed_recipients"), list)
                or not isinstance(disclosure_policy.get("allowed_transformations"), list)
                or not isinstance(disclosure_policy.get("allowed_source_ids"), list)):
            return _result(["missing_explicit_view_permission"])
        if recipient not in disclosure_policy["allowed_recipients"]:
            errors.append("view_recipient_not_authorized")
        if "fixed_pseudonymization" not in disclosure_policy["allowed_transformations"]:
            errors.append("view_transformation_not_authorized")
        if prepared.get("status") != "ok" or not isinstance(prepared.get("mapping"), RestorationMap):
            return _result([*errors, "view_not_prepared"])
        mapping, payload = prepared["mapping"], prepared["payload"]
        if mapping._policy_version != disclosure_policy.get("policy_version"):
            errors.append("view_policy_version_mismatch")
        if _digest(original) != mapping._source_payload_sha256:
            errors.append("view_source_payload_mismatch")
        if _digest(payload) != prepared.get("metadata", {}).get("payload_sha256"):
            errors.append("view_payload_hash_mismatch")
        original_memories = {item["source_id"]: item["text"] for item in original["memories"]}
        if original_memories != mapping._memories:
            errors.append("view_mapping_source_mismatch")
        if not set(original_memories) <= set(disclosure_policy["allowed_source_ids"]):
            errors.append("view_source_not_authorized")
        if len(payload["memories"]) != len(original_memories):
            errors.append("view_memory_count_mismatch")
        if any(set(entry.sources) - set(original_memories) for entry in mapping._entries.values()):
            errors.append("view_mapping_has_unknown_source")
        # Reconstruct the view independently from the original intervals. This
        # detects payload alteration even if someone recomputes its public hash.
        # Query positions are not held in _sensitive_spans. Exact token/string
        # validation for queries remains in privacy_egress; no completeness claim.
        for index, (sid, text) in enumerate(original_memories.items(), 1):
            cursor, parts = 0, []
            for start, end in mapping._sensitive_spans.get(sid, ()):
                if not _span(start, end, len(text)) or start < cursor:
                    errors.append("view_mapping_span_invalid")
                    break
                candidates = [token for token, entry in mapping._entries.items()
                              if sid in entry.sources and entry.value.casefold() == text[start:end].casefold()]
                if len(candidates) != 1:
                    errors.append("view_mapping_token_invalid")
                    break
                parts.extend((text[cursor:start], candidates[0]))
                cursor = end
            parts.append(text[cursor:])
            actual = payload["memories"][index - 1]
            if actual != {"source_id": f"m_{mapping._nonce}_{index}", "text": "".join(parts)}:
                errors.append("view_memory_projection_mismatch")
        if any(key in payload for key in {"mapping", "restoration_mapping", "original_values"}):
            errors.append("restoration_mapping_exposed_in_view")
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append("invalid_view_fields")
    return _result(errors, mapping_persisted=False, privacy_completeness="not_established",
                   query_egress="separate_existing_gate_required")
