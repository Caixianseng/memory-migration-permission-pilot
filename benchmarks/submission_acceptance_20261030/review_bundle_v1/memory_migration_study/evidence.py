"""Raw-response, operation-specific differential evidence with conservative unknowns."""
from __future__ import annotations

import hashlib
import json
from collections import Counter

from .backend import strings
from .policy import decision, validate_case

OPERATIONS = ("read", "list")


def _parsed(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def _has_content(observation, text):
    raw = observation.get("raw_body", "")
    bodies = [raw]
    if isinstance(observation.get("native_raw_body"), str):
        bodies.append(observation["native_raw_body"])
    return observation.get("response_checked") is True and any(
        text in body or any(text in value for value in strings(_parsed(body))) for body in bodies)


def _items(observation):
    value = _parsed(observation.get("raw_body", ""))
    if not isinstance(value, dict):
        return []
    if isinstance(value.get("item"), dict):
        return [value["item"]]
    return [i for i in value.get("items", []) if isinstance(i, dict)] if isinstance(value.get("items"), list) else []


def _qualified_native_empty_read(observation, target_id, backend_kind):
    """An explicit native ID-filter contract; generic HTTP 200 empties stay unknown."""
    raw = observation.get("native_raw_body")
    normalized = _parsed(observation.get("raw_body", ""))
    return (backend_kind == "native"
            and observation.get("empty_read_contract") == "open_webui_0.12.3_memory_id_filter_empty_v1"
            and observation.get("native_package_version") == "0.12.3"
            and observation.get("native_method") == "POST"
            and observation.get("native_path") == "/api/v1/memories/search"
            and observation.get("native_request_json") == {"memory_id": target_id, "type": "all", "limit": 1}
            and isinstance(raw, str) and _parsed(raw) == []
            and hashlib.sha256(raw.encode("utf-8")).hexdigest() == observation.get("native_body_sha256")
            and isinstance(normalized, dict) and normalized.get("items") == []
            and normalized.get("native_response") == [] and normalized.get("native_raw_body") == raw)


def _native_normalization_errors(bundle, reverse):
    """Recheck the declared WebUI normalization from saved raw strings only."""
    if bundle.get("evidence_contract") != "open_webui_0.12.3_native_memory_v1":
        return []
    control_ids = {spec["target_id"] for control in bundle.get("actor_controls", {}).values()
                   if isinstance((spec := control.get("positive_control")), dict) and isinstance(spec.get("target_id"), str)}
    errors = []
    for index, observation in enumerate(bundle.get("observations", [])):
        raw = observation.get("native_raw_body")
        normalized = _parsed(observation.get("raw_body", ""))
        reason = None
        if (not isinstance(raw, str) or hashlib.sha256(raw.encode("utf-8")).hexdigest() != observation.get("native_body_sha256")
                or observation.get("native_package_version") != "0.12.3"):
            reason = "native_raw_hash_or_version_mismatch"
        else:
            try:
                native = json.loads(raw)
            except (ValueError, TypeError):
                native = None
            if (not isinstance(normalized, dict) or normalized.get("native_response") != native
                    or normalized.get("native_raw_body") != raw):
                reason = "native_raw_normalization_copy_mismatch"
            else:
                expected_items, malformed = [], False
                if isinstance(native, list):
                    for row in native:
                        if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                                or not isinstance(row.get("content"), str) or not isinstance(row.get("user_id"), str)):
                            malformed = True
                            continue
                        source_id = "__positive_control__" if row["id"] in control_ids else reverse.get(row["id"], "__unregistered__")
                        expected_items.append({"target_id": row["id"], "source_id": source_id, "text": row["content"]})
                else:
                    malformed = observation.get("status") == 200
                if normalized.get("items") != expected_items:
                    reason = "native_items_not_derived_from_raw_rows"
                elif observation.get("operation") == "list":
                    expected_complete = observation.get("status") == 200 and isinstance(native, list) and not malformed
                    if (observation.get("native_method") != "GET" or observation.get("native_path") != "/api/v1/memories/"
                            or normalized.get("complete") is not expected_complete or normalized.get("next_offset") is not None):
                        reason = "native_list_contract_mismatch"
                elif (observation.get("native_method") != "POST"
                      or observation.get("native_path") != "/api/v1/memories/search"
                      or observation.get("native_request_json") != {"memory_id": observation.get("target_id"), "type": "all", "limit": 1}
                      or (isinstance(native, list) and (len(native) > 1 or any(item["target_id"] != observation.get("target_id") for item in expected_items)))):
                    reason = "native_id_filtered_read_contract_mismatch"
                if malformed and reason is None:
                    reason = "native_success_response_malformed"
        if reason:
            errors.append({"observation": index, "reason": reason})
    return errors


def _pages_complete(pages):
    """Check raw pagination evidence again when an evidence bundle is reloaded."""
    if not pages or [o.get("page") for o in pages] != list(range(len(pages))):
        return False
    previous_offset = 0
    for index, observation in enumerate(pages):
        value = _parsed(observation.get("raw_body", ""))
        if not isinstance(value, dict) or not isinstance(value.get("items"), list):
            return False
        if index == len(pages) - 1:
            return value.get("complete") is True and value.get("next_offset") is None
        offset = value.get("next_offset")
        if value.get("complete") is not False or type(offset) is not int or offset <= previous_offset:
            return False
        previous_offset = offset
    return False


def probe(case: dict, plan: dict, adapter) -> dict:
    """Probe every registered copy and all list pages, without logging credentials."""
    observations, actor_controls = [], {}
    for actor in case["actors"]:
        actor_id = actor["actor_id"]
        identity_valid, identity_response = adapter.identity(actor_id)
        control_spec = adapter.controls.get(actor_id, {})
        control_id = control_spec.get("target_id") if isinstance(control_spec, dict) else None
        control_hash = control_spec.get("text_sha256") if isinstance(control_spec, dict) else None
        def valid_control(item):
            text = item.get("text")
            return item.get("target_id") == control_id and isinstance(text, str) and bool(control_hash) and hashlib.sha256(text.encode()).hexdigest() == control_hash
        control_response = adapter.read(actor_id, control_id) if control_id else None
        positive_read = bool(control_response and control_response["status"] == 200 and
                             any(valid_control(item) for item in _items(control_response)))
        pages, complete = adapter.list_pages(actor_id)
        positive_list = complete and any(valid_control(item) for page in pages for item in _items(page))
        actor_controls[actor_id] = {"identity_valid": identity_valid, "identity_response": identity_response,
                                    "positive_control": control_spec,
                                    "positive_read": positive_read, "positive_list": positive_list,
                                    "list_complete": complete}
        if control_response:
            observations.append(dict(control_response, actor_id=actor_id, operation="read", endpoint="read_control", target_id=control_id))
        for source_id, targets in plan.get("object_mapping", {}).items():
            for target_id in targets:
                observations.append(dict(adapter.read(actor_id, target_id), actor_id=actor_id, operation="read",
                                         endpoint="read", target_id=target_id, requested_source_id=source_id))
        for index, page in enumerate(pages):
            observations.append(dict(page, actor_id=actor_id, operation="list", endpoint="list", target_id=None, page=index))
    bundle = {"schema_version": 1, "case": case, "plan": plan, "observations": observations,
            "actor_controls": actor_controls, "negative_contract": adapter.negative_contract,
            "backend_kind": adapter.backend_kind, "origin": "actual_http_responses",
            "scope": "declared_finite_actors_objects_read_list", "native_status": "not_run" if adapter.backend_kind == "reference_backend" else "configured_contract_probed"}
    if getattr(adapter, "evidence_contract", None):
        bundle["evidence_contract"] = adapter.evidence_contract
    return bundle


def _mapping_errors(case, plan):
    mapping = plan.get("object_mapping")
    expected = {r["source_id"] for r in case["records"]}
    errors = []
    if not isinstance(mapping, dict) or set(mapping) != expected:
        return ["incomplete_source_object_mapping"]
    copies = []
    for values in mapping.values():
        if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
            errors.append("malformed_copy_mapping")
        else:
            copies.extend(values)
    if len(copies) != len(set(copies)):
        errors.append("target_id_collision")
    if plan.get("mapping_complete") is not True:
        errors.append("mapping_not_complete")
    if plan.get("inventory_complete") is not True:
        errors.append("inventory_not_complete")
    return errors


def evaluate(bundle: dict) -> dict:
    case, plan = bundle["case"], bundle["plan"]
    validate_case(case)
    observations, controls = bundle.get("observations", []), bundle.get("actor_controls", {})
    if not isinstance(observations, list) or not isinstance(controls, dict):
        raise ValueError("observations and actor_controls have invalid shape")
    # Only allow evidence fields; authorization headers and tokens are never part of this schema.
    forbidden = {"authorization", "credential", "credentials", "api_key", "token"}
    def check_keys(value):
        if isinstance(value, dict):
            if any(str(key).lower() in forbidden for key in value):
                raise ValueError("credential-bearing evidence is not accepted")
            for item in value.values():
                check_keys(item)
        elif isinstance(value, list):
            for item in value:
                check_keys(item)
    check_keys(bundle)
    structural = _mapping_errors(case, plan)
    native_fields = {"native_raw_body", "native_body_sha256", "native_package_version", "native_path"}
    if (any(native_fields.intersection(observation) for observation in observations)
            and bundle.get("evidence_contract") != "open_webui_0.12.3_native_memory_v1"):
        structural.append("native_observation_contract_missing_or_mismatched")
    duplicate_texts = {r["text"] for r in case["records"] if sum(other["text"] == r["text"] for other in case["records"]) > 1}
    if duplicate_texts:
        structural.append("identical_registered_contents_require_attribution_review")
    actor_ids = {a["actor_id"] for a in case["actors"]}
    if any(o.get("actor_id") not in actor_ids or o.get("operation") not in OPERATIONS for o in observations):
        structural.append("unknown_observation_actor_or_operation")
    integrity, metadata = [], []
    record_by_id = {r["source_id"]: r for r in case["records"]}
    reverse = {t: s for s, values in plan.get("object_mapping", {}).items() if isinstance(values, list) for t in values}
    integrity.extend(_native_normalization_errors(bundle, reverse))
    for index, obs in enumerate(observations):
        for item in _items(obs):
            target_id = item.get("target_id")
            if item.get("source_id") == "__positive_control__":
                continue
            source_id = reverse.get(target_id)
            if source_id is None:
                integrity.append({"observation": index, "reason": "unregistered_copy", "target_id": target_id})
            elif item.get("source_id") != source_id or item.get("text") != record_by_id[source_id]["text"]:
                integrity.append({"observation": index, "reason": "content_or_source_mismatch", "target_id": target_id, "expected_source_id": source_id})
        values = set(strings(_parsed(obs.get("raw_body", ""))))
        for record in case["records"]:
            source_id = record["source_id"]
            identifiers = {source_id, *plan.get("object_mapping", {}).get(source_id, [])}
            if identifiers.intersection(values) and not _has_content(obs, record["text"]):
                metadata.append({"observation": index, "actor_id": obs.get("actor_id"), "source_id": source_id, "operation": obs.get("operation")})
    relationships, reachability = [], []
    for actor in case["actors"]:
        aid = actor["actor_id"]
        control = controls.get(aid, {})
        identity_valid = control.get("identity_valid") is True
        raw_identity = control.get("identity_response", {})
        actual_identity = _parsed(raw_identity.get("raw_body", ""))
        expected_identity = dict(actor, actor_id=case["actor_mapping"][aid])
        identity_valid = identity_valid and raw_identity.get("status") == 200 and isinstance(actual_identity, dict) and all(actual_identity.get(key) == expected_identity[key] for key in ("actor_id", "user_id", "agent_id"))
        for record in case["records"]:
            sid = record["source_id"]
            targets = plan.get("object_mapping", {}).get(sid, [])
            common = decision(record, aid)
            content_any = False
            for operation in OPERATIONS:
                relevant = [o for o in observations if o.get("actor_id") == aid and o.get("operation") == operation]
                # Attribute returned content by the complete registered content, not the requested ID.
                witnesses = [i for i, o in enumerate(observations) if o.get("actor_id") == aid and o.get("operation") == operation and _has_content(o, record["text"])]
                content = bool(witnesses)
                content_any |= content
                valid = lambda o: (o.get("response_checked") is True and not o.get("execution_error") and o.get("status") in {200, 403, 404})
                complete = not structural and identity_valid and bundle.get("negative_contract") is True
                if operation == "read":
                    complete = complete and control.get("positive_read") is True
                    for target in targets:
                        target_obs = [o for o in relevant if o.get("endpoint") == "read" and o.get("target_id") == target]
                        complete = complete and len(target_obs) == 1 and all(valid(o) for o in target_obs)
                        if target_obs and target_obs[0].get("status") == 200:
                            complete = complete and (any(item.get("target_id") == target and isinstance(item.get("text"), str) for item in _items(target_obs[0]))
                                                     or _qualified_native_empty_read(target_obs[0], target, bundle.get("backend_kind")))
                    # No copies is a known omission only with a complete registered inventory.
                else:
                    pages = [o for o in relevant if o.get("endpoint") == "list"]
                    complete = complete and control.get("positive_list") is True and control.get("list_complete") is True and _pages_complete(pages) and all(valid(o) and o.get("status") == 200 for o in pages)
                if integrity:
                    complete = False
                attribution_ambiguous = record["text"] in duplicate_texts and any(other["text"] == record["text"] and decision(other, aid) != "deny" for other in case["records"])
                state = "known_w_plus" if common == "deny" and content and not attribution_ambiguous else "unknown" if common == "unknown" or not complete else "known_w_minus" if common == "allow" and not content else "preserved"
                relationships.append({"case_id": case["case_id"], "actor_id": aid, "source_id": sid,
                                      "operation": operation, "reference": common, "content_observed": content,
                                      "probe_complete": bool(complete), "state": state, "witness_observations": witnesses})
            reachability.append({"actor_id": aid, "source_id": sid, "any_read_or_list_content": content_any,
                                 "diagnostic_only": True})
    counts = Counter(r["state"] for r in relationships)
    credential_failures = sum(c.get("identity_valid") is not True for c in controls.values()) + len(actor_ids - set(controls)) + sum(o.get("status") == 401 for o in observations)
    execution_errors = sum(bool(o.get("execution_error")) or o.get("status") not in {200, 401, 403, 404} for o in observations)
    complete_count = sum(r["probe_complete"] and r["reference"] != "unknown" for r in relationships)
    complete = complete_count == len(relationships) and not structural and not integrity and not credential_failures and not execution_errors
    wp, wm = counts["known_w_plus"], counts["known_w_minus"]
    allows = sum(r["reference"] == "allow" for r in relationships)
    safe = False if wp else True if complete else None
    return {"schema_version": 1, "case_id": case["case_id"], "method": plan.get("method"),
            "backend_kind": bundle.get("backend_kind", "unknown"), "native_status": bundle.get("native_status", "unknown"),
            "known_w_plus": wp, "known_w_minus": wm, "unknown_count": counts["unknown"],
            "declared_relationships": len(relationships), "observed_relationships": sum(r["probe_complete"] or r["content_observed"] for r in relationships),
            "content_integrity_errors": len(integrity), "metadata_disclosures": len(metadata),
            "credential_failures": credential_failures, "execution_errors": execution_errors,
            "coverage": {"complete": complete, "qualified_relationships": complete_count, "declared_relationships": len(relationships),
                         "ratio": complete_count / len(relationships) if relationships else None},
            "finite_scope_safe": safe, "legal_access_retention": (allows - wm) / allows if complete and allows else None,
            "known_w_plus_rate": wp / len(relationships) if complete and relationships else None,
            "known_w_minus_rate": wm / allows if complete and allows else None,
            "relationships": relationships, "logical_content_reachability": reachability,
            "integrity_details": integrity, "metadata_details": metadata, "structural_errors": structural,
            "content_detection": "exact_registered_text_only", "semantic_or_paraphrase_disclosure": None,
            "claim": "在该声明有限域未发现W+" if safe is True else "发现有限域W+反例" if safe is False else "证据不完整，不能判安全通过"}
