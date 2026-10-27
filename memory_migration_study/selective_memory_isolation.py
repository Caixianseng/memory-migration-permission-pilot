"""Optional whole-record isolation with new preparation, never an ACL bypass.

Default=request. A trusted dependency partition is a host declaration of
cross-source independence, not something inferred from detector output or a
cryptographic proof. Without it all sources (including query) form one group.
This module neither loads models nor logs. Returned mapping is process-local;
only ``isolation`` is diagnostic metadata, containing IDs/hashes, never text.
"""
from copy import deepcopy
import hashlib
import math

from . import privacy
from .privacy_egress import validate_outbound

VERSION = "selective_whole_memory_isolation_v1"
DEPENDENCY_VERSION = "trusted_source_dependency_partition_v1"
STRATEGIES = frozenset({"request", "record", "sentence", "position"})
_RELATION_CODES = frozenset({"candidate_budget_exceeded", "input_budget_exceeded",
    "gliner_full_token_budget_exceeded", "semantic_uncertainty"})
_AUTHORITY_KEYS = frozenset({"authority", "authorization", "authorized", "permissions", "permission",
    "readers", "owner", "owner_id", "actor_id", "agent_id", "grants", "grant", "allow", "acl"})


class _IsolationError(ValueError):
    """Only these fixed internal codes may appear in diagnostics."""


def _require(condition, code):
    if not condition:
        raise _IsolationError(code)


def _text_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _partition(payload, policy, groups):
    sources = privacy._sources(payload)
    _require(isinstance(groups, list) and bool(groups), "invalid_dependency_groups")
    flattened = []
    for group in groups:
        _require(isinstance(group, list) and bool(group)
                 and all(isinstance(sid, str) and sid in sources for sid in group), "invalid_dependency_groups")
        flattened.extend(group)
    _require(len(flattened) == len(set(flattened)) and set(flattened) == set(sources),
             "dependency_partition_must_cover_all_sources_once")
    order = {sid: index for index, sid in enumerate(sources)}
    return sorted((sorted(group, key=order.__getitem__) for group in groups), key=lambda g: order[g[0]])


def bind_dependency_groups(payload, policy, groups):
    """Bind a trusted caller's explicit complete partition; grants no authority."""
    payload, normalized = deepcopy(payload), privacy._policy(policy)
    checked = _partition(payload, normalized, groups)
    return {"version": DEPENDENCY_VERSION, "payload_sha256": privacy._digest(payload),
            "policy_sha256": privacy._digest(normalized), "groups": checked,
            "independent_groups": True}


def _single_payload(source_id, text):
    return {"query": text if source_id == privacy.QUERY_SOURCE else "",
            "memories": [] if source_id == privacy.QUERY_SOURCE else [{"source_id": source_id, "text": text}]}


def _response_valid(response, source_id, text, policy, source_payload, call_limit):
    """Check even review findings; ordinary detect skips their span validation."""
    _require(isinstance(response, dict) and not _AUTHORITY_KEYS.intersection(response), "invalid_agent_schema")
    _require(response.get("status") in {"ok", "needs_review"} and isinstance(response.get("findings"), list)
             and isinstance(response.get("errors"), list)
             and all(isinstance(code, str) and code in privacy._AGENT_ERROR_CODES for code in response["errors"]),
             "invalid_agent_schema")
    _require(type(response.get("local_calls")) is int and 0 <= response["local_calls"] <= call_limit
             and response.get("local_calls_complete", True) is True, "invalid_agent_accounting")
    elapsed = response.get("elapsed_seconds")
    _require(type(elapsed) in (float, int) and math.isfinite(elapsed) and elapsed >= 0,
             "invalid_agent_accounting")
    bindings = {"source_id": source_id, "source_id_sha256": _text_hash(source_id),
                "text_sha256": _text_hash(text), "policy_sha256": privacy._digest(policy),
                "payload_sha256": privacy._digest(source_payload)}
    for key, value in bindings.items():
        _require(key not in response or response[key] == value, "agent_source_binding_mismatch")
    relations = response.get("relation_errors", [])
    _require(isinstance(relations, list) and all(isinstance(c, str) and c in _RELATION_CODES for c in relations),
             "invalid_agent_relation_errors")
    _require(response["status"] != "ok" or (response["errors"] == [] and relations == []),
             "inconsistent_agent_status")
    for finding in response["findings"]:
        _require(isinstance(finding, dict) and not _AUTHORITY_KEYS.intersection(finding)
                 and finding.get("category") in policy["protected_categories"]
                 and isinstance(finding.get("quote"), str) and bool(finding["quote"]), "invalid_agent_finding")
        _require("source_id" not in finding or finding["source_id"] == source_id,
                 "agent_source_binding_mismatch")
        locations = list(privacy._occurrences(text, finding["quote"]))
        if "start" in finding or "end" in finding:
            point = (finding.get("start"), finding.get("end"))
            _require(all(type(value) is int for value in point) and point in locations, "invalid_agent_span")
        else:
            _require(len(locations) == 1, "ambiguous_agent_span")
    return True


def prepare_selective_private_payload(payload, policy, agent, *, actor_id, request_id,
                                      authorizer, strategy="request", dependency_groups=None,
                                      max_local_calls=64):
    """Detect each original source once; isolate only explicit local uncertainty.

    Semantic uncertainty and source-bound input coverage limits may quarantine a
    memory/group under record strategy. Schema, binding, transport, authorization
    and total-budget failures block the request. Sentence/position require a
    missing boundary contract and explicitly fall back to record, never slicing.
    """
    detail = {"version": VERSION, "requested_strategy": strategy if isinstance(strategy, str) else None,
              "effective_strategy": "request", "strategy_supported": strategy in {"request", "record"} if isinstance(strategy, str) else False,
              "fallback_reason": None, "original_payload_sha256": None, "filtered_payload_sha256": None,
              "policy_sha256": None, "dependency_binding_sha256": None, "dependency_mode": "all_sources_dependent",
              "kept_source_ids": [], "quarantined_source_ids": [], "source_outcomes": [],
              "local_calls": 0, "local_calls_complete": True, "agent_invocations": 0,
              "cache_replay_invocations": 0, "egress": None}

    def block(code):
        return {"status": "needs_review", "payload": None, "mapping": None, "error": code,
                "metadata": {}, "isolation": deepcopy(detail)}

    try:
        _require(isinstance(strategy, str) and strategy in STRATEGIES, "invalid_isolation_strategy")
        _require(type(max_local_calls) is int and 0 <= max_local_calls <= 256, "invalid_total_call_budget")
        _require(isinstance(actor_id, str) and bool(actor_id) and isinstance(request_id, str) and bool(request_id)
                 and callable(authorizer), "invalid_request_scope")
        source_payload = deepcopy(payload)
        normalized = privacy._policy(deepcopy(policy))
        sources = privacy._sources(source_payload)
        _require(1 <= len(source_payload["memories"]) <= 64, "invalid_memory_count")
        detail.update(original_payload_sha256=privacy._digest(source_payload), policy_sha256=privacy._digest(normalized))
        detail["effective_strategy"] = "request" if strategy == "request" else "record"
        if strategy in {"sentence", "position"}:
            detail["fallback_reason"] = "unsupported_complete_boundary_contract"
        if dependency_groups is None:
            groups = [list(sources)]
        else:
            _require(isinstance(dependency_groups, dict) and set(dependency_groups) == {
                "version", "payload_sha256", "policy_sha256", "groups", "independent_groups"}, "invalid_dependency_binding")
            groups = _partition(source_payload, normalized, dependency_groups["groups"])
            expected = bind_dependency_groups(source_payload, normalized, groups)
            _require(dependency_groups == expected, "dependency_binding_mismatch")
            detail.update(dependency_mode="trusted_partition", dependency_binding_sha256=privacy._digest(expected))
        # Authorization covers ALL original memories before any detection call.
        _require(all(privacy._authorized(authorizer, item["source_id"], actor_id, normalized["version"])
                     for item in source_payload["memories"]), "memory_authorization_failed")
        _require(all(len(text) <= normalized["max_text_chars"] for text in sources.values()),
                 "source_character_budget_exceeded")
        _require(not any(privacy._RESERVED.search(text) for text in sources.values()), "reserved_token_in_input")
        needed = sum(bool(text.strip()) and bool(normalized["protected_categories"]) for text in sources.values())
        call_limit = getattr(agent, "max_local_calls", 2) if needed else 1
        _require(not needed or callable(agent), "local_agent_required")
        _require(type(call_limit) is int and 1 <= call_limit <= 4, "invalid_local_agent_call_contract")
        _require(needed * call_limit <= max_local_calls, "total_call_budget_exceeded")
    except Exception as exc:
        return block(str(exc) if isinstance(exc, _IsolationError) else "invalid_input_or_policy")

    cache, quarantinable = {}, set()
    for sid, text in sources.items():
        single = _single_payload(sid, text)
        captured = []

        class BoundAgent:
            max_local_calls = call_limit

            def __call__(self, **kwargs):
                _require(kwargs == {"text": text, "source_id": sid, "policy": normalized, "rule_findings": []},
                         "agent_input_binding_mismatch")
                detail["agent_invocations"] += 1
                response = agent(**deepcopy(kwargs))
                captured.append(deepcopy(response))
                return response

        detected = privacy.detect_sensitive(single, normalized, agent=BoundAgent(), mode="combined")
        detail["local_calls"] += detected["local_calls"]
        detail["local_calls_complete"] &= detected["local_calls_complete"]
        record = {"source_id": sid, "source_id_sha256": _text_hash(sid), "text_sha256": _text_hash(text),
                  "policy_sha256": detail["policy_sha256"], "status": detected["status"],
                  "errors": deepcopy(detected["errors"]), "relation_errors": [],
                  "local_calls": detected["local_calls"], "local_calls_complete": detected["local_calls_complete"],
                  "failure_kind": "none"}
        detail["source_outcomes"].append(record)
        try:
            _require(detail["local_calls"] <= max_local_calls, "total_call_budget_exceeded")
            _require(detected["payload_sha256"] == privacy._digest(single)
                     and detected["policy_sha256"] == detail["policy_sha256"]
                     and detected["local_calls_complete"] is True, "source_detection_binding_or_accounting_failed")
            requires_agent = bool(text.strip()) and bool(normalized["protected_categories"])
            _require(len(captured) == int(requires_agent), "source_agent_capture_mismatch")
            if requires_agent:
                raw = captured[0]
                if isinstance(raw, dict) and raw.get("local_calls_complete", True) is not True:
                    detail["local_calls_complete"] = record["local_calls_complete"] = False
                _response_valid(raw, sid, text, normalized, single, call_limit)
                record["relation_errors"] = deepcopy(raw.get("relation_errors", []))
                if raw["status"] == "needs_review" and raw["errors"] in (["semantic_uncertainty"], ["input_budget_exceeded"]):
                    expected_errors = sorted({"local_agent_needs_review", *raw["errors"]})
                    _require(detected["errors"] == expected_errors, "mixed_source_failure")
                    record["failure_kind"] = "semantic" if raw["errors"] == ["semantic_uncertainty"] else "coverage"
                    quarantinable.add(sid)
                else:
                    _require(detected["status"] == "ok" and detected["errors"] == [], "global_source_failure")
                cache[sid] = {"text_sha256": _text_hash(text), "policy_sha256": detail["policy_sha256"],
                              "raw": deepcopy(raw)}
            else:
                _require(detected["status"] == "ok" and detected["errors"] == [], "global_source_failure")
        except Exception as exc:
            record["failure_kind"] = "global"
            return block(str(exc) if isinstance(exc, _IsolationError) else "invalid_source_detection")

    if privacy.QUERY_SOURCE in quarantinable:
        return block("query_detection_incomplete")
    if quarantinable and detail["effective_strategy"] == "request":
        return block("request_source_detection_incomplete")
    removed = {sid for group in groups if quarantinable.intersection(group) for sid in group}
    detail["quarantined_source_ids"] = [sid for sid in sources if sid in removed and sid != privacy.QUERY_SOURCE]
    if privacy.QUERY_SOURCE in removed:
        return block("query_depends_on_quarantined_memory")
    kept = [item for item in source_payload["memories"] if item["source_id"] not in removed]
    detail["kept_source_ids"] = [item["source_id"] for item in kept]
    if not kept:
        return block("all_memories_quarantined")
    # Recheck all originals: isolation must not hide an authorization change.
    if not all(privacy._authorized(authorizer, item["source_id"], actor_id, normalized["version"])
               for item in source_payload["memories"]):
        return block("memory_authorization_changed")
    filtered = {"query": source_payload["query"], "memories": deepcopy(kept)}
    detail["filtered_payload_sha256"] = privacy._digest(filtered)
    allowed = {privacy.QUERY_SOURCE, *detail["kept_source_ids"]}

    class CachedAgent:
        max_local_calls = 1

        def __call__(self, *, text, source_id, policy, rule_findings):
            _require(source_id in allowed and source_id in cache and policy == normalized and rule_findings == [],
                     "cache_source_binding_mismatch")
            item = cache[source_id]
            _require(item["text_sha256"] == _text_hash(text) and item["policy_sha256"] == privacy._digest(policy),
                     "cache_content_binding_mismatch")
            _require(item["raw"]["status"] == "ok" and item["raw"]["errors"] == [], "cache_not_successful")
            detail["cache_replay_invocations"] += 1
            raw = deepcopy(item["raw"])
            raw.update(local_calls=0, elapsed_seconds=0.0)
            return raw

    final_detection = privacy.detect_sensitive(filtered, normalized, agent=CachedAgent(), mode="combined")
    if (final_detection["status"] != "ok" or final_detection["errors"]
            or final_detection["local_calls"] != 0 or not final_detection["local_calls_complete"]):
        return block("filtered_detection_replay_failed")
    prepared = privacy.prepare_private_payload(filtered, final_detection, actor_id=actor_id, request_id=request_id,
        policy_version=normalized["version"], authorizer=authorizer, sensitivity_policy=normalized)
    detail["egress"] = validate_outbound(filtered, prepared, final_detection, normalized)
    if prepared["status"] != "ok":
        return block(prepared["error"])
    if detail["egress"]["status"] != "ok":
        return block(detail["egress"]["code"])
    mapping = prepared["mapping"]
    if (set(mapping._memories) != set(detail["kept_source_ids"])
            or set(mapping._memories).intersection(removed)
            or any(set(entry.sources) - set(detail["kept_source_ids"]) for entry in mapping._entries.values())):
        return block("isolated_source_retained_in_mapping")
    return {**prepared, "isolation": deepcopy(detail)}
