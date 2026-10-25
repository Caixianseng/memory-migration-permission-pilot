"""Trusted local generation labels and migration validation.

Models propose facts and sensitive spans, never ACLs. A local authority signs a
separate access grant and a content/policy-bound label. Labels are not a proof
of complete detection. Raw source records and HMAC keys stay on the local host.
Lifecycle checks here are controlled local checks, not native online revocation.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import math
import re
import secrets
from typing import Callable

from .privacy import (QUERY_SOURCE, _close_and_propagate,
                      _digest, _policy, _sources, detect_sensitive,
                      prepare_private_payload, restore_answer)
from .privacy_egress import validate_outbound

LABEL_VERSION = "local_memory_labels_v1"
SCHEMA = "local_labeled_memory_v1"
ACCESS_SCOPE_VERSION = "exact_fact_source_span_v1"


def _text_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identifier(value):
    return isinstance(value, str) and bool(value) and len(value) <= 256


def _version(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value) is not None


def _principals(values):
    if not isinstance(values, (list, tuple)) or any(not _identifier(v) for v in values):
        raise ValueError("invalid_trusted_principals")
    return sorted(set(values))


class MemoryLabelAuthority:
    """HMAC authority with explicitly exportable, signed local lifecycle state.

    Provision the key out of band; neither records nor export_state contain it.
    Reload a persisted authority with BOTH the same protected key and its latest
    state. Restarting without state would discard revocations and is not safe.
    HMAC provides trust only inside this shared-key local prototype.
    """

    def __init__(self, secret: bytes, *, state: dict | None = None):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("authority_key_requires_32_bytes")
        self.__secret = secret
        self._epoch = 0
        self._revoked_records = set()
        self._revoked_sources = set()
        if state is not None:
            if (not isinstance(state, dict) or set(state) != {"state", "signature"}
                    or not self._valid_signature("state", state["state"], state["signature"])):
                raise ValueError("invalid_lifecycle_state")
            data = state["state"]
            if (not isinstance(data, dict) or set(data) != {"version", "epoch", "revoked_records", "revoked_sources"}
                    or data["version"] != LABEL_VERSION or type(data["epoch"]) is not int or data["epoch"] < 0):
                raise ValueError("invalid_lifecycle_state")
            self._epoch = data["epoch"]
            self._revoked_records = set(_principals(data["revoked_records"]))
            self._revoked_sources = set(_principals(data["revoked_sources"]))

    def __repr__(self):
        return "<MemoryLabelAuthority: local key redacted>"

    def __getstate__(self):
        raise TypeError("authority keys cannot be serialized")

    def _sign(self, domain, value):
        message = (LABEL_VERSION + ":" + domain + ":" + _digest(value)).encode("ascii")
        return hmac.new(self.__secret, message, hashlib.sha256).hexdigest()

    def _valid_signature(self, domain, value, signature):
        try:
            return (isinstance(signature, str) and len(signature) == 64
                    and hmac.compare_digest(self._sign(domain, value), signature))
        except (TypeError, ValueError, UnicodeError):
            return False

    def export_state(self):
        data = {"version": LABEL_VERSION, "epoch": self._epoch,
                "revoked_records": sorted(self._revoked_records),
                "revoked_sources": sorted(self._revoked_sources)}
        return {"state": data, "signature": self._sign("state", data)}

    def bump_epoch(self):
        self._epoch += 1
        return self._epoch

    def revoke(self, record_id):
        if not _identifier(record_id):
            raise ValueError("invalid_record_id")
        self._revoked_records.add(record_id)

    def revoke_source(self, source_id):
        if not _identifier(source_id):
            raise ValueError("invalid_source_id")
        self._revoked_sources.add(source_id)

    def build_record(self, source: dict, fact: dict, policy: dict, *, owner_id: str,
                     readers: list[str], agent_id: str, builder_version: str,
                     allowed_agent_ids: list[str] | None = None,
                     detector_version: str | None = None) -> dict:
        """Sign an exact single-source extracted fact using trusted server ACLs.

        fact contains text/source_start/source_end/findings with fact-relative
        offsets. Extra model fields (owner, readers, public, etc.) are ignored.
        The access grant binds this exact content and source occurrence. Any
        later content/range change needs a new trusted authorization; a label
        rescan may repair sensitivity metadata, never the granted fact scope.
        """
        normalized = _policy(policy)
        if (not isinstance(source, dict) or not _identifier(source.get("source_id"))
                or source["source_id"] == QUERY_SOURCE or not isinstance(source.get("text"), str)):
            raise ValueError("invalid_source")
        if (not _identifier(owner_id) or not _identifier(agent_id)
                or not _version(builder_version) or not _version(detector_version or builder_version)):
            raise ValueError("invalid_trusted_metadata")
        read_ids = sorted(set(_principals(readers)) | {owner_id})
        agents = _principals(allowed_agent_ids if allowed_agent_ids is not None else [agent_id])
        if not agents:
            raise ValueError("empty_agent_scope")
        if not isinstance(fact, dict) or fact.get("status", "ok") != "ok":
            raise ValueError("fact_requires_review")
        start, end, text = fact.get("source_start"), fact.get("source_end"), fact.get("text")
        if (type(start) is not int or type(end) is not int or not isinstance(text, str)
                or not 0 <= start < end <= len(source["text"]) or source["text"][start:end] != text):
            raise ValueError("fact_source_location_invalid")
        findings = fact.get("findings")
        if not isinstance(findings, list):
            raise ValueError("invalid_generation_findings")
        safe_findings = []
        for item in findings:
            if (not isinstance(item, dict) or type(item.get("start")) is not int
                    or type(item.get("end")) is not int or not 0 <= item["start"] < item["end"] <= len(text)
                    or item.get("category") not in normalized["protected_categories"]):
                raise ValueError("invalid_generation_finding")
            safe_findings.append({key: item[key] for key in ("start", "end", "category")})
        safe_findings = [dict(zip(("start", "end", "category"), row)) for row in
                         sorted({(f["start"], f["end"], f["category"]) for f in safe_findings})]
        record_id = "memory_" + secrets.token_hex(16)
        source_hash = _text_hash(source["text"])
        grant = {"record_id": record_id, "owner_id": owner_id, "readers": read_ids,
                 "origin_agent_id": agent_id, "allowed_agent_ids": agents,
                 "source_id": source["source_id"], "source_sha256": source_hash, "epoch": self._epoch,
                 "scope_version": ACCESS_SCOPE_VERSION, "content_sha256": _text_hash(text),
                 "source_start": start, "source_end": end}
        label = {"version": LABEL_VERSION, "record_id": record_id, "status": "ok",
                 "findings": safe_findings, "content_sha256": _text_hash(text),
                 "source_start": start, "source_end": end, "source_sha256": source_hash,
                 "policy_sha256": _digest(normalized), "policy_version": normalized["version"],
                 "builder_version": builder_version, "detector_version": detector_version or builder_version,
                 "epoch": self._epoch, "access_sha256": _digest(grant)}
        return {"schema": SCHEMA, "status": "ok", "record_id": record_id, "source_id": record_id,
                "text": text, "source": {"source_id": source["source_id"], "text": source["text"], "sha256": source_hash},
                "source_start": start, "source_end": end, "access": grant,
                "access_signature": self._sign("access", grant), "label": label,
                "label_signature": self._sign("label", label)}

    def validate_access(self, record, *, actor_id, agent_id, authorizer=None, policy_version=None):
        """Validate exact fact scope; label failure cannot widen its grant.

        Historic grants without content/range binding remain signature-readable
        for audit but are refused by this current authorization path.
        """
        try:
            if not isinstance(record, dict) or record.get("schema") != SCHEMA:
                return "invalid_record"
            grant = record["access"]
            if not self._valid_signature("access", grant, record.get("access_signature")):
                return "access_signature_invalid"
            # An authenticated old source-level grant is not a fact-level
            # grant. Do not repair/re-sign it or treat label fallback as an
            # opportunity to select another slice of the same source.
            if not {"scope_version", "content_sha256", "source_start", "source_end"}.issubset(grant):
                return "access_content_binding_missing"
            if grant["scope_version"] != ACCESS_SCOPE_VERSION:
                return "access_scope_version_unsupported"
            if (type(grant["source_start"]) is not int or type(grant["source_end"]) is not int
                    or not isinstance(grant["content_sha256"], str)
                    or re.fullmatch(r"[a-f0-9]{64}", grant["content_sha256"]) is None):
                return "access_content_binding_invalid"
            rid = record["record_id"]
            if (record.get("source_id") != rid or grant["record_id"] != rid
                    or not _identifier(rid)):
                return "record_identity_changed"
            if grant["epoch"] != self._epoch:
                return "lifecycle_epoch_changed"
            if rid in self._revoked_records or grant["source_id"] in self._revoked_sources:
                return "grant_revoked"
            if actor_id not in grant["readers"] or agent_id not in grant["allowed_agent_ids"]:
                return "principal_not_authorized"
            source = record["source"]
            if (source["source_id"] != grant["source_id"] or not isinstance(source["text"], str)
                    or source.get("sha256") != grant["source_sha256"]
                    or _text_hash(source["text"]) != grant["source_sha256"]):
                return "source_identity_changed"
            start, end = record["source_start"], record["source_end"]
            if (type(start) is not int or type(end) is not int
                    or not 0 <= start < end <= len(source["text"])
                    or not isinstance(record["text"], str) or source["text"][start:end] != record["text"]):
                return "fact_source_location_invalid"
            if (start != grant["source_start"] or end != grant["source_end"]
                    or _text_hash(record["text"]) != grant["content_sha256"]):
                return "access_content_changed"
            if authorizer is not None:
                try:
                    allowed = authorizer(rid, actor_id, policy_version) is True
                except Exception:
                    allowed = False
                if not allowed:
                    return "current_authorization_failed"
        except (KeyError, TypeError, ValueError):
            return "invalid_record"
        return None

    def validate_label(self, record, policy, *, expected_builder_version=None, expected_detector_version=None):
        """Return a fixed invalidation reason or None; no authority decision."""
        try:
            label = record.get("label")
            if not isinstance(label, dict) or not record.get("label_signature"):
                return "label_missing"
            if not self._valid_signature("label", label, record["label_signature"]):
                return "label_signature_invalid"
            if expected_builder_version is not None and label.get("builder_version") != expected_builder_version:
                return "label_builder_changed"
            if expected_detector_version is not None and label.get("detector_version") != expected_detector_version:
                return "label_detector_changed"
            if label.get("policy_sha256") != _digest(_policy(policy)):
                return "label_policy_changed"
            if (label.get("content_sha256") != _text_hash(record["text"])
                    or label.get("source_start") != record["source_start"]
                    or label.get("source_end") != record["source_end"]):
                return "label_content_changed"
            if (label.get("version") != LABEL_VERSION or label.get("status") != "ok"
                    or label.get("record_id") != record["record_id"]
                    or label.get("epoch") != self._epoch
                    or label.get("source_sha256") != record["source"]["sha256"]
                    or label.get("access_sha256") != _digest(record["access"])
                    or not _version(label.get("builder_version")) or not _version(label.get("detector_version"))):
                return "label_binding_invalid"
            if not isinstance(label.get("findings"), list):
                return "label_findings_invalid"
            for f in label["findings"]:
                if (not isinstance(f, dict) or set(f) != {"start", "end", "category"}
                        or type(f["start"]) is not int or type(f["end"]) is not int
                        or not 0 <= f["start"] < f["end"] <= len(record["text"])
                        or f["category"] not in _policy(policy)["protected_categories"]):
                    return "label_findings_invalid"
        except (KeyError, ValueError, TypeError):
            return "label_binding_invalid"
        return None


def build_record(source, fact, policy, *, authority, **kwargs):
    """Convenience wrapper; only the trusted host supplies authority and ACLs."""
    return authority.build_record(source, fact, policy, **kwargs)


def _blocked(code, *, checks=None, original_payload=None):
    return {"status": "blocked", "payload": None, "mapping": None, "error": code,
            "metadata": {}, "checks": checks or [], "detection": None,
            "egress": {"status": "blocked", "code": code}, "local_calls": 0,
            "agent_elapsed_seconds": 0.0, "original_payload": original_payload}


_SEMANTIC_KINDS = ("local_encoder", "local_generation", "unknown")


def _semantic_baseline_agent(agent):
    """Observe physical baseline costs after cache binding, without text logs.

    Adapter-supplied typed counts must sum to its scalar count. For the two
    pinned adapters the host class establishes inference kind; model names do
    not. Positive costs of an unidentified adapter remain unknown and cannot
    pass the optional semantic pipeline's complete-cost contract.
    """
    counts, complete = dict.fromkeys(_SEMANTIC_KINDS, 0), [True]
    if agent is None:
        return None, counts, complete

    def observe(*, text, source_id, policy, rule_findings):
        try:
            response = agent(text=text, source_id=source_id, policy=policy, rule_findings=rule_findings)
        except Exception:
            complete[0] = False
            raise
        calls = response.get("local_calls") if isinstance(response, dict) else None
        if type(calls) is not int or calls < 0 or response.get("local_calls_complete", True) is not True:
            complete[0] = False
            return response
        typed = response.get("inference_counts")
        if typed is not None:
            if (not isinstance(typed, dict) or set(typed)-set(_SEMANTIC_KINDS)
                    or any(type(v) is not int or v < 0 for v in typed.values()) or sum(typed.values()) != calls):
                complete[0] = False
                counts["unknown"] += calls
                return response
            for kind in _SEMANTIC_KINDS:
                counts[kind] += typed.get(kind, 0)
            complete[0] = complete[0] and not typed.get("unknown", 0)
        elif calls:
            # The cache wrapper does not retain the adapter type. Its trusted
            # closure attaches the original kind below; cache hits cost zero.
            from .local_detector import LocalSensitivityAgent
            from .ner_detector import GlinerEntityAgent
            original = getattr(agent, "_semantic_original_adapter", agent)
            kind = ("local_encoder" if isinstance(original, GlinerEntityAgent) else
                    "local_generation" if isinstance(original, LocalSensitivityAgent) else "unknown")
            counts[kind] += calls
            complete[0] = complete[0] and kind != "unknown"
        return response

    observe.max_local_calls = getattr(agent, "max_local_calls", 2)
    return observe, counts, complete


def _semantic_cost_fields(baseline, result):
    """Check costs independently of accepting the hook's content decisions."""
    def typed(value):
        return (isinstance(value, dict) and set(value) == set(_SEMANTIC_KINDS)
                and all(type(n) is int and n >= 0 for n in value.values()) and value["unknown"] == 0)
    added, total = result.get("semantic_local_counts"), result.get("inference_counts")
    if (not typed(added) or added["local_encoder"] != 0 or added["local_generation"] > 2
            or not typed(total) or not typed(result.get("local_counts")) or _digest(result["local_counts"]) != _digest(total)
            or type(result.get("baseline_local_calls")) is not int or result["baseline_local_calls"] != baseline["local_calls"]
            or type(result.get("local_calls")) is not int or result["local_calls"] != sum(total.values())
            or result["local_calls"] != baseline["local_calls"]+sum(added.values())
            or any(total[k] != baseline["inference_counts"][k]+added[k] for k in _SEMANTIC_KINDS)
            or result.get("local_calls_complete") is not True or result.get("local_counts_complete") is not True):
        raise ValueError("semantic_result_call_accounting_invalid")
    observations, previous = result.get("agent_observations"), baseline["agent_observations"]
    if (not isinstance(observations, list) or len(observations) < len(previous)
            or _digest(observations[:len(previous)]) != _digest(previous)):
        raise ValueError("semantic_result_observations_invalid")
    observed = dict.fromkeys(_SEMANTIC_KINDS, 0)
    for observation in observations[len(previous):]:
        if (not isinstance(observation, dict)
                or set(observation) != {"stage", "local_calls", "elapsed_seconds", "inference_counts", "receipt_sha256"}
                or observation["stage"] != "local_policy_semantics_v1"
                or type(observation["local_calls"]) is not int or observation["local_calls"] < 0
                or not typed(observation["inference_counts"])
                or sum(observation["inference_counts"].values()) != observation["local_calls"]
                or not isinstance(observation["receipt_sha256"], str)
                or re.fullmatch(r"[a-f0-9]{64}", observation["receipt_sha256"]) is None
                or type(observation["elapsed_seconds"]) not in (int, float)
                or not math.isfinite(observation["elapsed_seconds"]) or observation["elapsed_seconds"] < 0):
            raise ValueError("semantic_result_observations_invalid")
        for kind in _SEMANTIC_KINDS:
            observed[kind] += observation["inference_counts"][kind]
    if observed != added:
        raise ValueError("semantic_result_observations_invalid")
    elapsed = result.get("agent_elapsed_seconds")
    if (type(elapsed) not in (int, float) or not math.isfinite(elapsed)
            or elapsed < baseline["agent_elapsed_seconds"]):
        raise ValueError("semantic_result_elapsed_invalid")
    return {key: copy.deepcopy(result[key]) for key in ("local_calls", "local_calls_complete", "local_counts_complete", "inference_counts", "local_counts", "semantic_local_counts", "baseline_local_calls", "agent_observations", "agent_elapsed_seconds")}


def _semantic_result(payload, policy, baseline, result, *, mode, cache_scope):
    """Validate hook data as classification evidence, never as a grant."""
    extra = {"full_policy_sha256", "semantic_mode", "baseline_local_calls", "semantic_local_counts",
             "policy_semantics", "baseline_detection_sha256", "cache_scope_sha256", "inference_counts",
             "local_counts", "local_counts_complete"}
    if not isinstance(result, dict) or set(result)-set(baseline)-extra:
        raise ValueError("semantic_result_schema_invalid")
    if (result.get("payload_sha256") != _digest(payload)
            or result.get("policy_sha256") != _digest(policy)
            or result.get("full_policy_sha256") != _digest(policy)
            or result.get("policy_version") != policy["version"]
            or result.get("policy_id") != policy["policy_id"]
            or result.get("protected_categories") != policy["protected_categories"]
            or result.get("semantic_mode") != mode
            or result.get("baseline_detection_sha256") != _digest(baseline)
            or result.get("cache_scope_sha256") != _digest(cache_scope)):
        raise ValueError("semantic_result_binding_invalid")
    if (baseline.get("status") != "ok" or baseline.get("errors") != []
            or result.get("status") not in {"ok", "needs_review"}
            or not isinstance(result.get("errors"), list)
            or any(not isinstance(e, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,128}", e) for e in result["errors"])
            or (result["status"] == "ok") != (not result["errors"])):
        raise ValueError("semantic_result_status_invalid")
    _semantic_cost_fields(baseline, result)
    sources = _sources(payload)
    if not isinstance(result.get("findings"), list):
        raise ValueError("semantic_result_findings_invalid")
    allowed = {"source_id", "start", "end", "category", "policy_id", "method", "quote", "provenance"}
    for finding in result["findings"]:
        if not isinstance(finding, dict) or set(finding)-allowed:
            raise ValueError("semantic_result_findings_invalid")
        sid, a, b, cat = (finding.get(k) for k in ("source_id", "start", "end", "category"))
        if (not isinstance(sid, str) or sid not in sources or type(a) is not int or type(b) is not int
                or not 0 <= a < b <= len(sources[sid]) or cat not in policy["protected_categories"]
                or finding.get("policy_id") != policy["policy_id"] or not isinstance(finding.get("method"), str)
                or not re.fullmatch(r"[A-Za-z0-9_+:-]{1,128}", finding["method"])
                or ("quote" in finding and finding["quote"] != sources[sid][a:b])):
            raise ValueError("semantic_result_findings_invalid")
        if "provenance" in finding:
            if not isinstance(finding["provenance"], list):
                raise ValueError("semantic_result_findings_invalid")
            for origin in finding["provenance"]:
                if (not isinstance(origin, dict) or set(origin) != {"source_id", "start", "end", "method"}
                        or origin["source_id"] not in sources or type(origin["start"]) is not int or type(origin["end"]) is not int
                        or not 0 <= origin["start"] < origin["end"] <= len(sources[origin["source_id"]])
                        or not isinstance(origin["method"], str)):
                    raise ValueError("semantic_result_findings_invalid")
    return copy.deepcopy(result)


def prepare_labeled_transfer(records, query, policy, *, authority: MemoryLabelAuthority,
                             actor_id, agent_id, request_id, mode="migration", agent=None,
                             authorizer: Callable | None = None, detection_cache=None,
                             label_requirements=None, privacy_pipeline="legacy",
                             semantic_refiner=None, semantic_mode="joint"):
    """Run A migration detection, B generation reuse, or C both, then real egress.

    All methods use the SAME records and ACL checks. B still independently
    detects the query and rechecks missing/invalid labels. The returned mapping
    and original_payload are process-local material, not a serialization format.
    The optional boundary pipeline refines detection and business-value recovery
    evidence after these same permission checks. Valid signed generation labels
    remain protective constraints; structural interpretation cannot remove them.
    The opt-in semantic hook receives only selected memory text, the question,
    normalized sensitivity policy and non-capability cache-domain hashes. Role
    decisions classify candidates; they cannot change any access grant.
    """
    if mode not in {"migration", "generation", "two_stage"}:
        return _blocked("invalid_transfer_mode")
    if not isinstance(privacy_pipeline, str) or privacy_pipeline not in {"legacy", "boundary", "semantic"}:
        return _blocked("invalid_privacy_pipeline")
    if (not isinstance(authority, MemoryLabelAuthority) or not isinstance(records, list)
            or not isinstance(query, str) or not all(_identifier(v) for v in (actor_id, agent_id, request_id))):
        return _blocked("invalid_transfer_input")
    try:
        normalized = _policy(policy)
    except ValueError:
        return _blocked("invalid_sensitivity_policy")
    if label_requirements is not None and not isinstance(label_requirements, dict):
        return _blocked("invalid_label_requirements")
    requirements = dict(label_requirements or {})
    if (set(requirements) - {"expected_builder_version", "expected_detector_version"}
            or any(not _version(v) for v in requirements.values())):
        return _blocked("invalid_label_requirements")
    checks, by_id, fallback = [], {}, []
    for record in records:
        access_error = authority.validate_access(record, actor_id=actor_id, agent_id=agent_id,
                                                 authorizer=authorizer, policy_version=normalized["version"])
        if access_error:
            return _blocked(access_error, checks=checks)
        rid = record["record_id"]
        if rid in by_id:
            return _blocked("duplicate_memory_identity", checks=checks)
        by_id[rid] = record
        reason = authority.validate_label(record, normalized, **requirements)
        checks.append({"record_id": rid, "label_valid": reason is None,
                       "fallback_reason": reason if mode == "generation" else None,
                       "label_check_reason": reason, "access_valid": True})
        if reason is not None:
            fallback.append({"source_id": rid, "text": record["text"]})
    if privacy_pipeline == "semantic":
        if not callable(semantic_refiner):
            return _blocked("semantic_refiner_required", checks=checks)
        if not isinstance(semantic_mode, str) or semantic_mode not in {"joint", "roles", "completion"}:
            return _blocked("invalid_semantic_mode", checks=checks)
    payload = {"query": query, "memories": [{"source_id": rid, "text": record["text"]}
                                              for rid, record in by_id.items()]}
    cache_before = None
    original_agent = agent
    if detection_cache is not None:
        from .detection_cache import DetectionCache
        if not isinstance(detection_cache, DetectionCache):
            return _blocked("invalid_detection_cache", checks=checks)
        cache_before = detection_cache.stats()
        if agent is not None:
            # Cache entries are never permission grants. Every record has already
            # passed current identity/source/lifecycle checks above; grant and
            # authority domains prevent reuse across users, Agents or authorities.
            scope = {"authority": authority._sign("detection_cache_domain", {}),
                     "actor_id": actor_id, "agent_id": agent_id,
                     "lifecycle": _digest(authority.export_state()),
                     "grants": {rid: _digest(r["access"]) for rid, r in by_id.items()}}
            agent = detection_cache.bind(agent, scope=scope)
            if privacy_pipeline == "semantic":
                agent._semantic_original_adapter = original_agent
    baseline_counts, baseline_complete = None, None
    if privacy_pipeline == "semantic":
        agent, baseline_counts, baseline_complete = _semantic_baseline_agent(agent)
    # Start with a real rules result: it binds payload and full normalized policy
    # and enforces format, reserved-token and size checks in all three arms.
    base = detect_sensitive(payload, normalized, mode="rules")
    if mode in {"migration", "two_stage"}:
        semantic_payload = payload
    else:
        semantic_payload = {"query": query, "memories": fallback}
    semantic = detect_sensitive(semantic_payload, normalized, agent=agent, mode="combined")
    detection = copy.deepcopy(base)
    detection["mode"] = mode
    detection["strategy"] = LABEL_VERSION + ":" + mode
    detection["local_calls"] = semantic["local_calls"]
    detection["local_calls_complete"] = semantic["local_calls_complete"]
    detection["agent_elapsed_seconds"] = semantic["agent_elapsed_seconds"]
    detection["agent_observations"] = copy.deepcopy(semantic["agent_observations"])
    detection["errors"] = sorted(set(base["errors"] + semantic["errors"]))
    findings = base["findings"] + semantic["findings"]
    signed_label_findings = []
    if mode in {"generation", "two_stage"}:
        for record, check in zip(records, checks):
            if check["label_valid"]:
                signed_label_findings.extend({"source_id": record["record_id"], "start": f["start"], "end": f["end"],
                                 "category": f["category"], "policy_id": normalized["policy_id"],
                                 "method": "generation_label"} for f in record["label"]["findings"])
        findings.extend(signed_label_findings)
    findings = _close_and_propagate(_sources(payload), findings, normalized["protected_categories"],
                                    normalized["policy_id"])
    unique = {(f["source_id"], f["start"], f["end"], f["category"]): f for f in findings}
    detection["findings"] = sorted(unique.values(), key=lambda f: (f["source_id"], f["start"], f["end"], f["category"]))
    detection["status"] = "needs_review" if detection["errors"] else "ok"

    prepare_fn = prepare_private_payload
    if privacy_pipeline == "boundary":
        from .boundary_detector import refine_detection
        from .boundary_preparation import prepare_boundary_payload
        detection = refine_detection(payload, normalized, detection)
        if detection["status"] == "ok" and signed_label_findings:
            # The authority authenticated these labels for generation reuse.
            # Never declassify them merely because a detector/parser disagrees.
            protected = _close_and_propagate(_sources(payload),
                detection["findings"] + signed_label_findings,
                normalized["protected_categories"], normalized["policy_id"])
            unique = {(f["source_id"], f["start"], f["end"], f["category"]): f for f in protected}
            detection["findings"] = sorted(unique.values(), key=lambda f: (f["source_id"], f["start"], f["end"], f["category"]))
        prepare_fn = prepare_boundary_payload
    elif privacy_pipeline == "semantic":
        # The same source/subject/Agent checks precede baseline inference and
        # the new hook. Recheck after baseline calls as lifecycle state may have
        # changed; old cache entries and sensitivity labels are never grants.
        detection["full_policy_sha256"] = _digest(normalized)
        detection["inference_counts"] = dict(baseline_counts)
        detection["local_counts"] = dict(baseline_counts)
        detection["local_counts_complete"] = bool(baseline_complete[0] and
            sum(baseline_counts.values()) == detection["local_calls"] and baseline_counts["unknown"] == 0)
        baseline = copy.deepcopy(detection)

        def semantic_failure(code, *, cost_complete=False, observed=None):
            failed = copy.deepcopy(baseline)
            failed.update(status="needs_review", errors=sorted(set(failed["errors"]+[code])),
                          semantic_mode=semantic_mode,
                          local_calls_complete=bool(failed["local_calls_complete"] and cost_complete),
                          local_counts_complete=bool(failed["local_counts_complete"] and cost_complete),
                          semantic_local_counts=dict.fromkeys(_SEMANTIC_KINDS, 0),
                          baseline_local_calls=baseline["local_calls"])
            if isinstance(observed, dict):
                try:
                    # A bad source/binding/authority claim cannot erase actual
                    # otherwise completely observed model work. Accept only
                    # its independent cost receipt, never its findings.
                    failed.update(_semantic_cost_fields(baseline, observed))
                except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
                    pass
            return failed

        access_error = next((reason for record in records if (reason := authority.validate_access(record,
            actor_id=actor_id, agent_id=agent_id, authorizer=authorizer, policy_version=normalized["version"]))), None)
        if access_error:
            detection = semantic_failure("semantic_authorization_changed_before_hook", cost_complete=True)
            prepared = _blocked(access_error, checks=checks)
            prepared.update(detection=detection, local_calls=detection["local_calls"],
                local_calls_complete=detection["local_calls_complete"],
                agent_elapsed_seconds=detection["agent_elapsed_seconds"],
                inference_counts=dict(detection["inference_counts"]), original_payload=payload)
            return prepared
        if (baseline["status"] != "ok" or baseline["errors"] or baseline["local_calls_complete"] is not True
                or baseline["local_counts_complete"] is not True):
            detection = semantic_failure("semantic_baseline_requires_review", cost_complete=True)
        else:
            semantic_scope = {"authority_domain": authority._sign("policy_semantic_cache_domain", {}),
                "lifecycle_sha256": _digest(authority.export_state()),
                "grants_sha256": _digest({rid: r["access"] for rid, r in by_id.items()})}
            try:
                proposed = semantic_refiner(copy.deepcopy(payload), copy.deepcopy(normalized), copy.deepcopy(baseline),
                    actor_id=actor_id, agent_id=agent_id, mode=semantic_mode, cache_scope=copy.deepcopy(semantic_scope))
            except Exception:
                detection = semantic_failure("semantic_refiner_failed")
            else:
                try:
                    detection = _semantic_result(payload, normalized, baseline, proposed,
                                                 mode=semantic_mode, cache_scope=semantic_scope)
                except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
                    detection = semantic_failure("semantic_refiner_result_invalid", observed=proposed)
            if detection["status"] == "ok":
                # Generic rules, explicit policy declarations and authenticated
                # generation labels remain mandatory protective constraints.
                # A new classifier can refine ML candidates, not declassify
                # independently imposed rules or signed generation metadata.
                protected = _close_and_propagate(_sources(payload),
                    detection["findings"]+base["findings"]+signed_label_findings,
                    normalized["protected_categories"], normalized["policy_id"])
                unique = {(f["source_id"], f["start"], f["end"], f["category"]): f for f in protected}
                detection["findings"] = sorted(unique.values(), key=lambda f: (f["source_id"], f["start"], f["end"], f["category"]))

    def current_auth(rid, actor, version):
        return (actor == actor_id and version == normalized["version"] and rid in by_id
                and authority.validate_access(by_id[rid], actor_id=actor, agent_id=agent_id,
                                              authorizer=authorizer, policy_version=version) is None)

    prepared = prepare_fn(payload, detection, actor_id=actor_id, request_id=request_id,
                                       policy_version=normalized["version"], authorizer=current_auth,
                                       sensitivity_policy=normalized)
    egress = validate_outbound(payload, prepared, detection, normalized)
    if prepared["status"] == "ok" and egress["status"] != "ok":
        prepared.update(status="blocked", payload=None, mapping=None, error=egress["code"])
    prepared.update(detection=detection, egress=egress, checks=checks, original_payload=payload,
                    local_calls=detection["local_calls"], local_calls_complete=detection["local_calls_complete"],
                    agent_elapsed_seconds=detection["agent_elapsed_seconds"])
    prepared["metadata"].update(label_version=LABEL_VERSION, transfer_mode=mode,
                                 privacy_pipeline=privacy_pipeline,
                                 valid_label_count=sum(c["label_valid"] for c in checks),
                                 fallback_count=len(fallback) if mode == "generation" else 0,
                                 generation_local_calls=0, migration_local_calls=detection["local_calls"])
    if cache_before is not None:
        cache_after = detection_cache.stats()
        prepared["metadata"]["detection_cache"] = {
            key: cache_after[key] - cache_before[key]
            for key in ("hits", "misses", "bypasses", "expired", "evictions", "stores")}
        prepared["metadata"]["detection_cache"]["entries"] = cache_after["entries"]
    if requirements:
        prepared["metadata"]["label_requirements"] = requirements
    if privacy_pipeline == "semantic":
        prepared["inference_counts"] = dict(detection["inference_counts"])
        prepared["metadata"].update(semantic_mode=semantic_mode,
            baseline_local_calls=detection["baseline_local_calls"],
            semantic_local_counts=copy.deepcopy(detection["semantic_local_counts"]),
            local_counts_complete=detection.get("local_counts_complete") is True,
            semantic_classification_is_not_authorization=True)
    return prepared


def restore_labeled_answer(answer, prepared, records, policy, *, authority, actor_id,
                           agent_id, request_id, authorizer=None):
    """Recheck local epoch, user, executing Agent and current grants at recovery."""
    def block(code):
        return {"status": "blocked", "answer": None, "error": code}
    if not isinstance(prepared, dict) or prepared.get("status") != "ok":
        return block("transfer_not_ready")
    if not isinstance(authority, MemoryLabelAuthority) or not isinstance(records, list):
        return block("invalid_restoration_records")
    try:
        normalized = _policy(policy)
        by_id = {r["record_id"]: r for r in records}
        if len(by_id) != len(records):
            return block("duplicate_memory_identity")
        memories = {rid: r["text"] for rid, r in by_id.items()}
        mapping = prepared.get("mapping")
        if getattr(mapping, "_memories", None) != memories:
            return block("restoration_records_changed")
        for record in records:
            reason = authority.validate_access(record, actor_id=actor_id, agent_id=agent_id,
                                                authorizer=authorizer, policy_version=normalized["version"])
            if reason:
                return block(reason)
    except (KeyError, ValueError, TypeError):
        return block("invalid_restoration_records")

    def current_auth(rid, actor, version):
        return (rid in by_id and actor == actor_id and version == normalized["version"]
                and authority.validate_access(by_id[rid], actor_id=actor, agent_id=agent_id,
                                              authorizer=authorizer, policy_version=version) is None)

    return restore_answer(answer, mapping, actor_id=actor_id, request_id=request_id,
                          policy_version=normalized["version"], authorizer=current_auth,
                          sensitivity_policy=normalized)
