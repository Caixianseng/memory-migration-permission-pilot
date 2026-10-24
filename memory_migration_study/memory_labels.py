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
import re
import secrets
from typing import Callable

from .privacy import (QUERY_SOURCE, _close_and_propagate,
                      _digest, _policy, _sources, detect_sensitive,
                      prepare_private_payload, restore_answer)
from .privacy_egress import validate_outbound

LABEL_VERSION = "local_memory_labels_v1"
SCHEMA = "local_labeled_memory_v1"


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
                 "source_id": source["source_id"], "source_sha256": source_hash, "epoch": self._epoch}
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
        """Validate the separately signed grant; label failure cannot grant access."""
        try:
            if not isinstance(record, dict) or record.get("schema") != SCHEMA:
                return "invalid_record"
            grant = record["access"]
            if not self._valid_signature("access", grant, record.get("access_signature")):
                return "access_signature_invalid"
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

    def validate_label(self, record, policy):
        """Return a fixed invalidation reason or None; no authority decision."""
        try:
            label = record.get("label")
            if not isinstance(label, dict) or not record.get("label_signature"):
                return "label_missing"
            if not self._valid_signature("label", label, record["label_signature"]):
                return "label_signature_invalid"
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


def prepare_labeled_transfer(records, query, policy, *, authority: MemoryLabelAuthority,
                             actor_id, agent_id, request_id, mode="migration", agent=None,
                             authorizer: Callable | None = None):
    """Run A migration detection, B generation reuse, or C both, then real egress.

    All methods use the SAME records and ACL checks. B still independently
    detects the query and rechecks missing/invalid labels. The returned mapping
    and original_payload are process-local material, not a serialization format.
    """
    if mode not in {"migration", "generation", "two_stage"}:
        return _blocked("invalid_transfer_mode")
    if (not isinstance(authority, MemoryLabelAuthority) or not isinstance(records, list)
            or not isinstance(query, str) or not all(_identifier(v) for v in (actor_id, agent_id, request_id))):
        return _blocked("invalid_transfer_input")
    try:
        normalized = _policy(policy)
    except ValueError:
        return _blocked("invalid_sensitivity_policy")
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
        reason = authority.validate_label(record, normalized)
        checks.append({"record_id": rid, "label_valid": reason is None,
                       "fallback_reason": reason if mode == "generation" else None,
                       "label_check_reason": reason, "access_valid": True})
        if reason is not None:
            fallback.append({"source_id": rid, "text": record["text"]})
    payload = {"query": query, "memories": [{"source_id": rid, "text": record["text"]}
                                              for rid, record in by_id.items()]}
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
    if mode in {"generation", "two_stage"}:
        for record, check in zip(records, checks):
            if check["label_valid"]:
                findings.extend({"source_id": record["record_id"], "start": f["start"], "end": f["end"],
                                 "category": f["category"], "policy_id": normalized["policy_id"],
                                 "method": "generation_label"} for f in record["label"]["findings"])
    findings = _close_and_propagate(_sources(payload), findings, normalized["protected_categories"],
                                    normalized["policy_id"])
    unique = {(f["source_id"], f["start"], f["end"], f["category"]): f for f in findings}
    detection["findings"] = sorted(unique.values(), key=lambda f: (f["source_id"], f["start"], f["end"], f["category"]))
    detection["status"] = "needs_review" if detection["errors"] else "ok"

    def current_auth(rid, actor, version):
        return (actor == actor_id and version == normalized["version"] and rid in by_id
                and authority.validate_access(by_id[rid], actor_id=actor, agent_id=agent_id,
                                              authorizer=authorizer, policy_version=version) is None)

    prepared = prepare_private_payload(payload, detection, actor_id=actor_id, request_id=request_id,
                                       policy_version=normalized["version"], authorizer=current_auth,
                                       sensitivity_policy=normalized)
    egress = validate_outbound(payload, prepared, detection, normalized)
    if prepared["status"] == "ok" and egress["status"] != "ok":
        prepared.update(status="blocked", payload=None, mapping=None, error=egress["code"])
    prepared.update(detection=detection, egress=egress, checks=checks, original_payload=payload,
                    local_calls=detection["local_calls"], local_calls_complete=detection["local_calls_complete"],
                    agent_elapsed_seconds=detection["agent_elapsed_seconds"])
    prepared["metadata"].update(label_version=LABEL_VERSION, transfer_mode=mode,
                                 valid_label_count=sum(c["label_valid"] for c in checks),
                                 fallback_count=len(fallback) if mode == "generation" else 0,
                                 generation_local_calls=0, migration_local_calls=detection["local_calls"])
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
