"""External trusted gate for one protected exact value and a native client.

This module neither starts clients nor writes files. It uses the existing broker,
detector, pseudonymization, egress and restoration checks. AGENTS.md is context,
not a native ACL. Caller-supplied identities/policies are trusted host inputs.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import threading
import weakref

from .native_agent_protocol import NativeAgentBroker, NativeProtocolError
from .privacy import (RestorationMap, _TOKEN, _digest, _policy, detect_sensitive,
                      prepare_private_payload, restore_answer)
from .privacy_egress import validate_outbound

ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = ROOT / "results"
VERSION = "external-native-single-value-gate-v1"
QUESTION = "Return the single authorized value in AGENTS.md exactly. No tools or explanation. If absent, reply UNKNOWN."
_KEY = secrets.token_bytes(32)
_LIVE = weakref.WeakKeyDictionary()
_LOCK = threading.Lock()
_POLICY_REQUIRED = frozenset({"version", "protected_categories", "instructions"})
_POLICY_ALLOWED = _POLICY_REQUIRED | {"policy_id", "max_text_chars", "entity_registry"}


class _Failure(ValueError):
    pass


class NativePrivateRequest:
    """Opaque, immutable process-local capability; every finish attempt consumes it."""
    __slots__ = ("_state", "_mapping", "_mac", "__weakref__")

    def __init__(self, state, mapping, mac):
        object.__setattr__(self, "_state", state)
        object.__setattr__(self, "_mapping", mapping)
        object.__setattr__(self, "_mac", mac)

    def __setattr__(self, name, value):
        raise AttributeError("native private requests are immutable")

    def __repr__(self):
        return "<NativePrivateRequest: redacted process-local capability>"

    def __getstate__(self):
        raise TypeError("native private requests must remain in process memory")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode("utf-8")).hexdigest()


def _blocked(code):
    return {"status": "blocked", "request": None, "agents_md": None, "question": None,
            "answer": None, "metadata": {"enforcement_scope": "external_gated",
                                        "native_acl": False, "version": VERSION}, "error": code}


def _policy_checked(policy):
    if (not isinstance(policy, dict) or not _POLICY_REQUIRED <= set(policy)
            or not set(policy) <= _POLICY_ALLOWED):
        raise _Failure("policy_missing_or_unknown_fields")
    return _policy(policy)


def _workspace(workspace, workspace_id):
    path = Path(workspace).absolute()
    resolved = path.resolve(strict=True)
    root = RESULTS_ROOT.resolve(strict=True)
    if (path != resolved or not resolved.is_relative_to(root) or resolved == root
            or not resolved.is_dir() or resolved.name != workspace_id):
        raise _Failure("workspace_binding_invalid")
    git = resolved / ".git"
    if not git.is_dir() or git.is_symlink() or git.resolve() != git:
        raise _Failure("workspace_git_boundary_missing")
    if (resolved / "AGENTS.local.md").exists() or (resolved / ".qoder").exists():
        raise _Failure("unexpected_native_context")
    if any(item.name not in {".git", "AGENTS.md"} for item in resolved.iterdir()):
        raise _Failure("unexpected_native_context")
    return resolved


def _authorized(authorizer, rid, actor_id, version):
    try:
        return authorizer(rid, actor_id, version) is True
    except Exception:
        return False


def _scope(packet, *, broker, sender_actor_id, actor_id, agent_id, workspace,
           request_id, authorizer, version):
    if not isinstance(broker, NativeAgentBroker) or not callable(authorizer):
        raise _Failure("invalid_current_authority")
    if any(not isinstance(v, str) or not v for v in (sender_actor_id, actor_id, agent_id, request_id)):
        raise _Failure("invalid_request_scope")
    # Validate ALL packet records using the original current-state broker first.
    broker.validate(packet, sender_actor_id=sender_actor_id, actor_id=actor_id)
    audience = packet["audience"]
    if audience["agent_id"] != agent_id:
        raise _Failure("agent_scope_mismatch")
    path = _workspace(workspace, audience["workspace_id"])
    if len(packet["items"]) != 1:
        raise _Failure("single_exact_value_required")
    for item in packet["items"]:
        if not _authorized(authorizer, item["record_id"], actor_id, version):
            raise _Failure("current_record_authorization_failed")
    return path


def _map_integrity(mapping):
    """Keyed in-memory integrity, never a serialized/restorable mapping artifact."""
    if not isinstance(mapping, RestorationMap):
        raise _Failure("mapping_invalid")
    digest = hmac.new(_KEY, b"native-private-map-v1", hashlib.sha256)

    def feed(text):
        data = text.encode("utf-8")
        digest.update(len(data).to_bytes(8, "big")); digest.update(data)

    for name in ("_actor_id", "_request_id", "_policy_version", "_policy_sha256",
                 "_source_payload_sha256", "_nonce"):
        feed(getattr(mapping, name))
    for token, entry in sorted(mapping._entries.items()):
        feed(token); feed(entry.value)
        for value in entry.categories + entry.sources:
            feed(value)
    for sid, text in sorted(mapping._memories.items()):
        feed(sid); feed(text)
    for value, categories in mapping._protected_values:
        feed(value)
        for category in categories:
            feed(category)
    for sid, spans in sorted(mapping._sensitive_spans.items()):
        feed(sid)
        for start, end in spans:
            feed(str(start)); feed(str(end))
    return digest.digest()


def _mac(state, mapping):
    return hmac.new(_KEY, b"native-private-request-v1\0" + state +
                    str(id(mapping)).encode() + _map_integrity(mapping), hashlib.sha256).digest()


def prepare_native_private_memory(packet, query, policy, *, broker, sender_actor_id,
                                  actor_id, agent_id, workspace, request_id,
                                  authorizer, detector=None, mode="rules"):
    """Prepare one exact-value record. Return PVT-only native memory, never raw facts.

    The broker record.text must itself be the exact value, not ``field = value``
    or a multi-fact passage. ``detector`` uses privacy.detect_sensitive's existing
    local-agent callable contract; default rules mode makes no model request.
    Host must write agents_md into this already registered workspace before finish.
    """
    try:
        normalized = _policy_checked(policy)
        if not isinstance(query, str) or not query.strip():
            raise _Failure("source_question_invalid")
        packet = deepcopy(packet)
        path = _scope(packet, broker=broker, sender_actor_id=sender_actor_id,
                      actor_id=actor_id, agent_id=agent_id, workspace=workspace,
                      request_id=request_id, authorizer=authorizer, version=normalized["version"])
        memory_file = path / "AGENTS.md"
        if memory_file.is_symlink() or (memory_file.exists() and memory_file.read_bytes().strip()):
            raise _Failure("target_workspace_not_fresh")
        payload = {"query": query, "memories": [{"source_id": item["record_id"], "text": item["text"]}
                                                 for item in packet["items"]]}

        def current_auth(rid, actor, version):
            if actor != actor_id or version != normalized["version"]:
                return False
            try:
                _scope(packet, broker=broker, sender_actor_id=sender_actor_id, actor_id=actor,
                       agent_id=agent_id, workspace=path, request_id=request_id,
                       authorizer=authorizer, version=version)
                return rid in {item["record_id"] for item in packet["items"]}
            except (NativeProtocolError, _Failure, OSError, ValueError, TypeError, KeyError):
                return False

        detection = detect_sensitive(payload, normalized, agent=detector, mode=mode)
        if detection.get("status") != "ok":
            raise _Failure("sensitive_detection_requires_review")
        prepared = prepare_private_payload(payload, detection, actor_id=actor_id,
            request_id=request_id, policy_version=normalized["version"],
            authorizer=current_auth, sensitivity_policy=normalized)
        if prepared.get("status") != "ok":
            raise _Failure("private_preparation_failed")
        egress = validate_outbound(payload, prepared, detection, normalized)
        if egress.get("status") != "ok":
            raise _Failure("private_egress_failed")
        token = prepared["payload"]["memories"][0]["text"]
        if _TOKEN.fullmatch(token) is None:
            raise _Failure("single_masked_value_required")
        # Exactly one token, with no original labels, query or line-ending
        # conversion ambiguity when Windows callers write this native file.
        agents_md = token
        native_payload = {"query": QUESTION, "memories": [
            {"source_id": prepared["payload"]["memories"][0]["source_id"], "text": agents_md}]}
        native_prepared = dict(prepared, payload=native_payload,
                               metadata={**prepared["metadata"], "payload_sha256": _digest(native_payload)})
        native_egress = validate_outbound(payload, native_prepared, detection, normalized)
        if native_egress.get("status") != "ok":
            raise _Failure("native_egress_failed")
        # No authorization/mapping cropping: both source-query and complete memory
        # remain in the original map, which the original restorer will consume.
        state = {"packet": packet, "policy": deepcopy(policy), "normalized_policy": normalized,
                 "payload": payload, "prepared_payload": prepared["payload"], "native_payload": native_payload,
                 "actor_id": actor_id, "agent_id": agent_id, "sender_actor_id": sender_actor_id,
                 "request_id": request_id, "workspace": str(path), "broker_identity": id(broker),
                 "token": token, "agents_md_sha256": _sha(agents_md), "question_sha256": _sha(QUESTION)}
        state_bytes = _canonical(state)
        mapping = prepared["mapping"]
        capability = NativePrivateRequest(state_bytes, mapping, _mac(state_bytes, mapping))
        with _LOCK:
            _LIVE[capability] = capability._mac
        metadata = {"version": VERSION, "enforcement_scope": "external_gated", "native_acl": False,
                    "native_memory_kind": "native_workspace_instructions", "record_count": len(packet["items"]),
                    "packet_sha256": _sha(_canonical(packet)), "policy_sha256": _sha(_canonical(policy)),
                    "source_payload_sha256": _digest(payload), "prepared_payload_sha256": _digest(prepared["payload"]),
                    "native_payload_sha256": _digest(native_payload), "agents_md_sha256": _sha(agents_md),
                    "question_sha256": _sha(QUESTION), "workspace_sha256": _sha(str(path)),
                    "local_calls": detection.get("local_calls"), "egress_scope": native_egress["scope"]}
        return {"status": "ok", "request": capability, "agents_md": agents_md,
                "question": QUESTION, "metadata": metadata, "error": None}
    except NativeProtocolError as exc:
        return _blocked("broker_" + exc.code)
    except _Failure as exc:
        return _blocked(str(exc))
    except (ValueError, TypeError, KeyError, OSError, AttributeError, UnicodeError, OverflowError):
        return _blocked("native_private_preparation_failed")


def restore_native_private_answer(answer, request, policy, *, broker, sender_actor_id,
                                  actor_id, agent_id, workspace, request_id, authorizer):
    """Consume once, reauthorize even UNKNOWN, then use the unchanged original map."""
    try:
        if not isinstance(request, NativePrivateRequest):
            raise _Failure("invalid_native_private_request")
        with _LOCK:
            issued_mac = _LIVE.pop(request, None)
        if issued_mac is None:
            raise _Failure("native_request_unknown_or_replayed")
        if (not isinstance(request._state, bytes) or not isinstance(request._mac, bytes)
                or not hmac.compare_digest(issued_mac, request._mac)
                or not hmac.compare_digest(issued_mac, _mac(request._state, request._mapping))):
            raise _Failure("native_request_integrity_invalid")
        state = json.loads(request._state)
        normalized = _policy_checked(policy)
        packet = state["packet"]
        path = _scope(packet, broker=broker, sender_actor_id=sender_actor_id,
                      actor_id=actor_id, agent_id=agent_id, workspace=workspace,
                      request_id=request_id, authorizer=authorizer, version=normalized["version"])
        actual = (sender_actor_id, actor_id, agent_id, request_id, str(path), id(broker), _canonical(policy))
        expected = (state["sender_actor_id"], state["actor_id"], state["agent_id"],
                    state["request_id"], state["workspace"], state["broker_identity"], _canonical(state["policy"]))
        if actual != expected:
            raise _Failure("native_request_scope_changed")
        memory_file = path / "AGENTS.md"
        if (not memory_file.is_file() or memory_file.is_symlink() or memory_file.stat().st_size > 256
                or _sha(memory_file.read_bytes()) != state["agents_md_sha256"]):
            raise _Failure("native_memory_not_installed_or_changed")

        def current_auth(rid, actor, version):
            if actor != actor_id or version != normalized["version"]:
                return False
            try:
                _scope(packet, broker=broker, sender_actor_id=sender_actor_id, actor_id=actor,
                       agent_id=agent_id, workspace=path, request_id=request_id,
                       authorizer=authorizer, version=version)
                return rid in {item["record_id"] for item in packet["items"]}
            except (NativeProtocolError, _Failure, OSError, ValueError, TypeError, KeyError):
                return False

        if not isinstance(answer, str) or answer.strip() not in {state["token"], "UNKNOWN"}:
            raise _Failure("native_answer_not_single_exported_value")
        result = restore_answer(answer, request._mapping, actor_id=actor_id, request_id=request_id,
                                policy_version=normalized["version"], authorizer=current_auth,
                                sensitivity_policy=normalized)
        return {**result, "enforcement_scope": "external_gated", "native_acl": False,
                "version": VERSION, "request_consumed": True}
    except NativeProtocolError as exc:
        result = _blocked("broker_" + exc.code)
    except _Failure as exc:
        result = _blocked(str(exc))
    except (ValueError, TypeError, KeyError, OSError, AttributeError, UnicodeError, OverflowError):
        result = _blocked("native_private_restoration_failed")
    return {"status": "blocked", "answer": None, "error": result["error"],
            "enforcement_scope": "external_gated", "native_acl": False, "version": VERSION,
            "request_consumed": True}
