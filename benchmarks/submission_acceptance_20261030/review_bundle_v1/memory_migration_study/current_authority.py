"""Explicit current-state delivery contract, separate from offline snapshots.

The witness is a trusted host dependency. Its state must be outside the
snapshot rollback failure domain. A second local directory is only a controlled
prototype of that deployment contract, not protection from a hostile host.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextvars import ContextVar
import secrets
import threading

from .authority_freshness import (
    Checkpoint, FreshnessConflict, SignedSnapshotStore, WitnessUnavailable,
    commit_snapshot, provision_snapshot, state_sha256,
)
from .memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from .principal_scope import EXACT_PRINCIPAL_SCOPE_VERSION, PrincipalIdentity, principal_scope_version
from .privacy import _digest


CURRENT_CONTRACT = "current_exact_principal_read_v1"
OFFLINE_CONTRACT = "offline_signed_snapshot_v1"
_ACCESS_AUDIT = ContextVar("current_authority_access_audit", default=None)


@dataclass(frozen=True)
class CurrentReadRequest:
    principal: PrincipalIdentity
    record_id: str
    source_id: str
    operation: str
    policy_version: str | None
    checkpoint: Checkpoint
    nonce: str

    @property
    def fingerprint(self):
        return _digest({"principal": self.principal.to_dict(), "record_id": self.record_id,
                        "source_id": self.source_id, "operation": self.operation,
                        "policy_version": self.policy_version, "namespace": self.checkpoint.namespace,
                        "revision": self.checkpoint.revision, "state_sha256": self.checkpoint.state_sha256,
                        "nonce": self.nonce})


@dataclass(frozen=True)
class CurrentReadDecision:
    """Host callback response; bools and unbound cached responses are unknown."""
    decision: str
    request_sha256: str

    @classmethod
    def for_request(cls, request, decision):
        if not isinstance(request, CurrentReadRequest) or decision not in {"allow", "deny", "unknown"}:
            raise ValueError("invalid_current_read_decision")
        return cls(decision, request.fingerprint)


def classify_access(code):
    """Separate authorized refusals from unavailable/unknown infrastructure."""
    if code is None:
        return {"decision": "allow", "code": None}
    if code in {"principal_not_authorized", "grant_revoked", "current_authorization_denied"}:
        return {"decision": "deny", "code": code}
    if code in {"authority_state_stale", "authority_state_unknown", "authority_state_unavailable",
                "current_authorizer_unavailable", "current_authorization_unknown",
                "current_authorization_response_invalid", "current_state_changed_during_check",
                "current_contract_legacy_callback_unsupported", "authority_commit_indeterminate"}:
        return {"decision": "unknown", "code": code}
    return {"decision": "invalid", "code": code}


class CurrentMemoryAuthority(MemoryLabelAuthority):
    """Exact identity, independent current state and live read checks required.

    Only this profile claims current authorization. The original authority is
    still an offline signed-snapshot verifier; loading its old valid snapshot
    does not establish freshness. This class never auto-provisions a witness.
    """
    verification_mode = "current"
    contract_version = CURRENT_CONTRACT

    def __init__(self, secret, *, state, namespace, witness, snapshot_store, live_authorizer):
        super().__init__(secret, state=state)
        if not isinstance(namespace, str) or not namespace or not callable(live_authorizer):
            raise ValueError("current_contract_requires_namespace_and_authorizer")
        if not isinstance(snapshot_store, SignedSnapshotStore):
            raise ValueError("current_contract_requires_snapshot_store")
        if not callable(getattr(witness, "check", None)) or not callable(getattr(witness, "head", None)):
            raise ValueError("current_contract_requires_external_witness")
        self.__current_key = secret
        self.__pending_commit = False
        self.namespace, self.witness, self.snapshot_store = namespace, witness, snapshot_store
        self.live_authorizer = live_authorizer
        self.__lock = threading.RLock()

    def __repr__(self):
        return "<CurrentMemoryAuthority: external freshness witness, key redacted>"

    @staticmethod
    def _validator(secret):
        def validate(envelope):
            try:
                MemoryLabelAuthority(secret, state=envelope)
                return True
            except (ValueError, TypeError, KeyError):
                return False
        return validate

    @classmethod
    def provision(cls, secret, *, namespace, witness, snapshot_store, live_authorizer, event_id="provision"):
        """Trusted explicit creation of a NEW authority namespace, never restore."""
        state = MemoryLabelAuthority(secret).export_state()
        provision_snapshot(snapshot_store, witness, namespace, state,
                           validator=cls._validator(secret), event_id=event_id)
        return cls(secret, state=state, namespace=namespace, witness=witness,
                   snapshot_store=snapshot_store, live_authorizer=live_authorizer)

    @classmethod
    def recover_current(cls, secret, *, namespace, witness, snapshot_store, live_authorizer):
        """Recover only the independently witnessed committed immutable blob."""
        checkpoint = witness.head(namespace)
        if not isinstance(checkpoint, Checkpoint):
            raise WitnessUnavailable("authority_namespace_not_provisioned")
        state = snapshot_store.load(checkpoint.state_sha256, validator=cls._validator(secret))
        return cls(secret, state=state, namespace=namespace, witness=witness,
                   snapshot_store=snapshot_store, live_authorizer=live_authorizer)

    def _state_check(self):
        if self.__pending_commit:
            return "authority_commit_indeterminate", None
        try:
            result = self.witness.check(self.namespace, state_sha256(self.export_state()))
            if result.status == "stale":
                return "authority_state_stale", result.checkpoint
            if (result.status != "current" or not isinstance(result.checkpoint, Checkpoint)
                    or result.checkpoint.namespace != self.namespace
                    or result.checkpoint.state_sha256 != state_sha256(self.export_state())):
                return "authority_state_unknown", None
            return None, result.checkpoint
        except Exception:
            return "authority_state_unavailable", None

    def build_record(self, *args, **kwargs):
        with self.__lock:
            error, _ = self._state_check()
            if error:
                raise ValueError(error)
            if kwargs.get("allowed_principals") is None:
                raise ValueError("current_contract_requires_exact_principals")
            record = super().build_record(*args, **kwargs)
            record["access"]["authority_namespace"] = self.namespace
            record["access_signature"] = self._sign("access", record["access"])
            record["label"]["access_sha256"] = _digest(record["access"])
            record["label_signature"] = self._sign("label", record["label"])
            return record

    def validate_access(self, record, *, actor_id, agent_id, authorizer=None, policy_version=None):
        code = self._validate_current_access(record, actor_id=actor_id, agent_id=agent_id,
                                              authorizer=authorizer, policy_version=policy_version)
        audit = _ACCESS_AUDIT.get()
        if audit is not None:
            audit.append((id(self), record.get("record_id") if isinstance(record, dict) else None,
                          actor_id, agent_id, code))
        return code

    def _validate_current_access(self, record, *, actor_id, agent_id, authorizer=None, policy_version=None):
        with self.__lock:
            error, checkpoint = self._state_check()
            if error:
                return error
            if authorizer is not None:
                # The old callback carries only the user, not the execution
                # Agent or a bound response. It cannot substitute this profile.
                return "current_contract_legacy_callback_unsupported"
            try:
                if principal_scope_version(record["access"]) != EXACT_PRINCIPAL_SCOPE_VERSION:
                    return "current_contract_requires_exact_principals"
                if record["access"].get("authority_namespace") != self.namespace:
                    return "authority_namespace_mismatch"
            except (KeyError, ValueError, TypeError):
                return "invalid_record"
            error = super().validate_access(record, actor_id=actor_id, agent_id=agent_id,
                                            policy_version=policy_version)
            if error:
                return error
            request = CurrentReadRequest(PrincipalIdentity(actor_id, agent_id), record["record_id"],
                record["access"]["source_id"], "read", policy_version, checkpoint, secrets.token_hex(16))
            try:
                decision = self.live_authorizer(request)
            except Exception:
                return "current_authorizer_unavailable"
            if (not isinstance(decision, CurrentReadDecision)
                    or decision.request_sha256 != request.fingerprint
                    or decision.decision not in {"allow", "deny", "unknown"}):
                return "current_authorization_response_invalid"
            after_error, after = self._state_check()
            if after_error:
                return after_error
            if after != checkpoint:
                return "current_state_changed_during_check"
            if decision.decision == "deny":
                return "current_authorization_denied"
            if decision.decision == "unknown":
                return "current_authorization_unknown"
            return None

    def access_decision(self, record, **kwargs):
        return {**classify_access(self.validate_access(record, **kwargs)),
                "contract": CURRENT_CONTRACT, "enforcement": "trusted_host_current_read_guard"}

    def _commit(self, method, value=None, *, event_id=None, expected=None):
        with self.__lock:
            error, checkpoint = self._state_check()
            if error:
                raise WitnessUnavailable(error)
            candidate = MemoryLabelAuthority(self.__current_key, state=self.export_state())
            if method == "bump_epoch":
                candidate.bump_epoch()
            else:
                getattr(candidate, method)(value)
            state = candidate.export_state()
            try:
                committed = commit_snapshot(self.snapshot_store, self.witness, self.namespace,
                    expected or checkpoint, state, validator=self._validator(self.__current_key),
                    event_id=event_id or secrets.token_hex(16))
            except Exception:
                self.__pending_commit = True
                raise
            # A commit receipt is the acknowledgment boundary. Failure above
            # leaves this instance unchanged and its next read fails closed.
            self._epoch = candidate._epoch
            self._revoked_records = candidate._revoked_records.copy()
            self._revoked_sources = candidate._revoked_sources.copy()
            if state_sha256(self.export_state()) != committed.state_sha256:
                raise FreshnessConflict("local_committed_state_mismatch")
            return committed

    def revoke(self, record_id, *, event_id=None, expected=None):
        return self._commit("revoke", record_id, event_id=event_id, expected=expected)

    def revoke_source(self, source_id, *, event_id=None, expected=None):
        return self._commit("revoke_source", source_id, event_id=event_id, expected=expected)

    def bump_epoch(self, *, event_id=None, expected=None):
        return self._commit("bump_epoch", event_id=event_id, expected=expected)


def prepare_current_transfer(*args, authority, **kwargs):
    if not isinstance(authority, CurrentMemoryAuthority):
        raise ValueError("current_authority_required")
    records = args[0] if args else kwargs.get("records", [])
    if (not isinstance(records, list)
            or any(not isinstance(record, dict)
                   or not isinstance(record.get("record_id"), str)
                   or not 0 < len(record["record_id"]) <= 256 for record in records)
            or any(not isinstance(kwargs.get(name), str)
                   or not 0 < len(kwargs[name]) <= 256
                   for name in ("actor_id", "agent_id", "request_id"))):
        from .memory_labels import _blocked
        result = _blocked("invalid_transfer_input")
        result["authorization"] = {**classify_access(result["error"]), "contract": CURRENT_CONTRACT}
        result["processing_outcome"] = "authorization_invalid"
        return result
    observations = []
    token = _ACCESS_AUDIT.set(observations)
    try:
        result = prepare_labeled_transfer(*args, authority=authority, **kwargs)
    finally:
        _ACCESS_AUDIT.reset(token)
    code = result.get("error")
    checks = result.get("checks", [])
    reasons = _request_access_errors(observations, authority, records, kwargs)
    if reasons:
        authorization = classify_access(reasons[0])
        result.update(status="blocked", payload=None, mapping=None, error=reasons[0])
    elif (len(checks) == len(records) and all(c.get("access_valid") is True for c in checks)
            and not (not records and result.get("status") == "blocked")
            and code not in {"current_authorization_failed", "preparation_authorization_failed"}):
        authorization = {"decision": "allow", "code": None,
                         "scope": "preparation_read_checks_not_detector_success"}
    else:
        authorization = classify_access(code)
    result["authorization"] = {**authorization, "contract": CURRENT_CONTRACT}
    result["processing_outcome"] = (
        "authorization_unknown" if authorization["decision"] == "unknown" else
        "policy_denied" if authorization["decision"] == "deny" else
        "authorization_invalid" if authorization["decision"] == "invalid" else
        "ready" if result.get("status") == "ok" else
        "needs_review" if result.get("status") == "needs_review" else "processing_failed")
    return result


def restore_current_answer(*args, authority, **kwargs):
    if not isinstance(authority, CurrentMemoryAuthority):
        raise ValueError("current_authority_required")
    records = args[2] if len(args) > 2 else kwargs.get("records", [])
    if (not isinstance(records, list)
            or any(not isinstance(record, dict)
                   or not isinstance(record.get("record_id"), str)
                   or not 0 < len(record["record_id"]) <= 256 for record in records)
            or any(not isinstance(kwargs.get(name), str)
                   or not 0 < len(kwargs[name]) <= 256
                   for name in ("actor_id", "agent_id", "request_id"))):
        code = "invalid_restoration_records"
        return {"status": "blocked", "answer": None, "error": code,
                "authorization": {**classify_access(code), "contract": CURRENT_CONTRACT}}
    observations = []
    token = _ACCESS_AUDIT.set(observations)
    try:
        result = restore_labeled_answer(*args, authority=authority, **kwargs)
    finally:
        _ACCESS_AUDIT.reset(token)
    reasons = _request_access_errors(observations, authority, records, kwargs)
    if reasons:
        result.update(status="blocked", answer=None, error=reasons[0])
    result["authorization"] = {**classify_access(reasons[0] if reasons else result.get("error")),
                                "contract": CURRENT_CONTRACT}
    return result


def _request_access_errors(observations, authority, records, kwargs):
    if not isinstance(records, list):
        return []
    ids = {record["record_id"] for record in records
           if isinstance(record, dict) and isinstance(record.get("record_id"), str)}
    return [code for owner, rid, actor, agent, code in observations if owner == id(authority)
            and isinstance(rid, str) and rid in ids
            and actor == kwargs.get("actor_id") and agent == kwargs.get("agent_id")
            and code is not None]
