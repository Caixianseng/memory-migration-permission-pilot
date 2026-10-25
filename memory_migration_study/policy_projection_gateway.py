"""Optional mandatory-route gateway core, with no native or model I/O of its own.

An external authentication layer constructs AuthenticatedPrincipal after checking
credentials. Native credentials stay inside the host's fetch callback, never in
this protocol. The host is also responsible for routing/bypass confinement.
Serial logical-clock barriers here do not prove native live revocation, erase
delivered plaintext, or authenticate a controller snapshot merely by its hash.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import threading

from .policy_projection_reference import CORE_FIELDS, ReferencePolicy, body_sha256


VERSION = "current_source_policy_projection_gateway_v1"
SNAPSHOT_VERSION = "controller_policy_gateway_snapshot_v1"
MAX_REQUEST_BYTES = 65536


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Trusted auth-layer value; a JSON actor/body is never accepted instead."""
    user_id: str
    agent_id: str


def _shape(value, required, optional=()):
    return isinstance(value, dict) and required <= set(value) <= required | set(optional)


def _parse_body(request):
    if isinstance(request, (bytes, str)):
        raw = request if isinstance(request, bytes) else request.encode("utf-8")
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError()
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        raw_hash = hashlib.sha256(raw).hexdigest()
    else:
        request = deepcopy(request)
        raw = json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError()
        raw_hash = body_sha256(request)
    if not isinstance(request, dict):
        raise ValueError()
    body_sha256(request)
    return request, raw_hash


class PolicyProjectionGateway:
    """Host-owned current policy + registry, suitable for an authenticated route.

    fetch_fact(object_id) must return actual native exact-fact UTF-8 bytes.
    export_sinks[destination_id](object_id, fact_bytes, metadata) must return
    exactly True to confirm a controlled write. Its arbitrary response is never
    returned. export does not imply read-to-caller. All callbacks are trusted
    host injections, not names/URLs supplied by a request.
    """
    def __init__(self, core, initial_state, *, fetch_fact, export_sinks=None, controller_token):
        self._initialize(core, initial_state, fetch_fact, export_sinks, controller_token)

    def _initialize(self, core, state, fetch_fact, export_sinks, controller_token):
        try:
            self._core = deepcopy(core)
            self._reference = ReferencePolicy(self._core)
            state = deepcopy(state)
            self._reference._state(state)
            self._grants = {g["grant_id"]: g for g in self._core["grants"]}
            self._facts = {f["object_id"]: f for f in self._core["facts"]}
            self._principals = {p["principal_id"]: p for p in self._core["principals"]}
            if any(self._grants[g]["parent_grant_id"] is not None for g in state["registered_grants"]):
                raise ValueError()
            sinks = {} if export_sinks is None else dict(export_sinks)
            if (controller_token is None or not callable(fetch_fact)
                    or not set(sinks) <= {d["destination_id"] for d in self._core["destinations"]}
                    or not all(callable(sink) for sink in sinks.values())):
                raise ValueError()
            self._state, self._fetch, self._sinks = state, fetch_fact, sinks
            self._controller = controller_token
            self._installed = {}
            self._lock = threading.RLock()
        except Exception:
            raise ValueError("invalid_gateway_configuration") from None

    def _controller_check(self, token):
        if token is not self._controller:
            raise PermissionError("controller_required")

    def _identity(self, principal):
        if type(principal) is not AuthenticatedPrincipal:
            raise ValueError()
        pair = {"user_id": principal.user_id, "agent_id": principal.agent_id}
        if not all(isinstance(v, str) and bool(v) and v == v.strip() for v in pair.values()):
            raise ValueError()
        return pair

    def _reference_request(self, principal, body):
        operation = body.get("operation")
        required = {"operation", "object_id"}
        optional = set()
        if operation == "export":
            required.add("destination")
        elif operation in {"share", "delegate"}:
            required |= {"recipient", "child_actions", "child_expires_at", "child_grant_id"}
            if operation == "delegate":
                required.add("child_delegation_depth")
            else:
                optional.add("child_delegation_depth")
        elif operation == "import_replay":
            required |= {"job_id", "payload", "body_sha256"}
            optional.add("underlying_operation")
        elif operation != "read":
            raise ValueError()
        if not _shape(body, required, optional):
            raise ValueError()
        request = {k: deepcopy(v) for k, v in body.items() if k != "child_grant_id"}
        request["actor"] = self._identity(principal)
        return request

    def _reply(self, body=None, raw_hash=None):
        body = body if isinstance(body, dict) else {}
        return {"version": VERSION, "http_status": 400, "decision": "deny", "source_decision": None,
            "reason": "invalid_request", "operation": body.get("operation") if isinstance(body.get("operation"), str) else None,
            "object_id": body.get("object_id") if isinstance(body.get("object_id"), str) else None,
            "raw_request_sha256": raw_hash, "data": None, "delivered_fact_ids": [],
            "side_effect": {"status": "not_attempted", "kind": None}, "reference": None,
            "contract_sha256": self._reference.contract_sha256, "state_sha256": body_sha256(self._state),
            "policy_revision": self._state["policy_revision"], "time": self._state["time"]}

    def _finish(self, reply):
        reply.update(state_sha256=body_sha256(self._state), policy_revision=self._state["policy_revision"], time=self._state["time"])
        return reply

    def _apply_reference(self, reply, reference):
        reply.update(reference=reference, source_decision=reference["decision"], decision=reference["decision"], reason=reference["reason"])
        if reference["decision"] != "allow":
            reply["http_status"] = 409 if reference["decision"] == "invalid_replay" else 403
            return False
        return True

    def _child(self, body, reference, state):
        grant_id = body["child_grant_id"]
        child = self._grants.get(grant_id)
        if (child is None or child["parent_grant_id"] not in reference["valid_grant_ids"]
                or child.get("issued_by_operation") != body["operation"]
                or child["object_id"] != body["object_id"] or child["subject"] != body["recipient"]
                or set(child["actions"]) != set(body["child_actions"])
                or child["expires_at"] != body["child_expires_at"]
                or child["delegation_depth"] != body.get("child_delegation_depth", 0)
                or not child["not_before"] <= state["time"] < child["expires_at"]
                or grant_id in state["revoked_grants"]):
            raise ValueError()
        return child

    def dispatch(self, authenticated_principal, request):
        """Authorize current state, then execute one managed operation.

        Failure is orthogonal to authorization: native/sink errors use 502 and
        decision=error/source_decision=allow, never a fake 200 or policy denial.
        This lock is only a serial host barrier, not native atomic revocation.
        """
        with self._lock:
            try:
                body, raw_hash = _parse_body(request)
            except Exception:
                return self._reply()
            reply = self._reply(body, raw_hash)
            try:
                self._identity(authenticated_principal)
            except Exception:
                reply.update(http_status=403, reason="authenticated_principal_required")
                return reply
            try:
                source_request = self._reference_request(authenticated_principal, body)
            except Exception:
                return reply
            reference = self._reference.evaluate(source_request, self._state)
            if not self._apply_reference(reply, reference):
                return self._finish(reply)
            operation, object_id = body["operation"], body["object_id"]
            if operation in {"share", "delegate"}:
                try:
                    child = self._child(body, reference, self._state)
                except Exception:
                    reply.update(http_status=403, decision="deny", reason="unregistered_or_mismatched_child_grant")
                    return self._finish(reply)
                grant_id = child["grant_id"]
                already = grant_id in self._state["registered_grants"]
                if already and grant_id not in self._installed:
                    reply.update(http_status=502, decision="error", reason="registry_provenance_missing")
                    return self._finish(reply)
                if not already:
                    before = deepcopy(self._state)
                    self._state["registered_grants"].append(grant_id)
                    self._installed[grant_id] = {"grant_id": grant_id, "parent_grant_id": child["parent_grant_id"],
                        "request": deepcopy(body), "principal": self._identity(authenticated_principal),
                        "state_before": before, "reference_sha256": body_sha256(reference),
                        "state_after_sha256": body_sha256(self._state)}
                reply.update(http_status=200, decision="allow", reason="child_grant_registered",
                    side_effect={"status": "confirmed", "kind": "register_grant", "grant_id": grant_id,
                                 "already_registered": already})
                return self._finish(reply)
            fact = self._facts[object_id]
            try:
                data = self._fetch(object_id)
                if type(data) is not bytes:
                    raise ValueError()
            except Exception:
                reply.update(http_status=502, decision="error", reason="native_fetch_failed")
                return self._finish(reply)
            if hashlib.sha256(data).hexdigest() != fact["content_sha256"]:
                reply.update(http_status=502, decision="error", reason="native_fact_integrity_failed")
                return self._finish(reply)
            try:
                text = data.decode("utf-8", errors="strict")
            except UnicodeError:
                reply.update(http_status=502, decision="error", reason="native_fact_encoding_failed")
                return self._finish(reply)
            # Trusted callback/control activity can change current state. Recheck
            # before returning bytes or forwarding them to a controlled sink.
            fresh = self._reference.evaluate(source_request, self._state)
            reply["pre_fetch_reference_sha256"] = body_sha256(reference)
            if not self._apply_reference(reply, fresh):
                return self._finish(reply)
            if operation == "export":
                destination = body["destination"]
                sink = self._sinks.get(destination)
                if sink is None:
                    reply.update(http_status=502, decision="error", reason="controlled_sink_unavailable")
                    return self._finish(reply)
                metadata = {"destination_id": destination, "content_sha256": fact["content_sha256"],
                    "principal": self._identity(authenticated_principal), "state_sha256": body_sha256(self._state),
                    "policy_revision": self._state["policy_revision"], "time": self._state["time"]}
                reply["side_effect"] = {"status": "unverified", "kind": "export", "destination_id": destination}
                try:
                    if sink(object_id, data, deepcopy(metadata)) is not True:
                        raise ValueError()
                except Exception:
                    reply.update(http_status=502, decision="error", reason="controlled_sink_failed")
                    return self._finish(reply)
                reply.update(http_status=200, decision="allow", reason="controlled_export_confirmed",
                    side_effect={"status": "confirmed", "kind": "export", "destination_id": destination,
                                 "content_sha256": fact["content_sha256"]})
            else:
                reply.update(http_status=200, decision="allow", reason="exact_fact_delivered",
                    data={"object_id": object_id, "text": text, "content_sha256": fact["content_sha256"]},
                    delivered_fact_ids=[object_id])
            return self._finish(reply)

    def transition_state(self, new_state, *, controller_token):
        """Controller-only serial barrier; no rollback or implicit child install."""
        with self._lock:
            self._controller_check(controller_token)
            try:
                new = deepcopy(new_state)
                self._reference._state(new)
                old = self._state
                if (new["time"] < old["time"] or new["policy_revision"] < old["policy_revision"]
                        or not set(old["registered_grants"]) <= set(new["registered_grants"])
                        or not set(old["revoked_grants"]) <= set(new["revoked_grants"])):
                    raise ValueError()
                added = set(new["registered_grants"])-set(old["registered_grants"])
                if any(self._grants[g]["parent_grant_id"] is not None for g in added):
                    raise ValueError()
                if (added or set(old["revoked_grants"]) != set(new["revoked_grants"])) and new["policy_revision"] <= old["policy_revision"]:
                    raise ValueError()
                self._state = new
            except Exception:
                raise ValueError("invalid_or_rollback_state_transition") from None
            return {"state_sha256": body_sha256(self._state), "policy_revision": self._state["policy_revision"], "time": self._state["time"]}

    def get_state_snapshot(self, *, controller_token):
        """Return controller-only IDs/receipts, without core plaintext or keys."""
        with self._lock:
            self._controller_check(controller_token)
            snapshot = {"version": SNAPSHOT_VERSION, "contract_sha256": self._reference.contract_sha256,
                "state": deepcopy(self._state), "installed_children": deepcopy(list(self._installed.values()))}
            return dict(snapshot, snapshot_sha256=body_sha256(snapshot))

    @classmethod
    def from_snapshot(cls, core, snapshot, *, fetch_fact, export_sinks=None, controller_token):
        """Trusted host fork, not a public import endpoint or authentication proof.

        The checksum checks content consistency, not origin. The controller must
        obtain the snapshot through its protected channel and record the fork.
        Recompute prior installation receipts rather than silently seeding kids.
        """
        try:
            snapshot = deepcopy(snapshot)
            fields = {"version", "contract_sha256", "state", "installed_children", "snapshot_sha256"}
            if not _shape(snapshot, fields) or snapshot["version"] != SNAPSHOT_VERSION:
                raise ValueError()
            if body_sha256({k:v for k,v in snapshot.items() if k!="snapshot_sha256"}) != snapshot["snapshot_sha256"]:
                raise ValueError()
            reference = ReferencePolicy(core)
            reference._state(snapshot["state"])
            if snapshot["contract_sha256"] != reference.contract_sha256 or not isinstance(snapshot["installed_children"], list):
                raise ValueError()
            grants = {g["grant_id"]:g for g in core["grants"]}
            bootstrap = deepcopy(snapshot["state"])
            bootstrap["registered_grants"] = [g for g in bootstrap["registered_grants"] if grants[g]["parent_grant_id"] is None]
            gateway = cls(core, bootstrap, fetch_fact=fetch_fact, export_sinks=export_sinks, controller_token=controller_token)
            installed, last_after = {}, None
            for receipt in snapshot["installed_children"]:
                if not _shape(receipt, {"grant_id", "parent_grant_id", "request", "principal", "state_before", "reference_sha256", "state_after_sha256"}):
                    raise ValueError()
                before = receipt["state_before"]
                reference._state(before)
                if last_after is not None and (before["time"] < last_after["time"]
                        or before["policy_revision"] < last_after["policy_revision"]
                        or not set(last_after["registered_grants"]) <= set(before["registered_grants"])
                        or not set(last_after["revoked_grants"]) <= set(before["revoked_grants"])):
                    raise ValueError()
                known_children = {g for g in before["registered_grants"] if grants[g]["parent_grant_id"] is not None}
                if known_children != set(installed) or receipt["grant_id"] in installed:
                    raise ValueError()
                principal = AuthenticatedPrincipal(**receipt["principal"])
                request = gateway._reference_request(principal, receipt["request"])
                result = reference.evaluate(request, before)
                child = gateway._child(receipt["request"], result, before)
                after = deepcopy(before);after["registered_grants"].append(child["grant_id"])
                if (result["decision"] != "allow" or child["grant_id"] != receipt["grant_id"]
                        or child["parent_grant_id"] != receipt["parent_grant_id"]
                        or body_sha256(result) != receipt["reference_sha256"]
                        or body_sha256(after) != receipt["state_after_sha256"]):
                    raise ValueError()
                installed[child["grant_id"]] = receipt
                last_after = after
            final_children = {g for g in snapshot["state"]["registered_grants"] if grants[g]["parent_grant_id"] is not None}
            if final_children != set(installed):
                raise ValueError()
            final = snapshot["state"]
            if last_after is not None and (final["time"] < last_after["time"]
                    or final["policy_revision"] < last_after["policy_revision"]
                    or not set(last_after["registered_grants"]) <= set(final["registered_grants"])
                    or not set(last_after["revoked_grants"]) <= set(final["revoked_grants"])):
                raise ValueError()
            gateway._state, gateway._installed = deepcopy(snapshot["state"]), installed
            return gateway
        except Exception:
            raise ValueError("invalid_gateway_snapshot") from None
