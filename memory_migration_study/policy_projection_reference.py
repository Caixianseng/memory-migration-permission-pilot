"""Pure standard reference policy, not a deployed authentication gateway.

The host supplies authenticated user/agent bindings and current trusted state.
Text, labels, request assertions and prior delivery do not create grants. The
class performs no I/O/native/model calls and does not install grants. This is
ordinary explicit authorization with exact principals, attenuation and replay
integrity, not a new algorithm or an already deployed native enforcement layer.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json


VERSION = "source_policy_projection_reference_v1"
CORE_FIELDS = ("principals", "sources", "facts", "destinations", "grants", "job_manifests")
ACTIONS = frozenset(("read", "share", "export", "delegate"))
_GRANT_BASE = {"grant_id", "object_id", "subject", "actions", "not_before", "expires_at",
               "parent_grant_id", "delegation_depth"}
_GRANT_EXTRA = {"issued_by_operation", "share_recipients", "share_actions", "export_destinations",
                "delegate_recipients", "delegate_actions", "maximum_delegated_expiry",
                "maximum_child_delegation_depth"}
_PAYLOAD_FIELDS = {"object_id", "recipient", "grant_id", "source_policy_revision"}


def body_sha256(payload):
    """Hash the complete JSON body; no projected subset and no nonfinite values."""
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def _text_sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identifier(value):
    return isinstance(value, str) and bool(value) and value == value.strip() and len(value) <= 256


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _shape(value, required, optional=()):
    return isinstance(value, dict) and required <= set(value) <= required | set(optional)


def _unique_strings(value, permitted=None, *, nonempty=True):
    return (isinstance(value, list) and (bool(value) or not nonempty)
        and all(_identifier(x) for x in value) and len(value) == len(set(value))
        and (permitted is None or set(value) <= set(permitted)))


class ReferencePolicy:
    """Construct with exactly CORE_FIELDS extracted from a trusted fixture.

    evaluate accepts actor/operation/object_id and only that operation's fields.
    actor is either a registered principal ID or exactly user_id/agent_id. Both
    forms are trusted host inputs, never proof that a network caller is genuine.
    All results carry hashes/IDs, never a fact's plaintext.
    """
    def __init__(self, contract):
        try:
            if not _shape(contract, set(CORE_FIELDS)):
                raise ValueError()
            core = deepcopy(contract)
            body_sha256(core)
            def registry(name, fields, identity, optional=()):
                rows = core[name]
                if not isinstance(rows, list):
                    raise ValueError()
                result = {}
                for row in rows:
                    if (not _shape(row, set(fields), optional) or not _identifier(row[identity])
                            or row[identity] in result):
                        raise ValueError()
                    result[row[identity]] = row
                return result
            self._principals = registry("principals", {"principal_id", "user_id", "agent_id"}, "principal_id")
            tuples = set()
            for row in self._principals.values():
                pair = (row["user_id"], row["agent_id"])
                if not all(_identifier(x) for x in pair) or pair in tuples:
                    raise ValueError()
                tuples.add(pair)
            self._sources = registry("sources", {"source_id", "text", "sha256", "public_synthetic_material"}, "source_id")
            for row in self._sources.values():
                if (not isinstance(row["text"], str) or _text_sha(row["text"]) != row["sha256"]
                        or type(row["public_synthetic_material"]) is not bool):
                    raise ValueError()
            self._facts = registry("facts", {"object_id", "source_id", "source_start", "source_end", "text",
                "content_sha256", "sensitivity", "labels_are_authorization"}, "object_id")
            for row in self._facts.values():
                source = self._sources[row["source_id"]]
                start, end = row["source_start"], row["source_end"]
                if (not _integer(start) or not _integer(end) or not start < end <= len(source["text"])
                        or not isinstance(row["text"], str) or source["text"][start:end] != row["text"]
                        or _text_sha(row["text"]) != row["content_sha256"]
                        or not _identifier(row["sensitivity"]) or row["labels_are_authorization"] is not False):
                    raise ValueError()
            self._destinations = registry("destinations", {"destination_id", "kind", "value"}, "destination_id")
            for row in self._destinations.values():
                if not _identifier(row["kind"]) or not (row["value"] is None or isinstance(row["value"], str)):
                    raise ValueError()
            self._grants = registry("grants", _GRANT_BASE, "grant_id", _GRANT_EXTRA)
            for grant in self._grants.values():
                self._validate_grant(grant)
            for grant in self._grants.values():
                self._chain(grant["grant_id"])
                if grant["parent_grant_id"] is not None:
                    if not self._link_valid(grant, self._grants[grant["parent_grant_id"]]):
                        raise ValueError()
            self._jobs = registry("job_manifests", {"job_id", "issued_state", "payload", "body_sha256"}, "job_id")
            for job in self._jobs.values():
                p = job["payload"]
                if (not _identifier(job["issued_state"]) or not _shape(p, _PAYLOAD_FIELDS)
                        or p["object_id"] not in self._facts or p["recipient"] not in self._principals
                        or p["grant_id"] not in self._grants or not _integer(p["source_policy_revision"], 1)
                        or body_sha256(p) != job["body_sha256"]):
                    raise ValueError()
                grant = self._grants[p["grant_id"]]
                if grant["object_id"] != p["object_id"] or grant["subject"] != p["recipient"] or "read" not in grant["actions"]:
                    raise ValueError()
            self.contract_sha256 = body_sha256(core)
        except Exception:
            raise ValueError("invalid_reference_contract") from None

    def _validate_grant(self, grant):
        if (grant["object_id"] not in self._facts or grant["subject"] not in self._principals
                or not _unique_strings(grant["actions"], ACTIONS)
                or not _integer(grant["not_before"]) or not _integer(grant["expires_at"])
                or grant["not_before"] >= grant["expires_at"] or not _integer(grant["delegation_depth"])):
            raise ValueError()
        parent = grant["parent_grant_id"]
        if parent is None:
            if "issued_by_operation" in grant:
                raise ValueError()
        elif parent not in self._grants or grant.get("issued_by_operation") not in {"share", "delegate"}:
            raise ValueError()
        for field, allowed in [("share_recipients", self._principals), ("delegate_recipients", self._principals),
                               ("share_actions", ACTIONS), ("delegate_actions", ACTIONS),
                               ("export_destinations", self._destinations)]:
            if field in grant and not _unique_strings(grant[field], allowed):
                raise ValueError()
        for field in ["maximum_delegated_expiry", "maximum_child_delegation_depth"]:
            if field in grant and not _integer(grant[field]):
                raise ValueError()
        actions = set(grant["actions"])
        if "share" in actions and (not grant.get("share_recipients") or not grant.get("share_actions")
                or not set(grant["share_actions"]) <= actions & {"read"}):
            raise ValueError()
        if "export" in actions and not grant.get("export_destinations"):
            raise ValueError()
        if "delegate" in actions:
            if (not grant.get("delegate_recipients") or not grant.get("delegate_actions")
                    or not set(grant["delegate_actions"]) <= actions
                    or grant["delegation_depth"] < 1
                    or not grant["not_before"] < grant.get("maximum_delegated_expiry", -1) <= grant["expires_at"]
                    or not 0 <= grant.get("maximum_child_delegation_depth", -1) < grant["delegation_depth"]):
                raise ValueError()

    def _chain(self, grant_id):
        chain, seen = [], set()
        while grant_id is not None:
            if grant_id in seen or grant_id not in self._grants:
                raise ValueError()
            seen.add(grant_id)
            grant = self._grants[grant_id]
            chain.append(grant)
            grant_id = grant["parent_grant_id"]
        return chain

    def _child_allowed(self, parent, operation, recipient, actions, expiry, depth, not_before):
        if (operation not in parent["actions"] or recipient not in parent.get(operation+"_recipients", [])
                or not set(actions) <= set(parent.get(operation+"_actions", [])) & set(parent["actions"])
                or not parent["not_before"] <= not_before < expiry <= parent["expires_at"]):
            return False
        if operation == "share":
            return set(actions) <= {"read"} and depth == 0
        return (parent["delegation_depth"] > 0 and depth < parent["delegation_depth"]
                and depth <= parent["maximum_child_delegation_depth"]
                and expiry <= parent["maximum_delegated_expiry"])

    def _link_valid(self, child, parent):
        if child["object_id"] != parent["object_id"] or not self._child_allowed(parent,
            child["issued_by_operation"], child["subject"], child["actions"], child["expires_at"],
            child["delegation_depth"], child["not_before"]):
            return False
        # A child's future scopes must also attenuate, not merely its actions.
        for field in ["share_recipients", "share_actions", "export_destinations", "delegate_recipients", "delegate_actions"]:
            if field in child and not set(child[field]) <= set(parent.get(field, [])):
                return False
        for field in ["maximum_delegated_expiry", "maximum_child_delegation_depth"]:
            if field in child and child[field] > parent.get(field, -1):
                return False
        return True

    def _principal(self, actor):
        if isinstance(actor, str) and actor in self._principals:
            row = self._principals[actor]
            return actor, {"user_id": row["user_id"], "agent_id": row["agent_id"]}
        if _shape(actor, {"user_id", "agent_id"}) and all(_identifier(actor[k]) for k in actor):
            for principal_id, row in self._principals.items():
                if (row["user_id"], row["agent_id"]) == (actor["user_id"], actor["agent_id"]):
                    return principal_id, deepcopy(actor)
        return None, None

    def _state(self, state):
        required = {"time", "policy_revision", "registered_grants", "revoked_grants"}
        optional = {"state_id", "parent_state", "trusted_fixture_events"}
        if (not _shape(state, required, optional) or not _integer(state["time"])
                or not _integer(state["policy_revision"], 1)
                or not _unique_strings(state["registered_grants"], self._grants, nonempty=False)
                or not _unique_strings(state["revoked_grants"], self._grants, nonempty=False)):
            raise ValueError()
        if any(k in state and not _identifier(state[k]) for k in ["state_id", "parent_state"]):
            raise ValueError()
        if "trusted_fixture_events" in state and not _unique_strings(state["trusted_fixture_events"], nonempty=False):
            raise ValueError()
        return state

    def _valid(self, grant_id, state):
        chain = self._chain(grant_id)
        for grant in chain:
            if grant["grant_id"] not in state["registered_grants"]:
                return False, "grant_or_ancestor_not_registered", [g["grant_id"] for g in chain]
            if grant["grant_id"] in state["revoked_grants"]:
                return False, "grant_or_ancestor_revoked", [g["grant_id"] for g in chain]
            if not grant["not_before"] <= state["time"] < grant["expires_at"]:
                return False, "grant_or_ancestor_outside_time", [g["grant_id"] for g in chain]
        return True, "valid_chain", [g["grant_id"] for g in chain]

    def _result(self, request, state):
        result = {"version": VERSION, "decision": "deny", "reason": "invalid_request",
            "contract_sha256": self.contract_sha256, "request_sha256": None, "state_sha256": None,
            "time": None, "policy_revision": None, "principal": None,
            "operation": None, "object_id": None, "valid_grant_ids": [], "grant_evidence": []}
        try:
            result["request_sha256"] = body_sha256(request)
            result["state_sha256"] = body_sha256(state)
        except Exception:
            pass
        return result

    def evaluate(self, request, state):
        """Return a decision only; authenticated identities/state come from host."""
        request, state = deepcopy((request, state))
        result = self._result(request, state)
        try:
            state = self._state(state)
            result.update(time=state["time"], policy_revision=state["policy_revision"])
        except Exception:
            result["reason"] = "invalid_state"
            return result
        try:
            if not isinstance(request, dict):
                return result
            operation = request.get("operation")
            fields = {"actor", "operation", "object_id"}
            if operation == "import_replay":
                if not _shape(request, fields | {"job_id", "payload", "body_sha256"}, {"underlying_operation"}) or request.get("underlying_operation", "read") != "read":
                    return result
                answer = self.validate_import_job({k: request[k] for k in ("job_id", "actor", "payload", "body_sha256")}, state)
                answer["request_sha256"] = result["request_sha256"]
                if answer["object_id"] != request["object_id"]:
                    answer.update(decision="invalid_replay", reason="job_object_mismatch", valid_grant_ids=[])
                return answer
            if operation == "export":
                fields |= {"destination"}
            elif operation in {"share", "delegate"}:
                fields |= {"recipient", "child_actions", "child_expires_at"}
                if operation == "delegate":
                    fields.add("child_delegation_depth")
            elif operation != "read":
                return result
            if not _shape(request, fields, {"child_delegation_depth"} if operation == "share" else ()):
                return result
            principal_id, principal = self._principal(request["actor"])
            result.update(principal=principal, operation=operation, object_id=request["object_id"])
            if principal_id is None:
                result["reason"] = "unknown_principal"
                return result
            if request["object_id"] not in self._facts:
                result["reason"] = "unknown_object"
                return result
            if operation == "export" and request["destination"] not in self._destinations:
                return result
            if operation in {"share", "delegate"}:
                if (request["recipient"] not in self._principals or not _unique_strings(request["child_actions"], ACTIONS)
                        or not _integer(request["child_expires_at"])
                        or not _integer(request.get("child_delegation_depth", 0))):
                    return result
            fact = self._facts[request["object_id"]]
            result.update(content_sha256=fact["content_sha256"], source_sha256=self._sources[fact["source_id"]]["sha256"],
                          source_range=[fact["source_start"], fact["source_end"]])
            for grant_id, grant in self._grants.items():
                if grant["subject"] != principal_id or grant["object_id"] != request["object_id"] or operation not in grant["actions"]:
                    continue
                valid, reason, chain = self._valid(grant_id, state)
                if valid and operation == "export" and request["destination"] not in grant.get("export_destinations", []):
                    valid, reason = False, "destination_not_allowed"
                if valid and operation in {"share", "delegate"} and not self._child_allowed(grant, operation,
                    request["recipient"], request["child_actions"], request["child_expires_at"],
                    request.get("child_delegation_depth", 0), state["time"]):
                    valid, reason = False, "child_scope_not_allowed"
                result["grant_evidence"].append({"grant_id": grant_id, "chain": chain, "valid": valid, "reason": reason})
                if valid:
                    result["valid_grant_ids"].append(grant_id)
            result.update(decision="allow" if result["valid_grant_ids"] else "deny",
                          reason="authorized" if result["valid_grant_ids"] else "no_valid_grant")
        except Exception:
            result.update(decision="deny", reason="invalid_request", valid_grant_ids=[])
        return result

    def validate_import_job(self, job, state):
        """Bind complete registered payload, then recheck its exact current grant.

        A newer policy revision is allowed after current checks. A different OR
        grant can authorize a new read, but cannot rescue this job's dependency.
        """
        job, state = deepcopy((job, state))
        result = self._result(job, state)
        result.update(decision="invalid_replay", reason="invalid_job", operation="import_replay")
        try:
            self._state(state)
            result.update(time=state["time"], policy_revision=state["policy_revision"])
        except Exception:
            result.update(decision="deny", reason="invalid_state")
            return result
        try:
            if not _shape(job, {"job_id", "actor", "payload", "body_sha256"}) or job["job_id"] not in self._jobs:
                return result
            manifest, payload = self._jobs[job["job_id"]], job["payload"]
            if (not _shape(payload, _PAYLOAD_FIELDS) or body_sha256(payload) != job["body_sha256"]
                    or job["body_sha256"] != manifest["body_sha256"]
                    or body_sha256(payload) != body_sha256(manifest["payload"])):
                result["reason"] = "job_body_mismatch"
                return result
            principal_id, principal = self._principal(job["actor"])
            result.update(principal=principal, object_id=payload["object_id"], job_id=job["job_id"],
                          job_body_sha256=job["body_sha256"])
            if principal_id is None or principal_id != payload["recipient"]:
                result.update(decision="deny", reason="job_recipient_mismatch")
                return result
            if state["policy_revision"] < payload["source_policy_revision"]:
                result.update(decision="deny", reason="job_revision_not_yet_current")
                return result
            grant = self._grants[payload["grant_id"]]
            valid, reason, chain = self._valid(grant["grant_id"], state)
            fact = self._facts[payload["object_id"]]
            result.update(content_sha256=fact["content_sha256"], source_sha256=self._sources[fact["source_id"]]["sha256"],
                          source_range=[fact["source_start"], fact["source_end"]],
                          grant_evidence=[{"grant_id": grant["grant_id"], "chain": chain, "valid": valid, "reason": reason}],
                          valid_grant_ids=[grant["grant_id"]] if valid else [], decision="allow" if valid else "deny",
                          reason="authorized_current_job" if valid else reason)
        except Exception:
            result.update(decision="invalid_replay", reason="invalid_job", valid_grant_ids=[])
        return result
