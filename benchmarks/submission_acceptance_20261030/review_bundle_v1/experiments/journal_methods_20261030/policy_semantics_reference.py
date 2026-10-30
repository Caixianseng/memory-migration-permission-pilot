"""Independent finite authorization reference for the 2026-10-30 study.

This module imports no production authorization code. It implements a frozen,
small policy language, not FACPL itself. Its custom combining order is explicit
Deny, then Indeterminate, then Permit, then NotApplicable. Thus uncertainty in
an applicable rule prevents delivery, but a missing attribute in an already
inapplicable rule does not contaminate another rule.

Policy schema::

    {"schema": "finite_policy_v1", "version": "v1",
     "combining": "deny_overrides_strict", "rules": [
       {"id": "r1", "effect": "Permit", "target": [], "conditions": [
         {"op": "principal", "pairs": [["alice", "harness"]]},
         {"op": "eq", "field": "operation", "value": "read"}],
        "obligations": ["source_binding"]}], "required_obligations": []}

Conditions are strict-typed equality, set membership, exact user/Agent pairs,
or a finite inclusive-start/exclusive-end time window. Condition fields select
top-level request attributes only. All conditions within a rule are conjuncts.
An absent/malformed request value is unknown, not a business denial. A valid
false conjunct makes the rule NotApplicable even alongside an unknown one.

Only Permit with every mandatory obligation *exactly* True can deliver. Failed,
missing or invalid obligation outcomes retain Permit and a separate operational
status, rather than becoming a spurious correct business Deny. Callers must not
feed this reference's output back into the production execution path.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from itertools import product
import math

SCHEMA = "finite_policy_v1"
COMBINING = "deny_overrides_strict"
DECISIONS = ("Permit", "Deny", "NotApplicable", "Indeterminate")
_MISSING = object()
_RULE_KEYS = frozenset({"id", "effect", "target", "conditions", "obligations"})
_POLICY_KEYS = frozenset({"schema", "version", "combining", "rules", "required_obligations"})


def _names(value):
    return (isinstance(value, list) and all(isinstance(x, str) and bool(x) for x in value)
            and len(value) == len(set(value)))


def _scalar(value):
    return (type(value) in (str, bool, int) or
            type(value) is float and math.isfinite(value))


def _same(a, b):
    """Avoid Python's True == 1 and 1 == 1.0 implicit coercions."""
    return type(a) is type(b) and a == b


def _condition(condition, request):
    """Return (True/False/None, stable reason); never execute source text."""
    if not isinstance(condition, dict):
        return None, "invalid_condition"
    op = condition.get("op")
    if not isinstance(op, str):
        return None, "unsupported_condition"
    if op == "principal":
        if set(condition) != {"op", "pairs"} or not isinstance(condition["pairs"], list):
            return None, "invalid_principal_condition"
        pairs = condition["pairs"]
        if not all(isinstance(pair, list) and len(pair) == 2
                   and all(isinstance(x, str) and bool(x) for x in pair) for pair in pairs):
            return None, "invalid_principal_condition"
        if not pairs:
            return False, "empty_principal_scope"
        user, agent = request.get("user_id", _MISSING), request.get("agent_id", _MISSING)
        # A known impossible component makes the pair false, even if the other
        # component is absent. This is finite pair semantics, not a Cartesian ACL.
        if isinstance(user, str) and user and not any(pair[0] == user for pair in pairs):
            return False, "principal_mismatch"
        if isinstance(agent, str) and agent and not any(pair[1] == agent for pair in pairs):
            return False, "principal_mismatch"
        if not isinstance(user, str) or not user or not isinstance(agent, str) or not agent:
            return None, "principal_attribute_missing_or_invalid"
        return ([user, agent] in pairs), "principal_match" if [user, agent] in pairs else "principal_mismatch"
    if op not in {"eq", "in", "time_window"}:
        return None, "unsupported_condition"
    field = condition.get("field")
    if not isinstance(field, str) or not field:
        return None, "invalid_condition_field"
    value = request.get(field, _MISSING)
    if op == "eq":
        if set(condition) != {"op", "field", "value"} or not _scalar(condition["value"]):
            return None, "invalid_eq_condition"
        if value is _MISSING or not _scalar(value) or type(value) is not type(condition["value"]):
            return None, "attribute_missing_or_invalid:" + field
        matched = _same(value, condition["value"])
    elif op == "in":
        if (set(condition) != {"op", "field", "values"} or not isinstance(condition["values"], list)
                or not all(_scalar(x) for x in condition["values"])):
            return None, "invalid_membership_condition"
        if not condition["values"]:
            return False, "empty_membership:" + field
        if (value is _MISSING or not _scalar(value)
                or not any(type(value) is type(x) for x in condition["values"])):
            return None, "attribute_missing_or_invalid:" + field
        matched = any(_same(value, x) for x in condition["values"])
    else:
        start, end = condition.get("start"), condition.get("end")
        # Python integers are finite without conversion to a C double. Avoid
        # OverflowError on large JSON integers while still rejecting bool.
        numeric = lambda v: type(v) is int or type(v) is float and math.isfinite(v)
        if (set(condition) != {"op", "field", "start", "end"}
                or not numeric(start) or not numeric(end) or start >= end):
            return None, "invalid_time_window_condition"
        if not numeric(value):
            return None, "attribute_missing_or_invalid:" + field
        matched = start <= value < end
    return matched, ("match:" if matched else "mismatch:") + field


def _conjunction(conditions, request):
    observations = [_condition(c, request) for c in conditions]
    if any(result is False for result, _ in observations):
        return False, [reason for result, reason in observations if result is False]
    if any(result is None for result, _ in observations):
        return None, [reason for result, reason in observations if result is None]
    return True, []


def _rule(rule, request, index):
    fallback = "rule_" + str(index)
    if (not isinstance(rule, dict) or set(rule) - _RULE_KEYS
            or not isinstance(rule.get("id"), str) or not rule["id"]
            or not isinstance(rule.get("effect"), str) or rule["effect"] not in {"Permit", "Deny"}
            or not isinstance(rule.get("target", []), list)
            or not isinstance(rule.get("conditions", []), list)
            or not _names(rule.get("obligations", []))):
        return {"id": fallback, "decision": "Indeterminate", "reasons": ["invalid_rule"], "obligations": []}
    # Target and rule conditions both identify applicability in this restricted
    # language. There is no invented distinction between 'false Deny condition'
    # and a matching business rejection: rejection is an explicit Deny rule.
    match, reasons = _conjunction(rule.get("target", []) + rule.get("conditions", []), request)
    decision = "NotApplicable" if match is False else "Indeterminate" if match is None else rule["effect"]
    return {"id": rule["id"], "decision": decision, "reasons": reasons,
            "obligations": list(rule.get("obligations", [])) if decision == "Permit" else []}


def _invalid(reason):
    return {"schema": SCHEMA, "policy_version": None, "decision": "Indeterminate",
            "deliver": False, "reasons": [reason], "rules": [], "obligations": [],
            "enforcement_status": "not_deliverable", "combining": COMBINING}


def evaluate(policy: dict, request: dict, obligations: dict | None = None) -> dict:
    """Evaluate one independently declared request under the frozen finite model.

    ``obligations`` supplies observed enforcement outcomes, not policy grants.
    Extra outcomes cannot satisfy a differently named mandatory obligation.
    Authentication/tool/database/budget failures should be stored separately by
    the harness; this function never infers them to be a business Deny.
    """
    if (not isinstance(policy, dict) or set(policy) - _POLICY_KEYS
            or policy.get("schema") != SCHEMA
            or not isinstance(policy.get("version"), str) or not policy["version"]
            or policy.get("combining") != COMBINING
            or not isinstance(policy.get("rules"), list)
            or not _names(policy.get("required_obligations", []))):
        return _invalid("invalid_or_unsupported_policy")
    if not isinstance(request, dict):
        return _invalid("invalid_request")
    ids = [rule.get("id") for rule in policy["rules"] if isinstance(rule, dict)]
    if len([x for x in ids if isinstance(x, str)]) != len(set(x for x in ids if isinstance(x, str))):
        return _invalid("duplicate_rule_id")
    rules = [_rule(rule, request, index) for index, rule in enumerate(policy["rules"])]
    decisions = {r["decision"] for r in rules}
    decision = next((d for d in ("Deny", "Indeterminate", "Permit") if d in decisions), "NotApplicable")
    reasons = [reason for rule in rules if rule["decision"] == decision for reason in rule["reasons"]]
    if not reasons:
        reasons = ["explicit_deny" if decision == "Deny" else "explicit_permit" if decision == "Permit"
                   else "no_applicable_rule" if decision == "NotApplicable" else "indeterminate_rule"]
    required = set(policy.get("required_obligations", []))
    if decision == "Permit":
        required.update(name for rule in rules if rule["decision"] == "Permit" for name in rule["obligations"])
    outcomes = obligations if isinstance(obligations, dict) else {}
    obligation_rows = []
    for name in sorted(required) if decision == "Permit" else []:
        actual = outcomes.get(name, _MISSING)
        status = "succeeded" if actual is True else "failed" if actual is False else "missing" if actual is _MISSING else "invalid"
        obligation_rows.append({"id": name, "status": status})
    satisfied = all(row["status"] == "succeeded" for row in obligation_rows)
    if decision != "Permit":
        status = "not_deliverable"
    elif not isinstance(obligations, dict) and obligations is not None:
        status = "invalid_obligation_outcomes"
        reasons.append("invalid_obligation_outcomes")
        satisfied = False
    elif not satisfied:
        status = "obligations_unsatisfied"
        reasons += ["obligation_" + row["status"] + ":" + row["id"] for row in obligation_rows if row["status"] != "succeeded"]
    else:
        status = "deliverable"
    return {"schema": SCHEMA, "policy_version": policy["version"], "decision": decision,
            "deliver": decision == "Permit" and satisfied, "reasons": reasons, "rules": rules,
            "obligations": obligation_rows, "enforcement_status": status, "combining": COMBINING}


def enumerate_requests(domains: Mapping[str, list]) -> Iterator[dict]:
    """Enumerate a declared Cartesian *request domain*, never a principal ACL.

    Domains must be a finite mapping of attribute names to nonempty lists of
    JSON scalar values. Use explicit request records for missing-field cases.
    No randomization or claim about unregistered subjects is involved.
    """
    if not isinstance(domains, Mapping) or not domains:
        raise ValueError("finite_domains_required")
    if any(not isinstance(name, str) or not name for name in domains):
        raise ValueError("invalid_domain_field")
    names = sorted(domains)
    if any(not isinstance(domains[name], list) or not domains[name]
           or not all(_scalar(value) for value in domains[name]) for name in names):
        raise ValueError("nonempty_scalar_domains_required")
    for values in product(*(domains[name] for name in names)):
        yield dict(zip(names, values))


def evaluate_domain(policy: dict, domains: Mapping[str, list], *, obligations: dict | None = None) -> list[dict]:
    """Return every declared request and its independent reference decision."""
    return [{"request": request, "reference": evaluate(policy, request, obligations)}
            for request in enumerate_requests(domains)]
