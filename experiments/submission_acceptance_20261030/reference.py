"""Independent decision table for a bounded Qoder -> Harness host contract.

This module reads no files, imports no executor, and grants no execution rights.
The caller supplies trusted declarations and an independently recorded state.
This is neither FACPL nor a model of arbitrary Agent authorization semantics.

Known violated requirements dominate unknown requirements. Only a fully known
Permit is deliverable. ``state=None`` denotes the declared initial state; an
explicit state must carry both strict boolean fields. Unknown operation names
are NotApplicable only when no known binding requirement has already failed.
"""

VERSION = "submission-independent-reference-v1"


def _result(decision, reason):
    return {"decision": decision, "deliver": decision == "Permit", "reason": reason}


def _identifier(value):
    return isinstance(value, str) and bool(value) and value == value.strip()


def judge(case, fact, request, state=None):
    """Judge one finite exact-source request without consulting observed output.

    Operations are ``read``, ``handoff`` and ``restore``. Handoff requires the
    sender and receiver's read grants plus independent export and copy grants.
    Restore requires current receiver read plus an explicit restore grant.
    Both operations target exactly (alice, harness); read supports every exact
    user-Agent pair declared in ``allowed_principals``. Origin is an exact
    nonempty source substring. Summaries and inferred dependence are unsupported.
    """
    if not all(isinstance(value, dict) for value in (case, fact, request)):
        return _result("Indeterminate", "invalid_input_container")
    denies, unknowns = [], []

    def bound(field, expected):
        actual = request.get(field)
        if not _identifier(actual) or not _identifier(expected):
            unknowns.append("missing_or_invalid:" + field)
        elif actual != expected:
            denies.append("binding_mismatch:" + field)

    source = case.get("source")
    if not isinstance(source, dict):
        unknowns.append("missing_or_invalid:source")
        source = {}
    bound("resource_id", fact.get("fact_id"))
    bound("source_id", source.get("source_id"))
    for field, value in (("policy_version", "journal-v1"), ("audience", "harness"),
                         ("model_recipient", "harness-model-provider")):
        bound(field, value)

    now = request.get("now")
    if type(now) is not int:
        unknowns.append("missing_or_invalid:now")
    elif not 0 <= now < 200:
        denies.append("outside_time_window")

    origin = fact.get("declared_origin_source_id", source.get("source_id"))
    if not _identifier(origin) or not _identifier(source.get("source_id")):
        unknowns.append("missing_or_invalid:origin_source_id")
    elif origin != source["source_id"]:
        denies.append("origin_source_mismatch")
    text, start, end = fact.get("text"), fact.get("start"), fact.get("end")
    source_text = source.get("text")
    if (not isinstance(text, str) or not text.strip() or not isinstance(source_text, str)
            or type(start) is not int or type(end) is not int):
        unknowns.append("missing_or_invalid:exact_source_span")
    elif not (0 <= start < end <= len(source_text) and source_text[start:end] == text):
        denies.append("exact_source_span_mismatch")

    pairs = fact.get("allowed_principals")
    pairs_valid = isinstance(pairs, list) and all(
        isinstance(pair, dict) and set(pair) == {"user_id", "agent_id"}
        and all(_identifier(value) for value in pair.values()) for pair in pairs)
    if not pairs_valid:
        unknowns.append("missing_or_invalid:allowed_principals")
        pairs = []
    normalized = {(pair["user_id"], pair["agent_id"]) for pair in pairs}
    user, agent = request.get("user_id"), request.get("agent_id")
    user_valid, agent_valid = _identifier(user), _identifier(agent)
    if not user_valid:
        unknowns.append("missing_or_invalid:user_id")
    if not agent_valid:
        unknowns.append("missing_or_invalid:agent_id")
    if pairs_valid:
        if (not pairs or user_valid and not any(pair[0] == user for pair in normalized)
                or agent_valid and not any(pair[1] == agent for pair in normalized)
                or user_valid and agent_valid and (user, agent) not in normalized):
            denies.append("principal_not_granted")

    operation = request.get("operation")
    if not _identifier(operation):
        unknowns.append("missing_or_invalid:operation")
    elif operation in {"handoff", "restore"}:
        if user_valid and user != "alice" or agent_valid and agent != "harness":
            denies.append("recipient_scope_mismatch")
        required = ("export_allowed", "copy_allowed") if operation == "handoff" else ("restore_allowed",)
        for permission in required:
            if type(fact.get(permission)) is not bool:
                unknowns.append("missing_or_invalid:" + permission)
            elif fact[permission] is False:
                denies.append("not_granted:" + permission)
        if operation == "handoff" and pairs_valid and ("alice", "qoder") not in normalized:
            denies.append("sender_read_not_granted")

    if state is None:
        state = {"revoked": False, "authority_unknown": False}
    if not isinstance(state, dict):
        unknowns.append("missing_or_invalid:state")
    else:
        for flag in ("revoked", "authority_unknown"):
            if type(state.get(flag)) is not bool:
                unknowns.append("missing_or_invalid:state." + flag)
        if state.get("revoked") is True:
            denies.append("grant_revoked")
        if state.get("authority_unknown") is True:
            unknowns.append("current_authority_unknown")

    if denies:
        return _result("Deny", denies[0])
    if unknowns:
        return _result("Indeterminate", unknowns[0])
    if operation not in {"read", "handoff", "restore"}:
        return _result("NotApplicable", "unsupported_operation")
    return _result("Permit", "all_contract_requirements_satisfied")
