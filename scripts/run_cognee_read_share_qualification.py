"""Bounded native capability qualification; not the 25-case policy matrix.

Two explicit cycles separate ordinary read/share revocation from interaction
with an independently controller-granted child. No model or native execution
occurs in plan-only mode or fake tests. The frozen worker is not modified.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_native_exact_fact_bridge import WorkerRPC, verify_sha_table

VERSION = "cognee_read_share_independent_child_qualification_v1"
WHEEL_SHA256 = "aaef9fdc02f542b1d125cde21759dde2fac56355d8928e39c734e7b5c6705eca"
MAX_HTTP = 48
EXPECTED_VALUE = "SYNTHETIC_VALUE_A71"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False); stream.write("\n")


class QualificationStop(ValueError):
    pass


def fact_from_proposal(proposal):
    facts = [f for f in proposal["facts"] if f["object_id"] == "fact.readonly"]
    if len(facts) != 1:
        raise ValueError("unique_readonly_fact_required")
    fact = facts[0]
    source = [s for s in proposal["sources"] if s["source_id"] == fact["source_id"]]
    if (len(source) != 1 or fact["text"] != EXPECTED_VALUE or
        hashlib.sha256(fact["text"].encode()).hexdigest() != fact["content_sha256"] or
        source[0]["text"][fact["source_start"]:fact["source_end"]] != fact["text"]):
        raise ValueError("exact_proposal_readonly_fact_required")
    return deepcopy(fact)


def build_plan(*, python, wheel, legacy, proposal, identity_receipt, state=None):
    python, wheel, legacy, proposal, identity_receipt = map(lambda p: Path(p).resolve(),
        (python, wheel, legacy, proposal, identity_receipt))
    if sha(wheel) != WHEEL_SHA256:
        raise ValueError("fixed_cognee_wheel_required")
    prerequisite = json.loads(identity_receipt.read_bytes())
    if (prerequisite.get("status") != "qualified" or prerequisite.get("postflight", {}).get("status") != "passed"
        or not prerequisite.get("checks") or not all(v is True for v in prerequisite["checks"].values())):
        raise ValueError("native_identity_prerequisite_not_qualified")
    selected = fact_from_proposal(json.loads(proposal.read_bytes()))
    temp_root = Path(tempfile.gettempdir()).resolve()
    state = Path(state).resolve() if state else temp_root / ("agent_memory_cognee_readshare_" + uuid.uuid4().hex)
    if state.parent != temp_root or not str(state).isascii() or state.exists():
        raise ValueError("new_ascii_system_temp_child_required")
    sources = [ROOT / "scripts" / n for n in ("run_cognee_read_share_qualification.py", "native_cognee_policy_worker.py",
        "native_exact_fact_common.py", "run_native_exact_fact_bridge.py")]
    sources += [legacy / "scripts/cognee_local_migration_probe.py"]
    hashes = {str(p.resolve()): sha(p) for p in sources}
    return {"version": VERSION, "python": str(python), "wheel": str(wheel), "wheel_sha256": WHEEL_SHA256,
        "legacy": str(legacy), "state": str(state), "proposal": str(proposal), "proposal_sha256": sha(proposal),
        "identity_receipt": str(identity_receipt), "identity_receipt_sha256": sha(identity_receipt),
        "code_sha256": hashes, "code_archive": [{"source": str(p.resolve()),
            "archive": f"implementation/source_{i}_{p.name}", "sha256": sha(p)} for i, p in enumerate(sources)],
        "fact": selected, "trusted_importer": "owner", "recipient": "assistant", "outsider": "outsider",
        "max_native_http_requests": MAX_HTTP, "expected_full_path_http_requests": 37,
        "max_datasets": 1, "max_imported_facts": 1, "max_children": 1, "max_model_calls": 0,
        "ordinary_cycle": ["owner_positive", "outsider_negative", "root_grants_assistant_read", "assistant_positive",
            "assistant_cannot_grant_outsider_read", "outsider_still_negative", "optional_child_discovery_without_direct_grant",
            "root_revokes_assistant_read", "assistant_negative"],
        "independent_child_cycle": ["root_regrants_assistant_read", "assistant_positive", "root_directly_grants_child_read",
            "child_positive", "root_revokes_assistant_direct_read", "parent_actual_read_observed", "child_actual_read_observed"],
        "stop_rule": "Immediate stop on outsider disclosure, scope/inference/network/asset failure. Child mechanism unknown stops its branch; ordinary user phases retained. Authentication/null/errors never count as object denial.",
        "scope": "Native capability qualification on one synthetic exact fact, not migration projection or the 25-case matrix."}


def read_classification(result, text):
    trace = result.get("trace", {})
    raw, status = trace.get("native_raw_body"), result.get("status")
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else None
    except (ValueError, TypeError):
        parsed = raw
    def strings(value):
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for v in value.values() for s in strings(v)]
        if isinstance(value, list):
            return [s for v in value for s in strings(v)]
        return []
    observed = (isinstance(raw, str) and text in raw) or any(text in s for s in strings(parsed))
    if (trace.get("response_checked") is not True or trace.get("execution_error") is not None or not isinstance(raw, str)
        or trace.get("status") != status or trace.get("cookie_present") is not False
        or hashlib.sha256(raw.encode()).hexdigest() != trace.get("native_body_sha256")):
        return {"state": "unqualified_trace", "full_content_observed": bool(observed), "ready": False}
    if status == 401:
        state = "authentication_error"
    elif status is None or not isinstance(status, int) or status >= 500:
        state = "execution_error"
    elif raw.strip() == "null":
        state = "null_response"
    elif status == 200 and raw == text:
        state = "available"
    elif status in {403, 404} and not observed:
        state = "denied"
    else:
        state = "unready_response"
    return {"state": state, "full_content_observed": observed, "ready": state in {"available", "denied"}}


def action_classification(result, operation):
    trace = result.get("trace", {})
    raw, status = trace.get("native_raw_body"), result.get("status")
    if (trace.get("response_checked") is not True or trace.get("execution_error") is not None or not isinstance(raw, str)
        or trace.get("status") != status or trace.get("cookie_present") is not False
        or not (trace.get("authorization_present") is True or trace.get("api_key_present") is True)
        or hashlib.sha256(raw.encode()).hexdigest() != trace.get("native_body_sha256")):
        return "unqualified_trace"
    try:
        value = json.loads(raw)
    except ValueError:
        return "unready_response"
    if status == 401:
        return "authentication_error"
    if value is None:
        return "null_response"
    if status == 403 and isinstance(value, dict):
        return "denied"
    message = "Permission assigned to principal" if operation == "grant" else "Permission revoked from principal"
    return "accepted_requires_postcondition" if status == 200 and value == {"message": message} else "unready_response"


def execute_protocol(worker, fact, *, pre_call=lambda: None, persist=lambda value: None):
    """Actual RPC schedule, also testable using an explicitly fake RPC object."""
    events, outcomes = [], {"basic_user_read": None, "read_not_share": None, "basic_user_revocation": None,
        "child_identity": None, "child_initial_read": None, "child_after_first_parent_revocation": None,
        "independent_child_read_retained": None, "parent_read_after_independent_child_grant": None,
        "final_owner_access": None, "final_outsider_denial": None}
    state = {"events": events, "outcomes": outcomes, "child_unknown": None, "stop_reason": None}

    def call(phase, command, data):
        pre_call()
        try:
            result = worker.call(command, data)
        except Exception as error:
            events.append({"phase": phase, "command": command, "rpc_failed": True, "exception_type": type(error).__name__})
            persist(state); raise
        events.append({"phase": phase, "command": command, "input": deepcopy(data), "result": deepcopy(result)})
        persist(state)
        if command in {"read_raw", "grant", "revoke", "whoami"} and result.get("trace", {}).get("actor") != data["actor"]:
            raise QualificationStop("native_actor_trace_changed")
        return result

    def read(phase, actor, expectation):
        result = call(phase, "read_raw", {"dataset": "qualification", "fact_key": "readonly", "actor": actor})
        observed = read_classification(result, fact["text"])
        credential = result.get("trace", {})
        authentic = (credential.get("api_key_present") is True and credential.get("authorization_present") is False) if actor == "assistant_agent" else (credential.get("authorization_present") is True and credential.get("api_key_present") is False)
        if not authentic:
            observed = {**observed, "state": "authentication_unqualified", "ready": False}
        events[-1]["assessment"] = observed; persist(state)
        if actor == "outsider" and observed["full_content_observed"]:
            state["stop_reason"] = "unauthorized_fact_disclosure"; persist(state)
            raise QualificationStop(state["stop_reason"])
        if not observed["ready"]:
            raise QualificationStop("raw_read_not_qualified")
        if expectation != "discovery" and observed["state"] != expectation:
            raise QualificationStop("raw_read_postcondition_failed")
        return observed

    def permission(phase, operation, actor, recipient, expected="accepted_requires_postcondition"):
        result = call(phase, operation, {"dataset": "qualification", "actor": actor,
            "recipient": recipient, "permission": "read"})
        observed = action_classification(result, operation)
        events[-1]["assessment"] = {"state": observed}; persist(state)
        if observed != expected:
            raise QualificationStop("permission_action_not_qualified")

    try:
        call("create_controller_owned_dataset", "create_dataset", {"dataset": "qualification", "actor": "owner"})
        call("native_exact_plaintext_add", "add_exact_fact", {"dataset": "qualification", "actor": "owner",
            "fact_key": "readonly", "text": fact["text"]})
        read("owner_positive", "owner", "available")
        read("outsider_before_grant", "outsider", "denied")
        permission("owner_grants_assistant_read", "grant", "owner", "assistant")
        read("assistant_read_only_positive", "assistant", "available")
        outcomes["basic_user_read"] = True
        # Always check outsider after the attempt, even an unexpected action response.
        attempted = call("assistant_attempts_share", "grant", {"dataset": "qualification", "actor": "assistant",
            "recipient": "outsider", "permission": "read"})
        share_state = action_classification(attempted, "grant")
        events[-1]["assessment"] = {"state": share_state}; persist(state)
        read("outsider_after_share_attempt", "outsider", "denied")
        outcomes["read_not_share"] = share_state == "denied"
        if share_state not in {"denied", "accepted_requires_postcondition"}:
            raise QualificationStop("share_attempt_not_qualified")

        child_ok = False
        try:
            child = call("child_creation", "create_child", {"actor": "assistant", "child": "assistant_agent"})
            who = call("child_explicit_whoami", "whoami", {"actor": "assistant_agent"})
            trace = who.get("trace", {})
            body = json.loads(trace.get("native_raw_body", "null"))
            identity = child["identity"]
            if (who.get("status") != 200 or trace.get("response_checked") is not True or trace.get("execution_error") is not None
                or trace.get("api_key_present") is not True or trace.get("cookie_present") is not False or not isinstance(body, dict)
                or body.get("id") != identity["id"] or body.get("parent_user_id") != identity["parent_user_id"]
                or body.get("is_superuser") is not False):
                raise QualificationStop("child_identity_unqualified")
            outcomes["child_identity"] = True
            initial = read("child_initial_read_discovery", "assistant_agent", "discovery")
            outcomes["child_initial_read"] = initial["state"]; child_ok = True
        except Exception as error:
            state["child_unknown"] = {"stage": "identity_or_initial_read", "phase": events[-1]["phase"], "exception_type": type(error).__name__}

        permission("owner_revokes_assistant_basic_read", "revoke", "owner", "assistant")
        read("assistant_after_basic_revocation", "assistant", "denied")
        outcomes["basic_user_revocation"] = True
        if child_ok:
            try:
                outcomes["child_after_first_parent_revocation"] = read("child_after_basic_parent_revocation_discovery", "assistant_agent", "discovery")["state"]
                permission("second_cycle_regrant_assistant", "grant", "owner", "assistant")
                read("second_cycle_assistant_positive", "assistant", "available")
                permission("independent_root_grants_child", "grant", "owner", "assistant_agent")
                read("independent_child_positive", "assistant_agent", "available")
                permission("second_cycle_revokes_parent_direct_read", "revoke", "owner", "assistant")
                # A native parent's reachability of child grants is an observation,
                # not fraud, a product bug, or a rewrite of the first cycle score.
                outcomes["parent_read_after_independent_child_grant"] = read("parent_after_independent_child_grant_discovery", "assistant", "discovery")["state"]
                retained = read("independent_child_after_parent_revocation", "assistant_agent", "available")
                outcomes["independent_child_read_retained"] = retained["state"] == "available"
            except Exception as error:
                state["child_unknown"] = {"stage": "independent_root_grant_cycle", "phase": events[-1]["phase"], "exception_type": type(error).__name__}
        read("owner_final_positive", "owner", "available"); outcomes["final_owner_access"] = True
        read("outsider_final_negative", "outsider", "denied"); outcomes["final_outsider_denial"] = True
    except Exception as error:
        state["stop_reason"] = state["stop_reason"] or (str(error) if isinstance(error, QualificationStop) else "native_protocol_failed")
        state["failure"] = {"exception_type": type(error).__name__}
    persist(state)
    return state


def run(output, *, python, wheel, legacy, proposal, identity_receipt, approved_plan=None, execute=False, rpc_factory=WorkerRPC):
    output = Path(output).resolve()
    if output.exists() or output == ROOT / "results" or not output.is_relative_to((ROOT / "results").resolve()):
        raise ValueError("new_workspace_results_required")
    approved = json.loads(Path(approved_plan).read_bytes()) if approved_plan else None
    plan = build_plan(python=python, wheel=wheel, legacy=legacy, proposal=proposal, identity_receipt=identity_receipt,
        state=approved["state"] if approved else None)
    if execute and (approved is None or plan != approved):
        raise ValueError("approved_plan_must_match_before_native_execution")
    output.mkdir(parents=True)
    (output / "implementation").mkdir()
    for item in plan["code_archive"]:
        data = Path(item["source"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("source_changed_before_archive")
        target = output / item["archive"]; target.write_bytes(data)
        if sha(target) != item["sha256"]:
            raise ValueError("archived_source_sha256_mismatch")
    save(output / "plan.json", plan)
    (output / "proposal.json").write_bytes(Path(proposal).read_bytes())
    if sha(output / "proposal.json") != plan["proposal_sha256"]:
        raise ValueError("proposal_changed_during_archive")
    if not execute:
        return {"status": "plan_only", "plan_sha256": sha(output / "plan.json"), "model_calls": 0, "native_calls": 0}
    worker, runtime, final, protocol, failure = None, None, {}, None, None
    def pre_call():
        if verify_sha_table(plan["code_sha256"])["status"] != "passed" or sha(proposal) != plan["proposal_sha256"]:
            raise QualificationStop("frozen_source_or_proposal_changed")
    def persist(value):
        (output / "phase_progress.json").write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        pre_call()
        worker = rpc_factory(python, ROOT / "scripts/native_cognee_policy_worker.py", ["--state", plan["state"],
            "--wheel", wheel, "--legacy-project", legacy, "--http-cap", str(MAX_HTTP)], timeout=240)
        runtime = worker.call("init", {})
        identities = runtime.get("identities", {})
        if (set(identities) != {"owner", "assistant", "outsider"} or len({x["id"] for x in identities.values()}) != 3
            or not all(x.get("is_superuser") is False for x in identities.values()) or runtime.get("wheel_sha256") != WHEEL_SHA256
            or runtime.get("limits", {}).get("http_requests") != MAX_HTTP):
            raise QualificationStop("fresh_native_identity_unqualified")
        protocol = execute_protocol(worker, plan["fact"], pre_call=pre_call, persist=persist)
    except Exception as error:
        failure = {"exception_type": type(error).__name__, "code": str(error) if isinstance(error, QualificationStop) else "native_qualification_failed"}
    finally:
        if worker is not None:
            try:
                final = worker.call("close", {})
            except Exception as error:
                final = {"close_error": {"exception_type": type(error).__name__}}
            save(output / "rpc_receipts.json", worker.calls); worker.terminate()
    postflight = {"code": verify_sha_table(plan["code_sha256"]), "wheel_identical": sha(wheel) == plan["wheel_sha256"],
        "proposal_identical": sha(proposal) == plan["proposal_sha256"], "identity_receipt_identical": sha(identity_receipt) == plan["identity_receipt_sha256"]}
    requests = final.get("native_requests")
    instrumentation = {"physical_http_cap": isinstance(requests, list) and len(requests) <= MAX_HTTP,
        "zero_observed_inference": final.get("generation_attempts") == final.get("embedding_attempts") == 0,
        "network_clear": isinstance(final.get("network_events"), list) and all(x.get("allowed") is True for x in final["network_events"]),
        "credentials_omitted": final.get("client_credential_values_persisted") is False,
        "fixed_http_cap": final.get("limits", {}).get("http_requests") == MAX_HTTP,
        "one_dataset_one_fact": len(final.get("datasets", {})) == len(final.get("facts", {})) == 1,
        "postflight": postflight["code"]["status"] == "passed" and postflight["wheel_identical"] and postflight["proposal_identical"] and postflight["identity_receipt_identical"]}
    outcomes = protocol["outcomes"] if protocol else {}
    user_ok = all(outcomes.get(k) is True for k in ("basic_user_read", "read_not_share", "basic_user_revocation"))
    qualified = failure is None and protocol is not None and protocol["stop_reason"] is None and user_ok and all(instrumentation.values())
    report = {"version": VERSION, "status": ("user_qualified_child_unknown" if protocol["child_unknown"] else "qualified") if qualified else "not_qualified",
        "runtime": runtime, "protocol": protocol, "final": final, "failure": failure, "instrumentation": instrumentation,
        "basic_user_read_share_revocation_qualified": user_ok, "postflight": postflight,
        "physical_native_http_requests": len(requests) if isinstance(requests, list) else None,
        "observed_generation_attempts": final.get("generation_attempts"), "observed_embedding_attempts": final.get("embedding_attempts"),
        "source_policy_projection_performed": False, "all_25_projection_entries_remain_unverified": True,
        "scope": plan["scope"]}
    save(output / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true"); mode.add_argument("--execute", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    parser.add_argument("--python", type=Path, default=ROOT / ".venv-native-cognee/Scripts/python.exe")
    parser.add_argument("--wheel", type=Path, default=ROOT / ".runtime/native_cognee_wheel/cognee-1.6.5-py3-none-any.whl")
    parser.add_argument("--legacy", type=Path, default=ROOT / "memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
    parser.add_argument("--proposal", type=Path, default=ROOT / "docs/proposals/source_policy_projection_contract_v1_20261026.json")
    parser.add_argument("--identity-receipt", type=Path, default=ROOT / "results/cognee_identity_qualification_20261026_v1/report.json")
    args = parser.parse_args()
    result = run(args.output, python=args.python, wheel=args.wheel, legacy=args.legacy, proposal=args.proposal,
        identity_receipt=args.identity_receipt, approved_plan=args.approved_plan, execute=args.execute)
    print(json.dumps({k: result[k] for k in ("status", "physical_native_http_requests", "instrumentation") if k in result}, ensure_ascii=False))
    raise SystemExit(0 if result["status"] in {"plan_only", "qualified", "user_qualified_child_unknown"} else 1)
