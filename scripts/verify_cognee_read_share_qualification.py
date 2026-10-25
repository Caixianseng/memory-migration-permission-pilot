"""Independent standard-library saved-evidence audit; no Cognee/native calls."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from uuid import UUID
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WHEEL_SHA = "aaef9fdc02f542b1d125cde21759dde2fac56355d8928e39c734e7b5c6705eca"
VALUE = "SYNTHETIC_VALUE_A71"
EXPLANATION_FILES = (
    "cognee/modules/data/methods/get_authorized_existing_datasets.py",
    "cognee/modules/users/permissions/methods/get_specific_user_permission_datasets.py",
    "cognee/modules/users/permissions/methods/get_all_user_permission_datasets.py",
    "cognee/modules/users/methods/get_user_agents.py",
    "cognee/modules/users/permissions/methods/get_principal_datasets.py",
    "cognee/modules/users/permissions/methods/authorized_give_permission_on_datasets.py",
    "cognee/modules/users/permissions/methods/authorized_revoke_permission_on_datasets.py",
    "cognee/modules/users/permissions/methods/revoke_permission_on_dataset.py",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate_json_key")
            result[k] = v
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def same(a, b):
    return json.dumps(a, sort_keys=True, ensure_ascii=False) == json.dumps(b, sort_keys=True, ensure_ascii=False)


def verify(run, failed_run, identity_run, output):
    run, failed_run, identity_run, output = map(lambda p: Path(p).resolve(), (run, failed_run, identity_run, output))
    checks = []
    def check(name, condition):
        checks.append({"check": name, "passed": bool(condition)})
    report, plan = load(run / "report.json"), load(run / "plan.json")
    rpc, final = load(run / "rpc_receipts.json"), report["final"]
    requests, identities = final["native_requests"], final["identities"]
    state = Path(plan["state"]).resolve()
    check("terminal_report", report["status"] == "qualified" and report["failure"] is None and report["protocol"]["stop_reason"] is None)
    check("exact_http_budget", len(requests) == 37 <= plan["max_native_http_requests"] == 48 and report["physical_native_http_requests"] == 37)
    check("zero_inference_and_network_failures", final["generation_attempts"] == final["embedding_attempts"] == 0 and not final["inference_events"] and all(x["allowed"] is True for x in final["network_events"]))
    check("no_saved_client_credentials", final["client_credential_values_persisted"] is False)
    check("no_full_projection_claim", report["source_policy_projection_performed"] is False and report["all_25_projection_entries_remain_unverified"] is True)
    for name, value in report["instrumentation"].items():
        check("producer_instrumentation_" + name, value is True)
    for name, expected in plan["code_sha256"].items():
        check("current_code_" + Path(name).name, sha(name) == expected)
    for item in plan["code_archive"]:
        check("executed_archive_" + Path(item["source"]).name, sha(run / item["archive"]) == item["sha256"] == plan["code_sha256"][item["source"]])
    for field, key in (("proposal", "proposal_sha256"), ("identity_receipt", "identity_receipt_sha256")):
        check("frozen_input_" + field, sha(plan[field]) == plan[key])
    check("archived_proposal_same", sha(run / "proposal.json") == plan["proposal_sha256"])
    check("wheel_fixed", sha(plan["wheel"]) == WHEEL_SHA == plan["wheel_sha256"])
    vendor_hashes = dict(report["runtime"]["vendor_source_sha256"])
    interpretation_hashes = {}
    installed = ROOT / ".venv-native-cognee/Lib/site-packages"
    with zipfile.ZipFile(plan["wheel"]) as archive:
        check("eleven_runtime_vendor_files", len(vendor_hashes) == 11)
        for name, expected in vendor_hashes.items():
            check("vendor_" + name, digest(archive.read(name)) == expected == sha(installed / name))
        for name in EXPLANATION_FILES:
            expected = digest(archive.read(name)); interpretation_hashes[name] = expected
            check("interpretation_source_" + name, sha(installed / name) == expected)
    check("native_state_scope", str(state).isascii() and state.exists() and report["runtime"]["file_scope"] == final["file_scope"] and all(final["file_scope"][k] is True for k in ("all_official_roots_within_state", "state_internal_resolution_allowed", "outside_state_resolution_denied")))
    check("scope_probe_did_not_create_files", final["file_scope"]["probe_files_created"] is False)
    check("four_distinct_native_principals", set(identities) == {"owner", "assistant", "outsider", "assistant_agent"} and len({x["id"] for x in identities.values()}) == 4 and all(x["is_superuser"] is False for x in identities.values()))
    for actor, identity in identities.items():
        check("uuid_" + actor, str(UUID(identity["id"])) == identity["id"])
    check("native_child_parent_binding", identities["assistant_agent"]["parent_user_id"] == identities["assistant"]["id"] and identities["assistant_agent"]["credential_kind"] == "api_key")
    raw_files, auth_omitted = [], 0
    for index, row in enumerate(requests):
        prefix = "http_" + str(index) + "_"
        check(prefix + "index_clock_cookie", row["index"] == index and row["started_ns"] <= row["finished_ns"] and row["cookie_present"] is False)
        if row["credential_response_omitted"]:
            auth_omitted += 1
            check(prefix + "no_auth_body_or_digest", not set(row).intersection({"native_raw_body", "native_body_sha256", "request_json", "request_data", "request_params", "native_response_file"}))
            check(prefix + "no_auth_bin", not (state / "safe_responses" / f"{index:04d}.bin").exists())
            continue
        raw = row["native_raw_body"].encode("utf-8"); path = Path(row["native_response_file"]).resolve()
        check(prefix + "actual_bin_and_sha", path.is_relative_to(state / "safe_responses") and path.read_bytes() == raw and digest(raw) == row["native_body_sha256"] and len(raw) == row["byte_count"])
        check(prefix + "response_ready", row["response_checked"] is True and row["execution_error"] is None)
        raw_files.append(path.name)
        if row["actor"] == "assistant_agent":
            check(prefix + "key_only", row["api_key_present"] is True and row["authorization_present"] is False)
        elif row["actor"] is not None:
            check(prefix + "bearer_only", row["authorization_present"] is True and row["api_key_present"] is False)
        if row["path"] == "/api/v1/users/me" and row["actor"]:
            body = json.loads(raw); expected = identities[row["actor"]]
            check(prefix + "actual_identity_json", row["status"] == 200 and body["id"] == expected["id"] and body["is_superuser"] is False and body.get("parent_user_id") == expected["parent_user_id"])
    check("raw_vs_auth_counts", auth_omitted == 7 and len(raw_files) == 30 and {p.name for p in (state / "safe_responses").glob("*.bin")} == set(raw_files))
    check("strict_native_clock_order", all(a["finished_ns"] <= b["started_ns"] for a, b in zip(requests, requests[1:])))
    protocol = report["protocol"]; events = protocol["events"]
    check("exact_rpc_phase_sequence", len(rpc) == len(events) + 2 and [r["command"] for r in rpc] == ["init"] + [e["command"] for e in events] + ["close"])
    check("rpc_no_error", all("error" not in row for row in rpc))
    check("rpc_init_and_close", same(rpc[0]["result"], report["runtime"]) and same(rpc[-1]["result"], final))
    for event, receipt in zip(events, rpc[1:-1]):
        check("rpc_phase_" + event["phase"], same(event["input"], receipt["input"]) and same(event["result"], receipt["result"]))
    fact = plan["fact"]
    check("exact_one_proposal_fact", fact["object_id"] == "fact.readonly" and fact["text"] == VALUE and digest(VALUE.encode()) == fact["content_sha256"] and len(final["datasets"]) == len(final["facts"]) == 1)
    adds = [r for r in requests if r["path"] == "/api/v1/add"]
    check("exact_same_raw_data_transport", len(adds) == 1 and adds[0]["status"] == 200 and adds[0]["request_data"]["raw_data"] == VALUE and adds[0]["request_data"]["run_in_background"] == "false" and "request_files" not in adds[0])
    dataset = final["datasets"]["qualification"]
    check("trusted_owner_dataset", dataset["owner"] == "owner" and final["facts"]["readonly"]["text_sha256"] == fact["content_sha256"])
    expected_reads = {
        "owner_positive": ("owner", 200, True), "outsider_before_grant": ("outsider", 403, False),
        "assistant_read_only_positive": ("assistant", 200, True), "outsider_after_share_attempt": ("outsider", 403, False),
        "child_initial_read_discovery": ("assistant_agent", 403, False), "assistant_after_basic_revocation": ("assistant", 403, False),
        "child_after_basic_parent_revocation_discovery": ("assistant_agent", 403, False), "second_cycle_assistant_positive": ("assistant", 200, True),
        "independent_child_positive": ("assistant_agent", 200, True), "parent_after_independent_child_grant_discovery": ("assistant", 200, True),
        "independent_child_after_parent_revocation": ("assistant_agent", 200, True), "owner_final_positive": ("owner", 200, True),
        "outsider_final_negative": ("outsider", 403, False)}
    expected_actions = {
        "owner_grants_assistant_read": ("owner", "assistant", "POST", 200),
        "assistant_attempts_share": ("assistant", "outsider", "POST", 403),
        "owner_revokes_assistant_basic_read": ("owner", "assistant", "DELETE", 200),
        "second_cycle_regrant_assistant": ("owner", "assistant", "POST", 200),
        "independent_root_grants_child": ("owner", "assistant_agent", "POST", 200),
        "second_cycle_revokes_parent_direct_read": ("owner", "assistant", "DELETE", 200)}
    phase_http = []
    for event in events:
        name = event["phase"]
        if name in expected_reads:
            actor, status, available = expected_reads[name]
            trace = event["result"]["trace"]; raw = trace["native_raw_body"]
            check("read_" + name, event["input"]["actor"] == actor and trace["actor"] == actor and trace["status"] == status and ((raw == VALUE) if available else VALUE not in raw) and raw.strip() != "null")
            check("read_native_journal_" + name, same(requests[trace["index"]], trace))
            phase_http.append({"phase": name, "index": trace["index"], "actor": actor, "http": status, "full_fact_observed": available})
        elif name in expected_actions:
            actor, recipient, method, status = expected_actions[name]; trace = event["result"]["trace"]
            check("action_" + name, trace["actor"] == actor and trace["method"] == method and trace["status"] == status and trace["path"] == "/api/v1/permissions/datasets/" + identities[recipient]["id"] and trace["request_params"] == {"permission_name": "read"} and trace["request_json"] == [dataset["id"]])
            check("action_native_journal_" + name, same(requests[trace["index"]], trace))
            if status == 200:
                expected_message = "Permission assigned to principal" if method == "POST" else "Permission revoked from principal"
                check("action_body_" + name, json.loads(trace["native_raw_body"]) == {"message": expected_message})
            phase_http.append({"phase": name, "index": trace["index"], "actor": actor, "recipient": recipient, "http": status})
    check("all_declared_read_and_action_phases", set(expected_reads).issubset(e["phase"] for e in events) and set(expected_actions).issubset(e["phase"] for e in events))
    old, old_plan = load(failed_run / "report.json"), load(failed_run / "plan.json")
    old_requests = old["final"]["native_requests"]; old_add = [r for r in old_requests if r["path"] == "/api/v1/add"]
    check("original_v1_failure_preserved", old["status"] == "not_qualified" and len(old_requests) == 13 and len(old_add) == 1 and old_add[0]["status"] == 415 and old_add[0]["request_data"]["raw_data"] == VALUE and "Local files are not accepted" in old_add[0]["native_raw_body"] and old["final"]["last_failure"]["code"] == "native_plaintext_add_failed")
    check("v1_same_exact_source_not_changed", same(old_plan["fact"], fact) and old_plan["proposal_sha256"] == plan["proposal_sha256"] and old_plan["wheel_sha256"] == plan["wheel_sha256"])
    for item in old_plan["code_archive"]:
        check("original_v1_archive_" + Path(item["source"]).name, sha(failed_run / item["archive"]) == item["sha256"])
    identity = load(identity_run / "report.json"); identity_requests = identity["final"]["native_requests"]
    check("original_identity_readiness_preserved", identity["status"] == "qualified" and len(identity_requests) == 10)
    all_runs = [identity, old, report]
    check("cumulative_60_http_zero_observed_inference", sum(len(r["final"]["native_requests"]) for r in all_runs) == 60 and all(r["final"]["generation_attempts"] == r["final"]["embedding_attempts"] == 0 and all(e["allowed"] is True for e in r["final"]["network_events"]) for r in all_runs))
    check("v2_postflight_unchanged", report["postflight"]["code"]["status"] == "passed" and all(report["postflight"][k] is True for k in ("wheel_identical", "proposal_identical", "identity_receipt_identical")))
    result = {"version": "independent_cognee_capability_saved_evidence_v1", "status": "passed" if all(c["passed"] for c in checks) else "failed",
        "checks": checks, "phase_http_indices_zero_based": phase_http, "interpretation_vendor_source_sha256": interpretation_hashes,
        "native_http_requests": 37, "cumulative_native_http_requests": 60, "new_verification_native_calls": 0, "new_verification_model_calls": 0,
        "scope": "Saved-evidence consistency of one synthetic native capability sequence; not the 25-case source projection matrix.",
        "limitations": ["Client secrets were intentionally omitted; structural/raw-file checks cannot independently compare discarded RAM secret values.",
            "Parent/child code matches the fixed installed wheel and supports the observed behavior; no SQL ACL decision trace or general proof was executed.",
            "Python inference/network guards are not GPU tracing or an OS sandbox."],
        "source_report_sha256": sha(run / "report.json"), "source_plan_sha256": sha(run / "plan.json"), "verifier_sha256": sha(__file__)}
    if output.exists() or not output.is_relative_to(ROOT / "results"):
        raise ValueError("new_project_results_receipt_required")
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2); stream.write("\n")
    print(json.dumps({"status": result["status"], "checks": len(checks), "failed": [c["check"] for c in checks if not c["passed"]],
        "receipt_sha256": sha(output), "new_native_calls": 0, "new_model_calls": 0}))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--failed-run", type=Path, required=True)
    parser.add_argument("--identity-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.run, args.failed_run, args.identity_run, args.output)
    raise SystemExit(0 if result["status"] == "passed" else 1)
