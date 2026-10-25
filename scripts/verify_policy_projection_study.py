"""Read-only, standard-library audit of a completed policy projection study.

This starts no ASGI/vendor/client/model, imports no project implementation,
and never opens native authentication stores. Credentials were deliberately
omitted: this audits recorded bindings and frozen code, not their signatures.
Only declared safe_responses/NNNN.bin and controlled_sinks/*.bin are read.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "independent_policy_projection_evidence_audit_v1"
CONTRACT_SHA256 = "918e6c4cc0c82e1c51bd43659d100b41c8b0393f4db8a4880c7862036a73ca6f"
ARMS = ("native_projection", "gateway_storage")
PIDS = ("alice.reader", "alice.worker", "bob.reader", "bob.worker")
ACTORS = {p: p.replace(".", "_") for p in PIDS}
DATASETS = {"fact.readonly": "readonly", "fact.managed": "managed"}
CORE = ("principals", "sources", "facts", "destinations", "grants", "job_manifests")
GROUPS = (("initial", tuple(f"P{i:02d}" for i in range(1, 13)) + ("P25",)),
    ("with_children", ("P13", "P14", "P15", "P16")), ("delegation_expired", ("P17",)),
    ("root_revoked", tuple(f"P{i:02d}" for i in range(18, 24))), ("all_managed_revoked", ("P24",)))
HTTP_SCOPES = ("source_main", "gateway_main", "source_delegation_expired", "gateway_delegation_expired",
    "source_root_revoked", "gateway_root_revoked")
MAX_JSON_BYTES = 64 * 1024 * 1024
PRIVATE_KEYS = {"password", "hashed_password", "password_hash", "token", "access_token", "refresh_token",
    "authorization", "apikey", "api_key", "agentapikey", "agent_api_key", "session_token"}


class AuditInputError(ValueError):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def jhash(value):
    return digest(canonical(value))


def strict_json(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise AuditInputError("json_duplicate_key")
            obj[key] = value
        return obj
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(AuditInputError("json_nonfinite")))
    except (ValueError, UnicodeError, TypeError):
        raise AuditInputError("invalid_json") from None


def private_fields(value):
    if isinstance(value, dict):
        return bool({str(k).lower() for k in value} & PRIVATE_KEYS) or any(private_fields(v) for v in value.values())
    return isinstance(value, list) and any(private_fields(v) for v in value)


def under(path, parent):
    path, parent = Path(path), Path(parent)
    if parent.is_symlink():
        raise AuditInputError("artifact_symlink_forbidden")
    parent = parent.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(parent) or resolved == parent or path.is_symlink():
        raise AuditInputError("artifact_path_outside_allowlist")
    current = path
    while current != parent and current != current.parent:
        if current.is_symlink():
            raise AuditInputError("artifact_symlink_forbidden")
        current = current.parent
    return resolved


class Audit:
    def __init__(self):
        self.checks = 0
        self.failures = []
        self.counts = {}
        self.artifact_sha256 = {}

    def check(self, condition, code):
        self.checks += 1
        if not condition:
            self.failures.append({"check": self.checks, "code": code})
        return bool(condition)

    def load(self, run, name):
        path = under(Path(run) / name, run)
        raw = path.read_bytes()
        if len(raw) > MAX_JSON_BYTES:
            raise AuditInputError("json_artifact_too_large")
        self.artifact_sha256[name] = digest(raw)
        return strict_json(raw)


class Oracle:
    """Independent ordinary grant-chain recomputation for this fixed contract.

    Does not import/call ReferencePolicy or a gateway. Request candidates come
    from the contract, never from a reported score or model answer.
    """
    def __init__(self, contract):
        self.contract = contract
        self.grants = {g["grant_id"]: g for g in contract["grants"]}
        self.jobs = {j["job_id"]: j for j in contract["job_manifests"]}
        self.principals = {p["principal_id"]: p for p in contract["principals"]}

    def valid(self, gid, state):
        seen = set()
        while gid is not None:
            if gid in seen or gid not in self.grants:
                return False
            seen.add(gid)
            g = self.grants[gid]
            if (gid not in state["registered_grants"] or gid in state["revoked_grants"]
                    or not g["not_before"] <= state["time"] < g["expires_at"]):
                return False
            gid = g["parent_grant_id"]
        return True

    def decide(self, pid, body, state):
        op, oid = body["operation"], body["object_id"]
        if op == "import_replay":
            job = self.jobs.get(body["job_id"])
            if (job is None or body["body_sha256"] != job["body_sha256"]
                    or jhash(body["payload"]) != body["body_sha256"] or body["payload"] != job["payload"]):
                return "invalid_replay", []
            payload = body["payload"]
            if payload["recipient"] != pid or oid != payload["object_id"]:
                return "deny", []
            if state["policy_revision"] < payload["source_policy_revision"]:
                return "deny", []
            ids = [payload["grant_id"]] if self.valid(payload["grant_id"], state) else []
            return ("allow" if ids else "deny"), ids
        ids = []
        for gid, g in self.grants.items():
            if g["subject"] != pid or g["object_id"] != oid or op not in g["actions"] or not self.valid(gid, state):
                continue
            if op == "export" and body["destination"] not in g.get("export_destinations", []):
                continue
            if op in {"share", "delegate"}:
                depth = body.get("child_delegation_depth", 0)
                if (body["recipient"] not in g.get(op + "_recipients", [])
                        or not set(body["child_actions"]) <= set(g.get(op + "_actions", [])) & set(g["actions"])
                        or not g["not_before"] <= state["time"] < body["child_expires_at"] <= g["expires_at"]):
                    continue
                if op == "share" and (not set(body["child_actions"]) <= {"read"} or depth != 0):
                    continue
                if op == "delegate" and not (g["delegation_depth"] > depth >= 0
                        and depth <= g.get("maximum_child_delegation_depth", -1)
                        and body["child_expires_at"] <= g.get("maximum_delegated_expiry", -1)):
                    continue
            ids.append(gid)
        return ("allow" if ids else "deny"), ids


def case_body(case, contract):
    body = {k: deepcopy(v) for k, v in case.items()
        if k not in {"case_id", "group", "state_id", "expected", "creates_grant", "actor"}}
    if body["operation"] in {"share", "delegate"}:
        body["child_grant_id"] = "grant.share" if body["operation"] == "share" else "grant.delegate"
    if body["operation"] == "import_replay":
        job = next(j for j in contract["job_manifests"] if j["job_id"] == body["job_id"])
        body.update(payload=deepcopy(job["payload"]), body_sha256=job["body_sha256"])
        if case["payload"] == "same_id_changed_recipient":
            body["payload"]["recipient"] = "alice.worker"
        elif case["payload"] != "registered_unchanged":
            raise AuditInputError("unknown_replay_manifest")
    return body


def verify_snapshot(audit, snapshot, core_sha, state):
    fields = {"version", "contract_sha256", "state", "installed_children", "snapshot_sha256"}
    audit.check(isinstance(snapshot, dict) and set(snapshot) == fields, "snapshot_closed_shape")
    audit.check(snapshot["version"] == "controller_policy_gateway_snapshot_v1"
        and snapshot["contract_sha256"] == core_sha, "snapshot_contract_binding")
    audit.check(snapshot["snapshot_sha256"] == jhash({k: v for k, v in snapshot.items() if k != "snapshot_sha256"}), "snapshot_checksum")
    audit.check(snapshot["state"] == state, "snapshot_current_complete_state")
    registered_children = {g for g in state["registered_grants"] if g in {"grant.share", "grant.delegate"}}
    audit.check({x["grant_id"] for x in snapshot["installed_children"]} == registered_children, "snapshot_child_installation_provenance")


def native_response(audit, row, *, state, read_files=True):
    audit.check(type(row.get("index")) is int and row["index"] >= 0, "native_request_index")
    audit.check(type(row.get("status")) is int and row["response_checked"] is True
        and row.get("execution_error") is None, "native_request_completed")
    audit.check(type(row.get("started_ns")) is int and type(row.get("finished_ns")) is int
        and row["started_ns"] <= row["finished_ns"], "native_request_clock")
    audit.check(row.get("cookie_present") is False and row.get("api_key_present") is False, "native_no_cookie_or_api_key")
    if row.get("actor") is not None:
        audit.check(row.get("authorization_present") is True, "native_bearer_present")
    if row.get("credential_response_omitted") is True:
        audit.check(not ({"native_raw_body", "native_response_file", "native_body_sha256", "request_json", "request_data"} & set(row)),
            "credential_response_and_input_omitted")
        return None
    raw = row.get("native_raw_body")
    audit.check(isinstance(raw, str), "native_response_raw_string")
    if not isinstance(raw, str):
        return None
    encoded = raw.encode()
    audit.check(digest(encoded) == row.get("native_body_sha256") and len(encoded) == row.get("byte_count"), "native_raw_hash_length")
    expected = Path(state).resolve() / "safe_responses" / f"{row['index']:04d}.bin"
    recorded = Path(row.get("native_response_file", "")).resolve()
    audit.check(recorded == expected.resolve(), "native_raw_exact_allowlisted_path")
    if read_files:
        safe = under(expected, Path(state).resolve() / "safe_responses")
        audit.check(safe.read_bytes() == encoded, "native_raw_disk_bytes")
    try:
        parsed = strict_json(raw)
    except AuditInputError:
        parsed = None
    audit.check(not private_fields(parsed), "native_no_credential_fields")
    return raw


def native_read(audit, row, text, facts, available):
    raw = row.get("native_raw_body")
    seen = {oid for oid, f in facts.items() if f["text"] in (raw or "")}
    if available:
        audit.check(row.get("status") == 200 and raw == text, "native_exact_authorized_read")
    else:
        audit.check(row.get("status") in {403, 404} and raw is not None and raw.strip() != "null"
            and not seen, "native_true_denial_without_registered_content")


def check_http(audit, row):
    raw = row.get("raw_body")
    audit.check(isinstance(raw, str) and digest(raw.encode()) == row.get("response_body_sha256"), "gateway_raw_response_hash")
    parsed = strict_json(raw)
    audit.check(parsed == row.get("parsed"), "gateway_raw_json_matches_parsed")
    audit.check(not private_fields(parsed), "gateway_no_credential_fields")
    audit.check(type(row.get("started_ns")) is int and type(row.get("completed_ns")) is int
        and row["started_ns"] <= row["completed_ns"], "gateway_http_clock")
    wire = b"" if row["method"] == "GET" else json.dumps(row["request_body"], ensure_ascii=False,
        separators=(",", ":"), allow_nan=False).encode()
    audit.check(digest(wire) == row.get("request_body_sha256"), "gateway_actual_request_bytes_hash")
    return parsed


def verify(run, *, read_native_files=True):
    """Audit only saved evidence. Returned details contain no raw bodies/IDs."""
    run = Path(run).resolve()
    audit = Audit()
    try:
        plan = audit.load(run, "plan.json")
        contract = audit.load(run, "source_contract.json")
        report = audit.load(run, "report.json")
        rows = audit.load(run, "unscored_rows.json")
        closure = audit.load(run, "prediction_phase_closed.json")
        rpc = audit.load(run, "rpc_receipts.json")
        events = audit.load(run, "events.json")
        barriers = audit.load(run, "barriers.json")
        bypass = audit.load(run, "bypass.json")
        sinks = audit.load(run, "sink_events.json")
        progress = audit.load(run, "phase_progress.json")
        http = {scope: audit.load(run, scope + "_http_requests.json") for scope in HTTP_SCOPES}
        audit.check(plan["proposal_sha256"] == CONTRACT_SHA256 == audit.artifact_sha256["source_contract.json"], "pinned_original_source_contract")
        audit.check(plan["target"] in {"cognee", "open_webui"} and plan["target"] == report["target"], "target_binding")
        audit.check(plan["max_model_calls"] == plan["max_paid_calls"] == 0 and plan["concurrency"] == 1, "zero_inference_serial_plan")
        audit.check(plan["physical_native_http_cap_per_arm"] == 200 and plan["gateway_http_cap_per_instance"] == 112, "declared_hard_caps")
        original_root = Path(plan["worker"]).parent.parent
        archived_paths = set()
        for source, expected in plan["code_sha256"].items():
            rel = Path(source).relative_to(original_root)
            archived = under(run / "implementation" / rel, run / "implementation")
            audit.check(archived.is_file() and digest(archived.read_bytes()) == expected, "archived_implementation_exact_hash")
            archived_paths.add(rel.as_posix())
        audit.check({"scripts/run_policy_projection_study.py", "scripts/policy_projection_gateway_http.py",
            "memory_migration_study/policy_projection_gateway.py", "memory_migration_study/policy_projection_reference.py",
            "memory_migration_study/privacy.py"} <= archived_paths, "executed_core_and_rpc_hash_dependency_frozen")
        audit.counts["archived_source_files"] = len(archived_paths)
        audit.check(closure == {"rows_sha256": audit.artifact_sha256["unscored_rows.json"], "row_count": len(rows)}, "prediction_closure_before_scoring")
        audit.check(progress == {"events": events, "unscored_rows": rows, "barriers": barriers, "bypass": bypass, "sink_events": sinks}, "terminal_checkpoint_matches_originals")
        audit.check(report["failure"] is None and report["status"] == "qualified_with_declared_limits", "completed_without_hidden_failure")

        facts = {f["object_id"]: f for f in contract["facts"]}
        states = {s["state_id"]: s for s in contract["states"]}
        cases = {c["case_id"]: c for c in contract["cases"]}
        principals = {p["principal_id"]: {k: p[k] for k in ("user_id", "agent_id")} for p in contract["principals"]}
        core_sha = jhash({k: contract[k] for k in CORE})
        oracle = Oracle(contract)
        for fact in facts.values():
            source = next(s for s in contract["sources"] if s["source_id"] == fact["source_id"])
            audit.check(source["public_synthetic_material"] is True and digest(source["text"].encode()) == source["sha256"], "synthetic_source_hash")
            audit.check(source["text"][fact["source_start"]:fact["source_end"]] == fact["text"]
                and digest(fact["text"].encode()) == fact["content_sha256"] and fact["labels_are_authorization"] is False,
                "exact_fact_source_span_and_non_authorizing_labels")
        audit.check(set(facts) == set(DATASETS) and set(principals) == set(PIDS), "fixed_fact_and_principal_inventory")
        audit.check(set(rpc) == set(ARMS) and set(report["native_final"]) == set(ARMS), "two_physical_native_arms")
        state_paths = [Path(plan["native_states"][a]).resolve() for a in ARMS]
        audit.check(len(set(state_paths)) == 2 and all(s.parent == Path(tempfile.gettempdir()).resolve()
            and str(s).isascii() for s in state_paths), "fresh_distinct_ascii_temp_states")
        physical, rpc_seen, all_identity_ids = {}, {}, []
        for arm in ARMS:
            summary = report["native_final"][arm]
            calls, requests = rpc[arm], summary["native_requests"]
            if plan["target"] == "cognee":
                audit.check(Path(summary["state"]).resolve() == Path(plan["native_states"][arm]).resolve(), "native_summary_actual_state_matches_plan")
            physical[arm] = requests
            audit.counts[arm + "_http"] = len(requests)
            audit.check(0 < len(requests) <= 200 and [r["index"] for r in requests] == list(range(len(requests))), "native_physical_http_complete_count_and_cap")
            audit.check(calls[0]["command"] == "init" and calls[-1]["command"] == "close"
                and [c["rpc_id"] for c in calls] == list(range(1, len(calls) + 1)), "rpc_lifecycle_and_sequence")
            audit.check(calls[-1]["result"] == summary, "close_summary_original_binding")
            rpc_seen[arm] = set()
            previous = -1
            for call in calls:
                audit.check("error" not in call and call.get("input_sha256") == jhash(call["input"])
                    and call.get("response_sha256") == jhash(call["result"]), "rpc_original_input_response_hashes")
                audit.check(type(call["started_ns"]) is int and previous <= call["started_ns"] <= call["finished_ns"], "rpc_serial_clock")
                previous = call["finished_ns"]
                for request in requests:
                    if call["started_ns"] <= request["started_ns"] <= request["finished_ns"] <= call["finished_ns"]:
                        audit.check(request["index"] not in rpc_seen[arm], "native_request_one_rpc_owner")
                        rpc_seen[arm].add(request["index"])
            audit.check(rpc_seen[arm] == set(range(len(requests))), "all_native_http_enclosed_in_actual_rpc")
            for index, request in enumerate(requests):
                native_response(audit, request, state=plan["native_states"][arm], read_files=read_native_files)
                if index:
                    audit.check(requests[index-1]["finished_ns"] <= request["started_ns"], "native_http_serial_clock")
            audit.counts[arm + "_credential_responses_omitted"] = sum(r["credential_response_omitted"] is True for r in requests)
            audit.check(summary["generation_attempts"] == summary["embedding_attempts"] == 0
                and summary["inference_events"] == [] and all(e.get("allowed") is True for e in summary["network_events"]), "no_observed_python_inference_or_blocked_network")
            audit.check(summary["client_credential_values_persisted"] is False and summary.get("last_failure") is None, "no_serialized_credentials_or_worker_error")
            init = calls[0]["result"]
            identities = init["identities"]
            audit.check(set(identities) == {"owner", *ACTORS.values()} and identities == summary["identities"], "five_actual_composite_identity_bindings")
            ids = [v["id"] for v in identities.values()]
            audit.check(len(set(ids)) == 5, "five_native_distinct_identity_ids")
            all_identity_ids.extend(ids)
            for actor, identity in identities.items():
                audit.check(identity.get("credential_kind") == "bearer" and (identity.get("is_superuser") is False
                    or identity.get("role") == "user") and identity.get("parent_user_id") is None, "ordinary_independent_native_account")
                whoami = [r for r in requests if r["actor"] == actor and r["method"] == "GET"
                    and r["path"] == ("/api/v1/users/me" if plan["target"] == "cognee" else "/api/v1/auths/")]
                audit.check(len(whoami) == 1 and whoami[0]["status"] == 200 and whoami[0]["authorization_present"] is True,
                    "actual_native_whoami_request_present")
                if plan["target"] == "cognee":
                    body = strict_json(whoami[0]["native_raw_body"])
                    audit.check(body["id"] == identity["id"] and body.get("is_superuser") is False
                        and body.get("parent_user_id") is None, "raw_whoami_matches_ordinary_native_identity")
                else:
                    audit.check(whoami[0]["credential_response_omitted"] is True
                        and identity["whoami_request_index"] == whoami[0]["index"], "credential_bearing_vendor_whoami_deliberately_omitted")
            audit.check(set(summary["datasets"]) == set(summary["facts"]) == set(DATASETS.values()), "two_native_containers_and_exact_facts")
            for oid, ds in DATASETS.items():
                fact = summary["facts"][ds]
                audit.check(fact["dataset"] == ds and fact["text_sha256"] == facts[oid]["content_sha256"], "native_fact_identity_content_binding")
            if plan["target"] == "cognee":
                audit.check(init["cognee_version"] == "1.6.5" and init["wheel_sha256"] == plan["wheel_sha256"], "cognee_pinned_wheel_runtime")
                wheel = Path(plan["wheel"])
                audit.check(wheel.is_file() and digest(wheel.read_bytes()) == plan["wheel_sha256"], "cognee_original_wheel_hash")
                audit.check(len(init["vendor_source_sha256"]) == 11 and summary["native_child_agents_created"] == 0
                    and summary["per_request_reference_gate_present"] is False, "cognee_native_scope_no_child_or_reference_gate")
            if arm == "gateway_storage":
                audit.check(not any(c["command"] in {"grant", "revoke"} for c in calls), "gateway_native_storage_no_acl_grants")
            expected_instrument = {"http_requests": len(requests), "http_cap_satisfied": len(requests) <= 200,
                "observed_generation_attempts": 0, "observed_embedding_attempts": 0,
                "no_observed_inference": True, "network_clear": True, "client_credentials_not_serialized": True}
            audit.check(report["instrumentation"][arm] == expected_instrument, "instrumentation_recomputed_not_trusted")
        audit.check(len(set(all_identity_ids)) == 10, "native_arms_do_not_share_accounts")

        for event in events:
            if event.get("arm") in ARMS and "command" in event:
                matches = [c for c in rpc[event["arm"]] if c["command"] == event["command"]
                    and c["input"] == event["input"] and c["result"] == event["result"]]
                audit.check(len(matches) == 1, "native_phase_event_matches_original_rpc")
                if event["command"] in {"read_raw", "list_data", "list_datasets", "grant", "revoke", "whoami"}:
                    trace = event["result"]["trace"]
                    audit.check(trace == physical[event["arm"]][trace["index"]]
                        and trace["actor"] == event["input"]["actor"], "native_event_trace_actual_actor_and_physical_row")
        for scope, requests in http.items():
            audit.counts[scope + "_http"] = len(requests)
            audit.check(len(requests) <= 112 and [r["index"] for r in requests] == list(range(len(requests))), "gateway_http_full_count_cap")
            previous = -1
            for request in requests:
                check_http(audit, request)
                audit.check(previous <= request["started_ns"], "gateway_instance_serial_http")
                previous = request["completed_ns"]
                handle = request["credential_handle"]
                audit.check(handle in {*PIDS, "invalid", None} and request["authenticated_header_present"] == (handle is not None), "actual_gateway_credential_handle_binding")
            if scope.endswith("main"):
                for index, pid in enumerate(PIDS):
                    audit.check(requests[index]["path"] == "/v1/identity" and requests[index]["credential_handle"] == pid
                        and requests[index]["status"] == 200 and requests[index]["parsed"] == principals[pid], "gateway_http_whoami_exact_user_agent_tuple")
                audit.check(requests[4]["credential_handle"] is None and requests[4]["status"] == 401
                    and requests[5]["credential_handle"] == "invalid" and requests[5]["status"] == 401
                    and requests[6]["credential_handle"] == "bob.reader" and requests[6]["status"] in {400, 403}
                    and requests[6]["request_body"]["actor"] == "alice.reader", "gateway_real_unauth_invalid_and_forged_actor_denial")

        order = [cid for _, group in GROUPS for cid in group]
        audit.check([r["case_id"] for r in rows] == order and len(set(order)) == 25, "all_25_original_cases_once_in_registered_order")
        audit.check([b["phase"] for b in barriers] == [g[0] for g in GROUPS], "five_native_state_barriers")
        current = deepcopy(states["initial"])
        installed = []
        child_snapshot = None
        previous_desired = set()
        scored = []
        row_by_id = {r["case_id"]: r for r in rows}
        for state_id, group in GROUPS:
            if state_id != "initial":
                current = deepcopy(states[state_id])
            if state_id in {"delegation_expired", "root_revoked"}:
                fork = [e for e in events if e.get("phase") == "fork_from_verified_with_children" and e["state_id"] == state_id]
                audit.check(len(fork) == 1 and fork[0]["independent_gateway_instances"] is True
                    and fork[0]["native_reuse_requires_full_acl_reset_barrier"] is True
                    and fork[0]["source_parent_state_sha256"] == digest(json.dumps(child_snapshot, sort_keys=True).encode()),
                    "fork_from_verified_child_snapshot_not_clock_rollback")
            barrier = next(b for b in barriers if b["phase"] == state_id)
            audit.check(barrier["state"] == current and len(barrier["all_eight_reads"]) == 8, "barrier_complete_source_state_eight_relations")
            expected_pairs = {(p, oid) for p in PIDS for oid in facts}
            desired = {(p, oid) for p, oid in expected_pairs
                if oracle.decide(p, {"operation": "read", "object_id": oid}, current)[0] == "allow"}
            mutations = [{"operation": op, "principal": p, "object_id": oid}
                for op, relations in (("revoke", previous_desired - desired), ("grant", desired - previous_desired))
                for p, oid in sorted(relations)]
            audit.check(barrier["changes"] == mutations, "controller_full_acl_diff_recomputed_at_each_barrier")
            for mutation in mutations:
                operation = mutation["operation"]
                expected_input = {"dataset": DATASETS[mutation["object_id"]], "actor": "owner",
                    "recipient": ACTORS[mutation["principal"]], "permission": "read"}
                matching = [e for e in events if e.get("arm") == "native_projection"
                    and e.get("phase") == state_id + "_" + operation and e.get("input") == expected_input]
                audit.check(len(matching) == 1 and matching[0]["result"]["status"] == 200, "native_controller_actual_acl_mutation_ack")
            previous_desired = desired
            audit.check({(r["principal"], r["object_id"]) for r in barrier["all_eight_reads"]} == expected_pairs, "barrier_no_missing_or_duplicate_relations")
            for check in barrier["all_eight_reads"]:
                pid, oid = check["principal"], check["object_id"]
                decision, _ = oracle.decide(pid, {"operation": "read", "object_id": oid}, current)
                available = decision == "allow"
                trace = physical["native_projection"][check["native_request_index"]]
                audit.check(check["desired_available"] is available and check["available"] is available
                    and trace["actor"] == ACTORS[pid], "barrier_read_matches_independent_current_chain_recompute")
                native_read(audit, trace, facts[oid]["text"], facts, available)
            for cid in group:
                row, case = row_by_id[cid], cases[cid]
                body = case_body(case, contract)
                audit.check(row["state_id"] == state_id and row["actor"] == case["actor"]
                    and row["operation"] == case["operation"] and row["request_body"] == body, "operation_request_manifest_without_gold_or_forged_actor")
                audit.check(not {"expected", "case_id", "actor"} & set(body), "no_scoring_fields_in_request")
                decision, grant_ids = oracle.decide(case["actor"], body, current)
                audit.check(decision == case["expected"], "source_contract_expected_independently_recomputed")
                for which in ("source", "gateway"):
                    verify_snapshot(audit, row[which + "_state_before"], core_sha, current)
                after = deepcopy(current)
                if decision == "allow" and body["operation"] in {"share", "delegate"}:
                    gid = body["child_grant_id"]
                    g = oracle.grants[gid]
                    audit.check(g["parent_grant_id"] in grant_ids and g["subject"] == body["recipient"]
                        and g["actions"] == body["child_actions"] and g["expires_at"] == body["child_expires_at"], "child_registered_from_valid_parent_exact_requested_scope")
                    after["registered_grants"].append(gid)
                    installed.append(gid)
                for which in ("source", "gateway"):
                    reply = row[which + "_http"]
                    suffix = "main" if state_id in {"initial", "with_children"} else ("delegation_expired" if state_id == "delegation_expired" else "root_revoked")
                    scope = which + "_" + suffix
                    audit.check(http[scope][reply["index"]] == reply and reply["credential_handle"] == case["actor"]
                        and reply["request_body"] == body and reply["path"] == "/v1/memory", "case_bound_to_actual_authenticated_http_original")
                    parsed = reply["parsed"]
                    audit.check(parsed["decision"] == decision and reply["status"] == {"allow": 200, "deny": 403, "invalid_replay": 409}[decision]
                        and parsed["http_status"] == reply["status"], "actual_http_policy_decision_and_status")
                    audit.check(parsed["contract_sha256"] == core_sha and parsed["raw_request_sha256"] == reply["request_body_sha256"]
                        and parsed["state_sha256"] == jhash(after), "http_request_contract_and_current_state_binding")
                    reference = parsed["reference"]
                    audit.check(reference["decision"] == decision and set(reference["valid_grant_ids"]) == set(grant_ids), "reference_receipt_matches_independent_chain_oracle")
                    if decision != "invalid_replay":
                        audit.check(reference["principal"] == principals[case["actor"]], "http_user_agent_pair_not_body_assertion")
                    allowed_values = {case["object_id"]} if decision == "allow" and body["operation"] in {"read", "import_replay"} else set()
                    seen = {oid for oid, fact in facts.items() if fact["text"] in reply["raw_body"]}
                    audit.check(seen == allowed_values, "all_registered_values_checked_in_complete_http_response")
                    if allowed_values:
                        fact = facts[case["object_id"]]
                        audit.check(parsed["data"] == {"object_id": case["object_id"], "text": fact["text"], "content_sha256": fact["content_sha256"]}
                            and parsed["delivered_fact_ids"] == [case["object_id"]], "actual_exact_fact_delivery_not_only_allow_text")
                    else:
                        audit.check(parsed["data"] is None and parsed["delivered_fact_ids"] == [], "no_unrequested_or_denied_fact_delivery")
                    if decision == "allow" and body["operation"] in {"share", "delegate", "export"}:
                        audit.check(parsed["side_effect"]["status"] == "confirmed", "allowed_managed_operation_has_confirmed_effect")
                    verify_snapshot(audit, row[which + "_state_after"], core_sha, after)
                    audit.check([r["grant_id"] for r in row[which + "_state_after"]["installed_children"]] == installed,
                        "actual_registered_child_receipts_in_source_and_gateway")
                native = row["native"]
                if case["operation"] == "read":
                    audit.check(native["classification"] == "native" and native["decision"] == decision, "native_read_is_not_gateway_substitute")
                    trace = physical["native_projection"][native["native_request_index"]]
                    audit.check(trace["actor"] == ACTORS[case["actor"]], "case_native_physical_actor_binding")
                    native_read(audit, trace, facts[case["object_id"]]["text"], facts, decision == "allow")
                    native_matches = native["decision"] == decision
                else:
                    audit.check(native["classification"] == "unrepresentable" and native["decision"] == "unsupported"
                        and native["available"] is False and "native_request_index" not in native, "native_nonread_unsupported_never_legal_success")
                    native_matches = None
                if decision == "allow" and body["operation"] in {"share", "delegate"}:
                    witness = row["created_grant_recipient_read"]
                    audit.check(witness == http["gateway_main"][witness["index"]] and witness["credential_handle"] == body["recipient"]
                        and witness["request_body"] == {"operation": "read", "object_id": body["object_id"]}
                        and witness["parsed"]["decision"] == "allow" and witness["parsed"]["data"]["text"] == facts[body["object_id"]]["text"]
                        and witness["started_ns"] >= row["gateway_http"]["completed_ns"], "created_child_actual_recipient_read_after_registration")
                scored.append({"case_id": cid, "expected": decision, "source_matches": True, "gateway_matches_with_effect": True,
                    "native_classification": native["classification"], "native_matches": native_matches})
                current = after
                if state_id == "with_children" and cid == group[-1]:
                    child_snapshot = row["source_state_after"]

        for row in rows:
            for which in ("source", "gateway"):
                for position in ("before", "after"):
                    for receipt in row[which + "_state_" + position]["installed_children"]:
                        origin_id = {"grant.share": "P07", "grant.delegate": "P11"}.get(receipt["grant_id"])
                        origin = row_by_id[origin_id]
                        audit.check(receipt == {"grant_id": receipt["grant_id"],
                            "parent_grant_id": oracle.grants[receipt["grant_id"]]["parent_grant_id"],
                            "request": origin["request_body"], "principal": principals[origin["actor"]],
                            "state_before": origin[which + "_state_before"]["state"],
                            "reference_sha256": jhash(origin[which + "_http"]["parsed"]["reference"]),
                            "state_after_sha256": jhash(origin[which + "_state_after"]["state"])},
                            "child_installation_receipt_matches_actual_authorized_operation")

        # Independently inspect all planned native list/raw bypass surfaces.
        for item in bypass:
            arm, state_id, pid = item["arm"], item["phase"], item["principal"]
            trace = physical[arm][item["native_request_index"]]
            audit.check(trace["actor"] == ACTORS[pid], "bypass_actual_native_principal")
            state = states[state_id]
            allowed = {oid for oid in facts if arm == "native_projection"
                and oracle.decide(pid, {"operation": "read", "object_id": oid}, state)[0] == "allow"}
            summary = report["native_final"][arm]
            container_ids = {oid: summary["datasets"][DATASETS[oid]]["id"] for oid in facts}
            fact_ids = {oid: summary["facts"][DATASETS[oid]]["id"] for oid in facts}
            raw = trace["native_raw_body"]
            values = {oid for oid, fact in facts.items() if fact["text"] in raw}
            known_facts = {oid for oid, fid in fact_ids.items() if fid in raw}
            if item["surface"] == "raw":
                audit.check(arm == "gateway_storage", "only_gateway_native_raw_bypass_manifest")
                native_read(audit, trace, facts[item["object_id"]]["text"], facts, False)
            else:
                parsed = strict_json(raw)
                kind = item["surface"]
                if kind == "container_list":
                    audit.check(trace["status"] == 200 and isinstance(parsed, list)
                        and all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in parsed), "native_complete_container_list_schema")
                    observed = {oid for oid, rid in container_ids.items() if rid in raw}
                    audit.check(observed == allowed and values | known_facts <= allowed
                        and set(item["registered_objects_seen"]) == observed, "complete_container_list_has_exact_authorized_inventory")
                else:
                    oid = item["object_id"]
                    expected = oid in allowed
                    if trace["status"] in {403, 404}:
                        schema = isinstance(parsed, dict) and isinstance(parsed.get("detail"), str) and not expected
                    elif trace["status"] == 200:
                        schema = (isinstance(parsed, dict) and isinstance(parsed.get("data"), dict)
                            and isinstance(parsed["data"].get("files"), list)) if plan["target"] == "open_webui" else (
                            isinstance(parsed, list) and all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in parsed))
                    else:
                        schema = False
                    audit.check(schema and parsed is not None, "native_complete_object_list_schema_not_null_or_error")
                    exposed = oid in values | known_facts
                    audit.check(exposed is expected and values | known_facts <= ({oid} if expected else set())
                        and item["registered_object_seen"] is exposed, "complete_object_list_no_other_fact_disclosure")
        expected_bypass = {(a, s, p, "container_list", None) for a in ARMS for s, _ in GROUPS for p in PIDS
            if a == "native_projection" or s in {"initial", "all_managed_revoked"}}
        expected_bypass |= {(a, s, p, "object_list", oid) for a in ARMS for s, _ in GROUPS for p in PIDS for oid in facts
            if a == "native_projection" or s in {"initial", "all_managed_revoked"}}
        expected_bypass |= {("gateway_storage", s, p, "raw", oid) for s in ("initial", "all_managed_revoked") for p in PIDS for oid in facts}
        actual_bypass = {(i["arm"], i["phase"], i["principal"], i["surface"], i.get("object_id")) for i in bypass}
        audit.check(actual_bypass == expected_bypass and len(bypass) == len(expected_bypass), "all_registered_bypass_probes_once")
        attack = [e for e in events if e.get("phase") == "read_is_not_share_native_attack"]
        post = [e for e in events if e.get("phase") == "read_only_share_attack_postcondition"]
        audit.check(len(attack) == len(post) == 1 and attack[0]["input"] == {"dataset": "readonly", "actor": "alice_reader", "recipient": "bob_worker", "permission": "read"}
            and attack[0]["result"]["status"] in {403, 404}, "native_read_only_principal_cannot_share")
        native_read(audit, post[0]["result"]["trace"], facts["fact.readonly"]["text"], facts, False)

        audit.check(len(sinks) == 2 and {s["scope"] for s in sinks} == {"source_main", "gateway_main"}, "source_and_gateway_controlled_export_both_executed")
        for item in sinks:
            path = under(run / item["path"], run / "controlled_sinks")
            raw = path.read_bytes()
            fact = facts[item["object_id"]]
            audit.check(path.suffix == ".bin" and raw == fact["text"].encode()
                and digest(raw) == item["sha256"] == fact["content_sha256"] and len(raw) == item["bytes"], "controlled_sink_actual_file_exact_fact_bytes")
            audit.check(item["metadata"]["destination_id"] == "destination.approved"
                and item["metadata"]["principal"] == principals["alice.reader"]
                and item["metadata"]["content_sha256"] == fact["content_sha256"]
                and item["metadata"]["state_sha256"] == jhash(row_by_id["P09"]["gateway_state_before"]["state"])
                and item["metadata"]["time"] == 10 and item["metadata"]["policy_revision"] == 1,
                "export_sink_bound_destination_principal_and_current_state")
        fetches = [e for e in events if e.get("phase") == "gateway_backend_owner_fetch"]
        allowed_fetch_http = [r for scope, requests in http.items() if scope.startswith("gateway") for r in requests
            if r["path"] == "/v1/memory" and isinstance(r["parsed"], dict) and r["parsed"].get("decision") == "allow"
            and r["request_body"]["operation"] in {"read", "export", "import_replay"}]
        audit.check(len(fetches) == len(allowed_fetch_http), "all_gateway_actual_delivery_and_export_have_backend_fetch")
        for request in allowed_fetch_http:
            matches = [e for e in fetches if request["started_ns"] <= e["result"]["trace"]["started_ns"]
                <= e["result"]["trace"]["finished_ns"] <= request["completed_ns"]]
            audit.check(len(matches) == 1 and matches[0]["input"]["actor"] == "owner"
                and matches[0]["input"]["fact_key"] == DATASETS[request["request_body"]["object_id"]], "http_delivery_encloses_actual_owner_native_read")
        audit.check(report["scored_rows"] == scored and report["source_matches"] == report["gateway_matches_with_effect"] == 25
            and report["native_read_matches"] == 11 and report["native_unsupported_operations"] == 14
            and report["case_count"] == 25, "scores_recomputed_after_closed_raw_predictions")
        audit.check(report["postflight"]["code"]["status"] == "passed" and report["postflight"]["proposal_identical"] is True, "original_postflight_present")
        for field in ("native_full_source_semantics_passed", "full_get_search_list_bypass_qualified", "search_vector_measured", "concurrent_revoke_measured", "paper_novelty_established"):
            audit.check(report[field] is False, "unmeasured_native_and_research_claims_remain_false")
        audit.counts.update(cases=len(rows), source_decisions=25, gateway_decisions=25, native_read_cases=11,
            native_nonread_unrepresentable=14, barriers=len(barriers), native_bypass_observations=len(bypass),
            actual_export_files=len(sinks), native_http_total=sum(len(v) for v in physical.values()),
            new_vendor_calls=0, new_model_calls=0, new_network_calls=0)
    except (OSError, ValueError, TypeError, KeyError, IndexError, StopIteration, AttributeError) as error:
        audit.check(False, "audit_input_unreadable_or_contract_mismatch")
    return {"version": VERSION, "status": "passed" if not audit.failures else "failed", "checks": audit.checks,
        "passed": audit.checks - len(audit.failures), "failures": audit.failures, "counts": audit.counts,
        "artifact_sha256": audit.artifact_sha256, "verifier_sha256": digest(Path(__file__).read_bytes()),
        "scope": "Saved synthetic original evidence only; no vendor/client/model/network execution or auth-store reads.",
        "limits": ["Recorded credential handles plus frozen authentication code; omitted credentials cannot be independently authenticated again.",
            "Controller snapshots and serial complete-ACL barriers; not vendor-native clocks, delegation chains or concurrent revocation.",
            "Only registered raw/list probes; complete get/search/list bypass coverage remains unverified.",
            "Python inference/network instrumentation, not hardware attestation; one synthetic story, no publication novelty claim."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run, output = args.run.resolve(), args.output.resolve()
    results = (ROOT / "results").resolve()
    if not run.is_relative_to(results) or run == results or not run.is_dir():
        raise ValueError("existing_workspace_results_run_required")
    if not output.is_relative_to(results) or output == results or output.exists() or output.suffix != ".json":
        raise ValueError("new_workspace_results_json_required")
    result = verify(run)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "checks": result["checks"], "passed": result["passed"],
        "failed": len(result["failures"]), "counts": result["counts"]}, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
