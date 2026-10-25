"""Frozen, bounded two-arm native read projection and authenticated gateway.

The source is an explicit trusted reference HTTP gateway, not a vendor IAM.
Native endpoints are real; logical state transitions are serial host barriers.
Native-unrepresented operations remain unsupported, never scored as successes.
Search/vector and concurrent lifecycle claims are outside this first run.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import secrets
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.policy_projection_reference import CORE_FIELDS, ReferencePolicy
from memory_migration_study.policy_projection_gateway import PolicyProjectionGateway
from scripts.policy_projection_gateway_http import GatewayHTTP
from scripts.run_native_exact_fact_bridge import WorkerRPC, archive_code, verify_sha_table
from scripts.run_cognee_read_share_qualification import read_classification, action_classification

VERSION = "native_read_projection_and_authenticated_gateway_v1"
SOURCE_FILE = ROOT / "docs/proposals/source_policy_projection_contract_v1_20261026.json"
NATIVE_HTTP_CAP = 200
HTTP_CAP = 112
NATIVE_ACTORS = {p: p.replace(".", "_") for p in ("alice.reader", "alice.worker", "bob.reader", "bob.worker")}
DATASETS = {"fact.readonly": "readonly", "fact.managed": "managed"}
GROUPS = [("initial", [f"P{i:02d}" for i in range(1, 13)] + ["P25"]),
          ("with_children", ["P13", "P14", "P15", "P16"]),
          ("delegation_expired", ["P17"]),
          ("root_revoked", [f"P{i:02d}" for i in range(18, 24)]),
          ("all_managed_revoked", ["P24"])]


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def validate_native_trace(result, actor):
    trace = result.get("trace", {})
    raw = trace.get("native_raw_body")
    if (not isinstance(raw, str) or trace.get("actor") != actor or trace.get("status") != result.get("status")
            or trace.get("response_checked") is not True or trace.get("execution_error") is not None
            or trace.get("authorization_present") is not True or trace.get("api_key_present") is not False
            or trace.get("cookie_present") is not False
            or hashlib.sha256(raw.encode()).hexdigest() != trace.get("native_body_sha256")):
        raise StudyStop("native_authenticated_trace_unqualified")
    return trace


def list_body(result, *, kind, target, expected_available):
    raw = result["trace"]["native_raw_body"]
    try: parsed = json.loads(raw)
    except (ValueError, UnicodeError): raise StudyStop("native_list_nonjson") from None
    status = result["status"]
    if not expected_available and kind == "object" and status in {403, 404}:
        if not isinstance(parsed, dict) or not isinstance(parsed.get("detail"), str):
            raise StudyStop("native_list_denial_schema_unqualified")
        return parsed
    if status != 200:
        raise StudyStop("native_list_transport_unqualified")
    if kind == "object" and target == "open_webui":
        if (not isinstance(parsed, dict) or not isinstance(parsed.get("id"), str)
                or not isinstance(parsed.get("data"), dict) or not isinstance(parsed["data"].get("files"), list)):
            raise StudyStop("native_note_detail_schema_unqualified")
    elif not isinstance(parsed, list) or not all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in parsed):
        raise StudyStop("native_list_array_schema_unqualified")
    return parsed


def allowed_mutation_ack(result):
    if result.get("status") != 200: return False
    try: parsed = json.loads(result["trace"]["native_raw_body"])
    except (ValueError, TypeError): return False
    return isinstance(parsed, dict) and bool(parsed) and "error" not in parsed


def request_body(case, contract):
    """Translate the operation manifest; scoring fields never enter HTTP."""
    excluded = {"case_id", "group", "state_id", "expected", "creates_grant", "actor"}
    body = {k: deepcopy(v) for k, v in case.items() if k not in excluded}
    if body["operation"] in {"share", "delegate"}:
        body["child_grant_id"] = "grant.share" if body["operation"] == "share" else "grant.delegate"
    if body["operation"] == "import_replay":
        manifest = next(j for j in contract["job_manifests"] if j["job_id"] == body["job_id"])
        body["payload"] = deepcopy(manifest["payload"])
        body["body_sha256"] = manifest["body_sha256"]
        if case["payload"] == "same_id_changed_recipient":
            body["payload"]["recipient"] = "alice.worker"
        elif case["payload"] != "registered_unchanged":
            raise ValueError("unknown_operation_payload_manifest")
    return body


def build_plan(target, *, approved=None):
    if target not in {"cognee", "open_webui"}: raise ValueError("unknown_target")
    worker = ROOT / ("scripts/native_cognee_projection_worker.py" if target == "cognee" else "scripts/native_webui_projection_worker.py")
    python = ROOT / (".venv-native-cognee/Scripts/python.exe" if target == "cognee" else ".venv-native-webui/Scripts/python.exe")
    if not python.is_file() or not worker.is_file(): raise ValueError("native_interpreter_or_worker_missing")
    files = [Path(__file__), worker, ROOT / "memory_migration_study/policy_projection_gateway.py",
        ROOT / "memory_migration_study/policy_projection_reference.py", ROOT / "scripts/policy_projection_gateway_http.py",
        ROOT / "scripts/native_exact_fact_common.py", ROOT / "scripts/run_native_exact_fact_bridge.py",
        ROOT / "scripts/run_cognee_read_share_qualification.py"]
    if target == "cognee":
        files += [ROOT / "scripts/native_cognee_policy_worker.py",
                  ROOT / "examples/native_cognee_probe_assets/scripts/cognee_local_migration_probe.py"]
    else:
        files += [ROOT / "scripts/native_exact_fact_target.py"]
    # The shared RPC imports labels/privacy/policy and their package helpers.
    # Freeze the complete project package rather than omitting transitive code.
    files += sorted((ROOT / "memory_migration_study").glob("*.py"))
    files = list(dict.fromkeys(p.resolve() for p in files))
    states = {}
    for arm in ("native_projection", "gateway_storage"):
        state = Path(approved["native_states"][arm]) if approved else Path(tempfile.gettempdir()) / ("agent_memory_projection_" + target + "_" + arm + "_" + uuid.uuid4().hex)
        if state.exists() or state.parent.resolve() != Path(tempfile.gettempdir()).resolve() or not str(state).isascii():
            raise ValueError("new_ascii_temp_child_required")
        states[arm] = str(state.resolve())
    contract = json.loads(SOURCE_FILE.read_bytes())
    ReferencePolicy({k: contract[k] for k in CORE_FIELDS})
    plan = {"version": VERSION, "target": target, "python": str(python), "worker": str(worker),
        "proposal": str(SOURCE_FILE), "proposal_sha256": sha(SOURCE_FILE),
        "code_sha256": {str(p.resolve()): sha(p) for p in files}, "native_states": states,
        "physical_native_http_cap_per_arm": NATIVE_HTTP_CAP, "gateway_http_cap_per_instance": HTTP_CAP,
        "max_native_http_total": NATIVE_HTTP_CAP * 2, "max_model_calls": 0, "max_paid_calls": 0,
        "concurrency": 1, "four_tuple_mapping": NATIVE_ACTORS, "facts": contract["facts"],
        "source": "Authenticated ASGI reference gateway with local frozen exact bytes; not native Mem0 IAM.",
        "arms": {"native_projection": "Composite ordinary accounts, two fact containers, eager full source-read ACL reconciliation at serial state barriers; no per-request source gate for actual native reads.",
                 "gateway_storage": "Separate owner-only native storage, independently authenticated HTTP gateway, current complete reference checks and actual managed side effects."},
        "native_nonread_policy": "Unsupported constrained operations are safe adapter rejections, not legal successes or vendor vulnerability claims.",
        "branch_order": [[state_id, list(case_ids)] for state_id, case_ids in GROUPS], "branch_reset": "Expiry and root-revocation fork the verified with_children source/gateway snapshot. Native containers are reused only after full current ACL reconciliation and all 8 read relations are checked.",
        "bypass_manifest": ["authenticated raw content", "authenticated object list", "authenticated container list", "read-only recipient attempts native share"],
        "unverified_surfaces": ["semantic/vector/search with a qualified positive index", "undeclared external tools", "concurrent operations", "production network deployment"],
        "stop_rule": "Preserve original failure and stop on identity/asset/guard errors, unexpected content, or unqualified empty/null/error; do not retry automatically.",
        "cleanup": "Close owned ASGI clients and child processes; preserve structured responses/native auth stores locally; never publish native auth state or credential responses."}
    if target == "cognee":
        wheel = ROOT / ".runtime/native_cognee_wheel/cognee-1.6.5-py3-none-any.whl"
        plan.update(wheel=str(wheel), wheel_sha256=sha(wheel), legacy=str(ROOT / "examples/native_cognee_probe_assets"))
    return plan


class StudyStop(ValueError): pass


def execute(plan, output, *, rpc_factory=WorkerRPC):
    contract = json.loads(SOURCE_FILE.read_bytes())
    core = {k: contract[k] for k in CORE_FIELDS}
    states = {x["state_id"]: x for x in contract["states"]}
    cases = {x["case_id"]: x for x in contract["cases"]}
    facts = {f["object_id"]: f for f in contract["facts"]}
    reference = ReferencePolicy(core)
    workers, final, rpc_receipts, events, rows, barriers, bypass = {}, {}, {}, [], [], [], []
    http_instances, sink_events = {}, []
    controller = object()
    failure = None

    def preflight():
        if sha(SOURCE_FILE) != plan["proposal_sha256"] or verify_sha_table(plan["code_sha256"])["status"] != "passed":
            raise StudyStop("frozen_input_changed")

    def checkpoint():
        path = output / "phase_progress.json"
        path.write_text(json.dumps({"events": events, "unscored_rows": rows, "barriers": barriers,
            "bypass": bypass, "sink_events": sink_events}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def native(arm, phase, command, data):
        preflight()
        result = workers[arm].call(command, data)
        events.append({"arm": arm, "phase": phase, "command": command, "input": deepcopy(data), "result": deepcopy(result)})
        checkpoint()
        if command in {"read_raw", "list_datasets", "list_data", "grant", "revoke", "whoami"}:
            validate_native_trace(result, data["actor"])
        return result

    def actual_read(arm, phase, principal, object_id):
        ds = DATASETS[object_id]
        result = native(arm, phase, "read_raw", {"dataset": ds, "fact_key": ds, "actor": principal})
        assessment = read_classification(result, facts[object_id]["text"])
        if assessment["state"] not in {"available", "denied"}: raise StudyStop("native_raw_unqualified")
        if assessment["state"] == "denied" and any(f["text"] in result["trace"]["native_raw_body"] for f in facts.values()):
            raise StudyStop("native_denial_still_contains_registered_secret")
        return result, assessment

    def fetch_target(object_id):
        result, assessment = actual_read("gateway_storage", "gateway_backend_owner_fetch", "owner", object_id)
        if assessment["state"] != "available": raise StudyStop("gateway_backend_owner_unavailable")
        return result["trace"]["native_raw_body"].encode()

    def sink(scope):
        def commit(object_id, raw, metadata):
            destination = output / "controlled_sinks" / (scope + "_" + str(len(sink_events)) + ".bin")
            destination.parent.mkdir(exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(raw)
            if destination.read_bytes() != raw:
                raise StudyStop("controlled_sink_write_not_confirmed")
            sink_events.append({"scope": scope, "object_id": object_id, "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw), "path": destination.relative_to(output).as_posix(), "metadata": deepcopy(metadata)})
            return True
        return commit

    def make_gateway(scope, snapshot=None):
        options = {"fetch_fact": (lambda oid: facts[oid]["text"].encode()) if scope.startswith("source") else fetch_target,
            "export_sinks": {"destination.approved": sink(scope)}, "controller_token": controller}
        gw = (PolicyProjectionGateway.from_snapshot(core, deepcopy(snapshot), **options) if snapshot is not None
              else PolicyProjectionGateway(core, deepcopy(states["initial"]), **options))
        http = GatewayHTTP(gw, contract["principals"], max_requests=HTTP_CAP)
        http_instances[scope] = http
        return gw, http

    active_acl = set()

    def sync_native(state, phase):
        desired = {(pid, oid) for pid in NATIVE_ACTORS for oid in facts
                   if reference.evaluate({"actor": pid, "operation": "read", "object_id": oid}, state)["decision"] == "allow"}
        changes = []
        for operation, pairs in (("revoke", sorted(active_acl - desired)), ("grant", sorted(desired - active_acl))):
            for pid, oid in pairs:
                result = native("native_projection", phase + "_" + operation, operation,
                    {"dataset": DATASETS[oid], "actor": "owner", "recipient": NATIVE_ACTORS[pid], "permission": "read"})
                if not allowed_mutation_ack(result):
                    raise StudyStop("native_acl_mutation_unqualified")
                changes.append({"operation": operation, "principal": pid, "object_id": oid})
        checks = []
        for pid in NATIVE_ACTORS:
            for oid in facts:
                result, observed = actual_read("native_projection", phase + "_barrier_read", NATIVE_ACTORS[pid], oid)
                wanted = (pid, oid) in desired
                checks.append({"principal": pid, "object_id": oid, "available": observed["state"] == "available",
                    "desired_available": wanted, "native_request_index": result["trace"]["index"]})
                if (observed["state"] == "available") != wanted:
                    raise StudyStop("native_read_projection_mismatch")
        active_acl.clear(); active_acl.update(desired)
        barriers.append({"phase": phase, "state": deepcopy(state), "changes": changes, "all_eight_reads": checks})
        checkpoint()

    def gateway_qualification(scope, http):
        for p in contract["principals"]:
            observed = http.request(p["principal_id"], identity=True)
            if observed["status"] != 200 or observed["parsed"] != {k: p[k] for k in ("user_id", "agent_id")}:
                raise StudyStop("gateway_identity_unqualified")
        denied = http.request(None, {"operation": "read", "object_id": "fact.readonly"})
        invalid = http.request("alice.reader", {}, invalid_credential=True)
        forged = http.request("bob.reader", {"actor": "alice.reader", "operation": "read", "object_id": "fact.readonly"})
        if denied["status"] != 401 or invalid["status"] != 401 or forged["status"] not in {400, 403}:
            raise StudyStop("gateway_authentication_boundary_failed")
        events.append({"arm": scope, "phase": "gateway_http_identity_and_forgery_qualification", "requests": len(http.requests)})

    def probe_bypasses(arm, phase, state):
        # All reachable objects in list responses are examined, not only top-1.
        for pid, actor in NATIVE_ACTORS.items():
            desired = {oid for oid in facts if arm == "native_projection" and (pid, oid) in active_acl}
            listed = native(arm, phase, "list_datasets", {"actor": actor})
            raw = listed.get("trace", {}).get("native_raw_body")
            list_body(listed, kind="container", target=plan["target"], expected_available=True)
            identities = {oid: final[arm]["datasets"][DATASETS[oid]]["id"] for oid in facts}
            native_fact_ids = {oid: final[arm]["facts"][DATASETS[oid]]["id"] for oid in facts}
            observed_ids = {oid for oid, rid in identities.items() if rid in raw}
            any_fact_ids = {oid for oid, rid in native_fact_ids.items() if rid in raw}
            any_fact_values = {oid for oid, f in facts.items() if f["text"] in raw}
            if observed_ids != desired or not (any_fact_ids | any_fact_values) <= desired:
                raise StudyStop("native_container_list_projection_mismatch")
            bypass.append({"arm": arm, "phase": phase, "surface": "container_list", "principal": pid,
                "registered_objects_seen": sorted(observed_ids), "native_request_index": listed["trace"]["index"]})
            for oid in facts:
                result = native(arm, phase, "list_data", {"actor": actor, "dataset": DATASETS[oid]})
                trace, expected = result.get("trace", {}), oid in desired
                body = trace.get("native_raw_body", "")
                list_body(result, kind="object", target=plan["target"], expected_available=expected)
                object_native_id = final[arm]["facts"][DATASETS[oid]]["id"]
                exposed = object_native_id in body or facts[oid]["text"] in body
                all_exposed = {other for other, rid in native_fact_ids.items() if rid in body}
                all_values = {other for other, f in facts.items() if f["text"] in body}
                if (result.get("status") not in ({200} if expected else {200, 403, 404})
                        or body.strip() == "null" or exposed != expected or not (all_exposed | all_values) <= ({oid} if expected else set())):
                    raise StudyStop("native_object_list_projection_mismatch")
                bypass.append({"arm": arm, "phase": phase, "surface": "object_list", "principal": pid,
                    "object_id": oid, "registered_object_seen": exposed, "native_request_index": trace.get("index")})
                if arm == "gateway_storage":
                    result, observed = actual_read(arm, phase, actor, oid)
                    if observed["state"] != "denied": raise StudyStop("gateway_direct_native_raw_bypass")
                    bypass.append({"arm": arm, "phase": phase, "surface": "raw", "principal": pid,
                        "object_id": oid, "registered_content_seen": False, "native_request_index": result["trace"]["index"]})
        checkpoint()

    try:
        for arm in ("native_projection", "gateway_storage"):
            preflight()
            arguments = ["--state", plan["native_states"][arm], "--http-cap", str(NATIVE_HTTP_CAP)]
            if plan["target"] == "cognee":
                arguments += ["--wheel", plan["wheel"], "--legacy-project", plan["legacy"],
                    "--expected-worker-sha256", plan["code_sha256"][plan["worker"]]]
            workers[arm] = rpc_factory(plan["python"], plan["worker"], arguments, timeout=240)
            runtime = native(arm, "independent_native_identity", "init", {})
            identities = runtime["identities"]
            required = {"owner", *NATIVE_ACTORS.values()}
            if (set(identities) != required or len({x["id"] for x in identities.values()}) != 5
                    or not all(x.get("is_superuser", x.get("role") == "admin") is False for x in identities.values())):
                raise StudyStop("five_native_ordinary_identities_unqualified")
            for oid, fact in facts.items():
                native(arm, "controller_creates_exact_fact_container", "create_dataset", {"dataset": DATASETS[oid], "actor": "owner"})
                native(arm, "controller_ingests_exact_fact", "add_exact_fact",
                    {"dataset": DATASETS[oid], "fact_key": DATASETS[oid], "actor": "owner", "text": fact["text"]})
            final[arm] = native(arm, "setup_manifest", "summary", {})

        source, source_http = make_gateway("source_main")
        gateway, gateway_http = make_gateway("gateway_main")
        gateway_qualification("source_main", source_http)
        gateway_qualification("gateway_main", gateway_http)
        child_snapshots = None
        for state_id, case_ids in GROUPS:
            state = states[state_id]
            if state_id in {"delegation_expired", "root_revoked"}:
                if child_snapshots is None: raise StudyStop("verified_children_snapshot_missing")
                source, source_http = make_gateway("source_" + state_id, child_snapshots[0])
                gateway, gateway_http = make_gateway("gateway_" + state_id, child_snapshots[1])
                source.transition_state(deepcopy(state), controller_token=controller)
                gateway.transition_state(deepcopy(state), controller_token=controller)
                events.append({"phase": "fork_from_verified_with_children", "state_id": state_id,
                    "source_parent_state_sha256": hashlib.sha256(json.dumps(child_snapshots[0], sort_keys=True).encode()).hexdigest(),
                    "independent_gateway_instances": True, "native_reuse_requires_full_acl_reset_barrier": True})
            elif state_id != "initial":
                source.transition_state(deepcopy(state), controller_token=controller)
                gateway.transition_state(deepcopy(state), controller_token=controller)
            sync_native(source.get_state_snapshot(controller_token=controller)["state"], state_id)
            probe_bypasses("native_projection", state_id, state)
            if state_id in {"initial", "all_managed_revoked"}:
                probe_bypasses("gateway_storage", state_id, state)
            for cid in case_ids:
                case = cases[cid]; body = request_body(case, contract)
                before_source = source.get_state_snapshot(controller_token=controller)
                before_gateway = gateway.get_state_snapshot(controller_token=controller)
                actual_source = source_http.request(case["actor"], body)
                actual_gateway = gateway_http.request(case["actor"], body)
                # No expected decision is provided to a running gateway/backend.
                if case["operation"] == "read":
                    result, seen = actual_read("native_projection", cid, NATIVE_ACTORS[case["actor"]], case["object_id"])
                    native_outcome = {"classification": "native", "decision": "allow" if seen["state"] == "available" else "deny",
                        "available": seen["full_content_observed"], "native_request_index": result["trace"]["index"]}
                else:
                    native_outcome = {"classification": "unrepresentable", "decision": "unsupported",
                        "reason": "This declared native mapping has no faithful constrained " + case["operation"] + " route; safely rejected without native mutation.", "available": False}
                rows.append({"case_id": cid, "state_id": state_id, "operation": case["operation"], "actor": case["actor"],
                    "request_body": body, "source_state_before": before_source, "gateway_state_before": before_gateway,
                    "source_http": actual_source, "gateway_http": actual_gateway, "native": native_outcome,
                    "source_state_after": source.get_state_snapshot(controller_token=controller),
                    "gateway_state_after": gateway.get_state_snapshot(controller_token=controller)})
                checkpoint()
                for reply in (actual_source, actual_gateway):
                    if reply["status"] >= 500 or not isinstance(reply["parsed"], dict):
                        raise StudyStop("gateway_transport_or_backend_error")
                # Actively check operation side effects without scoring labels.
                if case["operation"] in {"share", "delegate"} and actual_gateway["parsed"].get("decision") == "allow":
                    witness = gateway_http.request(body["recipient"], {"operation": "read", "object_id": body["object_id"]})
                    rows[-1]["created_grant_recipient_read"] = witness
                    if witness["parsed"].get("decision") != "allow" or (witness["parsed"].get("data") or {}).get("text") != facts[body["object_id"]]["text"]:
                        raise StudyStop("created_grant_real_read_not_confirmed")
            if state_id == "with_children":
                child_snapshots = (source.get_state_snapshot(controller_token=controller), gateway.get_state_snapshot(controller_token=controller))
                if set(child_snapshots[0]["state"]["registered_grants"]) != set(states[state_id]["registered_grants"]):
                    raise StudyStop("source_child_side_effect_registry_missing")
        # A genuine read-only native recipient tries to grant a denied fact.
        result = native("native_projection", "read_is_not_share_native_attack", "grant",
            {"dataset": "readonly", "actor": "alice_reader", "recipient": "bob_worker", "permission": "read"})
        if result["status"] not in {403, 404}: raise StudyStop("native_read_only_share_not_denied")
        _, witness = actual_read("native_projection", "read_only_share_attack_postcondition", "bob_worker", "fact.readonly")
        if witness["state"] != "denied": raise StudyStop("native_read_only_share_side_effect")
    except Exception as error:
        failure = {"exception_type": type(error).__name__, "code": str(error) if isinstance(error, StudyStop) else "study_execution_error"}
    finally:
        for name, http in http_instances.items():
            save(output / (name + "_http_requests.json"), http.requests)
            http.close()
        for arm, worker in workers.items():
            try: final[arm] = worker.call("close", {})
            except Exception as error: final[arm] = {"close_error": type(error).__name__}
            rpc_receipts[arm] = worker.calls
            worker.terminate()
        save(output / "rpc_receipts.json", rpc_receipts)
        save(output / "unscored_rows.json", rows)
        save(output / "events.json", events)
        save(output / "barriers.json", barriers)
        save(output / "bypass.json", bypass)
        save(output / "sink_events.json", sink_events)
        checkpoint()

    # Scoring is separate from requests and occurs after the unscored closure.
    save(output / "prediction_phase_closed.json", {"rows_sha256": sha(output / "unscored_rows.json"), "row_count": len(rows)})
    scored = []
    for row in rows:
        expected = cases[row["case_id"]]["expected"]
        source_decision = (row["source_http"]["parsed"] or {}).get("decision")
        gateway_decision = (row["gateway_http"]["parsed"] or {}).get("decision")
        valid_gateway = gateway_decision == expected
        registered_values_seen = {oid for oid, fact in facts.items() if fact["text"] in row["gateway_http"]["raw_body"]}
        source_values_seen = {oid for oid, fact in facts.items() if fact["text"] in row["source_http"]["raw_body"]}
        allowed_response_values = ({cases[row["case_id"]]["object_id"]} if expected == "allow"
            and row["operation"] in {"read", "import_replay"} else set())
        valid_gateway &= registered_values_seen <= allowed_response_values
        valid_source = source_decision == expected and source_values_seen <= allowed_response_values
        if expected == "allow":
            response = row["gateway_http"]["parsed"] or {}
            if row["operation"] in {"read", "import_replay"}:
                valid_gateway &= (response.get("data") or {}).get("text") == facts[cases[row["case_id"]]["object_id"]]["text"]
            else:
                valid_gateway &= response.get("side_effect", {}).get("status") == "confirmed"
        elif (row["gateway_http"]["parsed"] or {}).get("delivered_fact_ids"):
            valid_gateway = False
        native_supported = row["native"]["classification"] == "native"
        scored.append({"case_id": row["case_id"], "expected": expected, "source_matches": bool(valid_source),
            "gateway_matches_with_effect": bool(valid_gateway), "native_classification": row["native"]["classification"],
            "native_matches": row["native"]["decision"] == expected if native_supported else None})
    postflight = {"code": verify_sha_table(plan["code_sha256"]), "proposal_identical": sha(SOURCE_FILE) == plan["proposal_sha256"]}
    instrumentation = {}
    for arm, summary in final.items():
        requests = summary.get("native_requests")
        instrumentation[arm] = {"http_requests": len(requests) if isinstance(requests, list) else None,
            "http_cap_satisfied": isinstance(requests, list) and len(requests) <= NATIVE_HTTP_CAP,
            "observed_generation_attempts": summary.get("generation_attempts"),
            "observed_embedding_attempts": summary.get("embedding_attempts"),
            "no_observed_inference": summary.get("generation_attempts") == summary.get("embedding_attempts") == 0,
            "network_clear": isinstance(summary.get("network_events"), list) and all(e.get("allowed") is True for e in summary["network_events"]),
            "client_credentials_not_serialized": summary.get("client_credential_values_persisted") is False}
    complete = len(scored) == 25 and all(r["source_matches"] and r["gateway_matches_with_effect"] and r["native_matches"] is not False for r in scored)
    technical = len(instrumentation) == 2 and all(all(v[k] for k in ("http_cap_satisfied", "no_observed_inference", "network_clear", "client_credentials_not_serialized")) for v in instrumentation.values())
    qualified = failure is None and complete and technical and postflight["code"]["status"] == "passed" and postflight["proposal_identical"]
    report = {"version": VERSION, "target": plan["target"], "status": "qualified_with_declared_limits" if qualified else "incomplete_or_failed",
        "failure": failure, "case_count": len(scored), "source_matches": sum(r["source_matches"] for r in scored),
        "gateway_matches_with_effect": sum(r["gateway_matches_with_effect"] for r in scored),
        "native_read_matches": sum(r["native_matches"] is True for r in scored),
        "native_unsupported_operations": sum(r["native_classification"] == "unrepresentable" for r in scored),
        "scored_rows": scored, "instrumentation": instrumentation, "postflight": postflight, "native_final": final,
        "native_full_source_semantics_passed": False, "full_get_search_list_bypass_qualified": False,
        "semantics": plan["arms"], "search_vector_measured": False, "concurrent_revoke_measured": False,
        "new_independent_stories": 0, "synthetic_story_count": 1, "synthetic_fact_count": 2,
        "paper_novelty_established": False, "raw_artifacts_are_not_ordinary_logs": True}
    save(output / "report.json", report)
    return report


def run(output, target, *, execute_native=False, approved_plan=None):
    output = Path(output).resolve()
    if output.exists() or output == ROOT / "results" or not output.is_relative_to((ROOT / "results").resolve()):
        raise ValueError("new_workspace_results_required")
    approved = json.loads(Path(approved_plan).read_bytes()) if approved_plan else None
    plan = build_plan(target, approved=approved)
    if execute_native and (approved is None or approved != plan):
        raise ValueError("matching_frozen_plan_required")
    output.mkdir(parents=True)
    archive_code(list(plan["code_sha256"]), plan["code_sha256"], output)
    save(output / "plan.json", plan)
    (output / "source_contract.json").write_bytes(SOURCE_FILE.read_bytes())
    if not execute_native: return {"status": "plan_only", "native_calls": 0, "model_calls": 0}
    return execute(plan, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["cognee", "open_webui"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    value = run(args.output, args.target, execute_native=args.execute, approved_plan=args.approved_plan)
    print(json.dumps({k: value[k] for k in ("status", "target", "case_count", "source_matches", "gateway_matches_with_effect", "native_read_matches", "native_unsupported_operations", "failure", "instrumentation") if k in value}, ensure_ascii=False))
    raise SystemExit(0 if value["status"] in {"plan_only", "qualified_with_declared_limits"} else 1)
