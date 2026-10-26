"""Bounded native WebUI read-surface probe; no automatic native execution.

Two fresh owner-file/Note states. Seven original surfaces are retained;
read-filtered Note search replaces default-write search after ACL grants.
Owner-ineligible HTML/extracted-content surfaces are never scored as denials.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_native_exact_fact_bridge import WorkerRPC, archive_code
from scripts.native_webui_projection_worker import FROZEN_VENDOR
from scripts.native_webui_surface_worker import BASE_SHA256

VERSION = "webui_projection_surface_qualification_v1"
SOURCE = ROOT / "docs/proposals/source_policy_projection_contract_v1_20261026.json"
SOURCE_SHA256 = "918e6c4cc0c82e1c51bd43659d100b41c8b0393f4db8a4880c7862036a73ca6f"
ARMS = ("native_projection", "gateway_storage")
ACTORS = ("owner", "alice_reader", "alice_worker", "bob_reader", "bob_worker")
DATASETS = {"fact.readonly": "readonly", "fact.managed": "managed"}
PER_FILE = ("file_metadata", "file_data_content", "file_content_html", "file_content_named")
GLOBAL = ("file_list", "file_search", "note_search")
PHASES = ("ungranted_control", "current_read_grants", "alice_read_revoked")
HTTP_CAP = 200
EXPECTED_HTTP = {"native_projection": 192, "gateway_storage": 187}
VENDOR_EXTRA = {"models/files.py": "e0770c88528e5f95f64ee56fd11f1e662065ba269a7bf44688fa6d5ce224cb6d"}


class ProbeStop(ValueError):
    pass


def digest(raw): return hashlib.sha256(raw).hexdigest()
def file_sha(path): return digest(Path(path).read_bytes())


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def read_json(path):
    return json.loads(Path(path).read_bytes(), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def sweep_manifest(actor, phase):
    rows = [{"actor": actor, "object_id": oid, "operation": op} for oid in DATASETS for op in PER_FILE]
    for op in GLOBAL:
        effective = "note_search_read" if op == "note_search" and phase != "ungranted_control" else op
        rows.append({"actor": actor, "object_id": None, "operation": effective})
    return rows


def protocol_manifest():
    rows = []
    for phase in PHASES:
        actors = ACTORS if phase == "ungranted_control" else ACTORS[1:]
        for actor in actors:
            rows.extend(dict(item, phase=phase) for item in sweep_manifest(actor, phase))
        if phase == "ungranted_control":
            rows.append({"actor": "owner", "object_id": None, "operation": "note_search_read", "phase": phase})
        if phase == "current_read_grants":
            rows.append({"actor": "alice_reader", "object_id": None, "operation": "note_search", "phase": phase,
                "paired_default_write_control": True})
    return rows


def policy_relations(arm, phase):
    if arm == "gateway_storage" or phase == "ungranted_control": return set()
    if phase == "current_read_grants":
        return {("alice_reader", "fact.readonly"), ("alice_reader", "fact.managed"), ("bob_reader", "fact.managed")}
    if phase == "alice_read_revoked": return {("bob_reader", "fact.managed")}
    raise ValueError("unknown_probe_phase")


def source_states(contract):
    initial = deepcopy(next(s for s in contract["states"] if s["state_id"] == "initial"))
    empty = dict(initial, state_id="surface_ungranted_control", registered_grants=[])
    revoked = dict(initial, state_id="surface_alice_read_revoked", time=14, policy_revision=2,
        revoked_grants=["grant.readonly", "grant.root"])
    return {PHASES[0]: empty, PHASES[1]: initial, PHASES[2]: revoked}


def source_read_relations(contract, state):
    grants = {g["grant_id"]: g for g in contract["grants"]}
    def valid(gid):
        visited = set()
        while gid is not None:
            if gid in visited or gid not in grants: return False
            visited.add(gid); grant = grants[gid]
            if (gid not in state["registered_grants"] or gid in state["revoked_grants"]
                    or not grant["not_before"] <= state["time"] < grant["expires_at"]): return False
            gid = grant["parent_grant_id"]
        return True
    return {(grant["subject"].replace(".", "_"), grant["object_id"]) for gid, grant in grants.items()
        if "read" in grant["actions"] and valid(gid)}


def build_plan(*, approved=None):
    python = ROOT / ".venv-native-webui/Scripts/python.exe"
    worker = ROOT / "scripts/native_webui_surface_worker.py"
    if not python.is_file() or file_sha(ROOT / "scripts/native_webui_projection_worker.py") != BASE_SHA256:
        raise ValueError("pinned_native_runtime_or_base_missing")
    if file_sha(SOURCE) != SOURCE_SHA256: raise ValueError("source_contract_changed")
    vendor_root = python.parent.parent / "Lib/site-packages/open_webui"
    vendor = dict(FROZEN_VENDOR, **VENDOR_EXTRA)
    vendor_files = {}
    for name, expected in vendor.items():
        path = vendor_root / name
        if not path.is_file() or file_sha(path) != expected: raise ValueError("fixed_vendor_source_changed")
        vendor_files[str(path.resolve())] = expected
    files = [Path(__file__), worker, ROOT / "scripts/native_webui_projection_worker.py",
        ROOT / "scripts/native_exact_fact_common.py", ROOT / "scripts/run_native_exact_fact_bridge.py"]
    files += sorted((ROOT / "memory_migration_study").glob("*.py"))
    files = list(dict.fromkeys(p.resolve() for p in files))
    native_states = {}
    for arm in ARMS:
        state = Path(approved["native_states"][arm]) if approved else Path(tempfile.gettempdir()) / ("webui_surface_" + arm + "_" + uuid.uuid4().hex)
        if state.exists() or state.parent.resolve() != Path(tempfile.gettempdir()).resolve() or not str(state).isascii():
            raise ValueError("new_ascii_system_temp_child_required")
        native_states[arm] = str(state.resolve())
    if len(set(native_states.values())) != 2: raise ValueError("separate_native_states_required")
    contract = read_json(SOURCE)
    declared_states = source_states(contract)
    if any(source_read_relations(contract, state) != policy_relations("native_projection", phase)
        for phase, state in declared_states.items()):
        raise ValueError("source_chain_and_registered_phase_relations_disagree")
    return {"version": VERSION, "python": str(python.resolve()), "worker": str(worker.resolve()),
        "native_states": native_states, "source_contract": str(SOURCE), "source_contract_sha256": SOURCE_SHA256,
        "code_sha256": {str(p): file_sha(p) for p in files}, "vendor_source_sha256": vendor_files,
        "base_worker_sha256": BASE_SHA256, "http_cap_per_arm": HTTP_CAP,
        "expected_http_by_arm": EXPECTED_HTTP, "max_native_http_total": 379,
        "max_model_calls": 0, "max_paid_calls": 0, "concurrency": 1, "automatic_retries": 0,
        "actors": list(ACTORS), "source_tuple_mapping": {a.replace("_", ".", 1): a for a in ACTORS[1:]},
        "facts": contract["facts"], "source_states": declared_states,
        "source_state_boundary": "The empty control and revocation of both grant.readonly/grant.root are declared surface-fixture states, not additional original 25 cases. Independent grant.independent is retained.",
        "manifest_per_arm": protocol_manifest(), "expected_surface_rows_per_arm": 145,
        "raw_barriers": {"phases": list(PHASES[1:]), "relations_per_phase_per_arm": 8},
        "global_anchor": "readonly (ignored by the official global URL; no duplicate global call for managed)",
        "query_semantics": {"file_list": "owner uploads only; not shared Note enumeration",
            "file_search": "owner uploads only; no matches returns native404",
            "note_search": "original default permission=write; read-only grant does not require visibility",
            "note_search_read": "official permission=read; current Note read ACL plus ownership",
            "file_content_html": "ordinary uploader may be unsupported because official route requires uploader admin",
            "file_data_content": "process=false preserves raw upload; absent extracted text is not qualified content"},
        "owner_positive_rule": "same interface and object/value evidence first, per arm and per fact; no owner positive means no denial/utility pass",
        "stop_rule": "Immediately stop on auth/inference/network/asset/protocol failures or any forbidden registered fact/fileID/noteID. Preserve all raw results, no automatic retry. Unsupported/null owner content is recorded without becoming a permission pass.",
        "scope": "Native read-only surface qualification with explicit composite users; G owner-only native confinement, not a new gateway deployment, autonomous LLM Agent, full bypass proof or algorithm innovation."}


def verify_inputs(plan):
    if file_sha(SOURCE) != plan["source_contract_sha256"]: raise ProbeStop("source_contract_changed")
    for table in (plan["code_sha256"], plan["vendor_source_sha256"]):
        for path, expected in table.items():
            if not Path(path).is_file() or file_sha(path) != expected: raise ProbeStop("frozen_source_changed")


def trace_body(result, actor):
    trace = result.get("trace", {})
    raw = trace.get("native_raw_body")
    if (not isinstance(raw, str) or result.get("status") != trace.get("status") or trace.get("actor") != actor
            or trace.get("response_checked") is not True or trace.get("execution_error") is not None
            or trace.get("authorization_present") is not True or trace.get("api_key_present") is not False
            or trace.get("cookie_present") is not False or digest(raw.encode()) != trace.get("native_body_sha256")):
        raise ProbeStop("authenticated_native_trace_invalid")
    return trace, raw


def strings(value):
    if isinstance(value, str): return [value]
    if isinstance(value, dict): return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list): return [s for v in value for s in strings(v)]
    return []


def parsed_body(raw):
    try: return json.loads(raw)
    except (ValueError, UnicodeError): return None


def evidence(raw, parsed, facts, summary):
    haystacks = [raw, *strings(parsed)]
    def found(value): return any(value in s for s in haystacks)
    return {"values": sorted(oid for oid, f in facts.items() if found(f["text"])),
        "files": sorted(oid for oid, ds in DATASETS.items() if found(summary["facts"][ds]["id"])),
        "notes": sorted(oid for oid, ds in DATASETS.items() if found(summary["datasets"][ds]["id"]))}


def shape(operation, parsed):
    if operation == "file_metadata":
        return isinstance(parsed, dict) and all(isinstance(parsed.get(k), str) for k in ("id", "user_id", "filename"))
    if operation == "file_data_content": return isinstance(parsed, dict) and "content" in parsed and isinstance(parsed["content"], (str, type(None)))
    if operation in {"file_list", "note_search", "note_search_read"}:
        return (isinstance(parsed, dict) and isinstance(parsed.get("items"), list) and type(parsed.get("total")) is int
            and parsed["total"] >= 0 and all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in parsed["items"]))
    if operation == "file_search": return isinstance(parsed, list) and all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in parsed)
    return True


def classify(result, item, *, arm, facts, summary, owner_qualification):
    """Independent source authorization and native query-view observations.

    Eligibility never grants permission. Full response scanning precedes any
    unsupported/empty handling, including owner-ineligible surfaces.
    """
    actor, operation, oid, phase = item["actor"], item["operation"], item["object_id"], item["phase"]
    trace, raw = trace_body(result, actor)
    status, parsed = result["status"], parsed_body(raw)
    seen = evidence(raw, parsed, facts, summary)
    all_seen = set(seen["values"]) | set(seen["files"]) | set(seen["notes"])
    policy_allowed = set(facts) if actor == "owner" else {o for a, o in policy_relations(arm, phase) if a == actor}
    forbidden = all_seen - policy_allowed
    answer = {"classification": None, "owner_qualified": False, "safety_verdict": None, "view_matches": None,
        "utility_verdict": None, "evidence": seen, "source_read_allowed_objects": sorted(policy_allowed),
        "native_request_index": trace["index"], "safety_failure": False, "transport_failure": False,
        "unexpected_qualification_gap": False}
    if forbidden or (status in {403, 404} and all_seen):
        return dict(answer, classification="forbidden_registered_material_in_response", safety_failure=True,
            safety_verdict=False, forbidden_objects=sorted(forbidden or all_seen))
    if status == 401 or status >= 500 or status not in {200, 403, 404}:
        return dict(answer, classification="authentication_or_execution_error", transport_failure=True)
    denial = status in {403, 404} and isinstance(parsed, dict) and isinstance(parsed.get("detail"), str) and bool(parsed["detail"])
    if operation in {"file_list", "file_search", "note_search"}:
        expected_view = set(facts) if actor == "owner" else set()
    elif operation == "note_search_read": expected_view = policy_allowed
    else: expected_view = {oid} if oid in policy_allowed else set()
    answer["native_view_expected_objects"] = sorted(expected_view)
    owner = actor == "owner"
    owner_eligible = owner_qualification.get("qualified") is True if not owner else False
    if operation == "file_content_html" and owner and denial:
        return dict(answer, classification="unsupported_owner_not_admin", owner_qualified=False)
    if operation == "file_data_content" and owner:
        if status == 200 and isinstance(parsed, dict) and (parsed.get("content") is None or parsed.get("content") == ""):
            return dict(answer, classification="not_qualified_no_extracted_content")
        if status == 200 and parsed is None:
            return dict(answer, classification="not_qualified_owner_null_response")
    if status == 200 and not shape(operation, parsed):
        return dict(answer, classification="unqualified_response_schema", unexpected_qualification_gap=True)
    if operation in {"file_content_named", "file_content_html"}:
        valid_success = status == 200 and raw == facts[oid]["text"]
    elif operation == "file_data_content":
        valid_success = status == 200 and isinstance(parsed, dict) and parsed.get("content") == facts[oid]["text"]
    elif operation == "file_metadata":
        valid_success = status == 200 and parsed["id"] == summary["facts"][DATASETS[oid]]["id"]
    else:
        rows = parsed if operation == "file_search" else (parsed or {}).get("items", [])
        id_map = summary["datasets"] if operation.startswith("note_search") else summary["facts"]
        expected_ids = {id_map[DATASETS[o]]["id"] for o in expected_view}
        valid_success = status == 200 and {r["id"] for r in rows} == expected_ids and len(rows) == len(expected_ids)
        if operation != "file_search" and status == 200: valid_success &= parsed["total"] == len(expected_ids)
        if operation == "file_search" and not expected_view and denial: valid_success = True
    if owner:
        if valid_success and expected_view:
            return dict(answer, classification="qualified_owner_positive", owner_qualified=True, safety_verdict=True,
                view_matches=True, utility_verdict=True)
        return dict(answer, classification="not_qualified_owner_positive_missing", unexpected_qualification_gap=True)
    answer["owner_qualified"] = owner_eligible
    if not owner_eligible:
        return dict(answer, classification="not_qualified_owner_interface_unavailable")
    direct = operation in PER_FILE
    match = valid_success if expected_view or not direct else denial
    if status == 200 and raw.strip() in {"", "null"}:
        return dict(answer, classification="not_qualified_empty_or_null_not_denial", unexpected_qualification_gap=True)
    return dict(answer, classification="qualified_native_view" if match else "native_view_mismatch",
        safety_verdict=True, view_matches=bool(match), utility_verdict=bool(match) if expected_view else None,
        unexpected_qualification_gap=not match)


def execute(plan, output, *, rpc_factory=WorkerRPC, validate_inputs=verify_inputs):
    contract = read_json(SOURCE); facts = {f["object_id"]: f for f in contract["facts"]}
    workers, summaries, rpc_originals = {}, {}, {}
    events, observations, barriers, owner_qualifications = [], [], [], {}
    failure = None
    def checkpoint():
        (output / "phase_progress.json").write_text(json.dumps({"events": events, "observations": observations,
            "barriers": barriers, "owner_qualifications": owner_qualifications}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    def native(arm, phase, command, data):
        validate_inputs(plan)
        try:
            result = workers[arm].call(command, data)
        except Exception as error:
            events.append({"arm": arm, "phase": phase, "command": command, "input": deepcopy(data),
                "rpc_failed": True, "exception_type": type(error).__name__})
            checkpoint(); raise
        events.append({"arm": arm, "phase": phase, "command": command, "input": deepcopy(data), "result": deepcopy(result)})
        checkpoint()
        if command in {"grant", "revoke", "read_raw", "bypass"}: trace_body(result, data["actor"])
        return result
    def one_surface(arm, item):
        oid = item["object_id"] or "fact.readonly"
        result = native(arm, item["phase"], "bypass", {"dataset": DATASETS[oid], "fact_key": DATASETS[oid],
            "actor": item["actor"], "operation": item["operation"]})
        key = item["operation"] + "|" + (item["object_id"] or "GLOBAL")
        owners = owner_qualifications.setdefault(arm, {})
        assessment = classify(result, item, arm=arm, facts=facts, summary=summaries[arm],
            owner_qualification=owners.get(key, {}))
        observations.append({"arm": arm, **deepcopy(item), "native_result": result, "assessment": assessment})
        if item["actor"] == "owner": owners[key] = {"qualified": assessment["owner_qualified"],
            "classification": assessment["classification"], "native_request_index": result["trace"]["index"]}
        checkpoint()
        if assessment["safety_failure"]: raise ProbeStop("registered_material_disclosure")
        if assessment["transport_failure"]: raise ProbeStop("native_surface_transport_or_auth_failure")
    def raw_barrier(arm, phase):
        checks = []
        wanted = policy_relations(arm, phase)
        for actor in ACTORS[1:]:
            for oid, ds in DATASETS.items():
                result = native(arm, phase + "_raw_barrier", "read_raw", {"actor": actor, "dataset": ds, "fact_key": ds})
                trace, raw = trace_body(result, actor)
                available = (actor, oid) in wanted
                seen = evidence(raw, parsed_body(raw), facts, summaries[arm])
                all_seen = set(seen["values"]) | set(seen["files"]) | set(seen["notes"])
                denial = parsed_body(raw)
                valid = result["status"] == 200 and raw == facts[oid]["text"] if available else (
                    result["status"] in {403, 404} and isinstance(denial, dict)
                    and isinstance(denial.get("detail"), str) and bool(denial["detail"]) and not all_seen)
                check = {"actor": actor, "object_id": oid, "expected_available": available,
                    "actual_exact_match_or_true_denial": bool(valid), "native_result": deepcopy(result)}
                checks.append(check)
                barriers.append({"arm": arm, "phase": phase, **check}); checkpoint()
                if not valid: raise ProbeStop("native_current_read_barrier_mismatch")
    try:
        for arm in ARMS:
            validate_inputs(plan)
            workers[arm] = rpc_factory(plan["python"], plan["worker"], ["--state", plan["native_states"][arm],
                "--expected-worker-sha256", plan["code_sha256"][plan["worker"]], "--http-cap", str(HTTP_CAP)], timeout=240)
            runtime = native(arm, "identity_qualification", "init", {})
            ids = runtime["identities"]
            if set(ids) != set(ACTORS) or len({x["id"] for x in ids.values()}) != 5 or any(x.get("role") != "user" for x in ids.values()):
                raise ProbeStop("five_independent_ordinary_native_users_unqualified")
            for oid, ds in DATASETS.items():
                native(arm, "exact_fact_setup", "create_dataset", {"dataset": ds, "actor": "owner"})
                native(arm, "exact_fact_setup", "add_exact_fact", {"dataset": ds, "fact_key": ds, "actor": "owner", "text": facts[oid]["text"]})
            summaries[arm] = native(arm, "setup_manifest", "summary", {})
        if set(summaries[ARMS[0]]["identities"][a]["id"] for a in ACTORS) & set(summaries[ARMS[1]]["identities"][a]["id"] for a in ACTORS):
            raise ProbeStop("native_arms_share_identity")
        manifest = plan["manifest_per_arm"]
        for phase in PHASES:
            if phase != PHASES[0]:
                targets = [("alice_reader", "readonly"), ("alice_reader", "managed"), ("bob_reader", "managed")] if phase == PHASES[1] else [("alice_reader", "readonly"), ("alice_reader", "managed")]
                operation = "grant" if phase == PHASES[1] else "revoke"
                for actor, ds in targets:
                    result = native("native_projection", phase + "_acl", operation,
                        {"dataset": ds, "actor": "owner", "recipient": actor, "permission": "read"})
                    if result["status"] != 200: raise ProbeStop("native_acl_mutation_failed")
                for arm in ARMS: raw_barrier(arm, phase)
            for arm in ARMS:
                for item in manifest:
                    if item["phase"] == phase: one_surface(arm, item)
    except Exception as error:
        failure = {"exception_type": type(error).__name__, "code": str(error) if isinstance(error, ProbeStop) else "surface_probe_execution_error"}
    finally:
        for arm, worker in workers.items():
            try: summaries[arm] = worker.call("close", {})
            except Exception as error: summaries[arm] = {"close_error": type(error).__name__}
            rpc_originals[arm] = worker.calls
            worker.terminate()
        save(output / "events.json", events); save(output / "observations.json", observations)
        save(output / "barriers.json", barriers); save(output / "owner_qualifications.json", owner_qualifications)
        save(output / "native_summaries.json", summaries); save(output / "rpc_receipts.json", rpc_originals)
        checkpoint()
    save(output / "prediction_phase_closed.json", {"observations_sha256": file_sha(output / "observations.json"), "observation_count": len(observations)})
    try: validate_inputs(plan); postflight = {"status": "passed"}
    except Exception: postflight = {"status": "failed"}
    counts, technical = {}, True
    for arm, summary in summaries.items():
        requests = summary.get("native_requests", [])
        counts[arm] = {"http_records": len(requests), "expected_complete_http": EXPECTED_HTTP[arm],
            "cap_satisfied": len(requests) <= HTTP_CAP, "exact_expected_count": len(requests) == EXPECTED_HTTP[arm],
            "generation_attempts": summary.get("generation_attempts"), "embedding_attempts": summary.get("embedding_attempts"),
            "network_clear": isinstance(summary.get("network_events"), list) and all(x.get("allowed") is True for x in summary["network_events"]),
            "credential_values_not_saved": summary.get("client_credential_values_persisted") is False}
        technical &= (counts[arm]["cap_satisfied"] and counts[arm]["exact_expected_count"] and counts[arm]["network_clear"]
            and counts[arm]["credential_values_not_saved"] and summary.get("generation_attempts") == summary.get("embedding_attempts") == 0)
    assessments = [o["assessment"] for o in observations]
    gaps = sum(a["unexpected_qualification_gap"] for a in assessments)
    complete = len(observations) == 290 and len(barriers) == 32 and len(summaries) == 2
    ok = failure is None and complete and technical and postflight["status"] == "passed" and gaps == 0
    real = rpc_factory is WorkerRPC
    status = "completed_with_declared_surface_limits" if ok else "incomplete_or_unqualified"
    if not real and ok: status = "fake_transport_protocol_completed"
    report = {"version": VERSION, "status": status, "failure": failure,
        "execution_backend": "native_vendor_cli_child_process" if real else "explicit_fake_rpc_only",
        "native_qualification_established": bool(real and ok), "observation_count": len(observations),
        "raw_barrier_relations": len(barriers), "classification_counts": dict(Counter(a["classification"] for a in assessments)),
        "owner_qualified_rows": sum(a["owner_qualified"] for a in assessments),
        "qualified_safety_true": sum(a["safety_verdict"] is True for a in assessments),
        "qualified_safety_false": sum(a["safety_verdict"] is False for a in assessments),
        "unqualified_or_unsupported_safety_rows": sum(a["safety_verdict"] is None for a in assessments),
        "qualified_native_view_matches": sum(a["view_matches"] is True for a in assessments),
        "unexpected_qualification_gaps": gaps, "http_instrumentation": counts, "postflight": postflight,
        "all_eight_surface_variants_qualified": False, "all_seven_original_surfaces_privacy_proven": False,
        "full_get_search_list_bypass_qualified": False, "search_kind": "filename and Note title SQL filters, not vector or semantic search",
        "ordinary_owner_html_or_extracted_content_was_not_repaired": True,
        "native_agent_IAM_or_online_source_revocation_claimed": False,
        "native_default_write_search_is_model_refusal": False,
        "new_independent_stories": 0, "synthetic_story_count": 1, "synthetic_fact_count": 2,
        "paper_novelty_established": False, "native_auth_store_publishable": False}
    save(output / "report.json", report)
    return report


def run(output, *, execute_native=False, approved_plan=None):
    output = Path(output).resolve(); results = (ROOT / "results").resolve()
    if output.exists() or output == results or not output.is_relative_to(results): raise ValueError("new_results_directory_required")
    approved = read_json(approved_plan) if approved_plan else None
    plan = build_plan(approved=approved)
    if execute_native and (approved is None or approved != plan): raise ValueError("exact_frozen_plan_required")
    output.mkdir(parents=True)
    archive_code(list(plan["code_sha256"]), plan["code_sha256"], output)
    save(output / "plan.json", plan); (output / "source_contract.json").write_bytes(SOURCE.read_bytes())
    if not execute_native: return {"status": "plan_only", "native_calls": 0, "model_calls": 0, "expected_http_by_arm": EXPECTED_HTTP}
    return execute(plan, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true"); mode.add_argument("--execute", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    report = run(args.output, execute_native=args.execute, approved_plan=args.approved_plan)
    print(json.dumps({k: report[k] for k in ("status", "failure", "observation_count", "http_instrumentation", "expected_http_by_arm") if k in report}, ensure_ascii=False))
    raise SystemExit(0 if report["status"] in {"plan_only", "completed_with_declared_surface_limits"} else 1)
