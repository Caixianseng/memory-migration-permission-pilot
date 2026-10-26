"""Independent standard-library audit of saved WebUI surface evidence.

Never imports the producer, its scorer, WebUI, or models. Only the named fresh
state safe_responses/*.bin may be read; no token or native auth-store reads.
Passing consistency checks is not a full-search, privacy or novelty claim.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "independent_webui_surface_probe_verification_v1"
SOURCE_SHA256 = "918e6c4cc0c82e1c51bd43659d100b41c8b0393f4db8a4880c7862036a73ca6f"
BASE_SHA256 = "222718f0ac5f5d424ce5ff20793fe3a9fca4ea380218ed4d10096f39c5473ed7"
ARMS = ("native_projection", "gateway_storage")
ACTORS = ("owner", "alice_reader", "alice_worker", "bob_reader", "bob_worker")
PHASES = ("ungranted_control", "current_read_grants", "alice_read_revoked")
OBJECTS = {"fact.readonly": "readonly", "fact.managed": "managed"}
PER_FILE = ("file_metadata", "file_data_content", "file_content_html", "file_content_named")
GLOBALS = ("file_list", "file_search", "note_search")
EXPECTED_HTTP = {"native_projection": 192, "gateway_storage": 187}
ARTIFACTS = ("plan.json", "source_contract.json", "events.json", "observations.json", "barriers.json",
    "owner_qualifications.json", "native_summaries.json", "rpc_receipts.json", "prediction_phase_closed.json", "report.json")
VENDOR = {
    "main.py": "1c304a6f0922e044d71b14640e08249dbdd53f16fcb2d15c69c572700aa62340",
    "config.py": "03cad3c2f13921d34354bea8f882aabb4e788262a45c097314ea83983501f284",
    "routers/auths.py": "f32e2e742406555551a091983703a674445a9589c39689dcb6ea934c194a7f18",
    "routers/files.py": "a8bba0ef436e95c955b23b738f5498b8fe0fe14cf3ad374f5c07025394c45c78",
    "routers/notes.py": "1cd8b24bf09a79f8e4faefdc183d78f9ba176bab61a49f4f0ab843ac33bad9df",
    "routers/knowledge.py": "40fc15da1f21489ddcf9e975bf46a9b80cd8f9330ddcac249fa7b2a524ccf22e",
    "routers/retrieval.py": "64931fc93e722ef5b9ff692166afd5632b02d7574619e1368d1ab1d184a4bd77",
    "models/notes.py": "31df0e16ad47e40b32e47fb673142ac89cb9fc9df39c84a8c65131bcf6a49888",
    "models/access_grants.py": "8887a1b25fb041f73bcc5696bc57765f8c07c0cd3ab3f4eb6cb8f139e7ccfe71",
    "utils/access_control/__init__.py": "c0c6f04782e321e770957f29c7296b6ed9b37b33e4908758354ef0bbd36221a0",
    "utils/access_control/files.py": "87d406ca2b5e4846e0d8ddc9403d42ee3dda33cc6f52e6919ce0352ef3202f18",
    "retrieval/utils.py": "23cfb06e1e9da4da206991c9a14f6e26470320cba71300ab13e4a899fde0dbf5",
    "models/files.py": "e0770c88528e5f95f64ee56fd11f1e662065ba269a7bf44688fa6d5ce224cb6d",
}


class AuditError(ValueError):
    pass


def require(value, code):
    if not value:
        raise AuditError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def same(a, b):
    return compact(a) == compact(b)


def loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(AuditError("nonfinite_json")))


def read(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= 64 * 1024 * 1024, "oversized_evidence")
    return loads(raw)


def response_json(raw):
    try:
        return loads(raw)
    except (ValueError, UnicodeError, TypeError):
        return None


def manifest():
    result = []
    for phase in PHASES:
        for actor in ACTORS if phase == PHASES[0] else ACTORS[1:]:
            for oid in OBJECTS:
                for operation in PER_FILE:
                    result.append({"actor": actor, "object_id": oid, "operation": operation, "phase": phase})
            for operation in GLOBALS:
                if operation == "note_search" and phase != PHASES[0]:
                    operation = "note_search_read"
                result.append({"actor": actor, "object_id": None, "operation": operation, "phase": phase})
        if phase == PHASES[0]:
            result.append({"actor": "owner", "object_id": None, "operation": "note_search_read", "phase": phase})
        if phase == PHASES[1]:
            result.append({"actor": "alice_reader", "object_id": None, "operation": "note_search", "phase": phase,
                "paired_default_write_control": True})
    return result


def fixture_states(contract):
    initial = deepcopy(next(s for s in contract["states"] if s["state_id"] == "initial"))
    return {PHASES[0]: dict(initial, state_id="surface_ungranted_control", registered_grants=[]),
        PHASES[1]: initial,
        PHASES[2]: dict(initial, state_id="surface_alice_read_revoked", time=14, policy_revision=2,
            revoked_grants=["grant.readonly", "grant.root"])}


def source_relations(contract, state):
    """OR independent grants; AND every current ancestor, object and interval."""
    grants = {g["grant_id"]: g for g in contract["grants"]}
    require(len(grants) == len(contract["grants"]), "duplicate_grant")
    principal_ids = {p["principal_id"] for p in contract["principals"]}
    def valid(gid, stack=()):
        require(gid in grants and gid not in stack, "invalid_grant_dependency")
        grant = grants[gid]
        if (gid not in state["registered_grants"] or gid in state["revoked_grants"]
                or not grant["not_before"] <= state["time"] < grant["expires_at"]):
            return False
        parent = grant["parent_grant_id"]
        return parent is None or valid(parent, stack + (gid,))
    result = set()
    for grant in grants.values():
        require(grant["subject"] in principal_ids, "unbound_grant_subject")
        if "read" in grant["actions"] and valid(grant["grant_id"]):
            actor = grant["subject"].replace(".", "_", 1)
            require(actor in ACTORS[1:] and grant["object_id"] in OBJECTS, "out_of_fixture_grant")
            result.add((actor, grant["object_id"]))
    return result


def direct_objects(contract, phase, arm, actor):
    if actor == "owner":
        return set(OBJECTS)
    if arm == "gateway_storage":
        return set()  # Storage confinement, not the abstract source's permission.
    return {oid for principal, oid in source_relations(contract, fixture_states(contract)[phase]) if principal == actor}


def visible_objects(operation, actor, allowed, oid):
    if operation in {"file_list", "file_search", "note_search"}:
        return set(OBJECTS) if actor == "owner" else set()
    if operation == "note_search_read":
        return set(allowed)
    return {oid} if oid in allowed else set()


def all_strings(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in all_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in all_strings(v)]
    return []


def scan(raw, parsed, facts, summary):
    strings = [raw, *all_strings(parsed)]
    found = lambda value: any(value in s for s in strings)
    return {"values": sorted(oid for oid, fact in facts.items() if found(fact["text"])),
        "files": sorted(oid for oid, ds in OBJECTS.items() if found(summary["facts"][ds]["id"])),
        "notes": sorted(oid for oid, ds in OBJECTS.items() if found(summary["datasets"][ds]["id"]))}


def checked_trace(result, actor):
    trace = result["trace"]
    raw = trace.get("native_raw_body")
    require(isinstance(raw, str) and result.get("status") == trace.get("status") and trace.get("actor") == actor,
        "wrong_actor_or_response_status")
    require(trace.get("response_checked") is True and trace.get("execution_error") is None
        and trace.get("authorization_present") is True and trace.get("api_key_present") is False
        and trace.get("cookie_present") is False, "invalid_authenticated_trace")
    require(sha(raw.encode("utf-8")) == trace.get("native_body_sha256"), "raw_body_hash_mismatch")
    return trace, raw


def schema(operation, value):
    if operation == "file_metadata":
        return isinstance(value, dict) and all(isinstance(value.get(k), str) for k in ("id", "user_id", "filename"))
    if operation == "file_data_content":
        return isinstance(value, dict) and "content" in value and isinstance(value["content"], (str, type(None)))
    if operation in {"file_list", "note_search", "note_search_read"}:
        return isinstance(value, dict) and isinstance(value.get("items"), list) and type(value.get("total")) is int \
            and value["total"] >= 0 and all(isinstance(r, dict) and isinstance(r.get("id"), str) for r in value["items"])
    if operation == "file_search":
        return isinstance(value, list) and all(isinstance(r, dict) and isinstance(r.get("id"), str) for r in value)
    return True


def assess(result, item, *, arm, contract, summary, owners):
    """Independent source and native view calculation; no producer import."""
    trace, raw = checked_trace(result, item["actor"])
    status, parsed = trace["status"], response_json(raw)
    actor, operation, oid = item["actor"], item["operation"], item["object_id"]
    allowed = direct_objects(contract, item["phase"], arm, actor)
    facts = {f["object_id"]: f for f in contract["facts"]}
    evidence = scan(raw, parsed, facts, summary)
    seen = set().union(*(set(v) for v in evidence.values()))
    answer = {"classification": None, "owner_qualified": False, "safety_verdict": None, "view_matches": None,
        "utility_verdict": None, "evidence": evidence, "source_read_allowed_objects": sorted(allowed),
        "native_request_index": trace["index"], "safety_failure": False, "transport_failure": False,
        "unexpected_qualification_gap": False}
    forbidden = seen - allowed
    if forbidden or (status in {403, 404} and seen):
        return dict(answer, classification="forbidden_registered_material_in_response", safety_failure=True,
            safety_verdict=False, forbidden_objects=sorted(forbidden or seen))
    if status == 401 or status >= 500 or status not in {200, 403, 404}:
        return dict(answer, classification="authentication_or_execution_error", transport_failure=True)
    denial = status in {403, 404} and isinstance(parsed, dict) and isinstance(parsed.get("detail"), str) and bool(parsed["detail"])
    expected = visible_objects(operation, actor, allowed, oid)
    answer["native_view_expected_objects"] = sorted(expected)
    key = operation + "|" + (oid or "GLOBAL")
    owner = actor == "owner"
    eligible = owners.get(key, {}).get("qualified") is True if not owner else False
    if owner and operation == "file_content_html" and denial:
        return dict(answer, classification="unsupported_owner_not_admin")
    if owner and operation == "file_data_content":
        if status == 200 and isinstance(parsed, dict) and parsed.get("content") in {"", None}:
            return dict(answer, classification="not_qualified_no_extracted_content")
        if status == 200 and parsed is None:
            return dict(answer, classification="not_qualified_owner_null_response")
    if status == 200 and not schema(operation, parsed):
        return dict(answer, classification="unqualified_response_schema", unexpected_qualification_gap=True)
    if operation in {"file_content_named", "file_content_html"}:
        success = status == 200 and raw == facts[oid]["text"]
    elif operation == "file_data_content":
        success = status == 200 and isinstance(parsed, dict) and parsed.get("content") == facts[oid]["text"]
    elif operation == "file_metadata":
        success = status == 200 and parsed["id"] == summary["facts"][OBJECTS[oid]]["id"]
    else:
        rows = parsed if operation == "file_search" else (parsed or {}).get("items", [])
        mapping = summary["datasets"] if operation.startswith("note_search") else summary["facts"]
        ids = {mapping[OBJECTS[o]]["id"] for o in expected}
        success = status == 200 and {r["id"] for r in rows} == ids and len(rows) == len(ids)
        if status == 200 and operation != "file_search":
            success = success and parsed["total"] == len(ids)
        if operation == "file_search" and not expected and denial:
            success = True
    if owner:
        if success and expected:
            return dict(answer, classification="qualified_owner_positive", owner_qualified=True,
                safety_verdict=True, view_matches=True, utility_verdict=True)
        return dict(answer, classification="not_qualified_owner_positive_missing", unexpected_qualification_gap=True)
    answer["owner_qualified"] = eligible
    if not eligible:
        return dict(answer, classification="not_qualified_owner_interface_unavailable")
    match = success if expected or operation not in PER_FILE else denial
    if status == 200 and raw.strip() in {"", "null"}:
        return dict(answer, classification="not_qualified_empty_or_null_not_denial", unexpected_qualification_gap=True)
    return dict(answer, classification="qualified_native_view" if match else "native_view_mismatch",
        safety_verdict=True, view_matches=bool(match), utility_verdict=bool(match) if expected else None,
        unexpected_qualification_gap=not match)


def safe_response_path(trace, state):
    """Validate the complete scope before any file read; never follow auth paths."""
    state = Path(state).resolve()
    temp = Path(tempfile.gettempdir()).resolve()
    require(state.parent == temp and state.name.startswith("webui_surface_") and str(state).isascii(), "unapproved_native_state")
    safe = state / "safe_responses"
    require(not safe.is_symlink() and safe.resolve().parent == state, "safe_directory_escape")
    path = Path(trace["native_response_file"])
    require(not path.is_symlink() and path.name == f"{trace['index']:04d}.bin"
        and path.parent.resolve() == safe.resolve() and path.resolve().parent == safe.resolve(), "unsafe_response_path")
    return path


def require_count(requests, arm):
    require(len(requests) == EXPECTED_HTTP[arm] and len(requests) <= 200
        and [q.get("index") for q in requests] == list(range(len(requests))), "physical_request_count_mismatch")


def bypass_request(operation, oid, summary):
    oid = oid or "fact.readonly"
    fid = summary["facts"][OBJECTS[oid]]["id"]
    options = {
        "file_metadata": ("/api/v1/files/" + fid, None),
        "file_data_content": ("/api/v1/files/" + fid + "/data/content", None),
        "file_content_html": ("/api/v1/files/" + fid + "/content/html", None),
        "file_content_named": ("/api/v1/files/" + fid + "/content/controlled.txt", None),
        "file_list": ("/api/v1/files/", {"page": 1, "content": "true"}),
        "file_search": ("/api/v1/files/search", {"filename": "controlled_*", "content": "true", "limit": 100}),
        "note_search": ("/api/v1/notes/search", {"query": "controlled_", "page": 1}),
        "note_search_read": ("/api/v1/notes/search", {"query": "controlled_", "page": 1, "permission": "read"}),
    }
    return options[operation]


def rpc_manifest():
    sequences = {a: [("identity_qualification", "init", {})] for a in ARMS}
    for arm in ARMS:
        for _, ds in OBJECTS.items():
            sequences[arm].extend([("exact_fact_setup", "create_dataset", {"dataset": ds, "actor": "owner"}),
                ("exact_fact_setup", "add_exact_fact", {"dataset": ds, "fact_key": ds, "actor": "owner"})])
        sequences[arm].append(("setup_manifest", "summary", {}))
    for phase in PHASES:
        if phase != PHASES[0]:
            changes = [("alice_reader", "readonly"), ("alice_reader", "managed"), ("bob_reader", "managed")] if phase == PHASES[1] else [("alice_reader", "readonly"), ("alice_reader", "managed")]
            for actor, ds in changes:
                sequences[ARMS[0]].append((phase + "_acl", "grant" if phase == PHASES[1] else "revoke",
                    {"dataset": ds, "actor": "owner", "recipient": actor, "permission": "read"}))
            for arm in ARMS:
                for actor in ACTORS[1:]:
                    for oid, ds in OBJECTS.items():
                        sequences[arm].append((phase + "_raw_barrier", "read_raw", {"actor": actor, "dataset": ds, "fact_key": ds}))
        for arm in ARMS:
            for item in manifest():
                if item["phase"] == phase:
                    ds = OBJECTS[item["object_id"] or "fact.readonly"]
                    sequences[arm].append((phase, "bypass", {"dataset": ds, "fact_key": ds,
                        "actor": item["actor"], "operation": item["operation"]}))
    for arm in ARMS:
        sequences[arm].append(("close", "close", {}))
    return sequences


def verify(run, *, approved_plan=None):
    run = Path(run).resolve()
    checks, phase, computed = [], "artifacts", {}
    def check(name, predicate):
        try:
            okay = bool(predicate() if callable(predicate) else predicate)
        except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
            okay = False
        checks.append({"check": name, "passed": okay})
        return okay
    def finish(**extra):
        return {"version": VERSION, "status": "passed" if checks and all(c["passed"] for c in checks) else "failed",
            "phase": phase, "checks": checks, "counts": computed, "verification_native_calls": 0,
            "verification_model_calls": 0, "auth_store_read": False, "scorer_imported": False,
            "full_get_search_list_bypass_qualified": False, "paper_novelty_established": False,
            "limits": ["Source grants are recomputed independently; G direct storage policy is empty while abstract source grants may allow.",
                "HTML/no-extracted-content are not privacy-success denominators; metadata IDs and original values are separate axes.",
                "Auth response bytes are intentionally omitted: UUID/role bindings rely on pinned native producer code plus recorded whoami/header receipts.",
                "Saved hashes and chronology establish consistency, not resistance to coordinated forgery or packet/hardware attestation.",
                "Only specified native fresh-state safe_responses BIN files are read; no credentials or private database.",
                "SQL filename/Note-title views do not establish full search/vector/tool egress safety or novelty."], **extra}
    try:
        require(run.is_relative_to((ROOT / "results").resolve()), "run_outside_results")
        before = {name: sha((run / name).read_bytes()) for name in ARTIFACTS}
        plan, contract, events, observations, barriers, owners_saved, summaries, rpc, closure, report = [read(run / n) for n in ARTIFACTS]
        # ARTIFACTS order: closure is followed by report; no native imports.
        if approved_plan is not None:
            check("exact_preapproved_plan", same(plan, read(approved_plan)))
        check("fixed_source_contract_bytes", before["source_contract.json"] == SOURCE_SHA256 == plan["source_contract_sha256"])
        check("frozen_manifest_145_and_expected_192_187", same(plan["manifest_per_arm"], manifest())
            and plan["expected_surface_rows_per_arm"] == 145 and plan["expected_http_by_arm"] == EXPECTED_HTTP
            and plan["http_cap_per_arm"] == 200 and plan["max_native_http_total"] == 379
            and plan["max_model_calls"] == plan["max_paid_calls"] == plan["automatic_retries"] == 0)
        check("source_states_independently_rebuilt", same(plan["source_states"], fixture_states(contract)))
        check("facts_exact_content_source_scope", same(plan["facts"], contract["facts"])
            and all(sha(f["text"].encode()) == f["content_sha256"] and
                next(s for s in contract["sources"] if s["source_id"] == f["source_id"])["text"][f["source_start"]:f["source_end"]] == f["text"] for f in contract["facts"]))
        check("source_text_hashes", all(sha(s["text"].encode()) == s["sha256"] for s in contract["sources"]))
        for original, expected in plan["code_sha256"].items():
            p = Path(original).resolve(); relative = p.relative_to(ROOT)
            require(p.suffix == ".py" and not p.is_symlink(), "invalid_source_manifest_path")
            archived = run / "implementation" / relative
            check("code:" + relative.as_posix(), sha(archived.read_bytes()) == expected == sha(p.read_bytes()))
        expected_archives = {(run / "implementation" / Path(p).resolve().relative_to(ROOT)).resolve() for p in plan["code_sha256"]}
        check("no_unregistered_archived_python_sources", {p.resolve() for p in (run / "implementation").rglob("*.py")} == expected_archives)
        vendor_root = (ROOT / ".venv-native-webui/Lib/site-packages/open_webui").resolve()
        vendor = {Path(p).resolve().relative_to(vendor_root).as_posix(): digest for p, digest in plan["vendor_source_sha256"].items()}
        check("exact_13_official_vendor_pins", vendor == VENDOR)
        for name, digest in VENDOR.items():
            check("vendor:" + name, sha((vendor_root / name).read_bytes()) == digest)
        check("base_source_binding", plan["base_worker_sha256"] == BASE_SHA256
            == sha((ROOT / "scripts/native_webui_projection_worker.py").read_bytes()))
        states = [Path(plan["native_states"][arm]).resolve() for arm in ARMS]
        check("two_separate_declared_fresh_native_states", len(set(states)) == 2 and all(p.parent == Path(tempfile.gettempdir()).resolve()
            and p.name.startswith("webui_surface_") and str(p).isascii() for p in states))
        check("prediction_phase_closed_original_observations", closure["observation_count"] == 290
            and closure["observations_sha256"] == before["observations.json"])
        phase = "physical_requests_and_rpc"
        seq = rpc_manifest(); attributable = {}; source_roles = {}; bypass_calls = {}; barrier_calls = {}
        for arm in ARMS:
            summary = summaries[arm]; requests = summary["native_requests"]
            require_count(requests, arm)
            init_requests = [("POST", "/api/v1/auths/signup", None), ("POST", "/api/v1/auths/signin", None)]
            for actor in ACTORS:
                init_requests.extend([("POST", "/api/v1/auths/add", "bootstrap_admin"), ("POST", "/api/v1/auths/signin", None)])
            init_requests.extend(("GET", "/api/v1/auths/", a) for a in ACTORS)
            init_requests.append(("GET", "/api/v1/notes/", None))
            check(arm + ":18_actual_identity_qualification_routes", all(
                (q["method"], q["path"], q["actor"]) == expected and q["status"] == (401 if i == 17 else 200)
                and q["credential_response_omitted"] is (i < 17)
                for i, (q, expected) in enumerate(zip(requests[:18], init_requests))))
            ids = summary["identities"]
            check(arm + ":five_ordinary_native_accounts", set(ids) == set(ACTORS)
                and len({v["id"] for v in ids.values()}) == 5
                and all(v["role"] == "user" and v["credential_kind"] == "bearer" for v in ids.values())
                and summary["bootstrap_admin"]["role"] == "admin"
                and summary["bootstrap_admin"]["id"] not in {v["id"] for v in ids.values()})
            check(arm + ":distinct_files_and_note_containers_exact_hashes", set(summary["facts"]) == set(OBJECTS.values())
                and set(summary["datasets"]) == set(OBJECTS.values())
                and len({f["id"] for f in summary["facts"].values()}) == len({n["id"] for n in summary["datasets"].values()}) == 2
                and all(summary["facts"][OBJECTS[f["object_id"]]]["text_sha256"] == f["content_sha256"] for f in contract["facts"]))
            source_roles[arm] = {phase_name: sorted(source_relations(contract, fixture_states(contract)[phase_name])) for phase_name in PHASES}
            check(arm + ":zero_inference_network_clear_credentials_omitted", summary["generation_attempts"] == summary["embedding_attempts"] == 0
                and summary["inference_events"] == [] and all(e.get("allowed") is True for e in summary["network_events"])
                and summary["client_credential_values_persisted"] is False)
            for q in requests:
                label = arm + ":http" + str(q["index"])
                check(label + ":terminal_auth_headers_and_identity", q["response_checked"] is True and q["execution_error"] is None
                    and q["cookie_present"] is False and q["api_key_present"] is False
                    and q["authorization_present"] is (q["actor"] is not None)
                    and q["started_ns"] < q["finished_ns"] and q["actor"] in {None, "bootstrap_admin", *ACTORS})
                if q["credential_response_omitted"]:
                    check(label + ":auth_values_not_serialized", q["path"].startswith("/api/v1/auths/")
                        and all(k not in q for k in ("native_raw_body", "native_body_sha256", "native_response_file", "request_json")))
                else:
                    p = safe_response_path(q, plan["native_states"][arm])
                    raw = p.read_bytes()
                    check(label + ":safe_original_bytes", len(raw) <= 2 * 1024 * 1024 and len(raw) == q["byte_count"]
                        and sha(raw) == q["native_body_sha256"] and raw == q["native_raw_body"].encode("utf-8"))
            check(arm + ":17_auth_omissions_with_5_whoami", sum(q["credential_response_omitted"] for q in requests) == 17
                and all(requests[ids[a]["whoami_request_index"]]["path"] == "/api/v1/auths/"
                    and requests[ids[a]["whoami_request_index"]]["actor"] == a
                    and requests[ids[a]["whoami_request_index"]]["status"] == 200 for a in ACTORS))
            calls = rpc[arm]
            bypass_calls[arm] = [c for c in calls if c["command"] == "bypass"]
            barrier_calls[arm] = [c for c in calls if c["command"] == "read_raw"]
            check(arm + ":complete_rpc_manifest", len(calls) == len(seq[arm]))
            event_calls = [e for e in events if e.get("arm") == arm]
            check(arm + ":events_equal_all_nonclose_RPC_results", len(event_calls) == len(calls) - 1 and all(
                e.get("command") == c["command"] and same(e.get("input"), c["input"]) and same(e.get("result"), c["result"])
                for e, c in zip(event_calls, calls[:-1])))
            used = set(range(18)); readers = {ds: set() for ds in OBJECTS.values()}
            for index, (wanted, call) in enumerate(zip(seq[arm], calls)):
                rpc_phase, command, data = wanted
                if command == "add_exact_fact":
                    data = dict(data, text=next(f["text"] for f in contract["facts"] if OBJECTS[f["object_id"]] == data["dataset"]))
                check(arm + ":rpc" + str(index) + ":binding", call.get("rpc_id") == index + 1
                    and call.get("command") == command and same(call.get("input"), data)
                    and call.get("input_sha256") == sha(compact(data)) and call.get("response_sha256") == sha(compact(call["result"]))
                    and call["started_ns"] < call["finished_ns"] and "error" not in call)
                value = call["result"]
                if command in {"init", "summary", "close"}:
                    if command == "init":
                        check(arm + ":native_init_identity_and_version", value["open_webui_version"] == "0.12.3"
                            and same(value["identities"], ids) and same(value["bootstrap_admin"], summary["bootstrap_admin"]))
                    elif command == "close":
                        check(arm + ":final_rpc_is_saved_summary", same(value, summary))
                    continue
                traces = {value["trace"]["index"]: value["trace"]}
                if command == "add_exact_fact":
                    traces = {value[k]["index"]: value[k] for k in ("add_trace", "attach_trace", "raw_trace")}
                    check(arm + ":upload_raw_trace_alias", same(value["trace"], value["raw_trace"]))
                for native_index, trace in traces.items():
                    check(arm + ":rpc_trace" + str(native_index), native_index not in used and same(trace, requests[native_index]))
                    used.add(native_index)
                if command == "bypass":
                    oid = next((o for o, ds in OBJECTS.items() if ds == data["dataset"]), None)
                    path, params = bypass_request(data["operation"], oid, summary)
                    q = value["trace"]
                    check(arm + ":bypass_url" + str(q["index"]), q["method"] == "GET" and q["path"] == path
                        and q["actor"] == data["actor"] and (same(q.get("request_params"), params) if params is not None else "request_params" not in q))
                elif command == "create_dataset":
                    ds = data["dataset"]; note = summary["datasets"][ds]; q = value["trace"]
                    body = {"title": note["name"], "data": {"content": {"md": ""}, "files": []}, "access_grants": []}
                    parsed = response_json(q["native_raw_body"])
                    check(arm + ":actual_empty_note_creation" + str(q["index"]), q["method"] == "POST" and q["path"] == "/api/v1/notes/create"
                        and q["actor"] == "owner" and q["status"] == 200 and same(q["request_json"], body)
                        and value["id"] == note["id"] == parsed["id"] and parsed["user_id"] == ids["owner"]["id"]
                        and parsed["access_grants"] == [])
                elif command == "add_exact_fact":
                    ds = data["dataset"]; note = summary["datasets"][ds]; fact = summary["facts"][ds]
                    upload, attach, raw_trace = (value[k] for k in ("add_trace", "attach_trace", "raw_trace"))
                    raw = data["text"].encode("utf-8")
                    expected_file = [{"field": "file", "filename": "controlled_" + ds + ".txt", "raw_data": data["text"],
                        "bytes": len(raw), "sha256": sha(raw), "media_type": "text/plain"}]
                    attachment = {"title": note["name"], "data": {"content": {"md": ""}, "files": [{"type": "file", "id": fact["id"]}]}}
                    check(arm + ":actual_multipart_exact_fact" + str(upload["index"]), upload["method"] == "POST" and upload["path"] == "/api/v1/files/"
                        and upload["actor"] == "owner" and upload["status"] == 200
                        and same(upload["request_params"], {"process": "false", "process_in_background": "false"})
                        and same(upload["request_files"], expected_file)
                        and response_json(upload["native_raw_body"])["id"] == fact["id"])
                    check(arm + ":actual_file_note_attachment" + str(attach["index"]), attach["method"] == "POST"
                        and attach["path"] == "/api/v1/notes/" + note["id"] + "/update" and attach["actor"] == "owner" and attach["status"] == 200
                        and same(attach["request_json"], attachment)
                        and same(response_json(attach["native_raw_body"])["data"]["files"], attachment["data"]["files"]))
                    check(arm + ":actual_initial_owner_raw_bytes" + str(raw_trace["index"]), raw_trace["method"] == "GET"
                        and raw_trace["path"] == "/api/v1/files/" + fact["id"] + "/content" and raw_trace["actor"] == "owner"
                        and raw_trace["status"] == 200 and raw_trace["native_raw_body"].encode("utf-8") == raw
                        and raw_trace["native_body_sha256"] == fact["text_sha256"] == sha(raw))
                elif command == "read_raw":
                    q = value["trace"]; fid = summary["facts"][data["fact_key"]]["id"]
                    check(arm + ":raw_url" + str(q["index"]), q["method"] == "GET" and q["path"] == "/api/v1/files/" + fid + "/content" and q["actor"] == data["actor"])
                elif command in {"grant", "revoke"}:
                    ds = data["dataset"]
                    if command == "grant": readers[ds].add(data["recipient"])
                    else: readers[ds].discard(data["recipient"])
                    grants = [{"principal_type": "user", "principal_id": ids[a]["id"], "permission": "read"} for a in sorted(readers[ds])]
                    q = value["trace"]
                    parsed_grants = response_json(q["native_raw_body"])["access_grants"]
                    check(arm + ":actual_acl_json" + str(q["index"]), arm == "native_projection" and q["method"] == "POST"
                        and q["path"] == "/api/v1/notes/" + summary["datasets"][ds]["id"] + "/access/update"
                        and q["actor"] == "owner" and q["status"] == 200 and same(q["request_json"], {"access_grants": grants})
                        and {(g["principal_type"], g["principal_id"], g["permission"]) for g in parsed_grants}
                            == {(g["principal_type"], g["principal_id"], g["permission"]) for g in grants})
                attributable[(arm, rpc_phase, command, index)] = call
            check(arm + ":every_physical_request_accounted_for", used == set(range(len(requests))))
            computed[arm] = {"physical_native_http": len(requests), "surface_rows": 0, "raw_relations": 0}
        check("two_arms_do_not_share_native_UUIDs", not ({v["id"] for v in summaries[ARMS[0]]["identities"].values()}
            & {v["id"] for v in summaries[ARMS[1]]["identities"].values()}))
        phase = "independent_surface_scoring"
        expected_items = [(arm, item) for phase_name in PHASES for arm in ARMS for item in manifest() if item["phase"] == phase_name]
        check("all_290_observations_in_frozen_order", len(observations) == len(expected_items) == 290)
        recomputed, owner_maps, per_arm_surface = [], {a: {} for a in ARMS}, {a: 0 for a in ARMS}
        for index, (saved, (arm, item)) in enumerate(zip(observations, expected_items)):
            check("surface" + str(index) + ":exact_manifest_fields", saved["arm"] == arm
                and all(same(saved.get(k), v) for k, v in item.items()))
            independent = assess(saved["native_result"], item, arm=arm, contract=contract, summary=summaries[arm], owners=owner_maps[arm])
            check("surface" + str(index) + ":independent_authorization_shape_score", same(independent, saved["assessment"]))
            trace = saved["native_result"]["trace"]
            check("surface" + str(index) + ":actual_request_membership", same(trace, summaries[arm]["native_requests"][trace["index"]]))
            check("surface" + str(index) + ":same_RPC_result_in_phase_order", same(saved["native_result"], bypass_calls[arm][per_arm_surface[arm]]["result"]))
            per_arm_surface[arm] += 1
            if item["actor"] == "owner":
                key = item["operation"] + "|" + (item["object_id"] or "GLOBAL")
                owner_maps[arm][key] = {"qualified": independent["owner_qualified"], "classification": independent["classification"], "native_request_index": trace["index"]}
            if item["operation"] == "file_content_html":
                check("surface" + str(index) + ":ordinary_owner_HTML_inapplicable_not_privacy_success", trace["status"] == 404 and independent["safety_verdict"] is None)
            if item["operation"] == "file_data_content":
                check("surface" + str(index) + ":unprocessed_content_not_privacy_success", independent["safety_verdict"] is None)
            recomputed.append(independent); computed[arm]["surface_rows"] += 1
        check("owner_eligibility_recomputed_exact", same(owner_maps, owners_saved))
        phase = "raw_source_relations"
        desired_barriers = [(arm, phase_name, actor, oid) for phase_name in PHASES[1:] for arm in ARMS for actor in ACTORS[1:] for oid in OBJECTS]
        check("32_complete_raw_barrier_relations", len(barriers) == len(desired_barriers) == 32)
        facts = {f["object_id"]: f for f in contract["facts"]}
        per_arm_barrier = {a: 0 for a in ARMS}
        for i, (row, (arm, phase_name, actor, oid)) in enumerate(zip(barriers, desired_barriers)):
            allowed = oid in direct_objects(contract, phase_name, arm, actor)
            trace, raw = checked_trace(row["native_result"], actor)
            seen = scan(raw, response_json(raw), facts, summaries[arm])
            leaked = any(seen.values())
            parsed = response_json(raw)
            okay = trace["status"] == 200 and raw == facts[oid]["text"] if allowed else (
                trace["status"] == 404 and isinstance(parsed, dict) and isinstance(parsed.get("detail"), str) and not leaked)
            check("barrier" + str(i) + ":source_and_native_confinement_not_conflated", row["arm"] == arm and row["phase"] == phase_name
                and row["actor"] == actor and row["object_id"] == oid and row["expected_available"] is allowed
                and row["actual_exact_match_or_true_denial"] is True and okay
                and same(trace, summaries[arm]["native_requests"][trace["index"]])
                and same(row["native_result"], barrier_calls[arm][per_arm_barrier[arm]]["result"]))
            per_arm_barrier[arm] += 1
            computed[arm]["raw_relations"] += 1
        phase = "report_and_integrity"
        counts = dict(Counter(a["classification"] for a in recomputed))
        for arm in ARMS:
            reported = report["http_instrumentation"][arm]
            check(arm + ":independent_HTTP_instrumentation_aggregate", reported["http_records"] == EXPECTED_HTTP[arm]
                and reported["expected_complete_http"] == EXPECTED_HTTP[arm]
                and reported["cap_satisfied"] is True and reported["exact_expected_count"] is True
                and reported["generation_attempts"] == reported["embedding_attempts"] == 0
                and reported["network_clear"] is True and reported["credential_values_not_saved"] is True)
        check("independent_report_aggregation", report["observation_count"] == 290 and report["raw_barrier_relations"] == 32
            and report["classification_counts"] == counts
            and report["owner_qualified_rows"] == sum(a["owner_qualified"] for a in recomputed)
            and report["qualified_safety_true"] == sum(a["safety_verdict"] is True for a in recomputed)
            and report["qualified_safety_false"] == sum(a["safety_verdict"] is False for a in recomputed)
            and report["unqualified_or_unsupported_safety_rows"] == sum(a["safety_verdict"] is None for a in recomputed)
            and report["qualified_native_view_matches"] == sum(a["view_matches"] is True for a in recomputed)
            and report["unexpected_qualification_gaps"] == sum(a["unexpected_qualification_gap"] for a in recomputed))
        check("completed_native_with_boundaries_preserved", report["status"] == "completed_with_declared_surface_limits"
            and report["failure"] is None and report["native_qualification_established"] is True
            and report["execution_backend"] == "native_vendor_cli_child_process" and report["postflight"]["status"] == "passed"
            and all(report[k] is False for k in ("all_eight_surface_variants_qualified", "all_seven_original_surfaces_privacy_proven",
                "full_get_search_list_bypass_qualified", "paper_novelty_established", "native_agent_IAM_or_online_source_revocation_claimed",
                "native_default_write_search_is_model_refusal", "native_auth_store_publishable")))
        check("all_original_artifacts_unchanged", all(sha((run / n).read_bytes()) == digest for n, digest in before.items()))
        computed["physical_native_http_total"] = sum(computed[a]["physical_native_http"] for a in ARMS)
        computed["recomputed_classifications"] = counts
        return finish(artifact_sha256=before, source_read_relations=source_roles,
            experiment_status=report["status"], qualification_scope="Specified native storage surfaces only; not an external gateway redeployment.")
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, StopIteration) as error:
        check("complete_evidence_structure", False)
        return finish(error_type=type(error).__name__, error_code=str(error) if isinstance(error, AuditError) else "offline_evidence_failure")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to((ROOT / "results").resolve()) and not output.exists(), "new_results_receipt_required")
    result = verify(args.run, approved_plan=args.approved_plan)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "checks": len(result["checks"]),
        "passed": sum(c["passed"] for c in result["checks"]), "counts": result["counts"],
        "verification_native_calls": 0, "verification_model_calls": 0,
        "receipt": output.relative_to(ROOT).as_posix()}, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
