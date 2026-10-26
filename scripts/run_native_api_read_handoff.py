"""Finite native WebUI API read snapshot -> correct Cognee native mapping.

Only --execute starts native workers. One direction, one correct N baseline,
two synthetic exact facts; no source-policy fabrication or text-derived ACLs.
Host operator consent is separate from unverified native export/share rights.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_native_exact_fact_bridge import WorkerRPC, archive_code
from scripts.native_webui_projection_worker import FROZEN_VENDOR
from scripts.native_cognee_policy_worker import VENDOR_FILES, WHEEL_SHA256

VERSION = "finite_native_api_read_handoff_webui_to_cognee_v1"
PROFILE = "closed_world_native_user_read_snapshot_v1"
SOURCE_SHA = "222718f0ac5f5d424ce5ff20793fe3a9fca4ea380218ed4d10096f39c5473ed7"
TARGET_SHA = "973745b9613a8e498c1cac6ff84f9ad6d99a93618a2132eb6cc5b2b6ad0c1431"
CONTRACT = ROOT / "docs/proposals/source_policy_projection_contract_v1_20261026.json"
CONTRACT_SHA = "918e6c4cc0c82e1c51bd43659d100b41c8b0393f4db8a4880c7862036a73ca6f"
ARMS = ("source", "target")
ACTORS = ("owner", "alice_reader", "alice_worker", "bob_reader", "bob_worker")
SUBJECTS = ACTORS[1:]
DATASETS = {"fact.readonly": "readonly", "fact.managed": "managed"}
PHASES = ("initial", "alice_first_read_revoked", "old_packet_replay")
CAPS = {"source": 100, "target": 90}
EXPECTED_HTTP = {"source": 91, "target": 78}
GRANT_FIELDS = {"id", "resource_type", "resource_id", "principal_type", "principal_id", "permission", "created_at"}
NOTE_FIELDS = {"id", "user_id", "title", "data", "meta", "is_pinned", "access_grants", "created_at", "updated_at", "write_access"}
PACKET_FIELDS = {"version", "profile", "transfer_id", "source_system", "source_subjects", "records",
    "read_relations", "source_observation_sha256", "operator_consent", "native_export_authority_verified",
    "native_share_authority_verified", "complete_native_policy_exported", "unverified_semantics", "body_sha256"}


class Unverified(ValueError):
    pass


def require(condition, code):
    if not condition: raise Unverified(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
def jhash(value): return sha(canonical(value))
def file_sha(path): return sha(Path(path).read_bytes())


def parse(raw):
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj: raise ValueError("duplicate_json_key")
            obj[k] = v
        return obj
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False); stream.write("\n")


def expected_relations(phase):
    rows = {("alice_reader", "fact.readonly"), ("alice_reader", "fact.managed"), ("bob_reader", "fact.managed")}
    if phase != "initial": rows.remove(("alice_reader", "fact.readonly"))
    return rows


def build_plan(*, approved=None):
    require(file_sha(CONTRACT) == CONTRACT_SHA, "fixture_contract_changed")
    contract = parse(CONTRACT.read_bytes())
    workers = {"source": ROOT / "scripts/native_webui_projection_worker.py", "target": ROOT / "scripts/native_cognee_projection_worker.py"}
    require(file_sha(workers["source"]) == SOURCE_SHA and file_sha(workers["target"]) == TARGET_SHA, "frozen_worker_changed")
    pythons = {"source": ROOT / ".venv-native-webui/Scripts/python.exe", "target": ROOT / ".venv-native-cognee/Scripts/python.exe"}
    require(all(p.is_file() for p in pythons.values()), "qualified_native_interpreters_missing")
    files = [Path(__file__), *workers.values(), ROOT / "scripts/native_cognee_policy_worker.py",
        ROOT / "scripts/native_exact_fact_common.py", ROOT / "scripts/run_native_exact_fact_bridge.py",
        ROOT / "examples/native_cognee_probe_assets/scripts/cognee_local_migration_probe.py"]
    # Exact transitive project imports of WorkerRPC, not unrelated experiments.
    files += [ROOT / "memory_migration_study" / (n + ".py") for n in
        ("__init__", "memory_labels", "privacy", "privacy_egress", "policy")]
    wheel = ROOT / ".runtime/native_cognee_wheel/cognee-1.6.5-py3-none-any.whl"
    require(file_sha(wheel) == WHEEL_SHA256, "qualified_cognee_wheel_changed")
    assets = {str(wheel.resolve()): WHEEL_SHA256}
    webui_root = pythons["source"].parent.parent / "Lib/site-packages/open_webui"
    vendor = dict(FROZEN_VENDOR, **{"models/files.py": "e0770c88528e5f95f64ee56fd11f1e662065ba269a7bf44688fa6d5ce224cb6d"})
    for name, expected in vendor.items():
        path = webui_root / name
        require(file_sha(path) == expected, "source_vendor_changed"); assets[str(path.resolve())] = expected
    with zipfile.ZipFile(wheel) as archive:
        target_root = pythons["target"].parent.parent / "Lib/site-packages"
        for name in VENDOR_FILES:
            path = target_root / name; expected = sha(archive.read(name))
            require(file_sha(path) == expected, "target_vendor_changed"); assets[str(path.resolve())] = expected
    states = {}
    for arm in ARMS:
        state = Path(approved["native_states"][arm]) if approved else Path(tempfile.gettempdir()) / ("native_api_handoff_" + arm + "_" + uuid.uuid4().hex)
        require(not state.exists() and state.parent.resolve() == Path(tempfile.gettempdir()).resolve()
            and str(state).isascii(), "fresh_ascii_system_temp_child_required")
        states[arm] = str(state.resolve())
    require(len(set(states.values())) == 2, "independent_native_states_required")
    consent = {"kind": "explicit_research_operator_consent", "approved_for_controlled_synthetic_copy": True,
        "scope": "two_registered_public_synthetic_exact_facts_and_four_subject_read_projection",
        "native_export_permission_verified": False, "native_share_permission_claimed": False}
    return {"version": VERSION, "direction": "Open WebUI 0.12.3 -> Cognee 1.6.5", "profile": PROFILE,
        "workers": {a: str(p.resolve()) for a, p in workers.items()}, "pythons": {a: str(p.resolve()) for a, p in pythons.items()},
        "native_states": states, "source_contract_sha256": CONTRACT_SHA,
        "code_sha256": {str(p.resolve()): file_sha(p) for p in files}, "asset_sha256": assets,
        "wheel": str(wheel.resolve()), "legacy": str((ROOT / "examples/native_cognee_probe_assets").resolve()),
        "http_caps": CAPS, "expected_complete_http": EXPECTED_HTTP, "max_total_native_http": 169,
        "generation_calls": 0, "embedding_calls": 0, "paid_calls": 0, "retries": 0, "concurrency": 1,
        "facts": contract["facts"], "operator_consent": consent, "actors": list(ACTORS), "phases": list(PHASES),
        "native_snapshot_counts": {"source": 3, "target": 3, "read_relations_each": 8, "total_read_relations": 48},
        "enumeration_phases": ["initial", "old_packet_replay"],
        "content_export": "Owner official Note detail gives actual ACL/file association; official file content response bytes alone populate target writes. No fixture text fallback.",
        "acl_scope": "Only explicit user/read grants for the four actual ordinary-account bindings. group/role/anyone/public/unknown/unmapped grant -> unverified stop.",
        "update_barrier": "Serial explicit controller reconciliation from a newly fetched complete finite source view; not native live clocks or atomic cross-backend revocation.",
        "old_packet": "Revalidate original immutable package against current source API, retain object mappings, rebase current read relations; no new data writes or stale grants.",
        "research_scope": "One finite synthetic story, two facts, single correct N baseline. No N-vs-G superiority, new algorithm, universal policy export or full bypass claim.",
        "stop_rule": "Preserve first failure, stop on unknown ACL, source/target transport/auth/inference/network/asset failure, changed source content or forbidden registered material. Unknown is never a denied read."}


def verify_inputs(plan, *, assets=False):
    require(file_sha(CONTRACT) == plan["source_contract_sha256"], "fixture_changed")
    for path, expected in plan["code_sha256"].items(): require(file_sha(path) == expected, "registered_code_changed")
    if assets:
        for path, expected in plan["asset_sha256"].items(): require(file_sha(path) == expected, "registered_asset_changed")


def checked_trace(result, actor):
    trace = result.get("trace", {}); raw = trace.get("native_raw_body")
    require(isinstance(raw, str) and result.get("status") == trace.get("status") and trace.get("actor") == actor
        and trace.get("response_checked") is True and trace.get("execution_error") is None
        and trace.get("authorization_present") is True and trace.get("api_key_present") is False
        and trace.get("cookie_present") is False and sha(raw.encode()) == trace.get("native_body_sha256")
        and trace.get("byte_count") == len(raw.encode()), "native_credential_or_raw_trace_unverified")
    require(type(result["status"]) is int and result["status"] not in {401} and result["status"] < 500,
        "native_auth_or_execution_error")
    return trace, raw


def source_note(note, *, summary, dataset):
    require(isinstance(note, dict) and set(note) <= NOTE_FIELDS
        and {"id", "user_id", "data", "access_grants", "write_access"} <= set(note), "source_note_schema_unverified")
    nid = summary["datasets"][dataset]["id"]; fid = summary["facts"][dataset]["id"]
    require(note["id"] == nid and note["user_id"] == summary["identities"]["owner"]["id"]
        and note["write_access"] is True and note.get("meta") in (None, {}), "source_owner_or_unknown_note_constraints")
    require(note["data"] == {"content": {"md": ""}, "files": [{"type": "file", "id": fid}]}, "source_exact_file_association_unverified")
    inverse = {summary["identities"][a]["id"]: a for a in SUBJECTS}
    require(isinstance(note["access_grants"], list), "source_acl_missing")
    readers = set(); grant_ids = set()
    for grant in note["access_grants"]:
        require(isinstance(grant, dict) and set(grant) == GRANT_FIELDS, "source_acl_unknown_fields")
        require(grant["principal_type"] == "user" and grant["permission"] == "read"
            and grant["principal_id"] in inverse and grant["principal_id"] != "*", "source_acl_unrepresentable_principal_or_action")
        require(grant["resource_type"] == "note" and grant["resource_id"] == nid
            and isinstance(grant["id"], str) and bool(grant["id"]) and grant["id"] not in grant_ids
            and type(grant["created_at"]) is int and grant["created_at"] >= 0, "source_acl_context_or_identity_invalid")
        actor = inverse[grant["principal_id"]]
        require(actor not in readers, "source_acl_duplicate_relation")
        readers.add(actor); grant_ids.add(grant["id"])
    return readers


def make_packet(snapshot, consent):
    body = {"version": VERSION, "profile": PROFILE, "transfer_id": "webui-cognee-two-fact-read-v1",
        "source_system": "Open WebUI 0.12.3", "source_subjects": deepcopy(snapshot["source_subjects"]),
        "records": deepcopy(snapshot["records"]), "read_relations": deepcopy(snapshot["read_relations"]),
        "source_observation_sha256": jhash(snapshot), "operator_consent": deepcopy(consent),
        "native_export_authority_verified": False, "native_share_authority_verified": False,
        "complete_native_policy_exported": False,
        "unverified_semantics": ["native export/share authority", "implicit owner/admin rights outside four subjects",
            "roles/groups/public or unmapped users", "TTL/delegation/purposes", "concurrent state changes", "unmeasured routes"]}
    return dict(body, body_sha256=jhash(body))


def current_projection(packet, snapshot, consent):
    require(isinstance(packet, dict) and set(packet) == PACKET_FIELDS and packet["version"] == VERSION
        and packet["profile"] == PROFILE and packet["body_sha256"] == jhash({k:v for k,v in packet.items() if k != "body_sha256"}), "handoff_package_integrity_or_profile_unverified")
    require(consent.get("approved_for_controlled_synthetic_copy") is True and packet["operator_consent"] == consent
        and packet["native_export_authority_verified"] is False and packet["native_share_authority_verified"] is False
        and packet["complete_native_policy_exported"] is False, "operator_copy_consent_or_native_scope_changed")
    require(packet["source_subjects"] == snapshot["source_subjects"], "current_source_identity_binding_changed")
    fields = ("object_id", "source_note_id", "source_file_id", "content_sha256", "byte_count", "content_utf8")
    require(isinstance(packet["records"], list) and len(packet["records"]) == 2
        and len({r["object_id"] for r in packet["records"]}) == 2, "handoff_record_inventory_unverified")
    original = {r["object_id"]: {k:r[k] for k in fields} for r in packet["records"]}
    current = {r["object_id"]: {k:r[k] for k in fields} for r in snapshot["records"]}
    require(set(original) == set(current) == set(DATASETS) and original == current, "source_content_or_object_changed")
    # Deliberately do not use packet.read_relations: old policy cannot revive a grant.
    return {(r["actor"], r["object_id"]) for r in snapshot["read_relations"] if r["available"] is True}


def execute(plan, output, *, rpc_factory=WorkerRPC, input_check=verify_inputs):
    output = Path(output); facts = {f["object_id"]: f for f in plan["facts"]}
    workers, final, rpc_records = {}, {}, {}
    events, source_snapshots, target_snapshots, packets, barriers, enums, mappings = [], [], [], [], [], [], []
    active_acl = set(); failure = None; original_packet = None
    def checkpoint():
        (output / "phase_progress.json").write_text(json.dumps({"events": events, "source_snapshots": source_snapshots,
            "target_snapshots": target_snapshots, "packets": packets, "barriers": barriers,
            "enumerations": enums, "mappings": mappings}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    def native(arm, phase, command, data):
        input_check(plan)
        try: result = workers[arm].call(command, data)
        except Exception as error:
            events.append({"arm": arm, "phase": phase, "command": command, "input": deepcopy(data),
                "rpc_failed": True, "exception_type": type(error).__name__}); checkpoint(); raise
        events.append({"arm": arm, "phase": phase, "command": command, "input": deepcopy(data), "result": deepcopy(result)})
        checkpoint()
        if command in {"read_raw", "list_data", "list_datasets", "grant", "revoke"}: checked_trace(result, data["actor"])
        return result
    def launch(arm):
        input_check(plan, assets=True)
        args = ["--state", plan["native_states"][arm], "--http-cap", str(CAPS[arm])]
        if arm == "target": args += ["--wheel", plan["wheel"], "--legacy-project", plan["legacy"],
            "--expected-worker-sha256", TARGET_SHA]
        workers[arm] = rpc_factory(plan["pythons"][arm], plan["workers"][arm], args, timeout=240)
        runtime = native(arm, "identity_qualification", "init", {})
        ids = runtime["identities"]
        require(set(ids) == set(ACTORS) and len({v["id"] for v in ids.values()}) == 5
            and all(v.get("role") == "user" or v.get("is_superuser") is False for v in ids.values()), "five_ordinary_native_accounts_unverified")
        return ids
    def raw_read(arm, phase, actor, oid, *, available, expected_record=None):
        ds = DATASETS[oid]
        result = native(arm, phase, "read_raw", {"actor": actor, "dataset": ds, "fact_key": ds})
        trace, raw = checked_trace(result, actor)
        if available:
            wanted = facts[oid]["content_sha256"] if expected_record is None else expected_record["content_sha256"]
            require(result["status"] == 200 and sha(raw.encode()) == wanted and 0 < len(raw.encode()) <= 4096
                and raw == raw.strip(), "source_content_changed" if arm == "source" else "target_exact_content_not_preserved")
            return result, raw
        denial = parse(raw)
        known_ids = {v["id"] for section in ("datasets", "facts") for v in final[arm][section].values()}
        require(result["status"] in {403, 404} and isinstance(denial, dict)
            and isinstance(denial.get("detail", denial.get("message")), str)
            and not any(f["text"] in raw for f in facts.values())
            and not any(rid in raw for rid in known_ids), "native_negative_read_not_qualified")
        return result, None
    def observe_source(phase):
        input_check(plan, assets=True); before = time.perf_counter_ns()
        records, expected, policies = [], set(), []
        for oid, ds in DATASETS.items():
            response = native("source", phase + "_owner_policy", "list_data", {"actor": "owner", "dataset": ds})
            require(response["status"] == 200, "source_policy_http_unverified")
            note = parse(response["trace"]["native_raw_body"])
            readers = source_note(note, summary=final["source"], dataset=ds)
            expected.update((actor, oid) for actor in readers)
            original, text = raw_read("source", phase + "_owner_export", "owner", oid, available=True)
            # Only this actual API string becomes export content; no fixture fallback.
            records.append({"object_id": oid, "source_note_id": note["id"],
                "source_file_id": note["data"]["files"][0]["id"], "content_utf8": text,
                "byte_count": len(text.encode()), "content_sha256": sha(text.encode()),
                "owner_raw_native_index": original["trace"]["index"], "owner_policy_native_index": response["trace"]["index"]})
            policies.append({"object_id": oid, "native_note": note, "native_trace": deepcopy(response["trace"])})
        require(expected == expected_relations(phase), "source_fixture_positive_or_revocation_not_established")
        relations = []
        for actor in SUBJECTS:
            for oid in DATASETS:
                available = (actor, oid) in expected
                result, _ = raw_read("source", phase + "_source_read_matrix", actor, oid, available=available)
                relations.append({"actor": actor, "object_id": oid, "available": available,
                    "native_request_index": result["trace"]["index"], "native_result": result})
        view = {"phase": phase, "observed_start_ns": before, "observed_finish_ns": time.perf_counter_ns(),
            "source_subjects": deepcopy(final["source"]["identities"]), "records": records,
            "native_policy_evidence": policies, "read_relations": relations,
            "scope": "four_ordinary_subjects_two_source_objects_only", "native_policy_revision": None,
            "atomic_snapshot_claimed": False}
        source_snapshots.append(view); checkpoint(); return view
    def synchronize(phase, desired):
        changes = []
        for op, pairs in (("revoke", active_acl - desired), ("grant", desired - active_acl)):
            for actor, oid in sorted(pairs):
                result = native("target", phase + "_acl", op,
                    {"dataset": DATASETS[oid], "actor": "owner", "recipient": actor, "permission": "read"})
                ack = parse(result["trace"]["native_raw_body"])
                wanted = "Permission assigned to principal" if op == "grant" else "Permission revoked from principal"
                require(result["status"] == 200 and ack == {"message": wanted}, "target_native_acl_mutation_unverified")
                changes.append({"operation": op, "actor": actor, "object_id": oid,
                    "native_request_index": result["trace"]["index"]})
        observations = []
        for actor in SUBJECTS:
            for oid in DATASETS:
                result, _ = raw_read("target", phase + "_target_read_matrix", actor, oid, available=(actor, oid) in desired)
                observations.append({"actor": actor, "object_id": oid, "available": (actor, oid) in desired,
                    "native_request_index": result["trace"]["index"], "native_result": result})
        active_acl.clear(); active_acl.update(desired)
        target_snapshots.append({"phase": phase, "read_relations": observations})
        barriers.append({"phase": phase, "current_desired_relations": [[a,o] for a,o in sorted(desired)],
            "native_acl_changes": changes, "all_eight_relations_confirmed": True,
            "controller_synchronization": True, "native_live_revocation_claimed": False})
        checkpoint()
    def enumerate_objects(arm, phase, desired):
        for actor in SUBJECTS:
            allowed = {o for a,o in desired if a == actor}
            listing = native(arm, phase + "_container_list", "list_datasets", {"actor": actor})
            raw = listing["trace"]["native_raw_body"]; parsed = parse(raw)
            require(listing["status"] == 200 and isinstance(parsed, list)
                and all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in parsed), "native_container_list_unverified")
            expected_ids = {final[arm]["datasets"][DATASETS[o]]["id"] for o in allowed}
            all_material = {o for o,d in DATASETS.items() if final[arm]["datasets"][d]["id"] in raw
                or final[arm]["facts"][d]["id"] in raw or facts[o]["text"] in raw}
            require({x["id"] for x in parsed} == expected_ids and len(parsed) == len(expected_ids)
                and all_material <= allowed, "container_visibility_not_preserved")
            enums.append({"arm": arm, "phase": phase, "actor": actor, "kind": "containers", "result": listing})
            for oid, ds in DATASETS.items():
                result = native(arm, phase + "_object_list", "list_data", {"actor": actor, "dataset": ds})
                raw = result["trace"]["native_raw_body"]; obj = parse(raw); available = oid in allowed
                object_id = final[arm]["facts"][ds]["id"]
                exposed_ids = {o for o,d in DATASETS.items() if final[arm]["facts"][d]["id"] in raw}
                exposed_ids |= {o for o,d in DATASETS.items() if final[arm]["datasets"][d]["id"] in raw}
                exposed_values = {o for o,f in facts.items() if f["text"] in raw}
                require(exposed_ids | exposed_values <= ({oid} if available else set()), "object_list_registered_material_out_of_scope")
                if available:
                    schema = (isinstance(obj, dict) and obj.get("id") == final[arm]["datasets"][ds]["id"]
                        and isinstance(obj.get("data"), dict) and obj["data"].get("files") == [{"type":"file","id":object_id}]) if arm == "source" else (
                        isinstance(obj, list) and all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in obj)
                        and {x["id"] for x in obj} == {object_id} and len(obj) == 1)
                    require(result["status"] == 200 and schema and object_id in raw, "authorized_object_list_unverified")
                else:
                    require(result["status"] in {403, 404} and isinstance(obj, dict)
                        and isinstance(obj.get("detail", obj.get("message")), str), "object_list_denial_unverified")
                enums.append({"arm": arm, "phase": phase, "actor": actor, "object_id": oid, "kind": "objects", "result": result})
        checkpoint()
    try:
        require(plan["operator_consent"]["approved_for_controlled_synthetic_copy"] is True, "explicit_operator_consent_required")
        launch("source")
        for oid, ds in DATASETS.items():
            native("source", "source_fixture_setup", "create_dataset", {"actor":"owner","dataset":ds})
            native("source", "source_fixture_setup", "add_exact_fact", {"actor":"owner","dataset":ds,"fact_key":ds,"text":facts[oid]["text"]})
        final["source"] = native("source", "source_setup_ids", "summary", {})
        for actor, oid in sorted(expected_relations("initial")):
            ack = native("source", "source_initial_acl", "grant", {"dataset":DATASETS[oid],"actor":"owner","recipient":actor,"permission":"read"})
            require(ack["status"] == 200, "source_grant_ack_unverified")
        discovered = native("source", "owner_api_discovery", "list_datasets", {"actor":"owner"})
        require(discovered["status"] == 200 and {x["id"] for x in parse(discovered["trace"]["native_raw_body"])}
            == {x["id"] for x in final["source"]["datasets"].values()}, "source_owner_api_inventory_unverified")
        initial = observe_source("initial")
        original_packet = make_packet(initial, plan["operator_consent"]); packets.append(original_packet); checkpoint()
        desired = current_projection(original_packet, initial, plan["operator_consent"])
        launch("target")
        for record in original_packet["records"]:
            oid = record["object_id"]; ds = DATASETS[oid]
            require(sha(record["content_utf8"].encode()) == record["content_sha256"]
                and len(record["content_utf8"].encode()) == record["byte_count"], "exported_native_bytes_integrity_changed")
            native("target", "target_create_from_source_api", "create_dataset", {"dataset":ds,"actor":"owner"})
            native("target", "target_ingest_source_api_bytes", "add_exact_fact",
                {"dataset":ds,"fact_key":ds,"actor":"owner","text":record["content_utf8"]})
        final["target"] = native("target", "target_setup_ids", "summary", {})
        require(set(v["id"] for v in final["source"]["identities"].values()).isdisjoint(
            v["id"] for v in final["target"]["identities"].values()), "native_source_target_identity_collision")
        for record in initial["records"]:
            ds = DATASETS[record["object_id"]]
            mappings.append({"object_id":record["object_id"],"source_note_id":record["source_note_id"],"source_file_id":record["source_file_id"],
                "target_dataset_id":final["target"]["datasets"][ds]["id"],"target_data_id":final["target"]["facts"][ds]["id"],
                "content_sha256":record["content_sha256"],"actual_source_raw_evidence_index":record["owner_raw_native_index"]})
        synchronize("initial", desired)
        for arm in ARMS: enumerate_objects(arm, "initial", desired)
        revoke = native("source", "revoke_alice_first_only", "revoke", {"dataset":"readonly","actor":"owner","recipient":"alice_reader","permission":"read"})
        require(revoke["status"] == 200, "source_revoke_ack_unverified")
        current = observe_source("alice_first_read_revoked")
        desired = current_projection(original_packet, current, plan["operator_consent"])
        synchronize("alice_first_read_revoked", desired)
        current = observe_source("old_packet_replay")
        # The original package remains byte-for-byte identical. Its stale ACL is
        # never replayed; current native API evidence decides the complete view.
        desired = current_projection(original_packet, current, plan["operator_consent"])
        synchronize("old_packet_replay", desired)
        require(barriers[-1]["native_acl_changes"] == [], "old_packet_caused_native_acl_mutation")
        for arm in ARMS: enumerate_objects(arm, "old_packet_replay", desired)
    except Exception as error:
        failure = {"exception_type":type(error).__name__,"code":str(error) if isinstance(error,Unverified) else "native_api_handoff_execution_error"}
    finally:
        for arm, worker in workers.items():
            try: final[arm] = worker.call("close", {})
            except Exception as error: final[arm] = {"close_error":type(error).__name__}
            rpc_records[arm] = worker.calls; worker.terminate()
        for name,value in (("events",events),("source_snapshots",source_snapshots),("target_snapshots",target_snapshots),
            ("packets",packets),("barriers",barriers),("enumerations",enums),("mappings",mappings),
            ("native_final",final),("rpc_receipts",rpc_records)):
            save(output/(name+".json"),value)
        checkpoint()
    save(output/"prediction_phase_closed.json", {"source_snapshots_sha256":file_sha(output/"source_snapshots.json"),
        "target_snapshots_sha256":file_sha(output/"target_snapshots.json"),"packets_sha256":file_sha(output/"packets.json")})
    try: input_check(plan,assets=True); postflight={"status":"passed"}
    except Exception: postflight={"status":"failed"}
    instrumentation = {}; technical=True
    for arm, summary in final.items():
        requests=summary.get("native_requests",[])
        item={"physical_http":len(requests),"hard_cap":CAPS[arm],"expected":EXPECTED_HTTP[arm],
            "count_matches":len(requests)==EXPECTED_HTTP[arm],"cap_satisfied":len(requests)<=CAPS[arm],
            "generation_attempts":summary.get("generation_attempts"),"embedding_attempts":summary.get("embedding_attempts"),
            "network_clear":isinstance(summary.get("network_events"),list) and all(e.get("allowed") is True for e in summary["network_events"]),
            "credential_values_not_saved":summary.get("client_credential_values_persisted") is False}
        instrumentation[arm]=item
        technical &= item["count_matches"] and item["cap_satisfied"] and item["network_clear"] and item["credential_values_not_saved"] and item["generation_attempts"]==item["embedding_attempts"]==0
    complete=(len(source_snapshots)==len(target_snapshots)==len(barriers)==3 and len(mappings)==2 and len(enums)==48)
    real=rpc_factory is WorkerRPC
    ok=failure is None and complete and len(instrumentation)==2 and technical and postflight["status"]=="passed"
    report={"version":VERSION,"status":("qualified_finite_native_api_read_handoff" if real else "fake_protocol_completed") if ok else "unverified_or_incomplete",
        "failure":failure,"execution_backend":"actual_native_worker_cli" if real else "explicit_fake_rpc",
        "direction":"WebUI_to_Cognee","profile":PROFILE,"source_snapshots":len(source_snapshots),"target_snapshots":len(target_snapshots),
        "read_relations_checked":sum(len(s["read_relations"]) for s in source_snapshots+target_snapshots),
        "enumeration_observations":len(enums),"actual_source_api_fact_mappings":len(mappings),"packets":len(packets),
        "old_packet_body_sha256":original_packet["body_sha256"] if original_packet else None,
        "old_packet_replay":"current_source_revalidated_noop" if complete else "not_established",
        "source_native_policy_export_scope":"actual explicit Note user/read ACL and actual four-subject read matrix, not universal effective policy",
        "native_export_share_authority_verified":False,"operator_consent_separate":True,
        "complete_native_policy_exported":False,"native_atomic_or_live_source_revocation":False,
        "full_get_search_list_bypass_qualified":False,"N_vs_G_advantage_measured":False,"reverse_direction_measured":False,
        "new_algorithm_advantage_established":False,"paper_novelty_established":False,"new_independent_stories":0,
        "synthetic_story_count":1,"synthetic_fact_count":2,"postflight":postflight,"instrumentation":instrumentation}
    save(output/"report.json",report); return report


def run(output, *, execute_native=False, approved_plan=None):
    output=Path(output).resolve(); results=(ROOT/"results").resolve()
    require(not output.exists() and output.is_relative_to(results) and output!=results,"new_workspace_results_required")
    approved=parse(Path(approved_plan).read_bytes()) if approved_plan else None
    plan=build_plan(approved=approved)
    require(not execute_native or approved is not None and approved==plan,"matching_exact_json_frozen_plan_required")
    output.mkdir(parents=True); archive_code(list(plan["code_sha256"]),plan["code_sha256"],output)
    save(output/"plan.json",plan); (output/"source_contract.json").write_bytes(CONTRACT.read_bytes())
    if not execute_native:return {"status":"plan_only","native_calls":0,"model_calls":0,"expected_http":EXPECTED_HTTP,"hard_caps":CAPS}
    return execute(plan,output)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--output",type=Path,required=True)
    mode=p.add_mutually_exclusive_group(required=True); mode.add_argument("--plan-only",action="store_true");mode.add_argument("--execute",action="store_true")
    p.add_argument("--approved-plan",type=Path);args=p.parse_args()
    report=run(args.output,execute_native=args.execute,approved_plan=args.approved_plan)
    print(json.dumps({k:report[k] for k in ("status","failure","read_relations_checked","instrumentation","expected_http","hard_caps","native_calls","model_calls") if k in report},ensure_ascii=False))
    raise SystemExit(0 if report["status"] in {"plan_only","qualified_finite_native_api_read_handoff"} else 1)
