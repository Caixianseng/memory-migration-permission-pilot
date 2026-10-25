"""Independent, stdlib-only verifier for the bounded native bridge v3 trace.

Never imports or executes producer code, SDK, models, archived modules or services.
Public hashes attest consistency, not authenticity or omitted HMAC/credential secrets.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import math
from pathlib import Path, PurePosixPath
import re

PROJECT = Path(__file__).resolve().parents[1]
VERSION = "native_exact_fact_research_gateway_bridge_v3"
ACTORS = ("owner", "assistant", "outsider")
QUERY = "Customer service and delivery status."
STAGES = ("before_writes", "before_revoke", "export_disabled_existing_copies_retained",
          "revoked_before_target_cleanup", "after_cleanup", "after_old_job_replay")
HEX = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def same_readers(value, expected):
    """ACL order is not authority; retain duplicate/type/membership checks."""
    return (isinstance(value, list) and all(type(item) is str for item in value)
        and len(value) == len(expected) and len(set(value)) == len(value)
        and set(value) == set(expected))


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()


def loads(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "duplicate_json_key")
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def _rpc(report):
    merged, by_worker = [], {}
    for worker in ("source", "target"):
        calls = report.get(worker+"_rpc_receipts")
        require(isinstance(calls, list) and calls, "missing_rpc_trace")
        previous = -1
        for index, row in enumerate(calls, 1):
            require(isinstance(row, dict) and row.get("rpc_id") == index and type(row.get("rpc_id")) is int
                and isinstance(row.get("command"), str) and isinstance(row.get("input"), dict)
                and "result" in row and "error" not in row, "invalid_rpc_trace")
            require(digest(row["input"]) == row.get("input_sha256") and digest(row["result"]) == row.get("response_sha256"), "rpc_hash_mismatch")
            start, end = row.get("started_ns"), row.get("finished_ns")
            require(type(start) is type(end) is int and previous <= start < end, "invalid_rpc_order")
            previous = end
            merged.append((start, end, worker, row))
        require(calls[0]["command"] == "init" and calls[-1]["command"] == "close", "incomplete_rpc_lifecycle")
        require(calls[0]["result"] == report.get(worker+"_runtime")
            and calls[-1]["result"] == report.get(worker+"_final"), "rpc_runtime_or_final_mismatch")
        by_worker[worker] = calls
    merged.sort(key=lambda x: x[0])
    require(all(a[1] <= b[0] for a, b in zip(merged, merged[1:])), "overlapping_rpc_trace")
    return merged, by_worker


def _network(report, source_reads):
    counts = {}
    for worker in ("source", "target"):
        final = report[worker+"_final"]
        require(final.get("generation_attempts") == 0 and type(final.get("generation_attempts")) is int
            and final.get("credential_values_persisted") is False, "generation_or_credential_violation")
        events = final.get("network_events")
        require(isinstance(events, list) and events, "missing_network_observations")
        connects = 0
        for e in events:
            require(isinstance(e, dict) and e.get("allowed") is True and e.get("event") in {"socket.bind", "socket.connect"}, "disallowed_network_event")
            address = e.get("address")
            require(isinstance(address, list) and len(address) == 2 and type(address[1]) is int, "invalid_network_address")
            try:
                loopback = ipaddress.ip_address(address[0]).is_loopback
            except ValueError:
                loopback = address[0] == "localhost"
            require(loopback and address[1] not in {9, 11435}, "unapproved_network_destination")
            if e["event"] == "socket.bind":
                require(address[1] == 0, "unexpected_bind_port")
            elif worker == "source":
                require(address[1] == report["source_runtime"]["gateway_port"] or e.get("kind") == "stdlib_socketpair_internal", "unapproved_source_port")
            else:
                require(e.get("kind") == "stdlib_socketpair_internal", "unapproved_target_connect")
            connects += e["event"] == "socket.connect" and e.get("kind") != "stdlib_socketpair_internal"
        if worker == "source":
            require(connects >= source_reads, "source_http_network_coverage_missing")
        counts[worker] = len(events)
    require(report.get("generation_calls") == report.get("paid_api_calls") == 0, "unexpected_generation_cost")
    source = report["source_final"]
    events = source.get("embedding_method_events")
    require(isinstance(events, list) and events and source.get("mem0_embedding_method_invocations") == len(events), "source_embedding_count_invalid")
    require(all(e.get("method") in {"embed", "embed_batch"} and type(e.get("text_count")) is int and e["text_count"] > 0 for e in events)
        and source.get("embedding_texts") == sum(e["text_count"] for e in events), "source_embedding_events_invalid")
    require(type(report["target_final"].get("native_embedding_function_invocations")) is int
        and report["target_final"]["native_embedding_function_invocations"] > 0, "target_embedding_count_not_positive")
    return counts


def _source_trace(report, calls):
    init = calls[0]["input"].get("records")
    require(isinstance(init, list) and {r.get("fact_key") for r in init} == {"main", "valid_control"} and len(init) == 2, "invalid_source_fixture")
    state = {r["fact_key"]: {"text": r["text"], "readers": list(r["readers"]), "policy": r["migration_policy"]} for r in init}
    require(state["main"]["readers"] == ["owner", "assistant"] and state["valid_control"]["readers"] == ["assistant"], "registered_source_readers_changed")
    require(state["main"]["text"] == report["trusted_fixture"]["source"], "source_fixture_changed")
    ids, reads, history = report["source_runtime"]["rows"], [], []
    require(isinstance(ids, dict) and set(ids) == {"main", "valid_control"}
        and all(isinstance(v, str) and v for v in ids.values()) and len(set(ids.values())) == 2, "source_native_ids_not_independent")
    for call in calls:
        cmd, data, result = call["command"], call["input"], call["result"]
        if cmd == "set_migration_policy":
            state[data["fact_key"]]["policy"] = data["migration_policy"]
            require(result.get("updated") is True and result.get("record_id") == ids[data["fact_key"]], "source_policy_update_not_bound")
        elif cmd == "revoke":
            state[data["fact_key"]]["readers"] = []
            require(result.get("revoked") is True, "source_revoke_not_observed")
        elif cmd == "read":
            key, actor = data["fact_key"], data["actor"]
            current = state[key]
            require(result.get("authenticated_principal") == actor and result.get("record_id") == ids[key], "source_identity_binding_invalid")
            allowed = actor in current["readers"]
            require(result.get("status") == (200 if allowed else 403), "source_current_acl_not_enforced")
            if allowed:
                require(result.get("body", {}).get("id") == ids[key] and result["body"].get("memory") == current["text"], "source_native_content_mismatch")
                control = result.get("trusted_migration_control")
                require(isinstance(control, dict) and same_readers(control.get("source_readers"), current["readers"]),
                    "source_migration_control_mismatch")
                expected = {"source_id": ids[key], "source_sha256": hashlib.sha256(current["text"].encode()).hexdigest(),
                    "source_readers": control["source_readers"], "migration_policy": current["policy"]}
                require(control == expected, "source_migration_control_mismatch")
            else:
                require("trusted_migration_control" not in result, "denied_source_exposes_migration_control")
            reads.append(result)
        history.append((call["finished_ns"], loads(json.dumps(state))))
    require(reads == report["source_final"].get("requests"), "source_rpc_and_http_read_log_mismatch")
    return state, history, len(reads), {r["fact_key"]: r for r in init}


def _raw_requests(report, root):
    requests = report["target_final"].get("native_requests")
    require(isinstance(requests, list) and requests, "missing_native_http_trace")
    require(report.get("target_report", {}).get("native_requests") == requests, "target_report_trace_mismatch")
    decoded = {}
    for index, trace in enumerate(requests):
        require(trace.get("native_request_index") == index and type(trace.get("native_request_index")) is int
            and trace.get("response_checked") is True and trace.get("execution_error") is None
            and trace.get("cookie_present") is False, "unqualified_native_http_observation")
        path = trace.get("native_path", "")
        if "/auths" in path:
            require(trace.get("auth_response_omitted") is True and "native_raw_body" not in trace
                and trace.get("status") == 200, "unsafe_or_failed_auth_trace")
            continue
        raw, expected = trace.get("native_raw_body"), trace.get("native_body_sha256")
        require(isinstance(raw, str) and isinstance(expected, str) and HEX.fullmatch(expected)
            and hashlib.sha256(raw.encode()).hexdigest() == expected and trace.get("byte_count") == len(raw.encode()), "native_raw_body_hash_mismatch")
        file = Path(trace.get("native_response_file", "")).resolve()
        require(file.is_relative_to(root.resolve()/"target_state/responses") and file.name == f"{index:05d}.bin"
            and file.is_file() and not file.is_symlink(), "missing_or_unsafe_native_raw_file")
        require(file.read_bytes() == raw.encode(), "native_raw_file_mismatch")
        decoded[index] = loads(raw)
        if trace.get("actor_id") in ACTORS:
            require(trace.get("authorization_present") is True, "native_actor_missing_authentication")
    target = report["target_runtime"]
    mapping = target.get("native_user_ids")
    require(isinstance(mapping, dict) and set(mapping) == set(ACTORS) and all(isinstance(v, str) and v for v in mapping.values())
        and len(set(mapping.values())) == 3, "native_identity_mapping_invalid")
    receipts = target.get("whoami_public_receipts")
    require(isinstance(receipts, list) and len(receipts) == 3 and {x.get("actor") for x in receipts} == set(ACTORS), "missing_public_whoami_binding")
    for item in receipts:
        idx = item.get("native_request_index")
        require(type(idx) is int and 0 <= idx < len(requests), "invalid_whoami_index")
        t = requests[idx]
        require(item.get("id") == mapping[item["actor"]] and item.get("role") == "user"
            and t.get("actor_id") == item["actor"] and t.get("native_path") == "/api/v1/auths/"
            and t.get("native_method") == "GET" and t.get("authorization_present") is True, "native_whoami_binding_invalid")
    anonymous = [t for t in requests if t.get("actor_id") is None and t.get("native_path") == "/api/v1/memories/"]
    require(len(anonymous) == 1 and anonymous[0].get("status") in {401, 403} and not anonymous[0].get("authorization_present"), "anonymous_native_read_not_denied")
    return requests, decoded


def _grants(report, initial):
    side, grants = report.get("sidecar"), report.get("public_exact_grants")
    require(isinstance(side, dict) and set(side) == {"main", "valid_control"} and isinstance(grants, dict) and set(grants) == set(side), "missing_exact_grants")
    facts, copies = {}, {}
    for key in side:
        s, grant, text = side[key], grants[key], initial[key]["text"]
        a, b = s.get("source_start"), s.get("source_end")
        require(type(a) is type(b) is int and 0 <= a < b <= len(text), "invalid_exact_source_range")
        fact = text[a:b]
        require(key != "main" or fact == report["trusted_fixture"]["fact"], "fact_not_exact_source_slice")
        expected = {"record_id": s["record_id"], "owner_id": initial[key]["readers"][0], "readers": sorted(initial[key]["readers"]),
            "origin_agent_id": "AgentA", "allowed_agent_ids": ["AgentB"], "source_id": report["source_runtime"]["rows"][key],
            "source_sha256": hashlib.sha256(text.encode()).hexdigest(), "epoch": s["epoch"],
            "scope_version": "exact_fact_source_span_v1", "content_sha256": hashlib.sha256(fact.encode()).hexdigest(), "source_start": a, "source_end": b}
        require(grant == expected and s["source_id"] == expected["source_id"] and s["source_sha256"] == expected["source_sha256"]
            and s["content_sha256"] == expected["content_sha256"], "exact_grant_binding_invalid")
        require(type(s["epoch"]) is int and s["epoch"] >= 0, "invalid_grant_epoch")
        rows = s.get("copies")
        require(isinstance(rows, list) and len(rows) == len(initial[key]["readers"])
            and {x.get("actor") for x in rows} == set(initial[key]["readers"]), "missing_or_wrong_native_copy")
        for c in rows:
            rid = c.get("target_id")
            require(isinstance(rid, str) and rid and rid not in copies, "duplicate_or_invalid_native_copy_id")
            copies[rid] = {"actor": c["actor"], "content": fact, "path": "exact-fact/"+s["record_id"], "fact_key": key}
        evidence = s.get("migration_evidence", {})
        require(evidence.get("method") == "reader_copies" and evidence.get("actual_source_id") == expected["source_id"]
            and evidence.get("source_id") == s["record_id"] and evidence.get("source_sha256") == expected["source_sha256"]
            and evidence.get("content_sha256") == expected["content_sha256"]
            and evidence.get("source_start") == a and evidence.get("source_end") == b, "migration_evidence_fact_binding_invalid")
        readers = initial[key]["readers"]
        require(same_readers(evidence.get("source_readers"), readers) and evidence.get("recipient_readers") == sorted(readers)
            and evidence.get("target_readers") == readers and evidence.get("export_allowed") is True and evidence.get("copy_allowed") is True,
            "migration_evidence_acl_or_flags_invalid")
        require(evidence.get("decisions") == {actor: "allow" if actor in readers else "deny" for actor in ACTORS}
            and evidence.get("actor_mapping_sha256") == digest(report["target_runtime"]["native_user_ids"]), "migration_decisions_invalid")
        fact_policy = {"source_id": s["record_id"], "text": fact, "source_readers": evidence["source_readers"],
            "recipient_readers": sorted(readers), "target_readers": readers, "export_allowed": True, "copy_allowed": True}
        case = {"case_id": "native_exact_fact_"+s["record_id"], "actors": [
            {"actor_id": a, "user_id": a, "agent_id": "AgentB"} for a in ACTORS],
            "actor_mapping": report["target_runtime"]["native_user_ids"], "records": [fact_policy]}
        control = {"source_id": expected["source_id"], "source_sha256": expected["source_sha256"],
            "source_readers": evidence["source_readers"], "migration_policy": initial[key]["migration_policy"]}
        require(evidence.get("case_sha256") == digest(case) and evidence.get("plan_sha256") == digest(_reader_plan(case, sorted(readers)))
            and evidence.get("migration_control_sha256") == digest(control), "migration_plan_or_control_hash_invalid")
        facts[key] = fact
    residents = report.get("resident_controls")
    require(isinstance(residents, list) and len(residents) == 3 and {r.get("actor") for r in residents} == set(ACTORS), "missing_resident_positive_controls")
    for r in residents:
        require(r.get("target_id") not in copies and isinstance(r.get("target_id"), str) and isinstance(r.get("content"), str)
            and r["content"] and r.get("path") == "/resident-control/"+r["actor"], "resident_binding_invalid")
        copies[r["target_id"]] = {"actor": r["actor"], "content": r["content"], "path": r["path"].strip("/"), "fact_key": "resident"}
    require(len(copies) == 6, "finite_native_fixture_must_have_six_objects")
    return copies


def _reader_plan(case, readers):
    """Reconstruct the published reader_copies reference format, no producer import."""
    item, run = case["records"][0], "native-bridge-v3-"+case["records"][0]["source_id"]
    def stable(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:20]
    objects, containers, targets = [], [], []
    for actor in readers:
        namespace = stable([actor])
        target = run+"/"+namespace+"/"+stable(item["source_id"])
        container = run+"/group/"+namespace
        targets.append(target)
        objects.append({"target_id": target, "source_id": item["source_id"], "text": item["text"],
            "readers": [actor], "container_id": container})
        containers.append({"container_id": container, "readers": [actor], "target_ids": [target]})
    return {"schema_version": 1, "case_id": case["case_id"], "method": "reader_copies", "run_id": run,
        "objects": objects, "containers": containers, "object_mapping": {item["source_id"]: targets},
        "mapping_complete": True, "inventory_complete": True, "excluded": [], "backend_kind": "reference_backend",
        "source_only": False, "artificial_stress": False, "resource_constraint_origin": "none"}


def _snapshots(report, requests, decoded, copies):
    snapshots = report.get("snapshots")
    require(isinstance(snapshots, dict) and set(snapshots) == set(STAGES), "missing_native_lifecycle_stage")
    previous = -1
    vectors = 0
    for stage in STAGES:
        active = {} if stage == "before_writes" else {rid: obj for rid, obj in copies.items()
            if stage not in {"after_cleanup", "after_old_job_replay"} or obj["fact_key"] != "main"}
        ids = [] if stage == "before_writes" else list(copies)
        expected_keys = {(a, op, rid) for a in ACTORS for op, rid in
            [("list", None), ("lexical", None), ("semantic", None), *[("known_id", rid) for rid in ids]]}
        rows = snapshots[stage].get("rows")
        require(isinstance(rows, list) and len(rows) == len(expected_keys)
            and {(r.get("actor"), r.get("operation"), r.get("requested_id")) for r in rows} == expected_keys, "native_matrix_incomplete")
        listed = {}
        for row in rows:
            actor, op, rid = row["actor"], row["operation"], row.get("requested_id")
            require(row.get("response_checked") is True and row.get("execution_error") is None
                and hashlib.sha256(row.get("native_raw_body", "").encode()).hexdigest() == row.get("native_body_sha256"), "snapshot_raw_hash_invalid")
            method = "GET" if op == "list" else "POST"
            path = "/api/v1/memories/" if op == "list" else "/api/v1/memories/query" if op == "semantic" else "/api/v1/memories/search"
            body = None if op == "list" else {"content": QUERY, "k": 100} if op == "semantic" else {"memory_id": rid, "type": "all", "limit": 1} if op == "known_id" else {"query": "Customer", "type": "all", "limit": 100}
            matches = [t for t in requests if t["native_request_index"] > previous and t.get("actor_id") == actor
                and t.get("native_path") == path and t.get("native_method") == method and t.get("native_request_json") == body
                and t.get("native_body_sha256") == row["native_body_sha256"] and t.get("status") == row.get("status")]
            require(matches, "snapshot_not_bound_to_actual_http")
            t = matches[0]
            previous = t["native_request_index"]
            value = decoded[previous]
            own = {i: obj for i, obj in active.items() if obj["actor"] == actor}
            require(report["trusted_fixture"]["source_only_canary"] not in row["native_raw_body"], "source_canary_leaked_to_target")
            if op != "semantic":
                require(row.get("status") == 200 and isinstance(value, list) and row.get("items") == value, "sql_snapshot_not_successful_raw_array")
                require(all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in value)
                    and len({item["id"] for item in value}) == len(value), "invalid_sql_memory_items")
                observed = {item["id"] for item in value}
                expect = set(own) if op == "list" else ({rid} if rid in own else set()) if op == "known_id" else None
                require(observed <= set(own) and (expect is None or observed == expect), "native_acl_or_cleanup_mismatch")
                for item in value:
                    obj = own[item["id"]]
                    require(item.get("content") == obj["content"] and item.get("user_id") == report["target_runtime"]["native_user_ids"][actor]
                        and item.get("path") == obj["path"] and item.get("type") == "context", "native_content_or_owner_mismatch")
                if op == "list":
                    listed[actor] = {item["id"]: item for item in value}
            else:
                require(row.get("query") == QUERY and type(row.get("k")) is int and row["k"] == 100
                    and row.get("vector_result") == value and actor in listed, "semantic_query_contract_invalid")
                if row.get("status") == 404:
                    require(not own and not listed[actor] and value == {"detail": "No memories found for user"}, "false_empty_semantic_result")
                    continue
                require(row.get("status") == 200 and isinstance(value, dict) and set(value) == {"ids", "documents", "metadatas", "distances"}, "invalid_vector_response")
                require(all(isinstance(v, list) and len(v) == 1 and isinstance(v[0], list) for v in value.values()), "invalid_vector_dimensions")
                found, docs, meta, distances = (value[k][0] for k in ("ids", "documents", "metadatas", "distances"))
                require(all(type(i) is str for i in found) and len(set(found)) == len(found) and set(found) == set(own)
                    and len(found) == len(docs) == len(meta) == len(distances), "vector_ids_missing_residual_or_unauthorized")
                for i, doc, m, distance in zip(found, docs, meta, distances):
                    original = listed[actor][i]
                    p = original["path"]
                    require(type(distance) in {int, float} and math.isfinite(distance), "nonfinite_vector_distance")
                    require(not p or (not p.startswith("/") and not p.endswith("/") and "//" not in p and all(x not in {".", ".."} for x in p.split("/"))), "invalid_native_normalized_path")
                    expected_meta = {k: original.get(k) for k in ("created_at", "updated_at", "type", "path")}
                    require(doc == (p+"\n" if p else "")+original["content"] and m == expected_meta
                        and all(type(m[k]) is int for k in ("created_at", "updated_at")), "vector_document_or_metadata_mismatch")
                vectors += 1
    return vectors


def verify_trace(report, root):
    """Pure trace audit; tests may supply authored fake-worker artifacts explicitly."""
    require(report.get("version") == VERSION, "v3_full_trace_required")
    merged, calls = _rpc(report)
    require(report["source_runtime"].get("mem0_version") == "2.2.1" and report["source_runtime"].get("embedding_dimensions") == 384
        and report["source_runtime"].get("infer") is False and report["target_runtime"].get("open_webui_version") == "0.12.3"
        and report["source_runtime"].get("native_mem0_user_authentication") is False
        and report["source_runtime"].get("research_acl_gateway") is True
        and report["target_runtime"].get("source_sdk_overlay_present") is False
        and report["target_runtime"].get("model_discovery_disabled") is True, "runtime_not_pinned")
    _, history, read_count, initial = _source_trace(report, calls["source"])
    network = _network(report, read_count)
    requests, decoded = _raw_requests(report, Path(root))
    copies = _grants(report, initial)
    raw_writes = [t for t in requests if (t.get("native_method"), t.get("native_path")) == ("POST", "/api/v1/memories/add")]
    require(len(raw_writes) == len(copies) and {decoded[t["native_request_index"]].get("id") for t in raw_writes} == set(copies), "native_raw_copy_write_inventory_mismatch")
    for t in raw_writes:
        item = decoded[t["native_request_index"]]
        obj = copies[item["id"]]
        require(t.get("status") == 200 and t.get("actor_id") == obj["actor"]
            and t.get("native_request_json") == {"content": obj["content"], "path": "/"+obj["path"], "type": "context"}
            and item.get("content") == obj["content"] and item.get("path") == obj["path"]
            and item.get("user_id") == report["target_runtime"]["native_user_ids"][obj["actor"]], "native_raw_write_content_binding_invalid")
    vectors = _snapshots(report, requests, decoded, copies)
    source_calls, target_calls = calls["source"], calls["target"]
    snapshots = [c for c in target_calls if c["command"] == "snapshot"]
    require(len(snapshots) == 6 and all(c["result"] == report["snapshots"][stage] for c, stage in zip(snapshots, STAGES)), "snapshot_rpc_result_mismatch")
    writes = [c for c in target_calls if c["command"] == "add"]
    require(len(writes) == 3 and all(c["started_ns"] > snapshots[0]["finished_ns"] for c in writes), "unexpected_or_prewrite_target_write")
    for c in writes:
        data, result = c["input"], c["result"]
        obj = copies.get(result.get("target_id"))
        require(obj and obj["fact_key"] != "resident" and data == {"actor": obj["actor"], "text": obj["content"], "path": "/"+obj["path"]}
            and result.get("actor") == obj["actor"] and result.get("content") == obj["content"], "target_add_exact_fact_binding_invalid")
        source_state = next(state for end, state in reversed(history) if end < c["started_ns"])[obj["fact_key"]]
        require(source_state["policy"].get("export_allowed") is True and source_state["policy"].get("copy_allowed") is True
            and obj["actor"] in source_state["readers"]
            and not set(source_state["policy"])-{"export_allowed", "copy_allowed", "required_capabilities"}
            and isinstance(source_state["policy"].get("required_capabilities", []), list)
            and set(source_state["policy"].get("required_capabilities", [])) <= {"fixed_application_worker", "user_read_acl"}, "target_write_without_current_migration_eligibility")
    resident_calls = [c for c in target_calls if c["command"] == "add_residents"]
    require(len(resident_calls) == 1 and resident_calls[0]["result"].get("residents") == report["resident_controls"], "resident_rpc_result_mismatch")
    deletions = [c for c in target_calls if c["command"] == "delete"]
    main = {rid: obj for rid, obj in copies.items() if obj["fact_key"] == "main"}
    require(len(deletions) == len(main) == 2 and {c["input"].get("target_id") for c in deletions} == set(main), "missing_cleanup_copy")
    require([c["result"] for c in deletions] == report.get("deletions"), "deletion_rpc_result_mismatch")
    for c in deletions:
        rid = c["input"]["target_id"]
        require(c["input"] == {"actor": main[rid]["actor"], "target_id": rid} and c["result"].get("deleted") is True
            and c["result"].get("status") == 200, "delete_receipt_not_successful")
        native = [t for t in requests if t.get("native_method") == "DELETE" and t.get("native_path") == "/api/v1/memories/"+rid]
        require(len(native) == 1 and decoded[native[0]["native_request_index"]] is True and native[0].get("actor_id") == main[rid]["actor"], "delete_receipt_not_native_raw_true")
    source_revoke = [c for c in source_calls if c["command"] == "revoke" and c["input"] == {"fact_key": "main"}]
    require(len(source_revoke) == 1 and snapshots[3]["started_ns"] > source_revoke[0]["finished_ns"]
        and all(c["started_ns"] > snapshots[3]["finished_ns"] and c["finished_ns"] < snapshots[4]["started_ns"] for c in deletions), "revocation_cleanup_order_invalid")
    require(report.get("old_job", {}).get("replay", {}).get("error") == "current_source_denied"
        and report["old_job"]["replay"].get("copies") == []
        and report["old_job"].get("export_forbidden_replay", {}).get("error") == "export_forbidden"
        and report["old_job"]["export_forbidden_replay"].get("copies") == []
        and report["old_job"].get("export_forbidden_source_read_status") == 200, "old_job_control_not_refused")
    policies = [c for c in source_calls if c["command"] == "set_migration_policy" and c["finished_ns"] < snapshots[0]["started_ns"]]
    observed = [c["input"]["migration_policy"] for c in policies]
    require(any(p.get("export_allowed") is False for p in observed) and any(p.get("copy_allowed") is False for p in observed)
        and any(p.get("export_allowed") is None for p in observed) and any("copy_allowed" not in p for p in observed)
        and any(type(p.get("export_allowed")) is int for p in observed)
        and any(set(p)-{"export_allowed", "copy_allowed", "required_capabilities"} for p in observed), "migration_flag_negative_matrix_missing")
    require(any(c["command"] == "read" and c["input"] == {"fact_key": "valid_control", "actor": "assistant"}
        and c["result"].get("status") == 200 and c["started_ns"] > source_revoke[0]["finished_ns"] for c in source_calls), "independent_legal_source_not_preserved")
    require(report["trusted_fixture"]["source_only_canary"] not in json.dumps(report["target_final"], ensure_ascii=False), "source_only_canary_reached_target")
    return {"status": "passed", "verified_components": ["RPC inputs/results/order", "current source read and migration policy",
        "public exact-fact scopes", "three-set reader copy plan", "native raw HTTP and copy inventory", "identity/public whoami binding",
        "SQL and semantic lifecycle matrices", "explicit cleanup and replay", "network and separate embedding accounting"],
        "native_http_observations": len(requests), "qualified_nonempty_vector_rows": vectors,
        "source_gateway_reads": read_count, "network_observations": network, "copies_created": len(copies), "copies_deleted": len(main),
        "source_embedding_method_invocations": report["source_final"]["mem0_embedding_method_invocations"],
        "target_embedding_function_invocations": report["target_final"]["native_embedding_function_invocations"],
        "generation_calls": 0,
        "limits": ["Unsigned artifact consistency; no independent HMAC or omitted credential/JWT verification.",
            "Trusted same-host research ACL gateway and fixed worker; explicit cleanup, not native automatic cross-system revocation.",
            "Finite six-object fixture with k100 and fixed default threshold; no task utility, generalized interoperability or novelty claim."]}


def _inventory(plan, root, project):
    archive, hashes = plan.get("code_archive"), plan.get("code_sha256")
    require(isinstance(archive, dict) and set(archive) == set(hashes), "code_archive_inventory_mismatch")
    relative = set()
    for original, row in archive.items():
        name, stored = row.get("project_relative_path"), row.get("archive_path")
        require(isinstance(name, str) and isinstance(stored, str) and stored == "implementation/"+name
            and PurePosixPath(name).as_posix() == name and not PurePosixPath(name).is_absolute()
            and not any(p in {"..", "."} for p in PurePosixPath(name).parts), "unsafe_code_archive_path")
        source, copy = (project/name).resolve(), (root/stored).resolve()
        require(source.is_relative_to(project) and copy.is_relative_to(root) and str(source) == str(Path(original).resolve())
            and row.get("sha256") == hashes[original] and sha(copy) == hashes[original] and sha(source) == hashes[original], "code_archive_hash_mismatch")
        relative.add(name)
    package = {p.relative_to(project).as_posix() for p in (project/"memory_migration_study").glob("*.py")}
    required = {"scripts/"+n for n in ("run_native_exact_fact_bridge.py", "native_exact_fact_common.py", "native_exact_fact_source.py", "native_exact_fact_target.py")}
    require(set(plan.get("package_source_inventory", [])) == package and package <= relative and required <= relative
        and len([x for x in relative if x.endswith("/scripts/qualify_migration.py")]) == 1
        and len([x for x in relative if x.endswith("/scripts/openwebui_migration_probe.py")]) == 1
        and len(relative) == len(package)+6, "incomplete_native_code_archive")
    assets = plan.get("asset_sha256")
    require(isinstance(assets, dict) and len(assets) == 15, "incomplete_native_asset_inventory")
    required_suffixes = {"models/minilm/"+n for n in ("model.safetensors", "config.json", "modules.json", "tokenizer.json", "tokenizer_config.json", "1_Pooling/config.json")}
    required_suffixes |= {"native_dlls/libcrypto-3-x64.dll", "native_dlls/libssl-3-x64.dll", "installed_file_hashes.json", "pip-report.json", "open_webui/config.py"}
    required_suffixes |= {"open_webui/routers/memories.py", "open_webui/utils/memory.py", "open_webui/retrieval/vector/main.py", "open_webui/retrieval/vector/dbs/chroma.py"}
    require(all(any(Path(p).as_posix().endswith(s) for p in assets) for s in required_suffixes), "native_asset_categories_missing")
    for name, expected in assets.items():
        p = Path(name).resolve()
        require(p.is_relative_to(project) and HEX.fullmatch(expected) and sha(p) == expected, "native_asset_hash_mismatch")
    sdk = Path(plan["source_sdk_root"]).resolve()
    require(sdk.is_relative_to(project), "unsafe_sdk_root")
    manifest = sdk/"installed_file_hashes.json"
    require(assets.get(str(manifest)) == sha(manifest), "sdk_manifest_not_asset_bound")
    entries = loads(manifest.read_bytes())
    require(isinstance(entries, list) and len(entries) == 8875, "sdk_manifest_count_not_pinned")
    expected = {}
    for row in entries:
        name = row.get("path")
        require(isinstance(name, str) and "\\" not in name and ":" not in name and not PurePosixPath(name).is_absolute()
            and all(x not in {"..", "."} for x in PurePosixPath(name).parts) and name not in expected, "invalid_sdk_manifest_path")
        expected[name] = row
    site = sdk/"site-packages"
    actual = {p.relative_to(site).as_posix(): p for p in site.rglob("*") if p.is_file()}
    require(set(actual) == set(expected) and not any(p.is_symlink() for p in site.rglob("*")), "sdk_file_inventory_changed")
    for name, p in actual.items():
        row = expected[name]
        require(set(row) == {"path", "bytes", "sha256"} and type(row["bytes"]) is int and p.stat().st_size == row["bytes"] and sha(p) == row["sha256"], "sdk_installed_file_changed")
    return {"archived_source_files": len(relative), "package_source_files": len(package), "native_assets": len(assets), "installed_sdk_files": len(actual)}


def verify(directory, *, project=PROJECT):
    root, project = Path(directory).resolve(), Path(project).resolve()
    report, plan = loads((root/"report.json").read_bytes()), loads((root/"plan.json").read_bytes())
    if report.get("version") != VERSION:
        return {"status": "not_qualified_for_v3", "version": report.get("version"), "scope": "Earlier read/SQL evidence is not the v3 export/copy/vector protocol; historical report left unchanged."}
    require(plan.get("version") == VERSION and plan.get("generation_budget") == 0 and plan.get("external_network_allowed") is False, "invalid_native_v3_plan")
    inventory = _inventory(plan, root, project)
    config = plan.get("open_webui_config", {})
    observed = report.get("target_runtime", {}).get("model_discovery_configuration", {})
    require(config.get("version") == "0.12.3" and observed.get("native_config_path") == config.get("path")
        and observed.get("native_config_sha256") == config.get("sha256")
        and plan["asset_sha256"].get(config.get("path")) == config.get("sha256")
        and report.get("target_final", {}).get("model_discovery_configuration") == observed,
        "native_config_identity_not_bound")
    require(observed.get("observed_native_configuration") == {"ENABLE_OLLAMA_API": False, "ENABLE_OPENAI_API": False,
        "OLLAMA_BASE_URL": "http://127.0.0.1:9", "OLLAMA_BASE_URLS": ["http://127.0.0.1:9"]}, "native_model_discovery_configuration_invalid")
    contract = plan.get("native_semantic_query", {})
    require(contract == {"path": "/api/v1/memories/query", "content": QUERY, "k": 100,
        "relevance_threshold_changed": False, "own_resident_controls": list(ACTORS)}, "native_semantic_plan_changed")
    trace = verify_trace(report, root)
    return {"verifier_version": "independent_native_exact_fact_bridge_v1", **trace, **inventory,
        "report_sha256": sha(root/"report.json"), "plan_sha256": sha(root/"plan.json"), "producer_pass_flags_used": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.directory)
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, OverflowError) as error:
        result = {"status": "failed", "error": error.args[0] if type(error) is ValueError else type(error).__name__}
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        require(not args.output.exists(), "verification_output_must_be_new")
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if result["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
