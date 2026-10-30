"""Frozen native contexts, with offline revalidation before any model request.

Hashes provide corruption detection and provenance links, not signatures or an
OS security boundary. The model-facing payload is deliberately only query and
memories; audit metadata and evaluation labels stay on the trusted host.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import uuid

from .evidence import evaluate
from .policy import decision, make_plan, validate_case
from .tasks import GROUPS, retrieve, validate_runtime


SCHEMA_VERSION = 1
KIND = "native_context_snapshots"
PIPELINE = {"retrieval": "fixed_lexical_top_k", "top_k": 2, "context_chars": 4096,
            "deduplicate_by": "registered_source_id", "tie_break": "source_id", "fresh_session_each_group": True}
PROVENANCE_FILES = {"runtime": "native_runtime.json", "direct_evidence": "direct_evidence.json",
                    "native_requests": "native_requests.json"}
ENVELOPE_FIELDS = {"case_id", "task_id", "actor_id", "group", "session_id", "order_position",
                   "context_sha256", "runtime_sha256", "direct_evidence_sha256", "native_requests_sha256",
                   "native_request_indices", "native_identity_request_index"}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def context_sha256(memories):
    """Keep the existing task-run hash convention, including JSON whitespace."""
    return _sha(json.dumps(memories, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique_keys)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _validate_baseline(case, plan):
    _require(plan.get("method") == "reader_copies" and plan.get("source_only") is False,
             "snapshot baseline must be conjunctive reader_copies")
    expected = make_plan(case, "reader_copies", "validation-only")
    shape = lambda obj: (obj["source_id"], obj["text"], tuple(obj["readers"]))
    _require(sorted(map(shape, plan["objects"])) == sorted(map(shape, expected["objects"])),
             "reader_copies object inventory does not match joint authorization")
    declared = {source: sorted(obj["target_id"] for obj in plan["objects"] if obj["source_id"] == source)
                for source in plan["object_mapping"]}
    _require(declared == {source: sorted(values) for source, values in plan["object_mapping"].items()},
             "object inventory and source mapping differ")


def _validate_trace(trace, index, root):
    _require(trace.get("native_request_index") == index, "native request index mismatch")
    if "native_raw_body" not in trace:
        return
    raw = trace["native_raw_body"]
    _require(isinstance(raw, str), "native raw response must be text")
    encoded = raw.encode("utf-8")
    _require(_sha(encoded) == trace.get("native_body_sha256") and len(encoded) == trace.get("byte_count"),
             "native response hash or byte count mismatch")
    name = f"{index:05d}.bin"
    recorded_path = trace.get("native_response_file")
    _require(isinstance(recorded_path, str) and recorded_path.replace("\\", "/").rsplit("/", 1)[-1] == name,
             "native response archive filename does not match request index")
    # Retain the original recorded location as audit data, but read only the
    # bundled archive. This also permits replay after copying the entire bundle.
    archive = (root / "responses" / name).resolve()
    _require(archive.parent == root / "responses", "native response archive is outside this bundle")
    _require(archive.read_bytes() == encoded, "native raw archive differs from saved response")


def _validate_receipt_link(receipt, requests, root):
    index = receipt.get("native_request_index")
    _require(type(index) is int and 0 <= index < len(requests), "native evidence request index missing")
    trace = requests[index]
    _require(all(receipt.get(key) == value for key, value in trace.items()),
             "native evidence receipt does not match recorded request")
    _validate_trace(trace, index, root)


def _load_provenance(bundle, root):
    _require(set(bundle.get("provenance", {})) == set(PROVENANCE_FILES), "snapshot provenance scope mismatch")
    loaded = {}
    for key, name in PROVENANCE_FILES.items():
        spec = bundle["provenance"][key]
        _require(set(spec) == {"path", "sha256"} and spec["path"] == name, "unexpected provenance path")
        path = root / name
        _require(path.resolve() == path, "provenance file resolves outside this bundle")
        _require(_sha(path.read_bytes()) == spec["sha256"], "snapshot provenance hash mismatch")
        loaded[key] = _read(path)
    runtime = loaded["runtime"]
    validate_runtime(runtime)
    _require(isinstance(runtime.get("cases"), list) and len(runtime["cases"]) == 1,
             "native snapshot bundle must cover exactly one registered case")
    case = runtime["cases"][0]
    validate_case(case)
    evidence = loaded["direct_evidence"]
    _require(evidence.get("case") == case, "native evidence and runtime disagree")
    _require(evidence.get("backend_kind") == "native"
             and evidence.get("native_status") == "native_application_api_executed"
             and evidence.get("evidence_contract") == "open_webui_0.12.3_native_memory_v1",
             "snapshot requires executed native WebUI evidence")
    _validate_baseline(case, evidence["plan"])
    report = evaluate(evidence)
    _require(report["coverage"]["complete"] is True and not report["structural_errors"]
             and report["content_integrity_errors"] == 0, "native direct evidence is incomplete or corrupted")
    # A definite W+ is retained and reported, not repaired by filtering context.
    _require(bundle.get("direct_evidence_report") == report, "saved native evidence summary differs from reevaluation")
    requests = loaded["native_requests"].get("requests")
    _require(isinstance(requests, list), "native requests must be an indexed list")
    for index, trace in enumerate(requests):
        _validate_trace(trace, index, root)
    for receipt in evidence["observations"]:
        _validate_receipt_link(receipt, requests, root)
    for control in evidence["actor_controls"].values():
        _validate_receipt_link(control["identity_response"], requests, root)
    return case, evidence, requests


def _native_memories(envelope, case, evidence, requests):
    actor = envelope["actor_id"]
    identity_index = envelope["native_identity_request_index"]
    _require(type(identity_index) is int and 0 <= identity_index < len(requests), "task native identity receipt missing")
    identity = requests[identity_index]
    _require(identity.get("actor_id") == actor and identity.get("native_method") == "GET"
             and identity.get("native_path") == "/api/v1/auths/" and identity.get("status") == 200
             and identity.get("auth_response_omitted") is True and identity.get("response_checked") is True
             and identity.get("authorization_present") is True and identity.get("cookie_present") is False
             and not identity.get("execution_error"), "task native identity receipt invalid")
    indices = envelope["native_request_indices"]
    _require(isinstance(indices, list) and len(indices) == 1 and type(indices[0]) is int
             and identity_index < indices[0] < len(requests), "native WebUI task requires one complete indexed list")
    trace = requests[indices[0]]
    _require(trace.get("actor_id") == actor and trace.get("native_method") == "GET"
             and trace.get("native_path") == "/api/v1/memories/" and trace.get("status") == 200
             and trace.get("response_checked") is True and trace.get("authorization_present") is True
             and trace.get("cookie_present") is False and not trace.get("execution_error"),
             "task context does not come from a successful native list")
    rows = json.loads(trace["native_raw_body"], object_pairs_hook=_unique_keys)
    _require(isinstance(rows, list), "native list response is not a list")
    reverse = {target: source for source, targets in evidence["plan"]["object_mapping"].items() for target in targets}
    records = {record["source_id"]: record for record in case["records"]}
    controls = {spec["positive_control"]["target_id"]: spec["positive_control"]["text_sha256"]
                for spec in evidence["actor_controls"].values()}
    memories = []
    for row in rows:
        _require(isinstance(row, dict) and all(isinstance(row.get(key), str) for key in ("id", "content", "user_id")),
                 "malformed native list row")
        target = row["id"]
        if target in controls:
            _require(_sha(row["content"].encode("utf-8")) == controls[target], "native control content mismatch")
            continue
        source = reverse.get(target)
        _require(source in records and row["content"] == records[source]["text"],
                 "native task row has unverified source or content")
        # No decision() filter here: an unauthorized registered row must reach
        # retrieval as returned, so downstream scoring can report disclosure.
        memories.append({"source_id": source, "text": row["content"]})
    return memories


def _validate_bundle(bundle, root, *, freezing=False):
    _require(bundle.get("schema_version") == SCHEMA_VERSION and bundle.get("kind") == KIND,
             "unsupported context snapshot schema")
    _require(bundle.get("method") == "reader_copies" and bundle.get("pipeline") == PIPELINE,
             "snapshot baseline or retrieval settings changed")
    _require(bundle.get("capture_mode") == "captured_during_native_task_run"
             and bundle.get("policy_time") == "frozen_native_retrieval" and bundle.get("remote_model_calls") == 0,
             "snapshot capture declaration changed")
    case, evidence, requests = _load_provenance(bundle, root)
    _require(bundle.get("case_id") == case["case_id"], "snapshot case ID mismatch")
    tasks = case.get("tasks")
    _require(isinstance(tasks, list) and tasks, "snapshot requires registered tasks")
    by_id = {task["task_id"]: task for task in tasks}
    _require(len(by_id) == len(tasks), "duplicate registered task ID")
    actors = {actor["actor_id"] for actor in case["actors"]}
    _require(all(task.get("case_id") == case["case_id"] and task.get("actor_id") in actors
                 and isinstance(task.get("query"), str) and task["query"] for task in tasks), "invalid registered task")
    orders = bundle.get("orders", [])
    _require(len(orders) == len(tasks) and {order.get("task_id") for order in orders} == set(by_id),
             "snapshot order must cover exactly registered tasks")
    order_by_id = {}
    for order in orders:
        _require(set(order) == {"case_id", "task_id", "order"} and order["case_id"] == case["case_id"]
                 and isinstance(order["order"], list) and len(order["order"]) == len(GROUPS)
                 and set(order["order"]) == set(GROUPS), "invalid three-group order")
        order_by_id[order["task_id"]] = order["order"]
    snapshots = bundle.get("snapshots")
    _require(isinstance(snapshots, list) and len(snapshots) == len(tasks) * len(GROUPS),
             "snapshot count must equal registered tasks times three groups")
    seen, sessions, list_indices = set(), set(), set()
    task_lists, denied_relationships, unknown_relationships = [], set(), set()
    for snapshot in snapshots:
        _require(set(snapshot) == {"envelope", "payload"}, "unexpected snapshot fields")
        envelope, payload = snapshot["envelope"], snapshot["payload"]
        _require(set(envelope) == ENVELOPE_FIELDS, "unexpected snapshot envelope fields")
        _require(set(payload) == {"query", "memories"}, "model payload contains non-input fields")
        validate_runtime(payload)
        task_id, group = envelope["task_id"], envelope["group"]
        _require(task_id in by_id and group in GROUPS and (task_id, group) not in seen,
                 "duplicate or unregistered task/group snapshot")
        task = by_id[task_id]
        _require(envelope["case_id"] == case["case_id"] and envelope["actor_id"] == task["actor_id"]
                 and payload["query"] == task["query"], "snapshot query or actor differs from runtime")
        session = envelope["session_id"]
        _require(isinstance(session, str) and session not in sessions and str(uuid.UUID(session)) == session,
                 "snapshot sessions must be fresh distinct UUIDs")
        sessions.add(session)
        seen.add((task_id, group))
        _require(type(envelope["order_position"]) is int
                 and envelope["order_position"] == order_by_id[task_id].index(group), "snapshot group order differs")
        for key in PROVENANCE_FILES:
            field = "runtime_sha256" if key == "runtime" else key + "_sha256"
            _require(envelope[field] == bundle["provenance"][key]["sha256"], "snapshot provenance link mismatch")
        memories = payload["memories"]
        _require(isinstance(memories, list) and all(isinstance(item, dict) and set(item) == {"source_id", "text"}
                 and all(isinstance(item[key], str) for key in ("source_id", "text")) for item in memories),
                 "model memories must contain only source_id/text")
        if group == "migrated":
            available = _native_memories(envelope, case, evidence, requests)
            _require(not list_indices.intersection(envelope["native_request_indices"]), "task list response reused")
            list_indices.update(envelope["native_request_indices"])
            records = {record["source_id"]: record for record in case["records"]}
            returned = sorted({memory["source_id"] for memory in available})
            denied = [source for source in returned if decision(records[source], task["actor_id"]) == "deny"]
            unknown = [source for source in returned if decision(records[source], task["actor_id"]) == "unknown"]
            selected = {memory["source_id"] for memory in memories}
            task_lists.append({"case_id": case["case_id"], "task_id": task_id, "actor_id": task["actor_id"],
                               "native_request_indices": envelope["native_request_indices"],
                               "returned_source_ids": returned, "denied_returned_source_ids": denied,
                               "unknown_authorization_returned_source_ids": unknown,
                               "denied_selected_source_ids": [source for source in denied if source in selected]})
            denied_relationships.update((task["actor_id"], source) for source in denied)
            unknown_relationships.update((task["actor_id"], source) for source in unknown)
        else:
            _require(envelope["native_request_indices"] == [] and envelope["native_identity_request_index"] is None,
                     "non-native group cannot claim a native task read")
            available = [{"source_id": record["source_id"], "text": record["text"]} for record in case["records"]
                         if decision(record, task["actor_id"]) == "allow"] if group == "authorized_reference" else []
        expected = retrieve(task["query"], available, PIPELINE["top_k"], PIPELINE["context_chars"])
        _require(memories == expected and envelope["context_sha256"] == context_sha256(memories),
                 "snapshot context differs from verified retrieval or hash")
    report = {"scope": "task_phase_native_list_content_before_retrieval_and_selected_model_inputs",
              "task_lists": task_lists,
              "known_w_plus_task_lists": sum(bool(item["denied_returned_source_ids"]) for item in task_lists),
              "denied_returned_relationships": [{"actor_id": actor, "source_id": source}
                                                for actor, source in sorted(denied_relationships)],
              "unknown_authorization_returned_relationships": [{"actor_id": actor, "source_id": source}
                                                               for actor, source in sorted(unknown_relationships)]}
    if freezing:
        bundle["task_retrieval_report"] = report
    else:
        _require(bundle.get("task_retrieval_report") == report, "task native disclosure report differs from raw responses")
    return bundle


def load_snapshot_bundle(path):
    """Read and validate all 3×tasks contexts and their local native evidence."""
    path = Path(path).resolve()
    try:
        return _validate_bundle(_read(path), path.parent)
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise ValueError("malformed context snapshot bundle") from exc


def freeze_snapshot_bundle(*, runtime_path, evidence_path, requests_path, task_run, output_path):
    """Freeze contexts captured in this native task run; never call an answerer."""
    output_path = Path(output_path).resolve()
    provenance = {}
    for key, value in (("runtime", runtime_path), ("direct_evidence", evidence_path), ("native_requests", requests_path)):
        path = Path(value).resolve()
        _require(path.parent == output_path.parent and path.name == PROVENANCE_FILES[key],
                 "snapshot provenance must be saved alongside contexts")
        provenance[key] = {"path": path.name, "sha256": _sha(path.read_bytes())}
    evidence = _read(evidence_path)
    bundle = {"schema_version": SCHEMA_VERSION, "kind": KIND, "case_id": task_run["case_id"],
              "method": "reader_copies", "pipeline": copy.deepcopy(task_run["pipeline"]),
              "orders": copy.deepcopy(task_run["orders"]), "provenance": provenance,
              "direct_evidence_report": evaluate(evidence), "snapshots": [],
              "capture_mode": "captured_during_native_task_run", "policy_time": "frozen_native_retrieval",
              "remote_model_calls": 0}
    for run in task_run["runs"]:
        _require(run.get("status") == "ok" and "context_payload" in run, "cannot freeze a failed or uncaptured task")
        envelope = {key: run[key] for key in ("case_id", "task_id", "actor_id", "group", "session_id", "order_position", "context_sha256")}
        envelope.update(runtime_sha256=provenance["runtime"]["sha256"],
                        direct_evidence_sha256=provenance["direct_evidence"]["sha256"],
                        native_requests_sha256=provenance["native_requests"]["sha256"],
                        native_request_indices=[], native_identity_request_index=None)
        if run["group"] == "migrated":
            receipt = run["retrieval_evidence"]
            envelope["native_identity_request_index"] = receipt["identity"]["native_request_index"]
            envelope["native_request_indices"] = [page["native_request_index"] for page in receipt["pages"]]
        bundle["snapshots"].append({"envelope": envelope, "payload": copy.deepcopy(run["context_payload"])})
    _validate_bundle(bundle, output_path.parent, freezing=True)
    with output_path.open("x", encoding="utf-8") as stream:
        json.dump(bundle, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return load_snapshot_bundle(output_path)
