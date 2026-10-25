"""Controlled native source→target qualification, not a general migration system.

Run only in fresh child processes. No LLM is used; real local storage embedding
is required and reported separately. Main grants/state/keys stay in this host.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import queue
import re
import secrets
import subprocess
import sys
import threading
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.privacy import _digest
from memory_migration_study.policy import decision, make_plan, validate_case

VERSION = "native_exact_fact_research_gateway_bridge_v3"
POLICY = {"version": "native-bridge-v1", "protected_categories": []}
AGENT = "AgentB"
SUPPORTED_CAPABILITIES = frozenset({"user_read_acl", "fixed_application_worker"})
ACTORS = ("owner", "assistant", "outsider")
MIGRATION_POLICY = {"export_allowed": True, "copy_allowed": True,
    "required_capabilities": sorted(SUPPORTED_CAPABILITIES)}
SEMANTIC_QUERY = "Customer service and delivery status."


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_code(paths, hashes, output, *, project=PROJECT):
    """Archive the exact reviewed bytes, retaining project-relative paths."""
    project, output = Path(project).resolve(), Path(output).resolve()
    archive = {}
    for value in paths:
        source = Path(value).resolve()
        relative = source.relative_to(project)
        if source.is_symlink():
            raise ValueError("code_symlink_not_supported")
        expected = hashes[str(source)]
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("code_changed_before_archive")
        target = output/"implementation"/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        copied = file_sha256(target)
        if copied != expected:
            raise ValueError("code_archive_copy_mismatch")
        archive[str(source)] = {"project_relative_path": relative.as_posix(),
            "archive_path": target.relative_to(output).as_posix(), "sha256": copied}
    return archive


def verify_sha_table(hashes):
    differences = []
    for name, expected in hashes.items():
        path = Path(name)
        try:
            if file_sha256(path) != expected:
                differences.append({"path": name, "reason": "content_changed"})
        except (OSError, ValueError):
            differences.append({"path": name, "reason": "missing_or_unreadable"})
    return {"status": "passed" if not differences else "failed", "checked_files": len(hashes), "differences": differences}


def verify_sdk_inventory(sdk_root):
    """Read/hash every installed file, rejecting omission, additions and escapes."""
    root = Path(sdk_root).resolve()
    target = root/"site-packages"
    manifest = root/"installed_file_hashes.json"
    result = {"status": "failed", "manifest_sha256": None, "manifest_entries": None,
        "checked_files": 0, "actual_file_count": None, "differences": []}
    def unique(pairs):
        value = {}
        for name, item in pairs:
            if name in value:
                raise ValueError("duplicate_manifest_field")
            value[name] = item
        return value
    try:
        raw = manifest.read_bytes()
        result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        rows = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(rows, list) or not rows or target.is_symlink() or not target.is_dir():
            raise ValueError("invalid_sdk_manifest_or_target")
        result["manifest_entries"] = len(rows)
        expected = {}
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}
                    or not isinstance(row["path"], str) or not row["path"] or "\\" in row["path"] or ":" in row["path"]
                    or type(row["bytes"]) is not int or row["bytes"] < 0
                    or not isinstance(row["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None):
                raise ValueError("invalid_sdk_manifest_entry")
            relative = PurePosixPath(row["path"])
            if relative.is_absolute() or relative.as_posix() != row["path"] or any(part in {".", ".."} for part in relative.parts):
                raise ValueError("unsafe_sdk_manifest_path")
            if row["path"] in expected:
                raise ValueError("duplicate_sdk_manifest_path")
            expected[row["path"]] = row
        actual = {}
        for path in target.rglob("*"):
            name = path.relative_to(target).as_posix()
            if path.is_symlink():
                result["differences"].append({"path": name, "reason": "symlink_not_supported"})
            if path.is_file():
                actual[name] = path
        result["actual_file_count"] = len(actual)
        for name, row in expected.items():
            path = target/Path(name)
            if name not in actual:
                result["differences"].append({"path": name, "reason": "missing"})
                continue
            if not path.resolve().is_relative_to(target.resolve()) or path.is_symlink():
                result["differences"].append({"path": name, "reason": "unsafe_resolution"})
                continue
            result["checked_files"] += 1
            if path.stat().st_size != row["bytes"] or file_sha256(path) != row["sha256"]:
                result["differences"].append({"path": name, "reason": "size_or_hash_changed"})
        result["differences"].extend({"path": name, "reason": "unexpected_file"} for name in sorted(set(actual)-set(expected)))
        result["status"] = "passed" if not result["differences"] and result["checked_files"] == len(rows) else "failed"
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        result["differences"].append({"reason": "manifest_or_inventory_invalid"})
    return result


class WorkerRPC:
    """In-memory protocol; keys/credentials are never arguments or logged."""
    def __init__(self, python, script, args, *, timeout=300):
        self.calls, self.index, self.timeout = [], 0, timeout
        self.process = subprocess.Popen([str(python), "-B", "-X", "utf8", str(script), *map(str, args)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", bufsize=1, cwd=PROJECT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.messages = queue.Queue()
        def reader():
            for line in self.process.stdout:
                try:
                    self.messages.put(json.loads(line))
                except (ValueError, UnicodeError):
                    self.messages.put({"protocol_error": True})
            self.messages.put({"worker_closed": True})
        threading.Thread(target=reader, daemon=True).start()

    def call(self, command, data):
        self.index += 1
        started_ns = time.perf_counter_ns()
        request = {"id": self.index, "command": command, "data": deepcopy(data)}
        self.process.stdin.write(json.dumps(request, ensure_ascii=False)+"\n")
        self.process.stdin.flush()
        try:
            response = self.messages.get(timeout=self.timeout)
        except queue.Empty:
            self.calls.append({"rpc_id": self.index, "command": command, "input": deepcopy(data),
                "input_sha256": _digest(data), "started_ns": started_ns, "finished_ns": time.perf_counter_ns(),
                "error": "worker_operation_timed_out"})
            raise RuntimeError("worker_operation_timed_out") from None
        if (not isinstance(response, dict) or response.get("id") != self.index or response.get("ok") is not True
                or set(response) != {"id", "ok", "result"}):
            self.calls.append({"rpc_id": self.index, "command": command, "input": deepcopy(data), "input_sha256": _digest(data),
                "started_ns": started_ns, "finished_ns": time.perf_counter_ns(),
                "error": response.get("error") if isinstance(response, dict) else "invalid_protocol"})
            raise RuntimeError("worker_operation_or_protocol_failed")
        self.calls.append({"rpc_id": self.index, "command": command, "input": deepcopy(data),
            "input_sha256": _digest(data), "result": deepcopy(response["result"]), "response_sha256": _digest(response["result"]),
            "started_ns": started_ns, "finished_ns": time.perf_counter_ns()})
        return response["result"]

    def terminate(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)


def authorize_projection(source, authority, record, *, fact_key, actor, agent=AGENT,
                         required_capabilities=("user_read_acl", "fixed_application_worker"),
                         target_identity_mapping=None, target_readers=None):
    """Read the real current gateway before consulting the exact signed grant."""
    current = source.call("read", {"fact_key": fact_key, "actor": actor})
    if current.get("status") != 200 or current.get("authenticated_principal") != actor:
        return {"status": "blocked", "error": "current_source_denied", "current_source_status": current.get("status")}
    row = current.get("body")
    if (not isinstance(row, dict) or row.get("id") != record["source"]["source_id"]
            or row.get("memory") != record["source"]["text"]):
        return {"status": "blocked", "error": "current_source_content_changed"}
    error = authority.validate_access(record, actor_id=actor, agent_id=agent,
        authorizer=lambda rid, principal, version: rid == record["record_id"] and principal == actor and version == POLICY["version"],
        policy_version=POLICY["version"])
    if error:
        return {"status": "blocked", "error": error}
    control = current.get("trusted_migration_control")
    if (not isinstance(control, dict) or set(control) != {"source_id", "source_sha256", "source_readers", "migration_policy"}
            or current.get("record_id") != row["id"] or control.get("source_id") != row["id"]
            or control.get("source_sha256") != record["source"]["sha256"]
            or control.get("source_sha256") != hashlib.sha256(row["memory"].encode("utf-8")).hexdigest()):
        return {"status": "blocked", "error": "trusted_migration_control_binding_invalid"}
    migration_policy = control.get("migration_policy")
    if (not isinstance(migration_policy, dict)
            or not set(migration_policy) <= {"export_allowed", "copy_allowed", "required_capabilities"}):
        return {"status": "blocked", "error": "unsupported_migration_policy"}
    source_capabilities = migration_policy.get("required_capabilities", [])
    if (not isinstance(required_capabilities, (list, tuple))
            or any(not isinstance(item, str) for item in required_capabilities)
            or not isinstance(source_capabilities, list)
            or any(not isinstance(item, str) for item in source_capabilities)
            or not (set(required_capabilities) | set(source_capabilities) | SUPPORTED_CAPABILITIES) <= SUPPORTED_CAPABILITIES):
        return {"status": "blocked", "error": "unsupported_native_constraint"}
    fact_policy = {"source_id": record["record_id"], "text": record["text"],
        "source_readers": control["source_readers"], "recipient_readers": record["access"]["readers"],
        "target_readers": target_readers, "export_allowed": migration_policy.get("export_allowed"),
        "copy_allowed": migration_policy.get("copy_allowed")}
    case = {"case_id": "native_exact_fact_"+record["record_id"],
        "actors": [{"actor_id": name, "user_id": name, "agent_id": AGENT} for name in ACTORS],
        "actor_mapping": target_identity_mapping, "records": [fact_policy]}
    try:
        validate_case(case)
        plan = make_plan(case, "reader_copies", "native-bridge-v3-"+record["record_id"])
    except (ValueError, TypeError, KeyError):
        return {"status": "blocked", "error": "migration_case_invalid"}
    if plan["excluded"]:
        return {"status": "blocked", "error": plan["excluded"][0]["reason"]}
    selected = [item for item in plan["objects"] if item["readers"] == [actor]]
    if decision(fact_policy, actor) != "allow" or len(selected) != 1:
        return {"status": "blocked", "error": "migration_reader_denied"}
    evidence = {"method": "reader_copies", "source_id": record["record_id"],
        "actual_source_id": control["source_id"], "source_sha256": control["source_sha256"],
        "source_start": record["source_start"], "source_end": record["source_end"],
        "content_sha256": record["access"]["content_sha256"],
        "source_readers": fact_policy["source_readers"], "recipient_readers": fact_policy["recipient_readers"],
        "target_readers": fact_policy["target_readers"], "export_allowed": fact_policy["export_allowed"],
        "copy_allowed": fact_policy["copy_allowed"], "decisions": {name: decision(fact_policy, name) for name in ACTORS},
        "actor_mapping_sha256": _digest(target_identity_mapping), "case_sha256": _digest(case),
        "plan_sha256": _digest(plan), "migration_control_sha256": _digest(control)}
    return {"status": "ok", "payload": {"actor": actor, "text": record["text"],
        "path": "/exact-fact/"+record["record_id"]}, "grant_record_id": record["record_id"], "migration_evidence": evidence}


def migrate(source, target, authority, record, *, fact_key, actors, agent=AGENT, required_capabilities=None,
            target_identity_mapping=None):
    if (not isinstance(actors, list) or not actors or any(type(actor) is not str or actor not in ACTORS for actor in actors)
            or len(set(actors)) != len(actors)):
        return {"status": "blocked", "error": "migration_audience_invalid", "copies": []}
    projections, evidences = [], []
    for actor in actors:
        options = {} if required_capabilities is None else {"required_capabilities": required_capabilities}
        result = authorize_projection(source, authority, record, fact_key=fact_key, actor=actor, agent=agent,
            target_identity_mapping=target_identity_mapping, target_readers=actors, **options)
        if result["status"] != "ok":
            return {**result, "copies": []}
        projections.append(result["payload"])
        evidences.append(result["migration_evidence"])
    if any(item != evidences[0] for item in evidences[1:]):
        return {"status": "blocked", "error": "migration_control_changed_during_planning", "copies": []}
    copies = []
    for payload in projections:
        result = target.call("add", payload)
        if (not isinstance(result.get("target_id"), str) or result.get("actor") != payload["actor"]
                or result.get("content") != record["text"]):
            raise RuntimeError("native_write_not_verified")
        copies.append({"actor": payload["actor"], "target_id": result["target_id"]})
    return {"status": "ok", "copies": copies, "migration_evidence": evidences[0]}


def listed_ids(snapshot):
    result = {}
    for row in snapshot.get("rows", []):
        if row.get("operation") == "semantic":
            continue  # Checked against each subject's real list observation below.
        if (row.get("status") != 200 or row.get("response_checked") is not True
                or row.get("execution_error") is not None or not isinstance(row.get("items"), list)):
            raise ValueError("native_snapshot_not_a_qualified_observation")
        for item in row["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("content"), str):
                raise ValueError("native_snapshot_schema_invalid")
        if row.get("operation") == "list":
            if row["actor"] in result:
                raise ValueError("duplicate_native_list_observation")
            result[row["actor"]] = {item["id"] for item in row["items"]}
    if set(result) != {"owner", "assistant", "outsider"}:
        raise ValueError("incomplete_native_subject_matrix")
    return result


def check_semantic_row(row, *, expected_ids, listed_rows, source_canary):
    """Native vector response, not SQL search; errors never count as empty hits."""
    if (row.get("response_checked") is not True or row.get("execution_error") is not None
            or row.get("query") != SEMANTIC_QUERY or type(row.get("k")) is not int or row["k"] != 100
            or source_canary in json.dumps(row, ensure_ascii=False)):
        return False
    value = row.get("vector_result")
    raw = row.get("native_raw_body")
    try:
        if (not isinstance(raw, str) or json.loads(raw) != value
                or row.get("native_body_sha256") != hashlib.sha256(raw.encode("utf-8")).hexdigest()):
            return False
    except (TypeError, ValueError):
        return False
    if row.get("status") == 404:
        return not expected_ids and not listed_rows and value == {"detail": "No memories found for user"}
    if row.get("status") != 200 or not isinstance(value, dict) or set(value) != {"ids", "documents", "metadatas", "distances"}:
        return False
    for key in value:
        if not isinstance(value[key], list) or len(value[key]) != 1 or not isinstance(value[key][0], list):
            return False
    ids, docs, metas, distances = (value[key][0] for key in ("ids", "documents", "metadatas", "distances"))
    if (not all(type(rid) is str for rid in ids) or len(set(ids)) != len(ids)
            or not len(ids) == len(docs) == len(metas) == len(distances) or set(ids) != expected_ids):
        return False
    for rid, doc, meta, distance in zip(ids, docs, metas, distances):
        original = listed_rows.get(rid)
        if (original is None or not isinstance(doc, str) or not isinstance(meta, dict)
                or type(distance) not in (int, float) or not math.isfinite(distance)):
            return False
        # memory_vector_text in pinned 0.12.3: normalized path + newline + exact content.
        path = original.get("path")
        if path is not None and (not isinstance(path, str) or not path or path.startswith("/") or path.endswith("/")
                or "//" in path or any(part in {".", ".."} for part in path.split("/"))):
            return False
        expected_doc = (path+"\n" if path else "")+original["content"]
        expected_meta = {key: original.get(key) for key in ("created_at", "updated_at", "type", "path")}
        if (doc != expected_doc or _digest(meta) != _digest(expected_meta) or expected_meta["type"] != "context"
                or any(type(expected_meta[key]) is not int for key in ("created_at", "updated_at"))):
            return False
    return True


def check_snapshot(snapshot, expected, *, source_canary, expected_text=None, known_ids=()):
    ids = listed_ids(snapshot)
    if ids != expected:
        return False
    matrix = [(row.get("actor"), row.get("operation"), row.get("requested_id")) for row in snapshot["rows"]]
    required = {(actor, operation, rid) for actor in ("owner", "assistant", "outsider")
        for operation, rid in [("list", None), ("lexical", None), ("semantic", None), *[("known_id", rid) for rid in known_ids]]}
    if len(matrix) != len(required) or set(matrix) != required:
        return False
    for row in snapshot["rows"]:
        if row["operation"] == "semantic":
            listed = next(item["items"] for item in snapshot["rows"] if item["operation"] == "list" and item["actor"] == row["actor"])
            if not check_semantic_row(row, expected_ids=expected[row["actor"]],
                    listed_rows={item["id"]: item for item in listed}, source_canary=source_canary):
                return False
            continue
        if source_canary in json.dumps(row, ensure_ascii=False):
            return False
        observed = {item["id"] for item in row["items"]}
        if not observed <= expected[row["actor"]]:
            return False
        if row["operation"] == "known_id":
            requested = row["requested_id"]
            if observed != ({requested} if requested in expected[row["actor"]] else set()):
                return False
        if expected_text:
            for item in row["items"]:
                if item["id"] not in expected_text or item["content"] != expected_text[item["id"]]:
                    return False
    return True


def run_scenario(source, target, *, checkpoint=None):
    """Real host logic; injectable workers enable model-free offline tests."""
    canary = "SOURCE-ONLY-CANARY-"+secrets.token_hex(12)
    fact = "Customer: Alder Mutual. Service status: pending."
    source_text = fact+"\nUnmigrated note: "+canary
    control = "Delivery status: cleared."
    source_info = source.call("init", {"records": [
        {"fact_key": "main", "text": source_text, "readers": ["owner", "assistant"], "migration_policy": deepcopy(MIGRATION_POLICY)},
        {"fact_key": "valid_control", "text": control, "readers": ["assistant"], "migration_policy": deepcopy(MIGRATION_POLICY)}]})
    target_info = target.call("init", {})
    if (source_info.get("mem0_version") != "2.2.1" or source_info.get("embedding_dimensions") != 384
            or source_info.get("infer") is not False or target_info.get("open_webui_version") != "0.12.3"
            or target_info.get("source_sdk_overlay_present") is not False
            or target_info.get("model_discovery_disabled") is not True):
        raise ValueError("native_runtime_not_qualified")
    authority = MemoryLabelAuthority(secrets.token_bytes(32))
    target_mapping = target_info.get("native_user_ids")
    whoami = target_info.get("whoami_public_receipts")
    if (not isinstance(target_mapping, dict) or set(target_mapping) != set(ACTORS)
            or any(type(value) is not str or not value for value in target_mapping.values())
            or len(set(target_mapping.values())) != len(ACTORS)
            or not isinstance(whoami, list) or len(whoami) != len(ACTORS)
            or any(not isinstance(row, dict) or set(row) != {"actor", "id", "role", "native_request_index"}
                or row["actor"] not in ACTORS or row["id"] != target_mapping[row["actor"]] or row["role"] != "user"
                or type(row["native_request_index"]) is not int or row["native_request_index"] < 0 for row in whoami)
            or {row["actor"] for row in whoami} != set(ACTORS)
            or len({row["native_request_index"] for row in whoami}) != len(ACTORS)):
        raise ValueError("native_identity_mapping_not_qualified")
    def transfer(item, *, fact_key, actors, **kwargs):
        return migrate(source, target, authority, item, fact_key=fact_key, actors=actors,
            target_identity_mapping=target_mapping, **kwargs)
    def record(key, original, text, readers):
        return authority.build_record({"source_id": source_info["rows"][key], "text": original},
            {"text": text, "source_start": original.index(text), "source_end": original.index(text)+len(text), "findings": []},
            POLICY, owner_id=readers[0], readers=readers, agent_id="AgentA", allowed_agent_ids=[AGENT], builder_version=VERSION)
    main = record("main", source_text, fact, ["owner", "assistant"])
    valid = record("valid_control", control, control, ["assistant"])
    checks, gates, snapshots, sidecar, expected_text = [], [], {}, {}, {}
    def progress(stage):
        if checkpoint is not None:
            checkpoint({"version": VERSION, "status": "running", "stage": stage,
                "checks": checks, "prewrite_controls": gates, "snapshots": snapshots, "sidecar": sidecar})
    def check(name, value):
        checks.append({"name": name, "passed": value is True})
    # Real host negative controls, before any migration write.
    changed = deepcopy(main)
    changed["text"] = source_text
    variants = [("changed_content", changed, "owner", AGENT, None),
        ("wrong_actor", main, "outsider", AGENT, None), ("wrong_agent", main, "owner", "AgentC", None),
        ("unsupported_native_agent_acl", main, "owner", AGENT, ["per_agent_native_acl"])]
    changed_range = deepcopy(main)
    changed_range["source_start"] = 1
    variants.append(("changed_range", changed_range, "owner", AGENT, None))
    for name, item, actor, agent, capabilities in variants:
        result = transfer(item, fact_key="main", actors=[actor], agent=agent,
                         required_capabilities=capabilities)
        gates.append({"name": name, "status": result["status"], "error": result.get("error")})
        check("prewrite_"+name+"_refused", result["status"] == "blocked" and result.get("copies") == [])
    for name, migration_policy in (
            ("read_allowed_export_forbidden", {**MIGRATION_POLICY, "export_allowed": False}),
            ("read_allowed_copy_forbidden", {**MIGRATION_POLICY, "copy_allowed": False}),
            ("export_unknown", {**MIGRATION_POLICY, "export_allowed": None}),
            ("copy_missing", {"export_allowed": True}),
            ("export_invalid_boolean", {**MIGRATION_POLICY, "export_allowed": 1}),
            ("unknown_constraint", {**MIGRATION_POLICY, "purpose_limit": "unrepresented"}),
            ("source_requires_native_agent_acl", {**MIGRATION_POLICY, "required_capabilities": ["per_agent_native_acl"]})):
        updated = source.call("set_migration_policy", {"fact_key": "main", "migration_policy": migration_policy})
        readable = source.call("read", {"fact_key": "main", "actor": "owner"})
        result = transfer(main, fact_key="main", actors=["owner"])
        gates.append({"name": name, "status": result["status"], "error": result.get("error"),
            "current_source_status": readable.get("status"), "migration_policy": migration_policy})
        check("prewrite_"+name+"_refused_while_readable", updated.get("updated") is True
            and readable.get("status") == 200 and result["status"] == "blocked" and result.get("copies") == [])
    restored = source.call("set_migration_policy", {"fact_key": "main", "migration_policy": deepcopy(MIGRATION_POLICY)})
    check("explicit_positive_migration_policy_restored", restored.get("updated") is True)
    check("all_prewrite_negative_controls_made_zero_target_add_calls", not any(row["command"] == "add" for row in target.calls))
    snapshots["before_writes"] = target.call("snapshot", {"target_ids": []})
    check("negative_controls_created_no_objects", check_snapshot(snapshots["before_writes"],
        {"owner": set(), "assistant": set(), "outsider": set()}, source_canary=canary))
    progress("negative_controls_completed")
    for key, item, actors in (("main", main, ["owner", "assistant"]), ("valid_control", valid, ["assistant"])):
        result = transfer(item, fact_key=key, actors=actors)
        if result["status"] != "ok":
            raise ValueError("authorized_migration_failed")
        sidecar[key] = {"record_id": item["record_id"], "source_id": item["source"]["source_id"],
            "source_sha256": item["source"]["sha256"], "content_sha256": item["access"]["content_sha256"],
            "source_start": item["source_start"], "source_end": item["source_end"],
            "epoch": item["access"]["epoch"], "copies": result["copies"], "migration_evidence": result["migration_evidence"]}
        for copy in result["copies"]:
            expected_text[copy["target_id"]] = item["text"]
        progress("migrated_"+key)
    resident_control = target.call("add_residents", {})
    residents = resident_control.get("residents")
    if (not isinstance(residents, list) or len(residents) != len(ACTORS)
            or {item.get("actor") for item in residents if isinstance(item, dict)} != set(ACTORS)
            or any(not isinstance(item.get("target_id"), str) or not isinstance(item.get("content"), str)
                or not item["content"].strip() or item.get("path") != "/resident-control/"+item["actor"] for item in residents)
            or len({item["target_id"] for item in residents}) != len(ACTORS)):
        raise ValueError("native_resident_controls_not_verified")
    for item in residents:
        if item["target_id"] in expected_text:
            raise ValueError("native_resident_id_reused")
        expected_text[item["target_id"]] = item["content"]
    all_ids = list(expected_text)
    expected = {actor: {item["target_id"] for item in residents if item["actor"] == actor} for actor in ACTORS}
    for entry in sidecar.values():
        for copy in entry["copies"]:
            expected[copy["actor"]].add(copy["target_id"])
    snapshots["before_revoke"] = target.call("snapshot", {"target_ids": all_ids})
    check("native_legal_and_outsider_matrix", check_snapshot(snapshots["before_revoke"], expected,
        source_canary=canary, expected_text=expected_text, known_ids=all_ids))
    export_update = source.call("set_migration_policy", {"fact_key": "main",
        "migration_policy": {**MIGRATION_POLICY, "export_allowed": False}})
    readable_without_export = source.call("read", {"fact_key": "main", "actor": "assistant"})
    previous_add_count = sum(row["command"] == "add" for row in target.calls)
    export_retry = transfer(main, fact_key="main", actors=["owner", "assistant"])
    check("export_disabled_but_native_source_read_stays_200", export_update.get("updated") is True
        and readable_without_export.get("status") == 200)
    check("export_disabled_old_job_refused_before_new_copy", export_retry["status"] == "blocked"
        and export_retry.get("error") == "export_forbidden" and export_retry.get("copies") == []
        and sum(row["command"] == "add" for row in target.calls) == previous_add_count)
    snapshots["export_disabled_existing_copies_retained"] = target.call("snapshot", {"target_ids": all_ids})
    check("export_disable_does_not_revoke_already_delivered_copies", check_snapshot(
        snapshots["export_disabled_existing_copies_retained"], expected, source_canary=canary,
        expected_text=expected_text, known_ids=all_ids))
    restored = source.call("set_migration_policy", {"fact_key": "main", "migration_policy": deepcopy(MIGRATION_POLICY)})
    check("export_eligibility_restored_before_read_revocation", restored.get("updated") is True)
    progress("new_export_forbidden_existing_copies_retained")
    progress("before_revoke")
    revoke = source.call("revoke", {"fact_key": "main"})
    authority.revoke(main["record_id"])
    source_after = source.call("read", {"fact_key": "main", "actor": "assistant"})
    check("source_current_read_revoked", revoke.get("revoked") is True and source_after.get("status") == 403)
    snapshots["revoked_before_target_cleanup"] = target.call("snapshot", {"target_ids": all_ids})
    check("native_copies_still_visible_before_explicit_cleanup", check_snapshot(
        snapshots["revoked_before_target_cleanup"], expected, source_canary=canary, expected_text=expected_text, known_ids=all_ids))
    progress("source_revoked_before_cleanup")
    deletions = []
    for copy in sidecar["main"]["copies"]:
        outcome = target.call("delete", {"actor": copy["actor"], "target_id": copy["target_id"]})
        deletions.append(outcome)
        check("delete_receipt_"+copy["actor"], outcome.get("status") == 200 and outcome.get("deleted") is True
            and outcome.get("target_id") == copy["target_id"] and outcome.get("actor") == copy["actor"])
        expected[copy["actor"]].remove(copy["target_id"])
        progress("cleanup_"+copy["actor"])
    snapshots["after_cleanup"] = target.call("snapshot", {"target_ids": all_ids})
    check("all_old_ids_removed_resident_and_valid_control_preserved", check_snapshot(snapshots["after_cleanup"],
        expected, source_canary=canary, expected_text=expected_text, known_ids=all_ids))
    replay = transfer(main, fact_key="main", actors=["owner", "assistant"])
    check("old_job_current_source_denied_no_recreation", replay["status"] == "blocked" and replay.get("error") == "current_source_denied")
    snapshots["after_old_job_replay"] = target.call("snapshot", {"target_ids": all_ids})
    check("replay_left_target_matrix_unchanged", check_snapshot(snapshots["after_old_job_replay"], expected,
        source_canary=canary, expected_text=expected_text, known_ids=all_ids))
    progress("old_job_replay_completed")
    control_after = source.call("read", {"fact_key": "valid_control", "actor": "assistant"})
    check("independent_source_control_still_readable", control_after.get("status") == 200 and control_after.get("body", {}).get("memory") == control)
    target_report = target.call("report", {})
    check("source_only_canary_absent_from_all_target_raw_and_error_bodies", canary not in json.dumps(target_report, ensure_ascii=False))
    return {"version": VERSION, "status": "passed" if all(row["passed"] for row in checks) else "failed",
        "checks": checks, "prewrite_controls": gates, "source_runtime": source_info, "target_runtime": target_info,
        "sidecar": sidecar, "snapshots": snapshots, "deletions": deletions,
        "public_exact_grants": {"main": deepcopy(main["access"]), "valid_control": deepcopy(valid["access"])},
        "public_grant_scope": "trusted host signed-access payload only; signatures and signing keys omitted; not independent HMAC verification",
        "resident_controls": residents,
        "semantic_query_contract": {"endpoint": "/api/v1/memories/query", "content": SEMANTIC_QUERY, "k": 100,
            "scope": "all known native own-memory IDs in this small fixture, with exact documents and metadata",
            "qualified_empty": "only exact No memories found for user 404 plus independently empty native list",
            "relevance_threshold_changed": False, "vector_formatter": "pinned memory_vector_text(content,path)"},
        "old_job": {"job_sha256": _digest({"record_id": main["record_id"], "fact_sha256": sidecar["main"]["content_sha256"],
            "range": [main["source_start"], main["source_end"]], "agent": AGENT}), "replay": replay,
            "export_forbidden_replay": export_retry, "export_forbidden_source_read_status": readable_without_export.get("status")},
        "trusted_fixture": {"source": source_text, "fact": fact, "source_only_canary": canary},
        "target_report": target_report, "generation_calls": 0, "paid_api_calls": 0,
        "migration_gate": {"baseline": "memory_migration_study.policy.validate_case/decision/make_plan(reader_copies)",
            "source_readers": "current trusted research gateway ACL", "recipient_readers": "exact signed fact grant",
            "target_readers": "explicit requested native-user copies", "identity_mapping": "target native whoami-verified user IDs",
            "source_flags": "separate trusted migration control; never memory text", "per_agent_native_acl_supported": False},
        "scope": "Trusted same-host Mem0 research ACL gateway to native user-scoped WebUI with a fixed application worker; existing export/copy and conjunctive-read baseline, exact-fact grant, explicit cleanup. Export denial stops new copies only; neither automatic cross-system revocation nor a general Agent protocol."}


def run(output, *, python, sdk_root, legacy_project, timeout=300):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    package_paths = sorted((PROJECT/"memory_migration_study").glob("*.py"))
    package_inventory = [path.relative_to(PROJECT).as_posix() for path in package_paths]
    paths = [Path(__file__), PROJECT/"scripts/native_exact_fact_common.py", PROJECT/"scripts/native_exact_fact_source.py",
        PROJECT/"scripts/native_exact_fact_target.py", *package_paths, Path(legacy_project)/"scripts/qualify_migration.py",
        Path(legacy_project)/"scripts/openwebui_migration_probe.py"]
    assets = Path(legacy_project)/"runtime_assets"
    model_files = [assets/"models/minilm"/name for name in ("model.safetensors", "config.json", "modules.json",
        "tokenizer.json", "tokenizer_config.json", "1_Pooling/config.json")]
    support_files = [Path(sdk_root)/name for name in ("installed_file_hashes.json", "pip-report.json")]
    support_files += [assets/"native_dlls"/name for name in ("libcrypto-3-x64.dll", "libssl-3-x64.dll")]
    native_config = Path(python).resolve().parent.parent/"Lib/site-packages/open_webui/config.py"
    support_files.append(native_config)
    native_memory_sources = [native_config.parent/"routers/memories.py", native_config.parent/"utils/memory.py",
        native_config.parent/"retrieval/vector/main.py", native_config.parent/"retrieval/vector/dbs/chroma.py"]
    support_files.extend(native_memory_sources)
    source = target = None
    hashes, asset_hashes, archived = {}, {}, {}
    preflight = {"status": "not_run"}
    report = {"version": VERSION, "status": "failed", "error": None}
    try:
        hashes = {str(path.resolve()): file_sha256(path) for path in paths}
        archived = archive_code(paths, hashes, output)
        asset_hashes = {str(path.resolve()): file_sha256(path) for path in model_files+support_files}
        preflight = verify_sdk_inventory(sdk_root)
        save(output/"sdk_inventory_verification.json", preflight)
        save(output/"plan.json", {"version": VERSION, "code_sha256": hashes, "code_archive": archived,
            "python": str(python), "source_sdk_root": str(sdk_root), "generation_budget": 0,
            "external_network_allowed": False, "asset_sha256": asset_hashes, "sdk_inventory_preflight": preflight,
            "package_source_inventory": package_inventory,
            "open_webui_config": {"version": "0.12.3", "path": str(native_config),
                "sha256": asset_hashes[str(native_config.resolve())],
                "configuration": "explicit dead Ollama URLs and APIs off before import, guard still denies port 9"},
            "native_memory_contract_sources": {str(path): asset_hashes[str(path.resolve())] for path in native_memory_sources},
            "native_semantic_query": {"path": "/api/v1/memories/query", "content": SEMANTIC_QUERY, "k": 100,
                "relevance_threshold_changed": False, "own_resident_controls": list(ACTORS)},
            "scope": "fresh local native qualification; no LLM task efficacy or arbitrary interoperability claim"})
        if preflight["status"] != "passed":
            raise ValueError("sdk_inventory_not_verified")
        source = WorkerRPC(python, PROJECT/"scripts/native_exact_fact_source.py", ["--state", output/"source_state",
            "--sdk-root", sdk_root, "--model", assets/"models/minilm", "--legacy-project", legacy_project], timeout=timeout)
        target = WorkerRPC(python, PROJECT/"scripts/native_exact_fact_target.py", ["--state", output/"target_state",
            "--assets", assets, "--legacy-project", legacy_project], timeout=timeout)
        report = run_scenario(source, target, checkpoint=lambda value: save(output/"checkpoint.json", value))
    except Exception as error:
        report.update(status="failed", error={"type": type(error).__name__, "code": "native_exact_fact_bridge_failed"})
        if (output/"checkpoint.json").is_file():
            report["partial_checkpoint"] = json.loads((output/"checkpoint.json").read_text(encoding="utf-8"))
    finally:
        for name, worker in (("source", source), ("target", target)):
            if worker is not None:
                try:
                    report[name+"_final"] = worker.call("close", {})
                except Exception as error:
                    report[name+"_close_error"] = type(error).__name__
                    report["status"] = "failed"
                report[name+"_rpc_receipts"] = worker.calls
                worker.terminate()
    report["sdk_inventory_preflight"] = preflight
    report["code_postflight"] = verify_sha_table(hashes) if hashes else {"status": "not_run"}
    report["archive_postflight"] = verify_sha_table({str(output/item["archive_path"]): item["sha256"]
        for item in archived.values()}) if archived else {"status": "not_run"}
    report["asset_postflight"] = verify_sha_table(asset_hashes) if asset_hashes else {"status": "not_run"}
    report["package_source_inventory_unchanged"] = package_inventory == [path.relative_to(PROJECT).as_posix()
        for path in sorted((PROJECT/"memory_migration_study").glob("*.py"))]
    report["code_unchanged"] = report["code_postflight"]["status"] == "passed"
    for stage in ("source_final", "target_final"):
        final = report.get(stage, {})
        if final.get("generation_attempts", 0) or any(not event.get("allowed", False) for event in final.get("network_events", [])):
            report["status"] = "failed"
    if (not report["code_unchanged"] or report["archive_postflight"]["status"] != "passed"
            or report["asset_postflight"]["status"] != "passed" or preflight["status"] != "passed"
            or not report["package_source_inventory_unchanged"]):
        report["status"] = "failed"
    save(output/"report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=PROJECT/".venv-native-webui/Scripts/python.exe")
    parser.add_argument("--sdk-root", type=Path, default=PROJECT/".runtime/native_mem0_sdk_v1")
    parser.add_argument("--legacy-project", type=Path, default=PROJECT/"memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    result = run(args.output, python=args.python.resolve(), sdk_root=args.sdk_root.resolve(),
        legacy_project=args.legacy_project.resolve(), timeout=args.timeout)
    print(json.dumps({"status": result["status"], "checks": len(result.get("checks", [])), "generation_calls": 0}))
    raise SystemExit(0 if result["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
