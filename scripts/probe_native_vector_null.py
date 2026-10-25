"""Bounded, model-free Chroma 1.5.9 diagnostic in a fresh directory only."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import shutil
import struct
import sys
import time
import traceback

if __package__:
    from .native_exact_fact_common import NetworkGuard, isolate_environment
else:
    from native_exact_fact_common import NetworkGuard, isolate_environment

VERSION = "pure_chroma_vector_null_diagnostic_v1"
DIMENSIONS = 384
ACTORS = ("owner", "assistant", "outsider")
ROUNDS = 2
QUERY_LIMIT = 100
MAX_QUERIES = 12
TRACE_LIMIT = 10000
FORBIDDEN_MODULES = ("open_webui", "ollama", "mem0", "torch", "transformers", "sentence_transformers")


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def sha_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")


def vector(seed):
    """Finite, non-degenerate formula vectors; no embedder is instantiated."""
    values = [math.sin((i+1)*(seed+1)*0.017)+math.cos((i+3)*(seed+2)*0.011)+0.07*(i % 11-5)
              for i in range(DIMENSIONS)]
    norm = math.sqrt(sum(value*value for value in values))
    return list(struct.unpack("<"+"f"*DIMENSIONS, struct.pack("<"+"f"*DIMENSIONS,
        *[value/norm for value in values])))


def vector_stats(values):
    if not isinstance(values, list) or len(values) != DIMENSIONS or any(type(v) not in (float, int) for v in values):
        raise ValueError("vector_shape_or_type_invalid")
    finite = all(math.isfinite(v) for v in values)
    if not finite:
        raise ValueError("nonfinite_formula_vector")
    return {"dtype": "float32_le", "shape": [DIMENSIONS], "finite": True,
        "l2_norm": math.sqrt(sum(v*v for v in values)), "minimum": min(values), "maximum": max(values),
        "sha256": hashlib.sha256(struct.pack("<"+"f"*DIMENSIONS, *values)).hexdigest()}


def fixture():
    rows = [
        ("owner", "main-owner", 1, "Customer: Alder Mutual. Service status: pending.", "exact-fact/main"),
        ("owner", "resident-owner", 11, "Unrelated own resident for owner.", "resident-control/owner"),
        ("assistant", "main-assistant", 1, "Customer: Alder Mutual. Service status: pending.", "exact-fact/main"),
        ("assistant", "valid-assistant", 2, "Delivery status: cleared.", "exact-fact/valid-control"),
        ("assistant", "resident-assistant", 12, "Unrelated own resident for assistant.", "resident-control/assistant"),
        ("outsider", "resident-outsider", 13, "Unrelated own resident for outsider.", "resident-control/outsider"),
    ]
    return [{"actor": actor, "id": rid, "vector_seed": seed,
        "document": path+"\n"+text, "metadata": {"path": path, "type": "context", "created_at": 1, "updated_at": 1}}
        for actor, rid, seed, text, path in rows]


def schedule():
    return [{"phase": phase, "round": round_index, "actor": actor, "k": QUERY_LIMIT}
        for phase in ("before_delete", "after_delete") for round_index in range(1, ROUNDS+1) for actor in ACTORS]


def exception_record(error):
    message = str(error)
    return {"class": type(error).__module__+"."+type(error).__name__,
        "message_sha256": hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest(),
        "message": message[:2048], "message_truncated": len(message) > 2048,
        "stack": [{"file": frame.filename, "line": frame.lineno, "function": frame.name}
                  for frame in traceback.extract_tb(error.__traceback__)[-12:]]}


def plain(value):
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else {"nonfinite": repr(value)}
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    if hasattr(value, "tolist"):
        return plain(value.tolist())
    raise ValueError("unrecordable_native_result")


class Observer:
    def __init__(self, roots=()):
        self.roots = tuple(str(Path(path).resolve()) for path in roots)
        self.calls, self.exception_events = [], []
        self.stage = None
        self.trace_overflow = False

    def trace(self, frame, event, arg):
        if event == "exception" and self.roots and any(frame.f_code.co_filename.startswith(root) for root in self.roots):
            error_class, error, _ = arg
            if len(self.exception_events) >= TRACE_LIMIT:
                self.trace_overflow = True
            else:
                record = exception_record(error)
                record.update(stage=deepcopy(self.stage), file=frame.f_code.co_filename,
                    line=frame.f_lineno, function=frame.f_code.co_name,
                    control_flow=issubclass(error_class, (StopIteration, GeneratorExit)))
                self.exception_events.append(record)
        return self.trace

    def invoke(self, operation, actor, stage, function):
        self.stage = {"operation": operation, "actor": actor, "stage": stage}
        started = time.perf_counter_ns()
        previous_trace = sys.gettrace()
        sys.settrace(self.trace)
        try:
            result = function()
            record = {"operation": operation, "actor": actor, "stage": stage, "status": "ok", "result": plain(result)}
        except Exception as error:
            record = {"operation": operation, "actor": actor, "stage": stage, "status": "error", "error": exception_record(error)}
        finally:
            sys.settrace(previous_trace)
        record.update(started_ns=started, finished_ns=time.perf_counter_ns())
        self.calls.append(record)
        return record


def validate_query(result, expected_rows):
    """No null/exception/missing positive is converted into a safe empty result."""
    if not isinstance(result, dict):
        return False
    values = []
    for key in ("ids", "documents", "metadatas", "distances"):
        item = result.get(key)
        if not isinstance(item, list) or len(item) != 1 or not isinstance(item[0], list):
            return False
        values.append(item[0])
    ids, documents, metadatas, distances = values
    if (any(type(rid) is not str for rid in ids) or len(set(ids)) != len(ids)
            or set(ids) != set(expected_rows) or not len(ids) == len(documents) == len(metadatas) == len(distances)):
        return False
    return all(document == expected_rows[rid]["document"] and digest(meta) == digest(expected_rows[rid]["metadata"])
        and type(distance) in (int, float) and math.isfinite(distance)
        for rid, document, meta, distance in zip(ids, documents, metadatas, distances))


def run_matrix(client, output, *, roots=()):
    """Client seam is only for offline contract tests; CLI always imports Chroma."""
    output = Path(output)
    if not (output/"plan.json").is_file():
        raise ValueError("plan_must_exist_before_backend_operations")
    observer, collections = Observer(roots), {}
    rows = fixture()
    expected = {actor: {row["id"]: row for row in rows if row["actor"] == actor} for actor in ACTORS}
    for actor in ACTORS:
        made = observer.invoke("get_or_create_collection", actor, "setup", lambda actor=actor:
            {"id": str((collections.setdefault(actor, client.get_or_create_collection(name="user-memory-"+actor,
                metadata={"hnsw:space": "cosine"}, embedding_function=None))).id)})
        if made["status"] != "ok":
            return {"status": "setup_failed", "queries": [], "calls": observer.calls,
                "exception_events": observer.exception_events, "trace_overflow": observer.trace_overflow}
        values = list(expected[actor].values())
        written = observer.invoke("upsert", actor, "setup", lambda actor=actor, values=values: collections[actor].upsert(
            ids=[r["id"] for r in values], documents=[r["document"] for r in values],
            metadatas=[r["metadata"] for r in values], embeddings=[vector(r["vector_seed"]) for r in values]))
        if written["status"] != "ok":
            return {"status": "setup_failed", "queries": [], "calls": observer.calls,
                "exception_events": observer.exception_events, "trace_overflow": observer.trace_overflow}
    observations = []
    deleted = False
    for entry in schedule():
        if entry["phase"] == "after_delete" and not deleted:
            for actor in ("owner", "assistant"):
                rid = "main-"+actor
                deletion = observer.invoke("delete", actor, "delete_main_copy", lambda actor=actor, rid=rid:
                    collections[actor].delete(ids=[rid]))
                # Expected inventory follows the predeclared desired deletion even when native deletion fails.
                del expected[actor][rid]
            deleted = True
        actor, stage = entry["actor"], entry["phase"]+"_round_"+str(entry["round"])
        count = observer.invoke("count", actor, stage, lambda actor=actor: collections[actor].count())
        inventory = observer.invoke("get", actor, stage, lambda actor=actor:
            collections[actor].get(include=["documents", "metadatas"]))
        query = observer.invoke("query", actor, stage, lambda actor=actor:
            collections[actor].query(query_embeddings=[vector(41)], n_results=QUERY_LIMIT, where=None))
        current_ids = inventory.get("result", {}).get("ids") if inventory["status"] == "ok" else None
        control_ok = count["status"] == "ok" and type(count.get("result")) is int and count["result"] == len(expected[actor])
        control_ok = bool(control_ok and isinstance(current_ids, list) and len(current_ids) == len(set(current_ids))
            and set(current_ids) == set(expected[actor]))
        observation = {**entry, "collection_name": "user-memory-"+actor, "collection_id": str(collections[actor].id),
            "query_vector": vector_stats(vector(41)), "expected_ids": sorted(expected[actor]),
            "count": count, "get": inventory, "native_query": query,
            "count_get_positive_passed": control_ok,
            "query_complete_passed": query["status"] == "ok" and validate_query(query.get("result"), expected[actor])}
        observation["passed"] = observation["count_get_positive_passed"] and observation["query_complete_passed"]
        observations.append(observation)
        save(output/"queries.json", observations)
        save(output/"calls.json", observer.calls)
        save(output/"exception_events.json", observer.exception_events)
    return {"status": "completed", "queries": observations, "calls": observer.calls,
        "exception_events": observer.exception_events, "trace_overflow": observer.trace_overflow}


def source_inventory():
    distribution = importlib.metadata.distribution("chromadb")
    root = Path(distribution.locate_file(""))
    names = ["chromadb/api/client.py", "chromadb/api/models/Collection.py", "chromadb/api/models/CollectionCommon.py",
        "chromadb/api/rust.py", "chromadb/config.py"]
    paths = [root/name for name in names]
    paths += sorted((root/"chromadb_rust_bindings").glob("*.pyd"))
    if not paths or any(not path.is_file() for path in paths):
        raise ValueError("native_source_inventory_missing")
    return root, {str(path.resolve()): sha_file(path) for path in paths}


def run(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    isolate_environment(output)
    guard = NetworkGuard()
    sys.addaudithook(guard)
    installed_version = importlib.metadata.version("chromadb")
    root, sources = source_inventory()
    own_paths = (Path(__file__).resolve(), Path(__file__).with_name("native_exact_fact_common.py").resolve())
    own_hashes = {str(path): sha_file(path) for path in own_paths}
    archive = output/"implementation"
    archive.mkdir()
    for path in own_paths:
        shutil.copyfile(path, archive/path.name)
        if sha_file(archive/path.name) != own_hashes[str(path)]:
            raise ValueError("code_archive_hash_mismatch")
    plan = {"version": VERSION, "runtime": {"python": sys.executable, "python_version": platform.python_version(),
        "chromadb": installed_version, "required_chromadb": "1.5.9", "platform": platform.platform()},
        "source_sha256": sources, "own_source_sha256": own_hashes, "protocol": {"queries": MAX_QUERIES,
            "schedule": schedule(), "dimensions": DIMENSIONS, "n_results": QUERY_LIMIT,
            "initial_sizes": {"owner": 2, "assistant": 3, "outsider": 1}, "final_sizes": {"owner": 1, "assistant": 2, "outsider": 1},
            "delete_ids": ["main-owner", "main-assistant"], "retry": False, "query_threshold": "none in direct Chroma API",
            "space": "cosine", "upserts": 3, "deletes": 2, "count_get_pairs": MAX_QUERIES,
            "query_vector": vector_stats(vector(41)), "generation_calls": 0, "embedding_model_calls": 0,
            "network": "no endpoint allowed; loopback capability probes/stdlib socketpair only"},
        "fixture": fixture(), "record_vector_stats": {row["id"]: vector_stats(vector(row["vector_seed"])) for row in fixture()},
        "scope": "fresh pure Chroma synthetic-vector diagnosis, not a WebUI or migration acceptance rerun"}
    save(output/"plan.json", plan)  # Must precede third-party import, client creation and all storage operations.
    report = {"version": VERSION, "status": "failed", "queries": [], "calls": [], "exception_events": []}
    try:
        if installed_version != "1.5.9":
            raise ValueError("chromadb_version_not_pinned")
        if any(name == prefix or name.startswith(prefix+".") for name in sys.modules for prefix in FORBIDDEN_MODULES):
            raise ValueError("forbidden_model_or_application_already_loaded")
        import chromadb
        from chromadb.config import Settings
        client = chromadb.PersistentClient(path=str(output/"chroma"), settings=Settings(anonymized_telemetry=False, allow_reset=False))
        report = {"version": VERSION, **run_matrix(client, output, roots=(root/"chromadb", root/"chromadb_rust_bindings"))}
    except Exception as error:
        report["fatal_error"] = exception_record(error)
    report["generation_calls"] = report["embedding_model_calls"] = report["paid_api_calls"] = 0
    report["forbidden_loaded_modules"] = sorted(name for name in sys.modules
        if any(name == prefix or name.startswith(prefix+".") for prefix in FORBIDDEN_MODULES))
    report["network_events"] = list(guard.events)
    report["own_source_unchanged"] = all(sha_file(path) == value for path, value in own_hashes.items())
    report["source_unchanged"] = all(sha_file(path) == value for path, value in sources.items())
    report["query_attempts"] = sum(row["operation"] == "query" for row in report["calls"])
    report["queries_passed"] = sum(row["passed"] for row in report["queries"])
    report["native_exception_queries"] = sum(row["native_query"]["status"] == "error" for row in report["queries"])
    report["null_queries"] = sum(row["native_query"]["status"] == "ok" and row["native_query"].get("result") is None for row in report["queries"])
    report["protocol_passed"] = (report["status"] == "completed" and report["query_attempts"] == MAX_QUERIES
        and len(report["queries"]) == MAX_QUERIES and not report["forbidden_loaded_modules"]
        and not report.get("trace_overflow", False) and report["own_source_unchanged"] and report["source_unchanged"]
        and not any(event.get("allowed") is not True for event in guard.events))
    report["functional_observations_passed"] = report["queries_passed"] == MAX_QUERIES
    report["interpretation"] = "pure_chroma_failure_reproduced" if report["queries_passed"] < MAX_QUERIES else "pure_chroma_failure_not_reproduced_in_fixed_12_queries"
    save(output/"report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.output)
    print(json.dumps({key: report[key] for key in ("status", "protocol_passed", "query_attempts", "queries_passed",
        "native_exception_queries", "null_queries", "interpretation", "generation_calls", "embedding_model_calls")}, ensure_ascii=False))
    raise SystemExit(0 if report["protocol_passed"] else 1)


if __name__ == "__main__":
    main()
