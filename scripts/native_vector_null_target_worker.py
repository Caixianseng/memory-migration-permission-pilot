"""New target-only observer; existing native TargetWorker stays unchanged."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import inspect
from pathlib import Path
import sys
import threading
import time

if __package__:
    from .native_exact_fact_target import TargetWorker, SEMANTIC_QUERY
    from .native_exact_fact_common import serve_commands
    from .probe_native_vector_null import plain, exception_record
else:
    from native_exact_fact_target import TargetWorker, SEMANTIC_QUERY
    from native_exact_fact_common import serve_commands
    from probe_native_vector_null import plain, exception_record

MAX_QUERY = 12
MAX_EMBEDDING = 18
ACTORS = ("owner", "assistant", "outsider")
LOGICAL_ACTORS = {"main-owner": "owner", "main-assistant": "assistant", "valid-assistant": "assistant",
    "resident-owner": "owner", "resident-assistant": "assistant", "resident-outsider": "outsider"}


def numeric_stats(vectors):
    import numpy as np
    array = np.asarray(vectors)
    finite = bool(np.isfinite(array).all())
    return {"dtype": str(array.dtype), "shape": list(array.shape), "finite": finite,
        "l2_norm": float(np.linalg.norm(array)) if finite else None,
        "sha256": hashlib.sha256(array.tobytes(order="C")).hexdigest()}


class SearchObserver:
    """Read-only metadata plus original search exactly once, in its real thread."""
    def __init__(self, backend, identity_mapping):
        self.backend, self.original = backend, backend.search
        self.original_code = self.original.__code__
        self.signature = inspect.signature(self.original)
        self.actor_by_collection = {"user-memory-"+value: actor for actor, value in identity_mapping.items()}
        self.stage, self.observations, self.original_calls = None, [], 0
        self.observation_failures = []

    def __call__(self, *args, **kwargs):
        stage = deepcopy(self.stage)
        record = {"stage": stage, "thread_id": threading.get_ident(), "exception_events": [],
            "original_calls": 0, "started_ns": time.perf_counter_ns()}
        try:
            values = self.signature.bind(*args, **kwargs)
            values.apply_defaults()
            call = values.arguments
            collection_name = call["collection_name"]
            record["input"] = {"collection_name": collection_name,
                "actor_from_verified_native_identity": self.actor_by_collection.get(collection_name),
                "limit": call.get("limit"), "filter": plain(call.get("filter")),
                "query_vectors": numeric_stats(call["vectors"])}
            collection = self.backend.client.get_collection(name=collection_name, embedding_function=None)
            record["collection"] = {"id": str(collection.id), "name": collection.name,
                "tenant": getattr(collection, "tenant", None), "database": getattr(collection, "database", None)}
            record["count_get"] = {"count": collection.count(),
                "get": plain(collection.get(include=["documents", "metadatas"]))}
        except Exception as error:
            record["observation_error"] = exception_record(error)
        previous = sys.gettrace()
        def trace(frame, event, argument):
            if frame.f_code is self.original_code and event == "exception":
                try:
                    _, error, _ = argument
                    record["exception_events"].append({**exception_record(error),
                        "file": frame.f_code.co_filename, "line": frame.f_lineno,
                        "function": frame.f_code.co_name, "stage": stage})
                except BaseException as observer_error:
                    self.observation_failures.append(type(observer_error).__name__)
            return trace
        result = None
        try:
            sys.settrace(trace)
            self.original_calls += 1
            record["original_calls"] += 1
            result = self.original(*args, **kwargs)
        except BaseException as error:
            record["original_raised"] = exception_record(error)
            raise  # Preserve the original call's outward exception semantics.
        finally:
            sys.settrace(previous)
            try:
                value = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
                record["output"] = {"kind": "none" if result is None else type(result).__name__, "value": plain(value)}
            except Exception as error:
                record["output_observation_error"] = exception_record(error)
            record.update(finished_ns=time.perf_counter_ns(), trace_restored=sys.gettrace() is previous)
            self.observations.append(record)
        return result


class ObservedTargetWorker(TargetWorker):
    def initialize(self, data):
        result = super().initialize(data)
        if importlib.metadata.version("chromadb") != "1.5.9":
            raise ValueError("diagnostic_chromadb_not_pinned")
        from open_webui.retrieval.vector.factory import get_vector_db_client
        backend = get_vector_db_client()
        if type(backend).__module__ != "open_webui.retrieval.vector.dbs.chroma" or type(backend).__name__ != "ChromaClient":
            raise ValueError("diagnostic_backend_not_native_chroma")
        self.search_observer = SearchObserver(backend, result["native_user_ids"])
        backend.search = self.search_observer
        self.diagnostic_records, self.diagnostic_queries = {}, set()
        result["diagnostic_observation"] = {"version": "target_only_search_trace_v1", "chromadb": "1.5.9",
            "original_module": self.search_observer.original.__module__,
            "original_qualname": self.search_observer.original.__qualname__,
            "original_file": self.search_observer.original_code.co_filename,
            "original_first_line": self.search_observer.original_code.co_firstlineno,
            "original_file_sha256": hashlib.sha256(Path(self.search_observer.original_code.co_filename).read_bytes()).hexdigest(),
            "query": SEMANTIC_QUERY, "k": 100, "max_queries": MAX_QUERY, "max_embedding_invocations": MAX_EMBEDDING,
            "observability_intervention": "extra native count/get reads and per-call Python tracing; no return or except changes"}
        return result

    def __call__(self, command, data):
        if command in {"init", "close"}:
            return super().__call__(command, data)
        if not hasattr(self, "search_observer"):
            raise ValueError("diagnostic_not_initialized")
        if command in {"diagnostic_add", "diagnostic_query"} and self.embedding_invocations >= MAX_EMBEDDING:
            raise ValueError("diagnostic_embedding_budget_exhausted")
        if command == "diagnostic_add":
            if (not isinstance(data, dict) or set(data) != {"logical_id", "actor", "text", "path"}
                    or LOGICAL_ACTORS.get(data["logical_id"]) != data["actor"] or data["logical_id"] in self.diagnostic_records
                    or not isinstance(data["text"], str) or not data["text"].strip() or not isinstance(data["path"], str)):
                raise ValueError("diagnostic_write_invalid")
            from memory_migration_study.native_webui import _insert_memory
            rid = _insert_memory(self.recorder, data["actor"], self.identities[data["actor"]]["id"], data["text"], data["path"])
            record = {"target_id": rid, **deepcopy(data)}
            self.diagnostic_records[data["logical_id"]] = record
            return record
        if command == "diagnostic_delete":
            if set(data) != {"logical_id"} or data["logical_id"] not in {"main-owner", "main-assistant"}:
                raise ValueError("diagnostic_delete_invalid")
            record = self.diagnostic_records[data["logical_id"]]
            return super().__call__("delete", {"actor": record["actor"], "target_id": record["target_id"]})
        if command == "diagnostic_query":
            if (set(data) != {"actor", "phase", "round"} or data["actor"] not in ACTORS
                    or data["phase"] not in {"before_delete", "after_delete"} or type(data["round"]) is not int
                    or data["round"] not in (1, 2)):
                raise ValueError("diagnostic_query_invalid")
            identity = (data["phase"], data["round"], data["actor"])
            if identity in self.diagnostic_queries or len(self.diagnostic_queries) >= MAX_QUERY:
                raise ValueError("diagnostic_no_retry_or_extra_queries")
            self.diagnostic_queries.add(identity)
            async def threshold():
                from open_webui.models.config import Config
                return await Config.get("rag.relevance_threshold", 0.0)
            effective_threshold = self.client.portal.call(threshold)
            _, listed = self.recorder.request("GET", "/api/v1/memories/", actor_id=data["actor"])
            self.search_observer.stage = deepcopy(data)
            start = len(self.search_observer.observations)
            before = self.embedding_invocations
            response, trace = self.recorder.request("POST", "/api/v1/memories/query", actor_id=data["actor"],
                payload={"content": SEMANTIC_QUERY, "k": 100})
            try:
                value = response.json() if response is not None else None
            except (TypeError, ValueError):
                value = None
            return {**data, "effective_relevance_threshold": plain(effective_threshold), "native_list": listed,
                "semantic_row": {"actor": data["actor"], "operation": "semantic", "requested_id": None,
                    "query": SEMANTIC_QUERY, "k": 100, "status": trace["status"], "vector_result": value,
                    "response_checked": trace.get("response_checked"), "execution_error": trace.get("execution_error"),
                    "native_body_sha256": trace.get("native_body_sha256"), "native_raw_body": trace.get("native_raw_body")},
                "native_query": trace, "adapter_observations": deepcopy(self.search_observer.observations[start:]),
                "embedding_invocations_delta": self.embedding_invocations-before,
                "embedding_budget_respected": self.embedding_invocations <= MAX_EMBEDDING}
        if command == "diagnostic_report":
            return self.summary()
        raise ValueError("diagnostic_command_not_allowed")

    def summary(self):
        result = super().summary()
        if hasattr(self, "search_observer"):
            result["diagnostic"] = {"records": deepcopy(self.diagnostic_records),
                "query_attempts": len(self.diagnostic_queries), "original_search_calls": self.search_observer.original_calls,
                "adapter_observations": deepcopy(self.search_observer.observations),
                "observer_failures": list(self.search_observer.observation_failures),
                "embedding_budget_respected": self.embedding_invocations <= MAX_EMBEDDING}
        return result


def main():
    parser = argparse.ArgumentParser()
    for name in ("state", "assets", "legacy-project"):
        parser.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    serve_commands(ObservedTargetWorker(state=args.state, assets=args.assets, legacy_project=args.legacy_project))


if __name__ == "__main__":
    main()
