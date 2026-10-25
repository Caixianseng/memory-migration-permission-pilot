"""Fresh native target for one fixed-input timing arm, no count/get or retry."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import inspect
from pathlib import Path
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from scripts.native_exact_fact_target import TargetWorker, SEMANTIC_QUERY
from scripts.native_exact_fact_common import serve_commands
from scripts.native_vector_trace_only_worker import TraceOnlySearch
from scripts.native_vector_null_target_worker import numeric_stats, LOGICAL_ACTORS


class TimingSearch(TraceOnlySearch):
    def __call__(self, *args, **kwargs):
        values = self.signature.bind(*args, **kwargs)
        values.apply_defaults()
        params = values.arguments
        vectors = numeric_stats(params["vectors"])
        before = len(self.calls)
        try:
            return super().__call__(*args, **kwargs)
        finally:
            if len(self.calls) == before + 1:
                self.calls[-1].update(query_vectors=vectors, limit=params.get("limit"), filter=params.get("filter"))


class TimingTargetWorker(TargetWorker):
    def initialize(self, data):
        result = super().initialize(data)
        if importlib.metadata.version("chromadb") != "1.5.9":
            raise ValueError("timing_chromadb_version_changed")
        from open_webui.retrieval.vector.factory import get_vector_db_client
        backend = get_vector_db_client()
        if type(backend).__module__ != "open_webui.retrieval.vector.dbs.chroma":
            raise ValueError("timing_backend_changed")
        self.timing_stage = None
        self.search_trace = TimingSearch(backend.search, result["native_user_ids"], lambda: deepcopy(self.timing_stage))
        backend.search = self.search_trace
        original = backend.upsert
        signature = inspect.signature(original)
        self.upserts, self.writes, self.query_attempts = [], {}, 0
        def observed_upsert(*args, **kwargs):
            params = signature.bind(*args, **kwargs).arguments
            items = params["items"]
            row = {"collection_name": params["collection_name"], "started_ns": time.perf_counter_ns(),
                   "text_sha256": [hashlib.sha256(x["text"].encode()).hexdigest() for x in items],
                   "vectors": numeric_stats([x["vector"] for x in items]), "original_calls": 0}
            try:
                row["original_calls"] = 1
                value = original(*args, **kwargs)
                row["returned"] = True
                return value
            finally:
                row["finished_ns"] = time.perf_counter_ns()
                self.upserts.append(row)
        backend.upsert = observed_upsert
        async def threshold():
            from open_webui.models.config import Config
            return await Config.get("rag.relevance_threshold", 0.0)
        self.relevance_threshold = self.client.portal.call(threshold)
        if self.relevance_threshold != 0:
            raise ValueError("timing_relevance_threshold_changed")
        result.update(timing_contract={"max_queries": 1, "max_writes": 6, "max_embeddings": 7,
            "query": SEMANTIC_QUERY, "k": 100, "threshold": self.relevance_threshold,
            "extra_vector_count_get": 0, "search_original_calls": 1, "return_and_exception_unchanged": True,
            "original_search_sha256": hashlib.sha256(Path(self.search_trace.code.co_filename).read_bytes()).hexdigest()})
        return result

    def __call__(self, command, data):
        if command in {"init", "close"}:
            return super().__call__(command, data)
        if command == "timing_add":
            if (set(data) != {"logical_id", "actor", "text", "path"} or
                LOGICAL_ACTORS.get(data["logical_id"]) != data["actor"] or data["logical_id"] in self.writes or
                len(self.writes) >= 6 or self.query_attempts or self.embedding_invocations >= 7):
                raise ValueError("timing_write_scope_invalid")
            from memory_migration_study.native_webui import _insert_memory
            rid = _insert_memory(self.recorder, data["actor"], self.identities[data["actor"]]["id"], data["text"], data["path"])
            native = __import__("json").loads(self.recorder.requests[-1]["native_raw_body"])
            native_item = {k:native[k] for k in ("id","content","path","type","created_at","updated_at")}
            if native_item["id"] != rid or native_item["type"] != "context" or any(type(native_item[k]) is not int for k in ("created_at","updated_at")):
                raise ValueError("timing_native_write_metadata_invalid")
            self.writes[data["logical_id"]] = {**deepcopy(data), "target_id": rid,"native_item":native_item}
            return deepcopy(self.writes[data["logical_id"]])
        if command == "timing_query":
            if (set(data) != {"pair", "actor", "arm"} or data["actor"] not in {"owner","assistant","outsider"} or
                data["arm"] not in {"immediate","delay500"} or type(data["pair"]) is not int or
                not 0 <= data["pair"] < 6 or self.query_attempts or len(self.writes) != 6 or len(self.upserts) != 6):
                raise ValueError("timing_query_scope_invalid")
            self.query_attempts += 1
            self.timing_stage = deepcopy(data)
            scheduled = time.perf_counter_ns()
            if data["arm"] == "delay500":
                time.sleep(0.5)
            started = time.perf_counter_ns()
            before = self.embedding_invocations
            response, trace = self.recorder.request("POST", "/api/v1/memories/query", actor_id=data["actor"],
                                                   payload={"content": SEMANTIC_QUERY, "k": 100})
            try:
                value = response.json() if response is not None else None
            except (TypeError, ValueError):
                value = None
            return {**data, "scheduled_ns": scheduled, "http_started_ns": started,
                "http_finished_ns": time.perf_counter_ns(), "last_upsert_finished_ns": self.upserts[-1]["finished_ns"],
                "embedding_delta": self.embedding_invocations-before, "trace": deepcopy(self.search_trace.calls),
                "semantic_row": {"actor":data["actor"],"operation":"semantic","query":SEMANTIC_QUERY,"k":100,
                    "status":trace["status"],"vector_result":value,"response_checked":trace.get("response_checked"),
                    "execution_error":trace.get("execution_error"),"native_body_sha256":trace.get("native_body_sha256"),
                    "native_raw_body":trace.get("native_raw_body")}}
        raise ValueError("timing_command_not_allowed")

    def summary(self):
        result = super().summary()
        if hasattr(self, "search_trace"):
            result["timing"] = {"upserts":deepcopy(self.upserts),"writes":deepcopy(self.writes),
                "query_attempts":self.query_attempts,"search_calls":self.search_trace.original_calls,
                "search_observations":deepcopy(self.search_trace.calls),"observer_errors":list(self.search_trace.observer_errors)}
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("state", "assets", "legacy-project"):
        parser.add_argument("--"+name, type=Path, required=True)
    args = parser.parse_args()
    serve_commands(TimingTargetWorker(state=args.state, assets=args.assets, legacy_project=args.legacy_project))
