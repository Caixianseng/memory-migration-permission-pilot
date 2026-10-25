"""Trace-only subclass: unchanged native RPC sequence, no extra storage reads."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import inspect
from pathlib import Path
import re
import sys
import threading
import time
import traceback

if __package__:
    from .native_exact_fact_target import TargetWorker
    from .native_exact_fact_common import serve_commands
else:
    from native_exact_fact_target import TargetWorker
    from native_exact_fact_common import serve_commands

SNAPSHOTS = ("before_writes", "before_revoke", "export_disabled_existing_copies_retained",
    "revoked_before_target_cleanup", "after_cleanup", "after_old_job_replay")


def error_metadata(error):
    """No message text, locals, credentials or token values are collected."""
    text = str(error)
    message = text.encode("utf-8", errors="replace")
    lower = text.lower()
    templates = {"contiguous_2d_results": "contiguous 2d array", "plan_execution": "error executing plan",
        "index_id_lookup": "error finding id", "native_panic": "panic", "database_locked": "database is locked",
        "dimension_mismatch": "embedding dimension", "collection_missing": "collection does not exist"}
    codes = [code for code, needle in templates.items() if needle in lower]
    dimensions = re.search(r"expected embedding dimension(?: of)?\s+(\d{1,5})\D{1,12}got\s+(\d{1,5})", lower)
    return {"class": type(error).__module__+"."+type(error).__name__,
        "message_sha256": hashlib.sha256(message).hexdigest(), "message_bytes": len(message),
        "known_message_markers": codes, "dimension_numbers": list(map(int, dimensions.groups())) if dimensions else None,
        "stack": [{"file": frame.filename, "line": frame.lineno, "function": frame.name}
            for frame in traceback.extract_tb(error.__traceback__)[-12:]]}


class TraceOnlySearch:
    def __init__(self, original, identity_mapping, stage_provider):
        self.original, self.code = original, original.__code__
        self.signature = inspect.signature(original)
        self.actors = {"user-memory-"+native_id: actor for actor, native_id in identity_mapping.items()}
        self.stage_provider = stage_provider
        self.calls, self.original_calls, self.observer_errors = [], 0, []

    def __call__(self, *args, **kwargs):
        row = {"stage": deepcopy(self.stage_provider()), "thread_id": threading.get_ident(),
            "started_ns": time.perf_counter_ns(), "exception_events": [], "original_calls": 0}
        try:
            bound = self.signature.bind(*args, **kwargs)
            collection_name = bound.arguments["collection_name"]
            row.update(collection_name=collection_name, actor=self.actors.get(collection_name))
        except Exception as error:
            row["binding_observation_error"] = error_metadata(error)
        previous = sys.gettrace()
        def trace(frame, event, arg):
            if frame.f_code is self.code and event == "exception":
                try:
                    _, error, _ = arg
                    row["exception_events"].append({**error_metadata(error), "file": frame.f_code.co_filename,
                        "line": frame.f_lineno, "function": frame.f_code.co_name, "stage": deepcopy(row["stage"])})
                except BaseException as error:
                    self.observer_errors.append(type(error).__name__)
            return trace
        try:
            sys.settrace(trace)
            self.original_calls += 1
            row["original_calls"] += 1
            result = self.original(*args, **kwargs)
            # Only classification of the existing return object; no backend read or conversion.
            row["return_kind"] = "none" if result is None else type(result).__name__
            return result
        except BaseException as error:
            row["outward_exception"] = error_metadata(error)
            raise
        finally:
            sys.settrace(previous)
            row.update(finished_ns=time.perf_counter_ns(), trace_restored=sys.gettrace() is previous)
            self.calls.append(row)


class TraceOnlyTargetWorker(TargetWorker):
    def initialize(self, data):
        result = super().initialize(data)
        if importlib.metadata.version("chromadb") != "1.5.9":
            raise ValueError("trace_only_chromadb_not_pinned")
        from open_webui.retrieval.vector.factory import get_vector_db_client
        backend = get_vector_db_client()
        if type(backend).__module__ != "open_webui.retrieval.vector.dbs.chroma" or type(backend).__name__ != "ChromaClient":
            raise ValueError("trace_only_backend_not_native_chroma")
        self.snapshot_ordinal = 0
        def stage():
            ordinal = self.snapshot_ordinal
            return {"snapshot_ordinal": ordinal, "snapshot_name": SNAPSHOTS[ordinal-1] if 1 <= ordinal <= len(SNAPSHOTS) else "unexpected",
                "native_request_index": len(self.recorder.requests)}
        self.trace_only = TraceOnlySearch(backend.search, result["native_user_ids"], stage)
        backend.search = self.trace_only
        code_file = Path(self.trace_only.code.co_filename)
        result["trace_only_observation"] = {"version": "same_sequence_search_exception_trace_v1",
            "chromadb": "1.5.9", "original_file": str(code_file),
            "original_file_sha256": hashlib.sha256(code_file.read_bytes()).hexdigest(),
            "original_qualname": self.trace_only.original.__qualname__, "original_first_line": self.trace_only.code.co_firstlineno,
            "extra_native_reads": 0, "original_calls_per_search": 1, "message_text_persisted": False}
        return result

    def __call__(self, command, data):
        if command == "snapshot" and hasattr(self, "trace_only"):
            self.snapshot_ordinal += 1
        return super().__call__(command, data)

    def summary(self):
        result = super().summary()
        if hasattr(self, "trace_only"):
            result["trace_only"] = {"snapshot_calls": self.snapshot_ordinal,
                "original_search_calls": self.trace_only.original_calls, "observations": deepcopy(self.trace_only.calls),
                "observer_errors": list(self.trace_only.observer_errors), "extra_native_reads": 0}
        return result


def main():
    parser = argparse.ArgumentParser()
    for name in ("state", "assets", "legacy-project"):
        parser.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    serve_commands(TraceOnlyTargetWorker(state=args.state, assets=args.assets, legacy_project=args.legacy_project))


if __name__ == "__main__":
    main()
