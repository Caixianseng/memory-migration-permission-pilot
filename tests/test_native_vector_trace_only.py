"""Offline contracts for trace-only observation and scoped launcher injection."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import native_vector_trace_only_worker as worker
from scripts import run_native_vector_trace_only as launcher


class FakeBackend:
    def __init__(self, fail=False, escaping=False):
        self.calls, self.fail, self.escaping = 0, fail, escaping
        self.value = object()
    @property
    def client(self):
        raise AssertionError("trace-only must not access native client/count/get")
    def search(self, collection_name, vectors, filter=None, limit=10):
        self.calls += 1
        if self.escaping:
            raise KeyboardInterrupt("synthetic outward exception")
        try:
            if self.fail:
                raise RuntimeError("synthetic native error, never persist message text")
            return self.value
        except Exception:
            return None


class NativeVectorTraceOnlyContracts(unittest.TestCase):
    def make(self, backend):
        return worker.TraceOnlySearch(backend.search, {"owner": "native-owner"},
            lambda: {"snapshot_ordinal": 2, "snapshot_name": "before_revoke", "native_request_index": 35})

    def test_original_once_unchanged_identity_no_native_reads_and_trace_restored(self):
        backend = FakeBackend()
        observer = self.make(backend)
        previous = sys.gettrace()
        result = observer("user-memory-native-owner", [[0.0]*384], None, 100)
        self.assertIs(result, backend.value)
        self.assertEqual(backend.calls, 1)
        self.assertIs(sys.gettrace(), previous)
        self.assertTrue(observer.calls[0]["trace_restored"])
        self.assertEqual(observer.calls[0]["actor"], "owner")
        self.assertEqual(observer.calls[0]["exception_events"], [])

    def test_swallowed_error_is_observed_without_repair_or_message_text(self):
        backend = FakeBackend(fail=True)
        observer = self.make(backend)
        self.assertIsNone(observer("user-memory-native-owner", [[0.0]*384], None, 100))
        self.assertEqual(backend.calls, 1)
        row = observer.calls[0]
        self.assertEqual(row["return_kind"], "none")
        self.assertEqual(len(row["exception_events"]), 1)
        error = row["exception_events"][0]
        self.assertEqual(error["class"], "builtins.RuntimeError")
        self.assertEqual(error["message_sha256"], hashlib.sha256(b"synthetic native error, never persist message text").hexdigest())
        self.assertNotIn("message", error)
        self.assertNotIn("locals", json.dumps(row))
        self.assertNotIn("synthetic native error", json.dumps(row))

    def test_outward_baseexception_is_not_converted_to_none_and_trace_restores(self):
        backend = FakeBackend(escaping=True)
        observer = self.make(backend)
        previous = sys.gettrace()
        with self.assertRaises(KeyboardInterrupt):
            observer("user-memory-native-owner", [[0.0]*384], None, 100)
        self.assertIs(sys.gettrace(), previous)
        self.assertEqual(backend.calls, 1)
        self.assertEqual(observer.calls[0]["outward_exception"]["class"], "builtins.KeyboardInterrupt")

    def test_unknown_collection_actor_is_not_inferred_from_vectors_or_data(self):
        observer = self.make(FakeBackend())
        observer("user-memory-someone-else", [[0.0]*384], None, 100)
        self.assertIsNone(observer.calls[0]["actor"])

    def test_known_native_error_markers_without_storing_credentials_or_message(self):
        error = worker.error_metadata(RuntimeError("Error executing plan: Error finding id; Bearer SECRET.JWT.VALUE; token=password"))
        self.assertEqual(error["known_message_markers"], ["plan_execution", "index_id_lookup"])
        self.assertNotIn("SECRET", json.dumps(error))
        self.assertNotIn("password", json.dumps(error))
        self.assertNotIn("message", error)
        dims = worker.error_metadata(ValueError("Expected embedding dimension of 384, got 1024"))
        self.assertEqual(dims["dimension_numbers"], [384, 1024])

    def test_launcher_plan_and_extra_archive_precede_scoped_target_only_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/"new-run"
            constructed = []
            def fake_factory(python, script, args, *, timeout=300):
                plan = json.loads((output/"trace_plan.json").read_text(encoding="utf-8"))
                self.assertEqual(len(plan["extra_code_archive"]), 2)
                for entry in plan["extra_code_archive"].values():
                    self.assertTrue((output/"trace_implementation"/entry["archive_path"]).is_file())
                constructed.append((str(script), list(args)))
                return object()
            def fake_run(standard, **kwargs):
                self.assertTrue((output/"trace_plan.json").is_file())
                self.assertEqual(Path(standard), output/"standard_run")
                original_source = launcher.PROJECT/"scripts/native_exact_fact_source.py"
                original_target = launcher.PROJECT/"scripts/native_exact_fact_target.py"
                launcher.bridge.WorkerRPC(kwargs["python"], original_source, ["--state", "source"], timeout=3)
                launcher.bridge.WorkerRPC(kwargs["python"], original_target, ["--state", "target"], timeout=3)
                return {"status": "passed", "checks": [{"passed": True} for _ in range(29)],
                    "source_final": {"mem0_embedding_method_invocations": 2, "generation_attempts": 0, "network_events": []},
                    "target_final": {"native_embedding_function_invocations": 21, "generation_attempts": 0, "network_events": [],
                        "trace_only": {"snapshot_calls": 6, "original_search_calls": 15, "observer_errors": [],
                            "observations": [{"original_calls": 1, "trace_restored": True, "return_kind": "SearchResult", "exception_events": []} for _ in range(15)]}},
                    **{name: {"status": "passed"} for name in ("code_postflight", "archive_postflight", "asset_postflight", "sdk_inventory_preflight")}}
            with (patch.object(launcher.bridge, "WorkerRPC", side_effect=fake_factory) as original,
                    patch.object(launcher.bridge, "run", side_effect=fake_run)):
                result = launcher.run(output, python=Path("fake-python"), sdk_root=Path("fake-sdk"),
                    legacy_project=launcher.PROJECT/"memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
                self.assertIs(launcher.bridge.WorkerRPC, original)
            self.assertEqual(Path(constructed[0][0]).name, "native_exact_fact_source.py")
            self.assertEqual(Path(constructed[1][0]).name, "native_vector_trace_only_worker.py")
            self.assertEqual(constructed[0][1], ["--state", "source"])
            self.assertEqual(constructed[1][1], ["--state", "target"])
            self.assertTrue(result["instrumentation_protocol_passed"])
            self.assertTrue(result["factory_restored"])
            self.assertEqual(len(result["injection_spawns"]), 2)


if __name__ == "__main__":
    unittest.main()
