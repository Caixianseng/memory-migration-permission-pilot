"""Fake-only search tracing and raw-response contracts; no app/model loads."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import native_vector_null_target_worker as worker
from scripts import probe_native_vector_null_target as launcher


class FakeCollection:
    id, name, tenant, database = "collection-1", "user-memory-native-owner", "default_tenant", "default_database"
    def count(self):
        return 1
    def get(self, **kwargs):
        return {"ids": ["own-memory"], "documents": ["resident\nOwn value"], "metadatas": [{}]}


class FakeNativeClient:
    def get_collection(self, *, name, embedding_function):
        return FakeCollection()


class CatchingBackend:
    def __init__(self, fail=False):
        self.client, self.calls, self.fail = FakeNativeClient(), 0, fail
    def search(self, collection_name, vectors, filter=None, limit=10):
        self.calls += 1
        try:
            if self.fail:
                raise RuntimeError("synthetic swallowed backend exception")
            return {"ids": [["own-memory"]]}
        except Exception:
            return None


class RaisingBackend(CatchingBackend):
    def search(self, collection_name, vectors, filter=None, limit=10):
        self.calls += 1
        raise ValueError("synthetic escaping backend exception")


class NativeVectorNullTargetContracts(unittest.TestCase):
    def observer(self, backend):
        result = worker.SearchObserver(backend, {"owner": "native-owner"})
        result.stage = {"actor": "owner", "phase": "before_delete", "round": 1}
        return result

    def test_swallowed_exception_is_captured_from_exact_original_code_and_none_is_unchanged(self):
        backend = CatchingBackend(fail=True)
        observer = self.observer(backend)
        previous = sys.gettrace()
        with patch.object(worker, "numeric_stats", return_value={"dtype": "float64", "shape": [1, 384], "finite": True}):
            result = observer("user-memory-native-owner", [[0.0]*384], None, 100)
        self.assertIsNone(result)
        self.assertIs(sys.gettrace(), previous)
        self.assertEqual(backend.calls, 1)
        self.assertEqual(observer.original_calls, 1)
        row = observer.observations[0]
        self.assertEqual(row["original_calls"], 1)
        self.assertEqual(row["output"], {"kind": "none", "value": None})
        self.assertTrue(row["trace_restored"])
        self.assertEqual(row["input"]["actor_from_verified_native_identity"], "owner")
        self.assertEqual(len(row["exception_events"]), 1)
        event = row["exception_events"][0]
        self.assertEqual(event["class"], "builtins.RuntimeError")
        self.assertEqual(event["function"], "search")
        self.assertEqual(len(event["message_sha256"]), 64)
        self.assertEqual(event["stage"], observer.stage)
        self.assertNotIn("locals", json.dumps(row))

    def test_original_success_and_escaping_exception_are_not_changed(self):
        for backend in (CatchingBackend(), RaisingBackend()):
            observer = self.observer(backend)
            previous = sys.gettrace()
            with patch.object(worker, "numeric_stats", return_value={"shape": [1, 384]}):
                if isinstance(backend, RaisingBackend):
                    with self.assertRaisesRegex(ValueError, "synthetic escaping"):
                        observer("user-memory-native-owner", [[0.0]*384], None, 100)
                else:
                    self.assertEqual(observer("user-memory-native-owner", [[0.0]*384], None, 100), {"ids": [["own-memory"]]})
            self.assertIs(sys.gettrace(), previous)
            self.assertEqual(backend.calls, 1)
            self.assertEqual(len(observer.observations), 1)

    def test_metadata_observer_failure_does_not_replace_original_or_guess_actor_from_data(self):
        backend = CatchingBackend()
        observer = self.observer(backend)
        with patch.object(worker, "numeric_stats", side_effect=ValueError("metadata observer failure")):
            result = observer("user-memory-unregistered", [[0.0]*384], None, 100)
        self.assertEqual(result, {"ids": [["own-memory"]]})
        self.assertEqual(backend.calls, 1)
        self.assertIn("observation_error", observer.observations[0])
        self.assertNotIn("owner", observer.observations[0].get("input", {}))

    def test_retry_and_wrong_logical_actor_are_rejected_before_any_native_import(self):
        instance = object.__new__(worker.ObservedTargetWorker)
        instance.search_observer = object()
        instance.embedding_invocations = 0
        instance.diagnostic_queries = {("before_delete", 1, "owner")}
        instance.diagnostic_records = {}
        with self.assertRaisesRegex(ValueError, "no_retry"):
            instance("diagnostic_query", {"actor": "owner", "phase": "before_delete", "round": 1})
        with self.assertRaisesRegex(ValueError, "diagnostic_write_invalid"):
            instance("diagnostic_add", {"logical_id": "main-owner", "actor": "outsider", "text": "data", "path": "/data"})
        instance.embedding_invocations = 18
        with self.assertRaisesRegex(ValueError, "embedding_budget_exhausted"):
            instance("diagnostic_query", {"actor": "owner", "phase": "before_delete", "round": 1})

    def test_fixture_projection_copies_only_six_prior_target_inputs_not_source(self):
        original = {"sidecar": {"main": {"record_id": "r-main"}, "valid_control": {"record_id": "r-valid"}},
            "target_rpc_receipts": [{"command": "add", "input": {"actor": actor, "text": text, "path": path}}
                for actor, text, path in (("owner", "Main fact", "/exact-fact/r-main"),
                    ("assistant", "Main fact", "/exact-fact/r-main"), ("assistant", "Control", "/exact-fact/r-valid"))],
            "resident_controls": [{"actor": actor, "content": "Own "+actor, "path": "/resident-control/"+actor} for actor in launcher.ACTORS],
            "trusted_fixture": {"source_only_canary": "DO-NOT-PROJECT", "source": "full source DO-NOT-PROJECT"}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"fixture.json"
            path.write_text(json.dumps(original), encoding="utf-8")
            result = launcher.load_fixture(path)
        self.assertEqual(len(result), 6)
        self.assertEqual({actor: sum(r["actor"] == actor for r in result) for actor in launcher.ACTORS},
            {"owner": 2, "assistant": 3, "outsider": 1})
        self.assertNotIn("DO-NOT-PROJECT", json.dumps(result))

    def test_null_raw_is_preserved_as_failure_despite_valid_sql_and_instrumentation(self):
        item = {"id": "id", "content": "Own value", "path": "resident", "type": "context", "created_at": 1, "updated_at": 1}
        row = {"actor": "owner", "phase": "before_delete", "round": 1,
            "native_list": {"status": 200, "response_checked": True, "execution_error": None, "native_raw_body": json.dumps([item])},
            "semantic_row": {"actor": "owner", "operation": "semantic", "query": "Customer service and delivery status.", "k": 100,
                "status": 200, "response_checked": True, "execution_error": None, "vector_result": None,
                "native_raw_body": "null", "native_body_sha256": hashlib.sha256(b"null").hexdigest()},
            "adapter_observations": [{"stage": {"actor": "owner", "phase": "before_delete", "round": 1},
                "original_calls": 1, "trace_restored": True, "input": {"actor_from_verified_native_identity": "owner", "limit": 100,
                    "filter": None, "query_vectors": {"shape": [1, 384], "finite": True}}, "count_get": {"count": 1, "get": {"ids": ["id"]}}}]}
        result = launcher.score_observation(row, {"id"}, {"id": {"text": "Own value", "path": "/resident"}})
        self.assertTrue(result["instrumentation_passed"])
        self.assertTrue(result["native_sql_control_passed"])
        self.assertTrue(result["null_response"])
        self.assertFalse(result["native_semantic_complete_passed"])
        self.assertFalse(result["passed"])
        self.assertEqual(row["semantic_row"]["native_raw_body"], "null")
        self.assertEqual(len(launcher.matrix_schedule()), 12)


if __name__ == "__main__":
    unittest.main()
