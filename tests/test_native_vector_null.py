"""Offline diagnostic contracts only; no Chroma imports or model execution."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import probe_native_vector_null as probe


class FakeCollection:
    def __init__(self, name, *, fail=False, drop=False):
        self.id, self.rows, self.queries = name, {}, []
        self.fail, self.drop = fail, drop
    def upsert(self, *, ids, documents, metadatas, embeddings):
        for rid, doc, meta in zip(ids, documents, metadatas):
            self.rows[rid] = {"document": doc, "metadata": deepcopy(meta)}
    def count(self):
        return len(self.rows)
    def get(self, **kwargs):
        return {"ids": list(self.rows), "documents": [r["document"] for r in self.rows.values()],
            "metadatas": [r["metadata"] for r in self.rows.values()]}
    def delete(self, *, ids):
        for rid in ids:
            del self.rows[rid]
    def query(self, *, query_embeddings, n_results, where):
        self.queries.append({"n_results": n_results, "where": where, "shape": [len(v) for v in query_embeddings]})
        if self.fail:
            raise RuntimeError("synthetic native query failure")
        ids = list(self.rows)
        if self.drop and ids:
            ids = ids[:-1]
        return {"ids": [ids], "documents": [[self.rows[rid]["document"] for rid in ids]],
            "metadatas": [[self.rows[rid]["metadata"] for rid in ids]], "distances": [[0.2 for rid in ids]]}


class FakeClient:
    def __init__(self, **kwargs):
        self.rows, self.kwargs = {}, kwargs
    def get_or_create_collection(self, *, name, metadata, embedding_function):
        assert metadata == {"hnsw:space": "cosine"} and embedding_function is None
        return self.rows.setdefault(name, FakeCollection(name, **self.kwargs))


class NativeVectorNullContracts(unittest.TestCase):
    def matrix(self, client):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            probe.save(output/"plan.json", {"version": probe.VERSION})
            return probe.run_matrix(client, output)

    def test_vectors_are_finite_float32_nondegenerate_and_fixture_is_fixed(self):
        a, b = probe.vector(1), probe.vector(41)
        self.assertEqual(len(a), 384)
        self.assertNotEqual(a, b)
        self.assertTrue(probe.vector_stats(a)["finite"])
        self.assertAlmostEqual(probe.vector_stats(a)["l2_norm"], 1.0, places=6)
        self.assertEqual(probe.vector_stats(a), probe.vector_stats(probe.vector(1)))
        self.assertGreater(max(a)-min(a), 0.01)
        self.assertEqual({name: sum(r["actor"] == name for r in probe.fixture()) for name in probe.ACTORS},
            {"owner": 2, "assistant": 3, "outsider": 1})

    def test_fixed_twelve_query_denominator_and_exact_deletion_controls(self):
        client = FakeClient()
        result = self.matrix(client)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["queries"]), 12)
        self.assertTrue(all(row["passed"] for row in result["queries"]))
        self.assertEqual(len([row for row in result["calls"] if row["operation"] == "query"]), 12)
        self.assertEqual({name: c.count() for name, c in client.rows.items()},
            {"user-memory-owner": 1, "user-memory-assistant": 2, "user-memory-outsider": 1})
        self.assertTrue(all(q == {"n_results": 100, "where": None, "shape": [384]} for c in client.rows.values() for q in c.queries))

    def test_native_exceptions_are_recorded_without_retry_default_empty_or_denominator_loss(self):
        client = FakeClient(fail=True)
        result = self.matrix(client)
        self.assertEqual(len(result["queries"]), 12)
        self.assertEqual(sum(len(c.queries) for c in client.rows.values()), 12)
        self.assertTrue(all(row["count_get_positive_passed"] for row in result["queries"]))
        self.assertTrue(all(not row["query_complete_passed"] for row in result["queries"]))
        for row in result["queries"]:
            error = row["native_query"]["error"]
            self.assertEqual(error["class"], "builtins.RuntimeError")
            self.assertEqual(len(error["message_sha256"]), 64)
            self.assertTrue(error["stack"])

    def test_null_missing_positive_and_wrong_metadata_are_failures(self):
        self.assertFalse(probe.validate_query(None, {}))
        self.assertTrue(all(not row["passed"] for row in self.matrix(FakeClient(drop=True))["queries"]))
        expected = {"a": {"document": "doc", "metadata": {"created_at": 1}}}
        result = {"ids": [["a"]], "documents": [["doc"]], "metadatas": [[{"created_at": True}]], "distances": [[0.2]]}
        self.assertFalse(probe.validate_query(result, expected))

    def test_backend_operation_requires_preexisting_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            with self.assertRaisesRegex(ValueError, "plan_must_exist"):
                probe.run_matrix(client, directory)
            self.assertFalse(client.rows)


if __name__ == "__main__":
    unittest.main()
