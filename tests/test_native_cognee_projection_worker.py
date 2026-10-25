"""Fake HTTP tests only: no Cognee, model, gateway, or source-policy execution."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from scripts import native_cognee_projection_worker as projection
from scripts.native_cognee_policy_worker import SafeRecorder
from tests.test_native_cognee_policy_worker import FakeClient, FakeResponse


class ProjectionClient(FakeClient):
    def request(self, method, path, headers, **kwargs):
        if method == "GET" and path == "/api/v1/datasets":
            self.calls.append((method, path, dict(headers), kwargs))
            actor = self.bearers.get(headers.get("Authorization"))
            if actor is None: return FakeResponse({"detail": "not authenticated"}, 401, headers)
            rows = [{"id": rid, "name": row["name"]} for rid, row in self.datasets.items()
                if row["owner"] == actor or self.grants.get((rid, self.identities[actor]["id"], "read"))]
            return FakeResponse(rows, 200, headers)
        return super().request(method, path, headers, **kwargs)


class CogneeProjectionWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source_sha = hashlib.sha256(Path(projection.__file__).read_bytes()).hexdigest()
        self.worker = projection.CogneeProjectionWorker(expected_worker_sha256=self.source_sha,
            state=self.directory / "state", wheel=self.directory / "missing.whl", legacy_project=self.directory)
        self.worker.identities = {actor: {"id": str(uuid4()), "parent_user_id": None, "is_superuser": False,
            "credential_kind": "bearer"} for actor in projection.ACTORS}
        self.client = ProjectionClient({k: dict(v) for k, v in self.worker.identities.items()})
        self.worker.recorder = SafeRecorder(self.client, self.directory / "responses", max_requests=200)
        for actor in self.worker.identities:
            self.worker.recorder.bind(actor, "bearer", "fake-token-"+actor+"-long-local-only")
        self.worker._guard = Mock()  # explicit fake transport, never native init

    def add_facts(self):
        for key, text in (("readonly", "SYNTHETIC_VALUE_A71"), ("managed", "SYNTHETIC_VALUE_B92")):
            self.worker("create_dataset", {"dataset": key, "actor": "owner"})
            self.worker("add_exact_fact", {"dataset": key, "actor": "owner", "fact_key": key, "text": text})

    def permission(self, operation, actor, recipient, dataset="managed", permission="read"):
        return self.worker(operation, {"dataset": dataset, "actor": actor, "recipient": recipient, "permission": permission})

    def test_fixed_tuple_roster_and_source_aliases_are_independent_users(self):
        self.assertEqual(set(self.worker.identities), {"owner", "alice_reader", "alice_worker", "bob_reader", "bob_worker"})
        self.assertEqual(len({x["id"] for x in self.worker.identities.values()}), 5)
        for actor in projection.TUPLE_ACTORS:
            response = self.worker("whoami", {"actor": actor})
            self.assertEqual(response["status"], 200)
            self.assertEqual(json.loads(response["trace"]["native_raw_body"])["parent_user_id"], None)
        self.assertEqual(self.worker.summary()["source_actor_map"]["alice.reader"], "alice_reader")
        self.assertFalse(self.worker.summary()["per_request_reference_gate_present"])

    def test_n_grants_read_snapshot_and_revoke_use_native_results(self):
        self.add_facts()
        self.permission("grant", "owner", "alice_reader", "readonly")
        self.permission("grant", "owner", "alice_reader")
        self.permission("grant", "owner", "bob_reader")
        before = len(self.worker.recorder.requests)
        snapshot = self.worker("snapshot", {})
        self.assertEqual(snapshot["physical_http_requests"], 20)
        self.assertEqual(len(self.worker.recorder.requests)-before, 20)
        self.assertTrue(snapshot["both_exact_facts_ready"])
        raw = {(r["actor"], r["dataset"]): r["result"]["status"] for r in snapshot["observations"] if r["operation"] == "raw"}
        self.assertEqual(raw[("alice_reader", "readonly")], 200)
        self.assertEqual(raw[("alice_worker", "readonly")], 403)
        self.assertEqual(raw[("bob_reader", "managed")], 200)
        self.assertEqual(raw[("bob_reader", "readonly")], 403)
        self.permission("revoke", "owner", "bob_reader")
        denied = self.worker("read_raw", {"dataset": "managed", "fact_key": "managed", "actor": "bob_reader"})
        self.assertEqual(denied["status"], 403)
        self.assertIn("native_raw_body", denied["trace"])

    def test_g_native_bypass_without_any_grants_remains_visible_as_native_denial(self):
        self.add_facts()
        snapshot = self.worker("snapshot", {})
        for row in snapshot["observations"]:
            if row["operation"] == "list_datasets":
                self.assertEqual(row["result"]["status"], 200)
                self.assertEqual(json.loads(row["result"]["trace"]["native_raw_body"]), [])
            else: self.assertEqual(row["result"]["status"], 403)
        self.assertFalse(snapshot["source_policy_evaluated_here"])
        self.assertFalse(snapshot["atomic_snapshot_claimed"])

    def test_read_only_user_native_share_attempt_does_not_grant_recipient(self):
        self.add_facts(); self.permission("grant", "owner", "alice_reader")
        outcome = self.permission("grant", "alice_reader", "bob_worker")
        self.assertEqual(outcome["status"], 403)
        self.assertEqual(self.worker("read_raw", {"dataset": "managed", "fact_key": "managed", "actor": "bob_worker"})["status"], 403)

    def test_roster_old_alias_child_delete_and_arbitrary_scope_fail_before_http(self):
        self.add_facts(); before = len(self.client.calls)
        for command, data in [("whoami", {"actor": "assistant"}), ("whoami", {"actor": "alice.reader"}),
            ("create_child", {"actor": "owner", "child": "model_agent"}),
            ("delete_exact_object", {"actor": "owner", "dataset": "managed", "fact_key": "managed"}),
            ("create_dataset", {"actor": "owner", "dataset": "third"}),
            ("create_dataset", {"actor": "alice_reader", "dataset": "managed"}),
            ("snapshot", {"actors": ["alice_reader", "alice_reader"]}),
            ("snapshot", {"actors": ["owner"], "policy": "do not gate here"})]:
            with self.assertRaises(ValueError): self.worker(command, data)
        self.assertEqual(len(self.client.calls), before)

    def test_wrong_fact_dataset_pair_and_full_source_extra_field_rejected(self):
        self.worker("create_dataset", {"actor": "owner", "dataset": "readonly"}); before = len(self.client.calls)
        for data in [{"actor": "owner", "dataset": "readonly", "fact_key": "managed", "text": "Synthetic"},
            {"actor": "owner", "dataset": "readonly", "fact_key": "readonly", "text": "Synthetic", "source_text": "do not import"}]:
            with self.assertRaises(ValueError): self.worker("add_exact_fact", data)
        self.assertEqual(len(self.client.calls), before)

    def test_partial_snapshot_not_qualified_as_complete_and_owner_subset_count(self):
        partial = self.worker("snapshot", {})
        self.assertFalse(partial["both_exact_facts_ready"])
        self.assertEqual(partial["physical_http_requests"], 4)
        self.add_facts()
        owner = self.worker("snapshot", {"actors": ["owner"]})
        self.assertEqual(owner["physical_http_requests"], 5)
        self.assertTrue(all(row["result"]["status"] == 200 for row in owner["observations"]))

    def test_both_source_hash_bindings_are_checked_before_native_init(self):
        self.assertEqual(self.worker._bindings()["projection_worker_sha256"], self.source_sha)
        with patch.object(projection, "BASE_SHA256", "0"*64):
            with self.assertRaisesRegex(ValueError, "frozen_cognee_policy_worker_changed"): self.worker.initialize({})
        self.worker.expected_worker_sha256 = "0"*64
        with self.assertRaisesRegex(ValueError, "projection_worker_source_changed"): self.worker.initialize({})
        self.assertFalse(self.worker.state.exists())

    def test_summary_never_exports_bearers_or_claims_child_agent(self):
        self.add_facts(); summary = self.worker.summary(); text = json.dumps(summary)
        self.assertEqual(summary["native_child_agents_created"], 0)
        self.assertEqual(summary["limits"]["datasets"], 2)
        self.assertEqual(summary["limits"]["facts"], 2)
        self.assertFalse(summary["source_policy_evaluated_here"])
        self.assertNotIn("fake-token-", text)
        self.assertTrue(all(b"fake-token-" not in p.read_bytes() for p in (self.directory/"responses").iterdir()))

    def test_summary_rpc_has_no_http_or_state_mutation_and_includes_object_maps(self):
        self.add_facts()
        before_http = len(self.client.calls)
        before = self.worker.summary()
        result = self.worker("summary", {})
        self.assertEqual(len(self.client.calls), before_http)
        self.assertEqual(result, before)
        self.assertEqual(set(result["datasets"]), {"readonly", "managed"})
        self.assertEqual(set(result["facts"]), {"readonly", "managed"})
        result["datasets"]["readonly"]["id"] = "caller-change"
        self.assertNotEqual(self.worker.datasets["readonly"]["id"], "caller-change")
        with self.assertRaises(ValueError): self.worker("summary", {"actors": ["owner"]})
        self.assertEqual(len(self.client.calls), before_http)


if __name__ == "__main__":
    unittest.main()
