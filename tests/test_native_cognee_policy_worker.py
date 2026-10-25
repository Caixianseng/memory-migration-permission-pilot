"""Fake transport/boundary tests only; never import or start Cognee."""
from __future__ import annotations
import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4
import zipfile

from scripts.native_cognee_policy_worker import CogneePolicyWorker, InferenceBoundary, LIMITS, SafeRecorder, verify_official_file_scope, WHEEL_SHA256


class FakeResponse:
    def __init__(self, body, status, headers):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.request = SimpleNamespace(headers={k.lower(): v for k, v in headers.items()})
    def json(self):
        return json.loads(self.content)


class FakeClient:
    def __init__(self, identities):
        self.cookies = SimpleNamespace(clear=Mock())
        self.identities = identities
        self.calls, self.datasets, self.facts, self.grants = [], {}, {}, {}
        self.bearers = {"Bearer fake-token-" + a + "-long-local-only": a for a in identities}
        self.child_key = "fake-child-api-key-long-local-only"
        self.child_body = None
        self.corrupt_raw = False

    def request(self, method, path, headers, **kwargs):
        self.calls.append((method, path, dict(headers), kwargs))
        actor = self.bearers.get(headers.get("Authorization"))
        if headers.get("X-Api-Key") == self.child_key:
            actor = "assistant_agent"
        def reply(body, status=200): return FakeResponse(body, status, headers)
        if path == "/api/v1/agents/create":
            rid = str(uuid4()); self.identities["assistant_agent"] = {"id": rid,
                "parent_user_id": self.identities["assistant"]["id"], "is_superuser": False}
            return reply(self.child_body or {"agentId": rid, "agentApiKey": self.child_key})
        if path == "/api/v1/users/me":
            return reply(self.identities[actor]) if actor else reply({"detail": "not authenticated"}, 401)
        if path == "/api/v1/datasets" and method == "POST":
            rid = str(uuid4()); self.datasets[rid] = {"id": rid, "name": kwargs["json"]["name"], "owner": actor}
            return reply({"id": rid, "name": kwargs["json"]["name"]})
        if path.startswith("/api/v1/permissions/datasets/"):
            recipient = path.rsplit("/", 1)[-1]; ds = kwargs["json"][0]
            if actor != self.datasets[ds]["owner"]: return reply({"detail": "forbidden"}, 403)
            key = (ds, recipient, kwargs["params"]["permission_name"])
            if method == "POST": self.grants[key] = True
            else: self.grants.pop(key, None)
            return reply({"message": "accepted"})
        if path == "/api/v1/add":
            ds = kwargs["data"]["datasetId"]; rid = str(uuid4())
            self.facts[rid] = {"id": rid, "dataset": ds, "text": kwargs["data"]["raw_data"]}
            return reply({"status": "completed"})
        parts = path.strip("/").split("/")
        if len(parts) >= 5 and parts[:3] == ["api", "v1", "datasets"]:
            ds = parts[3]
            permitted = actor == self.datasets[ds]["owner"] or bool(self.grants.get((ds, self.identities[actor]["id"], "read")))
            if not permitted: return reply({"detail": "forbidden"}, 403)
            if len(parts) == 5 and parts[4] == "data":
                return reply([{"id": k} for k, v in self.facts.items() if v["dataset"] == ds])
            rid = parts[5]
            if rid not in self.facts or self.facts[rid]["dataset"] != ds: return reply({"detail": "missing"}, 404)
            if method == "DELETE": self.facts.pop(rid); return reply({"message": "deleted"})
            return reply(("changed text" if self.corrupt_raw else self.facts[rid]["text"]).encode())
        return reply({"detail": "unsupported"}, 404)


class CogneePolicyWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.worker = CogneePolicyWorker(state=self.root / "state", wheel=self.root / "missing.whl", legacy_project=self.root)
        self.worker.identities = {actor: {"id": str(uuid4()), "parent_user_id": None, "is_superuser": False,
            "credential_kind": "bearer"} for actor in ("owner", "assistant", "outsider")}
        self.client = FakeClient({k: dict(v) for k, v in self.worker.identities.items()})
        self.worker.recorder = SafeRecorder(self.client, self.root / "responses")
        for actor in self.worker.identities:
            self.worker.recorder.bind(actor, "bearer", "fake-token-" + actor + "-long-local-only")
        # Explicit fake transport qualification; do not initialize native runtime.
        self.worker._guard = Mock()

    def create_fact(self, dataset="source", owner="owner", key="fact"):
        self.worker("create_dataset", {"dataset": dataset, "actor": owner})
        return self.worker("add_exact_fact", {"dataset": dataset, "actor": owner,
            "fact_key": key, "text": "Project Maple | Customer: Synthetic Company"})

    def test_native_argv_route_shapes_read_share_revoke_and_raw_bytes(self):
        fact = self.create_fact()
        denied = self.worker("read_raw", {"dataset": "source", "fact_key": "fact", "actor": "assistant"})
        self.assertEqual(denied["status"], 403)
        request = {"dataset": "source", "actor": "owner", "recipient": "assistant", "permission": "read"}
        self.worker("grant", request)
        allowed = self.worker("read_raw", {"dataset": "source", "fact_key": "fact", "actor": "assistant"})
        self.assertEqual(allowed["status"], 200)
        self.worker("revoke", request)
        self.assertEqual(self.worker("read_raw", {"dataset": "source", "fact_key": "fact", "actor": "assistant"})["status"], 403)
        for method, path, headers, kwargs in self.client.calls:
            self.assertNotIn("Cookie", headers)
            if path.startswith("/api/v1/permissions/datasets/"):
                self.assertEqual(kwargs["params"], {"permission_name": "read"})
                self.assertEqual(kwargs["json"], [self.worker.datasets["source"]["id"]])
        raw = Path(fact["raw_trace"]["native_response_file"]).read_bytes()
        self.assertEqual(raw, b"Project Maple | Customer: Synthetic Company")

    def test_child_key_is_ram_only_and_native_parent_is_verified(self):
        self.create_fact()
        child = self.worker("create_child", {"actor": "assistant", "child": "assistant_agent"})
        self.assertEqual(child["identity"]["parent_user_id"], self.worker.identities["assistant"]["id"])
        grant = {"dataset": "source", "actor": "owner", "recipient": "assistant_agent", "permission": "read"}
        self.worker("grant", grant)
        self.assertEqual(self.worker("read_raw", {"dataset": "source", "fact_key": "fact", "actor": "assistant_agent"})["status"], 200)
        serialized = json.dumps(self.worker.summary())
        self.assertNotIn(self.client.child_key, serialized)
        self.assertTrue(all(self.client.child_key.encode() not in p.read_bytes() for p in (self.root / "responses").iterdir()))
        auth = [x for x in self.worker.recorder.requests if x["path"] == "/api/v1/agents/create"][0]
        self.assertNotIn("native_body_sha256", auth); self.assertNotIn("request_params", auth)
        self.assertTrue(auth["credential_response_omitted"])
        with self.assertRaises(ValueError): self.worker("create_child", {"actor": "assistant", "child": "assistant_agent"})

    def test_unknown_or_conflicting_scope_and_secret_fields_fail_before_transport(self):
        self.create_fact(); before = len(self.client.calls)
        for command, data in [("read_raw", {"dataset": "old", "fact_key": "fact", "actor": "owner"}),
            ("grant", {"dataset": "source", "actor": "owner", "recipient": "unregistered", "permission": "read"}),
            ("grant", {"dataset": "source", "actor": "owner", "recipient": "assistant", "permission": "admin"}),
            ("arbitrary_http", {"path": "/api/v1/cognify"}),
            ("add_exact_fact", {"dataset": "source", "actor": "owner", "fact_key": "new", "text": "Synthetic", "source_text": "do not import"})]:
            with self.assertRaises(ValueError): self.worker(command, data)
        self.assertEqual(len(self.client.calls), before)

    def test_plaintext_rejects_outer_whitespace_url_file_and_native_normalization(self):
        self.worker("create_dataset", {"dataset": "source", "actor": "owner"}); before = len(self.client.calls)
        for text in [" leading", "trailing\n", "https://example.invalid", "file:///private", "C:\\private.txt", "/private.txt"]:
            with self.assertRaises(ValueError): self.worker("add_exact_fact", {"dataset": "source", "actor": "owner", "fact_key": "new", "text": text})
        self.assertEqual(len(self.client.calls), before)
        self.client.corrupt_raw = True
        with self.assertRaisesRegex(ValueError, "native_exact_content_not_preserved"):
            self.worker("add_exact_fact", {"dataset": "source", "actor": "owner", "fact_key": "new", "text": "Synthetic"})
        self.assertNotIn("new", self.worker.facts)

    def test_non_auth_secret_echo_cannot_enter_raw_file_or_summary(self):
        secret = "fake-secret-known-to-recorder-only"
        self.worker.recorder.remember(secret)
        self.client.request = lambda *a, **k: FakeResponse({"error": secret}, 500, {})
        with self.assertRaisesRegex(ValueError, "credential_contaminated_native_response"):
            self.worker.recorder.request("GET", "/api/v1/users/me", actor="owner")
        self.assertFalse(list((self.root / "responses").iterdir()))
        self.assertNotIn(secret, json.dumps(self.worker.recorder.requests))

    def test_credential_like_fields_block_even_unknown_key(self):
        self.client.request = lambda *a, **k: FakeResponse({"agentApiKey": "not previously known"}, 200, {})
        with self.assertRaisesRegex(ValueError, "credential_field_in_native_response"):
            self.worker.recorder.request("GET", "/api/v1/users/me", actor="owner")
        self.assertFalse(list((self.root / "responses").iterdir()))

    def test_cross_container_read_measurement_is_allowed_but_delete_is_not(self):
        self.create_fact("first", "owner", "one"); self.create_fact("second", "owner", "two")
        self.assertEqual(self.worker("read_raw", {"dataset": "first", "fact_key": "two", "actor": "owner"})["status"], 404)
        before = len(self.client.calls)
        with self.assertRaises(ValueError): self.worker("delete_exact_object", {"dataset": "first", "fact_key": "two", "actor": "owner"})
        self.assertEqual(len(self.client.calls), before)

    def test_budget_and_cookie_guard_fail_without_erasing_error(self):
        self.worker.recorder.requests = [{} for _ in range(LIMITS["http_requests"])]
        with self.assertRaisesRegex(ValueError, "native_http_budget_exhausted"):
            self.worker.recorder.request("GET", "/api/v1/users/me", actor="owner")
        self.worker.recorder.requests = []
        self.client.request = lambda *a, **k: FakeResponse({}, 200, {"Cookie": "fake-cookie"})
        with self.assertRaisesRegex(ValueError, "native_cookie_contamination"):
            self.worker.recorder.request("GET", "/api/v1/users/me", actor="owner")
        self.assertFalse(self.worker.recorder.requests[-1]["response_checked"])

    def test_profile_blocks_model_before_body_and_restores_previous_profile(self):
        namespace = {"__name__": "cognee.infrastructure.llm.LLMGateway", "executed": []}
        exec("def acreate_structured_output():\n executed.append(True)\n", namespace)
        guard = InferenceBoundary(); guard.install()
        try:
            with self.assertRaisesRegex(RuntimeError, "unexpected_native_inference_blocked"):
                namespace["acreate_structured_output"]()
        finally:
            guard.close()
        self.assertEqual(namespace["executed"], []); self.assertEqual(guard.events[0]["kind"], "generation")
        self.assertEqual(InferenceBoundary.classify("cognee.infrastructure.databases.vector.embeddings.fast", "embed_text"), "embedding")
        self.assertIsNone(InferenceBoundary.classify("cognee.infrastructure.databases.vector.embeddings.config", "get_embedding_config"))

    def test_missing_wheel_and_existing_state_fail_before_native_import(self):
        with self.assertRaisesRegex(ValueError, "cognee_wheel_sha256_changed"): self.worker.initialize({})
        self.worker.state.mkdir()
        with self.assertRaisesRegex(ValueError, "new_ascii_system_temp_state_required"): self.worker.initialize({})

    def test_explicit_small_http_cap_and_secret_free_failure_metadata(self):
        recorder = SafeRecorder(self.client, self.root / "small_responses", max_requests=1)
        recorder.request("GET", "/api/v1/users/me")
        with self.assertRaisesRegex(ValueError, "native_http_budget_exhausted"):
            recorder.request("GET", "/api/v1/users/me")
        with self.assertRaises(ValueError): self.worker("unregistered_command", {})
        self.assertEqual(self.worker.summary()["last_failure"]["code"], "native_command_not_allowed")
        self.worker._dispatch = Mock(side_effect=ModuleNotFoundError("secret message not recorded", name="safe.missing_module"))
        with self.assertRaises(ModuleNotFoundError): self.worker("init", {})
        metadata = self.worker.summary()["last_failure"]
        self.assertEqual(metadata["missing_module"], "safe.missing_module")
        self.assertNotIn("secret message", json.dumps(metadata))

    def test_state_scope_rejects_escaped_root_or_unguarded_resolver(self):
        state = self.root / "new_state"
        with self.assertRaisesRegex(ValueError, "native_file_roots_escape_state"):
            verify_official_file_scope(state, lambda: (self.root,), lambda p, **kw: p)
        with self.assertRaisesRegex(ValueError, "native_outside_state_path_not_denied"):
            verify_official_file_scope(state, lambda: (state,), lambda p, **kw: p)

    def test_fixed_official_allow_root_functions_accept_inside_and_reject_outside(self):
        wheel = Path(__file__).resolve().parents[1] / ".runtime/native_cognee_wheel/cognee-1.6.5-py3-none-any.whl"
        if not wheel.is_file(): self.skipTest("Optional fixed official wheel not downloaded; no network/download in tests")
        self.assertEqual(hashlib.sha256(wheel.read_bytes()).hexdigest(), WHEEL_SHA256)
        with zipfile.ZipFile(wheel) as archive:
            source = archive.read("cognee/infrastructure/files/utils/local_path_safety.py").decode()
        # Execute the official function AST bodies unchanged, without importing
        # Cognee/application. Only its configuration accessor is a fake fixture.
        tree = ast.parse(source)
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
        state = self.root / "state_for_pure_helper"
        config = SimpleNamespace(**{name: str(state / name) for name in ("data_root_directory", "system_root_directory",
            "cache_root_directory", "logs_root_directory", "repos_root_directory")})
        namespace = {"os": os, "Path": Path, "get_base_config": lambda: config,
            "ALLOWED_LOCAL_FILE_ROOTS_ENV": "COGNEE_ALLOWED_LOCAL_FILE_ROOTS"}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "fixed_official_local_path_helpers.py", "exec"), namespace)
        with patch.dict(os.environ, {"COGNEE_ALLOWED_LOCAL_FILE_ROOTS": str(state)}):
            receipt = verify_official_file_scope(state, namespace["get_allowed_local_file_roots"], namespace["resolve_local_path"])
        self.assertTrue(receipt["state_internal_resolution_allowed"])
        self.assertTrue(receipt["outside_state_resolution_denied"])
        self.assertFalse(state.exists())  # no actual internal/external file IO


if __name__ == "__main__":
    unittest.main()
