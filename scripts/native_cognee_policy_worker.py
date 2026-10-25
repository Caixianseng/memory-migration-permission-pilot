"""Bounded fresh Cognee 1.6.5 native ACL worker; no default/core changes.

Only exact plaintext ingestion, native identities, raw reads and dataset
read/share controls are exposed. Unexpected model entry is blocked, not faked.
All client credential values stay in RAM; native auth storage remains native.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import threading
import time
from uuid import UUID
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from scripts.native_exact_fact_common import NetworkGuard, isolate_environment, serve_commands

VERSION = "cognee_native_policy_worker_v2_state_scoped_ingestion"
WHEEL_SHA256 = "aaef9fdc02f542b1d125cde21759dde2fac56355d8928e39c734e7b5c6705eca"
LEGACY_CONFIGURATION_SHA256 = "11f295bf655690b33c9051a48b650bbb8592e5d83bfb78beba57ee5694de6aad"
VERSION_EXPECTED = "1.6.5"
VENDOR_FILES = ("cognee/api/client.py", "cognee/api/v1/add/routers/get_add_router.py", "cognee/api/v1/add/add.py",
    "cognee/api/v1/agents/routers/get_agents_router.py", "cognee/api/v1/permissions/routers/get_permissions_router.py",
    "cognee/api/v1/datasets/routers/get_datasets_router.py", "cognee/modules/users/methods/get_authenticated_user.py",
    "cognee/infrastructure/files/utils/local_path_safety.py", "cognee/tasks/ingestion/save_data_item_to_storage.py",
    "cognee/tasks/ingestion/data_item_to_text_file.py", "cognee/tasks/ingestion/ingest_data.py")
PRINCIPALS = ("owner", "assistant", "outsider")
LIMITS = {"http_requests": 200, "datasets": 6, "facts": 7, "children": 1, "fact_chars": 4096}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class WorkerScopeError(ValueError):
    """Only fixed local contract codes, never native exception messages."""


def require(condition, error):
    if not condition:
        raise WorkerScopeError(error)


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value) is not None


def native_id(value):
    require(isinstance(value, str) and str(UUID(value)) == value.lower(), "native_uuid_invalid")
    return value


def verify_official_file_scope(state, get_roots, resolve_path):
    """Pure probes through official helpers: never create/read either probe file."""
    state = Path(state).resolve()
    roots = get_roots()
    require(isinstance(roots, tuple) and bool(roots) and all(Path(p).resolve().is_relative_to(state) for p in roots),
        "native_file_roots_escape_state")
    internal = state / "internal_scope_probe_not_created.txt"
    require(Path(resolve_path(internal, must_exist=False)).resolve() == internal, "native_internal_path_not_allowed")
    outside = state.parent / ("outside_scope_probe_" + state.name + ".txt")
    denied = False
    try:
        resolve_path(outside, must_exist=False)
    except ValueError:
        denied = True
    require(denied, "native_outside_state_path_not_denied")
    return {"all_official_roots_within_state": True, "state_internal_resolution_allowed": True,
        "outside_state_resolution_denied": True, "probe_files_created": False,
        "scope": "Official ingestion/storage path helpers, not an OS filesystem sandbox."}


class InferenceBoundary:
    """Profile known inference entries before their body, in main/new threads.

    This is a Python boundary, not tracing of arbitrary native/GPU forwards.
    Zero means no observed entry, not a hardware-level attestation.
    """
    def __init__(self):
        self.events, self.previous, self.previous_threads = [], None, None
        self.callback = self._profile
        self.installed = False

    @staticmethod
    def classify(module, name):
        if (module.startswith("cognee.infrastructure.databases.vector.embeddings") and name in {"embed_text", "embed_documents", "embed_query"}) or (module.startswith(("fastembed", "sentence_transformers")) and name in {"embed", "query_embed", "encode", "encode_query", "encode_document", "forward"}):
            return "embedding"
        if module.startswith("litellm") and name in {"embedding", "aembedding"}:
            return "embedding"
        if (module.startswith("cognee.infrastructure.llm") and (name.startswith(("generate", "complete")) or name in {"acreate_structured_output", "create_structured_output", "create_transcript", "transcribe_image", "chat", "invoke", "ainvoke"})) or (module.startswith("litellm") and name in {"completion", "acompletion", "transcription", "atranscription"}) or (module.startswith("openai.resources") and name == "create"):
            return "generation"
        return None

    def _profile(self, frame, event, arg):
        if event == "call":
            module, name = str(frame.f_globals.get("__name__", "")), frame.f_code.co_name
            kind = self.classify(module, name)
            if kind:
                self.events.append({"kind": kind, "module": module, "function": name})
                raise RuntimeError("unexpected_native_inference_blocked")

    def install(self):
        require(not self.installed, "inference_guard_already_installed")
        self.previous, self.previous_threads = sys.getprofile(), threading.getprofile()
        sys.setprofile(self.callback); threading.setprofile(self.callback)
        self.installed = True

    def verify(self):
        require(self.installed and sys.getprofile() is self.callback and threading.getprofile() is self.callback and not self.events,
                "inference_guard_changed_or_attempted")

    def close(self):
        if self.installed:
            sys.setprofile(self.previous); threading.setprofile(self.previous_threads)
            self.installed = False


class SafeRecorder:
    def __init__(self, client, response_dir, *, max_requests=LIMITS["http_requests"]):
        require(type(max_requests) is int and 1 <= max_requests <= LIMITS["http_requests"], "invalid_http_cap")
        self.client, self.response_dir = client, Path(response_dir)
        self.max_requests = max_requests
        self.response_dir.mkdir(parents=True, exist_ok=False)
        self.headers, self._secrets, self.requests = {}, [], []

    def remember(self, value):
        require(isinstance(value, str) and bool(value), "empty_credential")
        self._secrets.append(value.encode())

    def bind(self, actor, kind, value):
        require(actor not in self.headers and kind in {"bearer", "api_key"}, "credential_binding_invalid")
        self.remember(value)
        self.headers[actor] = {"Authorization": "Bearer " + value} if kind == "bearer" else {"X-Api-Key": value}

    def request(self, method, path, *, actor=None, credential=False, **kwargs):
        require(len(self.requests) < self.max_requests, "native_http_budget_exhausted")
        self.client.cookies.clear()
        header = self.headers.get(actor, {})
        row = {"index": len(self.requests), "method": method, "path": path, "actor": actor,
            "started_ns": time.perf_counter_ns(), "credential_response_omitted": credential,
            "authorization_present": False, "api_key_present": False, "cookie_present": False}
        if not credential:
            for name in ("json", "params", "data"):
                if name in kwargs:
                    row["request_" + name] = deepcopy(kwargs[name])
        try:
            response = self.client.request(method, path, headers=header, **kwargs)
            actual = getattr(getattr(response, "request", None), "headers", header)
            row.update(status=response.status_code, authorization_present=bool(actual.get("Authorization") or actual.get("authorization")),
                api_key_present=bool(actual.get("X-Api-Key") or actual.get("x-api-key")), cookie_present=bool(actual.get("cookie")))
            require(not row["cookie_present"], "native_cookie_contamination")
            if not credential:
                raw = bytes(response.content)
                require(len(raw) <= 2 * 1024 * 1024, "native_response_too_large")
                require(not any(secret in raw for secret in self._secrets), "credential_contaminated_native_response")
                try:
                    parsed = json.loads(raw)
                except (ValueError, UnicodeError):
                    parsed = None
                def private_keys(value):
                    if isinstance(value, dict):
                        return bool({str(k).lower() for k in value} & {"password", "hashed_password", "password_hash", "apikey", "api_key", "agentapikey", "agent_api_key", "access_token", "refresh_token", "authorization"}) or any(private_keys(v) for v in value.values())
                    return isinstance(value, list) and any(private_keys(v) for v in value)
                require(not private_keys(parsed), "credential_field_in_native_response")
                destination = self.response_dir / f"{row['index']:04d}.bin"
                with destination.open("xb") as stream:
                    stream.write(raw)
                row.update(native_raw_body=raw.decode("utf-8"), native_body_sha256=sha(raw), byte_count=len(raw),
                    native_response_file=str(destination.resolve()), response_checked=True, execution_error=None)
            else:
                row.update(response_checked=True, execution_error=None)
            return response, row
        except Exception as error:
            row.update(response_checked=False, execution_error=type(error).__name__)
            raise
        finally:
            row["finished_ns"] = time.perf_counter_ns(); self.requests.append(row)


class CogneePolicyWorker:
    def __init__(self, *, state, wheel, legacy_project, openssl_dll_dir=None, http_cap=LIMITS["http_requests"]):
        require(type(http_cap) is int and 1 <= http_cap <= LIMITS["http_requests"], "invalid_http_cap")
        self.http_cap = http_cap
        self.state, self.wheel, self.legacy = map(lambda p: Path(p).resolve(), (state, wheel, legacy_project))
        self.openssl = Path(openssl_dll_dir).resolve() if openssl_dll_dir else None
        self.guard, self.inference = NetworkGuard(), InferenceBoundary()
        self.context = self.client = self.recorder = self.dll_handle = None
        self.identities, self.datasets, self.facts, self.children = {}, {}, {}, {}
        self.ready, self.stage = False, "uninitialized"
        self.last_failure = None
        self.file_scope = None

    def initialize(self, data):
        self.stage = "native_vendor_preflight"
        require(data == {} and not self.ready and self.context is None, "native_init_invalid")
        require(self.state.is_relative_to(Path(tempfile.gettempdir()).resolve()) and self.state != Path(tempfile.gettempdir()).resolve()
            and str(self.state).isascii() and not self.state.exists(), "new_ascii_system_temp_state_required")
        require(self.wheel.is_file() and sha(self.wheel.read_bytes()) == WHEEL_SHA256, "cognee_wheel_sha256_changed")
        distribution = importlib.metadata.distribution("cognee")
        require(distribution.version == VERSION_EXPECTED, "native_cognee_version_changed")
        with zipfile.ZipFile(self.wheel) as archive:
            source_hashes = {}
            for name in VENDOR_FILES:
                expected = sha(archive.read(name)); installed = Path(distribution.locate_file(name))
                require(installed.is_file() and sha(installed.read_bytes()) == expected, "native_vendor_source_changed")
                source_hashes[name] = expected
        self.state.mkdir(parents=True, exist_ok=False)
        isolate_environment(self.state)
        sys.addaudithook(self.guard)
        self.inference.install()
        scripts = str(self.legacy / "scripts")
        config_source = self.legacy / "scripts/cognee_local_migration_probe.py"
        require(config_source.is_file() and sha(config_source.read_bytes()) == LEGACY_CONFIGURATION_SHA256,
            "legacy_configuration_missing_or_changed")
        sys.path.insert(0, scripts)
        from cognee_local_migration_probe import configure_isolated_cognee
        self.settings, self.dll_handle, self.legacy_network_events = configure_isolated_cognee(self.state, self.openssl)
        # Raw text and uploads are both staged and read back as local files.
        # v1's false also blocked those native internal reads (415). Preserve
        # identical raw_data transport and enable only state-scoped ingestion.
        os.environ.update({"ALLOW_HTTP_REQUESTS": "false", "ACCEPT_LOCAL_FILE_PATH": "true",
            "COGNEE_ALLOWED_LOCAL_FILE_ROOTS": str(self.state)})
        self.stage = "native_application_import"
        from cognee.api.client import app
        from cognee.infrastructure.files.utils.local_path_safety import get_allowed_local_file_roots, resolve_local_path
        from cognee.tasks.ingestion.data_item_to_text_file import settings as loader_settings
        from cognee.tasks.ingestion.save_data_item_to_storage import settings as save_settings
        require(loader_settings.accept_local_file_path is True and save_settings.accept_local_file_path is True,
            "native_internal_file_read_configuration_not_observed")
        self.file_scope = verify_official_file_scope(self.state, get_allowed_local_file_roots, resolve_local_path)
        from fastapi.testclient import TestClient
        self.context = TestClient(app, raise_server_exceptions=False)
        self.client = self.context.__enter__()
        self.recorder = SafeRecorder(self.client, self.state / "safe_responses", max_requests=self.http_cap)
        # Assert the portal thread received the same guard before native requests.
        async def portal_guard():
            return sys.getprofile() is self.inference.callback
        require(self.client.portal.call(portal_guard), "portal_inference_guard_missing")
        self.stage = "native_new_regular_users"
        for actor in PRINCIPALS:
            password = secrets.token_urlsafe(32); self.recorder.remember(password)
            email = "controlled-" + actor + "-" + secrets.token_hex(8) + "@example.com"
            response, _ = self.recorder.request("POST", "/api/v1/auth/register", credential=True,
                json={"email": email, "password": password})
            require(response.status_code == 201, "native_registration_failed")
            response, _ = self.recorder.request("POST", "/api/v1/auth/login", credential=True,
                data={"username": email, "password": password})
            require(response.status_code == 200, "native_login_failed")
            self.recorder.bind(actor, "bearer", response.json()["access_token"])
            response, _ = self.recorder.request("GET", "/api/v1/users/me", actor=actor)
            body = response.json()
            require(response.status_code == 200 and body.get("email") == email and body.get("is_superuser") is False,
                "native_regular_identity_not_qualified")
            self.identities[actor] = {"id": native_id(body["id"]), "parent_user_id": None,
                "is_superuser": False, "credential_kind": "bearer"}
        require(len({u["id"] for u in self.identities.values()}) == 3, "native_users_not_independent")
        _, anonymous = self.recorder.request("GET", "/api/v1/datasets")
        require(anonymous["status"] in {401, 403}, "native_anonymous_not_denied")
        self.ready, self.stage = True, "native_policy_ready"
        self._guard()
        return {"version": VERSION, "cognee_version": distribution.version, "identities": deepcopy(self.identities),
            "wheel_sha256": WHEEL_SHA256, "vendor_source_sha256": source_hashes, "limits": {**LIMITS, "http_requests": self.http_cap},
            "write_contract": "native_HTTP_raw_data_unchanged_exact_UTF8_state_scoped_internal_file_reads_v2",
            "file_scope": deepcopy(self.file_scope), "ingestion_configuration": {"ACCEPT_LOCAL_FILE_PATH": True,
                "ALLOW_HTTP_REQUESTS": False, "allowed_local_roots": "current_new_state_only"},
            "client_credentials_saved": False, "native_auth_storage_unmodified": True,
            "inference_scope": "guarded Python entry boundaries, not arbitrary native hardware attestation"}

    def _guard(self):
        require(self.ready, "native_not_initialized")
        self.inference.verify()
        require(all(e.get("allowed") is True for e in self.guard.events) and not self.legacy_network_events,
            "native_network_or_credential_guard_triggered")
        async def portal_guard():
            return sys.getprofile() is self.inference.callback
        require(self.client.portal.call(portal_guard), "portal_inference_guard_changed")

    def _actor(self, actor):
        require(actor in self.identities, "unknown_native_actor")
        return self.identities[actor]["id"]

    def _dataset(self, logical):
        require(logical in self.datasets, "unknown_current_run_dataset")
        return self.datasets[logical]

    def _envelope(self, response, trace):
        return {"status": response.status_code, "trace": deepcopy(trace)}

    def __call__(self, command, data):
        try:
            return self._dispatch(command, data)
        except Exception as error:
            module = getattr(error, "name", None) if isinstance(error, ModuleNotFoundError) else None
            if not isinstance(module, str) or len(module) > 120 or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module):
                module = None
            self.last_failure = {"exception_type": type(error).__name__,
                "code": str(error) if isinstance(error, WorkerScopeError) else "native_operation_failed",
                "missing_module": module, "stage": self.stage}
            raise

    def _dispatch(self, command, data):
        if command == "init":
            return self.initialize(data)
        if command == "close":
            require(data == {}, "close_arguments_forbidden"); self.close(); return self.summary()
        self._guard()
        require(isinstance(data, dict), "native_command_data_invalid")
        if command == "create_dataset":
            require(set(data) == {"dataset", "actor"} and identifier(data["dataset"]) and data["dataset"] not in self.datasets
                and len(self.datasets) < LIMITS["datasets"] and data["actor"] in PRINCIPALS, "dataset_scope_invalid")
            self._actor(data["actor"])
            name = "controlled_policy_" + data["dataset"] + "_" + secrets.token_hex(6)
            response, trace = self.recorder.request("POST", "/api/v1/datasets", actor=data["actor"], json={"name": name})
            require(response.status_code == 200, "native_dataset_creation_failed")
            body = response.json(); require(body.get("name") == name, "native_dataset_name_changed")
            self.datasets[data["dataset"]] = {"id": native_id(body["id"]), "name": name, "owner": data["actor"]}
            result = {**deepcopy(self.datasets[data["dataset"]]), "trace": deepcopy(trace)}
        elif command == "add_exact_fact":
            require(set(data) == {"dataset", "actor", "fact_key", "text"} and identifier(data["fact_key"])
                and data["fact_key"] not in self.facts and len(self.facts) < LIMITS["facts"], "fact_scope_invalid")
            ds = self._dataset(data["dataset"]); self._actor(data["actor"]); text = data["text"]
            require(data["actor"] == ds["owner"] and isinstance(text, str) and 0 < len(text) <= LIMITS["fact_chars"]
                and text == text.strip() and not re.match(r"(?i)(?:[/\\]|[a-z]:[/\\]|https?:|file:|s3:|ftp:)", text), "exact_plaintext_required")
            before, _ = self.recorder.request("GET", f"/api/v1/datasets/{ds['id']}/data", actor=data["actor"])
            require(before.status_code == 200 and isinstance(before.json(), list), "native_inventory_unready")
            old_ids = {native_id(row["id"]) for row in before.json()}
            response, trace = self.recorder.request("POST", "/api/v1/add", actor=data["actor"],
                data={"raw_data": text, "datasetName": ds["name"], "datasetId": ds["id"], "run_in_background": "false"})
            require(response.status_code == 200, "native_plaintext_add_failed")
            after, _ = self.recorder.request("GET", f"/api/v1/datasets/{ds['id']}/data", actor=data["actor"])
            require(after.status_code == 200 and isinstance(after.json(), list), "native_inventory_unready")
            added = [row for row in after.json() if native_id(row["id"]) not in old_ids]
            require(len(added) == 1, "native_exact_added_id_not_unique")
            rid = native_id(added[0]["id"])
            raw, raw_trace = self.recorder.request("GET", f"/api/v1/datasets/{ds['id']}/data/{rid}/raw", actor=data["actor"])
            require(raw.status_code == 200 and bytes(raw.content) == text.encode(), "native_exact_content_not_preserved")
            self.facts[data["fact_key"]] = {"id": rid, "dataset": data["dataset"], "text_sha256": sha(text.encode())}
            result = {**deepcopy(self.facts[data["fact_key"]]), "add_trace": deepcopy(trace), "raw_trace": deepcopy(raw_trace)}
        elif command == "read_raw":
            require(set(data) == {"dataset", "fact_key", "actor"} and data["fact_key"] in self.facts, "raw_read_scope_invalid")
            ds = self._dataset(data["dataset"]); self._actor(data["actor"])
            response, trace = self.recorder.request("GET", f"/api/v1/datasets/{ds['id']}/data/{self.facts[data['fact_key']]['id']}/raw", actor=data["actor"])
            result = self._envelope(response, trace)
        elif command in {"grant", "revoke"}:
            require(set(data) == {"dataset", "actor", "recipient", "permission"} and data["permission"] in {"read", "share"}, "permission_scope_invalid")
            ds = self._dataset(data["dataset"]); self._actor(data["actor"]); recipient = self._actor(data["recipient"])
            response, trace = self.recorder.request("POST" if command == "grant" else "DELETE",
                "/api/v1/permissions/datasets/" + recipient, actor=data["actor"],
                params={"permission_name": data["permission"]}, json=[ds["id"]])
            result = self._envelope(response, trace)
        elif command == "create_child":
            require(set(data) == {"actor", "child"} and data["actor"] == "assistant" and data["child"] == "assistant_agent"
                and not self.children, "child_scope_invalid")
            response, _ = self.recorder.request("POST", "/api/v1/agents/create", actor="assistant", credential=True,
                params={"name": "controlled-child-" + secrets.token_hex(6)})
            require(response.status_code == 200, "native_child_creation_failed")
            body = response.json()
            def dto(snake, camel):
                values = [body[k] for k in (snake, camel) if k in body]
                require(bool(values) and all(isinstance(v, str) and bool(v) for v in values) and len(set(values)) == 1,
                    "native_child_DTO_ambiguous")
                return values[0]
            rid, key = native_id(dto("agent_id", "agentId")), dto("agent_api_key", "agentApiKey")
            require(rid not in {v["id"] for v in self.identities.values()}, "native_child_identity_not_independent")
            self.recorder.bind("assistant_agent", "api_key", key); del key, body
            response, trace = self.recorder.request("GET", "/api/v1/users/me", actor="assistant_agent")
            body = response.json()
            require(response.status_code == 200 and body["id"] == rid and str(body.get("parent_user_id")) == self.identities["assistant"]["id"]
                and body.get("is_superuser") is False, "native_child_identity_not_qualified")
            self.identities["assistant_agent"] = {"id": rid, "parent_user_id": self.identities["assistant"]["id"],
                "is_superuser": False, "credential_kind": "api_key"}
            self.children["assistant_agent"] = rid
            result = {"identity": deepcopy(self.identities["assistant_agent"]), "trace": deepcopy(trace)}
        elif command == "whoami":
            require(set(data) == {"actor"}, "identity_scope_invalid"); self._actor(data["actor"])
            response, trace = self.recorder.request("GET", "/api/v1/users/me", actor=data["actor"])
            result = self._envelope(response, trace)
        elif command == "delete_exact_object":
            require(set(data) == {"dataset", "fact_key", "actor"} and data["fact_key"] in self.facts, "delete_scope_invalid")
            ds = self._dataset(data["dataset"]); self._actor(data["actor"])
            require(self.facts[data["fact_key"]]["dataset"] == data["dataset"], "delete_foreign_dataset_forbidden")
            response, trace = self.recorder.request("DELETE", f"/api/v1/datasets/{ds['id']}/data/{self.facts[data['fact_key']]['id']}", actor=data["actor"])
            result = self._envelope(response, trace)
        else:
            raise WorkerScopeError("native_command_not_allowed")
        self._guard()
        return result

    def summary(self):
        return {"version": VERSION, "native_requests": deepcopy(self.recorder.requests) if self.recorder else [],
            "identities": deepcopy(self.identities), "datasets": deepcopy(self.datasets), "facts": deepcopy(self.facts),
            "network_events": deepcopy(self.guard.events), "inference_events": deepcopy(self.inference.events),
            "generation_attempts": sum(x["kind"] == "generation" for x in self.inference.events),
            "embedding_attempts": sum(x["kind"] == "embedding" for x in self.inference.events),
            "client_credential_values_persisted": False, "native_auth_storage_unmodified": True,
            "state": str(self.state), "stage": self.stage, "last_failure": deepcopy(self.last_failure),
            "limits": {**LIMITS, "http_requests": self.http_cap}, "file_scope": deepcopy(self.file_scope)}

    def close(self):
        try:
            if self.context is not None:
                self.context.__exit__(None, None, None); self.context = None
        finally:
            if self.dll_handle is not None:
                self.dll_handle.close(); self.dll_handle = None
            self.inference.close(); self.ready = False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("state", "wheel", "legacy-project"):
        parser.add_argument("--" + argument, type=Path, required=True)
    parser.add_argument("--openssl-dll-dir", type=Path)
    parser.add_argument("--http-cap", type=int, default=LIMITS["http_requests"])
    args = parser.parse_args()
    serve_commands(CogneePolicyWorker(state=args.state, wheel=args.wheel, legacy_project=args.legacy_project,
        openssl_dll_dir=args.openssl_dll_dir, http_cap=args.http_cap))
