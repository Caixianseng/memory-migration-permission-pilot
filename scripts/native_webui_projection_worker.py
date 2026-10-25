"""Bounded official Open WebUI HTTP projection through owner files and Note ACLs.

No native calls run on import. Actual init is restricted to a fresh ASCII temp
state and pinned vendor files. User/Agent pairs are distinct native USER
accounts; this is not first-class Agent IAM, a vector benchmark or automatic
cross-system revocation. Do not replace native auth/ACL/storage functions.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from scripts.native_exact_fact_common import NetworkGuard, isolate_environment, serve_commands

VERSION = "native_webui_note_file_projection_worker_v1"
EXPECTED_VERSION = "0.12.3"
MAX_HTTP = 200
ACTORS = ("owner", "alice_reader", "alice_worker", "bob_reader", "bob_worker")
DATASETS = ("readonly", "managed")
FROZEN_VENDOR = {
    "main.py": "1c304a6f0922e044d71b14640e08249dbdd53f16fcb2d15c69c572700aa62340",
    "config.py": "03cad3c2f13921d34354bea8f882aabb4e788262a45c097314ea83983501f284",
    "routers/auths.py": "f32e2e742406555551a091983703a674445a9589c39689dcb6ea934c194a7f18",
    "routers/files.py": "a8bba0ef436e95c955b23b738f5498b8fe0fe14cf3ad374f5c07025394c45c78",
    "routers/notes.py": "1cd8b24bf09a79f8e4faefdc183d78f9ba176bab61a49f4f0ab843ac33bad9df",
    "routers/knowledge.py": "40fc15da1f21489ddcf9e975bf46a9b80cd8f9330ddcac249fa7b2a524ccf22e",
    "routers/retrieval.py": "64931fc93e722ef5b9ff692166afd5632b02d7574619e1368d1ab1d184a4bd77",
    "models/notes.py": "31df0e16ad47e40b32e47fb673142ac89cb9fc9df39c84a8c65131bcf6a49888",
    "models/access_grants.py": "8887a1b25fb041f73bcc5696bc57765f8c07c0cd3ab3f4eb6cb8f139e7ccfe71",
    "utils/access_control/__init__.py": "c0c6f04782e321e770957f29c7296b6ed9b37b33e4908758354ef0bbd36221a0",
    "utils/access_control/files.py": "87d406ca2b5e4846e0d8ddc9403d42ee3dda33cc6f52e6919ce0352ef3202f18",
    "retrieval/utils.py": "23cfb06e1e9da4da206991c9a14f6e26470320cba71300ab13e4a899fde0dbf5"
}
MODEL_DISCOVERY_OFF = {"ENABLE_OLLAMA_API": "false", "ENABLE_OPENAI_API": "false",
    "OLLAMA_BASE_URL": "http://127.0.0.1:9", "OLLAMA_BASE_URLS": "http://127.0.0.1:9",
    "OLLAMA_API_BASE_URL": "http://127.0.0.1:9/api"}


class ProjectionError(ValueError):
    """Fixed codes only; native exception messages are not receipts."""


def require(condition, code):
    if not condition:
        raise ProjectionError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(response):
    try:
        return response.json()
    except (ValueError, UnicodeError):
        return None


def _private_fields(value):
    if isinstance(value, dict):
        prohibited = {"password", "hashed_password", "password_hash", "token", "access_token",
            "refresh_token", "api_key", "apikey", "authorization", "session_token"}
        return bool({str(k).lower() for k in value} & prohibited) or any(_private_fields(v) for v in value.values())
    return isinstance(value, list) and any(_private_fields(v) for v in value)


class SafeHTTPRecorder:
    """Native HTTP bytes with an actual request cap; credentials remain in RAM."""
    def __init__(self, client, directory, *, http_cap):
        require(type(http_cap) is int and 1 <= http_cap <= MAX_HTTP, "invalid_http_cap")
        self.client, self.directory, self.http_cap = client, Path(directory), http_cap
        self.directory.mkdir(parents=True, exist_ok=False)
        self.tokens, self.secret_values, self.requests = {}, [], []

    def remember(self, value):
        require(isinstance(value, str) and bool(value), "invalid_credential")
        self.secret_values.append(value.encode("utf-8"))

    def request(self, method, path, *, actor=None, credential=False, **kwargs):
        require(len(self.requests) < self.http_cap, "native_http_cap_exhausted")
        require(actor is None or actor in self.tokens, "unknown_native_credential_handle")
        self.client.cookies.clear()
        headers = {"Authorization": "Bearer " + self.tokens[actor]} if actor is not None else {}
        row = {"index": len(self.requests), "method": method, "path": path, "actor": actor,
            "started_ns": time.perf_counter_ns(), "credential_response_omitted": credential,
            "authorization_present": False, "api_key_present": False, "cookie_present": False}
        if not credential:
            for name in ("json", "params", "data"):
                if name in kwargs:
                    row["request_" + name] = deepcopy(kwargs[name])
            if "files" in kwargs:
                row["request_files"] = []
                for field, (filename, content, media_type) in kwargs["files"].items():
                    require(isinstance(content, bytes), "multipart_bytes_required")
                    row["request_files"].append({"field": field, "filename": filename,
                        "raw_data": content.decode("utf-8"), "bytes": len(content),
                        "sha256": sha(content), "media_type": media_type})
        try:
            response = self.client.request(method, path, headers=headers, **kwargs)
            actual = getattr(getattr(response, "request", None), "headers", headers)
            row.update(status=response.status_code,
                authorization_present=bool(actual.get("authorization") or actual.get("Authorization")),
                cookie_present=bool(actual.get("cookie")), response_checked=False, execution_error=None)
            require(not row["cookie_present"], "native_cookie_contamination")
            if not credential:
                raw = bytes(response.content)
                require(len(raw) <= 2 * 1024 * 1024, "native_response_too_large")
                require(not any(secret in raw for secret in self.secret_values), "credential_value_in_response")
                require(not _private_fields(_json(response)), "credential_field_in_response")
                destination = self.directory / f"{row['index']:04d}.bin"
                with destination.open("xb") as out:
                    out.write(raw)
                row.update(native_raw_body=raw.decode("utf-8"), native_body_sha256=sha(raw),
                    byte_count=len(raw), native_response_file=str(destination.resolve()))
            row["response_checked"] = True
            return response, row
        except Exception as error:
            row.setdefault("status", None)
            row.update(response_checked=False, execution_error=type(error).__name__)
            raise
        finally:
            row["finished_ns"] = time.perf_counter_ns()
            self.requests.append(row)


class InferenceBoundary:
    """Observed Python inference entries, not hardware attestation."""
    def __init__(self):
        self.events, self.installed = [], False
        self.callback = self._profile

    @staticmethod
    def classify(module, name):
        if (module == "open_webui.retrieval.utils" and name in {"async_embedding_function", "generate_embeddings", "encode"}) or (
            module == "open_webui.routers.knowledge" and name == "embed_knowledge_base_metadata"):
            return "embedding"
        if module.startswith(("sentence_transformers", "fastembed")) and name in {"encode", "encode_query", "encode_document", "embed", "query_embed", "forward"}:
            return "embedding"
        if module.startswith("litellm") and name in {"embedding", "aembedding"}:
            return "embedding"
        if (module.startswith("openai.resources") and name == "create") or (
            module.startswith("litellm") and name in {"completion", "acompletion"}) or (
            module.startswith("open_webui.utils.chat") and name in {"generate_chat_completion", "generate_chat_completions"}):
            return "generation"
        return None

    def _profile(self, frame, event, _arg):
        if event == "call":
            module, name = str(frame.f_globals.get("__name__", "")), frame.f_code.co_name
            kind = self.classify(module, name)
            if kind:
                self.events.append({"kind": kind, "module": module, "function": name})
                raise ProjectionError("unexpected_native_inference_entry")

    def install(self):
        require(not self.installed, "inference_guard_already_installed")
        self.previous, self.previous_threads = sys.getprofile(), threading.getprofile()
        sys.setprofile(self.callback)
        threading.setprofile(self.callback)
        self.installed = True

    def verify(self):
        require(self.installed and sys.getprofile() is self.callback and threading.getprofile() is self.callback
            and not self.events, "inference_guard_changed_or_attempted")

    def close(self):
        if self.installed:
            sys.setprofile(self.previous)
            threading.setprofile(self.previous_threads)
            self.installed = False


def configure(state):
    """Official environment settings only, before any vendor import."""
    isolate_environment(state)
    settings = {"FROM_INIT_PY": "true", "DATA_DIR": str(state / "data"),
        "STATIC_DIR": str(state / "static"), "CACHE_DIR": str(state / "cache"),
        "DATABASE_URL": "sqlite:///" + (state / "data/webui.db").as_posix(),
        "OFFLINE_MODE": "true", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
        "PYTHON_DOTENV_DISABLED": "1", "DO_NOT_TRACK": "1", "ANONYMIZED_TELEMETRY": "False",
        "ENABLE_OTEL": "false", "ENABLE_VERSION_UPDATE_CHECK": "false",
        "ENABLE_OAUTH": "false", "ENABLE_LDAP": "false", "ENABLE_TOOL_SERVERS": "false",
        "ENABLE_COMMUNITY_SHARING": "false", "ENABLE_INITIAL_ADMIN_SIGNUP": "true",
        "ENABLE_LOGIN_FORM": "true", "ENABLE_SIGNUP": "false", "DEFAULT_USER_ROLE": "user",
        "WEBUI_AUTH": "true", "RAG_EMBEDDING_ENGINE": "", "RAG_EMBEDDING_MODEL": "",
        "RAG_EMBEDDING_MODEL_AUTO_UPDATE": "false", "RAG_EMBEDDING_MODEL_TRUST_REMOTE_CODE": "false",
        "ENABLE_HYBRID_SEARCH": "false", "ENABLE_MEMORIES": "true",
        "USE_CUDA_DOCKER": "false", **MODEL_DISCOVERY_OFF}
    os.environ.update(settings)
    os.environ["WEBUI_SECRET_KEY"] = secrets.token_urlsafe(48)
    (state / "data").mkdir()
    return settings


def _vendor_preflight():
    dist = importlib.metadata.distribution("open-webui")
    require(dist.version == EXPECTED_VERSION, "native_webui_version_changed")
    hashes = {}
    for name, expected in FROZEN_VENDOR.items():
        path = Path(dist.locate_file("open_webui/" + name))
        require(path.is_file() and sha(path.read_bytes()) == expected, "native_webui_source_changed")
        hashes[name] = expected
    return hashes


def create_identities(recorder):
    identities = {}
    for actor in ("bootstrap_admin", *ACTORS):
        email = "controlled-projection-" + actor + "-" + secrets.token_hex(6) + "@example.com"
        password = "Research-" + secrets.token_urlsafe(24)
        recorder.remember(password)
        body = {"email": email, "password": password, "name": "controlled-" + actor}
        if actor == "bootstrap_admin":
            path, issuer = "/api/v1/auths/signup", None
        else:
            path, issuer = "/api/v1/auths/add", "bootstrap_admin"
            body["role"] = "user"
        response, trace = recorder.request("POST", path, actor=issuer, credential=True, json=body)
        require(trace["status"] == 200, "native_user_creation_failed")
        response, trace = recorder.request("POST", "/api/v1/auths/signin", credential=True,
            json={"email": email, "password": password})
        value = _json(response)
        role = "admin" if actor == "bootstrap_admin" else "user"
        require(trace["status"] == 200 and isinstance(value, dict) and value.get("role") == role
            and value.get("email") == email and isinstance(value.get("id"), str)
            and isinstance(value.get("token"), str) and bool(value["token"]), "native_signin_failed")
        recorder.tokens[actor] = value["token"]
        recorder.remember(value["token"])
        identities[actor] = {"id": value["id"], "role": role, "credential_kind": "bearer"}
    require(len({v["id"] for v in identities.values()}) == 6
        and len(set(recorder.tokens.values())) == 6, "native_identity_collision")
    for actor in ACTORS:
        response, trace = recorder.request("GET", "/api/v1/auths/", actor=actor, credential=True)
        value = _json(response)
        require(trace["status"] == 200 and isinstance(value, dict) and value.get("id") == identities[actor]["id"]
            and value.get("role") == "user", "native_whoami_not_qualified")
        identities[actor]["whoami_request_index"] = trace["index"]
    return identities


class WebUIProjectionWorker:
    def __init__(self, *, state, http_cap=MAX_HTTP, openssl_dll_dir=None):
        require(type(http_cap) is int and 1 <= http_cap <= MAX_HTTP, "invalid_http_cap")
        self.state = Path(state).resolve()
        temp = Path(tempfile.gettempdir()).resolve()
        require(self.state.is_relative_to(temp) and self.state != temp and str(self.state).isascii()
            and not self.state.exists(), "new_ascii_system_temp_state_required")
        self.http_cap = http_cap
        self.openssl = Path(openssl_dll_dir).resolve() if openssl_dll_dir else None
        self.context = self.recorder = self.dll_handle = None
        self.guard, self.inference = NetworkGuard(), InferenceBoundary()
        self.identities, self.datasets, self.facts, self.readers = {}, {}, {}, {}
        self.ready, self.stage, self.last_failure = False, "uninitialized", None

    def initialize(self, data):
        require(data == {} and not self.ready and self.context is None, "native_init_invalid")
        require(not any(n == "open_webui" or n.startswith("open_webui.") for n in sys.modules),
            "fresh_vendor_process_required")
        self.stage = "native_source_preflight"
        self.vendor_hashes = _vendor_preflight()
        self.state.mkdir(parents=True, exist_ok=False)
        self.settings = configure(self.state)
        sys.addaudithook(self.guard)
        self.inference.install()
        if self.openssl is not None:
            require(all((self.openssl / n).is_file() for n in ("libssl-3-x64.dll", "libcrypto-3-x64.dll")), "existing_openssl3_dlls_required")
            self.dll_handle = os.add_dll_directory(str(self.openssl))
        self.stage = "native_application_lifespan"
        from open_webui.main import app
        from open_webui import config as native_config
        require(native_config.ENABLE_OLLAMA_API is False and native_config.ENABLE_OPENAI_API is False
            and native_config.OLLAMA_BASE_URL == MODEL_DISCOVERY_OFF["OLLAMA_BASE_URL"]
            and native_config.OLLAMA_BASE_URLS == [MODEL_DISCOVERY_OFF["OLLAMA_BASE_URL"]]
            and native_config.RAG_EMBEDDING_ENGINE == "" and native_config.RAG_EMBEDDING_MODEL == "",
            "native_declared_no_model_configuration_not_observed")
        from fastapi.testclient import TestClient
        self.context = TestClient(app, raise_server_exceptions=False)
        self.client = self.context.__enter__()
        require(app.state.ef is None, "native_encoder_unexpectedly_loaded")
        self.recorder = SafeHTTPRecorder(self.client, self.state / "safe_responses", http_cap=self.http_cap)
        self.stage = "native_independent_identities"
        self.identities = create_identities(self.recorder)
        _, anonymous = self.recorder.request("GET", "/api/v1/notes/")
        require(anonymous["status"] in {401, 403}, "native_anonymous_access_not_denied")
        self.inference.verify()
        require(all(e.get("allowed") is True for e in self.guard.events), "unapproved_network_attempt")
        self.ready, self.stage = True, "native_projection_ready"
        return {"version": VERSION, "open_webui_version": EXPECTED_VERSION,
            "identities": deepcopy({k: v for k, v in self.identities.items() if k != "bootstrap_admin"}),
            "bootstrap_admin": deepcopy(self.identities["bootstrap_admin"]),
            "identity_representation": "independent_native_user_accounts_per_trusted_user_agent_tuple",
            "native_agent_authentication": False, "storage_kind": "native_owner_file_plus_note_read_acl",
            "vendor_source_sha256": self.vendor_hashes, "limits": {"http_requests": self.http_cap, "datasets": 2, "facts": 2, "fact_chars": 4096},
            "configuration": {"embedding_engine": "", "embedding_model": "", "local_encoder_loaded": False,
                "model_apis_enabled": False, "vector_or_semantic_search_measured": False},
            "client_credentials_saved": False, "native_auth_storage_unmodified": True,
            "projection_matrix_qualified": False}

    def _scope(self, data, fields):
        require(self.ready and self.recorder is not None, "native_not_initialized")
        require(isinstance(data, dict) and set(data) == set(fields), "invalid_command_fields")
        require(data.get("actor") in ACTORS, "invalid_native_actor")
        if "dataset" in fields:
            require(data["dataset"] in DATASETS, "invalid_logical_dataset")

    def _response(self, response, trace, **extra):
        self.inference.verify()
        require(all(e.get("allowed") is True for e in self.guard.events), "unapproved_network_attempt")
        return {"status": trace["status"], "trace": trace, **extra}

    def _create_dataset(self, data):
        self._scope(data, ("dataset", "actor"))
        dataset, actor = data["dataset"], data["actor"]
        require(actor == "owner" and dataset not in self.datasets, "new_owner_dataset_required")
        title = "controlled_" + dataset + "_" + secrets.token_hex(6)
        body = {"title": title, "data": {"content": {"md": ""}, "files": []}, "access_grants": []}
        response, trace = self.recorder.request("POST", "/api/v1/notes/create", actor=actor, json=body)
        value = _json(response)
        if trace["status"] == 200 and isinstance(value, dict) and isinstance(value.get("id"), str):
            require(value.get("user_id") == self.identities["owner"]["id"] and value.get("access_grants") == [], "native_container_owner_or_acl_mismatch")
            self.datasets[dataset] = {"id": value["id"], "name": title, "owner": "owner", "kind": "native_note_acl_container"}
            self.readers[dataset] = set()
        selected = self.datasets.get(dataset)
        return self._response(response, trace, id=selected["id"] if selected else None,
            name=selected["name"] if selected else None, owner="owner", logical_dataset=dataset,
            dataset=deepcopy(selected))

    def _add_fact(self, data):
        self._scope(data, ("dataset", "fact_key", "actor", "text"))
        dataset, key, text = data["dataset"], data["fact_key"], data["text"]
        require(data["actor"] == "owner" and dataset in self.datasets and key == dataset and key not in self.facts
            and isinstance(text, str) and 0 < len(text) <= 4096, "invalid_exact_fact")
        raw = text.encode("utf-8")
        response, upload = self.recorder.request("POST", "/api/v1/files/", actor="owner",
            params={"process": "false", "process_in_background": "false"},
            files={"file": ("controlled_" + key + ".txt", raw, "text/plain")})
        value = _json(response)
        require(upload["status"] == 200 and isinstance(value, dict) and isinstance(value.get("id"), str)
            and value.get("user_id") == self.identities["owner"]["id"], "native_exact_file_upload_failed")
        fid = value["id"]
        require(all(f["id"] != fid for f in self.facts.values()), "native_fact_id_collision")
        note = self.datasets[dataset]
        body = {"title": note["name"], "data": {"content": {"md": ""}, "files": [{"type": "file", "id": fid}]}}
        response, attach = self.recorder.request("POST", "/api/v1/notes/" + note["id"] + "/update",
            actor="owner", json=body)
        attached = _json(response)
        require(attach["status"] == 200 and isinstance(attached, dict)
            and attached.get("data", {}).get("files") == [{"type": "file", "id": fid}], "native_note_file_attachment_failed")
        self.facts[key] = {"id": fid, "dataset": dataset, "text_sha256": sha(raw), "bytes": len(raw)}
        response, raw_trace = self.recorder.request("GET", "/api/v1/files/" + fid + "/content", actor="owner")
        require(raw_trace["status"] == 200 and bytes(response.content) == raw, "native_exact_file_bytes_not_preserved")
        return self._response(response, raw_trace, id=fid, dataset=dataset, text_sha256=sha(raw),
            add_trace=upload, attach_trace=attach, raw_trace=raw_trace)

    def _acl(self, command, data):
        self._scope(data, ("dataset", "actor", "recipient", "permission"))
        dataset = data["dataset"]
        require(dataset in self.datasets and data["recipient"] in ACTORS and data["permission"] == "read", "invalid_native_acl_scope")
        desired = set(self.readers[dataset])
        if command == "grant":
            desired.add(data["recipient"])
        else:
            desired.discard(data["recipient"])
        grants = [{"principal_type": "user", "principal_id": self.identities[a]["id"], "permission": "read"}
            for a in sorted(desired)]
        response, trace = self.recorder.request("POST", "/api/v1/notes/" + self.datasets[dataset]["id"] + "/access/update",
            actor=data["actor"], json={"access_grants": grants})
        value = _json(response)
        if trace["status"] == 200:
            require(isinstance(value, dict) and isinstance(value.get("access_grants"), list), "native_acl_response_invalid")
            observed = {(g["principal_type"], g["principal_id"], g["permission"]) for g in value["access_grants"]}
            intended = {(g["principal_type"], g["principal_id"], g["permission"]) for g in grants}
            require(observed == intended, "native_acl_response_not_exact_requested_set")
            self.readers[dataset] = desired
        return self._response(response, trace, operation=command, dataset=dataset, recipient=data["recipient"])

    def _read(self, data):
        self._scope(data, ("dataset", "fact_key", "actor"))
        require(data["dataset"] in self.datasets and data["fact_key"] in self.facts
            and self.facts[data["fact_key"]]["dataset"] == data["dataset"], "unknown_controlled_fact")
        fid = self.facts[data["fact_key"]]["id"]
        response, trace = self.recorder.request("GET", "/api/v1/files/" + fid + "/content", actor=data["actor"])
        return self._response(response, trace)

    def _list_data(self, data):
        self._scope(data, ("dataset", "actor"))
        require(data["dataset"] in self.datasets, "unknown_controlled_dataset")
        response, trace = self.recorder.request("GET", "/api/v1/notes/" + self.datasets[data["dataset"]]["id"], actor=data["actor"])
        return self._response(response, trace)

    def _list_datasets(self, data):
        self._scope(data, ("actor",))
        response, trace = self.recorder.request("GET", "/api/v1/notes/", actor=data["actor"])
        return self._response(response, trace)

    def _bypass(self, data):
        self._scope(data, ("dataset", "fact_key", "actor", "operation"))
        require(data["dataset"] in self.datasets and data["fact_key"] in self.facts
            and self.facts[data["fact_key"]]["dataset"] == data["dataset"], "unknown_controlled_fact")
        fid = self.facts[data["fact_key"]]["id"]
        options = {"file_metadata": ("/api/v1/files/" + fid, None),
            "file_data_content": ("/api/v1/files/" + fid + "/data/content", None),
            "file_content_html": ("/api/v1/files/" + fid + "/content/html", None),
            "file_content_named": ("/api/v1/files/" + fid + "/content/controlled.txt", None),
            "file_list": ("/api/v1/files/", {"page": 1, "content": "true"}),
            "file_search": ("/api/v1/files/search", {"filename": "controlled_*", "content": "true", "limit": 100}),
            "note_search": ("/api/v1/notes/search", {"query": "controlled_", "page": 1})}
        require(data["operation"] in options, "unsupported_bypass_operation")
        path, params = options[data["operation"]]
        kwargs = {"params": params} if params is not None else {}
        response, trace = self.recorder.request("GET", path, actor=data["actor"], **kwargs)
        return self._response(response, trace)

    def __call__(self, command, data):
        try:
            if command == "init":
                return self.initialize(data)
            if command in {"summary", "report"}:
                require(data == {}, "invalid_summary_fields")
                return self.summary()
            if command == "close":
                require(data == {}, "invalid_close_fields")
                self.close()
                return self.summary()
            if command == "create_dataset":
                return self._create_dataset(data)
            if command == "add_exact_fact":
                return self._add_fact(data)
            if command in {"grant", "revoke"}:
                return self._acl(command, data)
            if command == "read_raw":
                return self._read(data)
            if command == "list_data":
                return self._list_data(data)
            if command == "list_datasets":
                return self._list_datasets(data)
            if command == "bypass":
                return self._bypass(data)
            if command == "snapshot":
                require(data == {} and self.ready, "invalid_snapshot_fields")
                rows = []
                for actor in ACTORS[1:]:
                    rows.append({"actor": actor, "operation": "list_datasets", **self._list_datasets({"actor": actor})})
                    for key, fact in self.facts.items():
                        args = {"dataset": fact["dataset"], "fact_key": key, "actor": actor}
                        rows.append({"actor": actor, "fact_key": key, "operation": "read_raw", **self._read(args)})
                        rows.append({"actor": actor, "dataset": fact["dataset"], "operation": "list_data",
                            **self._list_data({"dataset": fact["dataset"], "actor": actor})})
                return {"rows": rows}
            raise ProjectionError("unsupported_native_command")
        except Exception as error:
            self.last_failure = {"command": command, "stage": self.stage, "type": type(error).__name__,
                "code": str(error) if isinstance(error, ProjectionError) else "native_operation_failed"}
            raise

    def summary(self):
        return {"version": VERSION, "open_webui_version": EXPECTED_VERSION, "stage": self.stage,
            "identities": deepcopy({k: v for k, v in self.identities.items() if k != "bootstrap_admin"}),
            "bootstrap_admin": deepcopy(self.identities.get("bootstrap_admin")),
            "datasets": deepcopy(self.datasets), "facts": deepcopy(self.facts),
            "native_requests": deepcopy(self.recorder.requests) if self.recorder else [],
            "network_events": deepcopy(self.guard.events), "inference_events": deepcopy(self.inference.events),
            "generation_attempts": sum(e["kind"] == "generation" for e in self.inference.events),
            "embedding_attempts": sum(e["kind"] == "embedding" for e in self.inference.events),
            "native_auth_storage_unmodified": True, "client_credential_values_persisted": False,
            "native_agent_authentication": False, "storage_kind": "native_owner_file_plus_note_read_acl",
            "native_agent_representation": "explicit_composite_native_user_accounts",
            "vector_or_semantic_search_measured": False, "last_failure": deepcopy(self.last_failure),
            "limits": {"http_requests": self.http_cap, "datasets": 2, "facts": 2, "fact_chars": 4096},
            "scope": "Native HTTP file/Note read ACL projection only; no automatic cross-backend revocation or complete protocol claim."}

    def close(self):
        try:
            if self.context is not None:
                self.context.__exit__(None, None, None)
                self.context = None
        finally:
            self.inference.close()
            if self.dll_handle is not None:
                self.dll_handle.close()
                self.dll_handle = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--http-cap", type=int, default=MAX_HTTP)
    parser.add_argument("--openssl-dll-dir", type=Path)
    args = parser.parse_args()
    serve_commands(WebUIProjectionWorker(state=args.state, http_cap=args.http_cap,
        openssl_dll_dir=args.openssl_dll_dir))


if __name__ == "__main__":
    main()

