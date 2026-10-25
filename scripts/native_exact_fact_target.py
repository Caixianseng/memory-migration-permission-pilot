"""Fresh native Open WebUI target; never loads the Mem0 SDK overlay."""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import secrets
import sys

if __package__:
    from .native_exact_fact_common import NetworkGuard, isolate_environment, serve_commands
else:
    from native_exact_fact_common import NetworkGuard, isolate_environment, serve_commands


MODEL_DISCOVERY_OFF = {"ENABLE_OLLAMA_API": "false", "ENABLE_OPENAI_API": "false",
    "OLLAMA_BASE_URL": "http://127.0.0.1:9", "OLLAMA_BASE_URLS": "http://127.0.0.1:9",
    "OLLAMA_API_BASE_URL": "http://127.0.0.1:9/api"}
SEMANTIC_QUERY = "Customer service and delivery status."


def disable_model_discovery():
    if any(name == "open_webui" or name.startswith("open_webui.") for name in sys.modules):
        raise ValueError("model_discovery_must_be_disabled_before_native_import")
    os.environ.update(MODEL_DISCOVERY_OFF)
    return dict(MODEL_DISCOVERY_OFF)


def load_native_application():
    from open_webui.main import app
    from open_webui import config
    return app, config


def configure_native_application(configure, state, assets, *, loader=None):
    # Legacy configure clears the environment. The explicit URLs must follow it
    # and precede config.py import, whose auto-probe ignores ENABLE_OLLAMA_API.
    settings, handle, egress = configure(state, assets)
    overrides = disable_model_discovery()
    app, native_config = (loader or load_native_application)()
    observed = {"ENABLE_OLLAMA_API": native_config.ENABLE_OLLAMA_API,
        "ENABLE_OPENAI_API": native_config.ENABLE_OPENAI_API,
        "OLLAMA_BASE_URL": native_config.OLLAMA_BASE_URL,
        "OLLAMA_BASE_URLS": native_config.OLLAMA_BASE_URLS}
    if (observed["ENABLE_OLLAMA_API"] is not False or observed["ENABLE_OPENAI_API"] is not False
            or observed["OLLAMA_BASE_URL"] != MODEL_DISCOVERY_OFF["OLLAMA_BASE_URL"]
            or observed["OLLAMA_BASE_URLS"] != [MODEL_DISCOVERY_OFF["OLLAMA_BASE_URL"]]):
        raise ValueError("model_discovery_off_configuration_not_observed")
    receipt = {"applied_after_legacy_configure_before_import_and_lifespan": True,
        "overrides": overrides, "observed_native_configuration": observed,
        "native_config_path": str(Path(native_config.__file__).resolve()),
        "native_config_sha256": hashlib.sha256(Path(native_config.__file__).read_bytes()).hexdigest(),
        "official_source": "https://github.com/open-webui/open-webui/blob/v0.12.3/backend/open_webui/config.py#L296",
        "network_allowlist_unchanged": True, "dead_endpoint_port_9_allowed": False}
    return settings, handle, egress, app, receipt


class TargetWorker:
    def __init__(self, *, state, assets, legacy_project):
        self.state, self.assets, self.legacy = map(Path, (state, assets, legacy_project))
        self.state.mkdir(parents=True, exist_ok=False)
        isolate_environment(self.state)
        self.guard = NetworkGuard()
        sys.addaudithook(self.guard)
        self.context = self.recorder = self.dll_handle = None
        self.embedding_invocations = 0
        self.stage = "target_created"

    def initialize(self, data):
        if data != {} or self.context is not None:
            raise ValueError("target_init_invalid")
        if importlib.metadata.version("open-webui") != "0.12.3":
            raise ValueError("target_version_not_pinned")
        sdk_fragment = "native_mem0_sdk_v1"
        if any(sdk_fragment in str(path) for path in sys.path):
            raise ValueError("source_overlay_must_not_enter_target")
        project = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(project))
        from memory_migration_study.native_webui import _legacy_configure, NativeRecorder, _create_identities
        configure, self.configuration_source = _legacy_configure(self.legacy)
        self.stage = "target_isolated_config"
        self.settings, self.dll_handle, self.legacy_egress, app, self.discovery_configuration = configure_native_application(
            configure, self.state, self.assets)
        from fastapi.testclient import TestClient
        import torch
        torch.set_num_threads(2)
        self.context = TestClient(app, raise_server_exceptions=False)
        self.stage = "target_native_lifespan"
        self.client = self.context.__enter__()
        if app.state.ef is None or not callable(app.state.EMBEDDING_FUNCTION):
            raise ValueError("target_local_embedding_unavailable")
        original = app.state.EMBEDDING_FUNCTION
        if inspect.iscoroutinefunction(original):
            async def counted(*args, **kwargs):
                self.embedding_invocations += 1
                return await original(*args, **kwargs)
        else:
            def counted(*args, **kwargs):
                self.embedding_invocations += 1
                return original(*args, **kwargs)
        app.state.EMBEDDING_FUNCTION = counted
        self.recorder = NativeRecorder(self.client, self.state/"responses")
        self.stage = "target_native_identities"
        self.identities = _create_identities(self.recorder)
        whoami_public = []
        for actor in ("owner", "assistant", "outsider"):
            response, trace = self.recorder.request("GET", "/api/v1/auths/", actor_id=actor)
            if response is None or trace["status"] != 200 or response.json().get("id") != self.identities[actor]["id"] or response.json().get("role") != "user":
                raise ValueError("target_whoami_not_qualified")
            whoami_public.append({"actor": actor, "id": response.json()["id"], "role": response.json()["role"],
                "native_request_index": trace["native_request_index"]})
        _, anonymous = self.recorder.request("GET", "/api/v1/memories/")
        if anonymous["status"] not in (401, 403):
            raise ValueError("target_anonymous_not_denied")
        self.stage = "target_ready"
        return {"open_webui_version": "0.12.3", "native_user_ids": {
            actor: self.identities[actor]["id"] for actor in ("owner", "assistant", "outsider")},
            "whoami_public_receipts": whoami_public,
            "anonymous_denied": True, "source_sdk_overlay_present": False,
            "model_discovery_disabled": True, "model_discovery_configuration": self.discovery_configuration,
            "agent_identity": "fixed_application_worker_not_native_agent_authentication"}

    def __call__(self, command, data):
        if command == "init":
            return self.initialize(data)
        if command == "close":
            self.close()
            return self.summary()
        if self.recorder is None:
            raise ValueError("target_not_initialized")
        if command == "add":
            if set(data) != {"actor", "text", "path"} or data["actor"] not in ("owner", "assistant") or not isinstance(data["text"], str) or not data["text"].strip():
                raise ValueError("target_add_invalid")
            from memory_migration_study.native_webui import _insert_memory
            rid = _insert_memory(self.recorder, data["actor"], self.identities[data["actor"]]["id"], data["text"], data["path"])
            return {"target_id": rid, "actor": data["actor"], "content": data["text"]}
        if command == "add_residents":
            if data:
                raise ValueError("target_resident_control_invalid")
            from memory_migration_study.native_webui import _insert_memory
            residents = []
            for actor in ("owner", "assistant", "outsider"):
                text = "Customer service status: unrelated resident for "+actor+" "+secrets.token_hex(12)
                path = "/resident-control/"+actor
                rid = _insert_memory(self.recorder, actor, self.identities[actor]["id"], text, path)
                residents.append({"target_id": rid, "actor": actor, "content": text, "path": path})
            return {"residents": residents}
        if command == "delete":
            if set(data) != {"actor", "target_id"} or data["actor"] not in ("owner", "assistant"):
                raise ValueError("target_delete_invalid")
            response, trace = self.recorder.request("DELETE", "/api/v1/memories/"+data["target_id"], actor_id=data["actor"])
            return {"status": trace["status"], "deleted": response.json() if response is not None else None,
                    "target_id": data["target_id"], "actor": data["actor"]}
        if command == "snapshot":
            if set(data) != {"target_ids"} or not isinstance(data["target_ids"], list):
                raise ValueError("target_snapshot_invalid")
            rows = []
            for actor in ("owner", "assistant", "outsider"):
                for operation, path, body in [("list", "/api/v1/memories/", None),
                        ("lexical", "/api/v1/memories/search", {"query": "Customer", "type": "all", "limit": 100}),
                        *[("known_id", "/api/v1/memories/search", {"memory_id": rid, "type": "all", "limit": 1}) for rid in data["target_ids"]]]:
                    response, trace = self.recorder.request("GET" if body is None else "POST", path,
                        actor_id=actor, payload=body)
                    value = response.json() if response is not None and trace["status"] == 200 else None
                    rows.append({"actor": actor, "operation": operation, "requested_id": body.get("memory_id") if body else None,
                        "status": trace["status"], "items": value, "response_checked": trace.get("response_checked"),
                        "execution_error": trace.get("execution_error"), "native_body_sha256": trace.get("native_body_sha256"),
                        "native_raw_body": trace.get("native_raw_body")})
                response, trace = self.recorder.request("POST", "/api/v1/memories/query", actor_id=actor,
                    payload={"content": SEMANTIC_QUERY, "k": 100})
                try:
                    value = response.json() if response is not None else None
                except (TypeError, ValueError):
                    value = None
                rows.append({"actor": actor, "operation": "semantic", "requested_id": None,
                    "query": SEMANTIC_QUERY, "k": 100, "status": trace["status"], "vector_result": value,
                    "response_checked": trace.get("response_checked"), "execution_error": trace.get("execution_error"),
                    "native_body_sha256": trace.get("native_body_sha256"), "native_raw_body": trace.get("native_raw_body")})
            return {"rows": rows}
        if command == "report":
            return self.summary()
        raise ValueError("unknown_target_command")

    def summary(self):
        return {"native_requests": list(self.recorder.requests) if self.recorder else [],
            "network_events": list(self.guard.events), "native_embedding_function_invocations": self.embedding_invocations,
            "generation_attempts": 0, "credential_values_persisted": False,
            "model_discovery_configuration": getattr(self, "discovery_configuration", None),
            "configuration_source": getattr(self, "configuration_source", None)}

    def close(self):
        if self.context is not None:
            self.context.__exit__(None, None, None)
            self.context = None
        if self.dll_handle is not None:
            self.dll_handle.close()
            self.dll_handle = None


def main():
    parser = argparse.ArgumentParser()
    for name in ("state", "assets", "legacy-project"):
        parser.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    serve_commands(TargetWorker(state=args.state, assets=args.assets, legacy_project=args.legacy_project))


if __name__ == "__main__":
    main()
