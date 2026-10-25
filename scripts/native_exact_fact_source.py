"""Fresh Mem0 SDK source and explicit research ACL gateway, invoked by launcher."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import secrets
import sys
import urllib.request

if __package__:
    from .native_exact_fact_common import NetworkGuard, isolate_environment, serve_commands
else:
    from native_exact_fact_common import NetworkGuard, isolate_environment, serve_commands


class MutableResearchACL:
    """Changes only the trusted reference, using the existing frozen RecordACL."""
    def __init__(self, factory, readers, names):
        self.factory, self.names, self.current = factory, list(names), factory(readers, names)
    @property
    def readers(self):
        return self.current.readers
    def allows(self, principal, record_id):
        return self.current.allows(principal, record_id)
    def revoke(self, record_id):
        replacement = {key: list(value) for key, value in self.current.readers.items()}
        replacement[record_id] = []
        self.current = self.factory(replacement, self.names)


class TrustedMigrationControl:
    """Host-controlled migration metadata, never parsed from stored memory text."""
    def __init__(self):
        self.records = {}

    def register(self, fact_key, source_id, text, migration_policy):
        if fact_key in self.records or not isinstance(migration_policy, dict):
            raise ValueError("trusted_migration_control_invalid")
        self.records[fact_key] = {"source_id": source_id,
            "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "migration_policy": deepcopy(migration_policy)}

    def update(self, fact_key, migration_policy):
        if fact_key not in self.records or not isinstance(migration_policy, dict):
            raise ValueError("trusted_migration_policy_update_invalid")
        self.records[fact_key]["migration_policy"] = deepcopy(migration_policy)

    def read(self, fact_key, source_readers):
        return {**deepcopy(self.records[fact_key]), "source_readers": list(source_readers)}


class SourceWorker:
    def __init__(self, *, state, sdk_root, model, legacy_project):
        self.state, self.sdk_root, self.model, self.legacy = map(Path, (state, sdk_root, model, legacy_project))
        self.state.mkdir(parents=True, exist_ok=False)
        isolate_environment(self.state)
        self.guard = NetworkGuard()
        sys.addaudithook(self.guard)
        self.memory = self.server = self.thread = None
        self.rows, self.tokens, self.requests = {}, {}, []
        self.migration_control = TrustedMigrationControl()
        self.embedding_invocations = self.embedding_texts = self.llm_attempts = 0
        self.embedding_events = []
        self.stage = "source_created"

    def initialize(self, data):
        if self.memory is not None or set(data) != {"records"} or not isinstance(data["records"], list):
            raise ValueError("source_init_invalid")
        sys.path.insert(0, str(self.sdk_root.resolve()/"site-packages"))
        sys.path.insert(0, str(self.legacy.resolve()/"scripts"))
        from mem0 import Memory
        from qualify_migration import Principal, BoundIdentity, RecordACL, gateway_server
        if importlib.metadata.version("mem0ai") != "2.2.1":
            raise ValueError("source_version_not_pinned")
        self.stage = "source_memory_config"
        self.memory = Memory.from_config({
            "llm": {"provider": "openai", "config": {"model": "never-generate-native-bridge",
                "api_key": "local-only-not-a-secret", "openai_base_url": "http://127.0.0.1:9/v1"}},
            "embedder": {"provider": "huggingface", "config": {"model": str(self.model.resolve()),
                "embedding_dims": 384, "model_kwargs": {"device": "cpu", "local_files_only": True}}},
            "vector_store": {"provider": "qdrant", "config": {"collection_name": "exact_fact_bridge",
                "path": str(self.state/"qdrant"), "embedding_model_dims": 384}},
            "history_db_path": str(self.state/"history.db")})
        for name in ("embed", "embed_batch"):
            original = getattr(self.memory.embedding_model, name, None)
            if original is None:
                continue
            def counted(value, *args, _original=original, _method=name, **kwargs):
                self.embedding_invocations += 1
                self.embedding_texts += len(value) if isinstance(value, list) else 1
                self.embedding_events.append({"method": _method, "text_count": len(value) if isinstance(value, list) else 1})
                return _original(value, *args, **kwargs)
            setattr(self.memory.embedding_model, name, counted)
        def forbid_generation(*args, **kwargs):
            self.llm_attempts += 1
            raise PermissionError("generative_calls_forbidden")
        self.memory.llm.generate_response = forbid_generation
        readers = {}
        for item in data["records"]:
            self.stage = "source_raw_write"
            if (not isinstance(item, dict) or set(item) != {"fact_key", "text", "readers", "migration_policy"}
                    or item["fact_key"] in self.rows or not isinstance(item["text"], str)):
                raise ValueError("source_record_invalid")
            added = self.memory.add(item["text"], user_id="trusted_controlled_storage", infer=False)
            if not isinstance(added, dict) or len(added.get("results", [])) != 1:
                raise ValueError("native_mem0_raw_add_failed")
            rid = added["results"][0]["id"]
            row = self.memory.get(rid)
            if not isinstance(row, dict) or row.get("memory") != item["text"]:
                raise ValueError("native_mem0_readback_mismatch")
            self.rows[item["fact_key"]] = rid
            readers[rid] = item["readers"]
            self.migration_control.register(item["fact_key"], rid, item["text"], item["migration_policy"])
        names = ["owner", "assistant", "outsider"]
        people = {name: Principal(name, "trusted_controlled_storage", "", "") for name in names}
        self.tokens = {name: secrets.token_urlsafe(32) for name in names}
        identities = BoundIdentity({self.tokens[name]: people[name] for name in names})
        self.acl = MutableResearchACL(RecordACL, readers, names)
        self.stage = "source_gateway_start"
        self.server, self.thread = gateway_server(self.memory, None, identities, record_acl=self.acl)
        self.guard.allowed_ports.add(self.server.server_port)
        self.stage = "source_ready"
        return {"rows": dict(self.rows), "mem0_version": "2.2.1", "embedding_dimensions": 384,
            "infer": False, "native_mem0_user_authentication": False, "research_acl_gateway": True,
            "sdk_module": str(Path(sys.modules["mem0"].__file__).resolve()),
            "gateway_host": "127.0.0.1", "gateway_port": self.server.server_port}

    def __call__(self, command, data):
        if command == "init":
            return self.initialize(data)
        if command == "close":
            self.close()
            return self.summary()
        if self.memory is None:
            raise ValueError("source_not_initialized")
        if command == "read":
            if set(data) != {"fact_key", "actor"} or data["actor"] not in self.tokens:
                raise ValueError("source_read_invalid")
            rid = self.rows[data["fact_key"]]
            request = urllib.request.Request(f"http://127.0.0.1:{self.server.server_port}/source/records/{rid}",
                headers={"Authorization": "Bearer "+self.tokens[data["actor"]]})
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    status, raw = response.status, response.read().decode("utf-8")
            except urllib.error.HTTPError as error:
                status, raw = error.code, error.read().decode("utf-8")
            result = {"status": status, "body": json.loads(raw), "authenticated_principal": data["actor"], "record_id": rid}
            if status == 200:
                result["trusted_migration_control"] = self.migration_control.read(data["fact_key"], self.acl.readers[rid])
            self.requests.append(result)
            return result
        if command == "set_migration_policy":
            if set(data) != {"fact_key", "migration_policy"}:
                raise ValueError("source_migration_policy_update_invalid")
            self.migration_control.update(data["fact_key"], data["migration_policy"])
            return {"updated": True, "record_id": self.rows[data["fact_key"]]}
        if command == "revoke":
            if set(data) != {"fact_key"}:
                raise ValueError("source_revoke_invalid")
            self.acl.revoke(self.rows[data["fact_key"]])
            return {"revoked": True, "record_id": self.rows[data["fact_key"]]}
        raise ValueError("unknown_source_command")

    def summary(self):
        return {"mem0_embedding_method_invocations": self.embedding_invocations, "embedding_texts": self.embedding_texts,
            "embedding_method_events": list(self.embedding_events),
            "embedding_count_unit": "instrumented SDK method invocations, potentially nested; not unique GPU batches",
            "generation_attempts": self.llm_attempts, "network_events": list(self.guard.events),
            "requests": list(self.requests), "credential_values_persisted": False}

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            self.server = None
        if self.memory is not None:
            client = getattr(self.memory.vector_store, "client", None)
            if client is not None:
                client.close()
            self.memory = None
        self.tokens.clear()


def main():
    parser = argparse.ArgumentParser()
    for name in ("state", "sdk-root", "model", "legacy-project"):
        parser.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    serve_commands(SourceWorker(state=args.state, sdk_root=args.sdk_root, model=args.model, legacy_project=args.legacy_project))


if __name__ == "__main__":
    main()
