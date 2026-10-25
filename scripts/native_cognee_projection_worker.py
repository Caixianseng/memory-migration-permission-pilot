"""Fresh Cognee backend with independent native accounts for source tuples.

This exposes native operations only. It never evaluates a source policy or
performs per-request reference-policy gating. N/G ACL synchronization and the
separate real gateway are the trusted driver's responsibility. No child agents.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import os
from pathlib import Path
import secrets
import sys
import tempfile
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
BASE_PATH = PROJECT / "scripts/native_cognee_policy_worker.py"
BASE_SHA256 = "54a26ac96b840c3e3aaaebf185a3bfc54d7a17885578bb3167f2f96b52d8fabc"
if hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() != BASE_SHA256:
    raise ValueError("frozen_cognee_policy_worker_changed")

from scripts.native_cognee_policy_worker import (CogneePolicyWorker, SafeRecorder, VENDOR_FILES,
    VERSION_EXPECTED, WHEEL_SHA256, LEGACY_CONFIGURATION_SHA256, WorkerScopeError,
    native_id, require, sha, verify_official_file_scope)
from scripts.native_exact_fact_common import isolate_environment, serve_commands

VERSION = "cognee_composite_principal_projection_worker_v1"
TUPLE_ACTORS = ("alice_reader", "alice_worker", "bob_reader", "bob_worker")
ACTORS = ("owner", *TUPLE_ACTORS)
FACTS = ("readonly", "managed")
SOURCE_ACTOR_MAP = {"alice.reader": "alice_reader", "alice.worker": "alice_worker",
    "bob.reader": "bob_reader", "bob.worker": "bob_worker"}
COMMANDS = frozenset({"init", "close", "create_dataset", "add_exact_fact", "read_raw", "grant", "revoke",
    "list_datasets", "list_data", "whoami", "snapshot", "summary"})


class CogneeProjectionWorker(CogneePolicyWorker):
    def __init__(self, *, expected_worker_sha256, **kwargs):
        require(isinstance(expected_worker_sha256, str) and len(expected_worker_sha256) == 64
            and all(c in "0123456789abcdef" for c in expected_worker_sha256), "projection_worker_hash_required")
        super().__init__(**kwargs)
        self.expected_worker_sha256 = expected_worker_sha256

    def _bindings(self):
        require(sha(BASE_PATH.read_bytes()) == BASE_SHA256, "frozen_cognee_policy_worker_changed")
        require(sha(Path(__file__).read_bytes()) == self.expected_worker_sha256, "projection_worker_source_changed")
        return {"base_policy_worker_sha256": BASE_SHA256, "projection_worker_sha256": self.expected_worker_sha256}

    def _limits(self):
        return {"http_requests": self.http_cap, "datasets": 2, "facts": 2, "children": 0, "fact_chars": 4096}

    def _actor(self, actor):
        require(isinstance(actor, str) and actor in ACTORS, "unknown_projection_actor")
        return super()._actor(actor)

    def _guard(self):
        self._bindings()
        return super()._guard()

    def initialize(self, data):
        """Reuse frozen isolation/recording contracts, replace only user roster.

        Calling super.initialize would create assistant/outsider and cannot
        represent four independent tuples. No base globals are patched.
        """
        self.stage = "projection_vendor_preflight"
        bindings = self._bindings()
        require(data == {} and not self.ready and self.context is None, "native_init_invalid")
        temp_root = Path(tempfile.gettempdir()).resolve()
        require(self.state.is_relative_to(temp_root) and self.state != temp_root and str(self.state).isascii()
            and not self.state.exists(), "new_ascii_system_temp_state_required")
        require(self.wheel.is_file() and sha(self.wheel.read_bytes()) == WHEEL_SHA256, "cognee_wheel_sha256_changed")
        distribution = importlib.metadata.distribution("cognee")
        require(distribution.version == VERSION_EXPECTED, "native_cognee_version_changed")
        source_hashes = {}
        with zipfile.ZipFile(self.wheel) as archive:
            for name in VENDOR_FILES:
                expected = sha(archive.read(name)); installed = Path(distribution.locate_file(name))
                require(installed.is_file() and sha(installed.read_bytes()) == expected, "native_vendor_source_changed")
                source_hashes[name] = expected
        self.state.mkdir(parents=True, exist_ok=False)
        isolate_environment(self.state)
        sys.addaudithook(self.guard); self.inference.install()
        config_source = self.legacy / "scripts/cognee_local_migration_probe.py"
        require(config_source.is_file() and sha(config_source.read_bytes()) == LEGACY_CONFIGURATION_SHA256,
            "legacy_configuration_missing_or_changed")
        sys.path.insert(0, str(self.legacy / "scripts"))
        from cognee_local_migration_probe import configure_isolated_cognee
        self.settings, self.dll_handle, self.legacy_network_events = configure_isolated_cognee(self.state, self.openssl)
        os.environ.update({"ALLOW_HTTP_REQUESTS": "false", "ACCEPT_LOCAL_FILE_PATH": "true",
            "COGNEE_ALLOWED_LOCAL_FILE_ROOTS": str(self.state)})
        self.stage = "projection_native_application_import"
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
        async def portal_guard():
            return sys.getprofile() is self.inference.callback
        require(self.client.portal.call(portal_guard), "portal_inference_guard_missing")
        self.stage = "projection_five_regular_users"
        for actor in ACTORS:
            password = secrets.token_urlsafe(32); self.recorder.remember(password)
            email = "controlled-projection-" + actor + "-" + secrets.token_hex(8) + "@example.com"
            response, _ = self.recorder.request("POST", "/api/v1/auth/register", credential=True,
                json={"email": email, "password": password})
            require(response.status_code == 201, "native_registration_failed")
            response, _ = self.recorder.request("POST", "/api/v1/auth/login", credential=True,
                data={"username": email, "password": password})
            require(response.status_code == 200, "native_login_failed")
            self.recorder.bind(actor, "bearer", response.json()["access_token"])
            response, _ = self.recorder.request("GET", "/api/v1/users/me", actor=actor)
            body = response.json()
            require(response.status_code == 200 and body.get("email") == email and body.get("is_superuser") is False
                and body.get("parent_user_id") is None, "native_independent_composite_identity_unqualified")
            self.identities[actor] = {"id": native_id(body["id"]), "parent_user_id": None,
                "is_superuser": False, "credential_kind": "bearer"}
        require(len({x["id"] for x in self.identities.values()}) == 5, "native_users_not_independent")
        _, anonymous = self.recorder.request("GET", "/api/v1/datasets")
        require(anonymous["status"] in {401, 403}, "native_anonymous_not_denied")
        self.ready, self.stage = True, "projection_native_ready"
        self._guard()
        return {"version": VERSION, "cognee_version": distribution.version, "identities": deepcopy(self.identities),
            "source_actor_map": deepcopy(SOURCE_ACTOR_MAP), "native_subject_representation": "independent_composite_user_accounts",
            "owner_role": "trusted_storage_and_acl_controller_not_source_tuple", "native_child_agents_created": 0,
            "source_policy_evaluated_here": False, "per_request_reference_gate_present": False,
            "wheel_sha256": WHEEL_SHA256, "vendor_source_sha256": source_hashes, "source_bindings": bindings,
            "limits": self._limits(), "expected_init_http_requests": 16, "file_scope": deepcopy(self.file_scope),
            "ingestion_configuration": {"ACCEPT_LOCAL_FILE_PATH": True, "ALLOW_HTTP_REQUESTS": False,
                "allowed_local_roots": "current_new_state_only"}, "client_credentials_saved": False,
            "native_auth_storage_unmodified": True, "write_contract": "inherited_exact_raw_data_state_scoped_ingestion",
            "inference_scope": "guarded Python entry boundaries, not arbitrary native hardware attestation"}

    def _dispatch(self, command, data):
        require(command in COMMANDS, "projection_command_not_allowed")
        if command in {"init", "close"}:
            return super()._dispatch(command, data)
        self._guard()
        require(isinstance(data, dict), "native_command_data_invalid")
        if command == "summary":
            require(data == {}, "projection_summary_scope_invalid")
            result = self.summary()
        elif command == "create_dataset":
            require(set(data) == {"dataset", "actor"} and data["dataset"] in FACTS and data["dataset"] not in self.datasets
                and len(self.datasets) < 2 and data["actor"] == "owner", "projection_dataset_scope_invalid")
            self._actor(data["actor"])
            name = "controlled_projection_" + data["dataset"] + "_" + secrets.token_hex(6)
            response, trace = self.recorder.request("POST", "/api/v1/datasets", actor="owner", json={"name": name})
            require(response.status_code == 200, "native_dataset_creation_failed")
            body = response.json(); require(body.get("name") == name, "native_dataset_name_changed")
            self.datasets[data["dataset"]] = {"id": native_id(body["id"]), "name": name, "owner": "owner"}
            result = {**deepcopy(self.datasets[data["dataset"]]), "trace": deepcopy(trace)}
        elif command == "add_exact_fact":
            require(set(data) == {"dataset", "actor", "fact_key", "text"} and data["dataset"] in FACTS
                and data["fact_key"] == data["dataset"] and data["actor"] == "owner" and len(self.facts) < 2,
                "projection_exact_fact_scope_invalid")
            return super()._dispatch(command, data)
        elif command == "list_datasets":
            require(set(data) == {"actor"}, "projection_list_scope_invalid"); self._actor(data["actor"])
            response, trace = self.recorder.request("GET", "/api/v1/datasets", actor=data["actor"])
            result = self._envelope(response, trace)
        elif command == "list_data":
            require(set(data) == {"dataset", "actor"}, "projection_list_scope_invalid")
            ds = self._dataset(data["dataset"]); self._actor(data["actor"])
            response, trace = self.recorder.request("GET", f"/api/v1/datasets/{ds['id']}/data", actor=data["actor"])
            result = self._envelope(response, trace)
        elif command == "snapshot":
            require(set(data) in (set(), {"actors"}), "projection_snapshot_scope_invalid")
            actors = data.get("actors", list(TUPLE_ACTORS))
            require(isinstance(actors, list) and 0 < len(actors) <= 5 and all(isinstance(a, str) and a in ACTORS for a in actors)
                and len(set(actors)) == len(actors), "projection_snapshot_scope_invalid")
            before = len(self.recorder.requests); observations = []
            for actor in actors:
                observations.append({"actor": actor, "operation": "list_datasets",
                    "result": self._dispatch("list_datasets", {"actor": actor})})
                for dataset in FACTS:
                    if dataset not in self.datasets:
                        continue
                    observations.append({"actor": actor, "operation": "list_data", "dataset": dataset,
                        "result": self._dispatch("list_data", {"actor": actor, "dataset": dataset})})
                    if dataset in self.facts:
                        observations.append({"actor": actor, "operation": "raw", "dataset": dataset, "fact_key": dataset,
                            "result": self._dispatch("read_raw", {"actor": actor, "dataset": dataset, "fact_key": dataset})})
            result = {"observations": observations, "native_http_start_index": before,
                "native_http_end_exclusive": len(self.recorder.requests), "physical_http_requests": len(self.recorder.requests) - before,
                "both_exact_facts_ready": set(self.datasets) == set(self.facts) == set(FACTS),
                "source_policy_evaluated_here": False, "atomic_snapshot_claimed": False}
        else:
            return super()._dispatch(command, data)
        self._guard()
        return result

    def summary(self):
        result = super().summary()
        result.update(version=VERSION, source_actor_map=deepcopy(SOURCE_ACTOR_MAP), limits=self._limits(),
            source_bindings={"base_policy_worker_sha256": BASE_SHA256, "projection_worker_sha256": self.expected_worker_sha256},
            native_subject_representation="independent_composite_user_accounts", native_child_agents_created=0,
            source_policy_evaluated_here=False, per_request_reference_gate_present=False)
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state", "wheel", "legacy-project"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-worker-sha256", required=True)
    parser.add_argument("--http-cap", type=int, default=200)
    parser.add_argument("--openssl-dll-dir", type=Path)
    args = parser.parse_args()
    serve_commands(CogneeProjectionWorker(state=args.state, wheel=args.wheel, legacy_project=args.legacy_project,
        expected_worker_sha256=args.expected_worker_sha256, http_cap=args.http_cap, openssl_dll_dir=args.openssl_dll_dir))
