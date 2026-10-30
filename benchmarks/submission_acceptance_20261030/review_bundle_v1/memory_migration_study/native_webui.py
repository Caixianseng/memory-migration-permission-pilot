"""Native Open WebUI 0.12.3 public controlled-memory instrumentation.

Run in a fresh process: the reviewed legacy configure() intentionally clears
the environment and installs a permanent socket audit hook. No product auth,
database, ACL, embedding, or retrieval implementation is replaced.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import secrets
import sys
import time
import traceback
from types import ModuleType

from .evidence import evaluate, probe
from .policy import make_plan
from .public_fixture import SpanInstrumentationAnswerer, prepare_controlled_fixture
from .runner import save_json
from .tasks import run_tasks, score_runs
from .snapshots import freeze_snapshot_bundle


VERSION = "0.12.3"
EMPTY_READ_CONTRACT = "open_webui_0.12.3_memory_id_filter_empty_v1"


class NativePilotError(RuntimeError):
    """Only fixed implementation codes are eligible for an error receipt."""
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _parsed(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


class NativeRecorder:
    """Keep native non-auth response bytes, never passwords, JWTs, or cookies."""

    def __init__(self, client, response_dir):
        self.client = client
        self.response_dir = Path(response_dir)
        self.response_dir.mkdir(parents=True, exist_ok=True)
        self.tokens, self.secret_values, self.requests = {}, [], []

    def request(self, method, path, *, actor_id=None, payload=None):
        self.client.cookies.clear()
        headers = {"Authorization": "Bearer " + self.tokens[actor_id]} if actor_id in self.tokens else {}
        kwargs = {"json": payload} if payload is not None else {}
        trace = {"native_request_index": len(self.requests),
                 "native_method": method, "native_path": path, "actor_id": actor_id,
                 "authorization_present": bool(headers), "cookie_present": False}
        if payload is not None and "/auths" not in path:
            trace["native_request_json"] = payload
        try:
            response = self.client.request(method, path, headers=headers, **kwargs)
            trace["status"] = response.status_code
            raw = bytes(response.content)
            text = raw.decode("utf-8")
            actual_headers = getattr(getattr(response, "request", None), "headers", {})
            trace["cookie_present"] = bool(actual_headers.get("cookie"))
            trace["authorization_present"] = bool(actual_headers.get("authorization", headers.get("Authorization")))
            if "/auths" in path:
                trace.update(auth_response_omitted=True, response_checked=True, execution_error=None)
            elif any(secret and secret.encode("utf-8") in raw for secret in self.secret_values):
                trace.update(raw_response_omitted=True, response_checked=False,
                             execution_error="credential_contaminated_native_response")
            else:
                path_out = self.response_dir / f"{len(self.requests):05d}.bin"
                path_out.write_bytes(raw)
                trace.update(native_raw_body=text, native_body_sha256=_sha(raw), byte_count=len(raw),
                             native_response_file=str(path_out.resolve()), response_checked=True, execution_error=None)
            self.requests.append(trace)
            return response, trace
        except Exception as exc:
            trace.setdefault("status", None)
            trace.update(response_checked=False, execution_error=type(exc).__name__)
            self.requests.append(trace)
            return None, trace


class NativeWebUIAdapter:
    """Normalize native memory rows while retaining their full response body.

    ``read`` is POST /memories/search with native memory_id filtering, not a GET
    endpoint. Actor/agent labels are application bindings to verified native
    user credentials; WebUI does not attest an independent agent principal.
    """
    backend_kind = "native"
    negative_contract = True
    evidence_contract = "open_webui_0.12.3_native_memory_v1"

    def __init__(self, recorder, case, plan, identities, controls):
        self.recorder, self.case, self.plan = recorder, case, plan
        self.identities, self.controls = identities, controls
        self.actors = {actor["actor_id"]: actor for actor in case["actors"]}
        self.reverse = {target: source for source, targets in plan["object_mapping"].items() for target in targets}
        self.control_ids = {spec["target_id"] for spec in controls.values()}

    def identity(self, actor_id):
        response, trace = self.recorder.request("GET", "/api/v1/auths/", actor_id=actor_id)
        value = _parsed(response.content) if response is not None else None
        expected = self.identities.get(actor_id, {})
        valid = (trace["status"] == 200 and isinstance(value, dict)
                 and value.get("id") == expected.get("id") == self.case["actor_mapping"].get(actor_id)
                 and value.get("role") == "user" and value.get("email") == expected.get("email"))
        actor = self.actors[actor_id]
        # The native auth response can contain a JWT; only this non-secret receipt is retained.
        normalized = {"actor_id": value.get("id") if isinstance(value, dict) else None,
                      "user_id": actor["user_id"], "agent_id": actor["agent_id"],
                      "native_user_id": value.get("id") if isinstance(value, dict) else None,
                      "native_role": value.get("role") if isinstance(value, dict) else None,
                      "agent_binding": "application_level_fixed_worker_not_native_agent_attestation"}
        return valid, {**trace, "raw_body": json.dumps(normalized), "response_checked": response is not None}

    def _normalize(self, trace, *, target_id=None, listing=False):
        raw = trace.get("native_raw_body", "")
        value = _parsed(raw)
        items, malformed = [], False
        if isinstance(value, list):
            for row in value:
                if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                        or not isinstance(row.get("content"), str) or not isinstance(row.get("user_id"), str)):
                    malformed = True
                    continue
                native_id = row["id"]
                source_id = "__positive_control__" if native_id in self.control_ids else self.reverse.get(native_id, "__unregistered__")
                items.append({"target_id": native_id, "source_id": source_id, "text": row["content"]})
            if not listing and (len(value) > 1 or any(item["target_id"] != target_id for item in items)):
                malformed = True
        else:
            malformed = trace.get("status") == 200
        normalized = {"items": items, "native_response": value, "native_raw_body": raw}
        if listing:
            normalized.update(complete=trace.get("status") == 200 and isinstance(value, list) and not malformed,
                              next_offset=None)
        result = dict(trace, raw_body=json.dumps(normalized, ensure_ascii=False), native_package_version=VERSION)
        if malformed and not result.get("execution_error"):
            result["execution_error"] = "native_memory_response_contract_violation"
        if not listing:
            result["empty_read_contract"] = EMPTY_READ_CONTRACT
        return result

    def read(self, actor_id, target_id):
        _, trace = self.recorder.request("POST", "/api/v1/memories/search", actor_id=actor_id,
                                        payload={"memory_id": target_id, "type": "all", "limit": 1})
        return self._normalize(trace, target_id=target_id)

    def list_pages(self, actor_id):
        _, trace = self.recorder.request("GET", "/api/v1/memories/", actor_id=actor_id)
        normalized = self._normalize(trace, listing=True)
        complete = (_parsed(normalized["raw_body"]).get("complete") is True
                    and normalized.get("response_checked") is True and not normalized.get("execution_error"))
        return [normalized], complete


def _create_identities(recorder):
    identities = {}
    for actor_id in ("controller", "owner", "assistant", "outsider"):
        email = f"native-public-{actor_id}-{secrets.token_hex(6)}@example.com"
        password = "Research-" + secrets.token_urlsafe(24)
        recorder.secret_values.append(password)
        body = {"email": email, "password": password, "name": "controlled-" + actor_id}
        path = "/api/v1/auths/signup" if actor_id == "controller" else "/api/v1/auths/add"
        if actor_id != "controller":
            body["role"] = "user"
        response, trace = recorder.request("POST", path, actor_id=None if actor_id == "controller" else "controller", payload=body)
        if trace["status"] != 200:
            raise NativePilotError("native_account_creation_failed")
        response, trace = recorder.request("POST", "/api/v1/auths/signin", payload={"email": email, "password": password})
        value = _parsed(response.content) if response is not None else None
        expected_role = "admin" if actor_id == "controller" else "user"
        if (trace["status"] != 200 or not isinstance(value, dict) or value.get("role") != expected_role
                or value.get("email") != email or not isinstance(value.get("id"), str)
                or not isinstance(value.get("token"), str) or not value["token"]):
            raise NativePilotError("native_independent_signin_failed")
        recorder.tokens[actor_id] = value["token"]
        recorder.secret_values.append(value["token"])
        identities[actor_id] = {"id": value["id"], "email": email, "role": expected_role}
    if len({value["id"] for value in identities.values()}) != 4 or len(set(recorder.tokens.values())) != 4:
        raise NativePilotError("native_identities_not_distinct")
    return identities


def _insert_memory(recorder, actor_id, native_id, text, path):
    response, trace = recorder.request("POST", "/api/v1/memories/add", actor_id=actor_id,
                                      payload={"content": text, "path": path, "type": "context"})
    value = _parsed(response.content) if response is not None else None
    if (trace["status"] != 200 or not isinstance(value, dict) or not isinstance(value.get("id"), str)
            or value.get("content") != text or value.get("user_id") != native_id):
        raise NativePilotError("native_memory_insert_or_embedding_failed")
    return value["id"]


def _native_plan(recorder, case, identities):
    intended = make_plan(case, "reader_copies", "native-public-" + secrets.token_hex(8))
    plan = copy.deepcopy(intended)
    plan.update(objects=[], containers=[], object_mapping={record["source_id"]: [] for record in case["records"]},
                backend_kind="native", native_container_semantics="user_scoped_memory_collection")
    groups = {}
    for obj in intended["objects"]:
        actor_id = obj["readers"][0]
        native_user = identities[actor_id]["id"]
        target_id = _insert_memory(recorder, actor_id, native_user, obj["text"], "/migration/" + obj["source_id"])
        container_id = "webui-user-memory/" + native_user
        plan["objects"].append(dict(obj, target_id=target_id, container_id=container_id))
        plan["object_mapping"][obj["source_id"]].append(target_id)
        groups.setdefault(container_id, {"container_id": container_id, "readers": [actor_id], "target_ids": []})["target_ids"].append(target_id)
    plan["containers"] = list(groups.values())
    targets = [obj["target_id"] for obj in plan["objects"]]
    if len(targets) != 4 or len(set(targets)) != 4:
        raise NativePilotError("native_copy_inventory_incomplete_or_colliding")
    controls = {}
    for actor in case["actors"]:
        actor_id = actor["actor_id"]
        text = "CONTROLLED-NATIVE-POSITIVE-" + actor_id + "-" + secrets.token_hex(16)
        target_id = _insert_memory(recorder, actor_id, identities[actor_id]["id"], text, "/native-positive-control")
        if target_id in set(targets) | {control["target_id"] for control in controls.values()}:
            raise NativePilotError("native_control_identity_collision")
        controls[actor_id] = {"target_id": target_id, "text_sha256": _sha(text.encode("utf-8"))}
    return plan, controls


def _legacy_configure(project):
    script = project / "scripts/openwebui_migration_probe.py"
    raw = script.read_bytes()
    sys.dont_write_bytecode = True
    scripts = str(script.parent.resolve())
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    module = ModuleType("_reviewed_native_webui_configuration")
    module.__file__ = str(script)
    exec(compile(raw, str(script), "exec"), module.__dict__)
    return module.configure, {"path": str(script.resolve()), "sha256": _sha(raw)}


def run_native_webui_public(*, legacy_project: Path, output: Path, artifacts_root=None, seed=42) -> dict:
    """Prepare and execute the native pilot. Call from a dedicated CLI process.

    Failure receipts retain the completed preparation, stage, and error type.
    Dependencies/assets are checked locally; this function never installs or
    downloads them. An existing output directory is never overwritten.
    """
    project, output = Path(legacy_project).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic()
    report = {"schema_version": 1, "kind": "controlled_native_webui_public_pilot", "status": "running",
              "stage": "prepare_fixture", "backend_kind": "native", "native_status": "not_run",
              "transport": "native_fastapi_in_process_testclient_http",
              "qualification": "controlled_machine_checked_fact_spans", "independent_stories": 1,
              "natural_acl_qualified": 0, "human_review": None, "real_llm": None,
              "remote_model_calls": 0, "generative_model_requests": 0, "real_llm_metrics": None,
              "vendor_migration_adapter_claimed": False, "product_vulnerability_claimed": False,
              "admin_scored_as_actor": False, "local_embedding": False,
              "identity_scope": "native_user_jwt_with_application_level_fixed_memory_worker_binding",
              "normalization": "derived_target_id_source_id_text_plus_full_native_json_and_raw_byte_archive",
              "read_operation": {"method": "POST", "path": "/api/v1/memories/search", "filter": "native_memory_id"},
              "list_operation": {"method": "GET", "path": "/api/v1/memories/"}}
    recorder = None
    dll_handle = None
    try:
        prepared = prepare_controlled_fixture(project, output / "fixture")
        report["fixture"] = prepared
        runtime = json.loads(Path(prepared["runtime_path"]).read_text(encoding="utf-8"))
        evaluation = json.loads(Path(prepared["evaluation_path"]).read_text(encoding="utf-8"))
        case = runtime["cases"][0]
        report["stage"] = "check_local_dependency"
        try:
            version = importlib.metadata.version("open-webui")
        except importlib.metadata.PackageNotFoundError:
            report.update(status="missing_dependency", missing_dependency="open-webui==" + VERSION)
            return report
        report["package"] = {"name": "open-webui", "version": version}
        if version != VERSION:
            report.update(status="unsupported_dependency_version")
            return report
        assets = Path(artifacts_root).resolve() if artifacts_root else project / "runtime_assets"
        if not (assets / "models/minilm").is_dir() or not (assets / "native_dlls").is_dir():
            report.update(status="missing_local_artifact", artifacts_root=str(assets))
            return report
        report["stage"] = "configure_isolated_native_state"
        configure, configuration_source = _legacy_configure(project)
        report["configuration_source"] = configuration_source
        state = output / "native_state"
        state.mkdir()
        settings, dll_handle, egress = configure(state, assets)
        report.update(settings=settings, egress_attempts=egress, artifacts_root=str(assets))
        distribution = importlib.metadata.distribution("open-webui")
        report["stage"] = "hash_native_product_code"
        code_paths = [Path(distribution.locate_file("open_webui/" + relative))
                      for relative in ("routers/memories.py", "routers/auths.py", "models/memories.py", "utils/memory.py")]
        report["required_native_code_files"] = [str(path) for path in code_paths]
        for path in code_paths:
            if not path.is_file():
                raise FileNotFoundError(2, "required native product source is absent", str(path))
        report["native_code_sha256"] = {str(path): _sha(path.read_bytes()) for path in code_paths}
        report["implementation_sha256"] = _sha(Path(__file__).read_bytes())
        report["stage"] = "import_native_application"
        import torch
        torch.set_num_threads(2)
        from open_webui.main import app
        from fastapi.testclient import TestClient
        report["stage"] = "start_native_lifespan"
        with TestClient(app, raise_server_exceptions=False) as client:
            if app.state.ef is None or not callable(app.state.EMBEDDING_FUNCTION):
                raise NativePilotError("native_local_embedder_not_ready")
            report["local_embedding"] = True
            report["stage"] = "native_independent_accounts"
            recorder = NativeRecorder(client, output / "responses")
            identities = _create_identities(recorder)
            report["native_identities"] = {actor: {"id": identity["id"], "role": identity["role"]} for actor, identity in identities.items()}
            case["actor_mapping"] = {actor["actor_id"]: identities[actor["actor_id"]]["id"] for actor in case["actors"]}
            save_json(output / "native_runtime.json", runtime)
            _, anonymous = recorder.request("GET", "/api/v1/memories/")
            if anonymous["status"] not in (401, 403):
                raise NativePilotError("anonymous_memory_control_failed")
            report["stage"] = "native_copy_and_positive_controls"
            plan, controls = _native_plan(recorder, case, identities)
            report["plan"] = plan
            report["positive_controls"] = controls
            adapter = NativeWebUIAdapter(recorder, case, plan, identities, controls)
            report["stage"] = "native_read_list_probe"
            bundle = probe(case, plan, adapter)
            bundle.update(native_status="native_application_api_executed", transport=report["transport"],
                          native_package={"name": "open-webui", "version": version},
                          agent_binding="application_level_fixed_worker_not_native_agent_attestation")
            save_json(output / "direct_evidence.json", bundle)
            report["direct"] = evaluate(bundle)
            report["evidence_file"] = str((output / "direct_evidence.json").resolve())
            report["stage"] = "seven_paired_span_instrumentation_tasks"
            task_run = run_tasks(case, plan, adapter, seed=seed, answerer=SpanInstrumentationAnswerer(), capture_contexts=True)
            report["tasks"] = dict(score_runs(task_run, evaluation["cases"][case["case_id"]]), run=task_run)
            save_json(output / "task_runs.json", report["tasks"])
            save_json(output / "native_requests.json", {"requests": recorder.requests})
            report["stage"] = "freeze_three_group_context_snapshots"
            snapshots = freeze_snapshot_bundle(runtime_path=output / "native_runtime.json",
                                                evidence_path=output / "direct_evidence.json",
                                                requests_path=output / "native_requests.json", task_run=task_run,
                                                output_path=output / "contexts.json")
            report["context_snapshots"] = {"path": str((output / "contexts.json").resolve()),
                                           "sha256": _sha((output / "contexts.json").read_bytes()),
                                           "count": len(snapshots["snapshots"]), "remote_model_calls": 0}
            report["task_retrieval_report"] = snapshots["task_retrieval_report"]
            report["native_status"] = "native_application_api_executed"
            if egress:
                report["status"] = "failed_remote_connection_attempt"
            elif any(request.get("cookie_present") for request in recorder.requests):
                report["status"] = "failed_cookie_isolation"
            elif report["direct"]["known_w_plus"] or report["task_retrieval_report"]["known_w_plus_task_lists"]:
                report["status"] = "counterexample_found"
            elif report["direct"]["finite_scope_safe"] is not True:
                report["status"] = "incomplete_evidence"
            else:
                groups = report["tasks"]["instrumentation_metrics"]["groups"]
                report["status"] = "completed" if all(groups[group]["correct"] == 7 for group in ("authorized_reference", "migrated")) else "incomplete_task_instrumentation"
            report["stage"] = "finished"
    except ModuleNotFoundError as exc:
        report.update(status="missing_dependency", error_type=type(exc).__name__, missing_dependency=exc.name)
    except Exception as exc:
        report.update(status="failed", error_type=type(exc).__name__)
        if isinstance(exc, NativePilotError):
            report["error_code"] = exc.code
        if isinstance(exc, OSError):
            report.update(error_errno=exc.errno, error_filename=exc.filename)
        report["error_frames"] = [{"file": frame.filename, "line": frame.lineno, "function": frame.name}
                                  for frame in traceback.extract_tb(exc.__traceback__)]
    finally:
        if recorder is not None:
            save_json(output / "native_requests.json", {"requests": recorder.requests})
            report["native_requests_file"] = str((output / "native_requests.json").resolve())
            report["native_requests"] = len(recorder.requests)
        report["elapsed_seconds"] = round(time.monotonic() - start, 3)
        save_json(output / "manifest.json", report)
        if dll_handle is not None:
            dll_handle.close()
    return report
