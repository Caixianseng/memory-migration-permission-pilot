"""Symmetric finite native read migration; explicit N/G and consumer boundary.

No execution on import or plan construction. Native services use their official
authenticated ASGI routes in isolated subprocesses, not physical TCP. G is an
external mandatory-route gateway over owner-only native storage. The three
phases are serial controller barriers, not atomic/live revocation. No holdout,
model, embedding, or paid call is required; consumers are separately budgeted.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_native_api_read_handoff as original
from scripts.run_native_exact_fact_bridge import WorkerRPC, archive_code
from scripts.policy_projection_gateway_http import GatewayHTTP
from memory_migration_study.policy_projection_gateway import PolicyProjectionGateway

VERSION = "review_native_finite_read_chain_v1"
DIRECTIONS = {"webui_to_cognee": ("open_webui", "cognee"),
              "cognee_to_webui": ("cognee", "open_webui")}
PHASES = ("initial", "alice_first_read_revoked", "old_packet_replay")
ACTORS = original.SUBJECTS
DATASETS = original.DATASETS
CONDITIONS = ("source", "N", "G", "none")
MAX_NATIVE_HTTP = 200
MAX_CONSUMER_CALLS = len(DIRECTIONS) * len(PHASES) * len(ACTORS) * len(DATASETS) * len(CONDITIONS)


class ChainStop(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ChainStop(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def build_plan(*, approved=None, consumer_model_cap=0):
    """Qualify pinned local source/assets only; never initialize a backend."""
    require(type(consumer_model_cap) is int and 0 <= consumer_model_cap <= MAX_CONSUMER_CALLS,
            "invalid_consumer_model_cap")
    expected = {"jsonschema": "4.26.0", "fastapi": "0.136.3", "httpx": "0.28.1", "starlette": "1.9.0"}
    try:
        installed = {name: importlib.metadata.version(name) for name in expected}
    except importlib.metadata.PackageNotFoundError:
        raise ChainStop("host_dependencies_missing_before_native_launch") from None
    require(installed == expected and sys.version_info[:2] == (3, 12), "host_dependency_versions_unqualified")
    qualified = original.build_plan()
    workers = {"open_webui": qualified["workers"]["source"], "cognee": qualified["workers"]["target"]}
    pythons = {"open_webui": qualified["pythons"]["source"], "cognee": qualified["pythons"]["target"]}
    instances = {}
    for direction, (source, target) in DIRECTIONS.items():
        for arm, backend in (("source", source), ("N", target), ("G", target)):
            name = direction + "." + arm
            state = (Path(approved["instances"][name]["state"]) if approved else
                     Path(tempfile.gettempdir()) / ("review_read_" + direction + "_" + arm + "_" + uuid.uuid4().hex))
            require(not state.exists() and state.parent.resolve() == Path(tempfile.gettempdir()).resolve()
                    and str(state).isascii(), "fresh_ascii_native_state_required")
            instances[name] = {"backend": backend, "state": str(state.resolve())}
    require(len({x["state"] for x in instances.values()}) == 6, "independent_native_states_required")
    files = {Path(x) for x in qualified["code_sha256"]}
    files.update((ROOT / "memory_migration_study").glob("*.py"))
    files.update((Path(__file__), ROOT / "scripts/policy_projection_gateway_http.py",
                  ROOT / "scripts/run_native_api_read_handoff.py",
                  ROOT / "scripts/run_review_read_integration.py"))
    return {"version": VERSION, "host_python": str(Path(sys.executable).resolve()),
        "host_python_version": sys.version.split()[0], "host_dependencies": installed,
        "source_contract_sha256": qualified["source_contract_sha256"],
        "facts": qualified["facts"], "principals": original.parse(original.CONTRACT.read_bytes())["principals"],
        "operator_consent": qualified["operator_consent"], "workers": workers, "pythons": pythons,
        "instances": instances, "wheel": qualified["wheel"], "legacy": qualified["legacy"],
        "code_sha256": {str(p.resolve()): original.file_sha(p) for p in sorted(files)},
        "asset_sha256": qualified["asset_sha256"], "directions": {k: list(v) for k, v in DIRECTIONS.items()},
        "phases": list(PHASES), "native_http_cap_per_instance": MAX_NATIVE_HTTP,
        "native_instances": 6, "max_total_native_http": MAX_NATIVE_HTTP * 6,
        "max_elapsed_seconds": 900, "rpc_timeout_seconds": 240, "retries": 0, "concurrency": 1,
        "max_consumer_calls": MAX_CONSUMER_CALLS, "max_consumer_model_calls": consumer_model_cap,
        "max_source_rechecks_per_consumer": 8,
        "native_generation_and_embedding_cap": 0, "paid_model_calls_enabled_by_cli": False,
        "source_policy_scope": {"open_webui": "explicit Note user/read ACL cross-checked against finite raw reads",
            "cognee": "finite effective raw-read matrix only; complete native ACL export unsupported"},
        "G_scope": "External authenticated gateway; native owner-only data. Not native source-policy execution.",
        "retrieval": "Same exact object-id raw route; no semantic retrieval/graph search claim.",
        "consumer": "Same four-condition callback per cell. None by default; no downstream effect claim.",
        "limitations": ["one exposed synthetic story; not independent acceptance", "ordinary composite-user accounts, not native Agent IAM",
            "serial barriers, not concurrent atomic revocation", "native export/share authority not verified",
            "registered raw read surface only; unmeasured routes not qualified", "old four vector nulls remain unresolved",
            "correct strong baselines; no new algorithm or superiority claim"]}


def verify_inputs(plan, *, assets=False):
    require(original.file_sha(original.CONTRACT) == plan["source_contract_sha256"], "fixture_changed")
    for name, expected in plan["code_sha256"].items():
        require(original.file_sha(name) == expected, "registered_code_changed")
    if assets:
        for name, expected in plan["asset_sha256"].items():
            require(original.file_sha(name) == expected, "registered_asset_changed")


def _read_core(records, principals):
    """Read-only standard policy; one grant per exact tuple/object relation."""
    sources, facts, grants = [], [], []
    for oid, record in sorted(records.items()):
        sid = "native.source." + oid
        text = record["text"]
        sources.append({"source_id": sid, "text": text, "sha256": record["sha256"], "public_synthetic_material": True})
        facts.append({"object_id": oid, "source_id": sid, "source_start": 0, "source_end": len(text),
            "text": text, "content_sha256": record["sha256"], "sensitivity": "synthetic_restricted", "labels_are_authorization": False})
        for principal in principals:
            grants.append({"grant_id": principal["principal_id"] + ":" + oid, "object_id": oid,
                "subject": principal["principal_id"], "actions": ["read"], "not_before": 0, "expires_at": 100,
                "parent_grant_id": None, "delegation_depth": 0})
    return {"principals": deepcopy(principals), "sources": sources, "facts": facts,
            "destinations": [], "grants": grants, "job_manifests": []}


def _gateway_state(core, desired, revision):
    native_actors = {p["principal_id"]: p["principal_id"].replace(".", "_") for p in core["principals"]}
    return {"time": revision, "policy_revision": revision + 1,
        "registered_grants": [g["grant_id"] for g in core["grants"]],
        "revoked_grants": [g["grant_id"] for g in core["grants"]
            if (native_actors[g["subject"]], g["object_id"]) not in desired]}


def execute(plan, output, *, rpc_factory=WorkerRPC, input_check=verify_inputs, consumer=None):
    """Execute an approved bounded native chain, optionally consuming deliveries.

    consumer(context) gets no scoring reference, native credential or forbidden
    source plaintext. It must return a small receipt (not a restoration map).
    Cooperative consumers declare a per-context upper bound before invocation.
    Reported model counts are checked against that reservation, not independently
    attested; this Python callback contract is not a sandbox for arbitrary code.
    """
    output = Path(output)
    facts = {x["object_id"]: x for x in plan["facts"]}
    principal_by_actor = {p["principal_id"].replace(".", "_"): p for p in plan["principals"]}
    require(set(principal_by_actor) == set(ACTORS), "exact_four_principals_required")
    cells = [{"direction": direction, "phase": phase, "actor": actor, "object_id": oid,
        "status": "not_run", "source_status": "not_run", "N_status": "not_run", "G_status": "not_run",
        "consumer": {c: {"status": "not_run"} for c in CONDITIONS}}
        for direction in DIRECTIONS for phase in PHASES for actor in ACTORS for oid in DATASETS]
    rows = {(r["direction"], r["phase"], r["actor"], r["object_id"]): r for r in cells}
    workers, summaries, events, snapshots, barriers, packets, gateway_traces = {}, {}, [], [], [], [], []
    http_clients, failure = [], None
    consumer_calls = consumer_models = 0
    started = time.monotonic()

    def checkpoint():
        save(output / "phase_progress.json", {"cells": cells, "snapshots": snapshots, "barriers": barriers,
            "events": events, "packets": packets, "gateway_http": gateway_traces})

    def bounded():
        require(time.monotonic() - started <= plan["max_elapsed_seconds"], "elapsed_budget_exceeded")

    def native(instance, phase, command, body):
        bounded(); input_check(plan)
        try:
            result = workers[instance].call(command, body)
        except Exception as error:
            events.append({"instance": instance, "phase": phase, "command": command,
                "input": deepcopy(body), "rpc_failure": type(error).__name__})
            checkpoint(); raise ChainStop("native_rpc_unknown") from None
        events.append({"instance": instance, "phase": phase, "command": command,
            "input": deepcopy(body), "result": deepcopy(result)})
        checkpoint(); bounded()
        if command in {"read_raw", "list_data", "grant", "revoke"}:
            original.checked_trace(result, body["actor"])
        return result

    def launch(name):
        input_check(plan, assets=True)
        item = plan["instances"][name]; backend = item["backend"]
        args = ["--state", item["state"], "--http-cap", str(plan["native_http_cap_per_instance"])]
        if backend == "cognee":
            args += ["--wheel", plan["wheel"], "--legacy-project", plan["legacy"],
                     "--expected-worker-sha256", original.TARGET_SHA]
        workers[name] = rpc_factory(plan["pythons"][backend], plan["workers"][backend], args,
                                   timeout=plan["rpc_timeout_seconds"])
        result = native(name, "identity_qualification", "init", {})
        identities = result["identities"]
        require(set(identities) == {"owner", *ACTORS} and len({p["id"] for p in identities.values()}) == 5,
                "independent_native_identity_binding_required")
        prior_ids = {row["id"] for summary in summaries.values() for row in summary.get("identities", {}).values()}
        require({row["id"] for row in identities.values()}.isdisjoint(prior_ids), "native_instance_identity_collision")
        require(all(p.get("role") == "user" if backend == "open_webui" else p.get("is_superuser") is False
                    for p in identities.values()), "native_regular_accounts_required")
        summaries[name] = {"identities": identities}

    def setup(name, record_values):
        for oid, record in record_values.items():
            ds = DATASETS[oid]
            native(name, "create", "create_dataset", {"actor": "owner", "dataset": ds})
            native(name, "ingest_actual_source_bytes", "add_exact_fact",
                   {"actor": "owner", "dataset": ds, "fact_key": ds, "text": record["text"]})
        summaries[name] = native(name, "object_bindings", "summary", {})

    def actual_read(name, phase, actor, oid):
        result = native(name, phase, "read_raw", {"actor": actor, "dataset": DATASETS[oid], "fact_key": DATASETS[oid]})
        trace, raw = original.checked_trace(result, actor)
        if result["status"] == 200:
            require(raw and len(raw.encode()) <= 4096 and raw == raw.strip()
                    and original.sha(raw.encode()) == facts[oid]["content_sha256"], "raw_content_unknown")
            return "available", raw, trace["index"]
        if result["status"] in {403, 404} and any(x["text"] in raw for x in facts.values()):
            raise ChainStop("denial_contains_registered_secret")
        body = original.parse(raw)
        require(result["status"] in {403, 404} and isinstance(body, dict)
                and isinstance(body.get("detail", body.get("message")), str)
                and not any(x["text"] in raw for x in facts.values()), "raw_denial_unknown")
        return "denied", None, trace["index"]

    def mutate(name, phase, operation, actor, oid):
        result = native(name, phase, operation, {"actor": "owner", "recipient": actor,
            "dataset": DATASETS[oid], "permission": "read"})
        body = original.parse(result["trace"]["native_raw_body"])
        require(result["status"] == 200, "native_acl_mutation_unknown")
        if plan["instances"][name]["backend"] == "cognee":
            message = "Permission assigned to principal" if operation == "grant" else "Permission revoked from principal"
            require(body == {"message": message}, "native_acl_ack_unknown")
        else:
            require(isinstance(body, dict) and isinstance(body.get("access_grants"), list), "native_acl_ack_unknown")

    def observe_source(direction, phase):
        name = direction + ".source"
        records, observations, acl = {}, [], None
        if plan["instances"][name]["backend"] == "open_webui":
            acl = set()
            for oid, ds in DATASETS.items():
                result = native(name, phase + "_policy", "list_data", {"actor": "owner", "dataset": ds})
                require(result["status"] == 200, "source_policy_unknown")
                readers = original.source_note(original.parse(result["trace"]["native_raw_body"]),
                                               summary=summaries[name], dataset=ds)
                acl.update((actor, oid) for actor in readers)
        for oid, ds in DATASETS.items():
            state, text, index = actual_read(name, phase + "_owner_export", "owner", oid)
            require(state == "available", "source_owner_positive_missing")
            records[oid] = {"text": text, "sha256": original.sha(text.encode()), "owner_native_index": index,
                "container_id": summaries[name]["datasets"][ds]["id"], "data_id": summaries[name]["facts"][ds]["id"]}
        desired = set()
        for actor in ACTORS:
            for oid in DATASETS:
                cell = rows[direction, phase, actor, oid]
                try:
                    status, text, index = actual_read(name, phase + "_matrix", actor, oid)
                except Exception as error:
                    if isinstance(error, ChainStop) and str(error) == "denial_contains_registered_secret":
                        cell.update(source_status="disclosed_after_denial", status="safety_failure",
                                    failure_class="new_unauthorized_disclosure")
                    else:
                        cell["source_status"] = "unknown"; cell["status"] = "infrastructure_unknown"
                    checkpoint(); raise
                cell.update(source_status=status, source_native_index=index)
                observations.append({"actor": actor, "object_id": oid, "status": status, "text": text, "index": index})
                if status == "available":
                    desired.add((actor, oid))
        require(desired == original.expected_relations(phase), "source_fixture_read_state_not_established")
        require(acl is None or acl == desired, "source_explicit_acl_and_effective_read_disagree")
        snapshot = {"direction": direction, "phase": phase, "records": records, "read_relations": observations,
            "source_identities": summaries[name]["identities"], "explicit_note_acl": acl is not None,
            "complete_native_acl_exported": False, "atomic_snapshot": False}
        snapshots.append(snapshot); checkpoint()
        return snapshot, desired

    def consume(cell, condition, text, source_text, source_record, target_name, status):
        nonlocal consumer_calls, consumer_models
        if consumer is None:
            return
        bounded(); require(consumer_calls < plan["max_consumer_calls"], "consumer_call_cap_exceeded")
        principal = principal_by_actor[cell["actor"]]
        target = summaries[target_name] if target_name else None
        ds = DATASETS[cell["object_id"]]
        rechecks, active_callback, check_lock = [0], [True], threading.Lock()
        exact_pair = {k: principal[k] for k in ("user_id", "agent_id")}

        def current_source_read(request_principal, object_id):
            """Process-local, current-cell native recheck; never serialized."""
            with check_lock:
                if not active_callback[0]:
                    return {"decision": "unknown", "code": "consumer_scope_closed"}
                if request_principal != exact_pair or object_id != cell["object_id"]:
                    return {"decision": "unknown", "code": "consumer_source_scope_mismatch"}
                if rechecks[0] >= plan.get("max_source_rechecks_per_consumer", 8):
                    return {"decision": "unknown", "code": "consumer_source_recheck_cap"}
                rechecks[0] += 1
                try:
                    state, current_text, index = actual_read(cell["direction"] + ".source",
                        cell["phase"] + "_consumer_current_recheck", cell["actor"], object_id)
                    return {"decision": "allow" if state == "available" else "deny",
                        "code": "native_current_raw_read", "content_sha256": original.sha(current_text.encode())
                        if current_text is not None else None, "native_request_index": index}
                except Exception as error:
                    return {"decision": "unknown", "code": str(error)
                        if isinstance(error, (ChainStop, original.Unverified)) else "native_current_read_unknown"}

        context = {"version": VERSION, "direction": cell["direction"], "phase": cell["phase"],
            "condition": condition, "object_id": cell["object_id"], "principal_id": principal["principal_id"],
            "principal": exact_pair, "current_source_read": current_source_read,
            "read_allowed": cell["source_status"] == "available", "delivery_status": status,
            "query": "Return the authorized value for " + cell["object_id"] + " exactly, or UNKNOWN.",
            "source_content": source_text if condition != "none" else None,
            "target_content": text if condition in {"N", "G"} else None,
            "memory_text": text, "retrieval_kind": "exact_object_id_raw",
            "source_object_ids": {"container_id": source_record["container_id"], "data_id": source_record["data_id"]},
            "target_object_ids": {"container_id": target["datasets"][ds]["id"], "data_id": target["facts"][ds]["id"]} if target else None,
            "source_native_identity": summaries[cell["direction"] + ".source"]["identities"][cell["actor"]]["id"],
            "target_native_identity": target["identities"][cell["actor"]]["id"] if target else None,
            "controller_barrier_revision": PHASES.index(cell["phase"])}
        try:
            declaration = getattr(consumer, "max_model_calls_for_context", None)
            if declaration is not None:
                require(callable(declaration), "consumer_model_budget_declaration_invalid")
                reserved = declaration(deepcopy(context))
            else:
                reserved = getattr(consumer, "max_model_calls_per_context", 1)
            require(type(reserved) is int and reserved in {0, 1}, "consumer_model_budget_declaration_invalid")
            remaining = plan["max_consumer_model_calls"] - consumer_models
            context.update(remaining_model_calls=remaining, reserved_model_calls=reserved)
            if reserved > remaining:
                cell["consumer"][condition] = {"status": "not_run", "failure_class": "budget_blocked",
                    "error": "consumer_model_budget_exhausted", "model_calls": 0}
                return
            consumer_calls += 1
            receipt = consumer(deepcopy(context))
            allowed = {"status", "error", "answer", "kind", "model_calls", "input_sha256", "output_sha256",
                       "restoration_status", "outbound_status", "failure_class", "authorization_decision",
                       "full_http_request_observed", "native_sdk_full_request_observed"}
            require(isinstance(receipt, dict) and not set(receipt) - allowed
                    and receipt.get("status") in {"ok", "blocked", "unknown", "error", "not_run"}, "consumer_receipt_invalid")
            count = receipt.get("model_calls", 0)
            require(type(count) is int and count >= 0, "consumer_model_count_invalid")
            consumer_models += count
            require(count <= reserved, "consumer_model_budget_contract_violation")
            require(consumer_models <= plan["max_consumer_model_calls"], "consumer_model_cap_exceeded")
            canonical(receipt)
            require(len(canonical(receipt)) <= 8192, "consumer_receipt_too_large")
            cell["consumer"][condition] = deepcopy(receipt)
        except Exception as error:
            cell["consumer"][condition] = {"status": "error", "failure_class": "consumer_unknown",
                "error": str(error) if isinstance(error, ChainStop) else type(error).__name__}
            raise ChainStop(str(error) if isinstance(error, ChainStop) else "consumer_execution_unknown") from None
        finally:
            active_callback[0] = False
            cell["consumer"][condition]["native_source_rechecks"] = rechecks[0]
        checkpoint(); bounded()

    try:
        require(plan["operator_consent"].get("approved_for_controlled_synthetic_copy") is True,
                "explicit_synthetic_copy_consent_required")
        for direction in DIRECTIONS:
            source_name, n_name, g_name = (direction + "." + a for a in ("source", "N", "G"))
            launch(source_name)
            setup(source_name, {oid: {"text": f["text"]} for oid, f in facts.items()})
            for actor, oid in sorted(original.expected_relations("initial")):
                mutate(source_name, "initial_fixture_acl", "grant", actor, oid)
            active, gateway, gateway_http, controller = set(), None, None, object()
            initial_packet, initial_bytes = None, None
            for revision, phase in enumerate(PHASES):
                if phase == PHASES[1]:
                    mutate(source_name, "source_revoke", "revoke", "alice_reader", "fact.readonly")
                snapshot, desired = observe_source(direction, phase)
                if initial_packet is None:
                    initial_packet = {"direction": direction, "source_identities": deepcopy(snapshot["source_identities"]),
                        "records": deepcopy(snapshot["records"]), "read_relations": sorted([list(x) for x in desired])}
                    initial_bytes = canonical(initial_packet); packets.append(deepcopy(initial_packet))
                    for name in (n_name, g_name):
                        launch(name); setup(name, snapshot["records"])
                    core = _read_core(snapshot["records"], plan["principals"])
                    def fetch(oid, name=g_name):
                        status, text, _ = actual_read(name, "gateway_owner_fetch", "owner", oid)
                        require(status == "available", "gateway_owner_positive_missing")
                        return text.encode()
                    gateway = PolicyProjectionGateway(core, _gateway_state(core, desired, revision),
                        fetch_fact=fetch, controller_token=controller)
                    gateway_http = GatewayHTTP(gateway, plan["principals"], max_requests=112)
                    http_clients.append(gateway_http)
                    for principal in plan["principals"]:
                        identity = gateway_http.request(principal["principal_id"], identity=True)
                        require(identity["status"] == 200 and identity["parsed"] == {k: principal[k] for k in ("user_id", "agent_id")},
                                "gateway_authenticated_pair_unknown")
                    require(gateway_http.request(None, {"operation": "read", "object_id": "fact.readonly"})["status"] == 401,
                            "gateway_anonymous_not_denied")
                else:
                    stable = lambda rs: {oid: {k: row[k] for k in ("text", "sha256", "container_id", "data_id")}
                                         for oid, row in rs.items()}
                    require(canonical(initial_packet) == initial_bytes and stable(initial_packet["records"]) == stable(snapshot["records"])
                            and initial_packet["source_identities"] == snapshot["source_identities"], "source_content_or_identity_changed")
                    gateway.transition_state(_gateway_state(core, desired, revision), controller_token=controller)
                changes = []
                for operation, pairs in (("revoke", active - desired), ("grant", desired - active)):
                    for actor, oid in sorted(pairs):
                        mutate(n_name, phase, operation, actor, oid)
                        changes.append({"operation": operation, "actor": actor, "object_id": oid})
                require(phase != PHASES[2] or not changes, "old_packet_replay_changed_native_acl")
                active = set(desired)
                barrier = {"direction": direction, "phase": phase, "current_source_relations": sorted([list(x) for x in desired]),
                    "N_changes": changes, "G_same_source_revision": revision, "old_packet_unchanged": canonical(initial_packet) == initial_bytes,
                    "native_live_or_atomic_revocation": False}
                barriers.append(barrier); checkpoint()
                source_observations = {(x["actor"], x["object_id"]): x for x in snapshot["read_relations"]}
                for actor in ACTORS:
                    for oid in DATASETS:
                        cell = rows[direction, phase, actor, oid]
                        source = source_observations[actor, oid]; wanted = (actor, oid) in desired
                        try:
                            n_status, n_text, n_index = actual_read(n_name, phase + "_N_read", actor, oid)
                            cell.update(N_status=n_status, N_native_index=n_index)
                            if (n_status == "available") != wanted:
                                cell["failure_class"] = "new_unauthorized_read" if n_status == "available" else "legal_access_loss"
                                raise ChainStop("native_read_mapping_mismatch")
                            bypass, _, bypass_index = actual_read(g_name, phase + "_G_confinement", actor, oid)
                            cell["G_native_direct_status"] = bypass; cell["G_native_direct_index"] = bypass_index
                            if bypass != "denied":
                                cell["failure_class"] = "native_gateway_confinement_failure"
                                raise ChainStop("gateway_native_owner_credentials_not_confined")
                            response = gateway_http.request(principal_by_actor[actor]["principal_id"], {"operation": "read", "object_id": oid})
                            gateway_traces.append({"direction": direction, "phase": phase, "actor": actor, "object_id": oid, "receipt": response})
                            reply = response["parsed"]
                            raw_response = response.get("raw_body")
                            require(isinstance(raw_response, str), "gateway_read_unknown")
                            # A denial label or HTTP error never excuses secret
                            # bytes elsewhere in the complete response body.
                            rejecting = (not wanted or response["status"] != 200
                                         or not isinstance(reply, dict) or reply.get("decision") != "allow")
                            # JSON escape spelling does not hide a literal
                            # secret from a client that decodes the response.
                            material = raw_response + "\n" + canonical(reply).decode("utf-8")
                            if rejecting and any(fact["text"] in material for fact in facts.values()):
                                cell["failure_class"] = "new_unauthorized_disclosure"
                                raise ChainStop("gateway_denial_contains_registered_secret")
                            require(isinstance(reply, dict) and reply.get("decision") in {"allow", "deny"}
                                    and (response["status"], reply["decision"]) in {(200, "allow"), (403, "deny")},
                                    "gateway_read_unknown")
                            if reply["decision"] == "deny":
                                require(reply.get("data") is None and reply.get("delivered_fact_ids") == [],
                                        "gateway_denial_payload_present")
                            g_status = "available" if reply["decision"] == "allow" else "denied"
                            g_text = reply.get("data", {}).get("text") if reply.get("data") is not None else None
                            cell.update(G_status=g_status, G_gateway_index=response["index"])
                            if (g_status == "available") != wanted or wanted and g_text != source["text"]:
                                cell["failure_class"] = "new_unauthorized_read" if g_status == "available" and not wanted else "legal_access_loss_or_changed_content"
                                raise ChainStop("gateway_read_mapping_mismatch")
                            cell["status"] = "direct_checks_matched"
                        except Exception as error:
                            if isinstance(error, ChainStop) and str(error) == "denial_contains_registered_secret":
                                cell["failure_class"] = "new_unauthorized_disclosure"
                            cell["status"] = "safety_failure" if "failure_class" in cell else "infrastructure_unknown"
                            checkpoint(); raise
                        source_text = source["text"] if wanted else None
                        for condition, text, name, status in (("source", source_text, None, source["status"]),
                                ("N", n_text if wanted else None, n_name, n_status),
                                ("G", g_text if wanted else None, g_name, g_status), ("none", None, None, "no_memory")):
                            consume(cell, condition, text, source_text, snapshot["records"][oid], name, status)
                        checkpoint()
    except Exception as error:
        failure = {"type": type(error).__name__, "code": str(error) if isinstance(error, (ChainStop, original.Unverified))
                   else "native_read_chain_execution_unknown"}
    finally:
        for client in http_clients:
            client.close()
        for name, worker in workers.items():
            try:
                summaries[name] = worker.call("close", {})
            except Exception as error:
                summaries[name] = {"close_error": type(error).__name__}
            worker.terminate()
        checkpoint()
    instrumentation = {}
    for name, summary in summaries.items():
        requests = summary.get("native_requests")
        instrumentation[name] = {"native_http": len(requests) if isinstance(requests, list) else None,
            "cap": plan["native_http_cap_per_instance"], "generation_attempts": summary.get("generation_attempts"),
            "embedding_attempts": summary.get("embedding_attempts"),
            "network_clear": isinstance(summary.get("network_events"), list)
                and all(x.get("allowed") is True for x in summary["network_events"]),
            "credential_values_not_saved": summary.get("client_credential_values_persisted") is False}
    technical = len(instrumentation) == 6 and all(type(x["native_http"]) is int and x["native_http"] <= x["cap"]
        and x["generation_attempts"] == x["embedding_attempts"] == 0 and x["network_clear"]
        and x["credential_values_not_saved"] for x in instrumentation.values())
    try:
        input_check(plan, assets=True); postflight = True
    except Exception:
        postflight = False
    complete = all(x["status"] == "direct_checks_matched" for x in cells)
    real = rpc_factory is WorkerRPC
    ok = failure is None and complete and technical and postflight
    report = {"version": VERSION, "status": ("qualified_finite_native_read_chain" if real else "fake_protocol_completed") if ok else "unverified_or_incomplete",
        "failure": failure, "execution_backend": "actual_native_worker_cli" if real else "explicit_fake_rpc",
        "registered_cells": len(cells), "direct_matched_cells": sum(x["status"] == "direct_checks_matched" for x in cells),
        "not_run_cells": sum(x["status"] == "not_run" for x in cells), "consumer_calls": consumer_calls,
        "safety_failure_cells": sum(x["status"] == "safety_failure" for x in cells),
        "infrastructure_unknown_cells": sum(x["status"] == "infrastructure_unknown" for x in cells),
        "new_unauthorized_disclosure_cells": sum(x.get("failure_class") in {"new_unauthorized_read", "new_unauthorized_disclosure"} for x in cells),
        "legal_access_loss_cells": sum(x.get("failure_class") in {"legal_access_loss", "legal_access_loss_or_changed_content"} for x in cells),
        "consumer_reported_model_calls": consumer_models, "consumer_model_counts_independently_attested": False,
        "downstream_effectiveness_evaluated": False, "consumer_present": consumer is not None,
        "instrumentation": instrumentation, "postflight": postflight, "elapsed_seconds": time.monotonic() - started,
        "gateway_http_counts": [len(client.requests) for client in http_clients],
        "N_G_superiority_established": False, "new_independent_stories": 0, "paper_novelty_established": False,
        "complete_native_policy_exported": False, "full_search_bypass_qualified": False,
        "native_atomic_or_live_revocation": False, "old_four_vector_nulls_closed": False,
        "native_HTTP_transport": "official FastAPI TestClient ASGI in isolated local processes, not physical TCP"}
    for name, value in (("cells", cells), ("events", events), ("source_snapshots", snapshots), ("barriers", barriers),
                        ("packets", packets), ("native_final", summaries), ("gateway_http", gateway_traces),
                        ("gateway_all_transport", [client.requests for client in http_clients]), ("report", report)):
        save(output / (name + ".json"), value)
    return report


def run(output, *, execute_native=False, approved_plan=None, consumer=None, consumer_model_cap=0):
    output = Path(output).resolve(); results = (ROOT / "results").resolve()
    require(not output.exists() and output.is_relative_to(results) and output != results, "new_workspace_results_required")
    approved = original.parse(Path(approved_plan).read_bytes()) if approved_plan else None
    plan = build_plan(approved=approved, consumer_model_cap=consumer_model_cap)
    require(not execute_native or approved is not None and approved == plan, "matching_frozen_plan_required")
    output.mkdir(parents=True)
    archive_code(list(plan["code_sha256"]), plan["code_sha256"], output)
    save(output / "plan.json", plan)
    if not execute_native:
        return {"status": "plan_only", "native_calls": 0, "model_calls": 0,
                "registered_cells": 48, "max_native_http": plan["max_total_native_http"]}
    return execute(plan, output, consumer=consumer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true"); mode.add_argument("--execute", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    result = run(args.output, execute_native=args.execute, approved_plan=args.approved_plan)
    print(json.dumps({k: result[k] for k in ("status", "failure", "registered_cells", "direct_matched_cells", "native_calls", "model_calls") if k in result}, ensure_ascii=False))
    raise SystemExit(0 if result["status"] in {"plan_only", "qualified_finite_native_read_chain"} else 1)
