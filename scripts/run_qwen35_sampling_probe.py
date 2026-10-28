"""Ten exposed diagnostics: explicit presence 1.5/0 on one Ollama backend.

Two real arms retain the old prompt/schema and at most one original repair.
Two historical arms are replays. All 40 preparations close before gold access.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_copy_tag_probe as history
from scripts import run_qwen35_model_probe as model_probe
from scripts import run_source_annotation_probe as prior
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.deadline_http import Deadline, DeadlineExceeded, exchange_http
from memory_migration_study.qwen35_sampling import SamplingQwen35Agent, build_request, ARMS as PENALTIES
from memory_migration_study.qwen35_occurrence import MODEL, ENDPOINT, RUNTIME_VERSION
from memory_migration_study.local_detector import _strict_json

save, sha, require = prior.save, prior.sha, prior.require
VERSION = "qwen35_presence_causal_diagnostic_v1"
PREREG = "docs/Qwen35重复惩罚_因果隔离预注册_2026-10-28.md"
RUNTIME_BOOTSTRAP = "scripts/start_qwen35_sampling_runtime.ps1"
TEXT_IDS = (1, 2, 4, 6, 11, 13, 14, 16, 19, 22)
NEW_ARMS = ("presence_15", "presence_zero")
ARMS = (*NEW_ARMS, "qwen35_quote", "qwen3_conditional")
MODEL_DIGEST = "d8b0f5e9760cd1682034f292d7ef72ec46f432149be0df7574bf2d6e92e38c04"
ASSET = ROOT / "results/qwen35_assets_20261028_run04/asset_receipt.json"
QUALIFICATION = ROOT / "results/qwen35_assets_20261028_run04/inference_qualification.json"
LIMITS = {"texts": 10, "rows": 40, "generation_cells": 20, "generation_posts": 40,
    "posts_per_cell": 2, "health_gets": 40, "wall_seconds": 1800,
    "prompt_tokens": 4096, "output_tokens": 1024, "concurrent_requests": 1,
    "new_canary_calls": 0, "cloud_calls": 0, "native_writes": 0, "new_target_posts": 0}


def read_json(path):
    return _strict_json(Path(path).read_text(encoding="utf-8-sig"))


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def wire(body):
    return json.dumps(body, ensure_ascii=False, allow_nan=False)


def wire_sha(body):
    return hashlib.sha256(wire(body).encode("utf-8")).hexdigest()


def generation_order():
    return [{"text_index": i, "arm": a} for ordinal, i in enumerate(TEXT_IDS)
            for a in (NEW_ARMS if ordinal % 2 == 0 else tuple(reversed(NEW_ARMS)))]


def requests_for(texts, policy):
    return {str(i): {a: [build_request(texts[i], "source_%02d" % i, policy, [],
        arm=a, repair=repair) for repair in (False, True)] for a in NEW_ARMS} for i in TEXT_IDS}


def qualified_runtime(path):
    path = Path(path).resolve()
    require(path.is_file() and path.is_relative_to(ROOT.resolve()), "runtime_receipt_scope")
    asset, qualification, paths = model_probe.qualified_receipts(ASSET, QUALIFICATION)
    receipt = read_json(path)
    require(type(receipt) is dict and receipt.get("status") == "ready"
        and receipt.get("version") == RUNTIME_VERSION and receipt.get("endpoint") == ENDPOINT
        and receipt.get("model") == MODEL
        and receipt.get("model_digest") == asset["model_digest"] == MODEL_DIGEST
        and type(receipt.get("executable")) is str and receipt["executable"] == asset.get("executable")
        and type(receipt.get("executable_sha256")) is str
        and re.fullmatch(r"[a-f0-9]{64}", receipt["executable_sha256"]) is not None
        and receipt["executable_sha256"] == asset.get("executable_sha256")
        and type(receipt.get("pid")) is int and receipt["pid"] > 0
        and receipt.get("asset_receipt_sha256") == sha(ASSET)
        and receipt.get("old_qualification_sha256") == sha(QUALIFICATION)
        and all(type(receipt.get(k)) is int and receipt[k] == 0
                for k in ("generation_calls", "download_calls", "new_canary_calls")),
        "runtime_not_ready_or_assets_changed")
    require(qualification["generation_calls"] == 1, "old_qualification_changed")
    return receipt, {"runtime_ready.json": path, **paths}


def manifest():
    files = (list((ROOT / "memory_migration_study").glob("*.py"))
        + list((ROOT / "scripts").glob("*.py")) + list((ROOT / "scripts").glob("*.ps1"))
        + [ROOT / PREREG, ROOT / RUNTIME_BOOTSTRAP,
           ROOT / "tests/test_qwen35_sampling.py", ROOT / "tests/test_qwen35_sampling_probe.py"])
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(files))}


def freeze(output, runtime_receipt):
    output = Path(output).resolve()
    require(output.is_relative_to((ROOT / "results").resolve()) and not output.exists(), "output_scope_or_exists")
    receipt, paths = qualified_runtime(runtime_receipt)
    texts, policy, quotes, conditional, inputs = history.historical_inputs()
    requests, sources = requests_for(texts, policy), manifest()
    output.mkdir(parents=True)
    for base, mapping, prefix in ((ROOT, sources, "implementation"), (history.HISTORY, inputs, "history")):
        for name in mapping:
            target = output / prefix / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(base / name, target)
    (output / "receipts").mkdir()
    for name, path in paths.items():
        shutil.copyfile(path, output / "receipts" / name)
    values = {"requests.json": requests,
        "request_wires.json": {str(i): {a: [wire(b) for b in requests[str(i)][a]] for a in NEW_ARMS} for i in TEXT_IDS},
        "texts.json": texts,
        "historical_quote.json": quotes, "historical_conditional.json": conditional}
    for name, value in values.items():
        save(output / name, value)
    plan = {"version": VERSION, "text_ids": list(TEXT_IDS), "arms": list(ARMS), "limits": LIMITS,
        "generation_order": generation_order(), "model": MODEL, "model_digest": MODEL_DIGEST,
        "endpoint": ENDPOINT, "runtime_version": RUNTIME_VERSION, "policy": policy,
        "sources": sources, "inputs": inputs, "reference_parsed": False,
        "receipts": {n: {"path": str(p), "sha256": sha(p)} for n, p in paths.items()},
        "artifacts": {n: sha(output / n) for n in values},
        "request_sha256": {str(i): {a: [digest(b) for b in requests[str(i)][a]] for a in NEW_ARMS} for i in TEXT_IDS},
        "request_wire_sha256": {str(i): {a: [wire_sha(b) for b in requests[str(i)][a]] for a in NEW_ARMS} for i in TEXT_IDS},
        "identities": {a: SamplingQwen35Agent(arm=a, expected_digest=MODEL_DIGEST).cache_identity() for a in NEW_ARMS},
        "sampling_only_difference": "options.presence_penalty=1.5 or 0; old call/repair method unchanged",
        "runtime_ready_generation_calls": receipt["generation_calls"], "old_qualification_generation_calls": 1,
        "scope": "10 exposed difficult diagnostics, not independent acceptance, algorithm novelty or downstream refusal evidence",
        "memory_method": "exact full source, empty labels, separate actual migration preparation"}
    save(output / "plan.json", plan)
    return {"status": "frozen", "plan_sha256": sha(output / "plan.json"), "new_model_calls": 0}


def verify(output, expected):
    output = Path(output).resolve()
    require(output.is_relative_to((ROOT / "results").resolve()) and sha(output / "plan.json") == expected, "plan_changed_or_scope")
    plan = read_json(output / "plan.json")
    require(plan.get("version") == VERSION and plan.get("text_ids") == list(TEXT_IDS)
        and plan.get("arms") == list(ARMS) and plan.get("limits") == LIMITS
        and plan.get("generation_order") == generation_order() and plan.get("sources") == manifest()
        and plan.get("reference_parsed") is False and plan.get("model") == MODEL
        and plan.get("model_digest") == MODEL_DIGEST and plan.get("endpoint") == ENDPOINT
        and plan.get("runtime_version") == RUNTIME_VERSION and plan.get("runtime_ready_generation_calls") == 0
        and plan.get("old_qualification_generation_calls") == 1, "frozen_contract_changed")
    for prefix, key in (("implementation", "sources"), ("history", "inputs")):
        require(all(sha(output / prefix / n) == h for n, h in plan[key].items()), "archive_changed")
    require(all(sha(output / n) == h for n, h in plan["artifacts"].items()), "frozen_artifact_changed")
    _, paths = qualified_runtime(plan["receipts"]["runtime_ready.json"]["path"])
    require(set(paths) == set(plan["receipts"]), "receipt_inventory_changed")
    for name, path in paths.items():
        value = plan["receipts"][name]
        require(str(path) == value["path"] and sha(path) == value["sha256"]
            and sha(output / "receipts" / name) == value["sha256"], "receipt_changed")
    texts = read_json(output / "texts.json")
    require(type(texts) is list and len(texts) == 24 and all(type(t) is str for t in texts), "runtime_inventory")
    requests = requests_for(texts, plan["policy"])
    require(digest(read_json(output / "requests.json")) == digest(requests)
        and read_json(output / "request_wires.json") == {str(i): {a: [wire(b) for b in requests[str(i)][a]] for a in NEW_ARMS} for i in TEXT_IDS}
        and plan["request_sha256"] == {str(i): {a: [digest(b) for b in requests[str(i)][a]] for a in NEW_ARMS} for i in TEXT_IDS}
        and plan["request_wire_sha256"] == {str(i): {a: [wire_sha(b) for b in requests[str(i)][a]] for a in NEW_ARMS} for i in TEXT_IDS},
        "requests_changed")
    require(digest(plan["identities"]) == digest({a: SamplingQwen35Agent(arm=a,
        expected_digest=MODEL_DIGEST).cache_identity() for a in NEW_ARMS}), "sampling_identity_changed")
    return plan, texts, requests


@contextmanager
def network_guard():
    original = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo
    counts = {"allowed_connects": 0, "blocked_connects": 0}
    def check(address):
        if not (type(address) is tuple and len(address) == 2 and address == ("127.0.0.1", 11435)):
            counts["blocked_connects"] += 1
            raise PermissionError("sampling_network_destination_forbidden")
    def connect(sock, address):
        check(address)
        counts["allowed_connects"] += 1
        return original[0](sock, address)
    def connect_ex(sock, address):
        check(address)
        counts["allowed_connects"] += 1
        return original[1](sock, address)
    def resolve(host, port, *args, **kwargs):
        check((host, port))
        return original[2](host, port, *args, **kwargs)
    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, resolve
    try:
        yield counts
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = original


def response_counts(value):
    require(type(value) is dict and value.get("model") == MODEL and value.get("done") is True
        and value.get("done_reason") == "stop" and type(value.get("message")) is dict
        and type(value["message"].get("content")) is str and not value["message"].get("thinking")
        and not value["message"].get("tool_calls"), "incomplete_generation_envelope")
    p, o = value.get("prompt_eval_count"), value.get("eval_count")
    require(type(p) is int and 0 <= p <= LIMITS["prompt_tokens"] and type(o) is int
        and 0 <= o <= LIMITS["output_tokens"], "actual_token_budget_or_count_missing")
    return p, o


class BoundedClient:
    def __init__(self, output, requests, *, exchange=None, now=time.monotonic):
        self.output, self.requests = Path(output), deepcopy(requests)
        self.exchange, self.now = exchange or self._exchange, now
        self.started, self.events, self.cells, self.order = now(), [], {}, []
        self.deadline = Deadline(self.started + LIMITS["wall_seconds"], clock=self.now)
        self.active, self.closed = None, False

    def _exchange(self, method, path, body, event):
        raw = exchange_http(method, path, wire(body).encode("utf-8") if body is not None else None,
            host="127.0.0.1", port=11435, deadline=self.deadline, event=event,
            connection_factory=http.client.HTTPConnection)
        require(event["http_status"] == 200 and len(raw) <= 1048576, "local_http_failure")
        return raw.decode("utf-8")

    def begin_cell(self, index, arm):
        require(not self.closed and self.active is None and self.now() - self.started < LIMITS["wall_seconds"], "client_closed_or_wall_budget")
        cell = {"text_index": index, "arm": arm}
        require(type(index) is int and index in TEXT_IDS and arm in NEW_ARMS
            and len(self.order) < len(generation_order()) and generation_order()[len(self.order)] == cell
            and (index, arm) not in self.cells, "cell_order_or_duplicate")
        self.active = (index, arm)
        self.cells[self.active] = {"health": [], "posts": 0, "complete": False}
        self.order.append(cell)
        return self.transport

    def transport(self, method, path, body=None):
        require(not self.closed and self.active is not None and self.now() - self.started < LIMITS["wall_seconds"], "client_closed_or_wall_budget")
        index, arm = self.active
        state = self.cells[self.active]
        if method == "GET":
            require(body is None and len(state["health"]) < 2 and path == ("/api/version", "/api/tags")[len(state["health"])]
                and sum(e["method"] == "GET" for e in self.events) < LIMITS["health_gets"] and state["posts"] == 0,
                "health_budget_or_order")
            state["health"].append(path)
        else:
            require(method == "POST" and path == "/api/chat" and len(state["health"]) == 2
                and state["posts"] < LIMITS["posts_per_cell"]
                and sum(e["method"] == "POST" for e in self.events) < LIMITS["generation_posts"], "generation_budget_or_path")
            expected = self.requests[str(index)][arm][state["posts"]]
            require(digest(body) == digest(expected) and wire_sha(body) == wire_sha(expected), "actual_request_changed")
            state["posts"] += 1
        event = {"method": method, "path": path, "text_index": index, "arm": arm,
            "body": deepcopy(body), "wire_body": wire(body) if body is not None else None,
            "wire_body_sha256": wire_sha(body) if body is not None else None,
            "raw_response": None, "http_status": None, "error_type": None, "error": None}
        self.events.append(event)
        try:
            raw = self.exchange(method, path, body, event)
            require(type(raw) is str and len(raw.encode("utf-8")) <= 1048576, "response_too_large_or_invalid")
            event["raw_response"] = raw
            value = _strict_json(raw)
            if method == "POST":
                p, o = response_counts(value)
                event["token_counts"] = {"prompt": p, "predicted": o}
            require(self.now() - self.started < LIMITS["wall_seconds"], "wall_budget_exceeded")
            return value
        except Exception as error:
            event["error_type"], event["error"] = type(error).__name__, str(error)[:160]
            raise
        finally:
            save(self.output / ("transport_%03d.json" % len(self.events)), event)

    def finish_cell(self, response):
        state = self.cells[self.active]
        require(response.get("local_calls_complete") is True and type(response.get("local_calls")) is int
            and response["local_calls"] == state["posts"] and 1 <= state["posts"] <= 2
            and len(state["health"]) == 2 and all(e["error_type"] is None for e in self.events), "cell_transport_or_count_failure")
        index, arm = self.active
        require(response.get("sampling_arm") == arm and digest(response.get("sampling_identity"))
            == digest(SamplingQwen35Agent(arm=arm, expected_digest=MODEL_DIGEST).cache_identity()), "actual_sampling_identity_changed")
        state["complete"] = True
        self.active = None

    def close(self):
        self.closed = True

    def inventory(self):
        posts = [e for e in self.events if e["method"] == "POST"]
        complete = all("token_counts" in e for e in posts)
        return {"post_attempts": len(posts), "health_gets": sum(e["method"] == "GET" for e in self.events),
            "complete_generation_responses": sum("token_counts" in e for e in posts), "token_counts_complete": complete,
            "prompt_tokens": sum(e["token_counts"]["prompt"] for e in posts) if complete else None,
            "predicted_tokens": sum(e["token_counts"]["predicted"] for e in posts) if complete else None,
            "repair_posts": sum(max(0, c["posts"] - 1) for c in self.cells.values()),
            "completed_cells": sum(c["complete"] for c in self.cells.values()),
            "new_canary_calls": 0, "cloud_calls": 0, "new_target_posts": 0, "native_writes": 0}


def prepare_case(index, text, policy, responses, authority):
    require(set(responses) == set(ARMS), "arm_response_inventory")
    source = {"source_id": "source_%02d" % index, "text": text}
    fact = {"text": text, "source_start": 0, "source_end": len(text), "findings": []}
    record = authority.build_record(source, fact, policy, owner_id=prior.ACTOR, agent_id=prior.SOURCE_AGENT,
        allowed_principals=prior.PRINCIPALS, builder_version=VERSION, detector_version="empty_source_label_v1")
    rows = []
    for arm in ARMS:
        response = deepcopy(responses[arm])
        prepared = prior.prepare_record(text, record, policy, response, authority=authority,
            mode="migration", request_id="sampling-%02d-%s" % (index, arm))
        reasons = set()
        if prepared["status"] != "ok":
            reasons.update(response.get("errors", []))
            reasons.update((prepared.get("detection") or {}).get("errors", []))
            if prepared.get("error"):
                reasons.add(prepared["error"])
        semantic = response.get("status") == "needs_review" and response.get("errors") == ["semantic_uncertainty"]
        rows.append({"cell": {"text_index": index, "profile": prior.base.PROFILE, "arm": arm},
            "status": prepared["status"], "response": response, "record": deepcopy(record),
            "exact_protective_findings": prior.exact_findings(text, response.get("findings", [])),
            "preparation": prepared, "baseline_empty_labels": True,
            "semantic_review_evidence": {"detector": semantic}, "block_reasons": sorted(reasons),
            "observation_origin": "new_local_generation" if arm in NEW_ARMS else "historical_replay", "new_target_posts": 0})
    return rows


def format_observation(response):
    """Initial/final form from the unchanged adapter's attempt diagnostics.

    A one-call accepted result is also initial. A first output/envelope/transport
    error is explicit initial failure. Missing multi-attempt diagnostics remain
    unmeasured, rather than being inferred from the repaired final answer.
    """
    final = response.get("status") in ("ok", "needs_review") and response.get("errors") in ([], ["semantic_uncertainty"])
    calls, diagnostics = response.get("local_calls"), response.get("diagnostics", [])
    first_failure = any(type(d) is dict and type(d.get("attempt")) is int
        and d["attempt"] == 1 and d.get("stage") in ("output", "envelope", "transport") for d in diagnostics)
    initial = False if first_failure else final if type(calls) is int and calls == 1 else None
    return initial, final


def score_rows(rows, reference, texts, inventory):
    require(len(texts) == 24 and len(rows) == LIMITS["rows"]
        and all(type(r["cell"]["text_index"]) is int for r in rows)
        and {(r["cell"]["text_index"], r["cell"]["arm"]) for r in rows}
        == {(i, a) for i in TEXT_IDS for a in ARMS}, "prediction_grid_incomplete")
    refs = prior.scoring._validate_reference(reference, texts)
    groups, scored = {}, []
    for row in deepcopy(rows):
        i, a = row["cell"]["text_index"], row["cell"]["arm"]
        require(row["cell"]["profile"] == prior.base.PROFILE and row["baseline_empty_labels"] is True, "arm_contract_changed")
        values = prior.span_score(texts[i], row, refs[i]["expected"][prior.base.PROFILE], refs[i]["allowed_fact"])
        row["score"] = values
        scored.append(row)
        group = groups.setdefault(a, {**dict.fromkeys(values, 0), "acl_negative_controls": 0,
            "initial_format_span_valid": 0, "initial_format_span_invalid": 0,
            "initial_format_span_unmeasured": 0, "format_span_valid": 0,
            "format_repair_posts": 0, "statuses": {}, "block_reasons": {}})
        for k, v in values.items():
            group[k] += v
        controls = row["preparation"]["acl_negative_controls"]
        if row["preparation"]["status"] == "ok":
            require(len(controls) == 2 and all(c.get("status") == "rejected" and c.get("payload_is_none") is True
                and c.get("error") == "principal_not_authorized" for c in controls), "acl_controls_invalid")
        group["acl_negative_controls"] += len(controls)
        response = row["response"]
        initial, final = format_observation(response)
        group["initial_format_span_valid"] += int(initial is True)
        group["initial_format_span_invalid"] += int(initial is False)
        group["initial_format_span_unmeasured"] += int(initial is None)
        group["format_span_valid"] += int(final)
        group["format_repair_posts"] += max(0, response.get("local_calls", 0) - 1)
        group["statuses"][row["status"]] = group["statuses"].get(row["status"], 0) + 1
        for reason in row["block_reasons"]:
            group["block_reasons"][reason] = group["block_reasons"].get(reason, 0) + 1
    for g in groups.values():
        tp, fp, fn = (g["raw_predicted_protective_" + k] for k in ("tp", "fp", "fn"))
        g["raw_predicted_protective_precision"] = tp / (tp + fp) if tp + fp else None
        g["raw_predicted_protective_recall"] = tp / (tp + fn) if tp + fn else None
    zero, positive, strong = (groups[a] for a in ("presence_zero", "presence_15", "qwen3_conditional"))
    gates = {"precision": (zero["raw_predicted_protective_precision"] or 0) >= .9,
        "recall": (zero["raw_predicted_protective_recall"] or 0) >= .95,
        "no_prepared_leak": zero["prepared_incomplete_spans"] == 0,
        "known_prepared_noninferior": zero["known_prepared"] >= max(positive["known_prepared"], strong["known_prepared"]),
        "semantic_unknown_review": zero["unknown"] > 0 and zero["semantic_unknown_review"] == zero["unknown"],
        "acl_negative_controls": zero["acl_negative_controls"] == 2 * zero["prepared"],
        "cost_inventory": inventory.get("completed_cells") == 20 and inventory.get("health_gets") == 40
            and 20 <= inventory.get("post_attempts", 0) <= 40 and inventory.get("token_counts_complete") is True
            and inventory.get("complete_generation_responses") == inventory.get("post_attempts")}
    improved = zero["format_span_valid"] > positive["format_span_valid"] or (
        zero["format_span_valid"] == positive["format_span_valid"] and zero["format_repair_posts"] < positive["format_repair_posts"])
    return {"rows": scored, "by_arm": groups, "format_mechanism_improvement_observed": improved,
        "format_mechanism": {a: {k: groups[a][k] for k in ("initial_format_span_valid", "initial_format_span_invalid",
            "initial_format_span_unmeasured", "format_span_valid", "format_repair_posts")} for a in NEW_ARMS},
        "effect_gate_components": gates, "effect_gate_passed": all(gates.values()),
        "runtime_log_sampling_verified": None, "causal_configuration_qualified": None,
        "proceed_full24": False, "requires_independent_runtime_sampling_audit": True,
        "independent_acceptance_passed": None,
        "downstream_task_success": None, "refusal_rate": None,
        "scope": "10 exposed difficult texts; parameters are an engineering causal diagnostic, not a new algorithm"}


def close_predictions(output, expected, rows, responses, client, network):
    client.deadline.check()
    counts = client.inventory()
    require(client.closed and client.active is None and len(rows) == 40 and len(responses) == 10
        and {(r["cell"]["text_index"], r["cell"]["arm"]) for r in rows} == {(i, a) for i in TEXT_IDS for a in ARMS}
        and {r["text_index"] for r in responses} == set(TEXT_IDS) and client.order == generation_order()
        and counts["completed_cells"] == 20 and counts["health_gets"] == 40
        and 20 <= counts["post_attempts"] <= 40 and counts["token_counts_complete"]
        and counts["complete_generation_responses"] == counts["post_attempts"]
        and network["blocked_connects"] == 0 and client.now() - client.started < LIMITS["wall_seconds"], "prediction_phase_not_closed")
    save(output / "predictions.json", rows)
    save(output / "model_responses.json", responses)
    closed = {"plan_sha256": expected, "reference_parsed": False, "rows": 40,
        "text_ids": list(TEXT_IDS), "generation_order": client.order, "call_inventory": counts,
        "network": deepcopy(network), "capture_sha256": {p.name: sha(p) for p in sorted(output.glob("transport_*.json"))},
        "predictions_sha256": sha(output / "predictions.json"), "model_responses_sha256": sha(output / "model_responses.json")}
    client.deadline.check()
    save(output / "prediction_phase_closed.json", closed)
    return closed


def load_closed_reference(output, expected):
    closed = read_json(output / "prediction_phase_closed.json")
    require(closed.get("plan_sha256") == expected and closed.get("reference_parsed") is False
        and closed.get("rows") == 40 and closed.get("text_ids") == list(TEXT_IDS)
        and closed.get("generation_order") == generation_order(), "prediction_closure_invalid")
    for name, key in (("predictions.json", "predictions_sha256"), ("model_responses.json", "model_responses_sha256")):
        require(sha(output / name) == closed[key], "closed_prediction_changed")
    require(all(sha(output / n) == h for n, h in closed["capture_sha256"].items()), "closed_capture_changed")
    plan = read_json(output / "plan.json")
    path = output / "history/historical/historical/evaluation.opaque.json"
    require(sha(output / "plan.json") == expected and sha(path)
        == plan["inputs"]["historical/historical/evaluation.opaque.json"], "closed_reference_changed")
    return read_json(path)


def execute(output, expected, *, exchange=None):
    output = Path(output).resolve()
    plan, texts, requests = verify(output, expected)
    save(output / "execution_started.json", {"plan_sha256": expected, "version": VERSION, "reference_parsed": False})
    client = BoundedClient(output, requests, exchange=exchange)
    authority, rows, responses = MemoryLabelAuthority(secrets.token_bytes(32)), [], []
    quotes, conditional = read_json(output / "historical_quote.json"), read_json(output / "historical_conditional.json")
    complete, error = False, None
    try:
        with network_guard() as network:
            for ordinal, i in enumerate(TEXT_IDS):
                verify(output, expected)
                result = {"qwen35_quote": deepcopy(quotes[i]), "qwen3_conditional": deepcopy(conditional[i])}
                for arm in (NEW_ARMS if ordinal % 2 == 0 else tuple(reversed(NEW_ARMS))):
                    transport = client.begin_cell(i, arm)
                    agent = SamplingQwen35Agent(arm=arm, expected_digest=MODEL_DIGEST, transport=transport)
                    result[arm] = agent(text=texts[i], source_id="source_%02d" % i, policy=plan["policy"], rule_findings=[])
                    save(output / ("model_response_%02d_%s.json" % (i, arm)), result[arm])
                    client.finish_cell(result[arm])
                case_rows = prepare_case(i, texts[i], plan["policy"], result, authority)
                rows.extend(case_rows)
                responses.append({"text_index": i, "responses": result})
                save(output / ("prepared_%02d.json" % i), case_rows)
            client.close()
            verify(output, expected)
            close_predictions(output, expected, rows, responses, client, network)
        client.deadline.check()
        reference = load_closed_reference(output, expected)
        report = score_rows(rows, reference, texts, client.inventory())
        save(output / "scored_rows.json", report.pop("rows"))
        client.deadline.check()
        save(output / "report.json", {**report, "plan_sha256": expected, "call_inventory": client.inventory()})
        try:
            client.deadline.check()
        except DeadlineExceeded:
            (output / "report.json").unlink()
            raise
        complete = True
        return report
    except KeyboardInterrupt as exc:
        error = {"type": type(exc).__name__, "code": str(exc)[:160]}
        raise
    except Exception as exc:
        error = {"type": type(exc).__name__, "code": str(exc)[:160]}
        raise
    finally:
        client.close()
        save(output / "execution_final.json", {"plan_sha256": expected, "complete": complete,
            "status": "complete" if complete else "interrupted" if error and error["type"] == "KeyboardInterrupt" else "stopped",
            "completed_rows": len(rows), "unobserved_rows": 40 - len(rows), "error": error,
            "call_inventory": client.inventory(), "elapsed_seconds": round(time.monotonic() - client.started, 6)})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--execute", action="store_true")
    p.add_argument("--runtime-receipt", type=Path)
    p.add_argument("--expected-plan-sha256")
    a = p.parse_args()
    if a.execute:
        require(bool(a.expected_plan_sha256), "expected_plan_hash_required")
        result = execute(a.output, a.expected_plan_sha256)
    else:
        require(a.runtime_receipt is not None, "runtime_receipt_required")
        result = freeze(a.output, a.runtime_receipt)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
