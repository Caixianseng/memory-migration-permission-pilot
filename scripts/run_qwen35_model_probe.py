"""Frozen 24-text model qualification; historical responses are replay, not calls.

Every arm uses the same empty-label migration preparation. No positive union,
reference-driven candidate construction, cloud inference or native write occurs.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_source_annotation_probe as prior
from memory_migration_study.qwen35_occurrence import (
    Qwen35OccurrenceAgent, MODEL, RUNTIME_VERSION, ENDPOINT, OPTIONS, build_request,
)
from memory_migration_study.local_detector import DIGEST as OLD_DIGEST
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.deadline_http import Deadline, DeadlineExceeded, exchange_http

save, sha, require = prior.save, prior.sha, prior.require
VERSION = "qwen35_fulltext_model_probe_v1"
PREREG = "docs/Qwen35全文检测_模型对照预注册_2026-10-28.md"
OLD = ROOT / "results/source_annotation_20261028_run_01"
PINNED = {
    "plan.json": "e93abc7b87e5127214c8a993dafdda678a5d0b29707e19e10ce3d9a6035a933e",
    "prediction_phase_closed.json": "30f5442632b6ec6fd9c639e3bbeb7cf3bef4c1fd62998b5fb32a8fe2498e9ef0",
    "predictions.json": "299a5a6212d02f3823240f31b98587d5fda3b4ebe5ec2e120464d5bd2b469046",
    "source_annotations.json": "5defa8b09b233b0bb4a6fa3bb639b8b55f27d7acc9631549f397c8b069f2f1f4",
    "receiver_responses.json": "f7c804785a0364c77859d2043784e48099eb9b563049d3997974f6c2c0263667",
}
ARMS = ("qwen3_fulltext", "qwen35_fulltext", "qwen3_conditional")
LIMITS = {"texts": 24, "rows": 72, "generation_posts": 48, "posts_per_text": 2,
          "qualification_generation_posts": 1, "wall_seconds": 1800,
          "cloud_calls": 0, "native_writes": 0, "new_target_posts": 0,
          "concurrent_requests": 1}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def wire_digest(value):
    """Match the fixed HTTP client's actual UTF-8 request serialization."""
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def workspace_file(path):
    path = Path(path).resolve()
    require(path.is_relative_to(ROOT.resolve()) and path.is_file(), "receipt_scope_or_missing")
    return path


def qualified_receipts(asset_path, qualification_path):
    asset_path, qualification_path = map(workspace_file, (asset_path, qualification_path))
    asset, qualification = read_json(asset_path), read_json(qualification_path)
    expected = {"model": MODEL, "version": RUNTIME_VERSION, "endpoint": ENDPOINT}
    require(asset.get("status") == "assets_verified" and all(asset.get(k) == v for k, v in expected.items())
            and type(asset.get("generation_calls")) is int and asset["generation_calls"] == 0,
            "asset_receipt_not_qualified")
    model_digest = asset.get("model_digest")
    require(isinstance(model_digest, str) and re.fullmatch(r"[a-f0-9]{64}", model_digest)
            and model_digest != OLD_DIGEST, "asset_digest_invalid")
    require(qualification.get("status") == "qualified"
            and all(qualification.get(k) == v for k, v in {**expected, "model_digest": model_digest}.items())
            and type(qualification.get("generation_calls")) is int and qualification["generation_calls"] == 1
            and type(qualification.get("formal_texts")) is int and qualification["formal_texts"] == 0
            and all(qualification.get(k) is True for k in
                    ("thinking_disabled", "json_schema_valid", "complete_generation")),
            "inference_qualification_required")
    require(qualification.get("asset_receipt_sha256") == sha(asset_path)
            and digest(qualification.get("adapter_identity")) == digest(Qwen35OccurrenceAgent(
                expected_digest=model_digest).cache_identity()), "qualification_adapter_or_assets_changed")
    paths = {"asset_receipt.json": asset_path, "inference_qualification.json": qualification_path,
             "show.json": workspace_file(asset_path.parent / "show.json")}
    for name, key in (("inference_request.json", "request_sha256"),
                      ("inference_response.json", "response_sha256")):
        path = workspace_file(qualification_path.parent / name)
        require(sha(path) == qualification.get(key), "qualification_capture_changed")
        paths[name] = path
    return asset, qualification, paths


def historical_inputs():
    require(all(sha(OLD / n) == h for n, h in PINNED.items()), "historical_roots_changed")
    plan, closure = read_json(OLD / "plan.json"), read_json(OLD / "prediction_phase_closed.json")
    require(closure["plan_sha256"] == PINNED["plan.json"] and closure["reference_parsed"] is False
            and closure["rows"] == 72 and closure["predictions_sha256"] == PINNED["predictions.json"]
            and closure["source_annotations_sha256"] == PINNED["source_annotations.json"],
            "historical_closure_invalid")
    inputs = {**PINNED, **{"historical/" + n: plan["inputs"][n]
                          for n in ("runtime.json", "evaluation.opaque.json")}}
    require(all(sha(OLD / n) == h for n, h in inputs.items()), "historical_material_changed")
    require(all(sha(OLD / n) == h for n, h in closure["capture_sha256"].items()),
            "historical_capture_changed")
    texts = prior.previous.read_runtime(OLD / "historical/runtime.json")
    annotations, receivers = read_json(OLD / "source_annotations.json"), read_json(OLD / "receiver_responses.json")
    require(type(annotations) is list and len(annotations) == 24 and type(receivers) is list
            and len(receivers) == 24, "historical_response_inventory")
    fulltext = [deepcopy(a["source_response"]) for a in annotations]
    require(all(isinstance(r, dict) and r.get("model") == prior.base.MODEL
                and r.get("digest") == OLD_DIGEST for r in fulltext), "historical_model_changed")
    requests = requests_for(texts, plan["policy"])
    attempts = dict.fromkeys(range(24), 0)
    for name in sorted(closure["capture_sha256"]):
        event = read_json(OLD / name)
        if event["method"] != "POST":
            continue
        body = event["body"]
        text = json.loads(body["messages"][1]["content"])["text"]
        require(text in texts, "historical_request_text_changed")
        index = texts.index(text)
        require(attempts[index] < 2, "historical_request_attempts_changed")
        comparable = deepcopy(requests[index][attempts[index]])
        comparable.pop("think")
        comparable["model"] = prior.base.MODEL
        require(digest(body) == digest(comparable), "historical_fulltext_method_changed")
        attempts[index] += 1
    require(all(attempts[i] == fulltext[i]["local_calls"] for i in range(24)),
            "historical_generation_count_changed")
    inputs.update(closure["capture_sha256"])
    return texts, fulltext, receivers, deepcopy(plan["policy"]), inputs


def manifest():
    paths = list((ROOT / "memory_migration_study").glob("*.py")) + list((ROOT / "scripts").glob("*.py"))
    paths += [ROOT / PREREG, ROOT / "tests/test_qwen35_model_probe.py",
              ROOT / "tests/test_qwen35_occurrence.py", ROOT / "scripts/qualify_qwen35_assets.ps1"]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(paths))}


def requests_for(texts, policy):
    return [[build_request(text, "source_%02d" % i, policy, [], repair=repair)
             for repair in (False, True)] for i, text in enumerate(texts)]


def freeze(output, model_receipt, qualification_receipt):
    output = Path(output).resolve()
    require(output.is_relative_to(ROOT / "results") and not output.exists(), "output_scope_or_exists")
    asset, qualification, receipt_paths = qualified_receipts(model_receipt, qualification_receipt)
    texts, fulltext, receivers, policy, inputs = historical_inputs()
    sources, requests = manifest(), requests_for(texts, policy)
    output.mkdir(parents=True)
    for name in sources:
        destination = output / "implementation" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    for name in inputs:
        destination = output / "historical" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(OLD / name, destination)
    (output / "receipts").mkdir()
    for name, path in receipt_paths.items():
        shutil.copyfile(path, output / "receipts" / name)
    save(output / "historical_fulltext_responses.json", fulltext)
    save(output / "historical_conditional_responses.json", receivers)
    save(output / "requests.json", requests)
    plan = {"version": VERSION, "model": MODEL, "model_digest": asset["model_digest"],
            "runtime_version": RUNTIME_VERSION, "endpoint": ENDPOINT,
            "options": OPTIONS, "think": False, "limits": LIMITS, "arms": list(ARMS),
            "sources": sources, "inputs": inputs, "policy": policy,
            "receipts": {n: {"path": str(p), "sha256": sha(p)} for n, p in receipt_paths.items()},
            "qualification_generation_calls": qualification["generation_calls"],
            "requests_sha256": sha(output / "requests.json"),
            "request_sha256": [[digest(r) for r in case] for case in requests],
            "request_wire_sha256": [[wire_digest(r) for r in case] for case in requests],
            "historical_fulltext_sha256": sha(output / "historical_fulltext_responses.json"),
            "historical_conditional_sha256": sha(output / "historical_conditional_responses.json"),
            "historical_fulltext_request_method_matched": True,
            "principals": prior.PRINCIPALS, "reference_parsed": False,
            "scope": "24 exposed development texts; not independent acceptance; downstream/refusal unmeasured",
            "comparison": "Same full-text method for model comparison; historical conditional is a different-method strong baseline; no protective union.",
            "memory_method": "exact full-source copy, empty source labels, separate migration preparation"}
    save(output / "plan.json", plan)
    return {"status": "frozen", "plan_sha256": sha(output / "plan.json"), "new_model_calls": 0}


def verify(output, expected):
    require(type(expected) is str and sha(output / "plan.json") == expected, "plan_changed")
    plan = read_json(output / "plan.json")
    texts, fulltext, receivers, policy, inputs = historical_inputs()
    receipt_paths = plan["receipts"]
    asset, qualification, current = qualified_receipts(receipt_paths["asset_receipt.json"]["path"],
                                                      receipt_paths["inference_qualification.json"]["path"])
    require(plan["version"] == VERSION and plan["sources"] == manifest() and plan["inputs"] == inputs
            and plan["policy"] == policy and plan["limits"] == LIMITS and plan["options"] == OPTIONS
            and plan["arms"] == list(ARMS) and plan["principals"] == prior.PRINCIPALS
            and plan["model"] == MODEL and plan["model_digest"] == asset["model_digest"]
            and plan["runtime_version"] == RUNTIME_VERSION and plan["endpoint"] == ENDPOINT
            and plan["think"] is False and plan["reference_parsed"] is False
            and plan["qualification_generation_calls"] == qualification["generation_calls"],
            "frozen_contract_changed")
    for name, h in plan["sources"].items():
        require(sha(output / "implementation" / name) == h, "archive_changed")
    for name, h in inputs.items():
        require(sha(output / "historical" / name) == h, "copied_material_changed")
    require(set(current) == set(receipt_paths), "receipt_inventory_changed")
    for name, path in current.items():
        require(str(path) == receipt_paths[name]["path"] and sha(path) == receipt_paths[name]["sha256"]
                and sha(output / "receipts" / name) == receipt_paths[name]["sha256"], "receipt_changed")
    requests = requests_for(texts, policy)
    require(sha(output / "requests.json") == plan["requests_sha256"]
            and read_json(output / "requests.json") == requests
            and [[digest(r) for r in case] for case in requests] == plan["request_sha256"]
            and [[wire_digest(r) for r in case] for case in requests] == plan["request_wire_sha256"], "requests_changed")
    for name, key, values in (("historical_fulltext_responses.json", "historical_fulltext_sha256", fulltext),
                              ("historical_conditional_responses.json", "historical_conditional_sha256", receivers)):
        require(sha(output / name) == plan[key] and read_json(output / name) == values,
                "historical_response_changed")
    return plan, texts, fulltext, receivers, requests


class BoundedClient(prior.base.Client):
    """The exact prebuilt body for each attempt is enforced before transport."""
    def __init__(self, output, requests, *, exchange=None):
        super().__init__(output, exchange=exchange)
        self.deadline = Deadline(self.started + LIMITS["wall_seconds"], clock=lambda: time.monotonic())
        self.requests, self.active_text, self.per_text_posts = deepcopy(requests), None, {}

    def begin_text(self, index):
        require(type(index) is int and 0 <= index < 24 and index not in self.per_text_posts,
                "text_repeated_or_invalid")
        self.active_text, self.per_text_posts[index] = index, 0

    def _exchange(self, method, path, body):
        event = self.events[-1]
        encoded = event["wire_body"].encode("utf-8") if body is not None else None
        raw = exchange_http(method, path, encoded, host="127.0.0.1", port=11435,
            deadline=self.deadline, event=event, connection_factory=http.client.HTTPConnection)
        require(event["http_status"] == 200 and len(raw) <= 1048576, "local_http_failure")
        return raw.decode("utf-8")

    def __call__(self, method, path, body=None):
        require(not self.closed and time.monotonic() - self.started < LIMITS["wall_seconds"],
                "client_closed_or_wall_budget")
        require((method == "GET" and path in {"/api/version", "/api/tags"} and body is None)
                or (method == "POST" and path == "/api/chat"), "transport_route_forbidden")
        if method == "POST":
            require(self.active_text is not None and self.posts < LIMITS["generation_posts"]
                    and self.per_text_posts[self.active_text] < LIMITS["posts_per_text"], "generation_budget")
            attempt = self.per_text_posts[self.active_text]
            require(digest(body) == digest(self.requests[self.active_text][attempt])
                    and wire_digest(body) == wire_digest(self.requests[self.active_text][attempt]), "actual_request_changed")
            self.per_text_posts[self.active_text] += 1
            self.posts += 1
        event = {"method": method, "path": path, "text_index": self.active_text,
                 "body": deepcopy(body), "wire_body_sha256": wire_digest(body) if body is not None else None,
                 "wire_body": json.dumps(body, ensure_ascii=False, allow_nan=False) if body is not None else None,
                 "raw_response": None, "http_status": None, "error_type": None}
        self.events.append(event)
        try:
            event["raw_response"] = self.exchange(method, path, body)
            decoded = prior.base._strict_json(event["raw_response"])
            if method == "POST":
                require(type(decoded) is dict and type(decoded.get("prompt_eval_count")) is int
                        and 0 <= decoded["prompt_eval_count"] <= OPTIONS["num_ctx"]
                        and type(decoded.get("eval_count")) is int
                        and 0 <= decoded["eval_count"] <= OPTIONS["num_predict"], "actual_token_budget_or_count_missing")
            require(time.monotonic() - self.started < LIMITS["wall_seconds"], "wall_budget_exceeded")
            return decoded
        except Exception as error:
            event["error_type"] = type(error).__name__
            raise
        finally:
            save(self.output / ("transport_%03d.json" % len(self.events)), event)

    def inventory(self):
        events = [e for e in self.events if e["method"] == "POST"]
        decoded = []
        for event in events:
            try:
                value = prior.base._strict_json(event["raw_response"]) if event["raw_response"] is not None else None
            except (ValueError, TypeError):
                value = None
            decoded.append(value)
        complete = len(events) == self.posts and all(type(e) is dict and type(e.get("prompt_eval_count")) is int
            and 0 <= e["prompt_eval_count"] <= OPTIONS["num_ctx"] and type(e.get("eval_count")) is int
            and 0 <= e["eval_count"] <= OPTIONS["num_predict"] for e in decoded)
        return {"post_attempts": self.posts,
                "raw_generation_responses": sum(e["raw_response"] is not None for e in events),
                "complete_generation_responses": sum(type(e) is dict and e.get("done") is True
                    and e.get("done_reason") == "stop" for e in decoded),
                "health_gets": sum(e["method"] == "GET" for e in self.events),
                "token_counts_complete": complete,
                "prompt_eval_count": sum(e["prompt_eval_count"] for e in decoded) if complete else None,
                "eval_count": sum(e["eval_count"] for e in decoded) if complete else None}


def prepare_case(index, text, policy, responses, authority):
    source = {"source_id": "source_%02d" % index, "text": text}
    fact = {"text": text, "source_start": 0, "source_end": len(text), "findings": []}
    record = authority.build_record(source, fact, policy, owner_id=prior.ACTOR, agent_id=prior.SOURCE_AGENT,
        allowed_principals=prior.PRINCIPALS, builder_version=VERSION, detector_version="empty_source_label_v1")
    rows = []
    require(set(responses) == set(ARMS), "arm_response_inventory")
    for arm in ARMS:
        response = deepcopy(responses[arm])
        prepared = prior.prepare_record(text, record, policy, response, authority=authority,
                                        mode="migration", request_id="model-probe-%02d-%s" % (index, arm))
        reasons = set()
        if prepared["status"] != "ok":
            reasons.update(response.get("errors", []))
            reasons.update((prepared.get("detection") or {}).get("errors", []))
            if prepared.get("error"):
                reasons.add(prepared["error"])
        uncertain = response.get("status") == "needs_review" and response.get("errors") == ["semantic_uncertainty"]
        rows.append({"cell": {"text_index": index, "profile": prior.base.PROFILE, "arm": arm},
                     "status": prepared["status"], "response": response, "record": deepcopy(record),
                     "exact_protective_findings": prior.exact_findings(text, response.get("findings", [])),
                     "preparation": prepared, "baseline_empty_labels": True,
                     "semantic_review_evidence": {"detector": uncertain}, "block_reasons": sorted(reasons),
                     "new_target_posts": 0, "observation_origin": "new_local_generation" if arm == ARMS[1] else "historical_replay"})
    return rows


def score_rows(rows, reference, texts):
    require(len(texts) == 24 and len(rows) == 72
            and {(r["cell"]["text_index"], r["cell"]["arm"]) for r in rows}
            == {(i, a) for i in range(24) for a in ARMS}, "prediction_grid_incomplete")
    refs = prior.scoring._validate_reference(reference, texts)
    groups, scored = {}, []
    for row in deepcopy(rows):
        i, arm = row["cell"]["text_index"], row["cell"]["arm"]
        require(row["cell"]["profile"] == prior.base.PROFILE and row["baseline_empty_labels"] is True,
                "arm_contract_changed")
        values = prior.span_score(texts[i], row, refs[i]["expected"][prior.base.PROFILE], refs[i]["allowed_fact"])
        row["score"] = values
        scored.append(row)
        group = groups.setdefault(arm, {**dict.fromkeys(values, 0), "statuses": {}, "block_reasons": {},
                                       "acl_negative_controls": 0})
        for key, value in values.items():
            group[key] += value
        controls = row["preparation"]["acl_negative_controls"]
        if row["preparation"]["status"] == "ok":
            require(len(controls) == 2 and all(c.get("status") == "rejected" and c.get("payload_is_none") is True
                    and c.get("error") == "principal_not_authorized" for c in controls), "acl_controls_invalid")
        group["acl_negative_controls"] += len(controls)
        group["statuses"][row["status"]] = group["statuses"].get(row["status"], 0) + 1
        for reason in row["block_reasons"]:
            group["block_reasons"][reason] = group["block_reasons"].get(reason, 0) + 1
    for group in groups.values():
        tp, fp, fn = (group["raw_predicted_protective_" + k] for k in ("tp", "fp", "fn"))
        group["raw_predicted_protective_precision"] = tp / (tp + fp) if tp + fp else None
        group["raw_predicted_protective_recall"] = tp / (tp + fn) if tp + fn else None
    new, strong = groups[ARMS[1]], groups[ARMS[2]]
    gates = {"precision": (new["raw_predicted_protective_precision"] or 0) >= .9,
             "recall": (new["raw_predicted_protective_recall"] or 0) >= .95,
             "no_prepared_leak": new["prepared_incomplete_spans"] == 0,
             "known_prepared_noninferior": new["known_prepared"] >= strong["known_prepared"],
             "semantic_unknown_review": new["unknown"] == 4 and new["semantic_unknown_review"] == 4,
             "acl_negative_controls": new["acl_negative_controls"] == 2 * new["prepared"]}
    return {"rows": scored, "by_arm": groups, "gate_components": gates,
            "development_gate_passed": all(gates.values()), "downstream_task_success": None,
            "refusal_rate": None, "independent_acceptance_passed": None,
            "case22": {r["cell"]["arm"]: r for r in scored if r["cell"]["text_index"] == 22}}


def close_prediction_phase(output, expected, rows, responses, client, network):
    client.deadline.check()
    require(client.closed and len(rows) == 72 and len(responses) == 24 and network["blocked_connects"] == 0,
            "prediction_phase_not_closed")
    save(output / "predictions.json", rows)
    save(output / "model_responses.json", responses)
    closure = {"plan_sha256": expected, "reference_parsed": False, "rows": 72,
               "new_generation_posts": client.posts, "new_target_posts": 0,
               "per_text_posts": client.per_text_posts, "network": deepcopy(network),
               "call_inventory": client.inventory(),
               "capture_sha256": {p.name: sha(p) for p in sorted(output.glob("transport_*.json"))},
               "predictions_sha256": sha(output / "predictions.json"),
               "model_responses_sha256": sha(output / "model_responses.json")}
    client.deadline.check()
    save(output / "prediction_phase_closed.json", closure)
    return closure


def load_closed_reference(output, expected):
    closure = read_json(output / "prediction_phase_closed.json")
    require(closure["plan_sha256"] == expected and closure["reference_parsed"] is False
            and closure["rows"] == 72, "prediction_closure_invalid")
    for name, key in (("predictions.json", "predictions_sha256"), ("model_responses.json", "model_responses_sha256")):
        require(sha(output / name) == closure[key], "closed_prediction_changed")
    require(all(sha(output / n) == h for n, h in closure["capture_sha256"].items()), "closed_capture_changed")
    return read_json(output / "historical/historical/evaluation.opaque.json")


def execute(output, expected):
    plan, texts, fulltext, receivers, requests = verify(output, expected)
    save(output / "execution_started.json", {"plan_sha256": expected, "reference_parsed": False})
    client = BoundedClient(output, requests)
    network = {"loopback_connects": 0, "blocked_connects": 0}
    prior.install_network_guard(network)
    agent = Qwen35OccurrenceAgent(expected_digest=plan["model_digest"], transport=client)
    authority, rows, responses = MemoryLabelAuthority(secrets.token_bytes(32)), [], []
    state = {"status": "started", "reference_parsed": False, "planned_texts": 24}
    fatal = {"local_health_failed", "local_transport_failed", "local_response_model_mismatch",
             "local_generation_incomplete", "local_response_invalid", "unexpected_model_behavior",
             "input_budget_exceeded", "invalid_input_or_policy", "repair_budget_exceeded", "local_failure"}
    try:
        for i, text in enumerate(texts):
            verify(output, expected)
            client.begin_text(i)
            before = client.posts
            response = agent(text=text, source_id="source_%02d" % i, policy=plan["policy"], rule_findings=[])
            require(response.get("local_calls_complete") is True and type(response.get("local_calls")) is int
                    and response["local_calls"] == client.posts - before <= 2, "generation_cost_accounting")
            responses.append(response)
            case_rows = prepare_case(i, text, plan["policy"], dict(zip(ARMS, (fulltext[i], response, receivers[i]))), authority)
            rows.extend(case_rows)
            save(output / ("model_response_%02d.json" % i), response)
            for row in case_rows:
                save(output / ("row_%02d_%s.json" % (i, row["cell"]["arm"])), row)
            print(json.dumps({"texts_completed": i + 1, "rows": len(rows), "new_generation_posts": client.posts}), flush=True)
            require(not fatal.intersection(response.get("errors", [])), "fatal_runtime_observation")
        client.closed = True
        verify(output, expected)
        inventory = client.inventory()
        require(inventory["token_counts_complete"] is True
                and inventory["raw_generation_responses"] == client.posts, "generation_cost_accounting")
        close_prediction_phase(output, expected, rows, responses, client, network)
        client.deadline.check()
        reference = load_closed_reference(output, expected)
        state["reference_parsed"] = True
        results = score_rows(rows, reference, texts)
        require(all(g["known"] == 20 and g["unknown"] == 4 for g in results["by_arm"].values()),
                "registered_reference_inventory_changed")
        save(output / "scored_rows.json", results["rows"])
        verify(output, expected)
        report = {k: v for k, v in results.items() if k != "rows"}
        report.update(version=VERSION, status="complete", model=MODEL, model_digest=plan["model_digest"],
            runtime_version=RUNTIME_VERSION, new_generation_posts=client.posts,
            qualification_generation_posts=1, total_new_generation_posts=client.posts + 1,
            historical_replay_rows=48, new_target_posts=0, cloud_calls=0, native_writes=0,
            network=network, unique_development_texts=24, rows=72, cost_complete=True,
            source_elapsed_seconds=sum(r["elapsed_seconds"] for r in responses),
            plan_sha256=expected, closure_sha256=sha(output / "prediction_phase_closed.json"),
            scope=plan["scope"], comparison=plan["comparison"])
        # Include every physical repair response; missing counts never become 0.
        report.update(inventory)
        report["gate_components"]["cost_complete"] = inventory["token_counts_complete"]
        report["development_gate_passed"] = all(report["gate_components"].values())
        client.deadline.check()
        save(output / "report.json", report)
        try:
            client.deadline.check()
        except DeadlineExceeded:
            (output / "report.json").unlink()
            raise
        state["status"] = "complete"
        return report
    except KeyboardInterrupt as error:
        state.update(status="interrupted", error_type=type(error).__name__, error=str(error))
        raise
    except Exception as error:
        state.update(status="stopped", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        client.closed = True
        state.update(rows=len(rows), completed_texts=len(responses), unobserved_texts=24 - len(responses),
                     new_generation_posts=client.posts, new_target_posts=0, network=network,
                     call_inventory=client.inventory(),
                     wall_seconds=time.monotonic() - client.started)
        save(output / "execution_final.json", state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model-receipt", type=Path)
    parser.add_argument("--qualification-receipt", type=Path)
    parser.add_argument("--expected-plan-sha")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to(ROOT / "results"), "output_scope")
    if args.plan_only:
        require(args.model_receipt is not None and args.qualification_receipt is not None, "qualified_receipts_required")
        result = freeze(output, args.model_receipt, args.qualification_receipt)
    else:
        result = execute(output, args.expected_plan_sha)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
