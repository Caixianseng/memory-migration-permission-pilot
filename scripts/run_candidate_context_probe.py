"""One source-bound candidate inventory / entity-marker development comparison."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_relation_event_probe as base
from scripts import relation_probe_scoring as scoring
from scripts import relation_redaction_audit as redaction
from memory_migration_study import candidate_context_batch as batch
from memory_migration_study.local_detector import LocalSensitivityAgent, _strict_json
from memory_migration_study.sensitivity_contract import category_contract

ARMS = ("plain", "marked")
VERSION = "candidate_context_probe_v1"
PREREG = "docs/完整候选与位置标记_开发对照预注册_2026-10-27.md"
save, sha, require = base.save, base.sha, base.require


def inputs():
    texts, pools, policy, hashes = base.frozen_inputs()
    closed = json.loads((base.OLD / "prediction_phase_closed.json").read_text(encoding="utf-8"))
    capture = base.OLD / "encoder_capture.json"
    require(sha(capture) == closed["capture_sha256"][capture.name], "proposal_capture_changed")
    records = json.loads(capture.read_text(encoding="utf-8"))
    proposals = [r for r in records if r["event"].get("kind") == "proposal"]
    require([r["text_index"] for r in proposals] == list(range(12)), "proposal_capture_inventory")
    for i, (text, pool, record) in enumerate(zip(texts, pools, proposals)):
        event = record["event"]
        require(event["text"] == text and event["decoded_output"] == pool["raw_result"]
            and event["options"] == {"splitter": "cjk_aware", "threshold": 0.5}
            and event["labels"] == {"organization": category_contract("any_specific_organization")["definitions"]["CUSTOMER"]}
            and event["counts"]["proposal_infer_invocations"] == i+1, "proposal_capture_binding")
        batch.validate_pool(text, pool)
    return texts, pools, policy, {**hashes, "encoder_capture.json": sha(capture)}


def requests_for(texts, pools):
    requests, checks = {}, []
    for i, (text, pool) in enumerate(zip(texts, pools)):
        for arm in ARMS:
            request = batch.build_request(text, pool, mode=arm)
            body = {"model": base.MODEL, "messages": request["messages"], "format": request["schema"],
                    "stream": False, "keep_alive": "30m", "options": deepcopy(base.OPTIONS)}
            requests[(i, arm)] = body
            checks.append({"text_index": i, "arm": arm, "request_sha256": scoring._hash(body),
                           "preflight": request["preflight"]})
    return requests, checks


def manifest():
    paths = list((ROOT / "memory_migration_study").glob("*.py")) + [Path(__file__)]
    paths += [ROOT / name for name in (
        "scripts/run_relation_event_probe.py", "scripts/relation_probe_scoring.py",
        "scripts/relation_redaction_audit.py", "scripts/run_boundary_preparation_audit.py",
        "tests/test_candidate_context_batch.py", "tests/test_candidate_context_probe.py", PREREG)]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def freeze(output):
    require(output.is_relative_to(ROOT / "results") and not output.exists(), "output_scope_or_exists")
    texts, pools, policy, hashes = inputs()
    _, checks = requests_for(texts, pools)
    output.mkdir(parents=True)
    files = manifest()
    for name in files:
        dest = output / "implementation" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    for name in ("runtime.json", "evaluation.opaque.json"):
        shutil.copyfile(base.OLD / name, output / name)
    save(output / "pools.json", pools)
    plan = {"version": VERSION, "arms": ARMS, "inputs": hashes, "sources": files,
            "policy": policy, "pool_sha256": sha(output / "pools.json"), "checks": checks,
            "spec": batch.compiled_spec(), "options": base.OPTIONS, "model": base.MODEL,
            "digest": base.DIGEST, "ollama": base.OLLAMA_VERSION, "max_posts": 24,
            "wall_seconds": 1800, "repairs": 0, "reference_parsed": False,
            "scope": "12 exposed development texts; complete returned inventories, not complete true-entity coverage."}
    save(output / "plan.json", plan)
    return {"plan_sha256": sha(output / "plan.json"), "checks": checks, "new_model_calls": 0}


def verify(output, expected):
    require(sha(output / "plan.json") == expected, "plan_changed")
    plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
    texts, pools, policy, hashes = inputs()
    requests, checks = requests_for(texts, pools)
    require(plan["sources"] == manifest() and plan["inputs"] == hashes and plan["policy"] == policy
        and plan["checks"] == checks and plan["spec"] == batch.compiled_spec()
        and plan["options"] == base.OPTIONS, "frozen_contract_changed")
    for name, digest in plan["sources"].items():
        require(sha(output / "implementation" / name) == digest, "archive_changed")
    for name in ("runtime.json", "evaluation.opaque.json"):
        require(sha(output / name) == hashes[name], "material_changed")
    require(sha(output / "pools.json") == plan["pool_sha256"]
        and json.loads((output / "pools.json").read_text(encoding="utf-8")) == pools, "pool_changed")
    return plan, texts, pools, requests


def observe(text, pool, arm, body, client):
    raw = client("POST", "/api/chat", body)
    require(type(raw) is dict and raw.get("model") == base.MODEL, "model_identity_changed")
    require(type(raw.get("prompt_eval_count")) is int and 0 <= raw["prompt_eval_count"] <= 3072
        and type(raw.get("eval_count")) is int and 0 <= raw["eval_count"] <= 1024, "token_accounting")
    message = raw.get("message")
    if (raw.get("done") is not True or raw.get("done_reason") != "stop" or type(message) is not dict
        or not isinstance(message.get("content"), str) or message.get("thinking") or message.get("tool_calls")):
        response = base.failure_response("local_generation_incomplete")
        response["local_calls"] = 1
        return "model_output_invalid", response, raw
    try:
        response = batch.decode_response(text, pool, _strict_json(message["content"]), mode=arm)
        require(response["errors"] in ([], ["semantic_uncertainty"]), "decode_failed")
    except (ValueError, TypeError, KeyError):
        response = base.failure_response("invalid_schema")
        response["local_calls"] = 1
        return "model_output_invalid", response, raw
    response["local_calls"] = 1
    return response["status"], response, raw


def score(rows, reference, texts):
    require(type(rows) is list and len(texts) == 12 and all(type(r) is dict and type(r.get("cell")) is dict
        and set(r["cell"]) == {"text_index", "arm", "profile"}
        and type(r["cell"]["text_index"]) is int for r in rows), "invalid_grid")
    require(len(rows) == 24 and {(r["cell"]["text_index"], r["cell"]["arm"], r["cell"]["profile"]) for r in rows}
        == {(i, a, base.PROFILE) for i in range(12) for a in ARMS}, "incomplete_grid")
    refs = scoring._validate_reference(reference, texts)
    groups, scored = {}, []
    for row in deepcopy(rows):
        i, arm = row["cell"]["text_index"], row["cell"]["arm"]
        text, truth = texts[i], refs[i]["expected"][base.PROFILE]
        known = truth["decision"] != "needs_review"
        predicted = scoring._validate_status(row, text)
        sent, payload = scoring._validate_preparation(row, text)
        gold = scoring._spans(truth["spans"], text, reference=True)
        trace = row["redaction_trace"]
        require(trace["response_sha256"] == scoring._hash(row["response"])
            and trace["frozen_preparation_sha256"] == scoring._hash(row["preparation"]), "trace_binding")
        mask = redaction.score_observation(text, trace, truth)
        require(mask["ready"] == sent, "trace_ready")
        actual = ("sensitive" if predicted else "not_sensitive") if row["status"] == "ok" else row["status"]
        values = {"cells": 1, "known": int(known), "known_exact": int(known and sent and actual == truth["decision"] and predicted == gold),
            "known_prepared": int(known and sent), "prepared": int(sent),
            "unknown": int(not known), "unknown_review": int(not known and row["status"] == "needs_review"),
            "unknown_negative": int(not known and actual == "not_sensitive"),
            "tp": len(predicted & gold) if known else 0, "fp": len(predicted-gold) if known else 0,
            "fn": len(gold-predicted) if known else 0,
            "prepared_incomplete_spans": ((mask["partially_masked_spans"] or 0)+(mask["unmasked_spans"] or 0)) if sent and known else 0,
            "fully_masked_spans": mask["fully_masked_spans"] or 0,
            "reference_spans": len(gold), "allowed_fact_retained": int(sent and any(refs[i]["allowed_fact"]["text"] in s for s in payload))}
        row["score"] = {**values, "mask": mask}; scored.append(row)
        group = groups.setdefault(arm, {**{k: 0 for k in values}, "statuses": {}})
        for key, value in values.items(): group[key] += value
        group["statuses"][row["status"]] = group["statuses"].get(row["status"], 0)+1
    for group in groups.values():
        group["precision"] = group["tp"]/(group["tp"]+group["fp"]) if group["tp"]+group["fp"] else None
        group["recall"] = group["tp"]/(group["tp"]+group["fn"]) if group["tp"]+group["fn"] else None
    return {"by_arm": groups, "rows": scored}


def execute(output, expected):
    plan, texts, pools, requests = verify(output, expected)
    save(output / "execution_started.json", {"plan_sha256": expected, "reference_parsed": False})
    rows, client = [], base.Client(output)
    state = {"status": "started", "reference_parsed": False}
    network = {"loopback_connects": 0, "blocked_connects": 0}
    def guard(event, args):
        if event == "socket.connect":
            if not isinstance(args[1], tuple) or args[1][:2] != ("127.0.0.1", 11435):
                network["blocked_connects"] += 1
                raise RuntimeError("external_network_forbidden")
            network["loopback_connects"] += 1
    sys.addaudithook(guard)
    try:
        if not all(c["preflight"]["fits"] for c in plan["checks"]):
            state["status"] = "preflight_blocked"
            return state
        local = LocalSensitivityAgent(transport=client)
        save(output / "identity.json", local.health())
        for i, (text, pool) in enumerate(zip(texts, pools)):
            verify(output, expected)
            for arm in ARMS if i%2 == 0 else tuple(reversed(ARMS)):
                status, response, raw = observe(text, pool, arm, requests[(i, arm)], client)
                row = {"cell": {"text_index": i, "arm": arm, "profile": base.PROFILE}, "status": status,
                    "response": response, "raw_response": raw, "pool_sha256": pool["pool_sha256"],
                    "preparation": scoring.prepare_observation(text, plan["policy"], response)}
                row["redaction_trace"] = redaction.audit_observation(text, plan["policy"], row)
                rows.append(row); save(output / ("row_%02d.json" % len(rows)), row)
            print(json.dumps({"texts_completed": i+1, "generation_posts": client.posts}), flush=True)
        require(client.posts == 24 and network["blocked_connects"] == 0, "call_accounting")
        local.health(); client.closed = True
        save(output / "predictions.json", rows); verify(output, expected)
        closure = {"plan_sha256": expected, "predictions_sha256": sha(output / "predictions.json"),
            "reference_parsed": False, "generation_posts": client.posts, "network": network,
            "capture_sha256": {p.name: sha(p) for p in sorted(output.glob("transport_*.json"))}}
        save(output / "prediction_phase_closed.json", closure)
        reference = json.loads((output / "evaluation.opaque.json").read_text(encoding="utf-8"))
        state["reference_parsed"] = True
        results = score(rows, reference, texts)
        save(output / "scored_rows.json", results["rows"])
        verify(output, expected)
        require(sha(output / "predictions.json") == closure["predictions_sha256"]
            and all(sha(output / n) == s for n, s in closure["capture_sha256"].items()), "closed_evidence_changed")
        report = {"version": VERSION, "status": "complete", "by_arm": results["by_arm"],
            "generation_posts": client.posts, "unique_development_texts": 12, "cloud_calls": 0, "native_calls": 0,
            "repairs": 0, "network": network, "plan_sha256": expected,
            "closure_sha256": sha(output / "prediction_phase_closed.json"),
            "scope": "Exposed development diagnosis; no independent acceptance, downstream task or novelty claim."}
        save(output / "report.json", report); state["status"] = "complete"
        return report
    except Exception as error:
        state.update(status="stopped", error_type=type(error).__name__, error=str(error)); raise
    finally:
        state.update(rows=len(rows), generation_posts=client.posts, network=network, wall_seconds=time.monotonic()-client.started)
        save(output / "execution_final.json", state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-plan-sha")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(); output = args.output.resolve()
    print(json.dumps(freeze(output) if args.plan_only else execute(output, args.expected_plan_sha), ensure_ascii=False, indent=2))


if __name__ == "__main__": main()
