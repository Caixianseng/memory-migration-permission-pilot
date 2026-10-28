"""Independent stdlib audit of a closed Qwen3.5 three-arm development run.

No producer scoring imports, network, model calls, restoration-map loading or
offline HMAC re-verification. Only a new requested audit directory is written.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_source_annotation_probe import (
    require, read, sha, text_sha, canonical_sha, spans, footprint, record_binding,
)

ARMS = ("qwen3_fulltext", "qwen35_fulltext", "qwen3_conditional")
PROFILE = "strict_customer_relation"


def strict_json(value):
    def unique(items):
        result = {}
        for key, item in items:
            require(key not in result, "duplicate_json_key")
            result[key] = item
        return result
    def nonfinite(value):
        raise ValueError("nonfinite_json")
    return json.loads(value, object_pairs_hook=unique, parse_constant=nonfinite)


def same(left, right):
    encode = lambda v: json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return encode(left) == encode(right)


def rule_literal(node):
    # Only a literal or a one-argument frozenset(literal) declaration is read;
    # no frozen producer code is executed by the audit.
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "frozenset" and len(node.args) == 1 and not node.keywords):
        return frozenset(ast.literal_eval(node.args[0]))
    return ast.literal_eval(node)


def occurrence_decode(content, text, pairs, punctuation):
    value = strict_json(content)
    require(type(value) is dict and set(value) == {"status", "findings"}
            and value["status"] in {"ok", "needs_review"}
            and type(value["findings"]) is list and len(value["findings"]) <= 32, "raw_schema")
    findings, repairs = set(), 0
    for item in value["findings"]:
        require(type(item) is dict and set(item) == {"quote", "occurrence", "category"}, "raw_finding_schema")
        quote, number = item["quote"], item["occurrence"]
        require(type(quote) is str and quote and type(number) is int and number >= 1
                and item["category"] == "CUSTOMER", "raw_finding_type")
        if quote not in text:
            wrapped = quote.strip()
            if wrapped and wrapped[-1] in punctuation:
                wrapped = wrapped[:-1]
            choices = [wrapped[1:-1] for a, b in pairs if len(wrapped) > 2
                       and wrapped.startswith(a) and wrapped.endswith(b) and wrapped[1:-1] in text]
            require(bool(choices), "raw_quote_absent")
            quote, repairs = choices[0], repairs + 1
        starts = [m.start() for m in re.finditer("(?=" + re.escape(quote) + ")", text)]
        require(number <= len(starts), "raw_occurrence_range")
        a = starts[number-1]
        findings.add((a, a + len(quote), "CUSTOMER"))
    return value["status"], findings, repairs


def independent_score(text, row, truth, fact, mask):
    predicted = spans(row["exact_protective_findings"], text)
    gold = spans(truth["spans"], text, reference=True)
    known, ready = truth["decision"] != "needs_review", row["status"] == "ok"
    protected = {p for a, b, _ in gold for p in range(a, b)}
    extra = len(mask - protected) if known and ready else 0
    full = partial = absent = 0
    for a, b, _ in gold:
        n = len(mask.intersection(range(a, b)))
        full += int(ready and n == b-a)
        partial += int(ready and 0 < n < b-a)
        absent += int(ready and n == 0)
    semantic = not ready and row["semantic_review_evidence"]["detector"]
    return {"total": 1, "known": int(known), "unknown": int(not known), "prepared": int(ready),
        "known_prepared": int(known and ready), "blocked": int(not ready),
        "known_exact": int(known and ready and predicted == gold), "unknown_blocked": int(not known and not ready),
        "semantic_unknown_review": int(not known and semantic),
        "unknown_blocked_without_semantic_uncertainty": int(not known and not ready and not semantic),
        "unknown_prepared": int(not known and ready), "raw_predicted_protective_tp": len(predicted & gold) if known else 0,
        "raw_predicted_protective_fp": len(predicted - gold) if known else 0,
        "raw_predicted_protective_fn": len(gold - predicted) if known else 0, "reference_spans": len(gold),
        "fully_masked_spans": full, "partially_masked_spans": partial, "unmasked_spans": absent,
        "prepared_incomplete_spans": partial + absent, "actual_masked_unprotected_chars": extra,
        "known_prepared_with_unprotected_masking": int(extra > 0),
        "blocked_reference_spans": len(gold) if not ready else 0,
        "allowed_fact_retained": int(ready and not mask.intersection(range(fact["start"], fact["end"]))),
        "allowed_fact_total": 1}


def verify(run, expected):
    plan, closed, report, final = (read(run / n) for n in
        ("plan.json", "prediction_phase_closed.json", "report.json", "execution_final.json"))
    require(sha(run / "plan.json") == expected == closed["plan_sha256"] == report["plan_sha256"], "plan_hash")
    require(plan["arms"] == list(ARMS) and plan["limits"]["generation_posts"] == 48
            and plan["limits"]["posts_per_text"] == 2 and plan["think"] is False
            and plan["options"] == {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42}, "plan_contract")
    for n, h in plan["sources"].items():
        require(sha(run / "implementation" / n) == h, "frozen_source_hash:" + n)
    for n, h in plan["inputs"].items():
        require(sha(run / "historical" / n) == h, "historical_hash:" + n)
    for n, item in plan["receipts"].items():
        require(sha(run / "receipts" / n) == item["sha256"], "receipt_hash:" + n)
    asset, qualification = (read(run / "receipts" / n) for n in ("asset_receipt.json", "inference_qualification.json"))
    require(asset["status"] == "assets_verified" and qualification["status"] == "qualified"
            and asset["model"] == qualification["model"] == plan["model"]
            and asset["model_digest"] == qualification["model_digest"] == plan["model_digest"]
            and asset["version"] == qualification["version"] == plan["runtime_version"] == "0.40.8"
            and qualification["generation_calls"] == 1 and qualification["formal_texts"] == 0
            and qualification["asset_receipt_sha256"] == sha(run / "receipts/asset_receipt.json"), "qualification_binding")
    for kind in ("request", "response"):
        require(qualification[kind + "_sha256"] == sha(run / f"receipts/inference_{kind}.json"), "qualification_capture")
    identity = qualification["adapter_identity"]
    require(identity["implementation_sha256"] == plan["sources"]["memory_migration_study/qwen35_occurrence.py"]
            and identity["occurrence_implementation_sha256"] == plan["sources"]["memory_migration_study/occurrence_qwen.py"], "qualified_code_identity")
    for n, key in (("predictions.json", "predictions_sha256"), ("model_responses.json", "model_responses_sha256")):
        require(sha(run / n) == closed[key], "closed_hash:" + n)
    require(report["closure_sha256"] == sha(run / "prediction_phase_closed.json")
            and closed["reference_parsed"] is False and closed["rows"] == 72
            and final["status"] == "complete" and final["reference_parsed"] is True and final["rows"] == 72,
            "closure_completion")
    module = ast.parse((run / "implementation/scripts/run_qwen35_model_probe.py").read_text(encoding="utf-8"))
    execute = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "execute")
    calls = {name: [n.lineno for n in ast.walk(execute) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == name]
             for name in ("close_prediction_phase", "load_closed_reference", "score_rows")}
    require(all(len(v) == 1 for v in calls.values()) and calls["close_prediction_phase"][0]
            < calls["load_closed_reference"][0] < calls["score_rows"][0], "reference_phase_order")
    local_ast = ast.parse((run / "implementation/memory_migration_study/local_detector.py").read_text(encoding="utf-8"))
    constants = {n.targets[0].id: rule_literal(n.value) for n in local_ast.body
                 if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                 and n.targets[0].id in {"_QUOTE_PAIRS", "_QUOTE_TRAILING_PUNCTUATION"}}
    pairs, punctuation = constants["_QUOTE_PAIRS"], constants["_QUOTE_TRAILING_PUNCTUATION"]
    rows, responses, texts, requests = (read(run / n) for n in
        ("predictions.json", "model_responses.json", "historical/historical/runtime.json", "requests.json"))
    texts = texts["texts"]
    require(len(texts) == len(set(texts)) == len(responses) == 24 and len(rows) == 72, "case_inventory")
    by = {(r["cell"]["text_index"], r["cell"]["arm"]): r for r in rows}
    require(len(by) == 72 and set(by) == {(i, a) for i in range(24) for a in ARMS}, "grid")
    full, conditional = (read(run / n) for n in ("historical_fulltext_responses.json", "historical_conditional_responses.json"))
    require(full == [a["source_response"] for a in read(run / "historical/source_annotations.json")]
            and conditional == read(run / "historical/receiver_responses.json"), "historical_response_replay")
    require(sha(run / "requests.json") == plan["requests_sha256"]
            and sha(run / "historical_fulltext_responses.json") == plan["historical_fulltext_sha256"]
            and sha(run / "historical_conditional_responses.json") == plan["historical_conditional_sha256"], "auxiliary_hash")
    names = sorted(closed["capture_sha256"])
    require(names == sorted(p.name for p in run.glob("transport_*.json")), "capture_inventory")
    for name in names:
        require(sha(run / name) == closed["capture_sha256"][name], "capture_hash:" + name)
    events = [read(run / n) for n in names]
    posts = [e for e in events if e["method"] == "POST"]
    require(24 <= len(posts) <= 48 and sum(e["method"] == "GET" for e in events) == 48, "call_limits")
    require(closed["network"] == report["network"] == final["network"]
            == {"loopback_connects": len(events), "blocked_connects": 0}, "network_receipts")
    by_text, raw_checked, invalid_final, input_tokens, output_tokens = {}, 0, [], 0, 0
    for event in posts:
        i = event["text_index"]
        require(type(i) is int and 0 <= i < 24 and event["path"] == "/api/chat" and event["error_type"] is None, "post_route")
        attempt = len(by_text.setdefault(i, []))
        require(attempt < 2 and same(event["body"], requests[i][attempt])
                and text_sha(event["wire_body"]) == event["wire_body_sha256"] == plan["request_wire_sha256"][i][attempt]
                and same(strict_json(event["wire_body"]), event["body"]), "actual_request_binding")
        body = event["body"]
        require(body["model"] == plan["model"] and body["think"] is False and body["options"] == plan["options"]
                and strict_json(body["messages"][1]["content"])["text"] == texts[i], "request_method")
        envelope = strict_json(event["raw_response"])
        require(event["http_status"] == 200 and event["raw_response_sha256"] == text_sha(event["raw_response"])
                and event["raw_response_bytes"] == len(event["raw_response"].encode())
                and envelope["model"] == plan["model"] and envelope["done"] is True
                and envelope["done_reason"] == "stop" and not envelope["message"].get("thinking")
                and not envelope["message"].get("tool_calls"), "raw_generation_envelope")
        require(type(envelope.get("prompt_eval_count")) is int and 0 <= envelope["prompt_eval_count"] <= 4096
                and type(envelope.get("eval_count")) is int and 0 <= envelope["eval_count"] <= 1024, "actual_token_budget")
        input_tokens += envelope["prompt_eval_count"]; output_tokens += envelope["eval_count"]
        by_text[i].append(envelope)
    require(set(by_text) == set(range(24)), "generation_case_inventory")
    for i, response in enumerate(responses):
        require(read(run / f"model_response_{i:02d}.json") == response, "response_shard")
        require(response["model"] == plan["model"] and response["digest"] == plan["model_digest"]
                and response["local_calls"] == len(by_text[i]) == closed["per_text_posts"][str(i)]
                and response["local_calls_complete"] is True, "model_response_cost")
        decoded = []
        for envelope in by_text[i]:
            try:
                decoded.append(occurrence_decode(envelope["message"]["content"], texts[i], pairs, punctuation))
            except (ValueError, TypeError, KeyError):
                decoded.append(None)
        if len(decoded) == 2:
            require(decoded[0] is None, "unjustified_format_repair")
        if decoded[-1] is None:
            require(response["errors"] == ["format_or_span_invalid"] and response["status"] == "needs_review"
                    and len(decoded) == 2 and response["findings"] == [], "format_failure_contract")
            invalid_final.append(i)
        else:
            status, findings, repairs = decoded[-1]
            require(response["status"] == status and spans(response["findings"], texts[i]) == findings
                    and response["quote_wrapper_repairs"] == repairs
                    and response["errors"] == (["semantic_uncertainty"] if status == "needs_review" else []), "raw_decode")
            raw_checked += 1
    require(len(posts) == closed["new_generation_posts"] == report["new_generation_posts"] == final["new_generation_posts"]
            and report["total_new_generation_posts"] == len(posts)+1 and report["qualification_generation_posts"] == 1
            and report["prompt_eval_count"] == input_tokens and report["eval_count"] == output_tokens
            and report["token_counts_complete"] is True and report["cost_complete"] is True, "report_cost")
    old_closure = read(run / "historical/prediction_phase_closed.json")
    attempts, old_count = Counter(), 0
    for name in sorted(old_closure["capture_sha256"]):
        event = read(run / "historical" / name)
        if event["method"] != "POST": continue
        body = dict(event["body"]); i = texts.index(strict_json(body["messages"][1]["content"])["text"])
        old_count += 1; new = dict(requests[i][attempts[i]]); attempts[i] += 1
        body.pop("model"); new.pop("model"); new.pop("think")
        require(same(body, new), "historical_same_method")
    require(old_count == 28 and set(attempts) == set(range(24)), "historical_method_inventory")
    covered, controls = {}, Counter()
    for (i, arm), row in by.items():
        require(read(run / f"row_{i:02d}_{arm}.json") == row and row["cell"]["profile"] == PROFILE, "row_shard")
        expected_response = {ARMS[0]: full[i], ARMS[1]: responses[i], ARMS[2]: conditional[i]}[arm]
        require(row["response"] == expected_response and row["baseline_empty_labels"] is True
                and row["record"]["label"]["findings"] == []
                and spans(row["exact_protective_findings"], texts[i]) == spans(expected_response["findings"], texts[i]), "arm_fairness")
        record_binding(row["record"], texts[i], i, plan)
        require(row["status"] == row["preparation"]["status"] and row["new_target_posts"] == 0
                and row["preparation"]["new_target_posts"] == 0, "row_status_or_calls")
        semantic = expected_response["status"] == "needs_review" and expected_response["errors"] == ["semantic_uncertainty"]
        require(row["semantic_review_evidence"] == {"detector": semantic}, "semantic_evidence")
        covered[(i, arm)] = footprint(texts[i], row["preparation"])
        negative = row["preparation"]["acl_negative_controls"]
        if row["status"] == "ok":
            require(len(negative) == 2 and {(v["actor_id"], v["agent_id"]) for v in negative}
                    == {("probe_wrong_user", "probe_target"), ("probe_user", "probe_wrong_agent")}
                    and all(v["status"] == "rejected" and v["error"] == "principal_not_authorized"
                            and v["payload_is_none"] is True for v in negative), "acl_negative_controls")
            require(all(c["access_valid"] is True and c["label_valid"] is True for c in row["preparation"]["checks"]), "recorded_runtime_checks")
            controls[arm] += 2
        else:
            require(negative == [], "blocked_acl_controls")
        require(not any(k in row["preparation"] for k in ("mapping", "_entries", "restoration_map", "authority_key")), "private_mapping_exported")
    # Gold is read only after frozen/raw/request/footprint/authorization audits.
    refs = {c["text_index"]: c for c in read(run / "historical/historical/evaluation.opaque.json")["cases"]}
    require(set(refs) == set(range(24)), "reference_inventory")
    groups, scores, fp_scopes = {}, {}, {}
    for (i, arm), row in by.items():
        case, text = refs[i], texts[i]
        require(case["text_sha256"] == text_sha(text)
                and text[case["allowed_fact"]["start"]:case["allowed_fact"]["end"]] == case["allowed_fact"]["text"], "reference_binding")
        truth = case["expected"][PROFILE]
        value = independent_score(text, row, truth, case["allowed_fact"], covered[(i, arm)])
        scores[(i, arm)] = value
        g = groups.setdefault(arm, {**dict.fromkeys(value, 0), "statuses": Counter(), "block_reasons": Counter(), "acl_negative_controls": 0})
        for k, v in value.items(): g[k] += v
        g["statuses"][row["status"]] += 1; g["block_reasons"].update(row["block_reasons"])
        g["acl_negative_controls"] += len(row["preparation"]["acl_negative_controls"])
        part = fp_scopes.setdefault(arm, {"all_known_raw": 0, "ready": 0, "blocked": 0})
        part["all_known_raw"] += value["raw_predicted_protective_fp"]
        part["ready" if row["status"] == "ok" else "blocked"] += value["raw_predicted_protective_fp"]
    for arm, g in groups.items():
        tp, fp, fn = (g["raw_predicted_protective_" + k] for k in ("tp", "fp", "fn"))
        g["raw_predicted_protective_precision"] = tp/(tp+fp) if tp+fp else None
        g["raw_predicted_protective_recall"] = tp/(tp+fn) if tp+fn else None
        require(g == report["by_arm"][arm] and g["known"] == 20 and g["unknown"] == 4, "independent_summary:" + arm)
    scored = read(run / "scored_rows.json")
    require(len(scored) == 72, "scored_inventory")
    for row in scored:
        key = (row["cell"]["text_index"], row["cell"]["arm"])
        require(row["score"] == scores[key] and {k: v for k, v in row.items() if k != "score"} == by[key], "independent_row_score")
    new, strong = groups[ARMS[1]], groups[ARMS[2]]
    gates = {"precision": (new["raw_predicted_protective_precision"] or 0) >= .9,
             "recall": (new["raw_predicted_protective_recall"] or 0) >= .95,
             "no_prepared_leak": new["prepared_incomplete_spans"] == 0,
             "known_prepared_noninferior": new["known_prepared"] >= strong["known_prepared"],
             "semantic_unknown_review": new["unknown"] == 4 and new["semantic_unknown_review"] == 4,
             "acl_negative_controls": new["acl_negative_controls"] == 2*new["prepared"], "cost_complete": True}
    require(report["gate_components"] == gates and report["development_gate_passed"] is all(gates.values()), "independent_gate")
    require(report["downstream_task_success"] is report["refusal_rate"] is report["independent_acceptance_passed"] is None, "unmeasured_not_zero")
    return {"status": "passed", "audit_version": "qwen35_model_independent_stdlib_v1", "plan_sha256": expected,
        "frozen_source_files_checked": len(plan["sources"]), "historical_files_checked": len(plan["inputs"]),
        "receipt_files_checked": len(plan["receipts"]), "capture_files_checked": len(events), "grid_cells_checked": 72,
        "new_generation_posts": len(posts), "qualification_generation_posts": 1, "health_gets": 48,
        "prompt_eval_count": input_tokens, "eval_count": output_tokens, "raw_decodes_checked": raw_checked,
        "format_failure_indices": invalid_final, "historical_method_posts_checked": old_count,
        "acl_negative_controls": dict(controls), "acl_negative_controls_total": sum(controls.values()),
        "independent_scores_match": True, "gate_components": gates, "development_gate_passed": all(gates.values()),
        "fp_scopes": fp_scopes, "by_arm": groups, "audit_model_calls": 0, "audit_network_calls": 0,
        "artifact_sha256": {n: sha(run/n) for n in ("plan.json", "prediction_phase_closed.json", "predictions.json", "model_responses.json", "report.json", "scored_rows.json")},
        "limits": ["Independent arithmetic and raw occurrence decoding; no producer scoring imported.",
                   "Ephemeral HMAC keys/maps were not persisted; bindings and runtime checks are audited, signatures are not reverified.",
                   "Local closure/control-flow evidence is not an external trusted timestamp; exposed development materials are not independent acceptance."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--expected-plan-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run, output = args.run.resolve(), args.output.resolve()
    require(run.is_relative_to(ROOT/"results") and output.is_relative_to(ROOT/"results")
            and not output.exists() and re.fullmatch(r"[a-f0-9]{64}", args.expected_plan_sha), "audit_scope")
    result = verify(run, args.expected_plan_sha)
    result["verifier_sha256"] = sha(Path(__file__))
    output.mkdir(parents=True)
    with (output/"audit.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2); stream.write("\n")
    print(json.dumps({"status": result["status"], "audit_sha256": sha(output/"audit.json"),
                      "new_generation_posts": result["new_generation_posts"], "development_gate_passed": result["development_gate_passed"]}))


if __name__ == "__main__":
    main()
