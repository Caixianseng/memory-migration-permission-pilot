"""Independent stdlib audit of a closed eight-text copy/tag diagnostic.

No producer, producer scorer, model, HTTP, gold-driven detector, persisted map,
or HMAC key is loaded. Reuses only earlier independent audit helpers. Run this
only after the formal prediction closure and completed execution are present.
The eight exposed diagnostics are not independent acceptance or a new method.
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
    require, sha, text_sha, spans, footprint, record_binding,
)
from scripts.verify_qwen35_model_probe import (
    strict_json, same, rule_literal, independent_score, occurrence_decode,
)

IDS = (1, 4, 6, 11, 13, 16, 19, 22)
ARMS = ("free_tag", "constrained_tag", "qwen35_quote", "qwen3_conditional")
PROFILE = "strict_customer_relation"
PROFILES = (PROFILE, "any_specific_organization")
MODEL_SHA = "a9d0a3e1d8c91732a3812becd31f8d4a8ff57414903f226306069f0437e2ac50"
PREEXECUTION_VERIFIER_SHA = "9d6b2a33cba6e28c28739194779629236ffd28e44633941379746f9f512fefa6"
WIRE_FIX_PLAN = "a15e7a552060de5e576e84588b775e5369e6fb292267d3fb94bdcdb6dce0ab55"
HISTORY_PINS = {
    "plan.json": "c347550171f836101fd950bdf954626b1b6e2295a5e8579c26298f23a6c9c0dc",
    "prediction_phase_closed.json": "3aadf94ba80f024fac5043e45e41d9a5671998a86a46fffbec1a673571463649",
}
LIMITS = {"texts": 8, "rows": 32, "generation_posts": 16, "posts_per_cell": 1,
          "wall_seconds": 1800, "prompt_tokens": 3072, "output_tokens": 1024,
          "n_ctx": 4096, "concurrent_requests": 1, "cloud_calls": 0,
          "new_target_posts": 0, "native_writes": 0, "repairs": 0}
PRINCIPALS = [{"user_id": "probe_user", "agent_id": "probe_target"}]


def read(path):
    return strict_json(Path(path).read_text(encoding="utf-8"))


def digest(value):
    return text_sha(json.dumps(value, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False))


def wire(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def frozen_path(base, name):
    require(type(name) is str and bool(name), "invalid_manifest_name")
    value = (base / name).resolve()
    require(value.is_relative_to(base.resolve()), "manifest_path_escape")
    return value


def constant(module, name):
    matches = [n.value for n in module.body if isinstance(n, ast.Assign)
               and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
               and n.targets[0].id == name]
    require(len(matches) == 1, "literal_constant:" + name)
    return rule_literal(matches[0])


def literal(value):
    substitutions = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    return '"' + ''.join(substitutions.get(c, "\\x%02X" % ord(c)
        if ord(c) < 32 or ord(c) == 127 else c) for c in value) + '"'


def independent_contract(text):
    """Reconstruct the declared two-state grammar without executing producer."""
    require(type(text) is str and len(text) <= 6000
            and not any(0xD800 <= ord(c) <= 0xDFFF for c in text), "source_contract_text")
    number = next(n for n in range(len(text) + 1)
                  if "<M%d>" % n not in text and "</M%d>" % n not in text)
    opening, closing = "<M%d>" % number, "</M%d>" % number
    lines = ["root ::= out0"]
    for p, char in enumerate(text):
        lines += ["out%d ::= %s out%d | %s %s in%d" %
                  (p, literal(char), p+1, literal(opening), literal(char), p+1),
                  "in%d ::= %s in%d | %s out%d" % (p, literal(char), p+1, literal(closing), p)]
    lines += ['out%d ::= ""' % len(text), "in%d ::= %s" % (len(text), literal(closing))]
    grammar = "\n".join(lines) + "\n"
    require(len(grammar.encode("utf-8")) <= 262144, "source_contract_grammar_limit")
    value = {"version": "lossless_source_copy_tag_v1", "category": "CUSTOMER", "text": text,
        "source_sha256": text_sha(text), "source_chars": len(text),
        "offset_unit": "unicode_codepoint_half_open", "normalization": "none",
        "open_tag": opening, "close_tag": closing, "grammar": grammar,
        "grammar_sha256": text_sha(grammar), "grammar_bytes": len(grammar.encode("utf-8")),
        "rule_count": len(lines), "limits": {"max_text_chars": 6000,
            "max_grammar_bytes": 262144, "max_spans": 32},
        "span_count_enforcement": "host_parser", "semantic_guarantee": False,
        "authorization_granted": False}
    return {**value, "contract_sha256": digest(value)}


def header_grammar(contract):
    return 'root ::= ("OK\\n" | "REVIEW\\n") tag-body\n' + contract["grammar"].replace(
        "root ::= out0\n", "tag-body ::= out0\n", 1)


def decode_copy(content, text, contract):
    """Decode tag events against an original-source cursor, never quote search.

    Returns only an observed status, exact span list and parser error. A complete
    copy or OK header never establishes semantic truth or an access grant.
    """
    head, separator, body = content.partition("\n")
    if not separator or head not in ("OK", "REVIEW"):
        return "needs_review", [], ["invalid_tag_header"], False
    opening, closing = contract["open_tag"], contract["close_tag"]
    if len(body) > len(text) + 32 * (len(opening) + len(closing)):
        return "needs_review", [], ["tag_output_limit_exceeded"], False
    events = re.compile(re.escape(opening) + "|" + re.escape(closing) + "|[\\s\\S]")
    position, start, found, error = 0, None, [], None
    for event in events.finditer(body):
        token = event.group()
        if token == opening:
            if start is not None:
                error = "nested_tag"; break
            start = position
        elif token == closing:
            if start is None:
                error = "unexpected_close_tag"; break
            if start == position:
                error = "empty_tag_span"; break
            found.append({"start": start, "end": position, "quote": text[start:position], "category": "CUSTOMER"})
            if len(found) > 32:
                error = "tag_span_limit_exceeded"; break
            start = None
        else:
            if position >= len(text) or text[position] != token:
                error = "source_copy_mismatch"; break
            position += 1
    if error is None and start is not None:
        error = "unclosed_tag"
    if error is None and position != len(text):
        error = "source_copy_incomplete"
    if error:
        return "needs_review", [], [error], False
    return ("ok" if head == "OK" else "needs_review", found,
            [] if head == "OK" else ["semantic_uncertainty"], True)


def token_counts(envelope):
    require(type(envelope) is dict and type(envelope.get("content")) is str
            and envelope.get("stop") is True and envelope.get("truncated") is False,
            "generation_not_complete")
    if "stop_type" in envelope:
        require(envelope["stop_type"] in ("eos", "word")
                and envelope.get("stopped_limit", False) is False, "terminal_reason")
    else:
        require(envelope.get("stopped_limit") is False and
                (envelope.get("stopped_eos") is True or envelope.get("stopped_word") is True), "terminal_reason")
    prompt, predicted = envelope.get("tokens_evaluated"), envelope.get("tokens_predicted")
    timings = envelope.get("timings", {})
    if type(timings) is dict:
        if prompt is None: prompt = timings.get("prompt_n")
        if predicted is None: predicted = timings.get("predicted_n")
    require(type(prompt) is int and 0 <= prompt <= 3072
            and type(predicted) is int and 0 <= predicted <= 1024, "generation_token_limits")
    return {"prompt": prompt, "predicted": predicted}


def profile_hashes(source):
    module = ast.parse(source.read_text(encoding="utf-8"))
    names = {n.targets[0].id: ast.literal_eval(n.value) for n in module.body
             if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id in {"CONTRACT_VERSION", "STRICT_CUSTOMER_RELATION", "ANY_SPECIFIC_ORGANIZATION"}}
    definition = next(n.value for n in module.body if isinstance(n, ast.Assign)
                      and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "_DEFINITIONS")
    require(isinstance(definition, ast.Dict), "profile_literal")
    definitions = {names[k.id]: ast.literal_eval(v) for k, v in zip(definition.keys, definition.values)}
    require(set(definitions) == set(PROFILES), "profile_inventory")
    return {p: digest({"ontology_id": p, "version": names["CONTRACT_VERSION"],
                      "definitions": {"CUSTOMER": definitions[p]}}) for p in PROFILES}


def validate_all_reference(reference, texts, profiles):
    """Check all 24 cases and both ontologies before selecting diagnostic IDs."""
    runtime = {"schema_version": "relation_occurrence_probe_runtime_v1", "texts": texts}
    runtime_hash = text_sha(json.dumps(runtime, ensure_ascii=False, indent=2) + "\n")
    require(type(reference) is dict and reference.get("schema_version") == "relation_occurrence_probe_evaluation_v1"
            and reference.get("runtime_sha256") == runtime_hash
            and reference.get("profile_contract_sha256") == profiles, "reference_top_binding")
    cases = reference.get("cases")
    require(type(cases) is list and len(cases) == 24, "full_reference_inventory")
    by = {}
    for case in cases:
        require(type(case) is dict and type(case.get("text_index")) is int
                and 0 <= case["text_index"] < 24 and case["text_index"] not in by, "reference_id")
        i = case["text_index"]; text = texts[i]
        require(case.get("text_sha256") == text_sha(text) and type(case.get("expected")) is dict
                and set(case["expected"]) == set(PROFILES), "reference_text_binding")
        for profile in PROFILES:
            truth = case["expected"][profile]
            require(type(truth) is dict and truth.get("decision") in ("sensitive", "not_sensitive", "needs_review"), "reference_decision")
            require(type(truth.get("spans")) is list and all(type(v) is dict and type(v.get("text")) is str
                    and v["text"] for v in truth["spans"]), "reference_span_schema")
            positions = spans(truth["spans"], text, reference=True)
            values = list(dict.fromkeys(v["text"] for v in truth["spans"]))
            require(len(positions) == len(truth["spans"]) and truth.get("must_mask_values") == values
                    and bool(positions) == (truth["decision"] == "sensitive"), "reference_values")
        fact = case.get("allowed_fact")
        require(type(fact) is dict and type(fact.get("slot_id")) is str and fact["slot_id"]
                and fact.get("match") == "exact_substring" and type(fact.get("text")) is str and fact["text"]
                and type(fact.get("start")) is int and type(fact.get("end")) is int
                and 0 <= fact["start"] < fact["end"] <= len(text)
                and text[fact["start"]:fact["end"]] == fact["text"] and text.count(fact["text"]) == 1
                and not any(v.casefold() in fact["text"].casefold()
                            for v in case["expected"][PROFILES[1]]["must_mask_values"]), "reference_allowed_fact")
        by[i] = case
    require(set(by) == set(range(24)), "full_reference_coverage")
    return by


def verify(run, expected):
    plan, closed, report, final = (read(run / name) for name in
        ("plan.json", "prediction_phase_closed.json", "report.json", "execution_final.json"))
    require(sha(run / "plan.json") == expected == closed["plan_sha256"] == report["plan_sha256"]
            == final["plan_sha256"], "plan_hash")
    require(plan["version"] == "source_copy_tag_diagnostic_probe_v1" and plan["text_ids"] == list(IDS)
            and plan["arms"] == list(ARMS) and plan["limits"] == LIMITS and plan["reference_parsed"] is False
            and plan["endpoint"] == "http://127.0.0.1:11436" and plan["model_sha256"] == MODEL_SHA
            and plan["new_cloud_calls"] == plan["new_target_posts"] == plan["native_writes"] == 0, "plan_contract")
    order = [{"text_index": i, "arm": arm} for n, i in enumerate(IDS)
             for arm in (ARMS[:2] if n % 2 == 0 else tuple(reversed(ARMS[:2])))]
    require(plan.get("generation_order") == closed.get("generation_order") == order, "balanced_generation_order")
    require(closed["reference_parsed"] is False and closed["rows"] == 32 and closed["text_ids"] == list(IDS)
            and final["complete"] is True and final["completed_rows"] == 32 and final["unobserved_rows"] == 0
            and final["error"] is None and type(final["elapsed_seconds"]) in (int, float)
            and 0 <= final["elapsed_seconds"] < 1800, "closed_complete_execution")
    for key, prefix in (("sources", "implementation"), ("inputs", "history"), ("artifacts", "")):
        for name, value in plan[key].items():
            require(re.fullmatch(r"[a-f0-9]{64}", value) and sha(frozen_path(run / prefix, name)) == value,
                    "archive_hash:" + key + ":" + name)
    self_name = "scripts/verify_copy_tag_probe.py"
    require(plan["sources"].get(self_name) in {sha(Path(__file__)), PREEXECUTION_VERIFIER_SHA}, "independent_verifier_frozen")
    require(plan["sources"].get("scripts/verify_source_annotation_probe.py") == sha(ROOT / "scripts/verify_source_annotation_probe.py")
            and plan["sources"].get("scripts/verify_qwen35_model_probe.py") == sha(ROOT / "scripts/verify_qwen35_model_probe.py"), "independent_helpers_frozen")
    require(set(plan["artifacts"]) == {"runtime_receipt.json", "prompt_bundle.json", "requests.json", "texts.json",
            "historical_quote.json", "historical_conditional.json", "contracts.json"}, "artifact_inventory")
    for name, value in HISTORY_PINS.items():
        require(plan["inputs"].get(name) == value, "historical_pin:" + name)
    old_plan, old_closed = read(run / "history/plan.json"), read(run / "history/prediction_phase_closed.json")
    require(old_closed["plan_sha256"] == HISTORY_PINS["plan.json"] and old_closed["reference_parsed"] is False
            and old_closed["rows"] == 72 and plan["policy"] == old_plan["policy"], "historical_closure")
    for name, value in old_closed["capture_sha256"].items():
        require(plan["inputs"].get(name) == value, "historical_capture_manifest")
    require(plan["inputs"]["model_responses.json"] == old_closed["model_responses_sha256"]
            and plan["inputs"]["historical_conditional_responses.json"] == old_plan["historical_conditional_sha256"]
            and plan["inputs"]["historical/historical/runtime.json"] == old_plan["inputs"]["historical/runtime.json"]
            and plan["inputs"]["historical/historical/evaluation.opaque.json"] == old_plan["inputs"]["historical/evaluation.opaque.json"],
            "historical_data_binding")
    module = ast.parse((run / "implementation/scripts/run_copy_tag_probe.py").read_text(encoding="utf-8"))
    execute = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "execute")
    calls = {name: [n.lineno for n in ast.walk(execute) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == name]
             for name in ("close_predictions", "load_closed_reference", "score_rows")}
    require(all(len(v) == 1 for v in calls.values()) and calls["close_predictions"][0]
            < calls["load_closed_reference"][0] < calls["score_rows"][0], "reference_phase_order")
    texts, contracts, requests, bundle, runtime = (read(run / n) for n in
        ("texts.json", "contracts.json", "requests.json", "prompt_bundle.json", "runtime_receipt.json"))
    require(type(texts) is list and len(texts) == len(set(texts)) == 24 and all(type(t) is str for t in texts)
            and read(run / "history/historical/historical/runtime.json")["texts"] == texts, "text_inventory")
    require(set(contracts) == set(requests) == {str(i) for i in IDS}, "request_case_inventory")
    for kind, filename in (("runtime", "runtime_receipt.json"), ("prompts", "prompt_bundle.json")):
        source = Path(plan["receipts"][kind]["path"])
        require(sha(source) == plan["receipts"][kind]["sha256"] and same(read(source), read(run / filename)), "original_receipt_binding")
    require(runtime.get("endpoint") == plan["endpoint"] and runtime.get("model_sha256") == MODEL_SHA
            and re.fullmatch(r"[a-f0-9]{64}", runtime.get("executable_sha256", ""))
            and type(runtime.get("n_ctx")) is int and runtime["n_ctx"] == 4096 and runtime.get("thinking") is False
            and runtime.get("canary", {}).get("success") is True
            and type(runtime["canary"].get("generation_calls")) is int
            and runtime["canary"]["generation_calls"] == 1
            and bundle.get("runtime_receipt_sha256") == plan["receipts"]["runtime"]["sha256"], "runtime_qualification")
    compilation = bundle.get("cases")
    require(type(compilation) is list and len(compilation) == 8, "compiled_case_inventory")
    by_compiled = {c["text_index"]: c for c in compilation}
    require(set(by_compiled) == set(IDS) and all(type(c["text_index"]) is int for c in compilation), "compiled_case_ids")
    system = constant(module, "SYSTEM")
    policy = plan["policy"]
    require(policy.get("protected_categories") == ["CUSTOMER"]
            and policy.get("category_contract", {}).get("ontology_id") == PROFILE, "policy_contract")
    ordered_requests = {}
    for i in IDS:
        contract, item = contracts[str(i)], by_compiled[i]
        require(same(contract, independent_contract(texts[i])), "independent_contract:" + str(i))
        messages = [{"role": "system", "content": system + "\n\nTrusted sensitivity policy JSON:\n" +
                     json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)},
                    {"role": "user", "content": json.dumps({"text": texts[i], "opening_tag": contract["open_tag"],
                     "closing_tag": contract["close_tag"]}, ensure_ascii=False, separators=(",", ":"), allow_nan=False)}]
        require(item.get("source_sha256") == text_sha(texts[i]) and item.get("policy_sha256") == digest(policy)
                and item.get("contract_sha256") == contract["contract_sha256"] and item.get("messages") == messages
                and type(item.get("prompt")) is str and item["prompt"] and type(item.get("token_count")) is int
                and 0 < item["token_count"] <= 3072
                and item.get("prompt_sha256", text_sha(item["prompt"])) == text_sha(item["prompt"]), "compiled_prompt_binding")
        require(item.get("apply_template_request", {}).get("messages") == messages
                and item.get("apply_template_response", {}).get("prompt") == item["prompt"]
                and item.get("tokenize_request", {}).get("content") == item["prompt"], "template_tokenize_binding")
        tokens = item.get("tokenize_response", {}).get("tokens")
        require(type(tokens) is list and len(tokens) == item["token_count"]
                and all(type(t) is int and t >= 0 for t in tokens), "compiled_token_count")
        base = {"prompt": item["prompt"], "n_predict": 1024, "temperature": 0, "seed": 42,
                "stream": False, "cache_prompt": True}
        expected_requests = {"free_tag": base, "constrained_tag": {**base, "grammar": header_grammar(contract)}}
        require(same(requests[str(i)], expected_requests), "same_prompt_grammar_only")
        ordered_requests[str(i)] = expected_requests
        for arm, body in expected_requests.items():
            require(plan["request_sha256"][str(i)][arm] == digest(body)
                    and plan["request_wire_sha256"][str(i)][arm] == text_sha(wire(body)), "request_hash")
    # The saved JSON is sorted for storage. Its parsed dict order is not the
    # original wire order. Preserve the independently reconstructed insertion
    # order, already checked against both saved objects and frozen wire hashes.
    requests = ordered_requests
    for name, key in (("predictions.json", "predictions_sha256"), ("model_responses.json", "model_responses_sha256")):
        require(sha(run / name) == closed[key], "closed_prediction_hash:" + name)
    require(read(run / "execution_started.json")["plan_sha256"] == expected, "execution_start_binding")
    names = sorted(closed["capture_sha256"])
    require(names == ["transport_%03d.json" % n for n in range(1, 17)]
            and names == sorted(p.name for p in run.glob("transport_*.json")), "capture_inventory")
    events, raw, totals = [], {}, Counter()
    for ordinal, name in enumerate(names):
        require(sha(run / name) == closed["capture_sha256"][name], "capture_hash:" + name)
        event = read(run / name); events.append(event)
        i, arm = event.get("text_index"), event.get("arm")
        require(type(i) is int and i in IDS and arm in ARMS[:2] and (i, arm) not in raw
                and event.get("method") == "POST" and event.get("path") == "/completion"
                and event.get("error_type") is None and event.get("error") is None and event.get("http_status") == 200,
                "capture_route_or_duplicate")
        require(event.get("generation_ordinal") == ordinal and {"text_index": i, "arm": arm} == order[ordinal], "actual_generation_ordinal")
        require(same(event["body"], requests[str(i)][arm]) and event["wire_body"] == wire(requests[str(i)][arm])
                and same(strict_json(event["wire_body"]), event["body"])
                and text_sha(event["wire_body"]) == event["wire_body_sha256"] == plan["request_wire_sha256"][str(i)][arm], "actual_request_wire")
        require(type(event.get("raw_response")) is str and text_sha(event["raw_response"]) == event["raw_response_sha256"]
                and 0 < event["raw_response_bytes"] == len(event["raw_response"].encode("utf-8")) <= 1048576, "raw_response_hash")
        envelope = strict_json(event["raw_response"])
        counts = token_counts(envelope)
        require(event.get("token_counts") == counts, "recorded_token_counts")
        totals.update(counts); raw[(i, arm)] = envelope
    require(set(raw) == {(i, a) for i in IDS for a in ARMS[:2]}, "new_generation_grid")
    require([{"text_index": e["text_index"], "arm": e["arm"]} for e in events] == order, "serial_no_repair_order")
    inventory = {"post_attempts": 16, "complete_generation_responses": 16, "token_counts_complete": True,
                 "generation_order": order,
                 "prompt_tokens": totals["prompt"], "predicted_tokens": totals["predicted"], "cloud_calls": 0,
                 "new_target_posts": 0, "native_writes": 0, "repairs": 0}
    require(closed["call_inventory"] == report["call_inventory"] == final["call_inventory"] == inventory
            and closed["network"] == {"allowed_connects": 16, "blocked_connects": 0}, "physical_call_inventory")
    rows, responses = read(run / "predictions.json"), read(run / "model_responses.json")
    require(type(rows) is list and len(rows) == 32 and type(responses) is list and len(responses) == 8, "prediction_inventory")
    by = {(r["cell"]["text_index"], r["cell"]["arm"]): r for r in rows}
    by_response = {r["text_index"]: r["responses"] for r in responses}
    require(len(by) == 32 and set(by) == {(i, a) for i in IDS for a in ARMS}
            and set(by_response) == set(IDS) and all(set(r) == set(ARMS) for r in by_response.values()), "full_prediction_grid")
    quote, conditional = read(run / "historical_quote.json"), read(run / "historical_conditional.json")
    require(len(quote) == len(conditional) == 24 and same(quote, read(run / "history/model_responses.json"))
            and same(conditional, read(run / "history/historical_conditional_responses.json")), "frozen_baseline_replay")
    # Independently decode the historical Qwen3.5 raw envelopes, including any
    # original format-repair attempt. These are historical costs, not new POSTs.
    local_module = ast.parse((run / "implementation/memory_migration_study/local_detector.py").read_text(encoding="utf-8"))
    pairs, punctuation = constant(local_module, "_QUOTE_PAIRS"), constant(local_module, "_QUOTE_TRAILING_PUNCTUATION")
    historical_raw = {}
    for name in sorted(old_closed["capture_sha256"]):
        event = read(run / "history" / name)
        if event.get("method") == "POST":
            require(event.get("error_type") is None and event.get("http_status") == 200
                    and event.get("raw_response_sha256") == text_sha(event["raw_response"]), "historical_raw_hash")
            historical_raw.setdefault(event["text_index"], []).append(strict_json(event["raw_response"]))
    require(set(historical_raw) == set(range(24)), "historical_raw_inventory")
    for i in IDS:
        parsed = []
        for envelope in historical_raw[i]:
            require(envelope.get("done") is True and envelope.get("done_reason") == "stop", "historical_complete")
            try: parsed.append(occurrence_decode(envelope["message"]["content"], texts[i], pairs, punctuation))
            except (ValueError, TypeError, KeyError): parsed.append(None)
        require(1 <= len(parsed) <= 2 and (len(parsed) == 1 or parsed[0] is None), "historical_repairs")
        if parsed[-1] is None:
            require(len(parsed) == 2 and quote[i]["status"] == "needs_review" and quote[i]["findings"] == []
                    and quote[i]["errors"] == ["format_or_span_invalid"], "historical_failed_decode")
        else:
            status, found, repairs = parsed[-1]
            require(quote[i]["status"] == status and spans(quote[i]["findings"], texts[i]) == found
                    and quote[i]["quote_wrapper_repairs"] == repairs
                    and quote[i]["errors"] == ([] if status == "ok" else ["semantic_uncertainty"]), "historical_raw_decode")
    coverage, controls, invalid = {}, Counter(), []
    for i in IDS:
        require(same(read(run / ("prepared_%02d.json" % i)), [by[(i, a)] for a in ARMS]), "prepared_shard")
        for arm in ARMS:
            row = by[(i, arm)]; response = row["response"]; prepared = row["preparation"]
            require(row["cell"] == {"text_index": i, "profile": PROFILE, "arm": arm}
                    and same(response, by_response[i][arm]) and row["baseline_empty_labels"] is True
                    and row["status"] == prepared["status"] and row["new_target_posts"] == prepared["new_target_posts"] == 0
                    and row["observation_origin"] == ("new_local_generation" if arm in ARMS[:2] else "historical_replay"), "row_binding")
            if arm in ARMS[:2]:
                require(same(read(run / ("model_response_%02d_%s.json" % (i, arm))), response), "model_response_shard")
                status, found, errors, copied = decode_copy(raw[(i, arm)]["content"], texts[i], contracts[str(i)])
                require(response["status"] == status and same(response["findings"], found) and response["errors"] == errors
                        and response["copy_verified"] is copied and response["semantic_verified"] is False
                        and response["authorization_granted"] is False and response["local_calls"] == 1
                        and response["local_calls_complete"] is True and response["model_sha256"] == MODEL_SHA
                        and response["contract_sha256"] == contracts[str(i)]["contract_sha256"]
                        and response["raw_output_sha256"] == text_sha(raw[(i, arm)]["content"]), "independent_tag_decode")
                if not copied: invalid.append({"text_index": i, "arm": arm, "errors": errors})
            else:
                require(same(response, {"qwen35_quote": quote, "qwen3_conditional": conditional}[arm][i]), "same_baseline_response")
            require(spans(row["exact_protective_findings"], texts[i]) == spans(response["findings"], texts[i]), "exact_detector_findings")
            record_binding(row["record"], texts[i], i, {"principals": PRINCIPALS})
            require(row["record"]["label"]["findings"] == [], "empty_source_label_baseline")
            require(all(same(by[(i, a)]["record"], row["record"]) for a in ARMS), "same_signed_source_record")
            semantic = response.get("status") == "needs_review" and response.get("errors") == ["semantic_uncertainty"]
            require(row["semantic_review_evidence"] == {"detector": semantic}, "semantic_review_evidence")
            reasons = set()
            if row["status"] != "ok":
                reasons.update(response.get("errors", [])); reasons.update((prepared.get("detection") or {}).get("errors", []))
                if prepared.get("error"): reasons.add(prepared["error"])
            require(row["block_reasons"] == sorted(reasons), "block_reason_evidence")
            coverage[(i, arm)] = footprint(texts[i], prepared)
            negatives = prepared["acl_negative_controls"]
            if row["status"] == "ok":
                require(len(negatives) == 2 and {(n["actor_id"], n["agent_id"]) for n in negatives}
                        == {("probe_wrong_user", "probe_target"), ("probe_user", "probe_wrong_agent")}
                        and all(n["status"] == "rejected" and n["error"] == "principal_not_authorized"
                                and n["payload_is_none"] is True for n in negatives), "all_acl_negative_controls")
                require(bool(prepared["checks"]) and all(c["access_valid"] is True and c["label_valid"] is True
                                                        for c in prepared["checks"]), "runtime_binding_checks")
                controls[arm] += 2
            else:
                require(negatives == [], "blocked_acl_controls")
            require(not any(key in prepared for key in ("mapping", "_entries", "restoration_map", "authority_key")), "private_mapping_exported")
    # First reference parse in this audit: closure, raw wire, independent copy
    # decoding, real masking footprints and ACL evidence have already passed.
    reference = read(run / "history/historical/historical/evaluation.opaque.json")
    refs = validate_all_reference(reference, texts,
        profile_hashes(run / "implementation/memory_migration_study/sensitivity_contract.py"))
    groups, scores, fp_scopes = {}, {}, {}
    for (i, arm), row in by.items():
        value = independent_score(texts[i], row, refs[i]["expected"][PROFILE], refs[i]["allowed_fact"], coverage[(i, arm)])
        scores[(i, arm)] = value
        group = groups.setdefault(arm, {**dict.fromkeys(value, 0), "acl_negative_controls": 0,
                    "copy_verified": 0, "statuses": Counter(), "block_reasons": Counter()})
        for key, amount in value.items(): group[key] += amount
        group["acl_negative_controls"] += len(row["preparation"]["acl_negative_controls"])
        group["copy_verified"] += int(row["response"].get("copy_verified") is True)
        group["statuses"][row["status"]] += 1; group["block_reasons"].update(row["block_reasons"])
        part = fp_scopes.setdefault(arm, {"all_known_raw": 0, "ready": 0, "blocked": 0})
        part["all_known_raw"] += value["raw_predicted_protective_fp"]
        part["ready" if row["status"] == "ok" else "blocked"] += value["raw_predicted_protective_fp"]
    for arm, group in groups.items():
        tp, fp, fn = (group["raw_predicted_protective_" + k] for k in ("tp", "fp", "fn"))
        group["raw_predicted_protective_precision"] = tp/(tp+fp) if tp+fp else None
        group["raw_predicted_protective_recall"] = tp/(tp+fn) if tp+fn else None
        require(same(group, report["by_arm"][arm]), "independent_summary:" + arm)
    scored = read(run / "scored_rows.json")
    require(type(scored) is list and len(scored) == 32 and len({(r["cell"]["text_index"], r["cell"]["arm"]) for r in scored}) == 32, "scored_inventory")
    for row in scored:
        key = (row["cell"]["text_index"], row["cell"]["arm"])
        require(row["score"] == scores[key] and same({k: v for k, v in row.items() if k != "score"}, by[key]), "independent_row_score")
    new, strong = groups["constrained_tag"], groups["qwen3_conditional"]
    mechanism = new["copy_verified"] == 8
    gates = {"precision": (new["raw_predicted_protective_precision"] or 0) >= .9,
        "recall": (new["raw_predicted_protective_recall"] or 0) >= .95,
        "no_prepared_leak": new["prepared_incomplete_spans"] == 0,
        "known_prepared_noninferior": new["known_prepared"] >= strong["known_prepared"],
        "semantic_unknown_review": new["unknown"] > 0 and new["semantic_unknown_review"] == new["unknown"],
        "acl_negative_controls": new["acl_negative_controls"] == 2*new["prepared"], "cost_inventory": True}
    effect = all(gates.values())
    require(report["effect_gate_components"] == gates and report["effect_gate_passed"] is effect
            and report["mechanism_gate_passed"] is mechanism
            and report["mechanism_gate"] == {"constrained_complete_source": new["copy_verified"], "required": 8}
            and report["proceed_full24"] is (mechanism and effect), "independent_gates")
    require(report["independent_acceptance_passed"] is report["downstream_task_success"] is report["refusal_rate"] is None, "unmeasured_not_zero")
    return {"status": "passed", "audit_version": "copy_tag_independent_stdlib_v2_wire_order_fix", "plan_sha256": expected,
        "frozen_verifier_sha256": plan["sources"][self_name],
        "instrument_revision": {"post_execution_fix": plan["sources"][self_name] != sha(Path(__file__)),
            "reason": "Reconstruct original JSON insertion order; sorted stored JSON is not a wire-byte record.",
            "producer_or_scoring_changed": False},
        "frozen_source_files_checked": len(plan["sources"]), "historical_files_checked": len(plan["inputs"]),
        "capture_files_checked": 16, "grid_cells_checked": 32, "full_reference_cases_checked": 24,
        "new_generation_posts": 16, "qualification_generation_posts": 1, "total_new_generation_posts": 17,
        "call_inventory": inventory, "raw_decodes_checked": 16, "format_failure_cells": invalid,
        "historical_quote_raw_decodes_checked": 8, "acl_negative_controls": dict(controls),
        "acl_negative_controls_total": sum(controls.values()), "independent_scores_match": True,
        "mechanism_gate_passed": mechanism, "effect_gate_components": gates, "effect_gate_passed": effect,
        "proceed_full24": mechanism and effect, "independent_acceptance_passed": None,
        "downstream_task_success": None, "refusal_rate": None, "fp_scopes": fp_scopes, "by_arm": groups,
        "audit_model_calls": 0, "audit_network_calls": 0,
        "artifact_sha256": {n: sha(run / n) for n in ("plan.json", "prediction_phase_closed.json",
            "predictions.json", "model_responses.json", "report.json", "scored_rows.json", "execution_final.json")},
        "limits": ["Eight previously exposed hard diagnostics, not independent acceptance or a novel decoding method.",
            "A complete copied source verifies representation and positions, not sensitivity, negation, ontology or authorization.",
            "Independent audit arithmetic and cursor decoding reuse only independent stdlib audit helpers, never producer scoring.",
            "Ephemeral HMAC keys/maps were not persisted; bindings/runtime evidence checked, signatures not reverified offline.",
            "Runtime/canary receipts and local closure are recorded evidence, not external trusted execution or timestamps.",
            "Historical replay methods/runtimes differ; only free/constrained new arms hold model, prompt and decoding budget fixed."]}


def self_test():
    text = "甲苔藓乙苔藓。"; contract = independent_contract(text)
    opening, closing = contract["open_tag"], contract["close_tag"]
    tagged = "甲" + opening + "苔藓" + closing + "乙苔藓。"
    good = decode_copy("OK\n" + tagged, text, contract)
    require(good == ("ok", [{"start": 1, "end": 3, "quote": "苔藓", "category": "CUSTOMER"}], [], True), "selftest_cursor")
    require(decode_copy("REVIEW\n" + text, text, contract) == ("needs_review", [], ["semantic_uncertainty"], True), "selftest_review")
    require(decode_copy("OK\n" + text, text, contract) == ("ok", [], [], True), "selftest_empty_is_syntax_only")
    second = decode_copy("OK\n甲苔藓乙" + opening + "苔藓" + closing + "。", text, contract)
    require(second[1] == [{"start": 4, "end": 6, "quote": "苔藓", "category": "CUSTOMER"}], "selftest_second_occurrence")
    unicode_text = "😀e\u0301苔藓"
    unicode_contract = independent_contract(unicode_text)
    unicode_result = decode_copy("OK\n😀e\u0301" + unicode_contract["open_tag"] + "苔藓" + unicode_contract["close_tag"], unicode_text, unicode_contract)
    require(unicode_result[1] == [{"start": 3, "end": 5, "quote": "苔藓", "category": "CUSTOMER"}], "selftest_codepoint_without_normalization")
    bad = {"header": "ok\n" + text, "copy_edit": "OK\n" + text.replace("苔", "台", 1),
           "incomplete": "OK\n" + text[:-1], "extra": "OK\n" + text + "!",
           "empty": "OK\n" + opening + closing + text,
           "nested": "OK\n" + opening + opening + text + closing + closing,
           "unclosed": "OK\n" + opening + text, "close": "OK\n" + closing + text}
    for name, content in bad.items():
        status, found, errors, copied = decode_copy(content, text, contract)
        require(status == "needs_review" and found == [] and errors and copied is False, "selftest_reject:" + name)
    require(independent_contract("<M0>x</M0>")["open_tag"] == "<M1>", "selftest_delimiter")
    require('\\x08' in independent_contract("\b")["grammar"] and '\\b' not in independent_contract("\b")["grammar"], "selftest_gbnf_control")
    envelope = {"content": "OK\n", "stop": True, "stop_type": "eos", "truncated": False,
                "tokens_evaluated": 12, "tokens_predicted": 2}
    require(token_counts(envelope) == {"prompt": 12, "predicted": 2}, "selftest_token_counts")
    for change in ({"stop_type": "limit"}, {"truncated": True}, {"tokens_evaluated": True},
                   {"tokens_predicted": 1025}, {"stop": False}, {"stopped_limit": True}):
        try: token_counts({**envelope, **change})
        except ValueError: pass
        else: raise ValueError("selftest_incomplete_envelope_accepted")
    try: strict_json('{"a":1,"a":2}')
    except ValueError: pass
    else: raise ValueError("selftest_duplicate_key")
    return {"status": "passed", "synthetic_parser_checks": 15, "synthetic_envelope_checks": 7,
            "model_calls": 0, "network_calls": 0, "gold_files_read": 0, "prediction_files_read": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--expected-plan-sha")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        require(args.run is None and args.output is None and args.expected_plan_sha is None, "selftest_scope")
        print(json.dumps(self_test(), ensure_ascii=False)); return
    require(args.run is not None and args.output is not None and args.expected_plan_sha is not None, "audit_arguments_required")
    run, output = args.run.resolve(), args.output.resolve()
    require(run.is_relative_to((ROOT / "results").resolve()) and output.is_relative_to((ROOT / "results").resolve())
            and not output.exists() and not output.is_relative_to(run)
            and re.fullmatch(r"[a-f0-9]{64}", args.expected_plan_sha), "audit_scope")
    result = verify(run, args.expected_plan_sha)
    result["verifier_sha256"] = sha(Path(__file__))
    output.mkdir(parents=True)
    if args.expected_plan_sha == WIRE_FIX_PLAN:
        failure = {"status": "failed", "attempt": 1, "plan_sha256": args.expected_plan_sha,
            "verifier_sha256": PREEXECUTION_VERIFIER_SHA, "exception": "ValueError: actual_request_wire",
            "location": "scripts/verify_copy_tag_probe.py:333", "reference_parsed_by_audit": False,
            "cause": "Auditor reserialized sorted saved requests instead of independently reconstructing original insertion order.",
            "producer_modified": False, "preserved_from": "First audit command traceback in the task tool output."}
        with (output / "attempt_01_failure.json").open("x", encoding="utf-8") as stream:
            json.dump(failure, stream, ensure_ascii=False, sort_keys=True, indent=2); stream.write("\n")
        result["prior_attempt_failure_sha256"] = sha(output / "attempt_01_failure.json")
    with (output / "audit.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False); stream.write("\n")
    print(json.dumps({"status": result["status"], "audit_sha256": sha(output / "audit.json"),
        "new_generation_posts": 16, "mechanism_gate_passed": result["mechanism_gate_passed"],
        "effect_gate_passed": result["effect_gate_passed"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
