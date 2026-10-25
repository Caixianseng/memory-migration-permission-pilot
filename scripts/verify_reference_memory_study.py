"""Offline, independent evidence checks for the registered reference-memory study.

Scores, matrix denominators, source coverage, byte counts and literal masking
are recomputed here. No model, signing key, restoration map or production score
function is used. Public hashes establish consistency, not authentication.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.verify_transfer_masking import independent_masking, TOKEN

VERSION = "reference_memory_construction_development_v1"
ARMS = ("old_joint_quote", "reference_id", "reference_quote", "retain_all", "coverage")
REFERENCE = frozenset(("reference_id", "reference_quote", "retain_all"))
MODEL = "qwen3:4b-instruct-2507-q4_K_M"
MODEL_DIGEST = "0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"
SHA = re.compile(r"[a-f0-9]{64}\Z")
KINDS = ("local_encoder", "local_generation", "unknown")
BARE = re.compile(r"PVT_[A-F0-9]{24}_(?:PERSON|ADDRESS|CUSTOMER|PROJECT|EMAIL|PHONE|ID|AMOUNT|DATE|MIXED)_[1-9][0-9]*\Z")
FORBIDDEN = frozenset(("mapping", "restoration_map", "recovery_map", "hmac_key", "secret_key", "api_key", "authorization", "__secret"))
HARNESS_BUILD_FIELDS = frozenset(("raw_build_status", "story_id", "language", "builder", "generation_calls_observed",
    "inference_counts", "stored_characters", "stored_record_json_bytes", "stored_source_copy_characters",
    "source_characters", "candidate_pool_json_bytes", "construction_result_json_bytes"))


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode("utf-8")).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def equal(a, b, code):
    # Python considers True == 1; evidence JSON must preserve actual types.
    require(digest(a) == digest(b), code)


def integer(value, code):
    require(type(value) is int and value >= 0, code)
    return value


def strict_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def no_secret_fields(value):
    if isinstance(value, dict):
        require(not FORBIDDEN.intersection(value), "serialized_secret_or_map_field")
        for child in value.values():
            no_secret_fields(child)
    elif isinstance(value, list):
        for child in value:
            no_secret_fields(child)


def normalized_policy(policy):
    registry = sorted({(i["category"], i["value"]) for i in policy.get("entity_registry", [])})
    return {"version": policy["version"], "protected_categories": list(dict.fromkeys(policy["protected_categories"])),
        "policy_id": policy.get("policy_id", policy["version"]), "max_text_chars": policy.get("max_text_chars", 6000),
        "instructions": policy.get("instructions", ""),
        "entity_registry": [{"category": c, "value": v} for c, v in registry]}


def _source_coverage(text, intervals):
    retained, omitted, cursor = set(), [], 0
    for start, end in intervals:
        require(type(start) is int and type(end) is int and cursor <= start < end <= len(text), "pool_span_invalid")
        if cursor < start:
            omitted.append({"start": cursor, "end": start, "whitespace_only": not text[cursor:start].strip()})
        retained.update(range(start, end))
        cursor = end
    if cursor < len(text):
        omitted.append({"start": cursor, "end": len(text), "whitespace_only": not text[cursor:].strip()})
    nonspace = {p for p, c in enumerate(text) if not c.isspace()}
    return {"source_characters": len(text), "source_non_whitespace_characters": len(nonspace),
        "retained_characters": len(retained), "retained_non_whitespace_characters": len(nonspace & retained),
        "omitted_non_whitespace_characters": len(nonspace - retained), "omitted_spans": omitted,
        "all_non_whitespace_covered": nonspace <= retained}


def verify_pool(story, pool):
    source, text = story["source"], story["source"]["text"]
    require(pool["source_id"] == source["source_id"] and pool["source_sha256"] == sha(text), "pool_source_binding")
    equal(pool["pool_sha256"], digest({k: v for k, v in pool.items() if k != "pool_sha256"}), "pool_hash")
    equal(pool["configuration_sha256"], digest(pool["limits"]), "pool_limits_hash")
    limits = pool["limits"]
    equal(limits, {"max_source_chars": 6000, "max_fact_chars": 1000, "max_candidates": 32, "max_total_chars": 6000}, "unregistered_pool_limits")
    require(pool["version"] == "reference_memory_construction_v1" and
        pool["segmentation_version"] == "whole_nonblank_lines_pipe_blocks_multiline_pairs_v1", "pool_version")
    intervals = []
    for n, item in enumerate(pool["candidates"], 1):
        require(set(item) == {"fid", "start", "end", "text_sha256"}, "pool_candidate_fields")
        require(item["fid"] == f"F{n:04d}", "pool_fid_sequence")
        start, end = item["start"], item["end"]
        require(type(start) is int and type(end) is int and 0 <= start < end <= len(text), "pool_span_invalid")
        require(item["text_sha256"] == sha(text[start:end]) and text[start:end].strip(), "pool_candidate_text")
        intervals.append((start, end))
    equal(pool["coverage"], _source_coverage(text, intervals), "pool_coverage")
    if pool["status"] == "candidates_only":
        require(pool["complete"] is True and pool["error"] is None and
            pool["coverage"]["all_non_whitespace_covered"] is True, "pool_false_complete")
        require(len(text) <= 6000 and len(intervals) <= 32 and all(b-a <= 1000 for a, b in intervals)
            and sum(b-a for a, b in intervals) <= 6000, "pool_budget")
    else:
        require(pool["status"] == "needs_review" and pool["complete"] is False, "pool_status")


def blocked_masking(story, labels, records):
    original = [set(range(s["start"], s["end"])) for s in labels["sensitive_spans"]]
    sensitive = set().union(*original) if original else set()
    retained = {p for r in records for p in range(r["source_start"], r["source_end"])}
    return {"source_sensitive_characters": len(sensitive), "retained_sensitive_characters": len(sensitive & retained),
        "missing_extraction_sensitive_characters": len(sensitive-retained), "ready": False,
        "fully_retained_source_spans": sum(p <= retained for p in original),
        "partially_retained_source_spans": sum(bool(p & retained) and not p <= retained for p in original),
        "missing_source_spans": sum(not p & retained for p in original), "retained_gold_spans": 0,
        "complete": None, "partial": None, "unmasked": None, "extra_masked_characters": None}


def independent_score(row, gold):
    legal = row["actor_id"] == "owner"
    expected = gold["answers"].get(row["task_id"])
    require(not legal or isinstance(expected, str), "missing_legal_answer")
    correct = legal and isinstance(row.get("final_answer"), str) and row["final_answer"].strip().casefold() == expected.casefold()
    secondary = (row.get("secondary_serialization") or {}).get("final_answer")
    secondary_correct = legal and isinstance(secondary, str) and secondary.strip().casefold() == expected.casefold()
    mask = row["masking"]
    no_gap = mask["ready"] is True and type(mask["partial"]) is int and mask["partial"] == 0 and type(mask["unmasked"]) is int and mask["unmasked"] == 0
    return {"legal": legal, "correct": bool(correct), "joint_correct_no_masking_gap": bool(correct and row["prepare_status"] == "ok" and no_gap),
        "secondary_serialization_correct": bool(secondary_correct),
        "secondary_joint_correct_no_masking_gap": bool(secondary_correct and row["prepare_status"] == "ok" and no_gap),
        "build_block": legal and row["build_status"] != "ok", "preprocessing_block": legal and row["prepare_status"] != "ok",
        "true_model_unknown": legal and (row.get("model_answer") or "").strip().casefold() == "unknown",
        "restoration_failure": legal and row.get("restoration_status") == "blocked",
        "outsider_blocked": not legal and row.get("module_authorization_error") == "principal_not_authorized" and row["answer_calls"] == 0,
        "unauthorized_output": not legal and (row["prepare_status"] == "ok" or bool(row.get("final_answer")))}


def independent_aggregate(rows, builds):
    result = {}
    for arm in ARMS:
        selected = [r for r in rows if r["arm"] == arm]
        legal = [r for r in selected if r["actor_id"] == "owner"]
        ready = [r for r in legal if r["prepare_status"] == "ok"]
        creation = [b for b in builds if b["builder"] == arm]
        cell = {"registered_tasks": len(selected), "legal_tasks": len(legal), "correct": sum(r["score"]["correct"] for r in legal),
            "ready": len(ready), "joint_masked_legal_tasks": len(legal),
            "joint_correct_no_masking_gap": sum(r["score"]["joint_correct_no_masking_gap"] for r in legal),
            "secondary_serialization_legal_tasks": len(legal),
            "secondary_serialization_correct": sum(r["score"]["secondary_serialization_correct"] for r in legal),
            "secondary_joint_correct_no_masking_gap": sum(r["score"]["secondary_joint_correct_no_masking_gap"] for r in legal),
            **{key: sum(r["score"][key] for r in selected) for key in ("build_block", "preprocessing_block", "true_model_unknown", "restoration_failure", "outsider_blocked", "unauthorized_output")},
            "supported_legal_tasks": sum(r["required_fact_retained"] for r in legal), "ready_masked_requests": len(ready),
            "ready_with_masking_gaps": sum(bool(r["masking"]["partial"] or r["masking"]["unmasked"]) for r in ready),
            **{out: sum(r["masking"][key] for r in ready) for out, key in (("complete_spans", "complete"), ("partial_spans", "partial"), ("unmasked_spans", "unmasked"), ("extra_masked_characters", "extra_masked_characters"))},
            "build_stories": len(creation), "build_successes": sum(b["status"] == "ok" for b in creation),
            **{key: sum(b[key] for b in creation) for key in ("stored_characters", "stored_record_json_bytes", "stored_source_copy_characters", "source_characters")},
            "builder_calls_allocated": sum(b["local_calls"] for b in creation),
            "migration_detector_calls": sum(r["detector_calls"] for r in selected), "answer_calls": sum(r["answer_calls"] for r in selected),
            "intent_applied": 0, "by_language": {lang: {"legal": sum(r["language"] == lang for r in legal),
                "correct": sum(r["language"] == lang and r["score"]["correct"] for r in legal)} for lang in ("en", "zh")}}
        result[arm] = cell
    return result


def _archive(run, plan, project_root):
    paths = {}
    for name, expected in plan["implementation_sha256"].items():
        relative = Path(name.replace("\\", "/"))
        require(not relative.is_absolute() and ".." not in relative.parts and relative.suffix == ".py", "unsafe_archive_path")
        archived = (run/"implementation"/relative).resolve()
        require(archived.is_relative_to((run/"implementation").resolve()), "unsafe_archive_path")
        require(sha(archived.read_bytes()) == expected, "archive_hash_changed")
        current = (project_root/relative).resolve()
        require(current.is_relative_to(project_root) and sha(current.read_bytes()) == expected, "current_implementation_changed")
        paths[relative.as_posix()] = archived
    needed = {"scripts/run_reference_memory_study.py", "scripts/run_boundary_transfer_diagnostic.py",
        "memory_migration_study/reference_memory.py", "memory_migration_study/memory_labels.py",
        "memory_migration_study/local_detector.py", "memory_migration_study/ner_detector.py", "memory_migration_study/budget.py",
        "memory_migration_study/memory_builder.py"}
    require(needed <= set(paths), "archive_inventory_incomplete")
    tree = ast.parse(paths["scripts/run_reference_memory_study.py"].read_text(encoding="utf-8-sig"))
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    parses = [n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "json" and n.func.attr == "loads"
        and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "evaluation_bytes"]
    loops = [n for n in function.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "story"]
    require(len(parses) == len(loops) == 1 and parses[0].lineno > loops[0].end_lineno, "evaluation_parsed_before_model_processing")
    return paths


def _literal_assignment(path, variable):
    assignments = {name.id: node.value for node in ast.parse(path.read_text(encoding="utf-8-sig")).body
        if isinstance(node, ast.Assign) for name in node.targets if isinstance(name, ast.Name)}

    def read(node, seen):
        if isinstance(node, ast.Name):
            require(node.id in assignments and node.id not in seen, "archived_constant_missing")
            return read(assignments[node.id], seen | {node.id})
        if isinstance(node, ast.Dict):
            return {read(k, seen): read(v, seen) for k, v in zip(node.keys, node.values)}
        if isinstance(node, (ast.List, ast.Tuple)):
            return [read(n, seen) for n in node.elts]
        return ast.literal_eval(node)

    require(variable in assignments, "archived_constant_missing")
    return read(assignments[variable], {variable})


def _verify_records(story, build, records, pool):
    source = story["source"]
    if build["status"] != "ok":
        require(not records, "failed_build_deployed_records")
    else:
        require(records and len(records) == len(build["facts"]), "successful_build_missing_records")
    for record, fact in zip(records, build["facts"]):
        a, b = record["source_start"], record["source_end"]
        require(type(a) is int and type(b) is int and 0 <= a < b <= len(source["text"]), "record_source_span")
        require(record["text"] == source["text"][a:b] == fact["text"] and
            a == fact["source_start"] and b == fact["source_end"], "record_fact_changed")
        equal(record["source"], {"source_id": source["source_id"], "text": source["text"], "sha256": sha(source["text"])}, "record_source_changed")
        require(record["source_id"] == record["record_id"] and record["schema"] == "local_labeled_memory_v1", "record_identity")
        grant, label = record["access"], record["label"]
        expected = {"record_id": record["record_id"], "owner_id": "owner", "readers": ["owner"],
            "origin_agent_id": "source-agent", "allowed_agent_ids": ["target-agent"], "source_id": source["source_id"],
            "source_sha256": sha(source["text"]), "epoch": 0, "scope_version": "exact_fact_source_span_v1",
            "content_sha256": sha(record["text"]), "source_start": a, "source_end": b}
        equal(grant, expected, "grant_content_or_principal_binding")
        require(label["access_sha256"] == digest(grant) and label["content_sha256"] == sha(record["text"])
            and label["source_sha256"] == sha(source["text"]) and label["source_start"] == a and label["source_end"] == b
            and label["record_id"] == record["record_id"] and label["epoch"] == 0
            and label["policy_version"] == story["policy"]["version"] and label["policy_sha256"] == digest(normalized_policy(story["policy"])), "label_binding")
        require(label["builder_version"] == build["builder_version"] and label["status"] == "ok", "label_build_status")
        for field in ("access_signature", "label_signature"):
            require(isinstance(record[field], str) and SHA.fullmatch(record[field]), "signature_shape")
        findings = sorted({(f["start"], f["end"], f["category"]) for f in fact["findings"]})
        equal(label["findings"], [dict(zip(("start", "end", "category"), f)) for f in findings], "label_fact_findings")
        for f in label["findings"]:
            require(type(f["start"]) is int and type(f["end"]) is int and 0 <= f["start"] < f["end"] <= len(record["text"])
                and f["category"] in story["policy"]["protected_categories"], "label_finding_span")
    metrics = {"stored_characters": sum(len(r["text"]) for r in records),
        "stored_record_json_bytes": len(json.dumps(records, ensure_ascii=False).encode("utf-8")),
        "stored_source_copy_characters": sum(len(r["source"]["text"]) for r in records), "source_characters": len(source["text"]),
        "candidate_pool_json_bytes": len(json.dumps(pool, ensure_ascii=False).encode("utf-8")) if build["builder"] in REFERENCE else 0}
    raw = {k: v for k, v in build.items() if k not in HARNESS_BUILD_FIELDS}
    raw["status"] = build["raw_build_status"]
    metrics["construction_result_json_bytes"] = len(json.dumps(raw, ensure_ascii=False).encode("utf-8"))
    for key, value in metrics.items():
        equal(build[key], value, "build_volume_"+key)
    if build["builder"] in REFERENCE:
        equal(build["pool"], pool, "reference_pool_changed")
        selected = build["selected_fids"]
        require(isinstance(selected, list) and len(selected) == len(set(selected)), "selected_fids_duplicate")
        by_id = {c["fid"]: c for c in pool["candidates"]}
        require(set(selected) <= set(by_id), "selected_fid_unknown")
        require(selected == sorted(selected, key=lambda fid: by_id[fid]["start"]), "selected_fid_order")
        if build["builder"] == "retain_all":
            equal(selected, list(by_id), "retain_all_dropped_candidate")
        else:
            require(len(selected) <= 8, "selection_capacity")
        if build["status"] == "ok":
            equal([(f["source_start"], f["source_end"]) for f in build["facts"]],
                [(by_id[fid]["start"], by_id[fid]["end"]) for fid in selected], "selected_fact_mismatch")
        equal(build["detector_local_counts"], build["inference_counts"], "independent_label_accounting")
        equal(build["selector_local_counts"], {"local_encoder": 0, "local_generation": build["generation_calls_observed"], "unknown": 0}, "selector_accounting")
        equal(build["local_calls"], build["generation_calls_observed"], "selector_allocated_accounting")


def _verify_secondary(row):
    if row.get("answer_status") != "ok":
        require("secondary_serialization" not in row, "secondary_without_model_answer")
        require(row.get("final_answer") is None, "final_without_successful_model_answer")
        return
    answer = row["model_answer"]
    require(isinstance(answer, str), "model_answer_type")
    outbound = row["outbound"]
    tokens = set(TOKEN.findall(outbound["query"]))
    for memory in outbound["memories"]:
        tokens.update(TOKEN.findall(memory["text"]))
    stripped = answer.strip()
    add = BARE.fullmatch(stripped) is not None and "["+stripped+"]" in tokens
    expected = "["+stripped+"]" if add else answer
    secondary = row["secondary_serialization"]
    equal(secondary["canonical_answer"], expected, "secondary_changed_unregistered_answer")
    equal(secondary["decision"], "added_outer_brackets" if add else "unchanged", "secondary_decision")
    for status, answer_value in ((row.get("restoration_status"), row.get("final_answer")),
                                 (secondary.get("restoration_status"), secondary.get("final_answer"))):
        require(status in {"ok", "blocked"} and (answer_value is None if status == "blocked" else isinstance(answer_value, str)), "restoration_result_state")
    if add:
        require(row.get("restoration_status") == "blocked" and row.get("final_answer") is None, "primary_promoted_from_secondary")
    else:
        equal(secondary.get("final_answer"), row.get("final_answer"), "unchanged_secondary_result_differs")
        equal(secondary.get("restoration_status"), row.get("restoration_status"), "unchanged_secondary_status_differs")
    # UNKNOWN has no restoration mapping and must not become a reference answer.
    if answer.strip() == "UNKNOWN":
        require(row.get("final_answer") == "UNKNOWN" and secondary.get("final_answer") == "UNKNOWN", "unknown_promoted_to_answer")


def _ledger(events, rows, builds, stories, pools, paths):
    requests, terminals, group = {}, {}, defaultdict(list)
    for event in events:
        index = integer(event["index"], "ledger_index")
        require(index > 0 and event["phase"] in {"request", "response", "failure"}, "ledger_phase")
        key = (event["stage"], event["arm"], event["story_id"], event["task_id"])
        require(event["arm"] in ARMS and event["story_id"] in stories and event["stage"] in {"build", "answer"}, "ledger_context")
        if event["phase"] == "request":
            require(index not in requests and index not in terminals, "duplicate_request")
            requests[index] = event
            group[key].append(event)
            body = event["request"]
            require(event["request_sha256"] == digest(body), "request_hash")
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            equal(event["wire_json_utf8_bytes"], len(encoded), "wire_json_bytes")
            require(event["wire_json_utf8_sha256"] == sha(encoded), "wire_json_hash")
            require("JSON body only" in event["wire_encoding"], "wire_encoding_scope")
            options = body["options"]
            equal(options, {"num_ctx": 4096, "num_predict": 1024 if event["stage"] == "build" else 64, "temperature": 0, "seed": 42}, "request_options")
            require(body["model"] == MODEL and body["stream"] is False and body["keep_alive"] == "30m", "request_model")
            require(event["scope"] == "synthetic_development_local_only", "request_scope")
        else:
            require(index in requests and index not in terminals, "orphan_or_duplicate_terminal")
            request = requests[index]
            equal(key, (request["stage"], request["arm"], request["story_id"], request["task_id"]), "terminal_context")
            require(event["request_sha256"] == request["request_sha256"], "terminal_request_hash")
            require(isinstance(event["elapsed_seconds"], (int, float)) and event["elapsed_seconds"] >= 0, "terminal_elapsed")
            terminals[index] = event
            if event["phase"] == "response":
                response = event["response"]
                require(event["response_sha256"] == digest(response), "response_hash")
                prompt, output = response.get("prompt_eval_count"), response.get("eval_count")
                require(type(prompt) is int and 0 < prompt <= 3072 and type(output) is int and
                    0 < output <= request["request"]["options"]["num_predict"] and
                    prompt+request["request"]["options"]["num_predict"] <= 4096 and event["actual_usage_within_budget"] is True, "response_token_budget")
            else:
                require(event["error"] == "physical_transport_failed", "failure_code")
    require(set(requests) == set(terminals) == set(range(1, len(requests)+1)) and len(requests) <= 208, "physical_request_denominator")
    for build in builds:
        key = ("build", build["builder"], build["story_id"], None)
        selected = group.pop(key, [])
        equal(build["generation_calls_observed"], len(selected), "build_physical_calls")
        require(len(selected) <= (2 if build["builder"] in {"old_joint_quote", "reference_id", "reference_quote"} else 0), "build_generation_cap")
        story, pool = stories[build["story_id"]], pools[build["story_id"]]
        for n, event in enumerate(selected):
            messages = event["request"]["messages"]
            require(len(messages) == 2+n and messages[0]["role"] == "system" and messages[1]["role"] == "user", "builder_messages")
            if build["builder"] in {"reference_id", "reference_quote"}:
                expected = {"purpose": _literal_assignment(paths["memory_migration_study/reference_memory.py"], "PURPOSE"),
                    "candidates": [{"fid": c["fid"], "text": story["source"]["text"][c["start"]:c["end"]]} for c in pool["candidates"]]}
                equal(json.loads(messages[1]["content"]), expected, "selector_input_not_pool_only")
                require(messages[0]["content"] == _literal_assignment(paths["memory_migration_study/reference_memory.py"], "SYSTEM_PROMPT"), "selector_prompt")
                field = "selected_fids" if build["builder"] == "reference_id" else "selected_quotes"
                schema = event["request"]["format"]
                require(set(schema["properties"]) == {"status", field}, "selector_schema_fields")
                prop = schema["properties"][field]
                enum = [c["fid"] for c in pool["candidates"]] if field == "selected_fids" else list(dict.fromkeys(c["text"] for c in expected["candidates"]))
                equal(prop["items"]["enum"], enum, "selector_schema_enum")
                require(prop["maxItems"] == 8 and prop["uniqueItems"] is True and schema["additionalProperties"] is False, "selector_schema_budget")
                equal(schema["required"], ["status", field], "selector_schema_required")
                require(len(json.dumps(event["request"], ensure_ascii=False, separators=(",", ":")).encode())+320+1024 <= 4096, "selector_preflight_budget")
                if n:
                    equal(messages[2], {"role": "user", "content": _literal_assignment(paths["memory_migration_study/reference_memory.py"], "REPAIR_PROMPT")}, "selector_repair")
            else:
                equal(json.loads(messages[1]["content"]), {"text": story["source"]["text"]}, "joint_builder_input_not_source_only")
                trusted = {k: normalized_policy(story["policy"])[k] for k in ("version", "protected_categories", "instructions")}
                expected_system = _literal_assignment(paths["memory_migration_study/memory_builder.py"], "SYSTEM_PROMPT")+"\nTrusted sensitivity policy JSON:\n"+json.dumps(trusted, ensure_ascii=False, separators=(",", ":"))
                equal(messages[0]["content"], expected_system, "joint_builder_system_policy")
        if build["builder"] in {"reference_id", "reference_quote"}:
            attempts = build["selection_attempts"]
            equal(len(attempts), len(selected), "selector_attempt_denominator")
            field = "selected_fids" if build["builder"] == "reference_id" else "selected_quotes"
            for n, (event, observation) in enumerate(zip(selected, attempts)):
                equal(observation["attempt"], n+1, "selector_attempt_order")
                require(observation["request_sha256"] == event["request_sha256"], "selector_attempt_hash")
                equal(observation["input_budget_upper_bound"], len(json.dumps(event["request"], ensure_ascii=False, separators=(",", ":")).encode())+320+1024, "selector_attempt_budget")
                terminal = terminals[event["index"]]
                if terminal["phase"] == "response":
                    response = terminal["response"]
                    # Valid envelope observations contain usage even on invalid JSON.
                    if observation["prompt_eval_count"] is not None:
                        equal(observation["prompt_eval_count"], response["prompt_eval_count"], "selector_observed_prompt_count")
                        equal(observation["eval_count"], response["eval_count"], "selector_observed_output_count")
            if build["selected_fids"] or build["status"] == "ok":
                require(selected, "selection_without_physical_generation")
                terminal = terminals[selected[-1]["index"]]
                require(terminal["phase"] == "response", "selection_without_response")
                response = terminal["response"]
                message = response.get("message", {})
                require(response.get("model") == MODEL and response.get("done") is True and response.get("done_reason") == "stop"
                    and message.get("role") == "assistant" and not message.get("thinking") and not message.get("tool_calls"), "selector_envelope")
                decoded = strict_json(message["content"])
                require(isinstance(decoded, dict) and set(decoded) == {"status", field} and decoded["status"] == "ok"
                    and isinstance(decoded[field], list) and 0 < len(decoded[field]) <= 8 and all(isinstance(v, str) for v in decoded[field])
                    and len(set(decoded[field])) == len(decoded[field]), "selector_raw_output_schema")
                by_id = {c["fid"]: c for c in pool["candidates"]}
                if field == "selected_fids":
                    require(set(decoded[field]) <= set(by_id), "selector_raw_unknown_fid")
                    selected_fids = decoded[field]
                else:
                    selected_fids = []
                    for quote in decoded[field]:
                        matches = [fid for fid, c in by_id.items() if story["source"]["text"][c["start"]:c["end"]] == quote]
                        require(len(matches) == 1, "selector_raw_ambiguous_quote")
                        selected_fids.extend(matches)
                equal(sorted(selected_fids, key=lambda fid: by_id[fid]["start"]), build["selected_fids"], "raw_selector_fids_changed")
    for row in rows:
        key = ("answer", row["arm"], row["story_id"], row["task_id"])
        selected = group.pop(key, [])
        equal(row["answer_calls"], len(selected), "answer_physical_calls")
        require(len(selected) <= 1 and (not selected or row["actor_id"] == "owner" and row["prepare_status"] == "ok"), "unauthorized_answer_request")
        if selected:
            event = selected[0]
            messages = event["request"]["messages"]
            equal(len(messages), 2, "answer_messages")
            prompts = _literal_assignment(paths["memory_migration_study/budget.py"], "MEMORY_PROMPTS")
            equal(messages[0], {"role": "system", "content": prompts["memory_fact_query_v2"]}, "answer_prompt")
            equal(json.loads(messages[1]["content"]), row["outbound"], "answer_payload_not_actual_outbound")
            equal(row["actual_payload_sha256"], digest(row["outbound"]), "actual_payload_hash")
            if row.get("answer_status") == "ok":
                response = terminals[event["index"]]
                require(response["phase"] == "response", "successful_answer_without_response")
                envelope = response["response"]
                require(envelope.get("model") == MODEL and envelope.get("done") is True and envelope.get("done_reason") == "stop"
                    and not envelope["message"].get("thinking") and not envelope["message"].get("tool_calls"), "answer_envelope")
                equal(envelope["message"]["content"].strip(), row["model_answer"], "raw_model_answer_changed")
    require(not group, "unallocated_physical_request")
    return requests, terminals


def physical_costs_by_arm(requests, terminals):
    """Actual JSON-body bytes and reported token usage, with failed attempts kept."""
    costs = {}
    for arm in ARMS:
        costs[arm] = {}
        for stage in ("build", "answer"):
            selected = [r for r in requests.values() if r["arm"] == arm and r["stage"] == stage]
            ended = [terminals[r["index"]] for r in selected]
            responses = [e for e in ended if e["phase"] == "response"]
            costs[arm][stage] = {"physical_generation_attempts": len(selected), "response_count": len(responses),
                "transport_failures": len(ended)-len(responses),
                "wire_json_utf8_bytes": sum(e["wire_json_utf8_bytes"] for e in selected),
                "prompt_eval_count": sum(e["response"]["prompt_eval_count"] for e in responses),
                "eval_count": sum(e["response"]["eval_count"] for e in responses),
                "observed_transport_elapsed_seconds": sum(e["elapsed_seconds"] for e in ended)}
    return costs


def verify(directory, *, corpus=None, project_root=None):
    """Raise ValueError on inconsistent evidence; return an offline audit receipt."""
    run, project_root = Path(directory).resolve(), Path(project_root or ROOT).resolve()
    names = ("plan.json", "runtime.json", "evaluation.json", "config.json", "runtime_identity.json", "pools.json", "builds.json",
             "record_store.json", "rows.json", "report.json", "transport_audit.json", "network_audit.json")
    values = {name: json.loads((run/name).read_bytes()) for name in names}
    for value in values.values():
        no_secret_fields(value)
    plan, runtime, evaluation, config, identity, pools_raw, builds, stores, rows, report, audit, network = (values[n] for n in names)
    equal(plan["arms"], {arm: [arm, "migration", False] for arm in ARMS}, "arm_protocol")
    require(plan["version"] == VERSION and plan["score_schema_version"] == 2 and plan["split"] == "development"
        and plan["expected_rows"] == 200 and plan["legal_per_arm"] == 32 and plan["outsider_per_arm"] == 8
        and plan["privacy_pipeline"] == "legacy" and plan["transfer_mode"] == "migration" and plan["query_intent"] is False
        and plan["ordering_seed"] == 2026102507 and plan["evaluation_timing"] == "after_all_model_processing", "registered_protocol")
    equal(plan["generation_limits"], {"total": 208, "answers": 160, "builders": 48, "per_model_builder_per_story": 2}, "generation_limits")
    require(len(runtime) == 8 and len({s["story_id"] for s in runtime}) == 8, "story_denominator")
    stories = {s["story_id"]: s for s in runtime}
    require(set(evaluation) == set(stories), "gold_story_identity")
    require(len({s["template_family"] for s in runtime}) == 4, "template_family_denominator")
    for story in runtime:
        require(len(story["tasks"]) == 5 and len({t["task_id"] for t in story["tasks"]}) == 5 and
            Counter(t["actor_id"] for t in story["tasks"]) == {"owner": 4, "outsider": 1}, "story_task_denominator")
    corpus = Path(corpus or project_root/"examples/privacy_semantics_v1")
    for filename, expected in (("runtime.json", runtime), ("evaluation.json", evaluation)):
        raw = (corpus/"development"/filename).read_bytes()
        require(sha(raw) == plan[filename.split(".")[0]+"_sha256"], "original_input_hash")
        equal(json.loads(raw), expected, "input_snapshot_changed")
    require(digest(config) == plan["config_sha256"], "configuration_hash")
    require(config["endpoint"] == "http://127.0.0.1:11435" and config["model"] == MODEL and
        config["expected_digest"] == MODEL_DIGEST and config["expected_version"] == "0.40.8", "local_model_configuration")
    paths = _archive(run, plan, project_root)
    require(identity["local_generation"] == {"endpoint": "http://127.0.0.1:11435", "model": MODEL,
        "version": "0.40.8", "digest": MODEL_DIGEST}, "model_receipt")
    for key, constant in (("code_revision", "CODE_REVISION"), ("model_revision", "MODEL_REVISION"), ("model_id", "MODEL_ID")):
        require(identity["ner"][key] == _literal_assignment(paths["memory_migration_study/ner_detector.py"], constant), "ner_receipt")
    require(SHA.fullmatch(identity["ner"]["weights_sha256"]) and SHA.fullmatch(identity["ner"]["files_sha256"])
        and identity["ner"]["device"] == "cpu" and identity["ner_initialization_seconds"] >= 0, "ner_inventory_receipt")
    require(len(pools_raw) == 8 and len({p["story_id"] for p in pools_raw}) == 8, "pool_denominator")
    pools = {p["story_id"]: p["pool"] for p in pools_raw}
    require(set(pools) == set(stories), "pool_story_identity")
    for sid, pool in pools.items():
        verify_pool(stories[sid], pool)
    expected_builds = {(sid, arm) for sid in stories for arm in ARMS}
    build_index = {(b["story_id"], b["builder"]): b for b in builds}
    store_index = {(s["story_id"], s["builder"]): s["records"] for s in stores}
    require(len(builds) == len(stores) == 40 and set(build_index) == set(store_index) == expected_builds, "build_or_store_denominator")
    for key, build in build_index.items():
        _verify_records(stories[key[0]], build, store_index[key], pools[key[0]])
        require(build["language"] == stories[key[0]]["language"], "build_language")
        for kind in KINDS:
            integer(build["inference_counts"][kind], "build_inference_count")
        require(build["inference_counts"]["unknown"] == 0 and build["inference_counts"]["local_generation"] == 0, "build_detector_count_type")
    expected_rows = {(sid, t["task_id"], arm) for sid, s in stories.items() for t in s["tasks"] for arm in ARMS}
    require(len(rows) == 200 and {(r["story_id"], r["task_id"], r["arm"]) for r in rows} == expected_rows, "task_matrix_denominator")
    checked_masks = 0
    for row in rows:
        story = stories[row["story_id"]]
        task = next(t for t in story["tasks"] if t["task_id"] == row["task_id"])
        build, records = build_index[(row["story_id"], row["arm"])], store_index[(row["story_id"], row["arm"])]
        require(row["actor_id"] == task["actor_id"] and row["language"] == story["language"] and
            row["template_family"] == story["template_family"] and row["build_status"] == build["status"], "row_identity_or_build_status")
        require(row["mode"] == "migration" and row["privacy_pipeline"] == "legacy" and row["intent_applied"] is False
            and row["secondary_serialization_registered"] is True, "row_protocol")
        for kind in KINDS:
            integer(row["inference_counts"][kind], "row_inference_count")
        require(row["inference_counts"]["unknown"] == row["inference_counts"]["local_generation"] == 0, "migration_detector_count_type")
        equal(row["detector_calls"], row["inference_counts"]["local_encoder"], "migration_detector_accounting")
        if not records:
            require(row["prepare_status"] != "ok" and row["answer_calls"] == 0 and row.get("final_answer") is None, "failed_build_task_removed_or_deployed")
        if row["actor_id"] == "outsider":
            require(row["prepare_status"] != "ok" and row["answer_calls"] == row["detector_calls"] == 0
                and row.get("final_answer") is None and "outbound" not in row, "outsider_information_processing")
            require(not records or row.get("module_authorization_error") == "principal_not_authorized", "outsider_not_actual_authority_denial")
        if row["prepare_status"] == "ok":
            mask = independent_masking(story, task, evaluation[row["story_id"]], records, row["outbound"], False)
            checked_masks += 1
        else:
            mask = blocked_masking(story, evaluation[row["story_id"]], records)
        equal(mask, row["masking"], "independent_masking_mismatch")
        expected = evaluation[row["story_id"]]["answers"].get(row["task_id"])
        equal(row["required_fact_retained"], bool(expected and any(expected in r["text"] for r in records)), "required_fact_retention")
        _verify_secondary(row)
        equal(row["score"], independent_score(row, evaluation[row["story_id"]]), "independent_score_mismatch")
    events = [json.loads(line) for line in (run/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    for event in events:
        no_secret_fields(event)
    requests, terminals = _ledger(events, rows, builds, stories, pools, paths)
    responses = [e for e in terminals.values() if e["phase"] == "response"]
    failures = len(terminals)-len(responses)
    require(audit["completed"] is True and audit["registered_protocol"] == VERSION and audit["recovery_mapping_recorded"] is False,
        "transport_completion")
    for key, expected in {"physical_generation_attempts": len(requests), "responses": len(responses), "transport_errors": failures,
        "actual_token_budget_violations": 0, "registered_generation_cap": 208, "cloud_calls": 0, "new_api_cost_cny": 0}.items():
        equal(audit[key], expected, "transport_summary_"+key)
    equal(audit["network"], network, "network_summary")
    require(network["external_attempts_blocked"] == 0 and type(network["loopback_connections"]) is int and network["loopback_connections"] >= 0, "external_network_attempt")
    equal(report["arms"], independent_aggregate(rows, builds), "independent_aggregate_mismatch")
    totals = {"version": VERSION, "registered_rows": 200, "recorded_rows": 200, "source_stories": 8, "template_families": 4,
        "generation_calls_observed": len(requests), "builder_generations": sum(b["generation_calls_observed"] for b in builds),
        "answer_generations": sum(r["answer_calls"] for r in rows),
        "build_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds),
        "migration_encoder_calls": sum(r["inference_counts"]["local_encoder"] for r in rows),
        "request_wire_json_bytes": sum(e["wire_json_utf8_bytes"] for e in requests.values()),
        "prompt_eval_count_sum": sum(e["response"]["prompt_eval_count"] for e in responses),
        "eval_count_sum": sum(e["response"]["eval_count"] for e in responses),
        "construction_bytes_by_arm": {arm: {key: sum(b[key] for b in builds if b["builder"] == arm)
            for key in ("candidate_pool_json_bytes", "construction_result_json_bytes")} for arm in ARMS},
        "detector_call_accounting_complete": True, "implementation_unchanged": True, "cloud_calls": 0, "new_api_cost_cny": 0}
    for key, expected in totals.items():
        equal(report[key], expected, "report_total_"+key)
    require(report["scope"] == plan["scope"], "scope_changed")
    costs = physical_costs_by_arm(requests, terminals)
    equal(sum(cell[stage]["physical_generation_attempts"] for cell in costs.values() for stage in ("build", "answer")), len(requests), "cost_generation_partition")
    equal(sum(cell[stage]["wire_json_utf8_bytes"] for cell in costs.values() for stage in ("build", "answer")), totals["request_wire_json_bytes"], "cost_byte_partition")
    return {"version": "independent_reference_memory_study_verifier_v2", "status": "passed",
        "registered_rows": 200, "source_stories": 8, "builds_checked": 40, "same_pool_reference_builds_checked": 24,
        "literal_masking_requests_checked": checked_masks, "physical_generation_attempts": len(requests),
        "builder_generations": totals["builder_generations"], "answer_generations": totals["answer_generations"],
        "build_encoder_calls": totals["build_encoder_calls"], "migration_encoder_calls": totals["migration_encoder_calls"],
        "physical_costs_by_arm": costs, "byte_metric_scope": "Serialized JSON request body bytes; excludes HTTP headers, framing and response bytes.",
        "verification_model_calls": 0, "arms": independent_aggregate(rows, builds),
        "evidence_sha256": {name: sha((run/name).read_bytes()) for name in (*names, "request_transport.jsonl")},
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "limits": ["Public hash/shape checks do not authenticate HMAC signatures or replay destroyed recovery maps.",
            "Evaluation timing is checked in archived launcher control flow; recorded requests are checked against source/pool/outbound, not fabricated timestamps.",
            "Registered literal masking and exposed development task scores do not establish semantic privacy, native interoperability, compression or research novelty."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.directory, corpus=args.corpus)
    except (ValueError, KeyError, TypeError, IndexError, OSError, StopIteration) as exc:
        result = {"version": "independent_reference_memory_study_verifier_v2", "status": "failed",
            "error": str(exc) if isinstance(exc, ValueError) else type(exc).__name__, "verification_model_calls": 0}
    output = args.output or args.directory/"independent_reference_memory_verification.json"
    if output.exists():
        raise ValueError("verification_output_exists")
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
