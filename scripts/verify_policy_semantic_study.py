"""Independent offline consistency checks for the five-arm A->B study.

No producer scorer, model, signing key or restoration map is used. The verifier
reuses independent source/pool/serialization and literal-alignment checks from
the earlier verifier. Passing means consistent evidence, not effect acceptance.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import verify_reference_memory_study as base

VERSION = "policy_semantic_transfer_development_v2"
VERSIONS = frozenset(("policy_semantic_transfer_development_v1", VERSION))
ARMS = ("baseline", "union", "roles", "completion", "joint")
SEMANTIC = frozenset(("roles", "completion", "joint"))
LIMITS = {"total": 464, "build": 16, "semantic_shared": 64, "answer": 160,
          "union_detection_no_cache_worst_case": 224}
digest, sha, require, equal, integer = base.digest, base.sha, base.require, base.equal, base.integer


def aggregate(rows, builds):
    """Independent shared-build aggregate, preserving every task denominator."""
    out = {}
    for arm in ARMS:
        selected = [r for r in rows if r["arm"] == arm]
        legal = [r for r in selected if r["actor_id"] == "owner"]
        ready = [r for r in legal if r["prepare_status"] == "ok"]
        out[arm] = {"registered_tasks": len(selected), "legal_tasks": len(legal),
            "correct": sum(r["score"]["correct"] for r in legal), "ready": len(ready),
            "joint_masked_legal_tasks": len(legal),
            "joint_correct_no_masking_gap": sum(r["score"]["joint_correct_no_masking_gap"] for r in legal),
            "secondary_serialization_legal_tasks": len(legal),
            "secondary_serialization_correct": sum(r["score"]["secondary_serialization_correct"] for r in legal),
            "secondary_joint_correct_no_masking_gap": sum(r["score"]["secondary_joint_correct_no_masking_gap"] for r in legal),
            **{k: sum(r["score"][k] for r in selected) for k in ("build_block", "preprocessing_block",
                "true_model_unknown", "restoration_failure", "outsider_blocked", "unauthorized_output")},
            "supported_legal_tasks": sum(r["required_fact_retained"] for r in legal),
            "ready_masked_requests": len(ready),
            "ready_with_masking_gaps": sum(bool(r["masking"]["partial"] or r["masking"]["unmasked"]) for r in ready),
            **{dest: sum(r["masking"][src] for r in ready) for dest, src in
                (("complete_spans", "complete"), ("partial_spans", "partial"), ("unmasked_spans", "unmasked"),
                 ("extra_masked_characters", "extra_masked_characters"))},
            "build_stories": len(builds), "build_successes": sum(b["status"] == "ok" for b in builds),
            **{k: sum(b[k] for b in builds) for k in ("stored_characters", "stored_record_json_bytes",
                "stored_source_copy_characters", "source_characters")},
            "builder_calls_allocated": sum(b["local_calls"] for b in builds),
            "migration_detector_calls": sum(r["detector_calls"] for r in selected),
            "answer_calls": sum(r["answer_calls"] for r in selected), "intent_applied": 0,
            "by_language": {lang: {"legal": sum(r["language"] == lang for r in legal),
                "correct": sum(r["language"] == lang and r["score"]["correct"] for r in legal)} for lang in ("en", "zh")}}
    return out


def archive(run, plan, root):
    paths, current_identical = {}, True
    for name, expected in plan["implementation_sha256"].items():
        relative = Path(name.replace("\\", "/"))
        require(not relative.is_absolute() and ".." not in relative.parts and relative.suffix == ".py", "unsafe_archive_path")
        saved, current = (run / "implementation" / relative).resolve(), (root / relative).resolve()
        require(saved.is_relative_to((run / "implementation").resolve()) and current.is_relative_to(root), "unsafe_archive_path")
        require(sha(saved.read_bytes()) == expected, "archive_hash_changed")
        current_identical = current_identical and current.is_file() and sha(current.read_bytes()) == expected
        paths[relative.as_posix()] = saved
    required = {"scripts/run_policy_semantic_study.py", "scripts/run_reference_memory_study.py",
        "scripts/run_boundary_transfer_diagnostic.py", "memory_migration_study/policy_semantics.py",
        "memory_migration_study/memory_labels.py", "memory_migration_study/reference_memory.py",
        "memory_migration_study/local_detector.py", "memory_migration_study/budget.py"}
    require(required <= set(paths), "archive_inventory_incomplete")
    archived_inventory = {p.relative_to(run / "implementation").as_posix() for p in (run / "implementation").rglob("*.py")}
    require(archived_inventory == set(paths), "archive_inventory_changed")
    current_package = {"memory_migration_study/"+p.name for p in (root / "memory_migration_study").glob("*.py")}
    current_identical = current_identical and current_package == {p for p in paths if p.startswith("memory_migration_study/")}
    equal(base._literal_assignment(paths["scripts/run_policy_semantic_study.py"], "VERSION"), plan["version"], "archived_driver_version")
    tree = ast.parse(paths["scripts/run_policy_semantic_study.py"].read_text(encoding="utf-8-sig"))
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    loops = [n for n in function.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "story"]
    parses = [n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "json" and n.func.attr == "loads"
        and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "evaluation_bytes"]
    closures = [n for n in function.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute)
        and t.attr == "model_phase_closed" for t in n.targets) and isinstance(n.value, ast.Constant) and n.value.value is True]
    require(len(loops) == len(parses) == len(closures) == 1 and loops[0].end_lineno < closures[0].lineno < parses[0].lineno,
        "evaluation_before_model_phase_closed")
    authority = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AuditedAuthority")
    validator = next(n for n in authority.body if isinstance(n, ast.FunctionDef) and n.name == "validate_access")
    super_calls = [n for n in ast.walk(validator) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "validate_access" and isinstance(n.func.value, ast.Call)
        and isinstance(n.func.value.func, ast.Name) and n.func.value.func.id == "super"]
    logs = [n for n in ast.walk(validator) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "event"]
    require(len(super_calls) == len(logs) == 1 and super_calls[0].lineno < logs[0].lineno, "authorization_logger_not_real_super")
    # Validate the archived contract even if preflight blocks every semantic
    # POST; actual calls below are checked again with their precise CID sets.
    expected_semantic_schema(paths["memory_migration_study/policy_semantics.py"], plan["version"], ["C0001"], 256)
    return paths, bool(current_identical)


def expected_semantic_schema(path, protocol, cids, maximum):
    """Reconstruct pure literal AST expressions; never import/execute archives.

    Only literal containers, local names, len/list and ROLES slicing are allowed.
    An independent fixed contract then rejects mixed or weakened structures.
    """
    require(protocol in VERSIONS, "unsupported_semantic_protocol")
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_schema"]
    require(len(functions) == 1, "archived_semantic_schema_function")
    roles = base._literal_assignment(path, "ROLES")
    equal(roles, ["value", "generic_role", "field_label", "other", "uncertain"], "archived_semantic_roles")
    names = {"cids": list(cids), "maximum": maximum, "ROLES": roles}
    def literal(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            require(node.id in names, "nonliteral_archived_schema_name")
            return deepcopy(names[node.id])
        if isinstance(node, (ast.List, ast.Tuple)):
            return [literal(n) for n in node.elts]
        if isinstance(node, ast.Dict):
            result = {}
            for key, value in zip(node.keys, node.values):
                require(key is not None, "nonliteral_archived_schema_unpack")
                result[literal(key)] = literal(value)
            return result
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"list", "len"}:
            require(len(node.args) == 1 and not node.keywords, "nonliteral_archived_schema_call")
            value = literal(node.args[0])
            require(isinstance(value, list), "nonliteral_archived_schema_call")
            return list(value) if node.func.id == "list" else len(value)
        if isinstance(node, ast.Subscript):
            value = literal(node.value)
            require(isinstance(value, list), "nonliteral_archived_schema_slice")
            if isinstance(node.slice, ast.Slice):
                bounds = [literal(n) if n is not None else None for n in
                          (node.slice.lower, node.slice.upper, node.slice.step)]
                require(all(n is None or type(n) is int for n in bounds), "nonliteral_archived_schema_slice")
                return value[slice(*bounds)]
            index = literal(node.slice)
            require(type(index) is int, "nonliteral_archived_schema_slice")
            return value[index]
        raise ValueError("nonliteral_archived_schema_expression")
    reconstructed = None
    for statement in functions[0].body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
            continue
        if isinstance(statement, ast.Assign):
            require(len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name), "nonliteral_archived_schema_statement")
            names[statement.targets[0].id] = literal(statement.value)
        elif isinstance(statement, ast.Return):
            require(reconstructed is None, "nonliteral_archived_schema_statement")
            reconstructed = literal(statement.value)
        else:
            raise ValueError("nonliteral_archived_schema_statement")
    require(reconstructed is not None, "archived_schema_missing_return")
    cid = {"type": "string", "enum": list(cids)}
    if protocol.endswith("_v1"):
        item = {"type": "object", "additionalProperties": False, "required": ["cid", "role", "quote"],
            "properties": {"cid": cid, "role": {"type": "string", "enum": roles},
                "quote": {"type": ["string", "null"], "minLength": 1, "maxLength": maximum}}}
    else:
        item = {"anyOf": [
            {"type": "object", "additionalProperties": False, "required": ["cid", "role", "quote"],
             "properties": {"cid": cid, "role": {"type": "string", "enum": ["value"]},
                "quote": {"type": "string", "minLength": 1, "maxLength": maximum}}},
            {"type": "object", "additionalProperties": False, "required": ["cid", "role", "quote"],
             "properties": {"cid": cid, "role": {"type": "string", "enum": roles[1:]}, "quote": {"type": "null"}}}]}
    expected = {"type": "object", "additionalProperties": False, "required": ["verdicts"],
        "properties": {"verdicts": {"type": "array", "minItems": len(cids), "maxItems": len(cids), "items": item}}}
    equal(reconstructed, expected, "archived_semantic_schema_contract")
    return expected


def verify_records(story, build, records, pool):
    # Adapt only names/metrics absent from the shared-build schema. The earlier
    # independent checker still verifies every persisted source/ACL/label field.
    adapted = deepcopy(build)
    adapted.update(builder="reference_id", raw_build_status=build["status"],
        candidate_pool_json_bytes=len(json.dumps(pool, ensure_ascii=False).encode()), construction_result_json_bytes=0)
    raw = {k: v for k, v in adapted.items() if k not in base.HARNESS_BUILD_FIELDS}
    raw["status"] = adapted["raw_build_status"]
    adapted["construction_result_json_bytes"] = len(json.dumps(raw, ensure_ascii=False).encode())
    base._verify_records(story, adapted, records, pool)


def successful_envelope(response):
    message = response.get("message", {})
    require(response.get("model") == base.MODEL and response.get("done") is True and
        response.get("done_reason") == "stop" and message.get("role") == "assistant" and
        not message.get("thinking") and not message.get("tool_calls") and isinstance(message.get("content"), str),
        "successful_model_envelope")


def verify_grounded_verdicts(raw, receipt, candidates, aliases, sources):
    """An accepted receipt must still obey the host cross-field contract."""
    require(isinstance(raw, dict) and set(raw) == {"verdicts"} and isinstance(raw["verdicts"], list), "semantic_raw_output_schema")
    by_cid = {r["cid"]: r for r in raw["verdicts"]}
    require(len(by_cid) == len(raw["verdicts"]) == len(candidates), "semantic_raw_cid_denominator")
    equal([by_cid[c["cid"]] for c in candidates], receipt["verdicts"], "semantic_raw_verdicts_changed")
    grounded = {r["cid"]: r for r in receipt["grounded_verdicts"]}
    require(set(grounded) == set(by_cid), "semantic_grounded_cid_denominator")
    for candidate, verdict in zip(candidates, receipt["verdicts"]):
        require(set(verdict) == {"cid", "role", "quote"} and verdict["role"] in
            {"value", "generic_role", "field_label", "other"}, "semantic_accepted_verdict")
        item = grounded[verdict["cid"]]
        sid = aliases[candidate["source"]]
        require(item["source_id"] == sid and item["category"] == candidate["category"]
            and item["role"] == verdict["role"], "semantic_grounded_source_or_type")
        if verdict["role"] == "value":
            a, b = item["start"], item["end"]
            require(type(a) is int and type(b) is int and 0 <= a <= candidate["start"] < candidate["end"] <= b <= len(sources[sid])
                and sources[sid][a:b] == item["quote"] == verdict["quote"], "semantic_completion_not_exact_cover")
        else:
            require(verdict["quote"] is None and item["quote"] is None and item["start"] == candidate["start"]
                and item["end"] == candidate["end"], "semantic_nonvalue_changed_span")


def ledger(events, rows, builds, stories, pools, records, paths):
    requests, terminals, groups = {}, {}, defaultdict(list)
    row_index = {(r["story_id"], r["task_id"], r["arm"]): r for r in rows}
    for event in events:
        base.no_secret_fields(event)
        index = integer(event["index"], "ledger_index")
        require(index > 0 and event["phase"] in {"request", "response", "failure"}, "ledger_phase")
        context = (event["stage"], event["arm"], event["story_id"], event["task_id"])
        stage, arm, sid, tid = context
        require(sid in stories and stage in {"build", "semantic", "union", "answer"}, "ledger_context")
        require((stage == "build" and arm == "reference" and tid is None) or
            (stage != "build" and (sid, tid, arm) in row_index and row_index[(sid, tid, arm)]["actor_id"] == "owner"),
            "unauthorized_or_unknown_model_context")
        require(stage != "union" or arm == "union", "union_stage_arm")
        require(stage != "semantic" or arm in SEMANTIC, "semantic_stage_arm")
        if event["phase"] == "request":
            require(index not in requests and index not in terminals, "duplicate_request")
            requests[index] = event
            groups[context].append(event)
            body = event["request"]
            require(set(body) == ({"model", "messages", "stream", "keep_alive", "options"} |
                (set() if stage == "answer" else {"format"})), "unregistered_request_fields")
            equal(digest(body), event["request_sha256"], "request_hash")
            wire = json.dumps(body, ensure_ascii=False).encode()
            equal(len(wire), event["wire_json_utf8_bytes"], "wire_bytes")
            equal(sha(wire), event["wire_json_utf8_sha256"], "wire_hash")
            equal(body["options"], {"num_ctx": 4096, "num_predict": 64 if stage == "answer" else 1024,
                "temperature": 0, "seed": 42}, "request_options")
            require(body["model"] == base.MODEL and body["stream"] is False and body["keep_alive"] == "30m", "request_model")
            require(event["scope"] == "synthetic_development_local_only" and "JSON body only" in event["wire_encoding"], "request_scope")
        else:
            require(index in requests and index not in terminals, "orphan_or_duplicate_terminal")
            request = requests[index]
            equal(context, tuple(request[k] for k in ("stage", "arm", "story_id", "task_id")), "terminal_context")
            equal(event["request_sha256"], request["request_sha256"], "terminal_request_hash")
            terminals[index] = event
            if event["phase"] == "response":
                response = event["response"]
                equal(digest(response), event["response_sha256"], "response_hash")
                prompt, output = response.get("prompt_eval_count"), response.get("eval_count")
                cap = request["request"]["options"]["num_predict"]
                require(type(prompt) is int and 0 < prompt <= 3072 and type(output) is int and 0 < output <= cap
                    and prompt + cap <= 4096 and event["actual_usage_within_budget"] is True, "actual_token_budget")
            else:
                equal(event["error"], "physical_transport_failed", "transport_failure_code")
    require(set(requests) == set(terminals) == set(range(1, len(requests)+1)) and len(requests) <= LIMITS["total"], "physical_request_cap")
    limits = {"build": 16, "semantic": 64, "answer": 160, "union": 224}
    counts = Counter(e["stage"] for e in requests.values())
    require(all(counts[k] <= v for k, v in limits.items()), "stage_generation_cap")
    for build in builds:
        sid = build["story_id"]
        selected = groups.get(("build", "reference", sid, None), [])
        equal(len(selected), build["generation_calls_observed"], "builder_physical_count")
        require(len(selected) <= 2, "builder_generation_cap")
        pool, story = pools[sid], stories[sid]
        candidates = [{"fid": c["fid"], "text": story["source"]["text"][c["start"]:c["end"]]} for c in pool["candidates"]]
        attempts = build["selection_attempts"]
        equal(len(attempts), len(selected), "selector_attempt_denominator")
        for n, (event, attempt) in enumerate(zip(selected, attempts)):
            body, messages = event["request"], event["request"]["messages"]
            equal(len(messages), 2+n, "selector_message_count")
            equal(messages[0], {"role": "system", "content": base._literal_assignment(paths["memory_migration_study/reference_memory.py"], "SYSTEM_PROMPT")}, "selector_prompt")
            equal(json.loads(messages[1]["content"]), {"purpose": base._literal_assignment(paths["memory_migration_study/reference_memory.py"], "PURPOSE"), "candidates": candidates}, "selector_input_not_runtime_only")
            enum = body["format"]["properties"]["selected_fids"]["items"]["enum"]
            equal(enum, [c["fid"] for c in candidates], "selector_enum")
            equal(body["format"], {"type": "object", "additionalProperties": False,
                "required": ["status", "selected_fids"], "properties": {
                    "status": {"type": "string", "enum": ["ok", "needs_review"]},
                    "selected_fids": {"type": "array", "maxItems": 8, "uniqueItems": True,
                        "items": {"type": "string", "enum": enum}}}}, "selector_schema")
            equal(attempt["attempt"], n+1, "selector_attempt_order")
            equal(attempt["request_sha256"], event["request_sha256"], "selector_attempt_hash")
            upper = len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode())+320+1024
            equal(attempt["input_budget_upper_bound"], upper, "selector_budget_receipt")
            require(upper <= 4096, "selector_preflight_budget")
            if n:
                equal(messages[2], {"role": "user", "content": base._literal_assignment(paths["memory_migration_study/reference_memory.py"], "REPAIR_PROMPT")}, "selector_repair")
        if build["status"] == "ok":
            require(selected and terminals[selected[-1]["index"]]["phase"] == "response", "successful_build_without_response")
            final_response = terminals[selected[-1]["index"]]["response"]
            successful_envelope(final_response)
            content = base.strict_json(final_response["message"]["content"])
            require(set(content) == {"status", "selected_fids"} and content["status"] == "ok", "selector_output_schema")
            by_id = {c["fid"]: c for c in pool["candidates"]}
            require(set(content["selected_fids"]) <= set(by_id) and len(content["selected_fids"]) == len(set(content["selected_fids"])), "selector_output_fids")
            equal(sorted(content["selected_fids"], key=lambda fid: by_id[fid]["start"]), build["selected_fids"], "raw_selection_changed")
    for row in rows:
        sid, tid, arm = row["story_id"], row["task_id"], row["arm"]
        task = next(t for t in stories[sid]["tasks"] if t["task_id"] == tid)
        answers = groups.get(("answer", arm, sid, tid), [])
        equal(len(answers), row["answer_calls"], "answer_physical_count")
        require(len(answers) <= 1 and (not answers or row["prepare_status"] == "ok"), "answer_without_preparation")
        if answers:
            body = answers[0]["request"]
            prompts = base._literal_assignment(paths["memory_migration_study/budget.py"], "MEMORY_PROMPTS")
            equal(body["messages"], [{"role": "system", "content": prompts["memory_fact_query_v2"]},
                {"role": "user", "content": json.dumps(row["outbound"], ensure_ascii=False, separators=(",", ":"))}], "answer_input_changed")
            equal(digest(row["outbound"]), row["actual_payload_sha256"], "outbound_hash")
            if row.get("answer_status") == "ok":
                terminal = terminals[answers[0]["index"]]
                require(terminal["phase"] == "response", "answer_success_without_response")
                successful_envelope(terminal["response"])
                equal(terminal["response"]["message"]["content"].strip(), row["model_answer"], "raw_answer_changed")
        prep = groups.get(("union", arm, sid, tid), []) + groups.get(("semantic", arm, sid, tid), [])
        equal(row["prepare_generation_calls_observed"], len(prep), "preparation_physical_calls")
        equal(row["inference_counts"]["local_generation"], len(groups.get(("union", arm, sid, tid), [])), "union_generation_count")
        equal(row["detector_calls"], sum(row["inference_counts"].values())+
            len(groups.get(("semantic", arm, sid, tid), [])), "detector_physical_count")
        for event in groups.get(("union", arm, sid, tid), []):
            body, policy = event["request"], base.normalized_policy(stories[sid]["policy"])
            messages = body["messages"]
            data = json.loads(messages[1]["content"])
            require(set(data) == {"text", "local_candidates"} and data["text"] in
                [task["query"]]+[r["text"] for r in records[sid]], "union_input_not_authorized_text")
            expected_system = base._literal_assignment(paths["memory_migration_study/local_detector.py"], "SYSTEM_PROMPT")+"\n\nTrusted sensitivity policy JSON:\n"+json.dumps(
                {k: policy[k] for k in ("version", "protected_categories", "instructions")}, ensure_ascii=False, separators=(",", ":"))
            equal(messages[0], {"role": "system", "content": expected_system}, "union_system_policy")
            require(all(set(c) == {"quote", "category"} and c["quote"] in data["text"] and c["category"] in policy["protected_categories"] for c in data["local_candidates"]), "union_rule_candidates")
            schema = {"type": "object", "additionalProperties": False, "required": ["status", "findings"],
                "properties": {"status": {"type": "string", "enum": ["ok", "needs_review"]},
                    "findings": {"type": "array", "maxItems": 32, "items": {
                        "type": "object", "additionalProperties": False, "required": ["quote", "category"],
                        "properties": {"quote": {"type": "string", "minLength": 1},
                            "category": {"type": "string", "enum": policy["protected_categories"]}}}}}}
            equal(body["format"], schema, "union_schema")
    for sid, story in stories.items():
        for task in story["tasks"]:
            shared = [e for e in requests.values() if e["stage"] == "semantic" and e["story_id"] == sid and e["task_id"] == task["task_id"]]
            require(len(shared) <= 2, "shared_semantic_recomputed_per_arm")
    return requests, terminals, groups


def union_cache_stats(rows):
    """Check the separately scoped cache deltas without assuming failed stores."""
    total = dict.fromkeys(("hits", "misses", "bypasses", "expired", "evictions", "stores"), 0)
    entries = defaultdict(int)
    for row in rows:
        cache = (row.get("prepare_metadata") or {}).get("detection_cache")
        if row["arm"] != "union":
            require(cache is None, "union_cache_shared_with_other_arm")
            continue
        if cache is None:
            require(row["prepare_status"] != "ok", "ready_union_without_cache_receipt")
            continue
        require(set(cache) == set(total) | {"entries"}, "union_cache_fields")
        for key in cache:
            integer(cache[key], "union_cache_nonnegative")
        observations = (row.get("detection") or {}).get("agent_observations", [])
        equal(cache["hits"]+cache["misses"]+cache["bypasses"], len(observations), "union_cache_source_attempts")
        require(cache["stores"] <= cache["misses"] and row["inference_counts"]["local_generation"] <=
            2*(cache["misses"]+cache["bypasses"]), "union_cache_claimed_savings")
        sid = row["story_id"]
        entries[sid] += cache["stores"]-cache["expired"]-cache["evictions"]
        equal(cache["entries"], entries[sid], "union_cache_entry_balance")
        for key in total:
            total[key] += cache[key]
    return {"observed_deltas": total, "final_entries_by_story": dict(entries),
            "scope": "Union-only host cache; failure results are not assumed to be stored."}


def auth_and_semantics(journal, rows, records, stories, groups, paths, terminals):
    protocol = base._literal_assignment(paths["scripts/run_policy_semantic_study.py"], "VERSION")
    require([e["sequence"] for e in journal] == list(range(1, len(journal)+1)), "auth_sequence")
    operations = defaultdict(list)
    closed = [e for e in journal if e["kind"] == "model_phase_closed"]
    require(len(closed) == 1 and closed[0] is journal[-1], "model_phase_closure_event")
    for event in journal:
        base.no_secret_fields(event)
        if event["kind"] != "model_phase_closed":
            require(event.get("operation") is not None, "auth_operation_missing")
            operations[event["operation"]].append(event)
    row_operations = {f"{r['story_id']}:{r['task_id']}:{r['arm']}": r for r in rows}
    require(set(operations) == set(row_operations), "auth_operation_matrix")
    shared, callback_count = {}, 0
    for operation, events in operations.items():
        row = row_operations[operation]
        sid, tid, arm = row["story_id"], row["task_id"], row["arm"]
        require(events[0]["kind"] == "prepare_start" and events[-1]["kind"] == "task_processing_end", "operation_event_bounds")
        start, end = events[0], events[-1]
        equal(start["record_ids"], [r["record_id"] for r in records[sid]], "auth_record_ids")
        equal(start["record_set_sha256"], digest(records[sid]), "auth_shared_record_hash")
        equal((start["story_id"], start["task_id"], start["arm"], start["actor_id"], start["agent_id"]),
            (sid, tid, arm, row["actor_id"], "target-agent"), "auth_principal_context")
        equal((end["prepare_status"], end["answer_calls"]), (row["prepare_status"], row["answer_calls"]), "auth_task_end")
        checks = [e for e in events if e["kind"] == "access_check"]
        require(all(e["actor_id"] == row["actor_id"] and e["agent_id"] == "target-agent" and
            e["record_id"] in start["record_ids"] for e in checks), "auth_check_principal")
        callbacks = [e for e in events if e["kind"] == "semantic_callback_start"]
        finishes = [e for e in events if e["kind"] == "semantic_callback_end"]
        require(len(callbacks) == len(finishes) <= 1, "semantic_callback_count")
        if row["actor_id"] != "owner":
            require(not callbacks and not row["answer_calls"] and row["inference_counts"] == dict.fromkeys(base.KINDS, 0), "outsider_model_or_callback")
            if records[sid]:
                require(checks and checks[0]["error"] == "principal_not_authorized", "outsider_not_real_authority_denial")
        if not records[sid]:
            require(not checks and not callbacks and row["prepare_error"] == "memory_build_unavailable", "failed_build_as_auth_denial")
        if arm not in SEMANTIC:
            require(not callbacks, "baseline_or_union_semantic_hook")
        if not callbacks:
            require(not groups.get(("semantic", arm, sid, tid)), "semantic_post_without_callback")
            continue
        callback_count += 1
        cb, finish = callbacks[0], finishes[0]
        require(arm in SEMANTIC and row["actor_id"] == "owner" and cb["sequence"] < finish["sequence"]
            and finish["callback_start_sequence"] == cb["sequence"], "semantic_callback_order")
        preceding = [e for e in checks if e["sequence"] < cb["sequence"]]
        require({e["record_id"] for e in preceding if e["error"] is None} == set(start["record_ids"])
            and all(e["error"] is None for e in preceding), "semantic_before_authorization")
        policy = base.normalized_policy(stories[sid]["policy"])
        task = next(t for t in stories[sid]["tasks"] if t["task_id"] == tid)
        payload = {"query": task["query"], "memories": [{"source_id": r["record_id"], "text": r["text"]} for r in records[sid]]}
        detection = row["detection"]
        equal(cb["payload_sha256"], digest(payload), "semantic_payload_binding")
        equal(cb["policy_sha256"], digest(policy), "semantic_policy_binding")
        equal(cb["baseline_sha256"], detection["baseline_detection_sha256"], "semantic_baseline_hash")
        equal(cb["mode"], arm, "semantic_mode")
        meta = detection.get("policy_semantics")
        require(isinstance(meta, dict), "semantic_metadata_missing")
        equal(finish["semantic_audit"], meta, "callback_audit_changed_after_return")
        source_texts_raw = {"__query__": task["query"], **{r["record_id"]: r["text"] for r in records[sid]}}
        baseline_spans = cb["baseline_spans"]
        equal(digest(baseline_spans), cb["baseline_spans_sha256"], "callback_baseline_span_hash")
        seeds = []
        for item in baseline_spans:
            require(set(item) == {"source_id", "start", "end", "category"}, "callback_baseline_span_fields")
            text = source_texts_raw[item["source_id"]]
            a, b = item["start"], item["end"]
            require(type(a) is int and type(b) is int and 0 <= a < b <= len(text)
                and item["category"] in policy["protected_categories"], "callback_baseline_span_location")
            seeds.append({**item, "quote": text[a:b]})
        seeds.sort(key=lambda r: (r["source_id"], r["start"], r["end"], r["category"]))
        equal(meta["baseline_spans_sha256"], digest(seeds), "semantic_baseline_spans_changed")
        equal(meta["cache_scope_sha256"], detection["cache_scope_sha256"], "semantic_scope_hash")
        receipt = meta["receipt"]
        equal(receipt["prompt_version"], base._literal_assignment(paths["memory_migration_study/policy_semantics.py"], "PROMPT_VERSION"), "semantic_prompt_version")
        equal(meta["receipt_sha256"], digest(receipt), "semantic_receipt_hash")
        equal(meta["payload_sha256"], digest(payload), "semantic_receipt_payload")
        equal(meta["full_policy_sha256"], digest(policy), "semantic_receipt_policy")
        equal(receipt["payload_sha256"], digest(payload), "semantic_agent_payload")
        equal(receipt["full_policy_sha256"], digest(policy), "semantic_agent_policy")
        equal(receipt["pool_sha256"], meta["pool_sha256"], "semantic_pool_hash")
        equal(receipt["local_counts"], meta["receipt_local_counts"], "semantic_receipt_count")
        calls = integer(receipt["local_calls"], "semantic_call_count")
        require(calls <= 2 and receipt["local_calls_complete"] is True and receipt["local_counts"] ==
            {"local_encoder": 0, "local_generation": calls, "unknown": 0}, "semantic_unknown_cost")
        selected_posts = groups.get(("semantic", arm, sid, tid), [])
        equal(finish["new_generation_attempts"], len(selected_posts), "callback_physical_calls")
        expected_added = {"local_encoder": 0, "local_generation": len(selected_posts), "unknown": 0}
        equal(finish["semantic_local_counts"], expected_added, "callback_costs")
        equal(detection["semantic_local_counts"], expected_added, "row_semantic_costs")
        equal(meta["stage_local_counts"], expected_added, "semantic_applied_costs")
        shared_key = (sid, tid, meta["cache_key_sha256"])
        if meta["cache_hit"]:
            require(shared_key in shared and shared[shared_key] == meta["receipt_sha256"] and not selected_posts,
                "semantic_cache_hit_without_prior_receipt")
            equal(meta["stage_observations"], [], "semantic_cache_recharged")
        else:
            require(shared_key not in shared, "semantic_receipt_recomputed")
            shared[shared_key] = meta["receipt_sha256"]
            equal(len(selected_posts), calls, "semantic_miss_call_count")
            equal(meta["stage_observations"], receipt["attempts"], "semantic_miss_observations")
        model_candidates = None
        for n, event in enumerate(selected_posts):
            body = event["request"]
            messages, data = body["messages"], json.loads(body["messages"][1]["content"])
            equal(len(messages), 2+n, "semantic_message_count")
            equal(messages[0], {"role": "system", "content": base._literal_assignment(paths["memory_migration_study/policy_semantics.py"], "SYSTEM_PROMPT")}, "semantic_system_prompt")
            require(set(data) == {"trusted_policy", "sources", "candidates"}, "semantic_input_fields")
            equal(data["trusted_policy"], {k: policy[k] for k in ("protected_categories", "instructions")}, "semantic_trusted_policy")
            expected_sources = [{"source": "S1", "text": task["query"]}]+[{"source": "S"+str(i+2), "text": r["text"]} for i, r in enumerate(records[sid])]
            equal(data["sources"], expected_sources, "semantic_input_not_current_sources")
            source_texts = {s["source"]: s["text"] for s in data["sources"]}
            cids = []
            for c in data["candidates"]:
                require(set(c) == {"cid", "source", "start", "end", "quote", "category"}
                    and isinstance(c["cid"], str) and re.fullmatch(r"C[0-9]{4}", c["cid"]), "semantic_candidate_fields")
                text, a, b = source_texts[c["source"]], c["start"], c["end"]
                require(type(a) is int and type(b) is int and 0 <= a < b <= len(text) and
                    text[a:b] == c["quote"] and c["category"] in {"PERSON", "ADDRESS", "CUSTOMER", "PROJECT"}, "semantic_candidate_location")
                cids.append(c["cid"])
            require(len(cids) == len(set(cids)) <= 16, "semantic_candidate_capacity")
            aliases = {s["source"]: original for s, original in zip(data["sources"], source_texts_raw)}
            actual_spans = {(aliases[c["source"]], c["start"], c["end"], c["category"]) for c in data["candidates"]}
            expected_spans = {(s["source_id"], s["start"], s["end"], s["category"]) for s in seeds
                              if s["category"] in {"PERSON", "ADDRESS", "CUSTOMER", "PROJECT"}}
            require(actual_spans == expected_spans, "semantic_candidates_not_current_baseline")
            model_candidates = data["candidates"]
            maximum = receipt["max_quote_chars"]
            require(type(maximum) is int and 1 <= maximum <= 256, "semantic_quote_capacity")
            equal(body["format"], expected_semantic_schema(paths["memory_migration_study/policy_semantics.py"],
                protocol, cids, maximum), "semantic_schema")
            equal(receipt["input_sha256"], sha(json.dumps({"messages": messages[:2], "format": body["format"]},
                ensure_ascii=False, separators=(",", ":"))), "semantic_input_schema_hash")
            upper = len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode())+320+1024
            require(upper <= 4096, "semantic_preflight_budget")
            attempt = receipt["attempts"][n]
            equal(attempt["attempt"], n+1, "semantic_attempt_order")
            equal(attempt["request_sha256"], sha(json.dumps(body, ensure_ascii=False, separators=(",", ":"))), "semantic_attempt_hash")
            equal(attempt["input_budget_upper_bound"], upper, "semantic_attempt_budget")
            terminal = terminals[event["index"]]
            if terminal["phase"] == "response" and attempt["prompt_eval_count"] is not None:
                equal(attempt["prompt_eval_count"], terminal["response"]["prompt_eval_count"], "semantic_usage_prompt")
                equal(attempt["eval_count"], terminal["response"]["eval_count"], "semantic_usage_output")
            if n:
                equal(messages[2], {"role": "user", "content": base._literal_assignment(paths["memory_migration_study/policy_semantics.py"], "REPAIR_PROMPT")}, "semantic_repair_prompt")
        if not meta["cache_hit"] and receipt["status"] == "semantics_only" and calls:
            response = terminals[selected_posts[-1]["index"]]
            require(response["phase"] == "response", "semantic_success_without_response")
            successful_envelope(response["response"])
            raw = base.strict_json(response["response"]["message"]["content"])
            verify_grounded_verdicts(raw, receipt, model_candidates, aliases, source_texts_raw)
    require(len({(sid, tid) for sid, tid, _ in shared}) <= 32, "semantic_shared_denominator")
    return callback_count, closed[0]


def verify(directory, *, corpus=None, project_root=None):
    run, root = Path(directory).resolve(), Path(project_root or ROOT).resolve()
    names = ("plan", "runtime", "evaluation", "config", "runtime_identity", "pools", "builds", "record_store", "rows", "report", "transport_audit", "network_audit", "auth_events")
    values = {n: json.loads((run / (n+".json")).read_bytes()) for n in names}
    for value in values.values():
        base.no_secret_fields(value)
    plan, runtime, gold, config = (values[n] for n in ("plan", "runtime", "evaluation", "config"))
    rows, builds, stores, report = (values[n] for n in ("rows", "builds", "record_store", "report"))
    require(plan["version"] in VERSIONS and plan["score_schema_version"] == 2 and plan["split"] == "development"
        and plan["expected_rows"] == 200 and plan["legal_per_arm"] == 32 and plan["outsider_per_arm"] == 8
        and plan["evaluation_timing"] == "after_model_phase_closed" and plan["query_intent"] is False
        and plan["ordering_seed"] == 2026102509, "registered_protocol")
    equal(plan["arms"], {a: ["reference", "migration", False] for a in ARMS}, "arm_protocol")
    equal(plan["generation_limits"], LIMITS, "generation_limits")
    require(len(runtime) == 8 and len({s["story_id"] for s in runtime}) == 8, "story_denominator")
    stories = {s["story_id"]: s for s in runtime}
    require(set(stories) == set(gold), "gold_story_matrix")
    for story in runtime:
        require(len(story["tasks"]) == 5 and len({t["task_id"] for t in story["tasks"]}) == 5 and
            Counter(t["actor_id"] for t in story["tasks"]) == {"owner": 4, "outsider": 1}, "task_denominator")
    corpus = Path(corpus or root / "examples/privacy_semantics_v1")
    for name, snapshot in (("runtime", runtime), ("evaluation", gold)):
        raw = (corpus / "development" / (name+".json")).read_bytes()
        equal(sha(raw), plan[name+"_sha256"], "original_input_hash")
        equal(json.loads(raw), snapshot, "input_snapshot_changed")
    equal(digest(config), plan["config_sha256"], "configuration_hash")
    require(config["endpoint"] == "http://127.0.0.1:11435" and config["model"] == base.MODEL and
        config["expected_digest"] == base.MODEL_DIGEST and config["expected_version"] == "0.40.8", "local_model_config")
    paths, current_identical = archive(run, plan, root)
    equal(values["runtime_identity"]["local_generation"], {"version": "0.40.8", "model": base.MODEL,
        "digest": base.MODEL_DIGEST, "endpoint": "http://127.0.0.1:11435"}, "model_identity")
    pools = {p["story_id"]: p["pool"] for p in values["pools"]}
    records = {s["story_id"]: s["records"] for s in stores}
    by_build = {b["story_id"]: b for b in builds}
    require(len(builds) == len(stores) == len(values["pools"]) == 8 and set(pools) == set(records) == set(by_build) == set(stories), "shared_build_denominator")
    require(sum(len(p["candidates"]) for p in pools.values()) <= 20, "union_worst_case_bound_not_supported")
    for sid, story in stories.items():
        equal(by_build[sid]["builder"], "reference", "shared_builder_kind")
        base.verify_pool(story, pools[sid])
        verify_records(story, by_build[sid], records[sid], pools[sid])
        require(by_build[sid]["inference_counts"]["unknown"] == 0 and by_build[sid]["inference_counts"]["local_generation"] == 0, "build_unknown_detector_cost")
    expected = {(sid, t["task_id"], a) for sid, s in stories.items() for t in s["tasks"] for a in ARMS}
    require(len(rows) == 200 and {(r["story_id"], r["task_id"], r["arm"]) for r in rows} == expected, "task_matrix_denominator")
    for row in rows:
        sid = row["story_id"]
        story, build = stories[sid], by_build[sid]
        task = next(t for t in story["tasks"] if t["task_id"] == row["task_id"])
        equal((row["actor_id"], row["language"], row["template_family"]), (task["actor_id"], story["language"], story["template_family"]), "row_runtime_binding")
        require(row["mode"] == "migration" and row["intent_applied"] is False and row["secondary_serialization_registered"] is True
            and row["privacy_pipeline"] == ("semantic" if row["arm"] in SEMANTIC else "legacy"), "row_arm_protocol")
        equal(row["build_status"], build["status"], "row_shared_build_status")
        for value in row["inference_counts"].values():
            integer(value, "row_inference_count")
        require(set(row["inference_counts"]) == set(base.KINDS), "row_inference_kinds")
        equal(row["inference_counts"]["unknown"], 0, "unknown_cost")
        mask = base.independent_masking(story, task, gold[sid], records[sid], row["outbound"], False) if row["prepare_status"] == "ok" else base.blocked_masking(story, gold[sid], records[sid])
        equal(mask, row["masking"], "independent_masking_mismatch")
        value = gold[sid]["answers"].get(row["task_id"])
        equal(row["required_fact_retained"], bool(value and any(value in r["text"] for r in records[sid])), "fact_retention")
        base._verify_secondary(row)
        equal(row["score"], base.independent_score(row, gold[sid]), "independent_score_mismatch")
    events = [json.loads(line) for line in (run / "request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    requests, terminals, groups = ledger(events, rows, builds, stories, pools, records, paths)
    callbacks, closure = auth_and_semantics(values["auth_events"], rows, records, stories, groups, paths, terminals)
    union_cache = union_cache_stats(rows)
    equal(closure["actual_generation_attempts"], len(requests), "closure_call_count")
    equal(report["arms"], aggregate(rows, builds), "independent_aggregate_mismatch")
    stages = Counter(e["stage"] for e in requests.values())
    totals = {"version": plan["version"], "registered_rows": 200, "recorded_rows": 200, "source_stories": 8,
        "generation_calls_observed": len(requests), "builder_generations": stages["build"],
        "semantic_shared_generations": stages["semantic"], "union_detection_generations": stages["union"],
        "answer_generations": stages["answer"], "build_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds),
        "total_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds)+sum(r["inference_counts"]["local_encoder"] for r in rows),
        "request_wire_json_bytes": sum(e["wire_json_utf8_bytes"] for e in requests.values()),
        "detector_call_accounting_complete": True, "implementation_unchanged": True,
        "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0}
    for key, value in totals.items():
        equal(report[key], value, "report_total_"+key)
    equal(report["scope"], plan["scope"], "scope_changed")
    audit, network = values["transport_audit"], values["network_audit"]
    responses = [e for e in terminals.values() if e["phase"] == "response"]
    require(audit["completed"] is True and audit["registered_protocol"] == plan["version"] and audit["recovery_mapping_recorded"] is False, "transport_completion")
    for key, value in {"physical_generation_attempts": len(requests), "responses": len(responses), "transport_errors": len(terminals)-len(responses),
        "actual_token_budget_violations": 0, "registered_generation_cap": 464, "cloud_calls": 0, "new_api_cost_cny": 0, "closed_phase_attempts": 0}.items():
        equal(audit[key], value, "transport_total_"+key)
    equal(audit["network"], network, "network_summary")
    require(network["external_attempts_blocked"] == 0 and type(network["loopback_connections"]) is int and network["loopback_connections"] >= 0, "external_network")
    costs = defaultdict(lambda: {"physical_calls": 0, "prompt_tokens": 0, "output_tokens": 0, "request_json_utf8_bytes": 0})
    for index, event in requests.items():
        cell = costs[(event["stage"], event["arm"])]
        cell["physical_calls"] += 1
        cell["request_json_utf8_bytes"] += event["wire_json_utf8_bytes"]
        if terminals[index]["phase"] == "response":
            cell["prompt_tokens"] += terminals[index]["response"]["prompt_eval_count"]
            cell["output_tokens"] += terminals[index]["response"]["eval_count"]
    return {"version": "independent_policy_semantic_study_verifier_v2", "study_version": plan["version"],
        "status": "passed", "registered_rows": 200, "current_snapshot_identical": current_identical,
        "shared_builds": 8, "legal_per_arm": 32, "outsider_per_arm": 8, "callbacks_checked": callbacks,
        "physical_generation_attempts": len(requests), "physical_costs_by_stage_and_observed_arm":
            [{"stage": stage, "first_observed_arm": arm, **v} for (stage, arm), v in sorted(costs.items())],
        "arms": aggregate(rows, builds), "verification_model_calls": 0,
        "union_detection_cache": union_cache,
        "evidence_sha256": {n+".json": sha((run / (n+".json")).read_bytes()) for n in names},
        "transport_sha256": sha((run / "request_transport.jsonl").read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()),
        "limits": ["Passing is evidence consistency, not a predefined effectiveness threshold or publication novelty.",
            "Archived hashes/inventory remain mandatory; current source drift is reported separately from the frozen run's end-of-execution checks.",
            "Public hashes/signature shapes do not authenticate destroyed HMAC keys or reconstruct private recovery maps.",
            "Receipt sharing is a physical DAG; per-observed-arm costs are not independent deployment costs.",
            "Authorization order is checked in archived real-super logger control flow and globally ordered events.",
            "Registered literal alignment does not establish semantic privacy or discovery of unregistered secrets."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "new_receipt_path_required")
    result = verify(args.directory, corpus=args.corpus)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "physical_generation_attempts": result["physical_generation_attempts"]}))


if __name__ == "__main__":
    main()
