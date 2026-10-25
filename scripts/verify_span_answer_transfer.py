"""Offline independent evidence audit for the 144-cell span-answer study.

No production scorer, pointer resolver, table reconstruction, model or signing
key is used. Public source/view checks cannot authenticate destroyed HMAC keys.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import verify_reference_memory_study as base
from scripts import verify_policy_semantic_study as shared
from scripts import verify_generation_union_transfer as generation
from scripts.analyze_boundary_transfer_mechanisms import locate, normalized_payload

VERSION = "span_answer_transfer_development_v1"
ARMS = ("free", "free_indexed", "span_pointer")
CONTROL = "missing_contact_email_control"
QUERIES = {"en": "What is the contact email address?", "zh": "联系人的电子邮箱地址是什么？"}
LIMITS = {"total": 264, "build": 16, "write_annotation": 128, "answer": 120}
ALIAS = re.compile(r"E_[A-F0-9]{32}\Z")
BARE = re.compile(r"PVT_[A-F0-9]{24}_(?:PERSON|ADDRESS|CUSTOMER|PROJECT|EMAIL|PHONE|ID|AMOUNT|DATE|MIXED)_[1-9][0-9]*\Z")
digest, sha, require, equal, integer = base.digest, base.sha, base.require, base.equal, base.integer


def no_private_objects(value):
    base.no_secret_fields(value)
    if isinstance(value, dict):
        require(not {"table", "evidence_table", "_key", "_seal", "_entries", "_scope"}.intersection(value), "serialized_private_table")
        for child in value.values():
            no_private_objects(child)
    elif isinstance(value, list):
        for child in value:
            no_private_objects(child)


def strict_pointer(raw):
    require(isinstance(raw, str) and len(raw.encode()) <= 4096, "invalid_pointer_json")
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_pointer_key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("invalid_pointer_constant")
    data = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    require(isinstance(data, dict), "invalid_pointer_schema")
    if set(data) == {"decision"} and data["decision"] == "UNKNOWN":
        return data
    require(set(data) == {"decision", "source", "start_token", "end_token"} and data["decision"] == "SPAN"
        and isinstance(data["source"], str) and ALIAS.fullmatch(data["source"])
        and type(data["start_token"]) is int and type(data["end_token"]) is int, "invalid_pointer_schema")
    return data


def schema_for(view):
    branches = [{"type": "object", "additionalProperties": False, "required": ["decision"],
        "properties": {"decision": {"type": "string", "enum": ["UNKNOWN"]}}}]
    selectable = [s for s in view["sources"] if s["tokens"]]
    if selectable:
        maximum = max(len(s["tokens"]) for s in selectable)-1
        branches.append({"type": "object", "additionalProperties": False,
            "required": ["decision", "source", "start_token", "end_token"], "properties": {
                "decision": {"type": "string", "enum": ["SPAN"]},
                "source": {"type": "string", "enum": [s["source"] for s in selectable]},
                "start_token": {"type": "integer", "minimum": 0, "maximum": maximum},
                "end_token": {"type": "integer", "minimum": 0, "maximum": maximum}}})
    return {"anyOf": branches}


def verify_view(context, policy):
    payload, view = context["payload"], context["view"]
    require(set(payload) == {"query", "memories"} and set(view) == {"sources"}
        and len(view["sources"]) == len(payload["memories"]), "view_source_count")
    packed, aliases, total = [], set(), 0
    for source, memory in zip(view["sources"], payload["memories"]):
        require(set(source) == {"source", "tokens"} and isinstance(source["source"], str)
            and ALIAS.fullmatch(source["source"]) and source["source"] not in aliases, "view_source_alias")
        aliases.add(source["source"])
        cursor, wire, boundaries = 0, [], []
        for i, token in enumerate(source["tokens"]):
            require(set(token) == {"index", "start", "end", "text"} and type(token["index"]) is int and token["index"] == i
                and type(token["start"]) is int and type(token["end"]) is int and token["start"] == cursor
                and cursor < token["end"] <= len(memory["text"]) and token["text"] == memory["text"][cursor:token["end"]], "view_token_binding")
            boundaries.append((cursor, token["end"]))
            cursor = token["end"]
            wire.append([i, token["text"]])
        require(cursor == len(memory["text"]), "view_dropped_source_text")
        for token in base.TOKEN.finditer(memory["text"]):
            require(token.span() in boundaries, "view_split_private_token")
        total += len(boundaries)
        packed.append({"source": source["source"], "tokens": wire})
    equal(context["response_schema"], schema_for(view), "closed_pointer_schema")
    meta, normalized = context["view_metadata"], base.normalized_policy(policy)
    equal(meta["payload_sha256"], digest(payload), "view_payload_hash")
    equal(meta["query_sha256"], sha(payload["query"]), "view_query_hash")
    equal(meta["policy_sha256"], digest({"full_input": policy, "normalized": normalized}), "view_full_policy_hash")
    hashes = sorted((m["source_id"], sha(m["text"])) for m in payload["memories"])
    equal(meta["source_hashes_sha256"], digest(hashes), "view_source_hashes")
    equal(meta["view_sha256"], digest(view), "view_hash")
    equal((meta["source_count"], meta["token_count"], meta["total_characters"]),
        (len(view["sources"]), total, len(payload["query"])+sum(len(m["text"]) for m in payload["memories"])), "view_counts")
    limits = meta["limits"]
    require(len(view["sources"]) <= limits["max_sources"] and total <= limits["max_total_tokens"]
        and meta["total_characters"] <= limits["max_total_chars"] and
        all(len(s["tokens"]) <= limits["max_tokens_per_source"] for s in view["sources"]), "view_limits")
    return {"sources": packed}


def archive(run, plan, root):
    paths, identical = {}, True
    for name, expected in plan["implementation_sha256"].items():
        relative = Path(name.replace("\\", "/"))
        require(not relative.is_absolute() and ".." not in relative.parts and relative.suffix == ".py", "unsafe_archive_path")
        saved, current = (run/"implementation"/relative).resolve(), (root/relative).resolve()
        require(saved.is_relative_to((run/"implementation").resolve()) and current.is_relative_to(root)
            and sha(saved.read_bytes()) == expected, "archive_hash_changed")
        identical = identical and current.is_file() and sha(current.read_bytes()) == expected
        paths[relative.as_posix()] = saved
    require({p.relative_to(run/"implementation").as_posix() for p in (run/"implementation").rglob("*.py")} == set(paths), "archive_inventory")
    needed = {"scripts/run_span_answer_transfer.py", "scripts/run_generation_union_transfer.py", "scripts/run_policy_semantic_study.py",
        "scripts/run_reference_memory_study.py", "scripts/run_boundary_transfer_diagnostic.py", "memory_migration_study/span_answerer.py",
        "memory_migration_study/span_answer_evidence.py", "memory_migration_study/reference_memory.py", "memory_migration_study/local_detector.py", "memory_migration_study/budget.py"}
    require(needed <= set(paths), "archive_missing_dependency")
    identical = identical and {"memory_migration_study/"+p.name for p in (root/"memory_migration_study").glob("*.py")} == {p for p in paths if p.startswith("memory_migration_study/")}
    driver = paths["scripts/run_span_answer_transfer.py"]
    equal(base._literal_assignment(driver, "VERSION"), VERSION, "archived_version")
    tree = ast.parse(driver.read_text(encoding="utf-8-sig"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    loops = [n for n in fn.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "story"]
    closes = [n for n in fn.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "model_phase_closed" for t in n.targets)]
    parses = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "loads"
        and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "evaluation_bytes"]
    require(len(loops) == len(closes) == len(parses) == 1 and loops[0].end_lineno < closes[0].lineno < parses[0].lineno
        and isinstance(closes[0].value, ast.Constant) and closes[0].value.value is True, "evaluation_before_model_closure")
    calls = Counter(n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name))
    require(calls["prepare_labeled_transfer"] == calls["build_span_evidence"] == 1, "shared_preparation_not_single_callsite")
    answer_calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Subscript)
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "answerers"]
    current_calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_current_access"]
    resolve_calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "resolve_span_evidence"]
    require(len(answer_calls) == len(resolve_calls) == 1 and len(current_calls) == 2 and
        current_calls[0].lineno < answer_calls[0].lineno < current_calls[1].lineno < resolve_calls[0].lineno
        and any(k.arg == "evidence_table" for k in answer_calls[0].keywords), "archived_answer_auth_order")
    authority_tree = ast.parse(paths["scripts/run_policy_semantic_study.py"].read_text(encoding="utf-8-sig"))
    authority = next(n for n in authority_tree.body if isinstance(n, ast.ClassDef) and n.name == "AuditedAuthority")
    validator = next(n for n in authority.body if isinstance(n, ast.FunctionDef) and n.name == "validate_access")
    real = [n for n in ast.walk(validator) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "validate_access" and isinstance(n.func.value, ast.Call)
        and isinstance(n.func.value.func, ast.Name) and n.func.value.func.id == "super"]
    logged = [n for n in ast.walk(validator) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "event"]
    require(len(real) == len(logged) == 1 and real[0].lineno < logged[0].lineno, "authority_logger_not_real_super")
    helper_tree = ast.parse(paths["memory_migration_study/span_answerer.py"].read_text(encoding="utf-8-sig"))
    helper = next(n for n in helper_tree.body if isinstance(n, ast.ClassDef) and n.name == "LocalSpanFactAnswerer")
    method = next(n for n in helper.body if isinstance(n, ast.FunctionDef) and n.name == "__call__")
    binds = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "validate_span_view_binding"]
    posts = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "transport"]
    require(len(binds) == len(posts) == 1 and binds[0].lineno < posts[0].lineno, "table_view_binding_after_post")
    return paths, bool(identical)


def task_map(stories):
    tasks = {}
    for sid, story in stories.items():
        for task in story["tasks"]:
            tasks[(sid, task["task_id"])] = {**task, "task_class": "legal" if task["actor_id"] == "owner" else "outsider"}
        tasks[(sid, CONTROL)] = {"task_id": CONTROL, "actor_id": "owner", "query": QUERIES[story["language"]], "task_class": "missing"}
    return tasks


def ledger(events, stories, tasks):
    requests, terminals = {}, {}
    for event in events:
        no_private_objects(event)
        index = integer(event["index"], "ledger_index")
        stage, arm, sid, tid = (event[k] for k in ("stage", "arm", "story_id", "task_id"))
        require(index > 0 and sid in stories and stage in {"build", "write_annotation", "answer"}, "ledger_stage")
        require((stage == "build" and arm == "common" and tid is None) or
            (stage == "write_annotation" and arm == "union_labels" and tid is None) or
            (stage == "answer" and arm in ARMS and (sid, tid) in tasks and tasks[(sid, tid)]["actor_id"] == "owner"), "ledger_model_context")
        if event["phase"] == "request":
            require(index not in requests, "duplicate_request")
            requests[index] = event
            body = event["request"]
            equal(digest(body), event["request_sha256"], "request_hash")
            wire = json.dumps(body, ensure_ascii=False).encode()
            equal((len(wire), sha(wire)), (event["wire_json_utf8_bytes"], event["wire_json_utf8_sha256"]), "wire_integrity")
            pointer = stage == "answer" and arm == "span_pointer"
            require(set(body) == {"model", "messages", "stream", "keep_alive", "options"} | ({"format"} if stage != "answer" or pointer else set()), "request_extra_fields")
            equal(body["options"], {"num_ctx": 4096, "num_predict": 64 if stage == "answer" else 1024, "temperature": 0, "seed": 42}, "request_options")
            require(body["model"] == base.MODEL and body["stream"] is False and body["keep_alive"] == "30m"
                and event["scope"] == "synthetic_development_local_only" and "JSON body only" in event["wire_encoding"], "local_request_contract")
        else:
            require(event["phase"] in {"response", "failure"} and index in requests and index not in terminals, "orphan_terminal")
            original = requests[index]
            for field in ("stage", "arm", "story_id", "task_id", "request_sha256"):
                equal(event[field], original[field], "terminal_context")
            if stage == "write_annotation":
                for field in ("fact_index", "fid", "fact_key"):
                    equal(event[field], original[field], "annotation_terminal_context")
            terminals[index] = event
            if event["phase"] == "response":
                response = event["response"]
                equal(digest(response), event["response_sha256"], "response_hash")
                prompt, output, cap = response.get("prompt_eval_count"), response.get("eval_count"), original["request"]["options"]["num_predict"]
                require(type(prompt) is int and 0 < prompt <= 3072 and type(output) is int and 0 < output <= cap
                    and prompt+cap <= 4096 and event["actual_usage_within_budget"] is True, "actual_usage_budget")
            else:
                equal(event["error"], "physical_transport_failed", "transport_error_code")
    require(set(requests) == set(terminals) == set(range(1, len(requests)+1)) and len(requests) <= 264, "physical_request_denominator")
    counts = Counter(e["stage"] for e in requests.values())
    require(all(counts[k] <= v for k, v in LIMITS.items() if k != "total"), "stage_post_cap")
    return requests, terminals


def constructions(values, stories, paths, requests, terminals):
    builds, raw_pools, stores, annotations = (values[n] for n in ("builds", "pools", "record_store", "annotations"))
    by_build, pools, records = {b["story_id"]: b for b in builds}, {p["story_id"]: p["pool"] for p in raw_pools}, {s["story_id"]: s["records"] for s in stores}
    require(len(builds) == len(raw_pools) == len(stores) == 8 and set(by_build) == set(pools) == set(records) == set(stories), "construction_matrix")
    labels = {(a["story_id"], a["fact_index"]): a for a in annotations}
    wanted = {(sid, i) for sid, b in by_build.items() if b["status"] == "ok" for i in range(len(b["facts"]))}
    require(len(labels) == len(annotations) and set(labels) == wanted, "annotation_matrix")
    used = set()
    for sid, story in stories.items():
        base.verify_pool(story, pools[sid])
        build = by_build[sid]
        require(len(build["facts"]) <= 8, "selected_fact_limit")
        eligible = build["status"] == "ok" and bool(build["facts"]) and all(labels[(sid, i)]["status"] == "ok" for i in range(len(build["facts"])))
        group_status = "ok" if eligible else "needs_review" if build["status"] == "ok" else "not_run"
        store = next(s for s in stores if s["story_id"] == sid)
        require(store["builder"] == "union" and store["union_label_set_status"] == group_status and bool(records[sid]) == eligible, "failed_annotation_deployed")
        policy, replacement = base.normalized_policy(story["policy"]), []
        for i, fact in enumerate(build["facts"] if build["status"] == "ok" else []):
            annotation = labels[(sid, i)]
            identity = {"source_id": story["source"]["source_id"], "source_sha256": sha(story["source"]["text"]),
                "source_start": fact["source_start"], "source_end": fact["source_end"], "content_sha256": sha(fact["text"])}
            equal({k: annotation[k] for k in identity}, identity, "annotation_exact_source")
            equal(annotation["fact_key"], digest(identity), "annotation_fact_key")
            equal(annotation["fid"], fact["fid"], "annotation_fid")
            aid = "write_"+digest(identity)[:32]
            payload = {"query": "", "memories": [{"source_id": aid, "text": fact["text"]}]}
            equal((annotation["annotation_source_id"], annotation["input_payload"]), (aid, payload), "annotation_input")
            detection = annotation["detection"]
            equal((detection["payload_sha256"], detection["policy_sha256"]), (digest(payload), digest(policy)), "annotation_detection_binding")
            selected = annotation["request_indices"]
            require(len(selected) <= 2 and len(selected) == len(set(selected)) and not used.intersection(selected), "annotation_call_allocation")
            used.update(selected)
            equal(annotation["generation_calls_observed"], len(selected), "annotation_generation_count")
            equal(annotation["inference_counts"]["local_generation"], len(selected), "annotation_typed_generations")
            equal(annotation["inference_counts"]["unknown"], 0, "annotation_unknown_cost")
            seeds, encoders = [], 0
            for member in annotation["member_raw_outputs"]:
                equal((member["source_id"], member["text_sha256"], member["policy_sha256"]), (aid, sha(fact["text"]), digest(policy)), "annotation_actual_ner_input")
                response = member["response"]
                encoders += integer(response["local_calls"], "annotation_encoder_count")
                for f in response["findings"]:
                    require(set(f) == {"start", "end", "quote", "category"} and type(f["start"]) is int and type(f["end"]) is int
                        and 0 <= f["start"] < f["end"] <= len(fact["text"]) and f["quote"] == fact["text"][f["start"]:f["end"]]
                        and f["category"] in policy["protected_categories"], "annotation_ner_span")
                    seeds.append((aid, f["start"], f["end"], f["category"]))
            equal(annotation["inference_counts"]["local_encoder"], encoders, "annotation_actual_encoders")
            equal(detection["local_calls"], encoders+len(selected), "annotation_total_calls")
            for n, index in enumerate(selected):
                event = requests[index]
                equal(tuple(event[k] for k in ("stage", "arm", "story_id", "fact_index", "fid", "fact_key")),
                    ("write_annotation", "union_labels", sid, i, fact["fid"], digest(identity)), "annotation_call_context")
                generation.detection_input(event, fact["text"], story["policy"], paths)
                equal(len(event["request"]["messages"]), 2+n, "annotation_attempt_order")
            if annotation["status"] == "ok":
                require(detection["status"] == "ok" and detection["errors"] == [] and detection["local_calls_complete"] is True
                    and all(m["response"]["status"] == "ok" for m in annotation["member_raw_outputs"]), "dirty_annotation_accepted")
                if selected:
                    terminal = terminals[selected[-1]]
                    require(terminal["phase"] == "response", "annotation_no_response")
                    shared.successful_envelope(terminal["response"])
                    raw = base.strict_json(terminal["response"]["message"]["content"])
                    require(set(raw) == {"status", "findings"} and raw["status"] == "ok", "annotation_raw_review")
                    for f in raw["findings"]:
                        require(set(f) == {"quote", "category"} and f["category"] in policy["protected_categories"], "annotation_raw_fields")
                        quote = locate(f["quote"], fact["text"])
                        starts = [m.start() for m in re.finditer("(?="+re.escape(quote)+")", fact["text"])]
                        require(starts, "annotation_raw_quote_missing")
                        seeds.extend((aid, a, a+len(quote), f["category"]) for a in starts)
                generation.verify_coverage(detection, {"__query__": "", aid: fact["text"]}, seeds, policy)
            equal((annotation["eligible_for_store"], annotation["group_status"]), (eligible, group_status), "annotation_deployment_state")
            replacement.append(dict(fact, findings=[{k: f[k] for k in ("start", "end", "category")} for f in detection["findings"]], status="ok"))
        adapted = dict(build, builder="reference", facts=replacement if eligible else [], status="ok" if eligible else "needs_review")
        shared.verify_records(story, adapted, records[sid], pools[sid])
        for record in records[sid]:
            equal(record["label"]["detector_version"], values["runtime_identity"]["union_detector_revision"], "signed_union_revision")
    require(used == {i for i, e in requests.items() if e["stage"] == "write_annotation"}, "unallocated_annotation_post")
    projected, seq = [], 1
    for i, event in requests.items():
        if event["stage"] == "build":
            projected += [dict(event, index=seq, arm="reference_id"), dict(terminals[i], index=seq, arm="reference_id")]
            seq += 1
    base._ledger(projected, [], [dict(b, builder="reference_id") for b in builds], stories, pools, paths)
    return by_build, records


def token_values(original, masked, selected):
    """Independent literal-anchor reconstruction; no saved restoration map."""
    matches, literals = list(base.TOKEN.finditer(masked)), base.TOKEN.split(masked)
    require(len(matches) <= 32 and original.startswith(literals[0]), "restoration_literal_alignment")
    work = [0]
    @lru_cache(None)
    def walk(index, cursor):
        work[0] += 1
        require(work[0] <= 10000, "restoration_alignment_budget")
        if index == len(matches):
            return frozenset({None}) if cursor == len(original) else frozenset()
        following = literals[index+1]
        candidates = ([len(original)-len(following)] if index == len(matches)-1 and original.endswith(following) else
            [m.start() for m in re.finditer("(?="+re.escape(following)+")", original)] if following else range(cursor+1, len(original)+1))
        values = set()
        for end in candidates:
            if end <= cursor or not original.startswith(following, end):
                continue
            tails = walk(index+1, end+len(following))
            if not tails:
                continue
            if matches[index].group() == selected:
                values.add(original[cursor:end])
            else:
                values.update(tails)
        return frozenset(values)
    return set(walk(0, len(literals[0])))-{None}


def check_restore(answer, status, final, context, records):
    if status == "blocked":
        require(final is None, "blocked_restore_disclosed")
        return
    require(status == "ok" and isinstance(answer, str) and isinstance(final, str), "invalid_restoration_state")
    value = answer.strip()
    if value == "UNKNOWN":
        equal(final, "UNKNOWN", "unknown_rewritten")
    elif base.TOKEN.fullmatch(value):
        options = set()
        for record, memory in zip(records, context["payload"]["memories"]):
            if value in {m.group() for m in base.TOKEN.finditer(memory["text"])}:
                options |= token_values(record["text"], memory["text"], value)
        require(options and final in options, "restored_token_without_source_value")
    else:
        require("PVT_" not in value and any(value in memory["text"] for memory in context["payload"]["memories"]), "literal_without_memory_evidence")
        equal(final, value, "literal_answer_rewritten")


def assess(row, task, gold):
    """Compute references from runtime/control class, independently of flags."""
    authorized, pointer = task["actor_id"] == "owner", row["arm"] == "span_pointer"
    reference = "UNKNOWN" if task["task_class"] == "missing" else gold["answers"].get(task["task_id"], "")
    final = row.get("final_answer")
    match = authorized and isinstance(final, str) and final.strip().casefold() == reference.casefold()
    accepted_abstention = (row.get("resolver_status") == "ok" and row.get("pointer_decision") == "UNKNOWN" if pointer else
        row["answer_status"] == "ok" and isinstance(row.get("model_answer"), str) and row["model_answer"].strip() == "UNKNOWN")
    correct = bool(match and (task["task_class"] != "missing" or accepted_abstention))
    mask = row["masking"]
    no_gap = mask["ready"] is True and mask["partial"] == mask["unmasked"] == 0
    second = (row.get("secondary_serialization") or {}).get("final_answer")
    second_correct = bool(authorized and isinstance(second, str) and second.strip().casefold() == reference.casefold())
    return {"authorized": authorized, "correct": correct, "joint_correct_no_masking_gap": bool(correct and no_gap),
        "model_chose_unknown": bool(accepted_abstention),
        "unknown_with_required_fact": bool(task["task_class"] == "legal" and row["required_fact_retained"] and accepted_abstention),
        "secondary_correct": None if pointer else second_correct,
        "secondary_joint_correct_no_masking_gap": None if pointer else bool(second_correct and no_gap),
        "outsider_blocked": task["task_class"] == "outsider" and row.get("prepare_error") == "principal_not_authorized" and row["answer_calls"] == 0,
        "unauthorized_output": bool(not authorized and (row["answer_calls"] > 0 or final)),
        "restoration_failure": row.get("restoration_status") == "blocked"}


def aggregate(rows):
    out = {}
    for arm in ARMS:
        out[arm] = {}
        for kind in ("legal", "missing", "outsider"):
            group = [r for r in rows if r["arm"] == arm and r["task_class"] == kind]
            cell = {"registered_tasks": len(group), **{name: sum(r["score"][name] for r in group) for name in
                ("correct", "joint_correct_no_masking_gap", "model_chose_unknown", "unknown_with_required_fact", "outsider_blocked", "unauthorized_output", "restoration_failure")},
                "secondary_correct": None if arm == "span_pointer" else sum(r["score"]["secondary_correct"] for r in group),
                "answer_calls": sum(r["answer_calls"] for r in group), "label_set_unavailable": sum(r["union_label_set_status"] != "ok" for r in group),
                "prepare_blocked": sum(r["prepare_status"] != "ok" for r in group),
                "view_blocked": sum(r["prepare_status"] == "ok" and r["view_status"] != "ok" and arm != "free" for r in group),
                "resolver_blocked": sum(r["resolver_status"] == "blocked" for r in group),
                "by_language": {lang: {"tasks": sum(r["language"] == lang for r in group), "correct": sum(r["language"] == lang and r["score"]["correct"] for r in group)} for lang in ("en", "zh")}}
            out[arm][kind] = cell
    return out


def verify(directory, *, corpus=None, project_root=None):
    run, root = Path(directory).resolve(), Path(project_root or ROOT).resolve()
    names = ("plan", "runtime", "evaluation", "config", "runtime_identity", "controls", "builds", "annotations", "record_store", "pools", "shared_contexts", "rows", "report", "auth_events", "transport_audit", "network_audit")
    values = {n: json.loads((run/(n+".json")).read_bytes()) for n in names}
    for value in values.values():
        no_private_objects(value)
    plan, runtime, gold, rows, contexts = (values[n] for n in ("plan", "runtime", "evaluation", "rows", "shared_contexts"))
    require(plan["version"] == VERSION and plan["score_schema_version"] == "span_answer_final_answer_v1" and plan["ordering_seed"] == 2026102517
        and plan["registered_tasks"] == 48 and plan["expected_rows"] == 144 and plan["legal_per_arm"] == 32 and plan["missing_per_arm"] == plan["outsider_per_arm"] == 8
        and plan["prepare_mode"] == "generation" and plan["privacy_pipeline"] == "legacy" and plan["query_intent"] is False
        and plan["evaluation_timing"] == "after_all_model_processing_and_model_phase_closed", "registered_protocol")
    equal(plan["arms"], list(ARMS), "registered_arms")
    equal(plan["generation_limits"], LIMITS, "registered_limits")
    require(len(runtime) == len({s["story_id"] for s in runtime}) == 8 and Counter(s["language"] for s in runtime) == {"en": 4, "zh": 4}, "story_matrix")
    stories = {s["story_id"]: s for s in runtime}
    require(set(stories) == set(gold), "evaluation_story_matrix")
    for story in runtime:
        require("@" not in story["source"]["text"] and len(story["tasks"]) == len({t["task_id"] for t in story["tasks"]}) == 5
            and CONTROL not in {t["task_id"] for t in story["tasks"]} and Counter(t["actor_id"] for t in story["tasks"]) == {"owner": 4, "outsider": 1}, "runtime_control_precondition")
    tasks = task_map(stories)
    expected_controls = [{"story_id": sid, "language": s["language"], **tasks[(sid, CONTROL)], "expected_answer": "UNKNOWN"} for sid, s in stories.items()]
    equal(values["controls"], expected_controls, "missing_controls_not_fixed_runtime_declaration")
    missing_plan = plan["missing_control"]
    equal((missing_plan["task_id"], missing_plan["queries"], missing_plan["expected_answer"]), (CONTROL, QUERIES, "UNKNOWN"), "control_reference_changed")
    corpus = Path(corpus or root/"examples/privacy_semantics_v1")
    for name, snapshot in (("runtime", runtime), ("evaluation", gold)):
        original = (corpus/"development"/(name+".json")).read_bytes()
        equal(sha(original), plan[name+"_sha256"], "original_input_hash")
        equal(json.loads(original), snapshot, "input_snapshot_changed")
    config = values["config"]
    equal(digest(config), plan["config_sha256"], "configuration_hash")
    require(config["endpoint"] == "http://127.0.0.1:11435" and config["model"] == base.MODEL and config["expected_digest"] == base.MODEL_DIGEST and config["expected_version"] == "0.40.8", "pinned_local_model")
    paths, identical = archive(run, plan, root)
    identity = values["runtime_identity"]
    equal(identity["local_generation"], {"version": "0.40.8", "model": base.MODEL, "digest": base.MODEL_DIGEST, "endpoint": "http://127.0.0.1:11435"}, "model_identity")
    equal(identity["union_detector_revision"], "sha256:"+digest(identity["union"]), "union_detector_revision")
    require(len(rows) == 144 and {(r["story_id"], r["task_id"], r["arm"]) for r in rows} == {(sid, tid, arm) for sid, tid in tasks for arm in ARMS}, "answer_matrix")
    require(len(contexts) == len({c["context_id"] for c in contexts}) == 48 and {(c["story_id"], c["task_id"]) for c in contexts} == set(tasks), "shared_context_matrix")
    events = [json.loads(line) for line in (run/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    requests, terminals = ledger(events, stories, tasks)
    builds, records = constructions(values, stories, paths, requests, terminals)
    context_index, packed = {}, {}
    for context in contexts:
        sid, tid = context["story_id"], context["task_id"]
        task, bundle = tasks[(sid, tid)], records[sid]
        equal(context["context_id"], sid+":"+tid, "context_identity")
        equal((context["actor_id"], context["task_class"]), (task["actor_id"], task["task_class"]), "context_task_binding")
        equal(context["context_sha256"], digest({k: v for k, v in context.items() if k != "context_sha256"}), "context_hash")
        equal(context["prepare_generation_calls_observed"], 0, "unexpected_prepare_generation")
        require("detection_cache" not in context["prepare_metadata"], "unexpected_detection_cache")
        equal((context["prepare_inference_counts"]["local_generation"], context["prepare_inference_counts"]["unknown"]), (0, 0), "prepare_unknown_cost")
        if context["prepare_status"] == "ok":
            require(task["actor_id"] == "owner" and bundle, "unauthorized_prepared_context")
            equal(context["payload_sha256"], digest(context["payload"]), "prepared_payload_hash")
            normalized_payload(context["payload"])
            require(len(context["payload"]["memories"]) == len(bundle), "prepared_source_count")
            equal(context["prepare_metadata"]["label_requirements"], {"expected_builder_version": builds[sid]["builder_version"], "expected_detector_version": identity["union_detector_revision"]}, "label_requirements")
            require(context["prepare_metadata"]["transfer_mode"] == "generation" and len(context["checks"]) == len(bundle), "generation_checks")
            src = {"__query__": task["query"], **{r["record_id"]: r["text"] for r in bundle}}
            seeds = [(r["record_id"], f["start"], f["end"], f["category"]) for r, check in zip(bundle, context["checks"]) if check["label_valid"] for f in r["label"]["findings"]]
            generation.verify_coverage(context["detection"], src, seeds, base.normalized_policy(stories[sid]["policy"]))
            if context["view_status"] == "ok":
                packed[context["context_id"]] = verify_view(context, stories[sid]["policy"])
        else:
            require(context["payload"] is None and context["view_status"] == "not_built", "blocked_context_published_view")
        context_index[context["context_id"]] = context
    assigned, per_task_messages = set(), defaultdict(dict)
    common = base._literal_assignment(paths["memory_migration_study/span_answerer.py"], "COMMON_PROMPT")
    outputs = base._literal_assignment(paths["memory_migration_study/span_answerer.py"], "OUTPUT_RULES")
    old_prompt = base._literal_assignment(paths["memory_migration_study/budget.py"], "MEMORY_PROMPTS")["memory_fact_query_v2"]
    for row in rows:
        sid, tid, arm = row["story_id"], row["task_id"], row["arm"]
        task, context, bundle = tasks[(sid, tid)], context_index[row["context_id"]], records[sid]
        equal((row["task_class"], row["actor_id"], row["language"], row["template_family"]), (task["task_class"], task["actor_id"], stories[sid]["language"], stories[sid]["template_family"]), "row_runtime_binding")
        equal((row["context_id"], row["context_sha256"], row["prepare_status"], row["prepare_error"], row["view_status"]),
            (sid+":"+tid, context["context_sha256"], context["prepare_status"], context["prepare_error"], context["view_status"]), "row_shared_context")
        require(row["mode"] == "generation" and row["common_build_status"] == builds[sid]["status"], "row_build_binding")
        expected_group = "ok" if bundle else "needs_review" if builds[sid]["status"] == "ok" else "not_run"
        equal(row["union_label_set_status"], expected_group, "row_union_label_status")
        selected = row.get("answer_request_indices", [])
        require(len(selected) <= 1 and len(selected) == row["answer_calls"] and not assigned.intersection(selected), "row_answer_call_allocation")
        assigned.update(selected)
        pointer_data = None
        if arm == "span_pointer":
            require(row["secondary_serialization_registered"] is False and "secondary_serialization" not in row,
                "pointer_repaired_after_model")
        else:
            require(row["secondary_serialization_registered"] is True, "free_secondary_unregistered")
        if selected:
            event, terminal = requests[selected[0]], terminals[selected[0]]
            equal(tuple(event[k] for k in ("stage", "arm", "story_id", "task_id")), ("answer", arm, sid, tid), "answer_call_context")
            require(context["prepare_status"] == "ok", "answer_before_prepare")
            body = event["request"]
            if arm == "free":
                expected_messages = [{"role": "system", "content": old_prompt}, {"role": "user", "content": json.dumps(context["payload"], ensure_ascii=False, separators=(",", ":"))}]
                require(row.get("answer_metadata") is None, "old_free_usage_fabricated")
            else:
                require(context["view_status"] == "ok", "indexed_call_without_view")
                expected_messages = [{"role": "system", "content": common+outputs[arm]}, {"role": "user", "content": json.dumps({"payload": context["payload"], "evidence": packed[context["context_id"]]}, ensure_ascii=False, separators=(",", ":"))}]
                expected_format = context["response_schema"] if arm == "span_pointer" else None
                if arm == "span_pointer":
                    equal(body["format"], expected_format, "actual_pointer_schema")
                upper = len(json.dumps(body, ensure_ascii=False).encode())+320+64
                require(upper <= 4096, "full_request_schema_budget")
                meta = row["answer_metadata"]
                for key, expected_value in {"mode": arm, "prompt_version": base._literal_assignment(paths["memory_migration_study/span_answerer.py"], "PROMPT_VERSION"),
                    "messages_sha256": digest(body["messages"]), "format_sha256": digest(expected_format) if expected_format is not None else None,
                    "input_sha256": digest({"messages": body["messages"], "format": expected_format}), "packed_view_sha256": digest(packed[context["context_id"]]),
                    "payload_sha256": context["payload_sha256"], "request_sha256": digest(body), "input_budget_upper_bound": upper}.items():
                    equal(meta[key], expected_value, "answer_metadata_"+key)
            equal(body["messages"], expected_messages, "answer_input_not_shared_exact")
            per_task_messages[(sid, tid)][arm] = body["messages"][1]
            if terminal["phase"] == "response":
                raw = terminal["response"].get("message", {}).get("content")
                equal(row["raw_model_answer"], raw, "full_raw_response_changed")
                if arm != "free":
                    equal((row["answer_metadata"]["prompt_eval_count"], row["answer_metadata"]["eval_count"]),
                        (terminal["response"]["prompt_eval_count"], terminal["response"]["eval_count"]), "actual_answer_usage")
                if row["answer_status"] == "ok":
                    shared.successful_envelope(terminal["response"])
                    equal(row["model_answer"], raw.strip() if arm == "free" else raw, "accepted_model_content_changed")
                    if arm == "span_pointer":
                        pointer_data = strict_pointer(raw)
                        if pointer_data["decision"] == "SPAN":
                            source = next((s for s in context["view"]["sources"] if s["source"] == pointer_data["source"]), None)
                            require(source is not None and 0 <= pointer_data["start_token"] <= pointer_data["end_token"] < len(source["tokens"]), "accepted_pointer_out_of_range")
            else:
                require(row["answer_status"] != "ok" and row["raw_model_answer"] is None, "transport_failure_as_answer")
        else:
            require(row["raw_model_answer"] is None and row["model_answer"] is None, "answer_without_model_call")
        if row["answer_status"] != "ok":
            require(row["model_answer"] is None and row["answer_for_restore"] is None and row["final_answer"] is None
                and row["resolver_status"] == "not_run" and row["pointer_decision"] is None and
                "secondary_serialization" not in row, "malformed_or_failed_call_promoted")
        elif arm == "span_pointer":
            require(not row["secondary_serialization_registered"] and "secondary_serialization" not in row, "pointer_repaired_after_model")
            if row["resolver_status"] == "ok":
                require(pointer_data is not None, "pointer_resolved_without_parsing")
                equal(row["pointer_decision"], pointer_data["decision"], "pointer_decision_changed")
                if pointer_data["decision"] == "UNKNOWN":
                    equal((row["source_span"], row["answer_for_restore"]), (None, "UNKNOWN"), "unknown_pointer_forged_source")
                else:
                    view_i = next(i for i, s in enumerate(context["view"]["sources"]) if s["source"] == pointer_data["source"])
                    tokens, memory = context["view"]["sources"][view_i]["tokens"], context["payload"]["memories"][view_i]
                    left, right = tokens[pointer_data["start_token"]]["start"], tokens[pointer_data["end_token"]]["end"]
                    exact = memory["text"][left:right]
                    require(exact.strip() and ("PVT_" not in exact or base.TOKEN.fullmatch(exact)), "accepted_pointer_not_single_value")
                    equal(row["source_span"], {"source_id": memory["source_id"], "start": left, "end": right,
                        "start_token": pointer_data["start_token"], "end_token": pointer_data["end_token"]}, "pointer_exact_source_span")
                    equal(row["answer_for_restore"], exact, "pointer_slice_modified")
            else:
                require(row["resolver_status"] == "blocked" and row["answer_for_restore"] is None and row["final_answer"] is None and row["pointer_decision"] is None, "failed_resolver_as_unknown")
        else:
            require(row["secondary_serialization_registered"] is True and row["resolver_status"] == "not_run" and row["source_span"] is None, "free_mode_used_pointer")
            equal(row["answer_for_restore"], row["model_answer"], "free_answer_modified")
            answer, second = row["model_answer"], row["secondary_serialization"]
            current_tokens = set(base.TOKEN.findall(context["payload"]["query"])) | {m.group() for source in context["payload"]["memories"] for m in base.TOKEN.finditer(source["text"])}
            add = BARE.fullmatch(answer.strip()) is not None and "["+answer.strip()+"]" in current_tokens
            equal((second["decision"], second["canonical_answer"]), ("added_outer_brackets" if add else "unchanged", "["+answer.strip()+"]" if add else answer), "secondary_not_exact_same_output")
            if add:
                require(row["restoration_status"] == "blocked" and row["final_answer"] is None, "secondary_overwrote_primary")
            check_restore(second["canonical_answer"], second["restoration_status"], second["final_answer"], context, bundle)
        if row["answer_for_restore"] is not None:
            check_restore(row["answer_for_restore"], row["restoration_status"], row["final_answer"], context, bundle)
        expected_answer = gold[sid]["answers"].get(tid) if task["task_class"] == "legal" else None
        equal(row["required_fact_retained"], bool(expected_answer and any(expected_answer in r["text"] for r in bundle)), "required_fact_retention")
        mask = base.independent_masking(stories[sid], task, gold[sid], bundle, context["payload"], False) if context["prepare_status"] == "ok" else base.blocked_masking(stories[sid], gold[sid], bundle)
        equal(row["masking"], mask, "independent_literal_masking")
        equal(row["score"], assess(row, task, gold[sid]), "independent_final_score")
    require(assigned == {i for i, e in requests.items() if e["stage"] == "answer"}, "unallocated_answer_post")
    for messages in per_task_messages.values():
        if {"free_indexed", "span_pointer"} <= set(messages):
            equal(messages["free_indexed"], messages["span_pointer"], "indexed_modes_not_same_input")
    journal = values["auth_events"]
    equal([e["sequence"] for e in journal], list(range(1, len(journal)+1)), "auth_sequence")
    require(journal and journal[-1]["kind"] == "model_phase_closed", "auth_model_closure")
    operations = defaultdict(list)
    for event in journal[:-1]:
        require(event["kind"] in {"prepare_start", "access_check", "arm_processing_end"}, "unexpected_auth_event")
        operations[event["operation"]].append(event)
    require(set(operations) == {c["context_id"]+":shared_prepare" for c in contexts} | {r["context_id"]+":"+r["arm"] for r in rows}, "auth_operation_matrix")
    for context in contexts:
        bundle = records[context["story_id"]]
        op = operations[context["context_id"]+":shared_prepare"]
        require(op[0]["kind"] == "prepare_start" and all(e["kind"] == "access_check" for e in op[1:]), "shared_prepare_auth_order")
        equal((op[0]["record_ids"], op[0]["record_set_sha256"], op[0]["request_sha256"]),
            ([r["record_id"] for r in bundle], digest(bundle), context["request_sha256"]), "shared_prepare_records_request")
        if not bundle:
            require(len(op) == 1 and context["prepare_error"] == "label_set_unavailable", "unavailable_labels_as_denial")
        elif context["actor_id"] != "owner":
            require(op[1]["error"] == "principal_not_authorized", "outsider_not_real_authority_denial")
        else:
            require({e["record_id"] for e in op[1:] if e["error"] is None} == {r["record_id"] for r in bundle}, "shared_prepare_missing_source_auth")
    for row in rows:
        context, bundle = context_index[row["context_id"]], records[row["story_id"]]
        op = operations[row["context_id"]+":"+row["arm"]]
        require(op[-1]["kind"] == "arm_processing_end" and all(e["kind"] == "access_check" for e in op[:-1]), "arm_auth_order")
        equal((op[-1]["answer_calls"], op[-1]["answer_status"], op[-1]["resolver_status"]), (row["answer_calls"], row["answer_status"], row["resolver_status"]), "arm_end_summary")
        require(all(e["record_id"] in {r["record_id"] for r in bundle} and e["actor_id"] == row["actor_id"] and e["agent_id"] == "target-agent" for e in op[:-1]), "arm_auth_context")
        if row["answer_calls"]:
            require(len(op) >= len(bundle)+1 and all(e["error"] is None for e in op[:len(bundle)])
                and [e["record_id"] for e in op[:len(bundle)]] == [r["record_id"] for r in bundle], "answer_without_current_all_record_auth")
            if row["arm"] == "span_pointer" and row["answer_status"] == "ok":
                require(len(op) >= 2*len(bundle)+1, "pointer_without_second_all_record_auth")
            if row["restoration_status"] is not None:
                require(len(op) >= 2*len(bundle)+1, "restore_without_current_auth")
        elif context["prepare_status"] != "ok":
            require(len(op) == 1, "blocked_context_executed_arm")
    equal(journal[-1]["actual_generation_attempts"], len(requests), "closure_actual_calls")
    report, audit, network = (values[n] for n in ("report", "transport_audit", "network_audit"))
    equal(report["arms"], aggregate(rows), "independent_aggregate")
    stages = Counter(e["stage"] for e in requests.values())
    expected_totals = {"version": VERSION, "registered_rows": 144, "recorded_rows": 144, "registered_tasks": 48, "source_stories": 8,
        "common_build_failures": sum(b["status"] != "ok" for b in builds.values()), "union_label_set_failures": sum(not r for r in records.values()),
        "shared_prepare_invocations": sum(bool(records[c["story_id"]]) for c in contexts), "shared_contexts": 48,
        "generation_calls_observed": len(requests), "builder_generations": stages["build"], "write_annotation_generations": stages["write_annotation"], "answer_generations": stages["answer"],
        "build_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds.values()),
        "write_annotation_encoder_calls": sum(a["inference_counts"]["local_encoder"] for a in values["annotations"]),
        "shared_prepare_encoder_calls": sum(c["prepare_inference_counts"]["local_encoder"] for c in contexts),
        "total_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds.values())+sum(a["inference_counts"]["local_encoder"] for a in values["annotations"])+sum(c["prepare_inference_counts"]["local_encoder"] for c in contexts),
        "detector_call_accounting_complete": True, "implementation_unchanged": True, "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0}
    for key, expected_value in expected_totals.items():
        equal(report[key], expected_value, "report_total_"+key)
    equal(report["scope"], plan["scope"], "report_scope")
    responses = [e for e in terminals.values() if e["phase"] == "response"]
    require(audit["completed"] is True and audit["registered_protocol"] == VERSION and audit["recovery_mapping_recorded"] is False, "audit_completion")
    for key, expected_value in {"physical_generation_attempts": len(requests), "responses": len(responses), "transport_errors": len(terminals)-len(responses),
        "actual_token_budget_violations": 0, "registered_generation_cap": 264, "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0}.items():
        equal(audit[key], expected_value, "audit_total_"+key)
    equal(audit["network"], network, "network_summary")
    require(network["external_attempts_blocked"] == 0 and type(network["loopback_connections"]) is int and network["loopback_connections"] >= 0, "external_network")
    cost = defaultdict(lambda: {"physical_calls": 0, "prompt_tokens": 0, "output_tokens": 0, "request_json_utf8_bytes": 0})
    for i, event in requests.items():
        cell = cost[(event["stage"], event["arm"])]
        cell["physical_calls"] += 1
        cell["request_json_utf8_bytes"] += event["wire_json_utf8_bytes"]
        if terminals[i]["phase"] == "response":
            cell["prompt_tokens"] += terminals[i]["response"]["prompt_eval_count"]
            cell["output_tokens"] += terminals[i]["response"]["eval_count"]
    return {"version": "independent_span_answer_transfer_v1", "status": "passed", "registered_rows": 144, "shared_contexts": 48,
        "physical_generation_attempts": len(requests), "current_snapshot_identical": identical, "arms": aggregate(rows),
        "physical_costs": [{"stage": stage, "arm": arm, **v} for (stage, arm), v in sorted(cost.items())], "verification_model_calls": 0,
        "evidence_sha256": {n+".json": sha((run/(n+".json")).read_bytes()) for n in names}, "transport_sha256": sha((run/"request_transport.jsonl").read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()),
        "limits": ["Passing means consistent evidence, not effect acceptance or innovation.", "This is exposed synthetic development, not a blind test or native interoperability.",
            "Source/view order and exact slices are independently reconstructed; destroyed table keys/maps and HMAC authenticity cannot be replayed.",
            "Token restoration is checked using original-source literal anchors without persisting a reconstructed map; registered masking is not semantic privacy.",
            "Current authorization order is checked in logged real calls and archived control flow, not authenticated by public hashes."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "new_receipt_path_required")
    receipt = verify(args.directory, corpus=args.corpus)
    args.output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "physical_generation_attempts": receipt["physical_generation_attempts"]}))


if __name__ == "__main__":
    main()
