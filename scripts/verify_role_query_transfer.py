"""Independent zero-model audit of source-role/query-only transfer experiments.

Production modules are never imported and archived code is never executed.
Public integrity/authentication observations do not recover destroyed HMAC keys.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import verify_reference_memory_study as base
from scripts import verify_span_answer_transfer as span
from scripts import verify_generation_union_transfer as generation
from scripts import verify_policy_semantic_study as shared
from scripts import verify_query_schema_transfer as query

digest, sha, require, equal = base.digest, base.sha, base.require, base.equal
ARMS = ("F", "Q0", "Q1")
SOURCE_ROLES = ("customer", "buyer", "consignee", "account_holder", "audit_observer", "carrier", "status")
QUERY_ROLES = SOURCE_ROLES + ("email", "UNKNOWN")
LIMITS = {"total": 224, "build": 16, "write_annotation": 128, "answer": 80}
BARE = re.compile(r"PVT_[A-F0-9]{24}_(?:PERSON|ADDRESS|CUSTOMER|PROJECT|EMAIL|PHONE|ID|AMOUNT|DATE|MIXED)_[1-9][0-9]*\Z")


def strict_role(raw, roles=QUERY_ROLES):
    """Parse a closed role decision; arbitrary quote/value fields are rejected."""
    require(isinstance(raw, str) and 0 < len(raw.encode()) <= 4096, "invalid_role_json")
    def unique(items):
        value = {}
        for key, child in items:
            require(key not in value, "duplicate_role_json_key")
            value[key] = child
        return value
    def invalid(_):
        raise ValueError("invalid_role_json_constant")
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except json.JSONDecodeError:
        raise ValueError("invalid_role_json") from None
    require(isinstance(value, dict) and set(value) == {"role"}
        and isinstance(value["role"], str) and value["role"] in roles, "invalid_role_schema")
    return value["role"]


def canonical(answer, payload):
    require(isinstance(answer, str), "invalid_answer")
    value = answer.strip()
    tokens = {m.group() for text in [payload["query"]] + [s["text"] for s in payload["memories"]]
              for m in base.TOKEN.finditer(text)}
    if BARE.fullmatch(value) and "["+value+"]" in tokens:
        return "["+value+"]", "added_outer_brackets"
    return answer, "unchanged"


def role_pattern(values):
    parts = []
    for value in sorted(values, key=len, reverse=True):
        parts.append((r"(?<![A-Za-z])"+re.escape(value)+r"(?![A-Za-z])") if value.isascii() else re.escape(value))
    return "(?:" + "|".join(parts) + ")"


def derive_cards(payload, aliases):
    """Read values only from masked memories, never a query or score reference."""
    require(isinstance(payload, dict) and set(payload) == {"query", "memories"}
        and isinstance(payload["query"], str) and isinstance(payload["memories"], list), "invalid_role_payload")
    require(set(aliases) == set(SOURCE_ROLES), "source_role_alias_contract")
    cards, seen_sources = {}, set()
    for memory in payload["memories"]:
        require(set(memory) == {"source_id", "text"} and isinstance(memory["source_id"], str)
            and memory["source_id"] not in seen_sources and isinstance(memory["text"], str), "role_source_identity")
        sid, text = memory["source_id"], memory["text"]
        seen_sources.add(sid)
        anchors = [(m.start(), m.end(), role) for role, terms in aliases.items() if role != "status"
                   for m in re.finditer(role_pattern(terms), text, re.I)]
        for match in base.TOKEN.finditer(text):
            a, b = match.span()
            candidates = [(x, y, role) for x, y, role in anchors if 0 <= a-y <= 32
                          and re.fullmatch(r"[\s,:：，=＝|｜]*(?:(?:is|was|是|为)\s*)?", text[y:a], re.I)]
            if not candidates:
                continue
            nearest = max(y for _, y, _ in candidates)
            selected = [(x, role) for x, y, role in candidates if y == nearest]
            if len({role for _, role in selected}) != 1:
                continue
            x, role = selected[0]
            cards[(sid, role, a, b)] = {"role": role, "source_id": sid, "value": text[a:b], "start": a, "end": b,
                "anchor_start": x, "anchor_end": nearest,
                "support_start": x, "support_end": b}
        pattern = role_pattern(aliases["status"])+r"\s*(?::|：|=|＝|\bis\b|\bwas\b|登记为|是|为)\s*(?P<value>[^。；;\r\n.!?！？|｜]+)"
        for match in re.finditer(pattern, text, re.I):
            left, right = match.span("value")
            a = left+len(text[left:right])-len(text[left:right].lstrip())
            b = right-(len(text[left:right])-len(text[left:right].rstrip()))
            value = text[a:b]
            if a < b and len(value) <= 160 and ("PVT_" not in value or base.TOKEN.fullmatch(value)):
                cards[(sid, "status", a, b)] = {"role": "status", "source_id": sid, "value": text[a:b], "start": a, "end": b,
                    "anchor_start": match.start(), "anchor_end": left,
                    "support_start": match.start(), "support_end": b}
    return sorted(cards.values(), key=lambda c: (c["source_id"], c["start"], c["end"], c["role"]))


def check_cards(cards, payload, aliases):
    require(isinstance(cards, list), "invalid_role_cards")
    expected = derive_cards(payload, aliases)
    equal(cards, expected, "role_cards_not_source_grammar")
    return expected


def dictionary_role(masked_query, aliases, status_patterns=(), multi_role_pattern=None):
    require(isinstance(masked_query, str), "invalid_query")
    # A private placeholder is data, not a language cue or an output field.
    text = base.TOKEN.sub("[REDACTED]", masked_query)
    found = {role for role, terms in aliases.items()
             if re.search(terms if isinstance(terms, str) else role_pattern(terms), text, re.I)}
    if len(found) > 1 and multi_role_pattern and re.search(multi_role_pattern, text, re.I):
        return "UNKNOWN"
    if "status" in found and any(re.search(pattern, text, re.I) for pattern in status_patterns):
        return "status"
    return next(iter(found)) if len(found) == 1 else "UNKNOWN"


def resolve_unique(role, cards):
    require(role in QUERY_ROLES, "unsupported_query_role")
    values = sorted({card["value"] for card in cards if card["role"] == role})
    return values[0] if role != "UNKNOWN" and len(values) == 1 else "UNKNOWN"


def physical_ledger(events, stories, tasks):
    """Count actual request/terminal pairs; a model claim cannot add calls."""
    requests, terminals = {}, {}
    for event in events:
        span.no_private_objects(event)
        index = event.get("index")
        require(type(index) is int and index > 0, "invalid_physical_index")
        stage, arm, sid, tid = (event[k] for k in ("stage", "arm", "story_id", "task_id"))
        require(sid in stories and stage in {"build", "write_annotation", "answer"}, "physical_stage")
        require((stage == "build" and arm == "common" and tid is None) or
                (stage == "write_annotation" and arm == "union_labels" and tid is None) or
                (stage == "answer" and arm in {"F", "Q1"} and (sid, tid) in tasks
                 and tasks[(sid, tid)]["actor_id"] == "owner"), "unauthorized_physical_context")
        if event["phase"] == "request":
            require(index not in requests, "duplicate_physical_request")
            requests[index] = event
            body = event["request"]
            wire = json.dumps(body, ensure_ascii=False).encode()
            equal((digest(body), len(wire), sha(wire)),
                  (event["request_sha256"], event["wire_json_utf8_bytes"], event["wire_json_utf8_sha256"]), "physical_wire_integrity")
            cap = 64 if stage == "answer" else 1024
            equal(body["options"], {"num_ctx": 4096, "num_predict": cap, "temperature": 0, "seed": 42}, "physical_options")
            require(set(body) == {"model", "messages", "stream", "keep_alive", "options"} |
                    ({"format"} if stage != "answer" or arm == "Q1" else set()), "physical_extra_fields")
            require(body["model"] == base.MODEL and body["stream"] is False and body["keep_alive"] == "30m"
                    and event["scope"] == "synthetic_development_local_only", "physical_model_contract")
        else:
            require(event["phase"] in {"response", "failure"} and index in requests and index not in terminals, "orphan_physical_terminal")
            request = requests[index]
            equal(tuple(event[k] for k in ("stage", "arm", "story_id", "task_id", "request_sha256")),
                  tuple(request[k] for k in ("stage", "arm", "story_id", "task_id", "request_sha256")), "physical_terminal_context")
            terminals[index] = event
            if event["phase"] == "response":
                response = event["response"]
                equal(sha(json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)),
                      event["response_sha256"], "physical_response_hash")
                prompt, output = response.get("prompt_eval_count"), response.get("eval_count")
                cap = request["request"]["options"]["num_predict"]
                require(type(prompt) is int and 0 < prompt <= 3072 and type(output) is int and 0 < output <= cap
                        and prompt+cap <= 4096 and event["actual_usage_within_budget"] is True, "physical_usage_budget")
            else:
                equal(event["error"], "physical_transport_failed", "physical_error_code")
    require(set(requests) == set(terminals) == set(range(1, len(requests)+1)), "physical_call_denominator")
    counts = Counter(r["stage"] for r in requests.values())
    require(len(requests) <= LIMITS["total"] and all(counts[k] <= v for k, v in LIMITS.items() if k != "total"), "physical_call_cap")
    return requests, terminals


def query_only_request(request, masked_query, *, prompt, schema, definitions=None):
    user = {"query": base.TOKEN.sub("[REDACTED]", masked_query)}
    if definitions is not None:
        user["role_definitions"] = definitions
    expected = [{"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(user, ensure_ascii=False, separators=(",", ":"))}]
    equal(request["messages"], expected, "q1_not_query_only")
    equal(request.get("format"), schema, "q1_not_closed_schema")


def literal_constant(path, name):
    """Evaluate only literal data and fixed list/tuple/mapping wrappers in AST."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8-sig"))
    values = {t.id: node.value for node in tree.body if isinstance(node, ast.Assign)
              for t in node.targets if isinstance(t, ast.Name)}
    active = set()
    def evaluate(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            result = [evaluate(n) for n in node.elts]
            return tuple(result) if isinstance(node, ast.Tuple) else result
        if isinstance(node, ast.Dict):
            require(all(k is not None for k in node.keys), "nonliteral_archive_constant")
            return {evaluate(k): evaluate(v) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.Name) and node.id in values:
            require(node.id not in active, "recursive_archive_constant")
            active.add(node.id)
            result = evaluate(values[node.id])
            active.remove(node.id)
            return result
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"MappingProxyType", "tuple", "list"} and len(node.args) == 1 and not node.keywords:
            result = evaluate(node.args[0])
            return result if node.func.id == "MappingProxyType" else tuple(result) if node.func.id == "tuple" else list(result)
        raise ValueError("nonliteral_archive_constant")
    require(name in values, "missing_archive_constant")
    return evaluate(values[name])


def archive(run, plan, root):
    paths, identical = {}, True
    for name, expected in plan["implementation_sha256"].items():
        rel = Path(name.replace("\\", "/"))
        require(not rel.is_absolute() and ".." not in rel.parts and rel.suffix == ".py", "unsafe_archive_path")
        saved, current = (run/"implementation"/rel).resolve(), (root/rel).resolve()
        require(saved.is_relative_to((run/"implementation").resolve()) and current.is_relative_to(root)
                and sha(saved.read_bytes()) == expected, "archive_hash_changed")
        paths[rel.as_posix()] = saved
        identical = identical and current.is_file() and sha(current.read_bytes()) == expected
    require(set(paths) == {p.relative_to(run/"implementation").as_posix() for p in (run/"implementation").rglob("*.py")}, "archive_inventory")
    required = {"scripts/run_role_query_transfer.py", "scripts/verify_role_query_transfer.py", "scripts/run_policy_semantic_study.py",
        "scripts/run_span_answer_transfer.py", "scripts/run_customer_schema_probe.py", "scripts/run_query_schema_transfer.py",
        "scripts/run_reference_memory_study.py", "memory_migration_study/role_query.py", "memory_migration_study/budget.py",
        "memory_migration_study/privacy.py", "memory_migration_study/ner_detector.py", "memory_migration_study/memory_labels.py"}
    require(required <= set(paths), "archive_missing_dependency")
    role_path, driver = paths["memory_migration_study/role_query.py"], paths["scripts/run_role_query_transfer.py"]
    equal(literal_constant(driver, "VERSION"), plan["version"], "archived_driver_version")
    equal(literal_constant(driver, "ARMS"), ARMS, "archived_arms")
    equal(literal_constant(driver, "SEED"), plan["ordering_seed"], "archived_seed")
    constants = {name: literal_constant(role_path, name) for name in ("ROLES", "ALIASES", "QUERY_ALIASES", "ROLE_SCHEMA",
        "ROLE_DEFINITIONS", "STATUS_QUESTION_PATTERNS", "MULTI_ROLE_CONNECTOR_PATTERN", "SYSTEM_PROMPT", "OPTIONS", "VERSION", "PROMPT_VERSION")}
    require(set(constants["ROLES"]) == set(QUERY_ROLES), "role_enum_contract")
    for field, name in (("roles", "ROLES"), ("source_aliases", "ALIASES"), ("query_aliases", "QUERY_ALIASES"), ("role_schema", "ROLE_SCHEMA")):
        equal(plan[field], constants[name], "frozen_role_contract")
    schema = {"type": "object", "additionalProperties": False, "required": ["role"],
              "properties": {"role": {"type": "string", "enum": list(constants["ROLES"])}}}
    equal(schema, constants["ROLE_SCHEMA"], "closed_role_schema")
    fn = next(n for n in ast.parse(driver.read_text(encoding="utf-8-sig")).body if isinstance(n, ast.FunctionDef) and n.name == "run")
    loops = [n for n in fn.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "story"]
    closes = [n for n in fn.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "model_phase_closed" for t in n.targets)]
    gold = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "loads"
            and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "evaluation_bytes"]
    require(len(loops) == len(closes) == len(gold) == 1 and loops[0].end_lineno < closes[0].lineno < gold[0].lineno
            and isinstance(closes[0].value, ast.Constant) and closes[0].value.value is True, "evaluation_before_model_closure")
    calls = defaultdict(list)
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls[node.func.id].append(node)
    require(len(calls["prepare_labeled_transfer"]) == 1 and len(calls["_current_access"]) == 1
            and len(calls["restore_labeled_answer"]) == 2
            and calls["prepare_labeled_transfer"][0].lineno < calls["_current_access"][0].lineno
            < min(n.lineno for n in calls["restore_labeled_answer"]), "shared_prepare_or_restore_order")
    authority = ast.parse(paths["scripts/run_policy_semantic_study.py"].read_text(encoding="utf-8-sig"))
    method = next(n for cls in authority.body if isinstance(cls, ast.ClassDef) and cls.name == "AuditedAuthority"
                  for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "validate_access")
    real = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "validate_access"
            and isinstance(n.func.value, ast.Call) and isinstance(n.func.value.func, ast.Name) and n.func.value.func.id == "super"]
    logged = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "event"]
    require(len(real) == len(logged) == 1 and real[0].lineno < logged[0].lineno, "authority_not_real_super")
    return paths, constants, bool(identical)


SCORES = ("correct", "joint_correct_no_masking_gap", "model_chose_unknown", "host_join_unknown", "unknown_with_required_fact",
          "strict_F_correct", "outsider_blocked", "unauthorized_output", "restoration_failure")


def independent_score(row, task, gold):
    allowed = task["actor_id"] == "owner"
    expected = "UNKNOWN" if task["task_class"] == "missing" else gold["answers"].get(task["task_id"], "")
    final, strict = row.get("final_answer"), row.get("strict_final_answer")
    correct = allowed and isinstance(final, str) and final.strip().casefold() == expected.casefold()
    mask = row["masking"]
    unknown = (row["arm"] == "F" and row["answer_status"] == "ok" and (row.get("raw_model_answer") or "").strip() == "UNKNOWN"
               or row["arm"] == "Q1" and (row.get("classification") or {}).get("status") == "ok"
               and (row.get("classification") or {}).get("role") == "UNKNOWN")
    return {"authorized": allowed, "correct": bool(correct),
        "joint_correct_no_masking_gap": bool(correct and mask.get("ready") is True and mask.get("partial") == mask.get("unmasked") == 0),
        "model_chose_unknown": bool(unknown), "host_join_unknown": row["arm"] != "F" and row.get("resolved_answer") == "UNKNOWN",
        "unknown_with_required_fact": task["task_class"] == "legal" and row["required_fact_retained"] and final == "UNKNOWN",
        "strict_F_correct": bool(row["arm"] == "F" and isinstance(strict, str) and strict.strip().casefold() == expected.casefold()),
        "outsider_blocked": task["task_class"] == "outsider" and row.get("prepare_error") == "principal_not_authorized" and row["answer_calls"] == 0,
        "unauthorized_output": bool(not allowed and (row["answer_calls"] > 0 or final)), "restoration_failure": row.get("restoration_status") == "blocked"}


def aggregate(rows):
    return {arm: {kind: {"registered_tasks": len(group), **{k: sum(r["score"][k] for r in group) for k in SCORES},
        "answer_calls": sum(r["answer_calls"] for r in group), "prepare_blocked": sum(r["prepare_status"] != "ok" for r in group)}
        for kind in ("legal", "missing", "outsider") for group in [[r for r in rows if r["arm"] == arm and r["task_class"] == kind]]} for arm in ARMS}


def verify(directory, *, corpus=None, project_root=None):
    run, root = Path(directory).resolve(), Path(project_root or ROOT).resolve()
    names = ("plan", "runtime", "evaluation", "config", "runtime_identity", "builds", "annotations", "record_store", "pools",
             "shared_contexts", "query_encoder_events", "rows", "report", "auth_events", "transport_audit", "network_audit")
    data = {name: json.loads((run/(name+".json")).read_bytes()) for name in names}
    for value in data.values():
        span.no_private_objects(value)
    plan, runtime, gold, rows = (data[name] for name in ("plan", "runtime", "evaluation", "rows"))
    require(plan["version"] == "source_role_query_join_development_v1" and plan["arms"] == list(ARMS)
        and (plan["source_stories"], plan["registered_tasks"], plan["expected_rows"], plan["legal_per_arm"], plan["missing_per_arm"], plan["outsider_per_arm"]) == (8, 48, 144, 32, 8, 8)
        and plan["prepare_mode"] == "generation" and plan["privacy_pipeline"] == "legacy"
        and (plan["threshold"], plan["splitter"], plan["max_encoded_tokens"]) == (.5, "cjk_aware", 512), "registered_protocol")
    equal(plan["generation_limits"], LIMITS, "registered_generation_limits")
    require(len(runtime) == len({s["story_id"] for s in runtime}) == 8 and Counter(s["language"] for s in runtime) == {"en": 4, "zh": 4}, "runtime_story_matrix")
    stories = {s["story_id"]: s for s in runtime}
    require(set(stories) == set(gold), "gold_story_matrix")
    tasks = span.task_map(stories)
    equal(plan["missing_control"]["queries"], span.QUERIES, "missing_control_queries")
    equal(plan["missing_control"]["expected_answer"], "UNKNOWN", "missing_control_answer")
    require(len(tasks) == 48 and all("@" not in s["source"]["text"] and len(s["tasks"]) == 5 for s in runtime), "missing_control_precondition")
    corpus = Path(corpus or root/"examples/privacy_semantics_v1")
    for name, snapshot in (("runtime", runtime), ("evaluation", gold)):
        original = (corpus/"development"/(name+".json")).read_bytes()
        equal(sha(original), plan[name+"_sha256"], "original_input_hash")
        equal(json.loads(original), snapshot, "original_input_snapshot")
    equal(digest(data["config"]), plan["config_sha256"], "config_hash")
    require(data["config"]["endpoint"] == "http://127.0.0.1:11435" and data["config"]["model"] == base.MODEL
            and data["config"]["expected_digest"] == base.MODEL_DIGEST and data["config"]["expected_version"] == "0.40.8", "pinned_model")
    paths, constants, identical = archive(run, plan, root)
    policy = base.normalized_policy(literal_constant(paths["scripts/run_customer_schema_probe.py"], "POLICY"))
    equal(plan["approved_policy"], policy, "approved_policy")
    require(all(base.normalized_policy(s["policy"]) == policy for s in runtime), "story_policy")
    identity = data["runtime_identity"]
    equal(identity["local_generation"], {"version": "0.40.8", "model": base.MODEL, "digest": base.MODEL_DIGEST, "endpoint": "http://127.0.0.1:11435"}, "model_identity")
    equal(identity["union_detector_revision"], "sha256:"+digest(identity["union"]), "union_revision")
    equal(identity["classifier"], plan["classifier_identity"], "classifier_identity_changed")
    classifier_identity = identity["classifier"]
    for name, expected in {"implementation_sha256": sha(paths["memory_migration_study/role_query.py"].read_bytes()),
        "source_aliases": constants["ALIASES"], "query_aliases": constants["QUERY_ALIASES"], "role_schema": constants["ROLE_SCHEMA"],
        "role_definitions": constants["ROLE_DEFINITIONS"], "options": constants["OPTIONS"], "system_sha256": sha(constants["SYSTEM_PROMPT"]),
        "model": base.MODEL, "digest": base.MODEL_DIGEST, "runtime": "0.40.8", "config": data["config"]}.items():
        equal(classifier_identity[name], expected, "classifier_frozen_"+name)
    require(len(rows) == 144 and {(r["story_id"], r["task_id"], r["arm"]) for r in rows} == {(s, t, a) for s, t in tasks for a in ARMS}, "answer_matrix")
    contexts = data["shared_contexts"]
    require(len(contexts) == len({c["context_id"] for c in contexts}) == 48 and {(c["story_id"], c["task_id"]) for c in contexts} == set(tasks), "shared_context_matrix")
    contexts = {c["context_id"]: c for c in contexts}
    events = [json.loads(line) for line in (run/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    requests, terminals = physical_ledger(events, stories, tasks)
    builds, records = span.constructions(data, stories, paths, requests, terminals)
    observations, observed = data["query_encoder_events"], set()
    equal([e["event_index"] for e in observations], list(range(len(observations))), "query_event_sequence")
    labels = literal_constant(paths["memory_migration_study/ner_detector.py"], "LABELS")
    total_query_encoders = 0
    for cid, context in contexts.items():
        sid, tid = context["story_id"], context["task_id"]
        task, bundle, story = tasks[(sid, tid)], records[sid], stories[sid]
        equal((cid, context["original_query"], context["actor_id"], context["agent_id"], context["policy"], context["record_scope_sha256"]),
              (sid+":"+tid, task["query"], task["actor_id"], "target-agent", story["policy"], digest(bundle)), "context_scope_binding")
        require(isinstance(context["request_id"], str) and re.fullmatch(r"[a-f0-9]{32}", context["request_id"]), "request_scope")
        indices = context["query_encoder_event_indices"]
        require(len(indices) <= 1 and not observed.intersection(indices), "query_observation_allocation")
        observed.update(indices)
        seeds, count = [], 0
        for index in indices:
            require(type(index) is int and 0 <= index < len(observations), "query_observation_index")
            event = observations[index]
            equal((event["context_id"], event["operation"]), (cid, cid+":shared"), "shared_query_context")
            projected = dict(event, operation=cid+":A")
            found, physical = query.query_observation(projected, dict(context, arm="A"), task, policy, {"A": labels})
            seeds += found
            count += physical
        total_query_encoders += count
        equal((context["prepare_generation_calls_observed"], context["inference_counts"]), (0, {"local_encoder": count, "local_generation": 0, "unknown": 0}), "shared_prepare_costs")
        ready = context["prepare_status"] == "ok"
        if ready:
            require(task["actor_id"] == "owner" and bundle and len(indices) == 1, "unauthorized_preparation")
            payload, detection = context["outbound"], context["detection"]
            equal(context["actual_payload_sha256"], digest(payload), "shared_payload_hash")
            require(context["egress"]["status"] == "ok" and detection["status"] == "ok" and not detection["errors"]
                    and detection["local_calls_complete"] is True, "dirty_preparation_accepted")
            original = {"query": task["query"], "memories": [{"source_id": r["record_id"], "text": r["text"]} for r in bundle]}
            equal((detection["payload_sha256"], detection["policy_sha256"], detection["local_calls"]), (digest(original), digest(policy), count), "detection_scope")
            require(len(context["checks"]) == len(bundle) and all(c["label_valid"] and c["access_valid"] and c["fallback_reason"] is None for c in context["checks"]), "memory_annotation_fallback")
            equal([c["record_id"] for c in context["checks"]], [r["record_id"] for r in bundle], "memory_check_sources")
            equal(context["prepare_metadata"]["label_requirements"], {"expected_builder_version": builds[sid]["builder_version"], "expected_detector_version": identity["union_detector_revision"]}, "annotation_version_binding")
            seeds += [(r["record_id"], f["start"], f["end"], f["category"]) for r in bundle for f in r["label"]["findings"]]
            generation.verify_coverage(detection, {"__query__": task["query"], **{r["record_id"]: r["text"] for r in bundle}}, seeds, policy)
            alias = re.fullmatch(r"m_([A-F0-9]{24})_1", payload["memories"][0]["source_id"])
            require(alias is not None, "shared_nonce_alias")
            equal(payload, query.reconstruct_payload(task["query"], bundle, detection["findings"], alias.group(1)), "masked_payload_not_exact_detection")
            if context["role_evidence_status"] == "ok":
                cards = check_cards(context["role_cards"], payload, constants["ALIASES"])
                equal(context["role_evidence_metadata"], {"version": constants["VERSION"], "card_count": len(cards), "payload_sha256": digest(payload),
                    "policy_sha256": digest({"full_input": story["policy"], "normalized": policy}), "record_scope_sha256": digest(bundle), "cards_sha256": digest(cards)}, "role_evidence_scope")
            else:
                require(context["role_evidence_status"] == "blocked" and context["role_cards"] == [] and context["role_evidence_metadata"] == {}, "blocked_role_evidence_exported")
        else:
            require(context["outbound"] is None and context["actual_payload_sha256"] is None and context["role_cards"] == [] and context["role_evidence_metadata"] == {}, "blocked_context_payload")
            if not bundle:
                equal(context["prepare_error"], "label_set_unavailable", "missing_labels_denominator")
            elif task["actor_id"] != "owner":
                require(context["prepare_error"] == "principal_not_authorized" and not indices, "outsider_model_before_auth")
        equal(context["role_cards_sha256"], digest(context["role_cards"]), "shared_cards_hash")
    require(observed == set(range(len(observations))), "unallocated_query_observation")
    assigned = set()
    free_prompt = literal_constant(paths["memory_migration_study/budget.py"], "MEMORY_PROMPTS")["memory_fact_query_v2"]
    for row in rows:
        sid, tid, arm = row["story_id"], row["task_id"], row["arm"]
        context, task, bundle, story = contexts[row["context_id"]], tasks[(sid, tid)], records[sid], stories[sid]
        for name in ("context_id", "story_id", "task_id", "actor_id", "request_id", "prepare_status", "prepare_error", "actual_payload_sha256", "role_cards_sha256", "record_scope_sha256"):
            equal(row[name], context[name], "row_shared_context")
        equal((row["language"], row["template_family"], row["task_class"], row["common_build_status"]), (story["language"], story["template_family"], task["task_class"], builds[sid]["status"]), "row_story_context")
        selected = row["answer_request_indices"]
        require(len(selected) == row["answer_calls"] <= 1 and not assigned.intersection(selected) and (arm != "Q0" or not selected), "answer_count_allocation")
        assigned.update(selected)
        ready = context["prepare_status"] == "ok"
        payload = context["outbound"]
        if selected:
            require(ready and task["actor_id"] == "owner", "model_before_authorization")
            request, terminal = requests[selected[0]], terminals[selected[0]]
            equal(tuple(request[k] for k in ("stage", "arm", "story_id", "task_id")), ("answer", arm, sid, tid), "actual_task_model_context")
            if arm == "F":
                equal(request["request"]["messages"], [{"role": "system", "content": free_prompt}, {"role": "user", "content": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))}], "actual_free_payload")
            else:
                query_only_request(request["request"], payload["query"], prompt=constants["SYSTEM_PROMPT"], schema=constants["ROLE_SCHEMA"], definitions=constants["ROLE_DEFINITIONS"])
            if terminal["phase"] == "response":
                raw = terminal["response"].get("message", {}).get("content")
                equal(row["raw_model_answer"], raw, "full_raw_model_answer")
                if row["answer_status"] == "ok":
                    shared.successful_envelope(terminal["response"])
            else:
                require(row["answer_status"] != "ok" and row["raw_model_answer"] is None, "model_failure_promoted")
        else:
            require(row["raw_model_answer"] is None, "raw_answer_without_post")
        classification = row["classification"]
        if arm == "F":
            require(classification is None, "free_classification_added")
            if row["answer_status"] == "ok":
                require(selected and isinstance(row["raw_model_answer"], str), "free_missing_raw_output")
                equal(row["resolved_answer"], row["raw_model_answer"].strip(), "free_answer_rewritten")
        elif classification is not None:
            equal((classification["version"], classification["query_sha256"], classification["local_calls"]),
                  (constants["VERSION"], sha(payload["query"]), row["answer_calls"]), "classification_scope")
            equal(classification["source"], "lexical" if arm == "Q0" else "query_only_local_model", "classification_source")
            if selected and terminals[selected[0]]["phase"] == "response":
                physical = terminals[selected[0]]["response"]
                valid_role = None
                try:
                    shared.successful_envelope(physical)
                    valid_role = strict_role(physical["message"]["content"], constants["ROLES"])
                except (KeyError, ValueError, TypeError):
                    pass
                if valid_role is not None:
                    require(classification["status"] == "ok" and classification["error"] is None
                        and classification["errors"] == [], "valid_role_response_reclassified_as_failure")
                    equal(classification["role"], valid_role, "classification_not_raw_role")
            if classification["status"] == "ok":
                role = dictionary_role(payload["query"], constants["QUERY_ALIASES"], constants["STATUS_QUESTION_PATTERNS"], constants["MULTI_ROLE_CONNECTOR_PATTERN"]) if arm == "Q0" else strict_role(row["raw_model_answer"], constants["ROLES"])
                equal(classification["role"], role, "classification_not_raw_or_lexical")
                answer = resolve_unique(role, context["role_cards"])
                resolution = row["resolution"]
                values = {c["value"] for c in context["role_cards"] if c["role"] == role}
                reason = "unknown_query_role" if role == "UNKNOWN" else "no_role_value" if not values else "conflicting_role_values" if len(values) != 1 else "unique_role_value"
                sources = sorted({c["source_id"] for c in context["role_cards"] if c["role"] == role}) if reason == "unique_role_value" else []
                equal((resolution["answer"], resolution["decision_reason"], resolution["source_ids"], resolution["role"], resolution["local_calls"], resolution["version"]),
                      (answer, reason, sources, role, 0, constants["VERSION"]), "host_join_not_exact_unique_evidence")
                require(resolution["status"] == row["answer_status"] == "ok" and resolution["error"] is None, "invalid_resolution_accepted")
                equal(row["resolved_answer"], answer, "resolved_answer_not_role_join")
            else:
                require(row["answer_status"] != "ok" and row["resolved_answer"] is None and row.get("resolution") is None, "failed_classification_promoted")
        if row["answer_status"] == "ok":
            require(ready and row["resolved_answer"] is not None and row["restoration_status"] in {"ok", "blocked"}, "answer_without_restore")
            expected, decision = canonical(row["resolved_answer"], payload)
            equal(row["canonicalization"], {"answer": expected, "decision": decision}, "canonical_not_exact_current_token")
            span.check_restore(expected, row["restoration_status"], row["final_answer"], {"payload": payload}, bundle)
            if arm == "F":
                strict = row["strict_restoration"]
                equal(row["strict_final_answer"], strict["answer"], "strict_free_result_changed")
                span.check_restore(row["resolved_answer"], strict["status"], strict["answer"], {"payload": payload}, bundle)
        else:
            require(row["final_answer"] is None and row["restoration_status"] is None, "unprocessed_task_promoted")
        reference = gold[sid]["answers"].get(tid) if task["task_class"] == "legal" else None
        equal(row["required_fact_retained"], bool(reference and any(reference in r["text"] for r in bundle)), "required_fact_retained")
        mask = base.independent_masking(story, task, gold[sid], bundle, payload, False) if ready else base.blocked_masking(story, gold[sid], bundle)
        equal(row["masking"], mask, "independent_registered_masking")
        equal(row["score"], independent_score(row, task, gold[sid]), "independent_score")
    require(assigned == {i for i, e in requests.items() if e["stage"] == "answer"}, "unallocated_task_post")
    journal = data["auth_events"]
    equal([e["sequence"] for e in journal], list(range(1, len(journal)+1)), "auth_sequence")
    require(len(journal) >= 2 and [e["kind"] for e in journal[-2:]] == ["model_phase_closed", "evaluation_loaded"], "evaluation_before_model_closure")
    equal(journal[-2]["actual_generation_attempts"], len(requests), "model_closure_call_count")
    equal(journal[-1]["evaluation_sha256"], plan["evaluation_sha256"], "scoring_input_not_frozen")
    operations = defaultdict(list)
    for event in journal[:-2]:
        require(event["kind"] in {"prepare_start", "prepare_end", "access_check", "task_processing_end"}, "unexpected_auth_event")
        operations[event["operation"]].append(event)
    require(set(operations) == {cid+":shared" for cid in contexts} | {r["context_id"]+":"+r["arm"] for r in rows}, "auth_operation_matrix")
    for cid, context in contexts.items():
        operation, bundle = operations[cid+":shared"], records[context["story_id"]]
        require(operation[0]["kind"] == "prepare_start" and operation[-1]["kind"] == "prepare_end" and all(e["kind"] == "access_check" for e in operation[1:-1]), "shared_prepare_auth_order")
        equal(operation[0]["record_ids"], [r["record_id"] for r in bundle], "shared_prepare_exact_records")
        checks = operation[1:-1]
        require(all(e["record_id"] in {r["record_id"] for r in bundle} and e["actor_id"] == context["actor_id"]
                and e["agent_id"] == "target-agent" and e["policy_version"] == stories[context["story_id"]]["policy"]["version"] for e in checks), "shared_authority_context")
        if not bundle:
            require(not checks, "missing_records_auth_checks")
        elif context["actor_id"] != "owner":
            require(len(checks) == 1 and checks[0]["error"] == "principal_not_authorized", "outsider_denial_not_native")
        else:
            require(len(checks) >= len(bundle) and all(e["error"] is None for e in checks), "shared_current_authorization")
        for arm in ARMS:
            values = operations[cid+":"+arm]
            require(values[-1]["kind"] == "task_processing_end" and values[0]["sequence"] > operation[-1]["sequence"]
                and all(e["kind"] == "access_check" for e in values[:-1]), "task_before_shared_prepare")
            row = next(r for r in rows if r["context_id"] == cid and r["arm"] == arm)
            checks = values[:-1]
            require(all(e["record_id"] in {r["record_id"] for r in bundle} and e["actor_id"] == row["actor_id"]
                    and e["agent_id"] == "target-agent" and e["policy_version"] == stories[row["story_id"]]["policy"]["version"] and e["error"] is None for e in checks), "task_current_authorization")
            if row["restoration_status"] is not None:
                require(len(checks) >= (3 if arm == "F" else 2)*len(bundle), "restore_without_current_auth")
            equal((values[-1]["prepare_status"], values[-1]["answer_calls"]), (row["prepare_status"], row["answer_calls"]), "task_auth_end")
    report = data["report"]
    equal(report["arms"], aggregate(rows), "independent_aggregate")
    counts = Counter(e["stage"] for e in requests.values())
    buildenc = sum(b["inference_counts"]["local_encoder"] for b in builds.values())
    writeenc = sum(a["inference_counts"]["local_encoder"] for a in data["annotations"])
    for name, expected in {"registered_rows": 144, "recorded_rows": 144, "shared_contexts": 48, "source_stories": 8,
        "registered_tasks": 48, "common_build_failures": sum(b["status"] != "ok" for b in builds.values()),
        "union_label_set_failures": sum(not r for r in records.values()), "generation_calls_observed": len(requests),
        "generation_calls_by_stage": dict(counts), "generation_calls_by_arm": {a: sum(e["stage"] == "answer" and e["arm"] == a for e in requests.values()) for a in ARMS},
        "build_encoder_calls": buildenc, "write_annotation_encoder_calls": writeenc, "query_prepare_encoder_calls": total_query_encoders,
        "total_encoder_calls": buildenc+writeenc+total_query_encoders, "detector_call_accounting_complete": True,
        "implementation_unchanged": True, "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0, "scope": plan["scope"]}.items():
        equal(report[name], expected, "report_total_"+name)
    audit, network = data["transport_audit"], data["network_audit"]
    require(audit["completed"] is True and audit["recovery_mapping_recorded"] is False and audit["closed_phase_attempts"] == 0, "transport_audit_completion")
    for name, expected in {"physical_generation_attempts": len(requests), "responses": sum(e["phase"] == "response" for e in terminals.values()),
        "transport_errors": sum(e["phase"] == "failure" for e in terminals.values()), "actual_token_budget_violations": 0,
        "registered_generation_cap": LIMITS["total"], "cloud_calls": 0, "new_api_cost_cny": 0, "generation_calls_by_stage": dict(counts)}.items():
        equal(audit[name], expected, "audit_actual_"+name)
    equal(audit["network"], network, "network_summary")
    require(network["external_attempts_blocked"] == 0 and type(network["loopback_connections"]) is int and network["loopback_connections"] >= 0, "external_network")
    costs = defaultdict(lambda: {"physical_calls": 0, "prompt_tokens": 0, "output_tokens": 0, "request_json_utf8_bytes": 0})
    for index, request in requests.items():
        cell = costs[(request["stage"], request["arm"])]
        cell["physical_calls"] += 1
        cell["request_json_utf8_bytes"] += request["wire_json_utf8_bytes"]
        if terminals[index]["phase"] == "response":
            cell["prompt_tokens"] += terminals[index]["response"]["prompt_eval_count"]
            cell["output_tokens"] += terminals[index]["response"]["eval_count"]
    return {"version": "independent_role_query_transfer_v1", "status": "passed", "registered_rows": 144, "shared_contexts": 48,
        "physical_generation_attempts": len(requests), "current_snapshot_identical": identical, "query_encoder_calls": total_query_encoders,
        "total_encoder_calls": buildenc+writeenc+total_query_encoders, "arms": aggregate(rows), "verification_model_calls": 0,
        "physical_costs": [{"stage": stage, "arm": arm, **values} for (stage, arm), values in sorted(costs.items())],
        "evidence_sha256": {name+".json": sha((run/(name+".json")).read_bytes()) for name in names},
        "transport_sha256": sha((run/"request_transport.jsonl").read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()),
        "limits": ["Evidence consistency is not effect acceptance, novelty, execution authenticity or general semantic privacy.",
                   "Only exposed synthetic development stories and one-host memory operations; no fresh acceptance or native backend proof.",
                   "Public authorization observations are checked; destroyed HMAC keys and recovery tables are not reconstructed."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--corpus", type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), "new_verification_output_required")
    result = verify(args.run, corpus=args.corpus)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, allow_nan=False)
    print(json.dumps({"status": result["status"], "rows": result["registered_rows"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
