"""Independent offline audit of common facts with two signed label sets.

No producer scorer/detector, model, signing key or restoration map is used.
Existing independent literal alignment and exact-source checks are reused.
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
from scripts import verify_policy_semantic_study as independent
from scripts.analyze_boundary_transfer_mechanisms import locate

VERSION = "generation_union_transfer_development_v1"
ARMS = {"M": ("ner", "migration", False), "U": ("ner", "migration", False),
        "G": ("union", "generation", False), "T": ("union", "two_stage", False)}
LIMITS = {"total": 848, "build": 16, "write_annotation": 128, "union_migration": 576, "answer": 128}
digest, sha, equal, require, integer = base.digest, base.sha, base.equal, base.require, base.integer
ENTITIES = frozenset(("PERSON", "ADDRESS", "CUSTOMER", "PROJECT"))


def aggregate(rows, label_sets):
    result = {}
    for arm, (family, _, _) in ARMS.items():
        # This independent shared-build aggregator has no model/producer code.
        projected = [dict(r, arm="baseline") for r in rows if r["arm"] == arm]
        result[arm] = independent.aggregate(projected, [s for s in label_sets if s["builder"] == family])["baseline"]
    return result


def archive(run, plan, root):
    paths, identical = {}, True
    for name, expected in plan["implementation_sha256"].items():
        relative = Path(name.replace("\\", "/"))
        require(not relative.is_absolute() and ".." not in relative.parts and relative.suffix == ".py", "unsafe_archive_path")
        path = (run/"implementation"/relative).resolve()
        require(path.is_relative_to((run/"implementation").resolve()) and sha(path.read_bytes()) == expected, "archive_hash_changed")
        current = (root/relative).resolve()
        require(current.is_relative_to(root), "unsafe_current_path")
        identical = identical and current.is_file() and sha(current.read_bytes()) == expected
        paths[relative.as_posix()] = path
    equal({p.relative_to(run/"implementation").as_posix() for p in (run/"implementation").rglob("*.py")} == set(paths), True, "archive_inventory")
    required = {"scripts/run_generation_union_transfer.py", "scripts/run_policy_semantic_study.py",
        "scripts/run_reference_memory_study.py", "scripts/run_boundary_transfer_diagnostic.py",
        "memory_migration_study/reference_memory.py", "memory_migration_study/memory_labels.py",
        "memory_migration_study/local_detector.py", "memory_migration_study/budget.py"}
    require(required <= set(paths), "archive_inventory_missing")
    identical = identical and {"memory_migration_study/"+p.name for p in (root/"memory_migration_study").glob("*.py")} == {p for p in paths if p.startswith("memory_migration_study/")}
    path = paths["scripts/run_generation_union_transfer.py"]
    equal(base._literal_assignment(path, "VERSION"), VERSION, "archived_driver_version")
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    run_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    loops = [n for n in run_fn.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "story"]
    closes = [n for n in run_fn.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "model_phase_closed" for t in n.targets)]
    gold = [n for n in ast.walk(run_fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "loads" and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "evaluation_bytes"]
    require(len(loops) == len(closes) == len(gold) == 1 and loops[0].end_lineno < closes[0].lineno < gold[0].lineno
        and isinstance(closes[0].value, ast.Constant) and closes[0].value.value is True, "gold_before_model_closure")
    authority_tree = ast.parse(paths["scripts/run_policy_semantic_study.py"].read_text(encoding="utf-8-sig"))
    authority = next(n for n in authority_tree.body if isinstance(n, ast.ClassDef) and n.name == "AuditedAuthority")
    fn = next(n for n in authority.body if isinstance(n, ast.FunctionDef) and n.name == "validate_access")
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "validate_access"
        and isinstance(n.func.value, ast.Call) and isinstance(n.func.value.func, ast.Name) and n.func.value.func.id == "super"]
    logs = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "event"]
    require(len(calls) == len(logs) == 1 and calls[0].lineno < logs[0].lineno, "auth_not_real_super")
    return paths, bool(identical)


def ascii_id(char):
    return char.isascii() and (char.isalnum() or char == "_")


def bounds(text, start, end, category):
    if category in ENTITIES:
        if ascii_id(text[start]):
            while start and ascii_id(text[start-1]):
                start -= 1
        while end < len(text) and ascii_id(text[end]):
            end += 1
    return start, end


def required_closure(sources, seeds, registry):
    """Independent coverage obligations for actual seeds and explicit registry.

    Check preservation/propagation, not equality to extra rule detections or
    the semantic correctness of a model's own category choices.
    """
    work = list(seeds)
    for entry in registry:
        for sid, text in sources.items():
            for match in re.finditer("(?="+re.escape(entry["value"])+")", text, re.I):
                a, b = match.start(), match.start()+len(entry["value"])
                if a and ascii_id(text[a-1]) and entry["value"][0].isascii() and entry["value"][0].isalnum():
                    continue
                if b < len(text) and ascii_id(text[b]) and entry["value"][-1].isascii() and entry["value"][-1].isalnum():
                    continue
                work.append((sid, a, b, entry["category"]))
    needed = set()
    for sid, a, b, category in work:
        a, b = bounds(sources[sid], a, b, category)
        needed.add((sid, a, b, category))
        value = sources[sid][a:b]
        for target, text in sources.items():
            for match in re.finditer("(?=("+re.escape(value)+"))", text, re.I):
                left, right = match.span(1)
                if category in ENTITIES:
                    inside_left = left > 0 and ascii_id(text[left-1]) and ascii_id(value[0])
                    inside_right = right < len(text) and ascii_id(text[right]) and ascii_id(value[-1])
                    if inside_left and inside_right or value.isascii() and 0 < sum(ascii_id(c) for c in value) < 3 and (inside_left or inside_right):
                        continue
                left, right = bounds(text, left, right, category)
                needed.add((target, left, right, category))
    return needed


def verify_coverage(detection, sources, seeds, policy):
    covered = defaultdict(set)
    for span in detection["findings"]:
        sid, a, b, cat = (span[k] for k in ("source_id", "start", "end", "category"))
        require(sid in sources and type(a) is int and type(b) is int and 0 <= a < b <= len(sources[sid])
            and cat in policy["protected_categories"] and span["policy_id"] == policy["policy_id"], "detection_span_binding")
        covered[(sid, cat)].update(range(a, b))
    for sid, a, b, cat in required_closure(sources, seeds, policy["entity_registry"]):
        require(set(range(a, b)) <= covered[(sid, cat)], "seed_or_registry_closure_dropped")


def transport(events, stories, rows):
    requests, terminals, groups = {}, {}, defaultdict(list)
    row_keys = {(r["story_id"], r["task_id"], r["arm"]): r for r in rows}
    for event in events:
        base.no_secret_fields(event)
        index = integer(event["index"], "ledger_index")
        stage, arm, sid, tid = (event[k] for k in ("stage", "arm", "story_id", "task_id"))
        require(index > 0 and sid in stories and stage in {"build", "write_annotation", "union_migration", "answer"}, "ledger_context")
        if stage == "build":
            require(arm == "common" and tid is None, "build_context")
        elif stage == "write_annotation":
            require(arm == "union_labels" and tid is None, "write_context")
        else:
            require((sid, tid, arm) in row_keys and row_keys[(sid, tid, arm)]["actor_id"] == "owner", "unauthorized_model_context")
            require(stage != "union_migration" or arm == "U", "union_arm_context")
        key = (stage, arm, sid, tid)
        if event["phase"] == "request":
            require(index not in requests, "duplicate_request")
            requests[index] = event
            groups[key].append(event)
            body = event["request"]
            equal(digest(body), event["request_sha256"], "request_hash")
            encoded = json.dumps(body, ensure_ascii=False).encode()
            equal(len(encoded), event["wire_json_utf8_bytes"], "wire_bytes")
            equal(sha(encoded), event["wire_json_utf8_sha256"], "wire_hash")
            require(set(body) == {"model", "messages", "stream", "keep_alive", "options"} | (set() if stage == "answer" else {"format"}), "request_extra_fields")
            equal(body["options"], {"num_ctx": 4096, "num_predict": 64 if stage == "answer" else 1024, "temperature": 0, "seed": 42}, "request_options")
            require(body["model"] == base.MODEL and body["stream"] is False and body["keep_alive"] == "30m"
                and event["scope"] == "synthetic_development_local_only" and "JSON body only" in event["wire_encoding"], "request_configuration")
        else:
            require(event["phase"] in {"response", "failure"} and index in requests and index not in terminals, "orphan_terminal")
            original = requests[index]
            equal(key, tuple(original[k] for k in ("stage", "arm", "story_id", "task_id")), "terminal_context")
            equal(event["request_sha256"], original["request_sha256"], "terminal_request_hash")
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
                equal(event["error"], "physical_transport_failed", "failure_code")
    require(set(requests) == set(terminals) == set(range(1, len(requests)+1)) and len(requests) <= 848, "physical_post_denominator")
    counts = Counter(e["stage"] for e in requests.values())
    require(all(counts[k] <= limit for k, limit in LIMITS.items() if k != "total"), "stage_post_cap")
    return requests, terminals, groups


def detection_input(event, text, policy, paths):
    body, policy = event["request"], base.normalized_policy(policy)
    data = json.loads(body["messages"][1]["content"])
    equal(data, {"text": text, "local_candidates": []}, "detector_input_not_exact_text")
    expected = base._literal_assignment(paths["memory_migration_study/local_detector.py"], "SYSTEM_PROMPT")+"\n\nTrusted sensitivity policy JSON:\n"+json.dumps(
        {k: policy[k] for k in ("version", "protected_categories", "instructions")}, ensure_ascii=False, separators=(",", ":"))
    equal(body["messages"][0], {"role": "system", "content": expected}, "detector_system_policy")
    schema = {"type": "object", "additionalProperties": False, "required": ["status", "findings"], "properties": {
        "status": {"type": "string", "enum": ["ok", "needs_review"]}, "findings": {"type": "array", "maxItems": 32,
            "items": {"type": "object", "additionalProperties": False, "required": ["quote", "category"],
                "properties": {"quote": {"type": "string", "minLength": 1}, "category": {"type": "string", "enum": policy["protected_categories"]}}}}}}
    equal(body["format"], schema, "detector_schema")
    require(len(body["messages"]) in {2, 3}, "detector_message_count")
    if len(body["messages"]) == 3:
        tree = ast.parse(paths["memory_migration_study/local_detector.py"].read_text(encoding="utf-8-sig"))
        repairs = [n.value.value for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "repair" for t in n.targets)
                   and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)]
        require(len(repairs) == 1, "archived_detector_repair")
        equal(body["messages"][2], {"role": "user", "content": repairs[0]}, "detector_repair_input")


def verify(directory, *, corpus=None, project_root=None):
    run, root = Path(directory).resolve(), Path(project_root or ROOT).resolve()
    names = ("plan", "runtime", "evaluation", "config", "runtime_identity", "pools", "builds", "label_sets", "record_store",
             "annotations", "fact_bindings", "rows", "report", "auth_events", "transport_audit", "network_audit")
    values = {n: json.loads((run/(n+".json")).read_bytes()) for n in names}
    for value in values.values():
        base.no_secret_fields(value)
    plan, runtime, gold, rows, builds, sets, stores = (values[n] for n in ("plan", "runtime", "evaluation", "rows", "builds", "label_sets", "record_store"))
    require(plan["version"] == VERSION and plan["expected_rows"] == 160 and plan["legal_per_arm"] == 32 and plan["outsider_per_arm"] == 8
        and plan["score_schema_version"] == 2 and plan["split"] == "development" and plan["max_facts_per_story"] == 8
        and plan["ordering_seed"] == 2026102511 and plan["privacy_pipeline"] == "legacy" and plan["query_intent"] is False
        and plan["cache_only_arm"] == "U" and plan["evaluation_timing"] == "after_model_phase_closed", "registered_protocol")
    equal(plan["arms"], {a: list(v) for a, v in ARMS.items()}, "registered_arms")
    equal(plan["generation_limits"], LIMITS, "registered_limits")
    require(len(runtime) == 8 and len({s["story_id"] for s in runtime}) == 8, "story_denominator")
    stories = {s["story_id"]: s for s in runtime}
    equal(set(stories) == set(gold), True, "evaluation_stories")
    for story in runtime:
        require(len(story["tasks"]) == len({t["task_id"] for t in story["tasks"]}) == 5 and
            Counter(t["actor_id"] for t in story["tasks"]) == {"owner": 4, "outsider": 1}, "story_task_matrix")
    corpus = Path(corpus or root/"examples/privacy_semantics_v1")
    for name, snapshot in (("runtime", runtime), ("evaluation", gold)):
        original = (corpus/"development"/(name+".json")).read_bytes()
        equal(sha(original), plan[name+"_sha256"], "original_input_hash")
        equal(json.loads(original), snapshot, "input_snapshot_changed")
    config = values["config"]
    equal(digest(config), plan["config_sha256"], "configuration_hash")
    require(config["endpoint"] == "http://127.0.0.1:11435" and config["model"] == base.MODEL and
        config["expected_digest"] == base.MODEL_DIGEST and config["expected_version"] == "0.40.8", "local_model_config")
    paths, current_identical = archive(run, plan, root)
    identity = values["runtime_identity"]
    equal(identity["local_generation"], {"version": "0.40.8", "model": base.MODEL, "digest": base.MODEL_DIGEST, "endpoint": "http://127.0.0.1:11435"}, "model_identity")
    equal(identity["ner_detector_revision"], "sha256:"+digest(identity["detector"]), "ner_revision")
    equal(identity["union_detector_revision"], "sha256:"+digest(identity["union"]), "union_revision")
    by_build = {b["story_id"]: b for b in builds}
    pools = {p["story_id"]: p["pool"] for p in values["pools"]}
    by_set = {(s["story_id"], s["builder"]): s for s in sets}
    records = {(s["story_id"], s["builder"]): s["records"] for s in stores}
    require(len(builds) == len(values["pools"]) == 8 and set(by_build) == set(pools) == set(stories), "common_build_matrix")
    require(len(sets) == len(stores) == 16 and set(by_set) == set(records) == {(sid, f) for sid in stories for f in ("ner", "union")}, "label_set_matrix")
    for sid, story in stories.items():
        base.verify_pool(story, pools[sid])
        build = by_build[sid]
        require(build["builder"] == "reference" and len(build["facts"]) <= 8, "common_builder")
        adapted = dict(build, candidate_pool_json_bytes=len(json.dumps(pools[sid], ensure_ascii=False).encode()))
        independent.verify_records(story, adapted, records[(sid, "ner")], pools[sid])
        require(build["inference_counts"]["local_generation"] == build["inference_counts"]["unknown"] == 0, "common_build_unknown_cost")
    expected = {(sid, t["task_id"], arm) for sid, story in stories.items() for t in story["tasks"] for arm in ARMS}
    require(len(rows) == 160 and {(r["story_id"], r["task_id"], r["arm"]) for r in rows} == expected, "task_matrix_denominator")
    events = [json.loads(line) for line in (run/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    requests, terminals, groups = transport(events, stories, rows)
    # Reuse the independent, source-only selector checker on a renumbered
    # projection. Request/response hashes and actual original indices remain
    # verified above; this does not rewrite any saved evidence.
    projected, next_index = [], 1
    for index, event in requests.items():
        if event["stage"] == "build":
            projected.extend([dict(event, index=next_index, arm="reference_id"), dict(terminals[index], index=next_index, arm="reference_id")])
            next_index += 1
    base._ledger(projected, [], [dict(b, builder="reference_id") for b in builds], stories, pools, paths)
    annotations = {(a["story_id"], a["fact_index"]): a for a in values["annotations"]}
    bindings = {(b["story_id"], b["fact_index"]): b for b in values["fact_bindings"]}
    required_annotations = {(sid, i) for sid, b in by_build.items() if b["status"] == "ok" for i in range(len(b["facts"]))}
    require(len(annotations) == len(values["annotations"]) == len(bindings) == len(values["fact_bindings"]) and
        set(annotations) == set(bindings) == required_annotations, "annotation_fact_matrix")
    allocated_write = set()
    for (sid, index), annotation in annotations.items():
        story, fact = stories[sid], by_build[sid]["facts"][index]
        source, policy = story["source"], base.normalized_policy(story["policy"])
        fact_identity = {"source_id": source["source_id"], "source_sha256": sha(source["text"]),
            "source_start": fact["source_start"], "source_end": fact["source_end"], "content_sha256": sha(fact["text"])}
        fact_key = digest(fact_identity)
        for item in (annotation, bindings[(sid, index)]):
            equal({k: item[k] for k in fact_identity}, fact_identity, "fact_source_identity")
            equal(item["fact_key"], fact_key, "fact_identity_hash")
            equal(item["fid"], fact["fid"], "fact_selected_fid")
        aid = "write_"+fact_key[:32]
        payload = {"query": "", "memories": [{"source_id": aid, "text": fact["text"]}]}
        equal(annotation["annotation_source_id"], aid, "annotation_source_alias")
        equal(annotation["input_payload"], payload, "annotation_input_not_exact_fact")
        equal(annotation["full_policy_sha256"], digest(story["policy"]), "annotation_full_policy")
        equal(annotation["policy_sha256"], digest(policy), "annotation_policy")
        detection = annotation["detection"]
        equal(annotation["errors"], detection["errors"], "annotation_error_receipt")
        equal(detection["payload_sha256"], digest(payload), "annotation_detection_payload")
        equal(detection["policy_sha256"], digest(policy), "annotation_detection_policy")
        selected = annotation["request_indices"]
        require(len(selected) <= 2 and len(selected) == len(set(selected)) and not allocated_write.intersection(selected), "annotation_post_allocation")
        allocated_write.update(selected)
        equal(annotation["generation_calls_observed"], len(selected), "annotation_physical_calls")
        equal(annotation["inference_counts"]["local_generation"], len(selected), "annotation_generation_count")
        equal(annotation["inference_counts"]["unknown"], 0, "annotation_unknown_cost")
        seeds, ner_calls = [], 0
        for member in annotation["member_raw_outputs"]:
            equal((member["source_id"], member["text_sha256"], member["policy_sha256"]), (aid, sha(fact["text"]), digest(policy)), "actual_ner_input")
            response = member["response"]
            require(not {"owner_id", "readers", "permissions", "authorization", "grants", "authority"}.intersection(response), "ner_authority_injection")
            ner_calls += integer(response["local_calls"], "actual_ner_calls")
            for f in response["findings"]:
                require(set(f) == {"start", "end", "quote", "category"}, "actual_ner_finding_fields")
                a, b = f["start"], f["end"]
                require(type(a) is int and type(b) is int and 0 <= a < b <= len(fact["text"])
                    and f["quote"] == fact["text"][a:b] and f["category"] in policy["protected_categories"], "actual_ner_span")
                seeds.append((aid, a, b, f["category"]))
        equal(annotation["inference_counts"]["local_encoder"], ner_calls, "annotation_encoder_count")
        equal(detection["local_calls"], ner_calls+len(selected), "annotation_total_calls")
        for n, post_index in enumerate(selected):
            event = requests[post_index]
            require((event["stage"], event["arm"], event["story_id"], event["fact_index"], event["fid"], event["fact_key"]) ==
                ("write_annotation", "union_labels", sid, index, fact["fid"], fact_key), "annotation_ledger_context")
            detection_input(event, fact["text"], story["policy"], paths)
            equal(len(event["request"]["messages"]), 2+n, "annotation_attempt_order")
        if annotation["status"] == "ok":
            require(detection["status"] == "ok" and detection["errors"] == [] and detection["local_calls_complete"] is True
                and all(m["response"]["status"] == "ok" for m in annotation["member_raw_outputs"]), "failed_member_signed_as_clean")
            if selected:
                terminal = terminals[selected[-1]]
                require(terminal["phase"] == "response", "clean_annotation_without_response")
                independent.successful_envelope(terminal["response"])
                raw = base.strict_json(terminal["response"]["message"]["content"])
                require(set(raw) == {"status", "findings"} and raw["status"] == "ok", "clean_annotation_raw_review")
                for f in raw["findings"]:
                    require(set(f) == {"quote", "category"} and f["category"] in policy["protected_categories"], "annotation_raw_fields")
                    quote = locate(f["quote"], fact["text"])
                    positions = [m.start() for m in re.finditer("(?="+re.escape(quote)+")", fact["text"])]
                    require(positions, "annotation_raw_quote_missing")
                    seeds.extend((aid, start, start+len(quote), f["category"]) for start in positions)
            verify_coverage(detection, {"__query__": "", aid: fact["text"]}, seeds, policy)
        else:
            equal(annotation["status"], "needs_review", "annotation_status")
        equal(bindings[(sid, index)]["annotation_status"], annotation["status"], "binding_annotation_status")
    equal(allocated_write == {i for i, e in requests.items() if e["stage"] == "write_annotation"}, True, "unallocated_annotation_post")
    for sid, story in stories.items():
        build = by_build[sid]
        ner_records, union_records = records[(sid, "ner")], records[(sid, "union")]
        eligible = bool(ner_records) and all(annotations[(sid, i)]["status"] == "ok" for i in range(len(build["facts"])))
        require(bool(union_records) == eligible, "failed_annotation_deployed_or_success_dropped")
        require(len(union_records) == (len(ner_records) if eligible else 0), "union_record_count")
        union_facts = []
        for i, fact in enumerate(build["facts"]):
            if build["status"] != "ok":
                break
            a, binding = annotations[(sid, i)], bindings[(sid, i)]
            equal(binding["ner_record_id"], ner_records[i]["record_id"], "binding_ner_record")
            equal(binding["union_record_id"], union_records[i]["record_id"] if eligible else None, "binding_union_record")
            equal(a["eligible_for_store"], eligible, "annotation_deployment_flag")
            equal(a["group_status"], "ok" if eligible else "needs_review", "annotation_group_status")
            union_facts.append(dict(fact, findings=[{k: f[k] for k in ("start", "end", "category")} for f in a["detection"]["findings"]], status="ok"))
        if eligible:
            adapted = dict(build, facts=union_facts, stored_characters=sum(len(r["text"]) for r in union_records),
                stored_record_json_bytes=len(json.dumps(union_records, ensure_ascii=False).encode()),
                stored_source_copy_characters=sum(len(r["source"]["text"]) for r in union_records))
            independent.verify_records(story, adapted, union_records, pools[sid])
        for family, bundle in (("ner", ner_records), ("union", union_records)):
            label_set = by_set[(sid, family)]
            equal(label_set["status"], "ok" if bundle else "needs_review", "label_set_status")
            equal(label_set["annotation_status"], "not_applicable" if family == "ner" else
                "ok" if eligible else "needs_review" if ner_records else "not_run", "label_set_annotation_status")
            equal(label_set["common_build_status"], build["status"], "label_set_common_build")
            require(label_set["common_construction_shared"] is True and label_set["local_calls"] == build["local_calls"], "common_construction_recharged")
            revision = identity["ner_detector_revision" if family == "ner" else "union_detector_revision"]
            equal(label_set["detector_revision"], revision, "label_set_revision")
            for record in bundle:
                equal(record["label"]["detector_version"], revision, "signed_detector_revision")
            for key, value in {"stored_characters": sum(len(r["text"]) for r in bundle),
                "stored_record_json_bytes": len(json.dumps(bundle, ensure_ascii=False).encode()),
                "stored_source_copy_characters": sum(len(r["source"]["text"]) for r in bundle), "source_characters": len(story["source"]["text"])}.items():
                equal(label_set[key], value, "label_set_volume")
    for row in rows:
        sid, arm = row["story_id"], row["arm"]
        story = stories[sid]
        task = next(t for t in story["tasks"] if t["task_id"] == row["task_id"])
        family, mode, _ = ARMS[arm]
        bundle, label_set = records[(sid, family)], by_set[(sid, family)]
        equal((row["mode"], row["label_family"], row["actor_id"], row["language"], row["template_family"]),
            (mode, family, task["actor_id"], story["language"], story["template_family"]), "row_runtime_binding")
        require(row["privacy_pipeline"] == "legacy" and row["intent_applied"] is False and row["secondary_serialization_registered"] is True, "row_protocol")
        equal(row["build_status"], label_set["status"], "row_label_set_status")
        equal(row["common_build_status"], by_build[sid]["status"], "row_common_build_status")
        equal(row["union_label_set_status"], by_set[(sid, "union")]["annotation_status"], "row_union_label_status")
        equal(set(row["inference_counts"]) == set(base.KINDS), True, "inference_kinds")
        for value in row["inference_counts"].values():
            integer(value, "inference_count")
        equal(row["inference_counts"]["unknown"], 0, "unknown_cost")
        prep_posts = groups.get(("union_migration", arm, sid, task["task_id"]), [])
        equal(row["prepare_generation_calls_observed"], len(prep_posts), "row_prepare_physical_count")
        equal(row["inference_counts"]["local_generation"], len(prep_posts), "row_prepare_generation_count")
        equal(row["detector_calls"], sum(row["inference_counts"].values()), "row_detector_count")
        for event in prep_posts:
            text = json.loads(event["request"]["messages"][1]["content"])["text"]
            require(text in [task["query"]]+[r["text"] for r in bundle], "migration_input_not_authorized_text")
            detection_input(event, text, story["policy"], paths)
        answers = groups.get(("answer", arm, sid, task["task_id"]), [])
        equal(row["answer_calls"], len(answers), "answer_physical_count")
        require(len(answers) <= 1 and (not answers or row["prepare_status"] == "ok"), "answer_before_preparation")
        if answers:
            event = answers[0]
            prompts = base._literal_assignment(paths["memory_migration_study/budget.py"], "MEMORY_PROMPTS")
            equal(event["request"]["messages"], [{"role": "system", "content": prompts["memory_fact_query_v2"]},
                {"role": "user", "content": json.dumps(row["outbound"], ensure_ascii=False, separators=(",", ":"))}], "answer_messages")
            equal(row["actual_payload_sha256"], digest(row["outbound"]), "outbound_hash")
            if row.get("answer_status") == "ok":
                terminal = terminals[event["index"]]
                require(terminal["phase"] == "response", "answer_without_response")
                independent.successful_envelope(terminal["response"])
                equal(terminal["response"]["message"]["content"].strip(), row["model_answer"], "raw_answer_changed")
        if arm in {"G", "T"} and row["actor_id"] == "owner" and bundle:
            expected_requirements = {"expected_builder_version": by_build[sid]["builder_version"], "expected_detector_version": identity["union_detector_revision"]}
            equal(row["prepare_metadata"]["label_requirements"], expected_requirements, "generation_label_requirements")
            require(len(row["checks"]) == len(bundle) and all(c["label_valid"] is True and c["access_valid"] is True for c in row["checks"]), "invalid_label_reused")
            sources = {"__query__": task["query"], **{r["record_id"]: r["text"] for r in bundle}}
            seeds = [(r["record_id"], f["start"], f["end"], f["category"]) for r in bundle for f in r["label"]["findings"]]
            verify_coverage(row["detection"], sources, seeds, base.normalized_policy(story["policy"]))
        mask = base.independent_masking(story, task, gold[sid], bundle, row["outbound"], False) if row["prepare_status"] == "ok" else base.blocked_masking(story, gold[sid], bundle)
        equal(mask, row["masking"], "independent_masking_mismatch")
        expected_answer = gold[sid]["answers"].get(row["task_id"])
        equal(row["required_fact_retained"], bool(expected_answer and any(expected_answer in r["text"] for r in bundle)), "fact_retention")
        base._verify_secondary(row)
        equal(row["score"], base.independent_score(row, gold[sid]), "independent_score_mismatch")
    journal = values["auth_events"]
    equal([e["sequence"] for e in journal], list(range(1, len(journal)+1)), "auth_sequence")
    operations = defaultdict(list)
    require(journal and journal[-1]["kind"] == "model_phase_closed", "model_phase_closure_event")
    for event in journal[:-1]:
        require(event["kind"] in {"prepare_start", "access_check", "task_processing_end"}, "unexpected_auth_event")
        operations[event["operation"]].append(event)
    require(len(operations) == 160, "auth_operation_matrix")
    for row in rows:
        sid, tid, arm = row["story_id"], row["task_id"], row["arm"]
        op = operations[f"{sid}:{tid}:{arm}"]
        bundle = records[(sid, ARMS[arm][0])]
        require(op[0]["kind"] == "prepare_start" and op[-1]["kind"] == "task_processing_end", "auth_operation_order")
        require(all(e["kind"] == "access_check" for e in op[1:-1]), "duplicate_auth_operation_boundary")
        equal(op[0]["record_ids"], [r["record_id"] for r in bundle], "auth_selected_record_set")
        equal(op[0]["record_set_sha256"], digest(bundle), "auth_selected_record_hash")
        equal((op[0]["actor_id"], op[0]["agent_id"]), (row["actor_id"], "target-agent"), "auth_principals")
        checks = [e for e in op if e["kind"] == "access_check"]
        require(all(e["actor_id"] == row["actor_id"] and e["agent_id"] == "target-agent" and e["record_id"] in op[0]["record_ids"] for e in checks), "auth_check_identity")
        if not bundle:
            require(not checks and row["prepare_error"] == "label_set_unavailable" and not row["answer_calls"], "missing_labels_as_auth_denial")
        elif row["actor_id"] != "owner":
            require(checks and checks[0]["error"] == "principal_not_authorized" and row["answer_calls"] == 0
                and row["inference_counts"] == dict.fromkeys(base.KINDS, 0), "outsider_not_real_denial")
        else:
            require({e["record_id"] for e in checks if e["error"] is None} == set(op[0]["record_ids"])
                and all(e["error"] is None for e in checks), "owner_record_authorization")
        equal((op[-1]["prepare_status"], op[-1]["answer_calls"]), (row["prepare_status"], row["answer_calls"]), "auth_task_end")
    equal(journal[-1]["actual_generation_attempts"], len(requests), "model_closure_call_count")
    cache_rows = [dict(r, arm="union" if r["arm"] == "U" else "other") for r in rows]
    cache = independent.union_cache_stats(cache_rows)
    report, audit, network = (values[n] for n in ("report", "transport_audit", "network_audit"))
    equal(report["arms"], aggregate(rows, sets), "independent_aggregate_mismatch")
    stage_counts = Counter(e["stage"] for e in requests.values())
    totals = {"version": VERSION, "registered_rows": 160, "recorded_rows": 160, "source_stories": 8,
        "common_fact_constructions": 8, "label_set_instances": 16, "generation_calls_observed": len(requests),
        "common_build_failures": sum(b["status"] != "ok" for b in builds),
        "union_label_set_failures": sum(s["builder"] == "union" and s["status"] != "ok" for s in sets),
        "builder_generations": stage_counts["build"], "write_annotation_generations": stage_counts["write_annotation"],
        "union_migration_generations": stage_counts["union_migration"], "answer_generations": stage_counts["answer"],
        "build_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds),
        "write_annotation_encoder_calls": sum(a["inference_counts"]["local_encoder"] for a in annotations.values()),
        "total_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds)+sum(a["inference_counts"]["local_encoder"] for a in annotations.values())+sum(r["inference_counts"]["local_encoder"] for r in rows),
        "union_label_stories_ready": sum(s["builder"] == "union" and s["status"] == "ok" for s in sets),
        "request_wire_json_bytes": sum(e["wire_json_utf8_bytes"] for e in requests.values()),
        "detector_call_accounting_complete": True, "implementation_unchanged": True, "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0}
    for key, expected_value in totals.items():
        equal(report[key], expected_value, "report_total_"+key)
    operation_costs = {arm: {"encoder_calls": sum(r["inference_counts"]["local_encoder"] for r in rows if r["arm"] == arm),
        "generation_calls": sum(r["prepare_generation_calls_observed"] for r in rows if r["arm"] == arm),
        "answer_calls": sum(r["answer_calls"] for r in rows if r["arm"] == arm),
        "union_cache_hits": sum((r.get("prepare_metadata") or {}).get("detection_cache", {}).get("hits", 0) for r in rows if r["arm"] == arm)} for arm in ARMS}
    equal(report["per_arm_operation_costs"], operation_costs, "operation_cost_partition")
    equal((report["scope"], report["cost_scope"]), (plan["scope"], plan["cost_scope"]), "scope_changed")
    response_count = sum(e["phase"] == "response" for e in terminals.values())
    require(audit["completed"] is True and audit["registered_protocol"] == VERSION and audit["recovery_mapping_recorded"] is False, "audit_completion")
    for key, expected_value in {"physical_generation_attempts": len(requests), "responses": response_count,
        "transport_errors": len(terminals)-response_count, "actual_token_budget_violations": 0,
        "registered_generation_cap": 848, "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0}.items():
        equal(audit[key], expected_value, "audit_total_"+key)
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
    return {"version": "independent_generation_union_transfer_v1", "status": "passed", "registered_rows": 160,
        "legal_per_arm": 32, "outsider_per_arm": 8, "common_fact_constructions": 8, "label_sets": 16,
        "annotation_facts_checked": len(annotations), "physical_generation_attempts": len(requests),
        "current_snapshot_identical": current_identical, "arms": aggregate(rows, sets), "union_cache": cache,
        "physical_costs": [{"stage": stage, "arm": arm, **v} for (stage, arm), v in sorted(costs.items())],
        "verification_model_calls": 0, "evidence_sha256": {n+".json": sha((run/(n+".json")).read_bytes()) for n in names},
        "transport_sha256": sha((run/"request_transport.jsonl").read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()),
        "limits": ["Passing is evidence consistency, not an effectiveness acceptance threshold or novelty claim.",
            "Two signed labels share exact source facts and authority; they are not independent sources or new grants.",
            "Raw actual member seeds, explicit registry and bounded propagation are independently checked for preservation; extra rule spans are evaluated by literal masking, not a separate proof of all rule grammar.",
            "Public hashes/signature shapes do not authenticate destroyed HMAC keys or reconstruct private recovery maps.",
            "Authorization logs, frozen code and literal masking cover controlled same-host JSON handoff, not native backend interoperability or semantic privacy."]}


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
