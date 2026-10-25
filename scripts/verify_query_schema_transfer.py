"""Independent, zero-inference audit of the paired query-schema development run.

Archives are parsed as data/AST, never executed. Public hashes and logs establish
consistency, not authenticity of destroyed signing keys or general privacy.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from copy import deepcopy
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import verify_span_answer_transfer as span
from scripts import verify_reference_memory_study as base
from scripts import verify_generation_union_transfer as generation
from scripts import verify_policy_semantic_study as shared

digest, sha, require, equal, integer = base.digest, base.sha, base.require, base.equal, base.integer
VERSION = "query_schema_transfer_development_v1"
ARMS = ("A", "B")
LIMITS = {"total": 224, "build": 16, "write_annotation": 128, "answer": 80}
FIELDS = ("correct", "joint_correct_no_masking_gap", "model_chose_unknown", "unknown_with_required_fact",
          "secondary_correct", "secondary_joint_correct_no_masking_gap", "outsider_blocked", "unauthorized_output", "restoration_failure")


def archive(run, plan, root):
    paths, identical = {}, True
    for name, expected in plan["implementation_sha256"].items():
        rel = Path(name.replace("\\", "/"))
        require(not rel.is_absolute() and ".." not in rel.parts and rel.suffix == ".py", "unsafe_archive_path")
        saved, current = (run/"implementation"/rel).resolve(), (root/rel).resolve()
        require(saved.is_relative_to(run/"implementation") and current.is_relative_to(root)
                and sha(saved.read_bytes()) == expected, "archive_hash_changed")
        paths[rel.as_posix()] = saved
        identical = identical and current.is_file() and sha(current.read_bytes()) == expected
    require(set(paths) == {p.relative_to(run/"implementation").as_posix() for p in (run/"implementation").rglob("*.py")}, "archive_inventory")
    needed = {"scripts/"+n for n in ("run_query_schema_transfer.py", "run_span_answer_transfer.py", "run_customer_schema_probe.py",
        "run_generation_union_transfer.py", "run_policy_semantic_study.py", "run_reference_memory_study.py", "run_boundary_transfer_diagnostic.py")}
    require(needed <= set(paths) and {"memory_migration_study/"+n for n in ("privacy.py", "ner_detector.py", "budget.py", "reference_memory.py", "local_detector.py")} <= set(paths), "archive_missing_dependency")
    identical = identical and {"memory_migration_study/"+p.name for p in (root/"memory_migration_study").glob("*.py")} == {n for n in paths if n.startswith("memory_migration_study/")}
    driver = paths["scripts/run_query_schema_transfer.py"]
    equal(base._literal_assignment(driver, "VERSION"), VERSION, "archived_version")
    tree = ast.parse(driver.read_text(encoding="utf-8-sig"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    loops = [n for n in fn.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "story"]
    closes = [n for n in fn.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "model_phase_closed" for t in n.targets)]
    parses = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "loads" and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "evaluation_bytes"]
    require(len(loops) == len(closes) == len(parses) == 1 and loops[0].end_lineno < closes[0].lineno < parses[0].lineno
            and isinstance(closes[0].value, ast.Constant) and closes[0].value.value is True, "evaluation_before_model_closure")
    calls = defaultdict(list)
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
            calls[n.func.id].append(n)
    require(len(calls["prepare_labeled_transfer"]) == len(calls["answerer"]) == len(calls["_current_access"]) == 1
            and calls["prepare_labeled_transfer"][0].lineno < calls["_current_access"][0].lineno < calls["answerer"][0].lineno
            and len(calls["restore_labeled_answer"]) == 2 and calls["answerer"][0].lineno < min(n.lineno for n in calls["restore_labeled_answer"]), "archived_auth_restore_order")
    patches = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "patch" and n.func.attr == "object"]
    require(len(patches) == 1 and isinstance(patches[0].args[0], ast.Name) and patches[0].args[0].id == "privacy"
            and isinstance(patches[0].args[1], ast.Constant) and patches[0].args[1].value == "secrets"
            and isinstance(patches[0].args[2], ast.Call) and isinstance(patches[0].args[2].func, ast.Name) and patches[0].args[2].func.id == "SimpleNamespace"
            and {k.arg for k in patches[0].args[2].keywords} == {"token_hex"}, "nonce_proxy_not_privacy_local")
    guard = next(n for n in ast.walk(fn) if isinstance(n, ast.FunctionDef) and n.name == "paired_token_hex")
    require("type(n) is not int or n != 12 or nonce_calls" in ast.unparse(guard)
            and "nonce_calls.append(12)" in ast.unparse(guard), "nonce_guard_missing")
    authority = ast.parse(paths["scripts/run_policy_semantic_study.py"].read_text(encoding="utf-8-sig"))
    cls = next(n for n in authority.body if isinstance(n, ast.ClassDef) and n.name == "AuditedAuthority")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "validate_access")
    real = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "validate_access" and isinstance(n.func.value, ast.Call) and isinstance(n.func.value.func, ast.Name) and n.func.value.func.id == "super"]
    logged = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "event"]
    require(len(real) == len(logged) == 1 and real[0].lineno < logged[0].lineno, "authority_not_real_super")
    return paths, bool(identical)


def fixed_schemas(paths):
    labels = base._literal_assignment(paths["memory_migration_study/ner_detector.py"], "LABELS")
    customer = base._literal_assignment(paths["scripts/run_customer_schema_probe.py"], "B_CUSTOMER")
    variants = {"A": deepcopy(labels), "B": deepcopy(labels)}
    variants["B"]["CUSTOMER"] = customer
    policy = base.normalized_policy(base._literal_assignment(paths["scripts/run_customer_schema_probe.py"], "POLICY"))
    return variants, policy


def ledger(events, stories, tasks):
    # Reuse independently implemented physical transport checks; only the answer
    # arm labels differ. Recheck this experiment's narrower cap after projection.
    projected = [dict(e, arm="free" if e["stage"] == "answer" else e["arm"]) for e in events]
    _, _ = span.ledger(projected, stories, tasks)
    requests = {e["index"]: e for e in events if e["phase"] == "request"}
    terminals = {e["index"]: e for e in events if e["phase"] != "request"}
    require(all(e["arm"] in ARMS for e in requests.values() if e["stage"] == "answer"), "answer_arm")
    stages = Counter(e["stage"] for e in requests.values())
    require(len(requests) <= LIMITS["total"] and all(stages[k] <= v for k, v in LIMITS.items() if k != "total"), "generation_cap224")
    return requests, terminals


def query_observation(event, row, task, policy, variants):
    equal((event["context_id"], event["operation"], event["story_id"], event["task_id"], event["arm"], event["source_id"]),
          (row["context_id"], row["context_id"]+":"+row["arm"], row["story_id"], row["task_id"], row["arm"], "__query__"), "query_encoder_context")
    equal((event["text"], event["text_sha256"], event["policy_sha256"]), (task["query"], sha(task["query"]), digest(policy)), "query_encoder_input")
    old, actual = variants["A"]["CUSTOMER"], variants[row["arm"]]["CUSTOMER"]
    equal(event["requested_labels"], {old[0]: old[1]}, "query_requested_schema")
    equal(event["actual_labels"], {actual[0]: actual[1]}, "query_actual_schema")
    equal(event["full_schema_sha256"], digest(variants[row["arm"]]), "query_full_schema_hash")
    equal(event["label_translation"], {actual[0]: old[0]}, "query_label_translation")
    equal(event["runtime_infer_attempts"], 1, "query_runtime_attempts")
    count = integer(event["extract_entities_calls"], "query_physical_count")
    require(count <= 1, "query_repeated_encoder")
    encoded = event["encoding_observations"]
    for observation in encoded:
        require(type(observation["input_ids"]) is int and observation["input_ids"] >= 0 and observation["max_len"] is None, "query_truncation")
    require(type(event["elapsed_seconds"]) in (int, float) and math.isfinite(event["elapsed_seconds"]) and event["elapsed_seconds"] >= 0, "query_elapsed")
    if event["status"] != "ok":
        require(event["status"] == "needs_review" and event["translated_result"] is None and row["prepare_status"] != "ok", "query_failure_accepted")
        if encoded and encoded[0]["input_ids"] > 512:
            require(count == 0 and event["error"] == "input_budget_exceeded", "query_overflow_forward")
        return [], count
    require(count == 1 and encoded and all(o["input_ids"] <= 512 for o in encoded) and event["error"] is None, "query_unverified_preflight")
    raw = event["raw_result"]
    require(isinstance(raw, dict) and set(raw) == {"entities"} and isinstance(raw["entities"], dict) and not(set(raw["entities"])-{actual[0]}), "query_raw_envelope")
    entities = raw["entities"].get(actual[0], [])
    require(isinstance(entities, list), "query_raw_entities")
    equal(event["translated_result"], {"entities": {old[0]: entities}}, "query_translation_changed_entity")
    seeds = []
    for entity in entities:
        require(isinstance(entity, dict), "query_raw_span")
        a, b, text, confidence = (entity.get(k) for k in ("start", "end", "text", "confidence"))
        require(type(a) is int and type(b) is int and 0 <= a < b <= len(task["query"]) and task["query"][a:b] == text
                and type(confidence) in (int, float) and math.isfinite(confidence) and .5 <= confidence <= 1, "query_raw_span")
        seeds.append(("__query__", a, b, "CUSTOMER"))
    return seeds, count


def reconstruct_payload(query, records, findings, nonce):
    """Reconstruct actual masks from public offsets, never a recovery map."""
    sources = {"__query__": query, **{r["record_id"]: r["text"] for r in records}}
    intervals, categories = {}, {}
    for sid, text in sources.items():
        merged = []
        for f in sorted((f for f in findings if f["source_id"] == sid), key=lambda f: (f["start"], f["end"])):
            a, b = f["start"], f["end"]
            require(type(a) is int and type(b) is int and 0 <= a < b <= len(text), "mask_span_bounds")
            if merged and a < merged[-1][1]:
                merged[-1][1] = max(b, merged[-1][1])
                merged[-1][2].add(f["category"])
            else:
                merged.append([a, b, {f["category"]}])
        intervals[sid] = merged
        for a, b, cats in merged:
            categories.setdefault(text[a:b].casefold(), set()).update(cats)
    tokens = {value: "[PVT_"+nonce+"_"+(next(iter(cats)) if len(cats) == 1 else "MIXED")+"_"+str(i)+"]"
              for i, (value, cats) in enumerate(categories.items(), 1)}
    transformed = {}
    for sid, text in sources.items():
        pieces, cursor = [], 0
        for a, b, _ in intervals[sid]:
            pieces.extend((text[cursor:a], tokens[text[a:b].casefold()]))
            cursor = b
        transformed[sid] = "".join(pieces)+text[cursor:]
    return {"query": transformed["__query__"], "memories": [{"source_id": "m_"+nonce+"_"+str(i), "text": transformed[r["record_id"]]} for i, r in enumerate(records, 1)]}


def aggregate(rows):
    result = {}
    for arm in ARMS:
        result[arm] = {}
        for kind in ("legal", "missing", "outsider"):
            group = [r for r in rows if r["arm"] == arm and r["task_class"] == kind]
            result[arm][kind] = {"registered_tasks": len(group), **{f: sum(r["score"][f] for r in group) for f in FIELDS},
                "answer_calls": sum(r["answer_calls"] for r in group), "prepare_blocked": sum(r["prepare_status"] != "ok" for r in group),
                "label_set_unavailable": sum(r["union_label_set_status"] != "ok" for r in group),
                "by_language": {lang: {"tasks": sum(r["language"] == lang for r in group), "correct": sum(r["language"] == lang and r["score"]["correct"] for r in group)} for lang in ("en", "zh")}}
    return result


def verify(directory, *, corpus=None, project_root=None):
    run, root = Path(directory).resolve(), Path(project_root or ROOT).resolve()
    names = ("plan", "runtime", "evaluation", "config", "runtime_identity", "controls", "builds", "annotations", "record_store", "pools", "paired_contexts", "query_encoder_events", "rows", "report", "auth_events", "transport_audit", "network_audit")
    values = {n: json.loads((run/(n+".json")).read_bytes()) for n in names}
    for value in values.values():
        span.no_private_objects(value)
    plan, runtime, gold, rows = (values[n] for n in ("plan", "runtime", "evaluation", "rows"))
    require(plan["version"] == VERSION and plan["score_schema_version"] == "query_schema_final_answer_v1" and plan["ordering_seed"] == 2026102519
            and plan["registered_tasks"] == 48 and plan["expected_rows"] == 96 and plan["legal_per_arm"] == 32 and plan["missing_per_arm"] == plan["outsider_per_arm"] == 8
            and plan["prepare_mode"] == "generation" and plan["privacy_pipeline"] == "legacy" and plan["evaluation_timing"] == "after_all_model_processing_and_model_phase_closed", "registered_protocol")
    equal(plan["arms"], list(ARMS), "registered_arms")
    equal(plan["generation_limits"], LIMITS, "registered_limits")
    equal((plan["threshold"], plan["splitter"], plan["max_encoded_tokens"]), (.5, "cjk_aware", 512), "registered_encoder_config")
    require(len(runtime) == len({s["story_id"] for s in runtime}) == 8 and Counter(s["language"] for s in runtime) == {"en": 4, "zh": 4}, "story_matrix")
    stories = {s["story_id"]: s for s in runtime}
    require(set(stories) == set(gold), "gold_story_matrix")
    for story in runtime:
        require("@" not in story["source"]["text"] and len(story["tasks"]) == len({t["task_id"] for t in story["tasks"]}) == 5
                and span.CONTROL not in {t["task_id"] for t in story["tasks"]} and Counter(t["actor_id"] for t in story["tasks"]) == {"owner": 4, "outsider": 1}, "runtime_control_precondition")
    tasks = span.task_map(stories)
    equal(values["controls"], [{"story_id": sid, "language": s["language"], **tasks[(sid, span.CONTROL)], "expected_answer": "UNKNOWN"} for sid, s in stories.items()], "fixed_missing_controls")
    equal((plan["missing_control"]["queries"], plan["missing_control"]["expected_answer"]), (span.QUERIES, "UNKNOWN"), "missing_reference")
    corpus = Path(corpus or root/"examples/privacy_semantics_v1")
    for n, snapshot in (("runtime", runtime), ("evaluation", gold)):
        original = (corpus/"development"/(n+".json")).read_bytes()
        equal(sha(original), plan[n+"_sha256"], "original_input_hash")
        equal(json.loads(original), snapshot, "input_snapshot")
    equal(digest(values["config"]), plan["config_sha256"], "configuration_hash")
    config = values["config"]
    require(config["endpoint"] == "http://127.0.0.1:11435" and config["model"] == base.MODEL and config["expected_digest"] == base.MODEL_DIGEST and config["expected_version"] == "0.40.8", "pinned_model")
    paths, identical = archive(run, plan, root)
    variants, policy = fixed_schemas(paths)
    equal(plan["schemas"], variants, "frozen_query_schemas")
    equal(plan["schema_sha256"], {a: digest(s) for a, s in variants.items()}, "schema_hashes")
    equal(plan["approved_policy"], policy, "approved_policy")
    require(all(base.normalized_policy(s["policy"]) == policy for s in runtime), "policy_scope")
    identity = values["runtime_identity"]
    equal(identity["local_generation"], {"version": "0.40.8", "model": base.MODEL, "digest": base.MODEL_DIGEST, "endpoint": "http://127.0.0.1:11435"}, "model_identity")
    equal(identity["union_detector_revision"], "sha256:"+digest(identity["union"]), "union_revision")
    require(set(identity["query_detectors"]) == set(ARMS), "query_identity_arms")
    for arm in ARMS:
        adapter = identity["query_detectors"][arm]
        proxy = adapter["query"]["runtime"]
        equal(proxy["original_runtime"], identity["ner"], "query_changed_model_weights")
        equal((proxy["query_schema_arm"], proxy["actual_schema"], proxy["schema_sha256"]), (arm, variants[arm], digest(variants[arm])), "query_identity_schema")
        equal((proxy["approved_policy_sha256"], proxy["splitter"], proxy["threshold"], proxy["max_encoded_tokens"]), (digest(policy), "cjk_aware", .5, 512), "query_identity_contract")
        equal(proxy["proxy_source_sha256"], sha(paths["scripts/run_query_schema_transfer.py"].read_bytes()), "query_identity_source")
        equal((adapter["source_sha256"], adapter["approved_policy"]), (proxy["proxy_source_sha256"], policy), "query_adapter_binding")
        for detector in (adapter["query"], adapter["fallback"]):
            equal((detector["labels"], detector["splitter"], detector["threshold"], detector["policy_contracts"], detector["adapter_sha256"]),
                  (variants["A"], "cjk_aware", .5, [digest(policy)], sha(paths["memory_migration_study/ner_detector.py"].read_bytes())), "query_default_host_adapter")
        equal(adapter["fallback"]["runtime"], identity["ner"], "fallback_changed_model_weights")
    require(len(rows) == 96 and {(r["story_id"], r["task_id"], r["arm"]) for r in rows} == {(s, t, a) for s, t in tasks for a in ARMS}, "answer_matrix")
    pairs = values["paired_contexts"]
    require(len(pairs) == len({p["context_id"] for p in pairs}) == 48 and {(p["story_id"], p["task_id"]) for p in pairs} == set(tasks), "paired_matrix")
    pairs = {p["context_id"]: p for p in pairs}
    events = [json.loads(line) for line in (run/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    requests, terminals = ledger(events, stories, tasks)
    builds, records = span.constructions(values, stories, paths, requests, terminals)
    observations = values["query_encoder_events"]
    equal([e["event_index"] for e in observations], list(range(len(observations))), "query_event_sequence")
    assigned, observed, paired_rows, bodies = set(), set(), defaultdict(dict), defaultdict(dict)
    prompt = base._literal_assignment(paths["memory_migration_study/budget.py"], "MEMORY_PROMPTS")["memory_fact_query_v2"]
    for row in rows:
        sid, tid, arm = row["story_id"], row["task_id"], row["arm"]
        story, task, bundle = stories[sid], tasks[(sid, tid)], records[sid]
        cid = sid+":"+tid
        pair = pairs[cid]
        equal({k: row[k] for k in pair}, pair, "row_paired_context")
        equal((pair["context_id"], pair["actor_id"], pair["task_class"], pair["records_sha256"]), (cid, task["actor_id"], task["task_class"], digest(bundle)), "paired_task_records")
        require(all(isinstance(pair[k], str) and re.fullmatch(r"[a-f0-9]{64}", pair[k]) for k in ("request_sha256", "paired_nonce_sha256")), "paired_scope_hash")
        equal((row["language"], row["template_family"], row["mode"], row["common_build_status"]), (story["language"], story["template_family"], "generation", builds[sid]["status"]), "row_source_binding")
        equal(row["union_label_set_status"], "ok" if bundle else "needs_review" if builds[sid]["status"] == "ok" else "not_run", "row_union_status")
        equal((row["prepare_generation_calls_observed"], row["inference_counts"]["local_generation"], row["inference_counts"]["unknown"]), (0, 0, 0), "prepare_generation_or_unknown_cost")
        indices = row["query_encoder_event_indices"]
        require(len(indices) <= 1 and not observed.intersection(indices), "query_event_allocation")
        observed.update(indices)
        seeds, calls = [], 0
        for i in indices:
            require(type(i) is int and 0 <= i < len(observations), "query_event_index")
            found, count = query_observation(observations[i], row, task, policy, variants)
            seeds.extend(found)
            calls += count
        equal(row["inference_counts"]["local_encoder"], calls, "query_encoder_count")
        ready = row["prepare_status"] == "ok"
        if ready:
            require(task["actor_id"] == "owner" and bundle and len(indices) == 1, "unauthorized_prepare")
            equal(row["serialization_nonce_calls"], 1, "ready_nonce_count")
            require(row["egress"]["status"] == "ok", "egress_not_passed")
            equal(row["actual_payload_sha256"], digest(row["outbound"]), "outbound_hash")
            require(len(row["outbound"]["memories"]) == len(bundle), "outbound_sources")
            memory_alias = row["outbound"]["memories"][0]["source_id"]
            m = re.fullmatch(r"m_([A-F0-9]{24})_1", memory_alias)
            require(m is not None, "nonce_source_alias")
            nonce = m.group(1)
            equal(sha(nonce.lower()), pair["paired_nonce_sha256"], "paired_nonce_mismatch")
            detection = row["detection"]
            original = {"query": task["query"], "memories": [{"source_id": r["record_id"], "text": r["text"]} for r in bundle]}
            equal((detection["payload_sha256"], detection["policy_sha256"]), (digest(original), digest(policy)), "detection_binding")
            require(detection["status"] == "ok" and detection["errors"] == [] and detection["local_calls_complete"] is True, "dirty_detection_accepted")
            equal(detection["local_calls"], calls, "detection_physical_calls")
            equal(row["prepare_metadata"]["label_requirements"], {"expected_builder_version": builds[sid]["builder_version"], "expected_detector_version": identity["union_detector_revision"]}, "generation_label_requirements")
            require(row["prepare_metadata"]["transfer_mode"] == "generation" and "detection_cache" not in row["prepare_metadata"]
                    and len(row["checks"]) == len(bundle) and all(c["label_valid"] and c["access_valid"] and c["fallback_reason"] is None for c in row["checks"]), "query_only_claim_has_memory_fallback")
            equal([c["record_id"] for c in row["checks"]], [r["record_id"] for r in bundle], "label_check_sources")
            seeds += [(r["record_id"], f["start"], f["end"], f["category"]) for r in bundle for f in r["label"]["findings"]]
            generation.verify_coverage(detection, {"__query__": task["query"], **{r["record_id"]: r["text"] for r in bundle}}, seeds, policy)
            equal(row["outbound"], reconstruct_payload(task["query"], bundle, detection["findings"], nonce), "mask_not_exact_detection")
        else:
            require(row["outbound"] is None and row["actual_payload_sha256"] is None and row["serialization_nonce_calls"] == 0, "blocked_payload_or_nonce")
            if not bundle:
                require(row["prepare_error"] == "label_set_unavailable" and not indices, "unavailable_labels_as_authority_denial")
            elif task["actor_id"] != "owner":
                require(row["prepare_error"] == "principal_not_authorized" and not indices, "outsider_inference_before_auth")
        selected = row.get("answer_request_indices", [])
        require(len(selected) == row["answer_calls"] <= 1 and not assigned.intersection(selected), "answer_count_allocation")
        assigned.update(selected)
        require(row["secondary_serialization_registered"] is True, "secondary_unregistered")
        if selected:
            require(ready, "answer_before_prepare")
            e, terminal = requests[selected[0]], terminals[selected[0]]
            equal(tuple(e[k] for k in ("stage", "arm", "story_id", "task_id")), ("answer", arm, sid, tid), "actual_answer_context")
            messages = [{"role": "system", "content": prompt}, {"role": "user", "content": json.dumps(row["outbound"], ensure_ascii=False, separators=(",", ":"))}]
            equal(e["request"]["messages"], messages, "actual_answer_input")
            require(len(messages[0]["content"].encode())+len(messages[1]["content"].encode())+320+64 <= 4096, "answer_preflight_budget")
            bodies[cid][arm] = e["request"]
            if terminal["phase"] == "response":
                raw = terminal["response"].get("message", {}).get("content")
                equal(row["raw_model_answer"], raw, "full_raw_answer")
                if row["answer_status"] == "ok":
                    shared.successful_envelope(terminal["response"])
                    require(isinstance(raw, str) and raw.strip(), "empty_answer")
                    equal(row["model_answer"], raw.strip(), "answer_altered_before_restore")
            else:
                require(row["answer_status"] != "ok" and row["raw_model_answer"] is None, "failed_transport_as_answer")
        else:
            require(row["raw_model_answer"] is None and row["model_answer"] is None, "answer_without_call")
        if row["answer_status"] == "ok":
            require(selected and row["restoration_status"] in {"ok", "blocked"}, "answer_without_restoration")
            context = {"payload": row["outbound"]}
            span.check_restore(row["model_answer"], row["restoration_status"], row["final_answer"], context, bundle)
            second = row["secondary_serialization"]
            tokens = {m.group() for text in [row["outbound"]["query"]]+[s["text"] for s in row["outbound"]["memories"]] for m in base.TOKEN.finditer(text)}
            answer = row["model_answer"]
            add = span.BARE.fullmatch(answer.strip()) is not None and "["+answer.strip()+"]" in tokens
            equal((second["decision"], second["canonical_answer"]), ("added_outer_brackets" if add else "unchanged", "["+answer.strip()+"]" if add else answer), "secondary_not_exact_same_output")
            if add:
                require(row["restoration_status"] == "blocked" and row["final_answer"] is None, "secondary_overwrote_primary")
            span.check_restore(second["canonical_answer"], second["restoration_status"], second["final_answer"], context, bundle)
        else:
            require(row["model_answer"] is None and row["final_answer"] is None and row["restoration_status"] is None and "secondary_serialization" not in row, "failed_model_promoted")
        reference = gold[sid]["answers"].get(tid) if task["task_class"] == "legal" else None
        equal(row["required_fact_retained"], bool(reference and any(reference in r["text"] for r in bundle)), "required_fact_retention")
        mask = base.independent_masking(story, task, gold[sid], bundle, row["outbound"], False) if ready else base.blocked_masking(story, gold[sid], bundle)
        equal(row["masking"], mask, "independent_literal_masking")
        equal(row["score"], span.assess(row, task, gold[sid]), "independent_score")
        paired_rows[cid][arm] = row
    require(observed == set(range(len(observations))), "unallocated_query_encoder")
    require(assigned == {i for i, e in requests.items() if e["stage"] == "answer"}, "unallocated_answer_post")
    pair_stats = Counter()
    for cid, group in paired_rows.items():
        a, b = group["A"], group["B"]
        equal(a["request_sha256"], b["request_sha256"], "paired_request_mismatch")
        equal(a["paired_nonce_sha256"], b["paired_nonce_sha256"], "paired_nonce_mismatch")
        if a["prepare_status"] == b["prepare_status"] == "ok":
            pair_stats["ready_pairs"] += 1
            same_detection = digest(a["detection"]["findings"]) == digest(b["detection"]["findings"])
            same_payload = digest(a["outbound"]) == digest(b["outbound"])
            if same_detection:
                require(same_payload, "same_findings_different_paired_payload")
            pair_stats["same_final_findings"] += same_detection
            pair_stats["identical_outbound"] += same_payload
            pair_stats["changed_outbound"] += not same_payload
            if same_payload and set(bodies[cid]) == set(ARMS):
                equal(bodies[cid]["A"], bodies[cid]["B"], "same_payload_different_answer_request")
                pair_stats["identical_actual_answer_request"] += 1
                pair_stats["different_raw_output_despite_identical_request"] += a["raw_model_answer"] != b["raw_model_answer"]
    journal = values["auth_events"]
    equal([e["sequence"] for e in journal], list(range(1, len(journal)+1)), "auth_sequence")
    require(journal and journal[-1]["kind"] == "model_phase_closed", "model_closure")
    operations = defaultdict(list)
    for e in journal[:-1]:
        require(e["kind"] in {"prepare_start", "access_check", "task_processing_end"}, "unexpected_auth_event")
        operations[e["operation"]].append(e)
    require(set(operations) == {r["context_id"]+":"+r["arm"] for r in rows}, "auth_operation_matrix")
    for row in rows:
        op, bundle = operations[row["context_id"]+":"+row["arm"]], records[row["story_id"]]
        require(op[0]["kind"] == "prepare_start" and op[-1]["kind"] == "task_processing_end" and all(e["kind"] == "access_check" for e in op[1:-1]), "auth_task_order")
        equal(op[0]["record_ids"], [r["record_id"] for r in bundle], "auth_exact_records")
        equal({k: op[0][k] for k in pairs[row["context_id"]]}, pairs[row["context_id"]], "auth_pair_binding")
        equal((op[-1]["prepare_status"], op[-1]["answer_calls"]), (row["prepare_status"], row["answer_calls"]), "auth_end_summary")
        checks = op[1:-1]
        require(all(e["record_id"] in {r["record_id"] for r in bundle} and e["actor_id"] == row["actor_id"] and e["agent_id"] == "target-agent" and e["policy_version"] == stories[row["story_id"]]["policy"]["version"] for e in checks), "auth_context")
        if not bundle:
            require(not checks, "failed_build_as_authority_denial")
        elif row["actor_id"] != "owner":
            require(len(checks) == 1 and checks[0]["error"] == "principal_not_authorized", "outsider_not_real_denial")
        else:
            require(len(checks) >= len(bundle) and all(e["error"] is None for e in checks), "owner_missing_auth")
            equal([e["record_id"] for e in checks[:len(bundle)]], [r["record_id"] for r in bundle], "prepare_auth_sources")
            if row["answer_calls"]:
                require(len(checks) >= 2*len(bundle), "answer_without_current_auth")
            if row["restoration_status"] is not None:
                require(len(checks) >= 4*len(bundle), "restore_without_current_auth")
    equal(journal[-1]["actual_generation_attempts"], len(requests), "closure_calls")
    report, audit, network = (values[n] for n in ("report", "transport_audit", "network_audit"))
    equal(report["arms"], aggregate(rows), "independent_aggregate")
    stages = Counter(e["stage"] for e in requests.values())
    buildenc = sum(b["inference_counts"]["local_encoder"] for b in builds.values())
    writeenc = sum(a["inference_counts"]["local_encoder"] for a in values["annotations"])
    queryenc = {a: sum(r["inference_counts"]["local_encoder"] for r in rows if r["arm"] == a) for a in ARMS}
    totals = {"version": VERSION, "registered_rows": 96, "recorded_rows": 96, "source_stories": 8, "registered_tasks": 48,
        "common_build_failures": sum(b["status"] != "ok" for b in builds.values()), "union_label_set_failures": sum(not r for r in records.values()),
        "generation_calls_observed": len(requests), "builder_generations": stages["build"], "write_annotation_generations": stages["write_annotation"], "answer_generations": stages["answer"],
        "build_encoder_calls": buildenc, "write_annotation_encoder_calls": writeenc, "query_prepare_encoder_calls": queryenc,
        "query_model_extract_entities_calls": sum(e["extract_entities_calls"] for e in observations), "total_encoder_calls": buildenc+writeenc+sum(queryenc.values()),
        "detector_call_accounting_complete": True, "implementation_unchanged": True, "default_labels_unchanged": True, "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0}
    for k, expected in totals.items():
        equal(report[k], expected, "report_total_"+k)
    equal(report["scope"], plan["scope"], "report_scope")
    responses = [e for e in terminals.values() if e["phase"] == "response"]
    require(audit["completed"] is True and audit["registered_protocol"] == VERSION and audit["recovery_mapping_recorded"] is False, "audit_completion")
    for k, expected in {"physical_generation_attempts": len(requests), "responses": len(responses), "transport_errors": len(terminals)-len(responses),
        "actual_token_budget_violations": 0, "registered_generation_cap": 224, "closed_phase_attempts": 0, "cloud_calls": 0, "new_api_cost_cny": 0}.items():
        equal(audit[k], expected, "audit_total_"+k)
    equal(audit["network"], network, "network_summary")
    require(network["external_attempts_blocked"] == 0 and type(network["loopback_connections"]) is int and network["loopback_connections"] >= 0, "external_network")
    cost = defaultdict(lambda: {"physical_calls": 0, "prompt_tokens": 0, "output_tokens": 0, "request_json_utf8_bytes": 0})
    for index, e in requests.items():
        cell = cost[(e["stage"], e["arm"])]
        cell["physical_calls"] += 1
        cell["request_json_utf8_bytes"] += e["wire_json_utf8_bytes"]
        if terminals[index]["phase"] == "response":
            cell["prompt_tokens"] += terminals[index]["response"]["prompt_eval_count"]
            cell["output_tokens"] += terminals[index]["response"]["eval_count"]
    return {"version": "independent_query_schema_transfer_v1", "status": "passed", "registered_rows": 96, "paired_contexts": 48,
        "physical_generation_attempts": len(requests), "current_snapshot_identical": identical, "arms": aggregate(rows), "paired_comparison": dict(pair_stats),
        "query_encoder_calls": queryenc, "total_encoder_calls": totals["total_encoder_calls"], "verification_model_calls": 0,
        "physical_costs": [{"stage": s, "arm": a, **v} for (s, a), v in sorted(cost.items())],
        "evidence_sha256": {n+".json": sha((run/(n+".json")).read_bytes()) for n in names}, "transport_sha256": sha((run/"request_transport.jsonl").read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()),
        "limits": ["Passing verifies evidence consistency, not effect acceptance, novelty, or execution authenticity.",
            "Exposed synthetic development with fixed CUSTOMER policy and source-only missing-email controls; not blind or native backend interoperability.",
            "Public source/ACL/label bindings and logged current authorization are checked; destroyed HMAC keys and recovery maps are not replayed.",
            "Offsets reconstruct masks independently; registered literal masking does not establish semantic privacy.",
            "Same-input output variation cannot be attributed to query schema; paired serialization randomness is an explicit counterfactual control."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--corpus", type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), "new_verification_output_required")
    result = verify(args.run, corpus=args.corpus)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
    print(json.dumps({"status": result["status"], "rows": result["registered_rows"], "calls": result["physical_generation_attempts"], "paired": result["paired_comparison"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
