"""Read-only zero-model verification of the paired source-card reader study.

Saved evidence and mechanism replay are distinct. Original authority secrets and
map objects were intentionally not persisted. A temporary independent authority
re-signs identical grant/label data to replay equivalent preparation, projection
and original restoration; this does NOT authenticate the original HMACs.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import re
import socket
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

VERSION = "independent_source_card_reader_verification_v1"
STUDY_VERSION = "full_context_source_fact_reader_development_v1"
ARMS = ("F", "Flat-ID", "Source-ID")
SEED = 2026102604
LIMITS = {"build": 16, "write_annotation": 128, "answer": 120}
TOKEN = re.compile(r"\[PVT_([A-F0-9]{24})_(?:PERSON|ADDRESS|CUSTOMER|PROJECT|EMAIL|PHONE|ID|AMOUNT|DATE|MIXED)_[1-9][0-9]*\]")
PRIVATE_KEYS = {"mapping", "_mapping", "_entries", "_nonce", "authority_key", "hmac_key", "private_key",
    "secret_key", "recovery_map", "restoration_map", "source_table", "_MemoryLabelAuthority__secret"}
ERRORS = (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, AssertionError,
    StopIteration, RecursionError, OverflowError)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 80 * 1024 * 1024:
        raise ValueError("artifact_missing_linked_or_too_large")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def same(left, right):
    return json.dumps(left, ensure_ascii=False, sort_keys=True, allow_nan=False) == json.dumps(
        right, ensure_ascii=False, sort_keys=True, allow_nan=False)


def clean_times(value):
    if isinstance(value, dict):
        return {key: clean_times(item) for key, item in value.items() if key not in {"elapsed_seconds", "agent_elapsed_seconds"}}
    return [clean_times(item) for item in value] if isinstance(value, list) else value


def digest(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def _walk_keys(value, forbidden):
    if isinstance(value, dict):
        return not (set(value) & forbidden) and all(_walk_keys(item, forbidden) for item in value.values())
    return not isinstance(value, list) or all(_walk_keys(item, forbidden) for item in value)


def _tasks(story):
    return [{**task, "task_class": "legal" if task["actor_id"] == "owner" else "outsider"} for task in story["tasks"]] + [
        {"task_id": "missing_contact_email_control", "actor_id": "owner", "query":
            "What is the contact email address?" if story["language"] == "en" else "联系人的电子邮箱地址是什么？", "task_class": "missing"}]


def _phase_order(source):
    tree = ast.parse(source)
    run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
    closes = [node.lineno for node in ast.walk(run) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
            and target.value.id == "observer" and target.attr == "model_phase_closed" for target in node.targets)
        and isinstance(node.value, ast.Constant) and node.value.value is True]
    gold = [node.lineno for node in ast.walk(run) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "evaluation" for target in node.targets)
        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "loads"]
    scoring = [node.lineno for node in ast.walk(run) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id in {"score", "score_masking"}]
    return len(closes) == len(gold) == 1 and bool(scoring) and closes[0] < gold[0] < min(scoring)


def _declaration(source):
    tree = ast.parse(source)
    return next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "REGISTERED_DEPENDENCIES" for target in node.targets))


def _record_copy(record, authority):
    # New signatures only: original grants/labels remain byte-equivalent JSON.
    clone = deepcopy(record)
    for domain, key in (("access", "access_signature"), ("label", "label_signature")):
        if not isinstance(clone.get(key), str) or re.fullmatch(r"[a-f0-9]{64}", clone[key]) is None:
            raise ValueError("invalid_saved_signature_representation")
        clone[key] = authority._sign(domain, clone[domain])
    return clone


def _coverage(original, masked, entries):
    """Independent monotone replacement alignment into original characters."""
    covered, before, after = set(), 0, 0
    for match in TOKEN.finditer(masked):
        unchanged = masked[after:match.start()]
        if original[before:before+len(unchanged)] != unchanged:
            raise ValueError("independent_mask_prefix_mismatch")
        before += len(unchanged)
        value = entries[match.group()].value
        if original[before:before+len(value)].casefold() != value.casefold():
            raise ValueError("independent_mask_value_mismatch")
        covered.update(range(before, before+len(value)))
        before += len(value)
        after = match.end()
    if original[before:] != masked[after:]:
        raise ValueError("independent_mask_suffix_mismatch")
    return covered


def _mask_score(story, gold, records, prepared):
    source_gold = {position for span in gold["sensitive_spans"] for position in range(span["start"], span["end"])}
    retained = {position for record in records for position in range(record["source_start"], record["source_end"])}
    original_spans = [set(range(span["start"], span["end"])) for span in gold["sensitive_spans"]]
    result = {"source_sensitive_characters": len(source_gold), "retained_sensitive_characters": len(source_gold & retained),
        "missing_extraction_sensitive_characters": len(source_gold-retained), "ready": False,
        "fully_retained_source_spans": sum(span <= retained for span in original_spans),
        "partially_retained_source_spans": sum(bool(span & retained) and not span <= retained for span in original_spans),
        "missing_source_spans": sum(not span & retained for span in original_spans), "retained_gold_spans": 0,
        "complete": None, "partial": None, "unmasked": None, "extra_masked_characters": None}
    if not prepared or prepared.get("status") != "ok":
        return result
    original, outbound = prepared["original_payload"], prepared["payload"]
    covered, sensitive = set(), set()
    for before, after in zip(original["memories"], outbound["memories"]):
        covered.update((before["source_id"], position) for position in _coverage(before["text"], after["text"], prepared["mapping"]._entries))
    covered.update(("__query__", position) for position in _coverage(original["query"], outbound["query"], prepared["mapping"]._entries))
    spans = []
    for span in gold["sensitive_spans"]:
        for record in records:
            a, b = max(span["start"], record["source_start"]), min(span["end"], record["source_end"])
            if a < b:
                spans.append(({(record["record_id"], position-record["source_start"]) for position in range(a, b)},
                    a != span["start"] or b != span["end"]))
        value = story["source"]["text"][span["start"]:span["end"]]
        for match in re.finditer(re.escape(value), original["query"], re.I):
            item = ({("__query__", position) for position in range(match.start(), match.end())}, False)
            if item not in spans:
                spans.append(item)
    complete = partial = unmasked = 0
    for characters, truncated in spans:
        sensitive |= characters
        if characters <= covered and not truncated:
            complete += 1
        elif characters & covered:
            partial += 1
        else:
            unmasked += 1
    result.update(ready=True, retained_gold_spans=len(spans), complete=complete, partial=partial,
        unmasked=unmasked, extra_masked_characters=len(covered-sensitive))
    return result


def _score(row, expected):
    authorized = row["actor_id"] == "owner"
    final = row.get("final_answer")
    unknown = row.get("model_response_status") == "ok" and (
        (row["arm"] == "F" and (row.get("raw_model_answer") or "").strip() == "UNKNOWN")
        or (row["arm"] != "F" and row.get("card_decision") == "UNKNOWN"))
    exact = authorized and isinstance(final, str) and final.strip().casefold() == expected.casefold()
    correct = exact and (row["task_class"] != "missing" or unknown)
    mask = row["masking"]
    gap_free = mask.get("ready") is True and mask.get("partial") == mask.get("unmasked") == 0
    strict = row.get("strict_final_answer")
    return {"correct": bool(correct), "joint_correct_no_masking_gap": bool(correct and gap_free),
        "model_chose_unknown": bool(unknown), "host_join_unknown": row["arm"] != "F" and row.get("resolved_answer") == "UNKNOWN",
        "unknown_with_required_fact": row["task_class"] == "legal" and row["required_fact_retained"] and final == "UNKNOWN",
        "strict_F_correct": bool(row["arm"] == "F" and isinstance(strict, str) and strict.strip().casefold() == expected.casefold()),
        "outsider_blocked": row["task_class"] == "outsider" and row.get("prepare_error") == "principal_not_authorized" and row["answer_calls"] == 0,
        "unauthorized_output": not authorized and (row["answer_calls"] > 0 or bool(final)),
        "restoration_failure": row.get("restoration_status") == "blocked"}


def _aggregate(rows):
    result = {}
    for arm in ARMS:
        result[arm] = {}
        for kind in ("legal", "missing", "outsider"):
            group = [row for row in rows if row["arm"] == arm and row["task_class"] == kind]
            keys = next(iter(group))["score"]
            result[arm][kind] = {"registered_tasks": len(group), **{key: sum(row["score"][key] for row in group) for key in keys},
                "answer_calls": sum(row["answer_calls"] for row in group),
                "prepare_blocked": sum(row["prepare_status"] != "ok" for row in group),
                "projection_blocked": sum(row.get("projection_status") != "ok" for row in group)}
    return result


def verify(run, *, approved_plan=None, corpus=None, config_source=None, source_root=None, bundle_root=None):
    run = Path(run).resolve()
    source_root = Path(source_root).resolve() if source_root else ROOT
    bundle_root = Path(bundle_root).resolve() if bundle_root else None
    approved_plan = Path(approved_plan) if approved_plan else ROOT / "results/source_card_reader_plan_20261026_v4/plan.json"
    corpus = Path(corpus) if corpus else ROOT / "examples/privacy_semantics_v1"
    config_source = Path(config_source) if config_source else ROOT / "configs/local_privacy_detector.json"
    checks, phase = [], "saved_evidence"
    def check(name, predicate):
        try:
            passed = bool(predicate() if callable(predicate) else predicate)
        except ERRORS:
            passed = False
        checks.append({"check": name, "passed": passed})
        return passed
    def finish(status=None, **extra):
        return {"version": VERSION, "status": status or ("passed" if all(item["passed"] for item in checks) else "failed"),
            "checks": checks, "phase": phase, "verification_model_calls": 0, "privacy_or_utility_acceptance": False,
            "original_HMAC_signatures_independently_verified": False, "original_python_mapping_identity_verified": False,
            "scope": "Saved-evidence consistency plus equivalent-map pure replay on exposed development data.",
            "limitations": ["Original HMAC key/map objects were not persisted; replay re-signs identical grants/labels with a temporary authority.",
                "Shared original object use is evidenced by frozen driver and saved journals, not an independently preserved map object.",
                "Gold ordering uses frozen-source AST and journal sequence; no separately sealed unscored artifact manifest was produced.",
                "Checksums and journals cannot defeat coordinated artifact forgery; request observations are not packet capture or GPU tracing.",
                "Eight exposed stories and paired repeated tasks do not establish independent generalization or algorithm novelty."], **extra}
    try:
        if not check("workspace_results_scope", run == bundle_root / "run" and source_root == run / "implementation"
                if bundle_root else run.is_relative_to((ROOT / "results").resolve())):
            return finish()
        audit = read(run / "transport_audit.json")
        if audit.get("completed") is not True:
            return finish("incomplete", execution_complete=False)
        plan, approved, config, runtime = read(run / "plan.json"), read(approved_plan), read(run / "config.json"), read(run / "runtime.json")
        check("approved_plan_and_fixed_three_arm_development_scope", lambda:
            same(plan, approved) and plan["version"] == STUDY_VERSION and plan["arms"] == list(ARMS)
            and plan["source_stories"] == 8 and plan["registered_tasks"] == 48 and plan["expected_rows"] == 144
            and (plan["legal_per_arm"], plan["missing_per_arm"], plan["outsider_per_arm"]) == (32, 8, 8)
            and plan["generation_limits"] == {"total": 264, **LIMITS} and plan["ordering_seed"] == SEED
            and plan["prepare_mode"] == "generation" and plan["privacy_pipeline"] == "legacy"
            and plan["threshold"] == .5 and plan["splitter"] == "cjk_aware" and plan["max_encoded_tokens"] == 512)
        check("original_runtime_gold_bytes_and_config_identity", lambda:
            sha((corpus / "development/runtime.json").read_bytes()) == plan["runtime_sha256"]
            and same(read(corpus / "development/runtime.json"), runtime)
            and sha((corpus / "development/evaluation.json").read_bytes()) == plan["evaluation_sha256"]
            and digest(config) == plan["config_sha256"] and same(config, read(config_source)))
        source = (run / "implementation/scripts/run_source_card_reader.py").read_text(encoding="utf-8")
        declared = set(_declaration(source))
        hashes = plan["implementation_sha256"]
        source_ok = check("all_50_current_and_archived_frozen_dependencies", lambda:
            len(declared) == 50 and declared == set(hashes)
            and {path.relative_to(run / "implementation").as_posix() for path in (run / "implementation").rglob("*.py")} == declared
            and all(not Path(name).is_absolute() and ".." not in Path(name).parts
                and sha((source_root / name).read_bytes()) == expected == sha((run / "implementation" / name).read_bytes()) for name, expected in hashes.items()))
        check("AST_gold_parse_and_scoring_follow_observer_close", lambda: _phase_order(source))
        rows, contexts, stores, builds, annotations, pools, source_sets, query_events, journal, report, identities, network = [read(run / name) for name in (
            "rows.json", "shared_contexts.json", "record_store.json", "builds.json", "annotations.json", "pools.json", "source_card_sets.json",
            "query_encoder_events.json", "auth_events.json", "report.json", "runtime_identity.json", "network_audit.json")]
        story_by_id = {story["story_id"]: story for story in runtime}
        task_by_id = {(story["story_id"], task["task_id"]): task for story in runtime for task in _tasks(story)}
        check("eight_stories_48_tasks_and_missing_precondition", lambda:
            len(runtime) == len(story_by_id) == 8 and Counter(story["language"] for story in runtime) == {"en": 4, "zh": 4}
            and len(task_by_id) == 48 and Counter(task["task_class"] for task in task_by_id.values()) == {"legal": 32, "missing": 8, "outsider": 8}
            and all("@" not in story["source"]["text"] for story in runtime))
        expected_order = []
        for story in runtime:
            for task in _tasks(story):
                cid = story["story_id"] + ":" + task["task_id"]
                arms = list(ARMS)
                random.Random(SEED + int(sha(cid.encode())[:8], 16)).shuffle(arms)
                expected_order.extend((cid, arm) for arm in arms)
        check("complete_unique_paired_144_rows_and_48_shared_preparations", lambda:
            len(rows) == len({(row["context_id"], row["arm"]) for row in rows}) == 144
            and [(row["context_id"], row["arm"]) for row in rows] == expected_order
            and len(contexts) == len({context["context_id"] for context in contexts}) == 48
            and len({context["request_id"] for context in contexts}) == 48
            and [context["context_id"] for context in contexts] == [sid + ":" + tid for sid, tid in task_by_id])
        close = [event for event in journal if event["kind"] == "model_phase_closed"]
        evaluation_events = [event for event in journal if event["kind"] == "evaluation_loaded"]
        closure_ok = check("journal_all_processing_then_closed_then_gold_loaded", lambda:
            [event["sequence"] for event in journal] == list(range(1, len(journal)+1))
            and len(close) == len(evaluation_events) == 1 and close[0]["sequence"] < evaluation_events[0]["sequence"]
            and evaluation_events[0]["evaluation_sha256"] == plan["evaluation_sha256"]
            and sum(event["kind"] == "task_processing_end" for event in journal) == 144
            and all(event["sequence"] < close[0]["sequence"] for event in journal if event["kind"] in {"task_processing_end", "access_check", "prepare_start", "prepare_end"}))
        if not closure_ok or not source_ok:
            return finish(execution_complete=False, note="Source/phase evidence invalid; no gold parsed or mechanism replay accepted.")
        check("no_private_map_or_authority_keys_persisted", lambda:
            all(_walk_keys(value, PRIVATE_KEYS) for value in (rows, contexts, stores, builds, annotations, pools, source_sets, query_events, journal, identities)))
        events = [json.loads(line) for line in (run / "request_transport.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        requests, terminals, stages = {}, {}, Counter()
        ledger_ok = True
        prompt_total = output_total = 0
        for position, item in enumerate(events):
            index = item["index"]
            if item["phase"] == "request":
                ledger_ok &= position == (index-1)*2 and index == len(requests)+1 and item["stage"] in LIMITS
                requests[index] = item; stages[item["stage"]] += 1
                body = item["request"]
                expected_output = 64 if item["stage"] == "answer" else 1024
                ledger_ok &= (digest(body) == item["request_sha256"] and body["model"] == config["model"]
                    and body["stream"] is False and body["keep_alive"] == "30m"
                    and body["options"] == {"num_ctx": 4096, "num_predict": expected_output, "temperature": 0, "seed": 42}
                    and _walk_keys(body, {"gold", "score", "scores", "answers", "expected_answer", "access_signature", "label_signature", *PRIVATE_KEYS})
                    and item["wire_json_utf8_bytes"] == len(json.dumps(body, ensure_ascii=False).encode())
                    and item["wire_json_utf8_sha256"] == sha(json.dumps(body, ensure_ascii=False).encode()))
            else:
                ledger_ok &= item["phase"] in {"response", "failure"} and index in requests and index not in terminals and position == (index-1)*2+1
                terminals[index] = item
                ledger_ok &= item["request_sha256"] == requests[index]["request_sha256"]
                ledger_ok &= all(item[key] == requests[index][key] for key in ("stage", "arm", "story_id", "task_id"))
                if item["phase"] == "response":
                    response, maximum = item["response"], requests[index]["request"]["options"]["num_predict"]
                    a, b = response.get("prompt_eval_count"), response.get("eval_count")
                    within = type(a) is int and type(b) is int and 0 < a <= 3072 and 0 < b <= maximum and a + maximum <= 4096
                    ledger_ok &= item["response_sha256"] == digest(response) and item["actual_usage_within_budget"] == within
                    if type(a) is int and type(b) is int:
                        prompt_total += a; output_total += b
                else:
                    ledger_ok &= item["error"] == "physical_transport_failed"
        check("physical_attempts_serial_owned_hashed_and_budgeted", ledger_ok and set(requests) == set(terminals)
            and len(requests) <= 264 and all(stages[stage] <= maximum for stage, maximum in LIMITS.items()))
        check("transport_report_and_no_closed_phase_or_external_requests", lambda:
            audit["physical_generation_attempts"] == report["generation_calls_observed"] == len(requests) == close[0]["actual_generation_attempts"]
            and audit["responses"] == sum(event["phase"] == "response" for event in terminals.values())
            and audit["transport_errors"] == sum(event["phase"] == "failure" for event in terminals.values())
            and audit["registered_generation_cap"] == 264 and audit["generation_calls_by_stage"] == report["generation_calls_by_stage"] == dict(stages)
            and audit["closed_phase_attempts"] == report["closed_phase_attempts"] == 0
            and audit["cloud_calls"] == audit["new_api_cost_cny"] == report["cloud_calls"] == report["new_api_cost_cny"] == 0
            and audit["recovery_mapping_recorded"] is False and audit["network"] == network
            and network["external_attempts_blocked"] == 0 and type(network["loopback_connections"]) is int
            and report["registered_rows"] == report["recorded_rows"] == 144 and report["shared_contexts"] == report["registered_tasks"] == 48
            and report["source_stories"] == 8 and report["implementation_unchanged"] is True)
        stage_by_cell = Counter((event["story_id"], event["task_id"], event["arm"]) for event in requests.values() if event["stage"] == "answer")
        check("at_most_one_answer_POST_per_registered_cell", all(count == 1 for count in stage_by_cell.values())
            and all((sid, tid) in task_by_id and arm in ARMS for sid, tid, arm in stage_by_cell)
            and report["generation_calls_by_arm"] == {arm: sum(count for (sid, tid, name), count in stage_by_cell.items() if name == arm) for arm in ARMS})
        phase = "equivalent_authority_replay"
        # Bundle mode imports only the explicitly approved, hash-checked pure
        # dependency tree. No archived launcher or model runtime is executed.
        sys.path.insert(0, str(source_root))
        from memory_migration_study.answer_serialization import canonicalize_answer
        from memory_migration_study.local_detector import LocalSensitivityAgent
        from memory_migration_study.memory_generation_experiment import LocalFactAnswerer
        from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
        from memory_migration_study.ner_detector import GlinerEntityAgent, LABELS
        from memory_migration_study.reference_memory import propose_fact_pool
        from memory_migration_study.request_projection import project_fact_cards, resolve_fact_card_answer
        from memory_migration_study.source_card_reader import LocalSourceCardReader
        from memory_migration_study.source_fact_cards import build_source_fact_cards, GRAMMAR_SHA256
        from scripts.run_reference_memory_study import TypedCountingDetector
        from scripts.run_query_schema_transfer import SchemaRuntimeProxy
        check("approved_pure_module_import_origins", all(
            Path(sys.modules[module].__file__).resolve() == (source_root / name).resolve()
            for name in hashes for module in [name[:-12].replace("/", ".") if name.endswith("/__init__.py") else name[:-3].replace("/", ".")]
            if module in sys.modules and getattr(sys.modules[module], "__file__", None)))
        check("pinned_local_reader_and_source_grammar", lambda:
            same(identities["reader"], plan["reader_identity"]) and same(identities["reader"], LocalSourceCardReader(config).cache_identity())
            and identities["local_generation"] == {"version": plan["reader_identity"]["client"]["runtime"], "model": config["model"],
                "digest": config["expected_digest"], "endpoint": "http://127.0.0.1:11435"}
            and plan["source_grammar_sha256"] == GRAMMAR_SHA256)
        record_by_id = {item["story_id"]: item for item in stores}
        build_by_id = {item["story_id"]: item for item in builds}
        source_by_id = {item["story_id"]: item for item in source_sets}
        pool_by_id = {item["story_id"]: item["pool"] for item in pools}
        check("one_common_source_construction_per_story", len(stores) == len(builds) == len(source_sets) == len(pools) == 8
            and set(record_by_id) == set(build_by_id) == set(source_by_id) == set(pool_by_id) == set(story_by_id))
        authorities, cloned_records, tables = {}, {}, {}
        for sid, story in story_by_id.items():
            records, built = record_by_id[sid]["records"], build_by_id[sid]
            def source_integrity():
                assert same(pool_by_id[sid], propose_fact_pool(story["source"]["text"], story["source"]["source_id"]))
                assert built["source_text_sha256"] == sha(story["source"]["text"].encode())
                assert built["full_policy_sha256"] == digest(story["policy"])
                if records:
                    assert built["status"] == record_by_id[sid]["union_label_set_status"] == "ok"
                    assert [(record["text"], record["source_start"], record["source_end"]) for record in records] == [
                        (fact["text"], fact["source_start"], fact["source_end"]) for fact in built["facts"]]
                for record in records:
                    a, b = record["source_start"], record["source_end"]
                    grant, label = record["access"], record["label"]
                    assert type(a) is int and type(b) is int and story["source"]["text"][a:b] == record["text"]
                    assert record["source"] == {**story["source"], "sha256": sha(story["source"]["text"].encode())}
                    assert grant["readers"] == ["owner"] and grant["owner_id"] == "owner" and grant["allowed_agent_ids"] == ["target-agent"]
                    assert grant["origin_agent_id"] == "source-agent" and grant["epoch"] == label["epoch"] == 0
                    assert grant["record_id"] == label["record_id"] == record["record_id"] == record["source_id"]
                    assert grant["source_id"] == story["source"]["source_id"] and grant["scope_version"] == "exact_fact_source_span_v1"
                    assert grant["content_sha256"] == label["content_sha256"] == sha(record["text"].encode())
                    assert grant["source_sha256"] == label["source_sha256"] == record["source"]["sha256"]
                    assert grant["source_start"] == label["source_start"] == a and grant["source_end"] == label["source_end"] == b
                    assert label["access_sha256"] == digest(grant) and label["builder_version"] == built["builder_version"]
                    annotation = next(item for item in annotations if item["story_id"] == sid and item["source_start"] == a and item["source_end"] == b)
                    expected_findings = sorted([{key: finding[key] for key in ("start", "end", "category")} for finding in annotation["detection"]["findings"]], key=lambda finding: (finding["start"], finding["end"], finding["category"]))
                    assert same(label["findings"], expected_findings) and annotation["status"] == annotation["group_status"] == "ok"
                    assert annotation["eligible_for_store"] is True and annotation["input_payload"]["memories"] == [{"source_id": annotation["annotation_source_id"], "text": record["text"]}]
                return True
            check("exact_original_fact_positions_grants_labels_and_union_annotation_" + sid, source_integrity)
            authority = MemoryLabelAuthority(sha(("offline-independent-reader-verifier:" + sid).encode()).encode())
            clones = [_record_copy(record, authority) for record in records]
            authorities[sid], cloned_records[sid] = authority, clones
            def authorize(rid, actor, version, records=clones, authority=authority, policy=story["policy"]):
                return actor == "owner" and version == policy["version"] and any(record["record_id"] == rid and
                    authority.validate_access(record, actor_id=actor, agent_id="target-agent", policy_version=version) is None for record in records)
            result = build_source_fact_cards(clones, story["policy"], authority=authority, actor_id="owner", agent_id="target-agent", authorizer=authorize) if clones else None
            tables[sid] = result
            check("authorized_source_only_card_construction_replay_" + sid, lambda:
                (result is None and source_by_id[sid]["status"] == "not_run") or
                (result["status"] == source_by_id[sid]["status"] and result["error"] == source_by_id[sid]["error"]
                 and same({key: value for key, value in result["metadata"].items() if key != "record_scope_sha256"},
                          {key: value for key, value in source_by_id[sid]["metadata"].items() if key != "record_scope_sha256"})
                 and source_by_id[sid]["metadata"]["record_scope_sha256"] == digest(records)))
        row_index = {(row["context_id"], row["arm"]): row for row in rows}
        prepared_by_context, clone_contexts, owned_answers, used_query_indices, net_faults = {}, {}, [], [], []
        def deny_network(*args, **kwargs):
            net_faults.append("unexpected_network_during_offline_replay")
            raise AssertionError("unexpected_network_during_offline_replay")
        with patch.object(socket.socket, "connect", deny_network), patch.object(socket, "create_connection", deny_network):
            for context in contexts:
                cid, sid, tid = context["context_id"], context["story_id"], context["task_id"]
                story, task = story_by_id[sid], task_by_id[(sid, tid)]
                records, authority, actor = cloned_records[sid], authorities[sid], task["actor_id"]
                scope = {"authority": authority, "actor_id": actor, "agent_id": "target-agent", "request_id": context["request_id"]}
                def authorizer(rid, user, version):
                    return user == actor and version == story["policy"]["version"] and any(record["record_id"] == rid and
                        authority.validate_access(record, actor_id=user, agent_id="target-agent", policy_version=version) is None for record in records)
                scope["authorizer"] = authorizer
                indices = context["query_encoder_event_indices"]
                selected_queries = [query_events[index] for index in indices]
                used_query_indices.extend(indices)
                remaining_queries, query_faults = list(selected_queries), []
                def infer(text, labels, *, splitter, threshold):
                    if not remaining_queries:
                        query_faults.append("missing_saved_encoder")
                        raise AssertionError("missing_saved_encoder")
                    observed = remaining_queries.pop(0)
                    if (text != observed["text"] or observed["context_id"] != cid or not same(labels, observed["requested_labels"])
                            or observed["text_sha256"] != sha(text.encode()) or splitter != "cjk_aware" or threshold != .5):
                        query_faults.append("encoder_input_changed")
                        raise AssertionError("encoder_input_changed")
                    if observed["status"] != "ok":
                        raise ValueError(observed.get("error") or "recorded_encoder_failure")
                    return deepcopy(observed["translated_result"])
                # Native QuerySchemaAgent wraps the original runtime in this
                # proxy. Its adapter reports MODEL_REVISION (not the original
                # runtime weights digest) because weights_sha256 is nested.
                # Rebuild that exact metadata contract rather than dropping
                # the digest comparison or modifying the saved observation.
                proxy_identity = SchemaRuntimeProxy(SimpleNamespace(identity=identities["ner"]), "A", []).identity
                detector = TypedCountingDetector(GlinerEntityAgent(SimpleNamespace(identity=proxy_identity, infer=infer), approved_policies=[story["policy"]]))
                nonce = next((TOKEN.search(memory["text"]).group(1) for memory in (context.get("outbound") or {}).get("memories", []) if TOKEN.search(memory["text"])), None)
                if nonce is None and context.get("outbound"):
                    nonce = re.fullmatch(r"m_([A-F0-9]{24})_1", context["outbound"]["memories"][0]["source_id"]).group(1)
                with patch("memory_migration_study.privacy.secrets.token_hex", return_value=(nonce or "0"*24).lower()):
                    prepared = prepare_labeled_transfer(records, task["query"], story["policy"], **{key: value for key, value in scope.items() if key != "authorizer"},
                        mode="generation", agent=detector, label_requirements={"expected_builder_version": build_by_id[sid]["builder_version"],
                            "expected_detector_version": identities["union_detector_revision"]}) if records else None
                prepared_by_context[cid] = prepared
                ready = prepared is not None and prepared["status"] == "ok"
                check("shared_preparation_input_scope_and_query_encoder_replay_" + cid, lambda:
                    not remaining_queries and not query_faults and context["original_query"] == task["query"]
                    and context["actor_id"] == actor and context["agent_id"] == "target-agent" and same(context["policy"], story["policy"])
                    and context["record_scope_sha256"] == digest(record_by_id[sid]["records"])
                    and (prepared["status"] if prepared else "blocked") == context["prepare_status"]
                    and (prepared.get("error") if prepared else "label_set_unavailable") == context["prepare_error"]
                    and (same(prepared["payload"], context["outbound"]) and same(clean_times(prepared["detection"]), clean_times(context["detection"]))
                         and same(prepared["checks"], context["checks"]) and same(prepared["metadata"], context["prepare_metadata"])
                         and same(prepared["egress"], context["egress"]) if ready else context["outbound"] is None)
                    and context["prepare_generation_calls_observed"] == 0)
                projection = None
                if ready and tables[sid] and tables[sid]["status"] == "ok":
                    saved_cards = context["views"].get("flat", {}).get("fact_cards", [])
                    tag = re.fullmatch(r"C_([A-F0-9]{8})_[1-9][0-9]*", saved_cards[0]["card_id"]).group(1) if saved_cards else "0"*8
                    with patch("memory_migration_study.request_projection.secrets.token_hex", return_value=tag.lower()):
                        projection = project_fact_cards(tables[sid]["source_table"], prepared, records, story["policy"], **scope)
                clone_contexts[cid] = (prepared, projection, scope)
                check("whole_position_projection_complete_equivalent_map_and_egress_" + cid, lambda:
                    (projection["status"] if projection else "not_run") == context["projection_status"]
                    and (not projection or (projection["error"] == context["projection_error"] and same(projection["views"], context["views"])
                        and same(projection["response_schema"], context["response_schema"])
                        and same({key: value for key, value in projection["metadata"].items() if key != "record_scope_sha256"},
                                 {key: value for key, value in context["projection_metadata"].items() if key != "record_scope_sha256"})))
                    and (not ready or digest(prepared["payload"]) == context["actual_payload_sha256"]))
                if context["projection_status"] == "ok":
                    flat, rich = context["views"]["flat"], context["views"]["source"]
                    check("Flat_and_Source_identical_full_context_IDs_values_only_extra_support_" + cid,
                        flat["query"] == rich["query"] == context["outbound"]["query"]
                        and flat["memories"] == rich["memories"] == context["outbound"]["memories"]
                        and flat["fact_cards"] == [{key: value for key, value in card.items() if key not in {"role", "support"}} for card in rich["fact_cards"]]
                        and all(set(card) == {"card_id", "value", "source_id", "role", "support"} for card in rich["fact_cards"]))
                for arm in ARMS:
                    row = row_index[(cid, arm)]
                    request_indices = row["answer_request_indices"]
                    owned_answers.extend(request_indices)
                    check("same_shared_scope_and_at_most_one_answer_" + cid + "_" + arm, lambda:
                        row["request_id"] == context["request_id"] and row["actor_id"] == actor and row["agent_id"] == "target-agent"
                        and row["prepare_status"] == context["prepare_status"] and row["prepare_error"] == context["prepare_error"]
                        and row["actual_payload_sha256"] == context["actual_payload_sha256"] and row["record_scope_sha256"] == context["record_scope_sha256"]
                        and row["projection_status"] == context["projection_status"] and row["projection_error"] == context["projection_error"]
                        and row["task_class"] == task["task_class"] and row["language"] == story["language"] and row["template_family"] == story["template_family"]
                        and row["answer_calls"] == len(request_indices) <= 1
                        and all(requests[index]["stage"] == "answer" and requests[index]["arm"] == arm and requests[index]["story_id"] == sid
                            and requests[index]["task_id"] == tid for index in request_indices))
                    if not ready:
                        check("blocked_context_sends_no_model_or_final_answer_" + cid + "_" + arm,
                            row["answer_calls"] == 0 and row["raw_model_answer"] is None and row["final_answer"] is None)
                        continue
                    if arm != "F" and (not projection or projection["status"] != "ok"):
                        check("projection_failure_never_reaches_model_" + cid + "_" + arm, row["answer_calls"] == 0 and row["final_answer"] is None)
                        continue
                    remaining, faults = list(request_indices), []
                    def transport(method, path, body=None):
                        if method != "POST" or path != "/api/chat" or not remaining:
                            faults.append("unexpected_answer_transport")
                            raise AssertionError("unexpected_answer_transport")
                        index = remaining.pop(0)
                        if not same(body, requests[index]["request"]):
                            faults.append("answer_request_changed")
                            raise AssertionError("answer_request_changed")
                        terminal = terminals[index]
                        if terminal["phase"] != "response" or terminal.get("actual_usage_within_budget") is False:
                            raise RuntimeError("saved_transport_or_budget_failure")
                        return deepcopy(terminal["response"])
                    if arm == "F":
                        response = LocalFactAnswerer(config, transport=transport)(prepared["payload"])
                        candidate, resolution = response.get("answer"), None
                    else:
                        mode = "flat" if arm == "Flat-ID" else "source"
                        response = LocalSourceCardReader(config, transport=transport)(projection["views"][mode], projection["table"], prepared,
                            records, story["policy"], arm=mode, **scope)
                        resolution = resolve_fact_card_answer(response["answer"], projection["table"], prepared, records, story["policy"], **scope) if response["status"] == "ok" else None
                        candidate = resolution.get("answer") if resolution and resolution["status"] == "ok" else None
                        check("native_reader_and_closed_choice_resolution_replay_" + cid + "_" + arm,
                            same(clean_times(response), clean_times(row["reader_response"])) and same(resolution, row["resolution"])
                            and row["card_decision"] == response.get("decision"))
                    pipeline_error = (resolution or {}).get("error")
                    status = "blocked" if pipeline_error else response["status"]
                    final = restoration_status = None
                    if status == "ok" and candidate is not None:
                        if arm == "F":
                            strict = restore_labeled_answer(candidate, prepared, records, story["policy"], **scope)
                            check("original_full_equivalent_map_strict_F_restore_" + cid,
                                same(strict, row["strict_restoration"]) and strict.get("answer") == row["strict_final_answer"])
                        canonical = canonicalize_answer(candidate, prepared["payload"])
                        restored = restore_labeled_answer(canonical["answer"], prepared, records, story["policy"], **scope)
                        final, restoration_status = restored.get("answer"), restored["status"]
                        check("original_restore_after_canonicalization_current_authorization_" + cid + "_" + arm,
                            same(canonical, row["canonicalization"]) and restored.get("error") == row.get("restoration_error"))
                    raw = terminals[request_indices[0]]["response"].get("message", {}).get("content") if request_indices and terminals[request_indices[0]]["phase"] == "response" else None
                    check("full_recorded_model_answer_and_final_restore_replay_" + cid + "_" + arm,
                        not remaining and not faults and row["model_response_status"] == response["status"]
                        and row["answer_status"] == status and row["answer_error"] == (pipeline_error or response.get("error"))
                        and row["raw_model_answer"] == raw and row["resolved_answer"] == candidate
                        and row["answer_calls"] == response["local_calls"] and row["final_answer"] == final and row["restoration_status"] == restoration_status)
        check("all_saved_query_encoder_events_owned_once", used_query_indices == list(range(len(query_events))))
        check("all_answer_requests_owned_once_and_no_network_during_replay", sorted(owned_answers) == [index for index, value in requests.items() if value["stage"] == "answer"]
            and len(owned_answers) == len(set(owned_answers)) and net_faults == [])
        check("original_saved_authorization_journal_bound_to_principals", all(
            event.get("actor_id") in {"owner", "outsider"} and event.get("agent_id") == "target-agent"
            and event.get("error") == ("principal_not_authorized" if event.get("actor_id") == "outsider" else None)
            for event in journal if event["kind"] == "access_check"))
        for context in contexts:
            cid, sid = context["context_id"], context["story_id"]
            expected_ids = {record["record_id"] for record in record_by_id[sid]["records"]}
            operation = cid + ":shared"
            original_checks = [event for event in journal if event["kind"] == "access_check" and event.get("operation") == operation]
            check("original_preparation_checks_all_grants_or_blocks_first_" + cid,
                (context["actor_id"] == "owner" and expected_ids <= {event["record_id"] for event in original_checks})
                or (context["actor_id"] == "outsider" and (not expected_ids or any(event["error"] == "principal_not_authorized" for event in original_checks))))
        phase = "independent_scoring"
        evaluation = read(run / "evaluation.json")
        check("evaluation_semantics_equal_original_after_closure", same(evaluation, read(corpus / "development/evaluation.json"))
            and set(evaluation) == set(story_by_id))
        recomputed_rows = []
        for row in rows:
            sid, tid, cid = row["story_id"], row["task_id"], row["context_id"]
            expected = "UNKNOWN" if row["task_class"] == "missing" else evaluation[sid]["answers"].get(tid, "")
            required = bool(row["task_class"] == "legal" and expected and any(expected in record["text"] for record in record_by_id[sid]["records"]))
            masking = _mask_score(story_by_id[sid], evaluation[sid], cloned_records[sid], prepared_by_context[cid])
            replacement = {**row, "required_fact_retained": required, "masking": masking}
            recomputed = _score(replacement, expected)
            check("independent_mask_and_full_denominator_score_" + cid + "_" + row["arm"],
                row["required_fact_retained"] == required and same(masking, row["masking"]) and same(recomputed, row["score"]))
            recomputed_rows.append({**replacement, "score": recomputed})
        summary = _aggregate(recomputed_rows)
        check("independent_three_arm_paired_summary", same(summary, report["arms"])
            and all(summary[arm][kind]["registered_tasks"] == number for arm in ARMS for kind, number in (("legal", 32), ("missing", 8), ("outsider", 8))))
        check("frozen_sources_and_original_materials_unchanged_after_replay", all(sha((source_root / name).read_bytes()) == expected for name, expected in hashes.items())
            and sha((corpus / "development/runtime.json").read_bytes()) == plan["runtime_sha256"]
            and sha((corpus / "development/evaluation.json").read_bytes()) == plan["evaluation_sha256"])
        paired = {}
        by_key = {(row["context_id"], row["arm"]): row for row in recomputed_rows}
        legal_contexts = [context["context_id"] for context in contexts if task_by_id[(context["story_id"], context["task_id"])]["task_class"] == "legal"]
        for left, right in (("F", "Flat-ID"), ("Flat-ID", "Source-ID"), ("F", "Source-ID")):
            counts = Counter((bool(by_key[(cid, left)]["score"]["joint_correct_no_masking_gap"]),
                bool(by_key[(cid, right)]["score"]["joint_correct_no_masking_gap"])) for cid in legal_contexts)
            paired[left + "_vs_" + right] = {"both_correct": counts[(True, True)], "left_only": counts[(True, False)],
                "right_only": counts[(False, True)], "both_failed": counts[(False, False)], "legal_tasks": len(legal_contexts)}
        phase = "complete"
        return finish(execution_complete=True, saved_evidence_and_equivalent_map_replay_complete=True,
            material_stories=8, shared_contexts=48, row_count=144, observed_generation_attempts=len(requests),
            observed_generation_by_stage=dict(stages), observed_runtime_tokens={"prompt": prompt_total, "output": output_total},
            recomputed_summary=summary, paired_joint_outcomes=paired)
    except ERRORS:
        check("artifact_structure_complete_at_" + phase, False)
        return finish(execution_complete=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--run", type=Path)
    inputs.add_argument("--input-root", type=Path, help="Public bundle with run/, source/, approved-plan.json; no model execution.")
    parser.add_argument("--approved-plan", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--config-source", type=Path)
    parser.add_argument("--output", type=Path, help="New receipt; never overwrites. Default RUN/independent_source_card_verification_v1.json")
    args = parser.parse_args()
    if args.input_root:
        bundle = args.input_root.resolve()
        args.run = bundle / "run"
        result = verify(args.run, approved_plan=bundle / "approved-plan.json", corpus=bundle / "source/examples/privacy_semantics_v1",
            config_source=bundle / "source/configs/local_privacy_detector.json", source_root=bundle / "run/implementation", bundle_root=bundle)
    else:
        result = verify(args.run, approved_plan=args.approved_plan, corpus=args.corpus, config_source=args.config_source)
    result["verifier_sha256"] = sha(Path(__file__).read_bytes())
    destination = args.output or args.run / "independent_source_card_verification_v1.json"
    try:
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
    except OSError:
        print(json.dumps({"status": "receipt_not_written", "error": "output_exists_or_unwritable"}))
        raise SystemExit(2)
    failed = [item["check"] for item in result["checks"] if not item["passed"]]
    print(json.dumps({"status": result["status"], "report_file": str(destination.resolve()), "checks": len(result["checks"]),
        "failed_count": len(failed), "failed_first_12": failed[:12], "verification_model_calls": 0,
        "privacy_or_utility_acceptance": False}, ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "passed" else 1)
