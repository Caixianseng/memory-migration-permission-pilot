"""Independent, model-free consistency audit of the paired transfer diagnostic.

This checks recorded evidence, not privacy/utility acceptance or server billing.
Recovery keys/maps were not persisted, so masking counters and authenticated
restoration cannot be independently rerun. Those limitations remain explicit.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
BASE_ARMS = {
    "model_build_migration": ("model", "migration", False),
    "coverage_migration": ("coverage", "migration", False),
    "coverage_intent_migration": ("coverage", "migration", True),
    "coverage_intent_generation": ("coverage", "generation", True),
    "coverage_intent_two_stage": ("coverage", "two_stage", True),
    "coverage_raw_local": ("coverage", "raw", True),
}
ARMS = {}
for _name, _spec in BASE_ARMS.items():
    if _spec[1] == "raw":
        ARMS[_name] = _spec
    else:
        ARMS[_name+"__legacy"] = _spec
        ARMS[_name+"__boundary"] = _spec
TOKEN = re.compile(r"\[PVT_[A-F0-9]{24}_(?:PERSON|ADDRESS|CUSTOMER|PROJECT|EMAIL|PHONE|ID|AMOUNT|DATE|MIXED)_[1-9][0-9]*\]")
KINDS = {"local_encoder", "local_generation", "unknown"}
FORBIDDEN_KEYS = {"mapping", "_entries", "_nonce", "authority_key", "hmac_key", "private_key", "secret_key",
                  "recovery_map", "restoration_map", "_secret", "_MemoryLabelAuthority__secret"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def read(path):
    return json.loads(Path(path).read_bytes())


def no_private_objects(value):
    if isinstance(value, dict):
        return not (set(value) & FORBIDDEN_KEYS) and all(no_private_objects(item) for item in value.values())
    return not isinstance(value, list) or all(no_private_objects(item) for item in value)


def recompute_score(row, gold):
    legal = row["actor_id"] == "owner"
    answer, expected = row.get("final_answer"), gold["answers"].get(row["task_id"])
    correct = bool(legal and isinstance(answer, str) and isinstance(expected, str)
                   and answer.strip().casefold() == expected.casefold())
    masking = row.get("masking")
    # These are SAVED masking measurements, not an independently repeated mask.
    no_gap = (isinstance(masking, dict) and masking.get("ready") is True
              and type(masking.get("partial")) is int and masking["partial"] == 0
              and type(masking.get("unmasked")) is int and masking["unmasked"] == 0)
    enabled = row.get("secondary_serialization_registered") is True
    secondary_answer = (row.get("secondary_serialization") or {}).get("final_answer")
    secondary_correct = bool(legal and isinstance(secondary_answer, str) and isinstance(expected, str)
        and secondary_answer.strip().casefold() == expected.casefold())
    return {"legal": legal, "correct": correct,
        "joint_correct_no_masking_gap": None if row["mode"] == "raw" else bool(correct and row.get("prepare_status") == "ok" and no_gap),
        "secondary_serialization_correct": secondary_correct if enabled else None,
        "secondary_joint_correct_no_masking_gap": bool(secondary_correct and row.get("prepare_status") == "ok" and no_gap) if enabled else None,
        "build_block": legal and row.get("build_status") != "ok",
        "preprocessing_block": legal and row.get("prepare_status") != "ok",
        "true_model_unknown": legal and (row.get("model_answer") or "").strip().casefold() == "unknown",
        "restoration_failure": legal and row.get("restoration_status") == "blocked",
        "outsider_blocked": not legal and row.get("module_authorization_error") == "principal_not_authorized" and row.get("answer_calls", 0) == 0,
        "unauthorized_output": not legal and (row.get("prepare_status") == "ok" or bool(answer))}


def verify(run, *, corpus=None, config_source=None, expected_stories=8, expected_legal=32, expected_outsiders=8):
    run = Path(run)
    checks = []
    def check(name, value):
        checks.append({"check": name, "passed": bool(value)})
    audit = read(run/"transport_audit.json")
    if audit.get("completed") is not True:
        log = run/"request_transport.jsonl"
        requests = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()] if log.is_file() else []
        count = sum(item.get("phase") == "request" for item in requests)
        return {"status": "incomplete", "execution_complete": False, "observed_post_attempts": count,
                "declared_post_attempts": audit.get("physical_generation_attempts"),
                "zero_call_attempt_confirmed": count == audit.get("physical_generation_attempts") == 0,
                "verification_model_calls": 0, "scope": "Incomplete attempt is not accepted experiment evidence."}
    plan, runtime, evaluation, report, config, network = [read(run/name) for name in
        ("plan.json", "runtime.json", "evaluation.json", "report.json", "config.json", "network_audit.json")]
    rows, builds, stores, intents = [read(run/name) for name in ("rows.json", "builds.json", "record_store.json", "intents.json")]
    stories = {story["story_id"]: story for story in runtime}
    tasks = {(story["story_id"], task["task_id"]): task for story in runtime for task in story["tasks"]}
    build_index = {(item["story_id"], item["builder"]): item for item in builds}
    record_index = {(item["story_id"], item["builder"]): item["records"] for item in stores}
    check("declared_protocol", plan.get("paired_boundary") is True and plan.get("split") == "development"
        and plan.get("detector_kind") == "gliner" and plan.get("score_schema_version") == 2
        and plan.get("evaluation_timing") == "after_all_model_processing"
        and plan.get("arms") == {key: list(value) for key, value in ARMS.items()})
    owner_count = sum(task["actor_id"] == "owner" for story in runtime for task in story["tasks"])
    outsider_count = len(tasks)-owner_count
    check("registered_story_and_task_counts", len(runtime) == len(stories) == expected_stories
        and owner_count == expected_legal and outsider_count == expected_outsiders
        and len(tasks) == expected_legal+expected_outsiders)
    expected_matrix = Counter((story["story_id"], task["task_id"], arm) for story in runtime for task in story["tasks"] for arm in ARMS)
    check("complete_unique_eleven_arm_matrix", Counter((row["story_id"], row["task_id"], row["arm"]) for row in rows) == expected_matrix)
    check("report_row_counts", report.get("registered_rows") == report.get("recorded_rows") == len(rows) == sum(expected_matrix.values())
        and report.get("legal_rows") == expected_legal*11 and report.get("outsider_rows") == expected_outsiders*11)
    order = []
    for story in runtime:
        for task in story["tasks"]:
            names = list(ARMS)
            random.Random(f"2026102502:{story['story_id']}:{task['task_id']}").shuffle(names)
            order.extend((story["story_id"], task["task_id"], arm) for arm in names)
    check("registered_interleaved_order", order == [(row["story_id"], row["task_id"], row["arm"]) for row in rows])
    expected_builds = Counter((sid, family) for sid in stories for family in ("model", "coverage"))
    check("shared_two_builder_matrix", Counter((item["story_id"], item["builder"]) for item in builds) == expected_builds
        and Counter((item["story_id"], item["builder"]) for item in stores) == expected_builds)
    records_ok = True
    for identity, build in build_index.items():
        sid, family = identity
        records, source = record_index[identity], stories[sid]["source"]
        if build["status"] != "ok":
            records_ok &= records == []
        else:
            records_ok &= [(item["text"], item["source_start"], item["source_end"]) for item in records] == [
                (item["text"], item["source_start"], item["source_end"]) for item in build["facts"]]
        for record in records:
            start, end, grant, label = record["source_start"], record["source_end"], record["access"], record["label"]
            records_ok &= (type(start) is int and type(end) is int and 0 <= start < end <= len(source["text"])
                and source["text"][start:end] == record["text"] and record["source"] ==
                {"source_id": source["source_id"], "text": source["text"], "sha256": sha(source["text"].encode())}
                and grant.get("content_sha256") == label["content_sha256"] == sha(record["text"].encode())
                and grant.get("source_start") == label["source_start"] == start
                and grant.get("source_end") == label["source_end"] == end
                and label["access_sha256"] == digest(grant)
                and grant["record_id"] == label["record_id"] == record["record_id"])
    check("build_failures_not_deployed_and_content_range_bindings", records_ok)
    row_ok = score_ok = outsider_ok = secondary_ok = True
    summaries, recomputed_scores = {}, {}
    for row in rows:
        sid, arm = row["story_id"], row["arm"]
        family, mode, _ = ARMS[arm]
        task = tasks[(sid, row["task_id"])]
        expected_pipeline = "boundary" if arm.endswith("__boundary") else "legacy"
        row_ok &= (row["actor_id"] == task["actor_id"] and row["mode"] == mode
            and row.get("privacy_pipeline") == expected_pipeline and row["build_status"] == build_index[(sid, family)]["status"])
        recomputed = recompute_score(row, evaluation[sid])
        recomputed_scores[(sid, row["task_id"], arm)] = recomputed
        score_ok &= row.get("score") == recomputed
        if task["actor_id"] != "owner":
            outsider_ok &= row.get("outbound") is None and row["answer_calls"] == 0 and row.get("final_answer") is None
            outsider_ok &= ((row.get("module_authorization_error") == "principal_not_authorized") if record_index[(sid, family)]
                            else row["build_status"] != "ok")
        else:
            expected = evaluation[sid]["answers"].get(row["task_id"])
            score_ok &= row.get("required_fact_retained") == bool(expected and any(expected in record["text"] for record in record_index[(sid, family)]))
        secondary = row.get("secondary_serialization")
        if secondary is not None:
            actual, primary = row.get("outbound"), row.get("model_answer")
            texts = [actual["query"], *(memory["text"] for memory in actual["memories"])] if isinstance(actual, dict) else []
            available = {match.group() for text in texts for match in TOKEN.finditer(text)}
            candidate = "["+primary.strip()+"]" if isinstance(primary, str) else None
            repaired = candidate in available if candidate is not None else False
            canonical = candidate if repaired else primary
            secondary_ok &= secondary.get("decision") == ("added_outer_brackets" if repaired else "unchanged")
            secondary_ok &= secondary.get("canonical_answer") == canonical
            if not repaired:
                secondary_ok &= (secondary.get("final_answer"), secondary.get("restoration_status"), secondary.get("restoration_error")) == (
                    row.get("final_answer"), row.get("restoration_status"), row.get("restoration_error"))
            secondary_ok &= row["answer_calls"] == 1 and mode != "raw"
    check("rows_bound_to_registered_tasks_builders_and_pipeline", row_ok)
    check("independent_primary_secondary_and_joint_row_scores", score_ok)
    check("outsiders_have_no_model_or_outbound_or_final_answer", outsider_ok)
    check("secondary_exact_current_payload_token_only_primary_retained", secondary_ok)
    def calculated(row):
        return recomputed_scores[(row["story_id"], row["task_id"], row["arm"])]
    for arm, (family, mode, _) in ARMS.items():
        selected = [row for row in rows if row["arm"] == arm]
        legal = [row for row in selected if row["actor_id"] == "owner"]
        metrics = {"registered_tasks": len(selected), "legal_tasks": len(legal),
            "correct": sum(calculated(row)["correct"] for row in legal),
            "joint_masked_legal_tasks": 0 if mode == "raw" else len(legal),
            "joint_correct_no_masking_gap": None if mode == "raw" else sum(calculated(row)["joint_correct_no_masking_gap"] is True for row in legal),
            "secondary_serialization_legal_tasks": 0 if mode == "raw" else len(legal),
            "secondary_serialization_correct": None if mode == "raw" else sum(calculated(row)["secondary_serialization_correct"] is True for row in legal),
            "secondary_joint_correct_no_masking_gap": None if mode == "raw" else sum(calculated(row)["secondary_joint_correct_no_masking_gap"] is True for row in legal),
            "build_block": sum(calculated(row)["build_block"] for row in legal),
            "ready": sum(row.get("prepare_status") == "ok" for row in legal),
            "outsider_blocked": sum(calculated(row)["outsider_blocked"] for row in selected),
            "unauthorized_output": sum(calculated(row)["unauthorized_output"] for row in selected),
            "answer_calls": sum(row["answer_calls"] for row in selected)}
        check("independent_arm_summary_"+arm, len(legal) == expected_legal and len(selected)-len(legal) == expected_outsiders
            and all(report["arms"][arm].get(key) == value for key, value in metrics.items()))
        summaries[arm] = {**metrics, "primary_accuracy": metrics["correct"]/expected_legal if expected_legal else None,
            "secondary_minus_primary_correct": None if mode == "raw" else metrics["secondary_serialization_correct"]-metrics["correct"]}
    corpus = Path(corpus) if corpus is not None else ROOT/"examples/privacy_semantics_v1"
    for name, field in (("runtime.json", "runtime_sha256"), ("evaluation.json", "evaluation_sha256")):
        snapshot, original = (run/name).read_bytes(), (corpus/"development"/name).read_bytes()
        check("frozen_"+field, sha(original) == plan[field] and json.loads(original) == json.loads(snapshot))
    archive = run/"implementation"
    expected_archive = dict(plan["implementation_sha256"])
    for path, value in plan["entrypoint_sha256"].items():
        basename = Path(path).name
        if basename in expected_archive:
            raise ValueError("archive_basename_collision")
        expected_archive[basename] = value
    check("exact_declared_archive_and_hashes", {path.name for path in archive.glob("*.py")} == set(expected_archive)
        and all((archive/name).is_file() and sha((archive/name).read_bytes()) == value for name, value in expected_archive.items()))
    config_source = Path(config_source) if config_source is not None else ROOT/"configs/local_privacy_detector.json"
    check("frozen_config_semantics_and_original_bytes", digest(config) == plan["config_sha256"]
        and config == plan["config"] == read(config_source) and sha(config_source.read_bytes()) == audit["config_sha256"])
    check("launcher_snapshot_hash", sha((run/"launcher.py").read_bytes()) == audit["launcher_sha256"]
        and audit.get("launcher_unchanged") is True
        and audit["launcher_sha256"] == expected_archive.get("run_boundary_transfer_diagnostic.py"))
    events = [json.loads(line) for line in (run/"request_transport.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    requests, terminal, stages, response_by_index = [], {}, Counter(), {}
    ledger_ok = usage_ok = True
    answer_posts, build_posts, intent_posts = [], [], []
    for event in events:
        index = event["index"]
        if event["phase"] == "request":
            ledger_ok &= index == len(requests)+1
            body = event["request"]
            ledger_ok &= digest(body) == event["request_sha256"]
            options = body.get("options", {})
            ledger_ok &= (body.get("model") == config["model"] and body.get("stream") is False
                and options.get("num_ctx") == 4096 and options.get("num_predict") in (64, 1024)
                and options.get("temperature") == 0 and options.get("seed") == 42)
            properties = body.get("format", {}).get("properties", {})
            stage = "build" if "facts" in properties else "intent" if "intent" in properties else "answer" if "format" not in body else "unknown"
            stages[stage] += 1
            requests.append(event)
            {"build": build_posts, "intent": intent_posts, "answer": answer_posts}.get(stage, []).append(event)
        elif event["phase"] in {"response", "failure"}:
            ledger_ok &= type(index) is int and 1 <= index <= len(requests) and index not in terminal
            terminal[index] = event
            ledger_ok &= event["request_sha256"] == requests[index-1]["request_sha256"]
            if event["phase"] == "response":
                response, options = event["response"], requests[index-1]["request"]["options"]
                ledger_ok &= digest(response) == event["response_sha256"]
                prompt, generated = response.get("prompt_eval_count"), response.get("eval_count")
                within = (type(prompt) is int and type(generated) is int and 0 < prompt <= 3072
                    and 0 < generated <= options["num_predict"] and prompt+options["num_predict"] <= 4096)
                usage_ok &= within and event.get("actual_usage_within_budget") is True
                response_by_index[index] = response
        else:
            ledger_ok = False
    check("transport_sequential_requests_and_terminal_hashes", ledger_ok and set(terminal) == set(range(1, len(requests)+1)))
    check("actual_usage_complete_and_within_registered_limits", usage_ok and audit.get("actual_token_budget_violations") == 0)
    totals = {"model_builder_generations": sum(build["local_calls"] for build in builds if build["builder"] == "model"),
        "query_intent_generations": sum(intent["local_calls"] for intent in intents), "answer_generations": sum(row["answer_calls"] for row in rows)}
    check("post_stage_counts_match_shared_build_intent_answer", stages == Counter(build=totals["model_builder_generations"],
        intent=totals["query_intent_generations"], answer=totals["answer_generations"])
        and all(report[key] == value for key, value in totals.items())
        and len(requests) == sum(totals.values()) == audit.get("physical_generation_attempts") <= audit.get("registered_generation_cap") == 400
        and stages["build"] <= 16 and stages["intent"] <= 32 and stages["answer"] <= 352)
    encoder_counts = {"coverage_builder_encoder_calls": sum(item["inference_counts"]["local_encoder"] for item in builds),
        "coverage_builder_detector_generations": sum(item["inference_counts"]["local_generation"] for item in builds),
        "migration_encoder_calls": sum(row["inference_counts"]["local_encoder"] for row in rows),
        "migration_detector_generations": sum(row["inference_counts"]["local_generation"] for row in rows)}
    decomposition = all(set(item["inference_counts"]) == KINDS
        and all(type(value) is int and value >= 0 for value in item["inference_counts"].values())
        and item["inference_counts"]["unknown"] == 0 for item in [*rows, *builds])
    decomposition &= all(sum(row["inference_counts"].values()) == row["detector_calls"] for row in rows)
    decomposition &= all(sum(item["inference_counts"].values()) == item["local_calls"] if item["builder"] == "coverage"
                          else sum(item["inference_counts"].values()) == 0 for item in builds)
    check("saved_encoder_decomposition_and_report_totals", decomposition
        and all(report.get(key) == value for key, value in encoder_counts.items())
        and encoder_counts["coverage_builder_detector_generations"] == encoder_counts["migration_detector_generations"] == 0
        and report.get("detector_call_accounting_complete") is True)
    check("transport_response_failure_totals", audit.get("responses") == len(response_by_index)
        and audit.get("transport_errors") == sum(event["phase"] == "failure" for event in terminal.values()))
    answering_rows = [row for row in rows if row["answer_calls"] == 1]
    outputs_ok = len(answer_posts) == len(answering_rows)
    for row, event in zip(answering_rows, answer_posts):
        body = event["request"]
        actual = json.loads(body["messages"][1]["content"])
        outputs_ok &= actual == row.get("outbound")
        if row.get("actual_payload_sha256") is not None:
            outputs_ok &= digest(actual) == row["actual_payload_sha256"]
        response = response_by_index.get(event["index"])
        if row.get("answer_status") == "ok":
            outputs_ok &= (isinstance(response, dict) and response.get("model") == config["model"]
                and response.get("done") is True and response.get("done_reason") == "stop"
                and not response.get("message", {}).get("thinking") and not response.get("message", {}).get("tool_calls")
                and isinstance(response.get("message", {}).get("content"), str)
                and response["message"]["content"].strip() == row.get("model_answer"))
    check("actual_outbound_and_http_model_answers_one_to_one", outputs_ok)
    expected_build_texts = [stories[build["story_id"]]["source"]["text"] for build in builds if build["builder"] == "model"
                            for _ in range(build["local_calls"])]
    check("builder_requests_use_registered_source_text_only", [json.loads(event["request"]["messages"][1]["content"]) for event in build_posts]
          == [{"text": text} for text in expected_build_texts])
    check("intent_requests_use_registered_queries_once", [json.loads(event["request"]["messages"][1]["content"]) for event in intent_posts]
          == [{"query": tasks[(intent["story_id"], intent["task_id"])]["query"]} for intent in intents if intent["local_calls"] == 1])
    check("no_persisted_mapping_or_authority_key_objects", all(no_private_objects(value) for value in
        (plan, runtime, evaluation, report, config, rows, builds, stores, intents, events, audit)))
    check("local_only_network_and_cost", network.get("external_attempts_blocked") == 0 and audit.get("network") == network
        and audit.get("cloud_calls") == report.get("cloud_calls") == 0
        and audit.get("new_api_cost_cny") == report.get("new_api_cost_cny") == 0
        and config.get("endpoint") == "http://127.0.0.1:11435")
    return {"status": "passed" if all(item["passed"] for item in checks) else "failed", "execution_complete": True,
        "checks": checks, "rows_verified": len(rows), "arms": summaries, "physical_posts": len(requests),
        "observed_stage_posts": dict(stages), "verification_model_calls": 0,
        "encoder_counts_from_saved_host_observations": encoder_counts,
        "independent_mask_alignment_recomputed": False, "masking_basis": "saved original masking counters reused explicitly",
        "authenticated_restore_reexecuted": False, "privacy_utility_acceptance": "not_determined_by_this_verifier",
        "scope": "Independent arithmetic, matrix, source bindings, archive/input hashes and recorded HTTP consistency. Not cryptographic authenticity of a self-recorded trace or independent server billing. HMAC keys and recovery maps are absent, so authenticated restore and character-level masking cannot be replayed here."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=ROOT/"results/boundary_transfer_development_20261025_v2")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.run)
    except (ValueError, TypeError, KeyError, OSError, IndexError) as exc:
        result = {"status": "failed", "error": "audit_input_or_schema_invalid", "error_type": type(exc).__name__, "verification_model_calls": 0}
    if args.output:
        if args.output.exists():
            raise ValueError("new_verification_output_required")
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    sys.exit(0 if result["status"] == "passed" else 1)
