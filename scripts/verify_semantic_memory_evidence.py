"""Verify saved full-memory experiment consistency; never invoke a model.

Passing means the saved evidence agrees with its declared inputs/accounting.
It does not mean the method meets privacy, utility, or publication criteria.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.coverage_memory import verify_coverage_certificate
from memory_migration_study.privacy import _digest, _policy
from memory_migration_study.query_intent import INTENT_VERSION, query_sha256
from memory_migration_study.semantic_memory_benchmark import ARMS, aggregate


def sha(data):
    return hashlib.sha256(data).hexdigest()


def independent_score(row, gold):
    legal = row["actor_id"] == "owner"
    answer, expected = row.get("final_answer"), gold["answers"].get(row["task_id"])
    return {"legal": legal,
            "correct": bool(legal and isinstance(answer, str) and isinstance(expected, str)
                            and answer.strip().casefold() == expected.casefold()),
            "build_block": legal and row.get("build_status") != "ok",
            "preprocessing_block": legal and row.get("prepare_status") != "ok",
            "true_model_unknown": legal and (row.get("model_answer") or "").strip().casefold() == "unknown",
            "restoration_failure": legal and row.get("restoration_status") == "blocked",
            "outsider_blocked": (not legal and row.get("module_authorization_error") == "principal_not_authorized"
                                  and row.get("answer_calls", 0) == 0),
            "unauthorized_output": not legal and (row.get("prepare_status") == "ok" or bool(answer))}


def verify(run, *, corpus=None, allow_added_sources=()):
    run = Path(run)
    project = Path(__file__).resolve().parents[1]
    read = lambda name: json.loads((run / name).read_bytes())
    plan, runtime, evaluation = read("plan.json"), read("runtime.json"), read("evaluation.json")
    rows, builds, stores, report = read("rows.json"), read("builds.json"), read("record_store.json"), read("report.json")
    intents = read("intents.json") if (run / "intents.json").is_file() else []
    stories = {story["story_id"]: story for story in runtime}
    tasks = {(s["story_id"], t["task_id"]): t for s in runtime for t in s["tasks"]}
    build_index = {(b["story_id"], b["builder"]): b for b in builds}
    store_index = {(s["story_id"], s["builder"]): s["records"] for s in stores}
    checks = []
    def check(name, passed):
        checks.append({"check": name, "passed": bool(passed)})

    expected_builds = Counter((sid, family) for sid in stories for family in ("model", "coverage"))
    expected_rows = Counter((s["story_id"], t["task_id"], arm) for s in runtime for t in s["tasks"] for arm in ARMS)
    check("complete_unique_source_story_ids", len(stories) == len(runtime))
    check("complete_unique_build_matrix", Counter((b["story_id"], b["builder"]) for b in builds) == expected_builds)
    check("complete_unique_record_store_matrix", Counter((s["story_id"], s["builder"]) for s in stores) == expected_builds)
    check("complete_unique_story_task_six_arm_matrix", len(ARMS) == 6 and
          Counter((r["story_id"], r["task_id"], r["arm"]) for r in rows) == expected_rows)
    check("plan_arms_match", plan["arms"] == {key: list(value) for key, value in ARMS.items()})
    check("report_scope", report["source_stories"] == len(runtime) and report["split"] == plan["split"]
          and report["detector_kind"] == plan["detector_kind"]
          and report["template_families"] == len({s["template_family"] for s in runtime}))

    input_hash_sources = {}
    corpus = Path(corpus) if corpus is not None else project / "examples/privacy_semantics_v1"
    for name, field in (("runtime.json", "runtime_sha256"), ("evaluation.json", "evaluation_sha256")):
        snapshot = (run / name).read_bytes()
        matched = sha(snapshot) == plan[field]
        input_hash_sources[name] = "run_snapshot_raw_bytes" if matched else "unverified"
        original_path = corpus / plan["split"] / name
        if not matched and original_path.is_file():
            original = original_path.read_bytes()
            matched = sha(original) == plan[field] and json.loads(original) == json.loads(snapshot)
            if matched:
                input_hash_sources[name] = "original_corpus_bytes_and_equal_run_json"
        check("frozen_" + field, matched)
    archive = run / "implementation"
    expected_code = plan["implementation_sha256"]
    check("complete_executed_source_archive", {p.name for p in archive.glob("*.py")} == set(expected_code)
          and all(sha((archive / name).read_bytes()) == value for name, value in expected_code.items()))
    current_code = {p.name: sha(p.read_bytes()) for p in (project / "memory_migration_study").glob("*.py")}
    allowed_additions = set(allow_added_sources)
    if any(not isinstance(name, str) or Path(name).name != name or not name.endswith(".py")
           or name in expected_code for name in allowed_additions):
        raise ValueError("invalid_declared_source_addition")
    additions = set(current_code) - set(expected_code)
    unchanged = all(current_code.get(name) == digest for name, digest in expected_code.items())
    check("executed_sources_unchanged_and_only_declared_additions",
          unchanged and additions <= allowed_additions and report["implementation_unchanged"] is True)

    evidence_ok, certificates_ok, deployment_ok, volumes_ok, labels_ok = True, True, True, True, True
    storage = {}
    for build in builds:
        sid, family = build["story_id"], build["builder"]
        story = stories[sid]
        source = story["source"]
        original = source["text"]
        records = store_index[(sid, family)]
        facts = build["facts"]
        def is_exact(item):
            a, b = item.get("source_start"), item.get("source_end")
            return (type(a) is int and type(b) is int and 0 <= a < b <= len(original)
                    and original[a:b] == item.get("text"))
        evidence_ok &= all(is_exact(fact) for fact in facts) and all(is_exact(record) for record in records)
        deployment_ok &= ([(r["text"], r["source_start"], r["source_end"]) for r in records] ==
                          [(f["text"], f["source_start"], f["source_end"]) for f in facts] if build["status"] == "ok" else not records)
        if family == "coverage":
            certificate = build["coverage"]
            certificates_ok &= verify_coverage_certificate(original, certificate)
            certificates_ok &= [(s["start"], s["end"]) for s in certificate["spans"]] == [(f["source_start"], f["source_end"]) for f in facts]
        characters = sum(len(r["text"]) for r in records)
        json_bytes = len(json.dumps(records, ensure_ascii=False).encode("utf-8"))
        source_copies = sum(len(r["source"]["text"]) for r in records)
        volumes_ok &= (build["stored_characters"] == characters and build["stored_record_json_bytes"] == json_bytes
                       and build["stored_source_copy_characters"] == source_copies and build["source_characters"] == len(original))
        storage[(sid, family)] = {"stored_characters": characters, "stored_record_json_bytes": json_bytes,
                                 "stored_source_copy_characters": source_copies,
                                 "stored_source_copy_utf8_bytes": sum(len(r["source"]["text"].encode("utf-8")) for r in records)}
        for record in records:
            label, grant = record["label"], record["access"]
            labels_ok &= (record["source"] == {"source_id": source["source_id"], "text": original, "sha256": sha(original.encode("utf-8"))}
                          and record["source_id"] == record["record_id"] == label["record_id"] == grant["record_id"]
                          and label["content_sha256"] == sha(record["text"].encode("utf-8"))
                          and label["source_start"] == record["source_start"] and label["source_end"] == record["source_end"]
                          and label["source_sha256"] == grant["source_sha256"] == record["source"]["sha256"]
                          and grant["source_id"] == source["source_id"]
                          and label["policy_version"] == story["policy"]["version"]
                          and label["policy_sha256"] == _digest(_policy(story["policy"])) and label["access_sha256"] == _digest(grant))
    check("all_candidate_and_stored_facts_are_exact_contiguous_source_spans", evidence_ok)
    check("only_successful_builds_deployed_exact_candidates", deployment_ok)
    check("candidate_coverage_certificates_recomputed", certificates_ok)
    check("stored_source_content_and_label_hash_links", labels_ok)
    check("all_record_storage_volumes_recomputed", volumes_ok)

    row_bindings, scores_ok, support_ok, call_decomposition_ok, detection_observations_ok, outbound_hashes_ok = (True,)*6
    by_arm = {arm: {"legal": 0, "supported": 0, "supported_and_ready": 0, "supported_model_unknown": 0,
                    "supported_ready_model_unknown": 0, "supported_without_final_fact": 0,
                    "unsupported_model_unknown": 0, "outsider_module_denials": 0,
                    "outsider_not_executed_no_records": 0, "outsider_answer_calls": 0,
                    "outbound_attempts": 0, "raw_local_outbound_attempts": 0,
                    "full_registered_secret_memory_exposures": 0, "full_registered_secret_query_exposures": 0}
              for arm in ARMS}
    outsider_ok = True
    for row in rows:
        sid, arm = row["story_id"], row["arm"]
        family, mode, _ = ARMS[arm]
        task, story = tasks[(sid, row["task_id"])], stories[sid]
        records, build = store_index[(sid, family)], build_index[(sid, family)]
        row_bindings &= (row["actor_id"] == task["actor_id"] and row["mode"] == mode
                         and row["language"] == story["language"] and row["template_family"] == story["template_family"]
                         and row["build_status"] == build["status"])
        recomputed = independent_score(row, evaluation[sid])
        scores_ok &= recomputed == row["score"]
        expected = evaluation[sid]["answers"].get(row["task_id"])
        supported = bool(expected and any(expected in r["text"] for r in records))
        support_ok &= supported == row["required_fact_retained"]
        metrics = by_arm[arm]
        if recomputed["legal"]:
            metrics["legal"] += 1
            metrics["supported"] += supported
            ready = row.get("prepare_status") == "ok"
            unknown = row.get("answer_status") == "ok" and (row.get("model_answer") or "").strip().casefold() == "unknown"
            metrics["supported_and_ready"] += supported and ready
            metrics["supported_model_unknown"] += supported and unknown
            metrics["supported_ready_model_unknown"] += supported and ready and unknown
            metrics["unsupported_model_unknown"] += not supported and unknown
            metrics["supported_without_final_fact"] += supported and (not row.get("final_answer") or row["final_answer"].strip().casefold() == "unknown")
        else:
            metrics["outsider_answer_calls"] += row["answer_calls"]
            if records:
                metrics["outsider_module_denials"] += row.get("module_authorization_error") == "principal_not_authorized"
                outsider_ok &= row.get("module_authorization_error") == "principal_not_authorized" and row["prepare_status"] == "blocked"
            else:
                metrics["outsider_not_executed_no_records"] += 1
                outsider_ok &= row.get("module_authorization_error") is None and not row["score"]["outsider_blocked"]
            outsider_ok &= row["answer_calls"] == 0 and row.get("outbound") is None and row.get("final_answer") is None
        breakdown = row["inference_counts"]
        call_decomposition_ok &= (set(breakdown) == {"local_encoder", "local_generation", "unknown"}
                                  and all(type(v) is int and v >= 0 for v in breakdown.values())
                                  and sum(breakdown.values()) == row["detector_calls"]
                                  and type(row["answer_calls"]) is int and row["answer_calls"] in (0, 1))
        detection = row.get("detection")
        if detection is not None:
            observations = detection["agent_observations"]
            detection_observations_ok &= (sum(o.get("local_calls", 0) for o in observations) == detection["local_calls"] == row["detector_calls"])
        elif mode == "raw" or not records:
            detection_observations_ok &= row["detector_calls"] == 0
        actual = row.get("outbound")
        if row.get("actual_payload_sha256") is not None:
            outbound_hashes_ok &= actual is not None and _digest(actual) == row["actual_payload_sha256"]
        if row["answer_calls"]:
            outbound_hashes_ok &= isinstance(actual, dict) and set(actual) == {"query", "memories"}
            metrics["outbound_attempts"] += 1
            if mode == "raw":
                metrics["raw_local_outbound_attempts"] += 1
            else:
                source = story["source"]["text"]
                values = [source[s["start"]:s["end"]].casefold() for s in evaluation[sid]["sensitive_spans"]]
                metrics["full_registered_secret_memory_exposures"] += any(v in m["text"].casefold() for v in values for m in actual["memories"])
                metrics["full_registered_secret_query_exposures"] += any(v in actual["query"].casefold() for v in values)
    check("rows_bound_to_registered_tasks_and_builders", row_bindings)
    check("independent_per_task_scores", scores_ok)
    check("required_fact_retention_recomputed_from_store", support_ok)
    check("actual_outsider_module_denials_or_explicit_unexecuted_builds", outsider_ok)
    check("per_row_encoder_generation_decomposition", call_decomposition_ok)
    check("saved_host_detection_call_observations", detection_observations_ok)
    check("captured_answer_input_hashes", outbound_hashes_ok)

    build_calls_ok = True
    for build in builds:
        breakdown = build["inference_counts"]
        build_calls_ok &= (set(breakdown) == {"local_encoder", "local_generation", "unknown"}
                           and all(type(v) is int and v >= 0 for v in breakdown.values())
                           and type(build["local_calls"]) is int and 0 <= build["local_calls"])
        if build["builder"] == "coverage":
            build_calls_ok &= sum(breakdown.values()) == build["local_calls"] == build["detector_local_calls"]
            build_calls_ok &= sum(d["local_calls"] for d in build["diagnostics"]) == build["local_calls"]
        else:
            build_calls_ok &= sum(breakdown.values()) == 0
    check("per_build_encoder_generation_decomposition", build_calls_ok)
    intent_expected = Counter((sid, task_id) for (sid, task_id), task in tasks.items()
                              if task["actor_id"] == "owner" and store_index[(sid, "coverage")])
    check("unique_eligible_intent_matrix_no_outsider_calls", Counter((i["story_id"], i["task_id"]) for i in intents) == intent_expected)
    check("classifier_query_hash_version_and_single_call_bound", all(
          i["query_sha256"] == query_sha256(tasks[(i["story_id"], i["task_id"])]["query"])
          and i["version"] == INTENT_VERSION and type(i["local_calls"]) is int and i["local_calls"] in (0, 1)
          and isinstance(i["request_id"], str) and bool(i["request_id"]) for i in intents))
    totals = {"model_builder_generations": sum(b["local_calls"] for b in builds if b["builder"] == "model"),
              "coverage_builder_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds),
              "coverage_builder_detector_generations": sum(b["inference_counts"]["local_generation"] for b in builds),
              "query_intent_generations": sum(i["local_calls"] for i in intents),
              "migration_encoder_calls": sum(r["inference_counts"]["local_encoder"] for r in rows),
              "migration_detector_generations": sum(r["inference_counts"]["local_generation"] for r in rows),
              "answer_generations": sum(r["answer_calls"] for r in rows)}
    check("all_actual_physical_call_total_fields", all(report[k] == v for k, v in totals.items()))
    check("all_six_arm_aggregates_recomputed", aggregate(rows, builds) == report["arms"])
    check("no_cloud_declared_by_plan_and_report", plan["no_cloud"] is True and report["cloud_calls"] == 0 and report["new_api_cost_cny"] == 0)
    storage_totals = {family: {key: sum(value[key] for (_, f), value in storage.items() if f == family)
                              for key in ("stored_characters", "stored_record_json_bytes", "stored_source_copy_characters", "stored_source_copy_utf8_bytes")}
                      for family in ("model", "coverage")}
    return {"status": "passed" if all(c["passed"] for c in checks) else "failed", "checks": checks,
            "run_split": plan["split"], "detector_kind": plan["detector_kind"], "rows_verified": len(rows),
            "builds_verified": len(builds), "input_hash_sources": input_hash_sources,
            "current_snapshot_identical": current_code == expected_code,
            "additional_current_sources": sorted(additions), "declared_allowed_additions": sorted(allowed_additions),
            "actual_call_totals": totals, "detector_call_accounting_complete": report["detector_call_accounting_complete"],
            "supported_tasks_and_literal_scan": by_arm, "storage_totals": storage_totals,
            "record_store_file_bytes": (run / "record_store.json").stat().st_size,
            "verification_model_calls": 0, "verification_script_sha256": sha(Path(__file__).read_bytes()),
            "scope": "Evidence consistency only; not privacy/utility acceptance. Raw local control is excluded from privacy-violation scans. Full-value scans cannot establish zero partial leaks or detect semantic inference. Original character-level masking alignment and authenticated restoration cannot be replayed because recovery maps and HMAC keys were not saved. Candidate coverage certificates describe candidate source retention, not successful storage or privacy. Actual call totals reflect saved host instrumentation, not independent server billing."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, help="Optional original corpus for raw-byte input hashes before snapshot reserialization")
    parser.add_argument("--allow-added-source", action="append", default=[],
                        help="Explicit new module absent from the executed archive; never permits changes to an executed file")
    args = parser.parse_args()
    try:
        result = verify(args.run, corpus=args.corpus, allow_added_sources=args.allow_added_source)
    except (KeyError, ValueError, TypeError, OSError, AttributeError):
        result = {"status": "failed", "error": "evidence_input_or_schema_invalid", "verification_model_calls": 0}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8"))
    print(json.dumps({"status": result["status"], "checks": len(result.get("checks", [])),
                      "rows_verified": result.get("rows_verified"), "verification_model_calls": 0}))
    raise SystemExit(0 if result["status"] == "passed" else 1)
