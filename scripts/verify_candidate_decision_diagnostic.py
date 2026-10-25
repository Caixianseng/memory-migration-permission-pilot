"""Independent zero-model audit of the seven-arm exposed candidate diagnostic.

Never executes archived code or reads gold before requiring model closure.
Current source-pinned pure adapters consume saved observations through a fake
transport. Successful verification means consistency, never method acceptance.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import random
import socket
import sys
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_context_candidate_diagnostic import (
    clean_times, compact, moment, no_gold_fields, read, same, score, sha,
    span_keys, sum_counts, text_sources, usage_evidence, _replay_material,
)

VERSION = "independent_candidate_decision_diagnostic_verification_v1"
REFERENCE_SHA256 = "330d31c9e70980631dd3b67dc8a059512af77693e39870c2b8570b696effce43"
RUN_VERSION = "flat_candidate_decision_paired_development_v1"
SEED = 2026102603
PRIMARY = "primary_boundary_full_no_prior"
CONFIGS = {
    "flat_local_prior": {"context_view": "local_windows", "show_proposed_category": True},
    "flat_local_no_prior": {"context_view": "local_windows", "show_proposed_category": False},
    "flat_full_no_prior": {"context_view": "full_source", "show_proposed_category": False},
    PRIMARY: {"context_view": "full_source", "show_proposed_category": False},
}
CONTROLS = ("recorded_raw_ner", "standard_boundary_ner", "recorded_five_field_all")
ARMS = (*CONTROLS, *CONFIGS)
SPLITS = {"development": 80, "heldout": 40}
SOURCE_NAMES = ("privacy", "local_detector", "ner_detector", "candidate_proposals", "candidate_adjudicator",
    "context_candidate_typing", "context_typed_detection", "boundary_detector", "boundary_reconciliation",
    "structured_candidates", "amount_candidates", "candidate_decision", "candidate_decision_detection")
SOURCES = {"scripts/run_candidate_decision_diagnostic.py", "scripts/run_context_candidate_diagnostic.py",
    "scripts/run_semantic_detection_benchmark.py", *("memory_migration_study/" + name + ".py" for name in SOURCE_NAMES)}
OLD_SOURCES = {"scripts/run_context_candidate_diagnostic.py", "scripts/run_semantic_detection_benchmark.py",
    *("memory_migration_study/" + name + ".py" for name in SOURCE_NAMES[:7])}
BOUND = {"plan.json", "reference_materials.json", "identities.json", "materials.json", "model_calls.json", "unscored_rows.json"}
ERRORS = (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, AssertionError,
          StopIteration, RecursionError, zipfile.BadZipFile)


def _json_bytes(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def _normalized_sources(values):
    result = {key.replace("\\", "/"): value for key, value in values.items()}
    if len(result) != len(values) or any(Path(key).is_absolute() or ".." in Path(key).parts for key in result):
        raise ValueError("invalid_source_manifest")
    return result


def _static_phase_order(source):
    tree = ast.parse(source)
    run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
    closed = [node.lineno for node in ast.walk(run) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
            and target.value.id == "observer" and target.attr == "closed" for target in node.targets)
        and isinstance(node.value, ast.Constant) and node.value.value is True]
    gold = [node.lineno for node in ast.walk(run) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json" and node.func.attr == "loads"
        and "evaluation.json" in ast.unparse(node)]
    scores = [node.lineno for node in ast.walk(run) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "score_detection"]
    prepare = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "prepare_reference")
    early_loads = [ast.unparse(node) for node in ast.walk(prepare) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json" and node.func.attr == "loads"]
    return (len(closed) == len(gold) == 1 and bool(scores) and closed[0] < gold[0] < min(scores)
        and all("evaluation.json" not in value and "rows.json" not in value and "report.json" not in value
                for value in early_loads))


def _archive(archive):
    if sha(archive.read_bytes()) != REFERENCE_SHA256:
        raise ValueError("not_the_fixed_public_reference_archive")
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        if len(names) != len(set(names)) or sum(item.file_size for item in source.infolist()) > 80 * 1024 * 1024:
            raise ValueError("invalid_public_archive")
        blobs = {name: source.read(name) for name in names}
    manifest = _json_bytes(blobs["PUBLIC_ARTIFACT_MANIFEST.json"])
    # Publisher's packaging README is deliberately outside the member manifest;
    # the hard-pinned whole-ZIP digest still binds those bytes as well.
    if set(manifest["files"]) != set(blobs) - {"PUBLIC_ARTIFACT_MANIFEST.json", "README.txt"} or any(
            sha(blobs[name]) != expected for name, expected in manifest["files"].items()):
        raise ValueError("public_archive_member_hash_mismatch")
    plan = _json_bytes(blobs["plan.json"])
    if set(_normalized_sources(plan["implementation_sha256"])) != OLD_SOURCES:
        raise ValueError("historical_source_set_changed")
    # Gold remains bytes here. Only prediction/runtime metadata is decoded.
    return blobs, manifest, plan, _json_bytes(blobs["materials.json"]), _json_bytes(blobs["identities.json"])


def _without_scores(value):
    if isinstance(value, dict):
        return not (set(value) & {"gold", "score", "scores", "accepted", "accepted_complete_exact", "answers"}) \
            and all(_without_scores(item) for item in value.values())
    return not isinstance(value, list) or all(_without_scores(item) for item in value)


def _replay_stage(case, pool, saved, observed, config):
    from memory_migration_study.candidate_decision import LocalCandidateDecision, preflight
    remaining, faults = list(observed), []
    def transport(method, path, body=None):
        if method != "POST" or path != "/api/chat" or not remaining:
            faults.append("unexpected_transport")
            raise AssertionError("unexpected_transport")
        call = remaining.pop(0)
        if not same(body, call["request"]):
            faults.append("body_mismatch")
            raise AssertionError("body_mismatch")
        if call.get("transport_error") is not None:
            raise RuntimeError("recorded_transport_failure")
        return deepcopy(call["response"])
    agent = LocalCandidateDecision(config, transport=transport)
    def health():
        if saved.get("error") == "decision_local_health_failed":
            raise RuntimeError("recorded_health_failure")
        return deepcopy(saved.get("health"))
    agent.health = health
    replayed = agent.classify(case["payload"], case["policy"], pool)
    if remaining or faults or not same(clean_times(replayed), clean_times(saved)):
        raise ValueError("recorded_stage_replay_mismatch")
    return preflight(case["payload"], case["policy"], pool, config=config)


def verify(run, *, archive=None):
    run = Path(run).resolve()
    archive = Path(archive).resolve() if archive else ROOT / "benchmarks/artifacts/context_candidate_detection_20261026_v2.zip"
    checks, phase = [], "reference"
    def check(name, predicate):
        try:
            passed = bool(predicate() if callable(predicate) else predicate)
        except ERRORS:
            passed = False
        checks.append({"check": name, "passed": passed})
        return passed
    def finish(status=None, **extra):
        return {"version": VERSION, "status": status or ("passed" if all(c["passed"] for c in checks) else "failed"),
            "checks": checks, "verification_model_calls": 0, "privacy_or_recall_acceptance": False,
            "independent_acceptance": False, "phase": phase,
            "scope": "Offline consistency and fake replay; exposed development/regression, never new acceptance.",
            "limitations": ["Checksums/timestamps establish consistency, not resistance to coordinated forgery.",
                "Physical POST receipts observe the local transport entry, not packet capture or GPU kernels.",
                "A failed detector may still receive a passed consistency audit; method acceptance is separate."], **extra}
    try:
        if not check("results_workspace_scope", run.is_relative_to((ROOT / "results").resolve())):
            return finish()
        blobs, public, old_plan, reference_materials, old_ids = _archive(archive)
        check("fixed_public_reference_archive_and_all_members", True)
        plan = read(run / "plan.json")
        reference = plan["reference"]
        check("reference_receipt_historical_cost_not_new_inference", lambda:
            reference["archive_sha256"] == REFERENCE_SHA256 and same(reference["public_manifest"], public)
            and same(reference["corpus_sha256"], old_plan["corpus_sha256"])
            and reference["historical_encoder_calls"] == 168 and reference["historical_generation_calls"] == 81
            and reference["new_encoder_calls"] == 0
            and reference["reference_materials_sha256"] == sha(blobs["materials.json"])
            == sha((run / "reference_materials.json").read_bytes())
            and _without_scores(reference_materials))
        corpus = []
        for split, number in SPLITS.items():
            raw = (run / split / "runtime.json").read_bytes()
            values = _json_bytes(raw)
            check(split + "_original_runtime_and_gold_bytes", lambda: len(values) == number
                and raw == blobs[split + "/runtime.json"]
                and sha(raw) == old_plan["corpus_sha256"][split + "/runtime.json"]
                and (run / split / "evaluation.json").read_bytes() == blobs[split + "/evaluation.json"]
                and sha(blobs[split + "/evaluation.json"]) == old_plan["corpus_sha256"][split + "/evaluation.json"])
            corpus.extend({**case, "split": split} for case in values)
        by_id = {case["case_id"]: case for case in corpus}
        references = {material["case_id"]: material for material in reference_materials}
        order = deepcopy(corpus)
        rng = random.Random(SEED)
        rng.shuffle(order)
        schedule = []
        for case in order:
            arms = list(CONFIGS)
            rng.shuffle(arms)
            schedule.append({"case_id": case["case_id"], "arm_order": arms})
        check("predeclared_primary_configs_schedule_counts_and_caps", lambda:
            plan["version"] == RUN_VERSION and plan["seed"] == SEED and same(plan["schedule"], schedule)
            and same(plan["configs"], CONFIGS) and plan["controls"] == list(CONTROLS) and plan["primary"] == PRIMARY
            and len(by_id) == len(references) == len(corpus) == plan["material_count"] == 120
            and set(references) == set(by_id) and plan["row_count"] == 840
            and plan["max_new_generations"] == 960 and plan["max_output_tokens"] == 1024
            and plan["context_tokens"] == 4096 and plan["max_candidates"] == 16
            and plan["heldout_scope"] == "exposed_regression_not_independent_acceptance"
            and plan["cloud_calls"] == plan["new_api_cost_cny"] == 0 and plan["default_branch_changed"] is False
            and plan["raw_pool_development_ceiling"]["covered"] == 55
            and plan["raw_pool_development_ceiling"]["gold_spans"] == 58
            and plan["boundary_pool_development_ceiling"]["covered"] == 57
            and plan["boundary_pool_development_ceiling"]["gold_spans"] == 58)
        current_sources = _normalized_sources(plan["implementation_sha256"])
        old_sources = _normalized_sources(old_plan["implementation_sha256"])
        source_ok = check("source_hashes_current_frozen_and_nine_historical_implementations", lambda:
            set(current_sources) == SOURCES and all(sha((ROOT / rel).read_bytes()) == expected
                == sha((run / "frozen_source" / rel).read_bytes()) for rel, expected in current_sources.items())
            and all(current_sources[rel] == expected for rel, expected in old_sources.items()))
        check("source_declares_gold_parse_and_scoring_after_model_closure", lambda: _static_phase_order(
            (run / "frozen_source/scripts/run_candidate_decision_diagnostic.py").read_text(encoding="utf-8")))
        if not (run / "model_phase_closed.json").is_file():
            return finish("incomplete" if all(item["passed"] for item in checks) else "failed",
                execution_complete=False, note="No closed phase; gold was not parsed and no scores were accepted.")
        phase = "closed_artifacts"
        closure, scoring = read(run / "model_phase_closed.json"), read(run / "score_phase_started.json")
        closed_ok = check("closed_artifact_hashes_and_gold_phase_time", lambda:
            closure["model_phase_closed"] is True and set(closure["artifact_sha256"]) == BOUND
            and all(sha((run / name).read_bytes()) == expected for name, expected in closure["artifact_sha256"].items())
            and scoring["closure_sha256"] == sha((run / "model_phase_closed.json").read_bytes())
            and moment(plan["created_at"]) <= moment(closure["closed_at"]) <= moment(scoring["started_at"]))
        if not closed_ok or not source_ok:
            return finish(execution_complete=False, note="Untrusted closure/source; gold was not parsed and archived code was not executed.")
        materials, calls, unscored, rows, report, identities, network = [read(run / name) for name in (
            "materials.json", "model_calls.json", "unscored_rows.json", "rows.json", "report.json", "identities.json", "network_audit.json")]
        expected_rows = [(entry["case_id"], arm) for entry in schedule for arm in (*CONTROLS, *entry["arm_order"])]
        check("all_120_materials_and_840_rows_preserved", lambda:
            [material["case_id"] for material in materials] == [entry["case_id"] for entry in schedule]
            and [(row["case_id"], row["arm"]) for row in rows] == expected_rows
            and len(rows) == 840 and len(materials) == 120
            and same([{key: value for key, value in row.items() if key != "score"} for row in rows], unscored)
            and all("score" not in row for row in unscored))
        row_index = {(row["case_id"], row["arm"]): row for row in rows}
        forbidden_ids = {case["case_id"] for case in corpus}
        forbidden_ids.update(item["source_id"] for case in corpus for item in case["payload"]["memories"])
        forbidden_ids.update(case["policy"][key] for case in corpus for key in ("version", "policy_id") if key in case["policy"])
        def physical_calls_ok():
            assert len(calls) <= 960 and [call["index"] for call in calls] == list(range(len(calls)))
            assert closure["new_generation_posts"] == report["new_generation_posts"] == len(calls)
            previous_end = moment(plan["created_at"])
            for call in calls:
                body = call["request"]
                assert call["case_id"] in by_id and call["arm"] in CONFIGS and call["path"] == "/api/chat"
                assert set(body) == {"model", "messages", "format", "stream", "keep_alive", "options"}
                assert body["options"] == {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42}
                assert body["stream"] is False and body["keep_alive"] == "30m" and no_gold_fields(body)
                assert len(body["messages"]) in (2, 3) and body["messages"][1]["role"] == "user"
                data = _json_bytes(body["messages"][1]["content"])
                assert no_gold_fields(data) and set(data["trusted_policy"]) == {"protected_categories", "instructions"}
                config = CONFIGS[call["arm"]]
                assert set(data) == ({"trusted_policy", "sources", "candidates"} if config["context_view"] == "full_source"
                    else {"trusted_policy", "evidence", "candidates"})
                assert all(("proposed_category" in candidate) == config["show_proposed_category"] for candidate in data["candidates"])
                schema = body["format"]
                assert set(schema) == {"type", "minItems", "maxItems", "items"} and schema["type"] == "array"
                assert schema["minItems"] == schema["maxItems"] == len(data["candidates"]) <= 16
                assert schema["items"]["required"] == ["cid", "decision"] and schema["items"]["additionalProperties"] is False
                assert set(schema["items"]["properties"]) == {"cid", "decision"}
                assert schema["items"]["properties"]["cid"] == {"enum": [candidate["cid"] for candidate in data["candidates"]]}
                assert schema["items"]["properties"]["decision"] == {"enum": [
                    *("VALUE_" + cat for cat in data["trusted_policy"]["protected_categories"]), "GENERIC_ROLE", "FIELD_LABEL", "OTHER", "UNCERTAIN"]}
                serialized = compact(body)
                assert not any(identifier in serialized for identifier in forbidden_ids if len(identifier) > 6)
                assert call["request_utf8_bytes"] == len(serialized.encode("utf-8"))
                assert call["request_sha256"] == sha(serialized.encode("utf-8"))
                assert len(serialized.encode("utf-8")) + 320 + 1024 <= 4096
                assert previous_end <= moment(call["started_at"]) <= moment(call["completed_at"]) <= moment(closure["closed_at"])
                previous_end = moment(call["completed_at"])
                assert call["transport_error"] in {None, "local_transport_failed"}
            return True
        check("physical_POST_schema_no_gold_or_source_IDs_serial_budget", physical_calls_ok)
        check("new_zero_encoder_and_loopback_only_network_accounting", lambda:
            network == report["network"] and set(network) == {"allowed_loopback_connections", "blocked_external_connections"}
            and all(type(value) is int and value >= 0 for value in network.values()) and network["blocked_external_connections"] == 0
            and report["new_encoder_calls"] == report["cloud_calls"] == report["new_api_cost_cny"] == 0
            and report["new_generation_posts_by_arm"] == dict(Counter(call["arm"] for call in calls)))
        phase = "pure_replay"
        from memory_migration_study.boundary_detector import refine_detection
        from memory_migration_study.candidate_proposals import propose_candidates
        from memory_migration_study.candidate_decision import LocalCandidateDecision
        from memory_migration_study.candidate_decision_detection import compose_decision_detection
        from memory_migration_study.context_typed_detection import compose_typed_detection
        check("runtime_model_and_four_method_identities", lambda:
            set(identities["agents"]) == set(CONFIGS)
            and all(same(identities["agents"][arm], LocalCandidateDecision(config).cache_identity()) for arm, config in CONFIGS.items())
            and same(identities["recorded_ner"], old_ids["ner"]) and same(identities["recorded_old_typer"], old_ids["typer"])
            and identities["health"] == {"version": identities["agents"][PRIMARY]["runtime"], "model": identities["agents"][PRIMARY]["model"],
                "digest": identities["agents"][PRIMARY]["digest"], "endpoint": "http://127.0.0.1:11435"})
        old_calls, old_encodings = _json_bytes(blobs["model_calls.json"]), _json_bytes(blobs["encoding_invocations.json"])
        all_indices, pools, unexpected_network = [], {}, []
        def deny_network(*args, **kwargs):
            unexpected_network.append("network_attempt_during_offline_replay")
            raise AssertionError("network_attempt_during_offline_replay")
        with patch.object(socket.socket, "connect", deny_network), patch.object(socket, "create_connection", deny_network):
            for material in materials:
                cid, case = material["case_id"], by_id[material["case_id"]]
                historical = references[cid]
                selected_old = [old_calls[index] for index in historical["generation_indices"]]
                encodings = [item for item in old_encodings if item["case_id"] == cid]
                check("historical_encoder_and_five_field_stage_replay_" + cid,
                    lambda: bool(_replay_material(case, historical, encodings, selected_old, old_ids)))
                baseline = historical["baseline"]
                raw_pool = propose_candidates(case["payload"], case["policy"], baseline["findings"], max_candidates=16, max_quote_chars=256)
                boundary = refine_detection(case["payload"], case["policy"], baseline)
                boundary_pool = propose_candidates(case["payload"], case["policy"], boundary["findings"], max_candidates=16, max_quote_chars=256)
                pools[cid] = (raw_pool, boundary_pool)
                expected_controls = {CONTROLS[0]: baseline, CONTROLS[1]: boundary,
                    CONTROLS[2]: compose_typed_detection(case["payload"], case["policy"], baseline, raw_pool, historical["typing"])}
                check("three_recorded_controls_and_boundary_pool_" + cid, lambda:
                    same(raw_pool, historical["pool"]) and same(boundary, material["boundary_baseline"])
                    and same(boundary_pool, material["boundary_pool"]) and set(material["stages"]) == set(CONFIGS)
                    and all(same(clean_times(value), clean_times(row_index[(cid, arm)]["detection"])) for arm, value in expected_controls.items()))
                for arm in next(entry["arm_order"] for entry in schedule if entry["case_id"] == cid):
                    saved = material["stages"][arm]
                    stage, indices = saved["stage"], saved["generation_indices"]
                    def binding_ok():
                        assert isinstance(indices, list) and all(type(index) is int and 0 <= index < len(calls) for index in indices)
                        assert len(indices) == stage["local_calls"] == len(stage["raw_calls"]) <= 2
                        selected = [calls[index] for index in indices]
                        assert all(call["case_id"] == cid and call["arm"] == arm for call in selected)
                        assert all(same(call["request"], raw["request"]) and same(call["response"], raw["response"])
                            and (call["transport_error"] is None) == (raw["error"] is None) for call, raw in zip(selected, stage["raw_calls"]))
                        assert same(stage["config"], CONFIGS[arm])
                        return True
                    bound = check("physical_attempt_binding_" + cid + "_" + arm, binding_ok)
                    all_indices.extend(indices)
                    base, pool = (boundary, boundary_pool) if arm == PRIMARY else (baseline, raw_pool)
                    def replay_ok():
                        assert bound
                        expected_preflight = _replay_stage(case, pool, stage, [calls[index] for index in indices], CONFIGS[arm])
                        expected = compose_decision_detection(case["payload"], case["policy"], base, pool, stage)
                        assert same(expected_preflight, saved["preflight"])
                        assert same(clean_times(expected), clean_times(row_index[(cid, arm)]["detection"]))
                        return True
                    check("preflight_rawstage_fake_replay_and_composition_" + cid + "_" + arm, replay_ok)
                    immutable = {key for key in span_keys(base["findings"], case["payload"])[0]
                        if key[3] not in {"PERSON", "CUSTOMER", "PROJECT", "ADDRESS"} or any(
                            (finding.get("source_id"), finding.get("start"), finding.get("end"), finding.get("category")) == key
                            and "registry" in finding.get("method", "").split("+") for finding in base["findings"])}
                    current = row_index[(cid, arm)]["detection"]
                    check("strong_protections_or_explicit_processing_failure_" + cid + "_" + arm,
                        current["status"] != "ok" or immutable <= span_keys(current["findings"], case["payload"])[0])
        check("every_new_physical_attempt_owned_exactly_once", all_indices == list(range(len(calls))))
        check("offline_replay_attempted_no_network", unexpected_network == [])
        usage = usage_evidence(calls)
        invalid_usage = set(usage["over_budget_call_indices"] + usage["usage_unavailable_call_indices"])
        check("invalid_usage_never_becomes_successful_stage", all(
            not (set(saved["generation_indices"]) & invalid_usage) or saved["stage"]["status"] != "typing_only"
            for material in materials for saved in material["stages"].values()))
        check("report_predeclared_primary_scope_complete_and_source_unchanged", lambda:
            report["version"] == RUN_VERSION and report["primary"] == PRIMARY and report["rows"] == 840
            and report["materials"] == 120 and report["implementation_unchanged"] is True
            and report["independent_acceptance"] is False and report["default_changed"] is False
            and all(sha((ROOT / rel).read_bytes()) == expected for rel, expected in current_sources.items()))
        # Only now parse original evaluation labels. They never enter fake model input.
        phase = "independent_score"
        labels = {}
        for split in SPLITS:
            check(split + "_post_model_gold_bytes_still_original", lambda:
                (run / split / "evaluation.json").read_bytes() == blobs[split + "/evaluation.json"])
            gold = read(run / split / "evaluation.json")
            check(split + "_complete_gold_identity", set(gold) == {case["case_id"] for case in corpus if case["split"] == split})
            labels.update(gold)
        for row in rows:
            cid, arm = row["case_id"], row["arm"]
            check("independent_full_span_score_" + cid + "_" + arm, lambda:
                same(row["score"], score(row["detection"], labels[cid], by_id[cid]["payload"]))
                and row["split"] == by_id[cid]["split"] and row["language"] == by_id[cid]["language"])
        summary = {split: {} for split in SPLITS}
        for split, number in SPLITS.items():
            for arm in ARMS:
                selected = [row for row in rows if row["split"] == split and row["arm"] == arm]
                recomputed = [score(row["detection"], labels[row["case_id"]], by_id[row["case_id"]]["payload"]) for row in selected]
                check("full_material_denominator_" + split + "_" + arm, len(selected) == number)
                summary[split][arm] = {"materials": len(selected), "accepted": sum_counts([item["accepted"] for item in recomputed]),
                    "ok": sum(row["detection"]["status"] == "ok" for row in selected),
                    "complete_exact": sum(item["accepted_complete_exact"] for item in recomputed),
                    "errors": dict(Counter(error for row in selected for error in row["detection"]["errors"]))}
        check("independent_summary_all_seven_arms", same(summary, report["summary"]))
        ceilings = {}
        for split in SPLITS:
            totals = {"gold_spans": 0, "raw_pool_covered": 0, "boundary_pool_covered": 0}
            for case in corpus:
                if case["split"] != split:
                    continue
                cid = case["case_id"]
                expected = span_keys(labels[cid]["findings"], case["payload"], strict=True)[0]
                totals["gold_spans"] += len(expected)
                for index, name in enumerate(("raw_pool_covered", "boundary_pool_covered")):
                    candidates = pools[cid][index]["candidates"]
                    totals[name] += sum(any((candidate["source_id"], candidate["start"], candidate["end"]) == key[:3]
                        and candidate["proposed_category"] in (None, key[3]) for candidate in candidates) for key in expected)
            ceilings[split] = totals
        check("post_closure_candidate_ceiling_qualifies_primary_boundary", ceilings == {
            "development": {"gold_spans": 58, "raw_pool_covered": 55, "boundary_pool_covered": 57},
            "heldout": {"gold_spans": 20, "raw_pool_covered": 20, "boundary_pool_covered": 20}})
        phase = "complete"
        return finish(execution_complete=True, material_count=120, row_count=840,
            primary_method=PRIMARY, primary_comparator="standard_boundary_ner",
            observed_new_generations=len(calls), observed_new_encoders=0, historical_generations=81, historical_encoders=168,
            runtime_token_usage=usage, candidate_ceiling=ceilings, recomputed_summary=summary)
    except ERRORS:
        check("artifact_structure_complete_at_" + phase, False)
        return finish(execution_complete=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path, help="New receipt; defaults to RUN/independent_decision_verification_v1.json. Never overwrites.")
    args = parser.parse_args()
    result = verify(args.run, archive=args.archive)
    result["verifier_sha256"] = sha(Path(__file__).read_bytes())
    destination = args.output or args.run / "independent_decision_verification_v1.json"
    try:
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
    except OSError:
        print(json.dumps({"status": "receipt_not_written", "error": "output_exists_or_unwritable"}))
        raise SystemExit(2)
    failed = [item["check"] for item in result["checks"] if not item["passed"]]
    print(json.dumps({"status": result["status"], "report_file": str(destination.resolve()), "check_count": len(result["checks"]),
        "failed_check_count": len(failed), "failed_checks_first_12": failed[:12], "verification_model_calls": 0,
        "privacy_or_recall_acceptance": False}, ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "passed" else 1)
