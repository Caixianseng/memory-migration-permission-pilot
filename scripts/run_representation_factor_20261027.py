"""Freeze / execute a bounded local representation diagnostic, never native clients.

--plan performs no network or model calls. --execute requires the exact plan
hash. All 144 bodies are constructed before inference; no retries or resume.
The four old development stories remain exposed mechanism-development data.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.focused_semantic_reader import canonical, digest, require, candidates
from memory_migration_study.local_detector import LocalSensitivityAgent, MODEL, DIGEST, VERSION
from memory_migration_study.private_request_boundary import LoopbackJSONSender
from memory_migration_study.representation_factor_probe import (CONDITIONS, REPRESENTATIONS, PROMPTS,
    SYSTEMS, OPTIONS, SCHEMA, ModelBudget, call_order, model_body, validate_entities, call_model, score)

VERSION_ID = "representation_factor_exposed_development_20261027_v1"
MATERIAL = ROOT / "examples/focused_semantic_20261027/development.json"
REFERENCE = ROOT / "examples/focused_semantic_20261027/scoring_reference.json"
ENTITIES = ROOT / "examples/representation_factor_20261027/entities.json"
PREREGISTRATION = ROOT / "docs/隐私表示因素诊断_预注册方案_2026-10-27.md"
CODE_INPUTS = (
    "memory_migration_study/__init__.py",
    "memory_migration_study/authority_freshness.py",
    "memory_migration_study/current_authority.py",
    "memory_migration_study/focused_semantic_reader.py",
    "memory_migration_study/focused_semantic_scoring.py",
    "memory_migration_study/local_detector.py",
    "memory_migration_study/memory_labels.py",
    "memory_migration_study/principal_scope.py",
    "memory_migration_study/privacy.py",
    "memory_migration_study/privacy_egress.py",
    "memory_migration_study/private_request_boundary.py",
    "memory_migration_study/representation_factor_probe.py",
    "scripts/run_representation_factor_20261027.py",
    "tests/test_representation_factor_probe.py",
)


def file_sha(path):
    return digest(Path(path).read_bytes())


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def parse(path):
    return json.loads(Path(path).read_bytes())


def validate_material(material):
    require(set(material) == {"version", "stories"} and len(material["stories"]) == 4, "four_exposed_stories_required")
    require({s["id"] for s in material["stories"]} == {
        "dev_zh_roles", "dev_en_time", "dev_zh_negation", "dev_en_paraphrase"}, "exposed_story_inventory")
    for story in material["stories"]:
        require(set(story) == {"id", "language", "source_backend", "target_backend", "objects", "facts", "questions", "sensitive_values"}, "material_fields")
        require(len(story["questions"]) == 3 and {q["id"] for q in story["questions"]} == {"Q1", "Q2", "Q3"}
                and all(set(q) == {"id", "text"} for q in story["questions"]), "natural_questions_without_answers")
        require(len(story["sensitive_values"]) == len(set(story["sensitive_values"])) == 4, "four_entity_registry")
        candidates(story, {o["key"]: o["text"] for o in story["objects"]})


def build_plan():
    material, entities = parse(MATERIAL), parse(ENTITIES)
    validate_material(material); validate_entities(material, entities)
    requests = []
    question_index = 0
    for story in material["stories"]:
        for question in story["questions"]:
            nonce = secrets.token_hex(12).upper()
            for condition in call_order(question_index):
                representation, prompt = condition.split(":")
                body = model_body(story, question, entities["stories"][story["id"]], representation, prompt, nonce)
                require(len(canonical(body)) <= 4032, "conservative_input_budget_exceeded")
                requests.append({"position": len(requests), "story_id": story["id"], "question_id": question["id"],
                    "condition": condition, "representation": representation, "prompt": prompt, "nonce": nonce,
                    "candidate_order": ["F1", "F2", "F3", "F4"], "request_sha256": digest(body),
                    "request_bytes": len(canonical(body)), "body": body})
            question_index += 1
    require(len(requests) == 144, "full_matrix_required")
    positions = {c: Counter(r["position"] % 12 for r in requests if r["condition"] == c) for c in CONDITIONS}
    require(all(count == Counter(range(12)) for count in positions.values()), "unbalanced_call_order")
    # The explicit local import dependency closure is independent of unrelated
    # modules that unittest discovery or another caller loaded into sys.modules.
    files = [ROOT / relative for relative in CODE_INPUTS]
    return {"version": VERSION_ID, "scope": "four previously exposed development stories; mechanism diagnostic only",
        "provenance": "Local copies of prior development text; prior source/target exact-input equality is historical evidence, not a new native migration run.",
        "model": MODEL, "digest": DIGEST, "runtime": VERSION, "endpoint": "http://127.0.0.1:11435",
        "options": OPTIONS, "schema_sha256": digest(SCHEMA), "system_sha256": {k: digest(v.encode()) for k,v in SYSTEMS.items()},
        "material_path": str(MATERIAL), "material_sha256": file_sha(MATERIAL),
        "entities_path": str(ENTITIES), "entities_sha256": file_sha(ENTITIES),
        "reference_path": str(REFERENCE), "reference_sha256": file_sha(REFERENCE),
        "preregistration_path": str(PREREGISTRATION), "preregistration_sha256": file_sha(PREREGISTRATION),
        "code_sha256": {str(p.relative_to(ROOT)).replace("\\", "/"): file_sha(p) for p in files},
        "representations": list(REPRESENTATIONS), "prompts": list(PROMPTS),
        "max_model_calls": 144, "retries": 0, "concurrency": 1, "max_elapsed_seconds": 3600,
        "paid_calls": 0, "native_client_calls": 0, "native_backend_calls": 0, "building_or_labeling_model_calls": 0,
        "host_python": str(Path(sys.executable).resolve()),
        "controls": {"entity_ids": "source registry order, identical across representations",
            "nonce": "same 24 hex digits per question; short has first four, long appends remaining 20",
            "type_labels": "manual oracle PROJECT_/PERSON__/ORG_____ versus coarse CUSTOMER; all eight ASCII characters",
            "natural": "manual bijection, no explicit type label; matched character/UTF8/word lengths, compound lexical control",
            "prompts": "original SYSTEM unchanged; generic relation/time/negation evidence requirement appended in evidence arm",
            "order": "F1-F4 in every body; 12-condition Latin rotation across 12 questions",
            "scoring": "reference bytes hash/copied opaque; first content parse after prediction closure",
            "claims": "representation format effects, no pure length causation, no algorithm novelty or independent acceptance"},
        "requests": requests}


def verify_inputs(plan):
    require(plan["version"] == VERSION_ID and plan["max_model_calls"] == 144
            and len(plan["requests"]) == 144, "frozen_plan_identity")
    require(plan["model"] == MODEL and plan["digest"] == DIGEST and plan["runtime"] == VERSION
            and plan["endpoint"] == "http://127.0.0.1:11435", "pinned_model_contract")
    for path_key, hash_key in (("material_path", "material_sha256"), ("entities_path", "entities_sha256"),
                               ("reference_path", "reference_sha256"), ("preregistration_path", "preregistration_sha256")):
        require(file_sha(plan[path_key]) == plan[hash_key], "frozen_material_changed")
    for relative, expected in plan["code_sha256"].items():
        require(file_sha(ROOT / relative) == expected, "frozen_code_changed")


def execute(plan, output):
    verify_inputs(plan)
    output = Path(output).resolve()
    require(output.parent == (ROOT / "results").resolve(), "result_scope")
    output.mkdir(exist_ok=False)
    (output / "wire").mkdir()
    (output / "responses").mkdir()
    save(output / "plan.json", plan)
    for relative in plan["code_sha256"]:
        target = output / "frozen_source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    for name, source in (("development.json", MATERIAL), ("entities.json", ENTITIES),
                         ("opaque_scoring_reference.json", REFERENCE), ("preregistration.md", PREREGISTRATION)):
        (output / name).write_bytes(source.read_bytes())
    material = parse(output / "development.json")
    stories = {s["id"]: s for s in material["stories"]}
    # Save exactly the planned request bytes before any network call.
    for request in plan["requests"]:
        raw = canonical(request["body"])
        require(digest(raw) == request["request_sha256"], "planned_wire_mismatch")
        (output / "wire" / (f'{request["position"]:03d}.planned.json')).write_bytes(raw)
    predictions = []
    budget = ModelBudget(144)
    start = time.monotonic()
    error = None
    try:
        health = LocalSensitivityAgent().health()
        save(output / "health_before.json", health)
        sender = LoopbackJSONSender(timeout=120)
        for request in plan["requests"]:
            verify_inputs(plan)
            require(time.monotonic() - start <= plan["max_elapsed_seconds"], "elapsed_budget_exhausted")
            position = request["position"]
            actual_wire = output / "wire" / f"{position:03d}.actual.json"
            response_path = output / "responses" / f"{position:03d}.json"
            def capture(raw):
                require(raw == (output / "wire" / f"{position:03d}.planned.json").read_bytes(), "actual_wire_changed")
                with actual_wire.open("xb") as stream:
                    stream.write(raw)
                response = sender(raw)
                save(response_path, response)
                return response
            row = {k: v for k, v in request.items() if k not in {"body", "request_bytes", "request_sha256"}}
            registered = [] if request["representation"] == "raw" else stories[request["story_id"]]["sensitive_values"]
            prediction = call_model(row, request["body"], registered, budget, sender=capture)
            if actual_wire.exists():
                prediction["actual_wire_sha256"] = file_sha(actual_wire)
                require(prediction["actual_wire_sha256"] == request["request_sha256"], "actual_wire_receipt_mismatch")
            predictions.append(prediction)
            save(output / f"prediction_{position:03d}.json", prediction)
            print(json.dumps({"position": position, "condition": request["condition"], "status": prediction["status"],
                              "attempted": budget.attempted}, separators=(",", ":")), flush=True)
            require(prediction["status"] == "ok", "prediction_engineering_failure:" + str(prediction["failure_class"]))
        save(output / "health_after.json", LocalSensitivityAgent().health())
    except Exception as exc:
        error = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    # Close even partial runs. Unattempted opportunities remain in all denominators.
    for request in plan["requests"][len(predictions):]:
        predictions.append({k: v for k,v in request.items() if k != "body"} | {
            "status": "not_run", "answer_id": None, "model_calls": 0, "failure_class": error or "not_run"})
    save(output / "predictions.json", predictions)
    closed = {"version": VERSION_ID, "predictions_sha256": file_sha(output / "predictions.json"),
        "plan_sha256": digest(plan), "attempted": budget.attempted, "cap": 144, "closed": True,
        "reference_parsed": False, "error": error, "elapsed_seconds": time.monotonic() - start}
    save(output / "prediction_phase_closed.json", closed)
    require(file_sha(output / "opaque_scoring_reference.json") == plan["reference_sha256"], "opaque_reference_changed")
    # First scoring-reference content parse in this process.
    metrics = score(predictions, parse(output / "opaque_scoring_reference.json"))
    save(output / "metrics.json", metrics)
    drift = None
    try:
        verify_inputs(plan)
    except Exception as exc:
        drift = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    evidence = {str(path.relative_to(output)).replace("\\", "/"): file_sha(path)
                for path in sorted(output.rglob("*")) if path.is_file()}
    summary = {"version": VERSION_ID, "status": "completed" if error is None and drift is None else "failed_closed",
        "scope": plan["scope"], "plan_sha256": digest(plan), "model": MODEL, "digest": DIGEST,
        "model_calls": budget.attempted, "max_model_calls": 144, "native_client_calls": 0,
        "native_backend_calls": 0, "paid_calls": 0, "retries": 0, "error": error, "postrun_drift": drift,
        "closed_before_reference_parse": True, "conditions": metrics["conditions"],
        "evidence_sha256": evidence, "elapsed_seconds": time.monotonic() - start}
    save(output / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", type=Path)
    mode.add_argument("--execute", type=Path)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.plan:
        plan = build_plan()
        save(args.plan, plan)
        print(json.dumps({"plan": str(args.plan), "plan_sha256": digest(plan), "planned": 144,
                          "model_calls": 0, "native_client_calls": 0}, indent=2))
    else:
        require(args.output is not None and args.expected_plan_sha256 is not None, "execution_hash_and_output_required")
        plan = parse(args.execute)
        require(digest(plan) == args.expected_plan_sha256, "plan_hash_mismatch")
        summary = execute(plan, args.output)
        print(json.dumps({k: summary[k] for k in ("status", "model_calls", "error", "postrun_drift")}, indent=2))
        if summary["status"] != "completed":
            raise SystemExit(1)


if __name__ == "__main__":
    main()
