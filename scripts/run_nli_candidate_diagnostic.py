"""Frozen exposed-corpus NLI diagnostic with ML-only, gold-denied children.

Plan tokenization loads no model weights. Explicit execution runs one fixed
classifier phase. Scoring is host-only and occurs after prediction closure.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SELF = "scripts/run_nli_candidate_diagnostic.py"
QUALIFIER = "scripts/qualify_mdeberta_nli_runtime_v3.py"
QUALIFIER_SHA = "84e932a72b9e098289aa8a9e3e02abc1b4b023f29bf24c4a769701d6f9dea6e8"
CONTRACT = "docs/proposals/nli_candidate_contract_v1_20261026.json"
VERSION = "nli_candidate_exposed_three_arm_v1"
ARMS = ("standard_boundary", "nli_existing", "nli_full_pool")
SEED = 2026102608
AGENT_CONFIG = {"allow_forward": True, "max_candidates": 16}


def require(value, code):
    if not value:
        raise ValueError(code)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(encoded(value))


def scope(path):
    p = Path(path).absolute()
    require(p == p.resolve() and p.is_relative_to(ROOT / "results") and p != ROOT / "results", "result_scope_invalid")
    return p


def qualifier():
    require(sha(ROOT / QUALIFIER) == QUALIFIER_SHA, "qualified_runtime_wrapper_changed")
    spec = importlib.util.spec_from_file_location("qualified_nli_for_diagnostic", ROOT / QUALIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_qualifier()


def runtime_binding(q):
    run = ROOT / "results/mdeberta_nli_runtime_20261026_v3"
    original = q.loads((run / "plan.json").read_bytes())
    require(q.encoded(q.build_plan(run)) == q.encoded(original), "qualified_runtime_binding_changed")
    report = q.loads((run / "report.json").read_bytes())
    require(report.get("runtime_qualified") is True and report.get("method_acceptance") is False,
            "qualified_runtime_reference_invalid")
    return {"plan_sha256": sha(run / "plan.json"), "report_sha256": sha(run / "report.json"),
            "runtime_plan": original, "scope": "Runtime qualification, never privacy acceptance."}


def sources():
    return sorted({SELF, QUALIFIER, "scripts/qualify_mdeberta_nli_runtime.py",
                   "scripts/qualify_mdeberta_nli_runtime_v2.py", "scripts/native_exact_fact_common.py",
                   "scripts/run_candidate_decision_diagnostic.py", "scripts/run_context_candidate_diagnostic.py",
                   "scripts/run_semantic_detection_benchmark.py", CONTRACT,
                   *(p.relative_to(ROOT).as_posix() for p in (ROOT / "memory_migration_study").glob("*.py"))})


def source_manifest():
    return {name: sha(ROOT / name) for name in sources()}


def prepare_inputs(archive, output):
    sys.path.insert(0, str(ROOT))
    from memory_migration_study.boundary_detector import refine_detection
    from memory_migration_study.candidate_proposals import propose_candidates
    from scripts.run_candidate_decision_diagnostic import prepare_reference
    corpus, recorded, _, reference = prepare_reference(archive, output)
    random.Random(SEED).shuffle(corpus)
    material, inputs = [], []
    for case in corpus:
        cid = case["case_id"]
        baseline = refine_detection(case["payload"], case["policy"], recorded[cid]["baseline"])
        pool = propose_candidates(case["payload"], case["policy"], baseline["findings"],
                                  max_candidates=16, max_quote_chars=256)
        material.append({**case, "baseline": baseline, "pool": pool})
        inputs.append({"case_id": cid, "payload": case["payload"], "policy": case["policy"], "pool": pool})
    require(len(inputs) == 120 and len({r["case_id"] for r in inputs}) == 120, "source_material_count_invalid")
    unique = {encoded(r["policy"]): r["policy"] for r in inputs}
    return material, inputs, list(unique.values()), reference


def validate_inputs(inputs):
    require(isinstance(inputs, list) and len(inputs) == 120 and len({r["case_id"] for r in inputs}) == 120,
            "runtime_input_count_invalid")
    require(all(set(r) == {"case_id", "payload", "policy", "pool"} for r in inputs), "runtime_input_extra_fields")


def launch_phase(output, *, phase, inputs, policies, contract, implementation, runtime_reference, cap):
    directory = scope(output / phase)
    directory.mkdir(exist_ok=False)
    q = qualifier()
    job = {"schema": VERSION + "_worker", "phase": phase, "output": output.relative_to(ROOT).as_posix(),
           "inputs": inputs, "approved_policies": policies, "contract": contract, "agent_config": AGENT_CONFIG,
           "implementation_sha256": implementation, "runtime_reference": runtime_reference,
           "max_forwards": cap}
    save(directory / "worker_job.json", job)
    save(directory / "plan.json", {"job_sha256": sha(directory / "worker_job.json"), "phase": phase, "cap": cap})
    command = [str(ROOT / q.PYTHON), "-I", "-B", str(ROOT / SELF), "--worker-job", str(directory / "worker_job.json")]
    process = subprocess.Popen(command, cwd=ROOT, env=q.child_environment(directory / "child_home"),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=1800)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    save(directory / "process_receipt.json", {"returncode": process.returncode,
         "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
         "stdout_bytes": len(stdout), "stderr_bytes": len(stderr), "raw_console_saved": False})
    predictions = directory / "worker_predictions.json"
    require(predictions.is_file(), "worker_predictions_missing")
    result = q.loads(predictions.read_bytes())
    require(result.get("status") == "completed" and process.returncode == 0
            and result.get("guard", {}).get("blocked_attempts") == 0, "worker_runtime_or_guard_failed")
    require(len(result["records"]) == 120, "worker_material_count_changed")
    return result


def plan_only(archive, output):
    output = scope(output)
    require(not output.exists(), "new_output_required")
    output.mkdir(parents=True)
    q = qualifier()
    reference = runtime_binding(q)
    contract = q.loads((ROOT / CONTRACT).read_bytes())
    material, inputs, policies, corpus_reference = prepare_inputs(archive, output)
    validate_inputs(inputs)
    frozen = source_manifest()
    for name in frozen:
        target = output / "frozen_source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write((ROOT / name).read_bytes())
    save(output / "materials_input.json", material)
    save(output / "runtime_inputs.json", inputs)
    tokenization = launch_phase(output, phase="tokenization", inputs=inputs, policies=policies, contract=contract,
                               implementation=frozen, runtime_reference=reference, cap=0)
    require(all(v == 0 for v in tokenization["runtime_counts"].values()), "tokenization_used_model")
    maximum = sum(r["preflight"]["request_count"] for r in tokenization["records"] if r["preflight"]["executable"])
    require(0 <= maximum <= 120 * 16 * 7, "forward_preflight_cap_invalid")
    plan = {"schema": VERSION, "output": output.relative_to(ROOT).as_posix(), "seed": SEED,
            "arms": list(ARMS), "primary": "nli_full_pool", "materials": 120, "rows": 360,
            "approved_policies": policies, "contract": contract, "agent_config": AGENT_CONFIG,
            "implementation_sha256": frozen, "runtime_reference": reference, "corpus_reference": corpus_reference,
            "input_sha256": {n: sha(output / n) for n in ("materials_input.json", "runtime_inputs.json")},
            "tokenization_sha256": sha(output / "tokenization/worker_predictions.json"),
            "max_classifier_forwards": maximum, "max_encoder_forwards": maximum,
            "new_generation_cap": 0, "cloud_cap": 0, "truncation": False,
            "child_pycache_prefix": "fresh child_home/pycache; bytecode writes disabled",
            "scope": "80 exposed development + 40 exposed regression; not fresh independent acceptance or innovation.",
            "default_changed": False, "no_automatic_retry": True}
    require(source_manifest() == frozen, "source_changed_during_plan")
    save(output / "plan.json", plan)
    return plan


def approved(path):
    path = scope(path)
    plan = json.loads(path.read_bytes())
    output = ROOT / plan["output"]
    require(path == output / "plan.json" and plan["schema"] == VERSION and plan["arms"] == list(ARMS)
            and plan["agent_config"] == AGENT_CONFIG and plan["materials"] == 120, "plan_contract_changed")
    require(plan["implementation_sha256"] == source_manifest(), "implementation_changed")
    for name, digest in plan["implementation_sha256"].items():
        require(sha(output / "frozen_source" / name) == digest, "source_snapshot_changed")
    for name, digest in plan["input_sha256"].items():
        require(sha(output / name) == digest, "input_changed")
    require(sha(output / "tokenization/worker_predictions.json") == plan["tokenization_sha256"], "tokenization_changed")
    require(runtime_binding(qualifier()) == plan["runtime_reference"], "qualified_runtime_changed")
    require(json.loads((ROOT / CONTRACT).read_bytes()) == plan["contract"], "semantic_contract_changed")
    return plan


def score_closed(output, plan, predictions):
    closed = json.loads((output / "model_phase_closed.json").read_bytes())
    require(closed["closed"] is True and sha(output / "inference/worker_predictions.json") == closed["prediction_sha256"],
            "predictions_not_closed")
    sys.path.insert(0, str(ROOT))
    from memory_migration_study.nli_candidate import compose_nli_detection
    from scripts.run_semantic_detection_benchmark import score_detection, sum_counts
    materials = json.loads((output / "materials_input.json").read_bytes())
    gold = {}
    for split in ("development", "heldout"):
        path = output / split / "evaluation.json"
        require(sha(path) == plan["corpus_reference"]["corpus_sha256"][split + "/evaluation.json"], "gold_bytes_changed")
        gold.update(json.loads(path.read_bytes()))
    require([r["case_id"] for r in materials] == [r["case_id"] for r in predictions["records"]], "prediction_schedule_changed")
    rows = []
    for case, result in zip(materials, predictions["records"]):
        for arm in ARMS:
            detection = case["baseline"] if arm == ARMS[0] else compose_nli_detection(
                case["payload"], case["policy"], case["baseline"], case["pool"], result["stage"],
                approved_policies=plan["approved_policies"], contract=plan["contract"],
                preflight=result["preflight"], include_new=arm == ARMS[2])
            rows.append({"case_id": case["case_id"], "split": case["split"], "language": case["language"],
                         "arm": arm, "detection": detection, "score": score_detection(detection, gold[case["case_id"]], case["payload"])})
    summary = {}
    for split in ("development", "heldout"):
        summary[split] = {}
        for arm in ARMS:
            selected = [r for r in rows if r["split"] == split and r["arm"] == arm]
            summary[split][arm] = {"materials": len(selected), "accepted": sum_counts([r["score"]["accepted"] for r in selected]),
                                  "ok": sum(r["detection"]["status"] == "ok" for r in selected),
                                  "complete_exact": sum(r["score"]["accepted_complete_exact"] for r in selected)}
    save(output / "rows.json", rows)
    return summary


def execute(path):
    plan = approved(path)
    output = ROOT / plan["output"]
    save(output / "execution_started.json", {"plan_sha256": sha(path), "no_automatic_retry": True})
    inputs = json.loads((output / "runtime_inputs.json").read_bytes())
    predictions = launch_phase(output, phase="inference", inputs=inputs, policies=plan["approved_policies"],
                               contract=plan["contract"], implementation=plan["implementation_sha256"],
                               runtime_reference=plan["runtime_reference"], cap=plan["max_classifier_forwards"])
    token = json.loads((output / "tokenization/worker_predictions.json").read_bytes())
    for before, after in zip(token["records"], predictions["records"]):
        require(before["case_id"] == after["case_id"] and before["preflight"]["requests"] == after["preflight"]["requests"],
                "tokenization_request_changed")
    save(output / "model_phase_closed.json", {"closed": True, "prediction_sha256": sha(output / "inference/worker_predictions.json"),
                                              "plan_sha256": sha(path), "runtime_counts": predictions["runtime_counts"]})
    summary = score_closed(output, plan, predictions)
    report = {"schema": VERSION + "_report", "summary": summary, "runtime_counts": predictions["runtime_counts"],
              "guard": predictions["guard"], "materials": 120, "rows": 360,
              "independent_acceptance": False, "default_changed": False, "new_generations": 0, "cloud_calls": 0,
              "new_api_cost_cny": 0, "implementation_unchanged": source_manifest() == plan["implementation_sha256"]}
    save(output / "report.json", report)
    return report


def worker(path):
    path = scope(path)
    job = json.loads(path.read_bytes())
    output = scope(ROOT / job["output"])
    directory = scope(output / job["phase"])
    require(path == directory / "worker_job.json" and job["schema"] == VERSION + "_worker"
            and job["phase"] in ("tokenization", "inference"), "worker_job_invalid")
    validate_inputs(job["inputs"])
    require(job["implementation_sha256"] == source_manifest(), "worker_source_changed")
    q = qualifier()
    require(runtime_binding(q) == job["runtime_reference"], "worker_runtime_changed")
    home = directory / "child_home"
    home.mkdir(exist_ok=False)
    env = q.child_environment(home)
    os.environ.clear()
    os.environ.update(env)
    sys.dont_write_bytecode = True
    sys.pycache_prefix = str(home / "pycache")
    common = q.load_common()
    guard = q.WorkerGuard(common, path, directory)
    guard.read_files.update((ROOT / name).resolve() for name in job["implementation_sha256"])
    sys.addaudithook(guard)
    result = {"schema": VERSION + "_worker_predictions", "status": "error", "records": [],
              "phase": job["phase"], "job_sha256": sha(path), "generation_calls": 0, "cloud_calls": 0}
    runtime = None
    discard = io.StringIO()
    try:
        with redirect_stdout(discard), redirect_stderr(discard):
            sys.path.insert(0, str(ROOT))
            from memory_migration_study.nli_candidate import LocalNLICandidate, PinnedNLIRuntime
            runtime = PinnedNLIRuntime({"max_forwards": job["max_forwards"]})
            agent = LocalNLICandidate(job["agent_config"], approved_policies=job["approved_policies"],
                                      contract=job["contract"], runtime=runtime)
            for index, item in enumerate(job["inputs"]):
                preflight = agent.preflight(item["payload"], item["policy"], item["pool"])
                record = {"case_id": item["case_id"], "preflight": preflight}
                if job["phase"] == "inference":
                    record["stage"] = agent.classify(item["payload"], item["policy"], item["pool"], preflight=preflight)
                result["records"].append(record)
                if (index + 1) % 10 == 0:
                    save(home / ("checkpoint_" + str(index + 1) + ".json"),
                         {"completed": index + 1, "total": 120, "runtime_counts": runtime.snapshot_counts()})
            result["runtime_counts"] = runtime.snapshot_counts()
            result["loading_evidence"] = runtime.loading_evidence
            result["status"] = "completed"
    except Exception as error:
        result.update(error_type=type(error).__name__, error_code="nli_candidate_worker_failed")
        frames = []
        tb = error.__traceback__
        while tb is not None:
            frames.append({"file": Path(tb.tb_frame.f_code.co_filename).name,
                           "function": tb.tb_frame.f_code.co_name, "line": tb.tb_lineno})
            tb = tb.tb_next
        result["error_frames"] = frames[-8:]
        result["runtime_counts"] = runtime.snapshot_counts() if runtime else None
    result["guard"] = guard.accounting()
    result["discarded_console_bytes"] = len(discard.getvalue().encode())
    save(directory / "worker_predictions.json", result)
    return 0 if result["status"] == "completed" and result["guard"]["blocked_attempts"] == 0 else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan-only", action="store_true")
    modes.add_argument("--execute", action="store_true")
    modes.add_argument("--worker-job", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--archive", type=Path, default=ROOT / "benchmarks/artifacts/context_candidate_detection_20261026_v2.zip")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    if args.worker_job:
        return worker(args.worker_job)
    if args.plan_only:
        require(args.output is not None, "output_required")
        plan = plan_only(args.archive, args.output)
        print(json.dumps({"status": "plan_only_zero_forward", "materials": 120,
                          "maximum_forwards": plan["max_classifier_forwards"]}))
    else:
        require(args.approved_plan is not None, "approved_plan_required")
        report = execute(args.approved_plan)
        print(json.dumps({"runtime_counts": report["runtime_counts"], "summary": report["summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
