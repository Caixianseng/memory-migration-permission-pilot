"""Pinned GLiClass vs recorded boundary/flat on exposed synthetic materials.

Default is a zero-forward plan and complete tokenizer qualification. Only
--execute enables new encoder forwards; no Qwen or remote API is called.
Gold stays opaque bytes until model_phase_closed.json has been written.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import shutil
import socket
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.boundary_detector import refine_detection
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.gliclass_candidate import LocalGLiClassCandidate, PinnedGLiClassRuntime, compose_gliclass_detection
from scripts.run_candidate_decision_diagnostic import prepare_reference
from scripts.run_context_candidate_diagnostic import save, sha, utc
from scripts.run_semantic_detection_benchmark import score_detection, sum_counts

VERSION = "gliclass_candidate_exposed_regression_v1"
ARMS = ("standard_boundary_ner", "recorded_flat_primary", "gliclass_candidate")
PRIMARY = "gliclass_candidate"
FLAT_PRIMARY = "primary_boundary_full_no_prior"
SEED = 2026102605


@contextmanager
def no_network(audit):
    original = socket.socket.connect
    def denied(*args, **kwargs):
        audit["blocked_connection_attempts"] += 1
        raise RuntimeError("gliclass_diagnostic_network_forbidden")
    socket.socket.connect = denied
    try:
        yield
    finally:
        socket.socket.connect = original


def _implementations():
    names = ("gliclass_candidate", "candidate_decision", "candidate_proposals", "candidate_adjudicator", "privacy",
             "local_detector", "boundary_detector", "boundary_reconciliation", "structured_candidates", "amount_candidates")
    return [Path(__file__).resolve(), *(ROOT / "memory_migration_study" / (name + ".py") for name in names),
            *(ROOT / "scripts" / (name + ".py") for name in ("run_candidate_decision_diagnostic", "run_context_candidate_diagnostic", "run_semantic_detection_benchmark"))]


def _flat_reference(path, archive_sha):
    path = Path(path).resolve(strict=True)
    if not path.is_relative_to(ROOT / "results"):
        raise ValueError("flat_reference_outside_results")
    plan = json.loads((path / "plan.json").read_text(encoding="utf-8"))
    closure = json.loads((path / "model_phase_closed.json").read_text(encoding="utf-8"))
    if plan["reference"]["archive_sha256"] != archive_sha or closure.get("model_phase_closed") is not True:
        raise ValueError("flat_reference_archive_or_closure_mismatch")
    names = ("plan.json", "materials.json", "unscored_rows.json")
    for name in names:
        if sha(path / name) != closure["artifact_sha256"][name]:
            raise ValueError("flat_reference_bound_bytes_changed")
    materials = json.loads((path / "materials.json").read_text(encoding="utf-8"))
    rows = json.loads((path / "unscored_rows.json").read_text(encoding="utf-8"))
    if any("score" in row for row in rows):
        raise ValueError("scored_flat_rows_forbidden_before_closure")
    selected = [row for row in rows if row["arm"] == FLAT_PRIMARY]
    if len(materials) != 120 or len(selected) != 120 or len({row["case_id"] for row in selected}) != 120:
        raise ValueError("flat_reference_material_identity_invalid")
    return {row["case_id"]: row for row in materials}, {row["case_id"]: row for row in selected}, {
        "result_dir": str(path.relative_to(ROOT)), "primary_arm": FLAT_PRIMARY,
        "sha256": {name: sha(path / name) for name in (*names, "model_phase_closed.json")},
        "scope": "recorded same-source failed flat reference, not an achieved P90/R95 method"}


def run(archive, flat_reference, output, *, execute=False, runtime=None):
    archive, output = Path(archive).resolve(), Path(output).resolve()
    if output.exists() or not output.is_relative_to((ROOT / "results").resolve()):
        raise ValueError("new_results_directory_required")
    output.mkdir(parents=True)
    corpus, source_materials, _, reference = prepare_reference(archive, output)
    flat_materials, flat_rows, flat_binding = _flat_reference(flat_reference, reference["archive_sha256"])
    if set(source_materials) != set(flat_materials) or set(flat_rows) != {case["case_id"] for case in corpus}:
        raise ValueError("source_flat_identity_mismatch")
    policies = [case["policy"] for case in corpus]
    runtime = runtime or PinnedGLiClassRuntime()
    agent = LocalGLiClassCandidate({"allow_forward": bool(execute)}, approved_policies=policies, runtime=runtime)
    network = {"blocked_connection_attempts": 0, "remote_model_calls": 0, "qwen_calls": 0}
    with no_network(network):
        rng = random.Random(SEED);rng.shuffle(corpus)
        prepared = []
        for case in corpus:
            cid = case["case_id"]
            boundary = refine_detection(case["payload"], case["policy"], source_materials[cid]["baseline"])
            pool = propose_candidates(case["payload"], case["policy"], boundary["findings"], max_candidates=16, max_quote_chars=256)
            if boundary != flat_materials[cid]["boundary_baseline"] or pool != flat_materials[cid]["boundary_pool"]:
                raise ValueError("flat_boundary_reconstruction_mismatch")
            qualification = agent.preflight(case["payload"], case["policy"], pool)
            prepared.append({"case_id": cid, "split": case["split"], "boundary_baseline": boundary,
                             "boundary_pool": pool, "preflight": qualification})
        frozen = {str(path.relative_to(ROOT)): sha(path) for path in _implementations()}
        for relative, expected in frozen.items():
            target = output / "frozen_source" / relative
            target.parent.mkdir(parents=True, exist_ok=True);shutil.copyfile(ROOT / relative, target)
            if sha(target) != expected:
                raise ValueError("implementation_snapshot_changed")
        save(output / "qualification.json", prepared)
        save(output / "identities.json", {"agent": agent.cache_identity(), "runtime": runtime.health()})
        maximum = sum(len(item["preflight"]["requests"]) for item in prepared if item["preflight"]["executable"])
        plan = {"version": VERSION, "created_at": utc(), "seed": SEED, "schedule": [case["case_id"] for case in corpus],
            "arms": list(ARMS), "primary": PRIMARY, "material_count": 120, "row_count": 360,
            "reference": reference, "reference_flat": flat_binding, "implementation_sha256": frozen,
            "agent_config": deepcopy(agent.config), "approved_policies": policies, "max_encoder_forwards": maximum,
            "max_root_forwards": maximum, "cpu_threads": 4, "batch_size": 1, "dtype": "float32", "max_tokens": 512,
            "qualification_sha256": sha(output / "qualification.json"), "identities_sha256": sha(output / "identities.json"),
            "scope": "80 exposed development + 40 exposed regression; diagnostic strong baseline, not independent acceptance",
            "timing_scope": "first candidate may include lazy weight loading; not a controlled speed comparison with recorded flat",
            "new_generations": 0, "cloud_calls": 0, "new_api_cost_cny": 0, "default_changed": False,
            "execution_requested": bool(execute)}
        save(output / "plan.json", plan)
        if not execute:
            if any(runtime.snapshot_counts().values()) or network["blocked_connection_attempts"]:
                raise ValueError("preflight_unexpected_forward_or_network")
            save(output / "network_audit.json", network)
            return {"status": "plan_only", "materials": 120, "preflight_executable": sum(item["preflight"]["executable"] for item in prepared),
                "max_encoder_forwards": maximum, "max_input_tokens": max(item["preflight"].get("max_input_tokens", 0) for item in prepared), "model_forwards": 0}
        rows, materials, all_calls = [], [], []
        for index, (case, item) in enumerate(zip(corpus, prepared)):
            if any(sha(ROOT / rel) != expected for rel, expected in frozen.items()):
                raise ValueError("implementation_changed_during_model_phase")
            cid = case["case_id"]
            stage = agent.classify(case["payload"], case["policy"], item["boundary_pool"])
            detection = compose_gliclass_detection(case["payload"], case["policy"], item["boundary_baseline"], item["boundary_pool"],
                                                  stage, approved_policies=policies, runtime=runtime)
            materials.append({**item, "stage": stage})
            for call in stage["raw_results"]:
                all_calls.append({"index": len(all_calls), "case_id": cid, "split": case["split"], **deepcopy(call)})
            for arm, current in ((ARMS[0], item["boundary_baseline"]), (ARMS[1], flat_rows[cid]["detection"]), (ARMS[2], detection)):
                rows.append({"case_id": cid, "split": case["split"], "language": case["language"], "arm": arm, "detection": current})
            if any(count > maximum for count in runtime.snapshot_counts().values()) or network["blocked_connection_attempts"]:
                raise ValueError("forward_or_network_budget_exceeded")
            save(output / "materials.json", materials);save(output / "encoder_calls.json", all_calls);save(output / "unscored_rows.json", rows)
            if (index + 1) % 10 == 0:
                print(json.dumps({"complete": index + 1, "materials": 120, "forwards": runtime.snapshot_counts()}), flush=True)
        bound = ("plan.json", "qualification.json", "identities.json", "materials.json", "encoder_calls.json", "unscored_rows.json", "reference_materials.json")
        save(output / "model_phase_closed.json", {"model_phase_closed": True, "closed_at": utc(), "forward_counts": runtime.snapshot_counts(),
            "artifact_sha256": {name: sha(output / name) for name in bound}})
        save(output / "score_phase_started.json", {"started_at": utc(), "closure_sha256": sha(output / "model_phase_closed.json")})
        gold = {}
        for split in ("development", "heldout"):
            for name in ("runtime.json", "evaluation.json"):
                if sha(output / split / name) != reference["corpus_sha256"][split + "/" + name]:
                    raise ValueError("source_corpus_changed")
            gold.update(json.loads((output / split / "evaluation.json").read_text(encoding="utf-8")))
        by_id = {case["case_id"]: case for case in corpus}
        for row in rows:
            row["score"] = score_detection(row["detection"], gold[row["case_id"]], by_id[row["case_id"]]["payload"])
        summary = {}
        for split in ("development", "heldout"):
            summary[split] = {}
            for arm in ARMS:
                selected = [row for row in rows if row["split"] == split and row["arm"] == arm]
                summary[split][arm] = {"materials": len(selected), "accepted": sum_counts([row["score"]["accepted"] for row in selected]),
                    "ok": sum(row["detection"]["status"] == "ok" for row in selected),
                    "errors": dict(Counter(error for row in selected for error in row["detection"]["errors"]))}
        report = {"version": VERSION, "summary": summary, "primary": PRIMARY, "rows": len(rows), "materials": 120,
            "new_root_forwards": runtime.snapshot_counts()["root"], "new_encoder_forwards": runtime.snapshot_counts()["encoder"],
            "candidate_count": sum(len(item["boundary_pool"]["candidates"]) for item in prepared),
            "evaluated_candidates": sum(item["stage"]["evaluated_candidates"] for item in materials),
            "encoder_input_tokens": sum(item["stage"]["input_tokens"] for item in materials),
            "preflight_executable": sum(item["preflight"]["executable"] for item in prepared), "network": network,
            "new_generation_posts": 0, "cloud_calls": 0, "new_api_cost_cny": 0, "default_changed": False,
            "independent_acceptance": False, "implementation_unchanged": all(sha(ROOT / rel) == expected for rel, expected in frozen.items())}
        save(output / "rows.json", rows);save(output / "report.json", report);save(output / "network_audit.json", network)
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "benchmarks/artifacts/context_candidate_detection_20261026_v2.zip")
    parser.add_argument("--reference-flat", type=Path, default=ROOT / "results/flat_candidate_detection_20261026_v1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.archive, args.reference_flat, args.output, execute=args.execute), ensure_ascii=False))
