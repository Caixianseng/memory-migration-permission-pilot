"""Four predeclared flat-decision conditions; recorded detector input reused.

Old 80 development + 40 exposed regression, never fresh acceptance. Baseline
bytes come from the published synthetic archive. Only runtime/material data
are parsed before model closure; no gold or recorded scores enter inference.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.boundary_detector import refine_detection
from memory_migration_study.candidate_decision import LocalCandidateDecision, preflight
from memory_migration_study.candidate_decision_detection import compose_decision_detection
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.context_typed_detection import compose_typed_detection
from memory_migration_study.local_detector import LocalSensitivityAgent
from scripts.run_context_candidate_diagnostic import ModelObserver, save, sha, utc
from scripts.run_semantic_detection_benchmark import install_network_guard, score_detection, sum_counts

VERSION = "flat_candidate_decision_paired_development_v1"
SEED = 2026102603
CONFIGS = {
    "flat_local_prior": {"context_view": "local_windows", "show_proposed_category": True},
    "flat_local_no_prior": {"context_view": "local_windows", "show_proposed_category": False},
    "flat_full_no_prior": {"context_view": "full_source", "show_proposed_category": False},
    "primary_boundary_full_no_prior": {"context_view": "full_source", "show_proposed_category": False},
}
CONTROLS = ("recorded_raw_ner", "standard_boundary_ner", "recorded_five_field_all")
PRIMARY = "primary_boundary_full_no_prior"
SPLITS = ("development", "heldout")


def source_files():
    names = ("privacy", "local_detector", "ner_detector", "candidate_proposals", "candidate_adjudicator",
             "context_candidate_typing", "context_typed_detection", "boundary_detector", "boundary_reconciliation",
             "structured_candidates", "amount_candidates", "candidate_decision", "candidate_decision_detection")
    return [Path(__file__).resolve(), ROOT / "scripts/run_context_candidate_diagnostic.py",
            ROOT / "scripts/run_semantic_detection_benchmark.py",
            *(ROOT / "memory_migration_study" / (name + ".py") for name in names)]


def prepare_reference(archive, output):
    receipt = json.loads(archive.with_suffix(".manifest.json").read_text(encoding="utf-8"))
    if sha(archive) != receipt["sha256"]:
        raise ValueError("published_reference_archive_changed")
    with zipfile.ZipFile(archive) as source:
        public = json.loads(source.read("PUBLIC_ARTIFACT_MANIFEST.json"))
        for rel, expected in public["files"].items():
            if hashlib.sha256(source.read(rel)).hexdigest() != expected:
                raise ValueError("published_reference_member_changed")
        old_plan = json.loads(source.read("plan.json"))  # Contains no gold labels.
        for rel, expected in old_plan["implementation_sha256"].items():
            if sha(ROOT / rel.replace("\\", "/")) != expected:
                raise ValueError("recorded_reference_implementation_changed")
        corpus = []
        for split in SPLITS:
            (output / split).mkdir()
            for name in ("runtime.json", "evaluation.json"):
                raw = source.read(split + "/" + name)
                if hashlib.sha256(raw).hexdigest() != old_plan["corpus_sha256"][split + "/" + name]:
                    raise ValueError("reference_corpus_mismatch")
                (output / split / name).write_bytes(raw)  # Gold stays bytes.
            runtime = json.loads((output / split / "runtime.json").read_text(encoding="utf-8"))
            if len(runtime) != (80 if split == "development" else 40):
                raise ValueError("original_corpus_size_changed")
            corpus.extend({**row, "split": split} for row in runtime)
        raw_materials = source.read("materials.json")
        (output / "reference_materials.json").write_bytes(raw_materials)
        materials = json.loads(raw_materials)  # Predictions only; no scoring labels.
        identities = json.loads(source.read("identities.json"))
    return corpus, {r["case_id"]: r for r in materials}, identities, {
        "archive": str(archive.relative_to(ROOT)), "archive_sha256": receipt["sha256"],
        "public_manifest": public, "corpus_sha256": old_plan["corpus_sha256"],
        "historical_encoder_calls": 168, "historical_generation_calls": 81,
        "new_encoder_calls": 0, "reference_materials_sha256": sha(output / "reference_materials.json")}


def run(archive, output, *, execute=False):
    archive, output = Path(archive).resolve(), Path(output).resolve()
    if output.exists() or not output.is_relative_to((ROOT / "results").resolve()):
        raise ValueError("new_results_directory_required")
    output.mkdir(parents=True)
    corpus, references, old_identities, reference = prepare_reference(archive, output)
    if len(references) != len(corpus) or set(references) != {c["case_id"] for c in corpus}:
        raise ValueError("reference_material_identity_mismatch")
    schedule = []
    rng = random.Random(SEED)
    rng.shuffle(corpus)
    for case in corpus:
        order = list(CONFIGS)
        rng.shuffle(order)
        schedule.append({"case_id": case["case_id"], "arm_order": order})
    implementations = {str(p.relative_to(ROOT)): sha(p) for p in source_files()}
    for rel, expected in implementations.items():
        dest = output / "frozen_source" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dest)
        if sha(dest) != expected:
            raise ValueError("source_snapshot_changed")
    plan = {"version": VERSION, "created_at": utc(), "seed": SEED, "schedule": schedule,
        "configs": CONFIGS, "controls": list(CONTROLS), "primary": PRIMARY,
        "material_count": 120, "row_count": 840, "max_new_generations": 960, "max_output_tokens": 1024,
        "context_tokens": 4096, "max_candidates": 16, "reference": reference,
        "implementation_sha256": implementations, "heldout_scope": "exposed_regression_not_independent_acceptance",
        "raw_pool_development_ceiling": {"covered": 55, "gold_spans": 58, "scope": "earlier separate offline qualification"},
        "boundary_pool_development_ceiling": {"covered": 57, "gold_spans": 58, "scope": "earlier separate offline qualification"},
        "scope": "Old-five-field comparison is a recorded interface reference; causal input contrasts are among new flat arms.",
        "cloud_calls": 0, "new_api_cost_cny": 0, "default_branch_changed": False}
    save(output / "plan.json", plan)
    if not execute:
        return {"status": "plan_only", "new_model_calls": 0, "material_count": 120}
    network = {"allowed_loopback_connections": 0, "blocked_external_connections": 0}
    install_network_guard(network)
    observer = ModelObserver(output, LocalSensitivityAgent()._transport, 960)
    agents = {arm: LocalCandidateDecision(config, transport=observer) for arm, config in CONFIGS.items()}
    save(output / "identities.json", {"health": next(iter(agents.values())).health(),
        "agents": {arm: agent.cache_identity() for arm, agent in agents.items()},
        "recorded_ner": old_identities["ner"], "recorded_old_typer": old_identities["typer"]})
    rows, materials = [], []
    for index, case in enumerate(corpus):
        if any(sha(ROOT / rel) != expected for rel, expected in implementations.items()):
            raise ValueError("implementation_changed_during_model_phase")
        cid = case["case_id"]
        parent = references[cid]
        baseline = parent["baseline"]
        raw_pool = propose_candidates(case["payload"], case["policy"], baseline["findings"], max_candidates=16, max_quote_chars=256)
        if raw_pool != parent["pool"]:
            raise ValueError("recorded_pool_reconstruction_mismatch")
        boundary = refine_detection(case["payload"], case["policy"], baseline)
        boundary_pool = propose_candidates(case["payload"], case["policy"], boundary["findings"], max_candidates=16, max_quote_chars=256)
        controls = {CONTROLS[0]: baseline, CONTROLS[1]: boundary,
                    CONTROLS[2]: compose_typed_detection(case["payload"], case["policy"], baseline, raw_pool, parent["typing"])}
        material = {"case_id": cid, "split": case["split"], "boundary_baseline": boundary,
                    "boundary_pool": boundary_pool, "stages": {}}
        for arm, detection in controls.items():
            rows.append({"case_id": cid, "split": case["split"], "language": case["language"], "arm": arm,
                         "detection": detection})
        for arm in schedule[index]["arm_order"]:
            is_primary = arm == PRIMARY
            pool, current_base = (boundary_pool, boundary) if is_primary else (raw_pool, baseline)
            observer.case_id = cid
            before = len(observer.calls)
            qualification = preflight(case["payload"], case["policy"], pool, config=CONFIGS[arm])
            stage = agents[arm].classify(case["payload"], case["policy"], pool)
            if network["blocked_external_connections"]:
                raise ValueError("external_connection_attempt_aborts_experiment")
            indices = list(range(before, len(observer.calls)))
            for k in indices:
                observer.calls[k]["arm"] = arm
            save(output / "model_calls.json", observer.calls)
            material["stages"][arm] = {"preflight": qualification, "stage": stage, "generation_indices": indices}
            detection = compose_decision_detection(case["payload"], case["policy"], current_base, pool, stage)
            rows.append({"case_id": cid, "split": case["split"], "language": case["language"], "arm": arm, "detection": detection})
        materials.append(material)
        save(output / "materials.json", materials)
        save(output / "unscored_rows.json", rows)
        if (index + 1) % 10 == 0:
            print(json.dumps({"complete": index + 1, "total": 120, "new_posts": len(observer.calls)}), flush=True)
    observer.closed = True
    bound = ("plan.json", "reference_materials.json", "identities.json", "materials.json", "model_calls.json", "unscored_rows.json")
    save(output / "model_phase_closed.json", {"model_phase_closed": True, "closed_at": utc(),
        "new_generation_posts": len(observer.calls), "artifact_sha256": {f: sha(output / f) for f in bound}})
    save(output / "score_phase_started.json", {"started_at": utc(), "closure_sha256": sha(output / "model_phase_closed.json")})
    labels = {}
    for split in SPLITS:
        for name in ("runtime.json", "evaluation.json"):
            if sha(output / split / name) != reference["corpus_sha256"][split + "/" + name]:
                raise ValueError("corpus_changed_during_model_phase")
        labels.update(json.loads((output / split / "evaluation.json").read_text(encoding="utf-8")))
    by_id = {c["case_id"]: c for c in corpus}
    for row in rows:
        row["score"] = score_detection(row["detection"], labels[row["case_id"]], by_id[row["case_id"]]["payload"])
    summary = {}
    for split in SPLITS:
        summary[split] = {}
        for arm in (*CONTROLS, *CONFIGS):
            selected = [r for r in rows if r["split"] == split and r["arm"] == arm]
            summary[split][arm] = {"materials": len(selected), "accepted": sum_counts([r["score"]["accepted"] for r in selected]),
                "ok": sum(r["detection"]["status"] == "ok" for r in selected),
                "complete_exact": sum(r["score"]["accepted_complete_exact"] for r in selected),
                "errors": dict(Counter(e for r in selected for e in r["detection"]["errors"]))}
    report = {"version": VERSION, "summary": summary, "primary": PRIMARY, "rows": len(rows), "materials": 120,
              "new_generation_posts": len(observer.calls), "new_encoder_calls": 0,
              "new_generation_posts_by_arm": dict(Counter(c["arm"] for c in observer.calls)),
              "network": network, "implementation_unchanged": all(sha(ROOT / r) == h for r, h in implementations.items()),
              "cloud_calls": 0, "new_api_cost_cny": 0, "independent_acceptance": False, "default_changed": False}
    save(output / "rows.json", rows)
    save(output / "report.json", report)
    save(output / "network_audit.json", network)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "benchmarks/artifacts/context_candidate_detection_20261026_v2.zip")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.archive, args.output, execute=args.execute), ensure_ascii=False))
