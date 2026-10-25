"""Frozen local-only, paired candidate-typing development diagnostic.

The original 80 development and 40 already-exposed former heldout materials are
kept separate. No fresh acceptance set, native-client call or paid API is used.
Gold files are hashed/copied as bytes initially and parsed only after closure.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.context_candidate_typing import LocalContextCandidateTyper, preflight
from memory_migration_study.context_typed_detection import compose_typed_detection
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import _digest, _sources, detect_sensitive
from scripts.run_semantic_detection_benchmark import CountingAgent, install_network_guard, score_detection, sum_counts

VERSION = "context_candidate_development_v1"
ARMS = ("ner_rules", "typed_seeded_only", "typed_all_candidates")
SPLITS = ("development", "heldout")
SEED = 2026102602


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def utc():
    return datetime.now(timezone.utc).isoformat()


class ModelObserver:
    def __init__(self, output, transport, maximum):
        self.output, self.transport, self.maximum = output, transport, maximum
        self.calls, self.case_id, self.closed = [], None, False
        save(self.output / "model_calls.json", [])

    def __call__(self, method, path, body=None):
        if method != "POST":
            return self.transport(method, path, body)
        if self.closed or len(self.calls) >= self.maximum or path != "/api/chat":
            raise ValueError("registered_generation_budget_exceeded")
        raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        record = {"index": len(self.calls), "case_id": self.case_id, "path": path,
                  "request": deepcopy(body), "request_utf8_bytes": len(raw),
                  "request_sha256": hashlib.sha256(raw).hexdigest(), "started_at": utc(),
                  "response": None, "transport_error": None}
        self.calls.append(record)  # Do not refund uncertain/failed submissions.
        save(self.output / "model_calls.json", self.calls)
        started = time.monotonic()
        try:
            record["response"] = self.transport(method, path, body)
            return record["response"]
        except Exception:
            record["transport_error"] = "local_transport_failed"
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic() - started
            record["completed_at"] = utc()
            save(self.output / "model_calls.json", self.calls)


def implementation_files():
    names = ("privacy", "local_detector", "ner_detector", "candidate_proposals", "candidate_adjudicator",
             "context_candidate_typing", "context_typed_detection")
    return [Path(__file__).resolve(), ROOT / "scripts/run_semantic_detection_benchmark.py",
            *(ROOT / "memory_migration_study" / (name + ".py") for name in names)]


def run(data_root, output, *, execute=False, model_root=None):
    data_root, output = Path(data_root).resolve(), Path(output).resolve()
    if not output.is_relative_to((ROOT / "results").resolve()) or output.exists():
        raise ValueError("new_results_directory_required")
    output.mkdir(parents=True)
    corpus = []
    corpus_hashes = {}
    for split in SPLITS:
        directory = output / split
        directory.mkdir()
        for name in ("runtime.json", "evaluation.json"):
            source = data_root / split / name
            corpus_hashes[split + "/" + name] = sha(source)
            shutil.copyfile(source, directory / name)  # No gold parsing here.
        runtime = json.loads((directory / "runtime.json").read_text(encoding="utf-8"))
        if not isinstance(runtime, list) or len(runtime) != (80 if split == "development" else 40):
            raise ValueError("original_corpus_size_mismatch")
        corpus.extend({**row, "split": split} for row in runtime)
    if len({r["case_id"] for r in corpus}) != len(corpus):
        raise ValueError("duplicate_material_id")
    files = implementation_files()
    source_hashes = {str(p.relative_to(ROOT)): sha(p) for p in files}
    for rel, expected in source_hashes.items():
        destination = output / "frozen_source" / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, destination)
        if sha(destination) != expected:
            raise ValueError("source_snapshot_mismatch")
    random.Random(SEED).shuffle(corpus)
    max_generations = 2 * len(corpus)
    max_encodings = sum(bool(text.strip()) and bool(r["policy"]["protected_categories"])
                        for r in corpus for text in _sources(r["payload"]).values())
    plan = {"version": VERSION, "created_at": utc(), "arms": list(ARMS), "seed": SEED,
            "case_order": [r["case_id"] for r in corpus], "corpus_sha256": corpus_hashes,
            "implementation_sha256": source_hashes, "material_count": len(corpus),
            "max_generations": max_generations, "max_encodings": max_encodings,
            "max_candidates": 16, "max_quote_chars": 256, "context_window_chars": 24,
            "context_tokens": 4096, "max_output_tokens": 1024,
            "request_byte_scope": "canonical compact JSON, not HTTP framing or a wire capture",
            "strict_processing_failures_in_recall_denominator": True,
            "heldout_scope": "already_exposed_regression_not_fresh_acceptance",
            "shared_verdict_ablation": "seeded-only reuses all-candidate judgments; not a standalone competing detector",
            "no_default_branch_change": True, "cloud_calls": 0, "new_api_cost_cny": 0}
    save(output / "plan.json", plan)
    if not execute:
        return {"status": "plan_only", "material_count": len(corpus), "model_calls": 0}
    network = {"allowed_loopback_connections": 0, "blocked_external_connections": 0}
    install_network_guard(network)
    runtime_model = LocalNerRuntime(model_root or ROOT / ".runtime/github_ner")
    encoding_invocations = []
    save(output / "encoding_invocations.json", [])
    current_case = {"case_id": None}
    original_infer = runtime_model.infer
    def observe_encoding(text, labels, *, splitter, threshold):
        if len(encoding_invocations) >= max_encodings:
            raise ValueError("registered_encoding_budget_exceeded")
        record = {"index": len(encoding_invocations), "case_id": current_case["case_id"],
                  "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "labels": deepcopy(labels), "splitter": splitter, "threshold": threshold,
                  "started_at": utc(), "response": None, "error": None}
        encoding_invocations.append(record)
        save(output / "encoding_invocations.json", encoding_invocations)
        try:
            record["response"] = original_infer(text, labels, splitter=splitter, threshold=threshold)
            return record["response"]
        except Exception:
            record["error"] = "local_encoder_failed"
            raise
        finally:
            record["completed_at"] = utc()
            save(output / "encoding_invocations.json", encoding_invocations)
    runtime_model.infer = observe_encoding
    ner = GlinerEntityAgent(runtime_model, approved_policies=[r["policy"] for r in corpus])
    observer = ModelObserver(output, LocalSensitivityAgent()._transport, max_generations)
    typer = LocalContextCandidateTyper(transport=observer)
    save(output / "identities.json", {"ner": ner.cache_identity(), "typer": typer.cache_identity(), "health": typer.health()})
    rows, materials = [], []
    for index, case in enumerate(corpus):
        if any(sha(ROOT / rel) != expected for rel, expected in source_hashes.items()):
            raise ValueError("implementation_changed_during_model_phase")
        observer.case_id = case["case_id"]
        current_case["case_id"] = case["case_id"]
        counting = CountingAgent(ner, "local_encoder")
        baseline = detect_sensitive(case["payload"], case["policy"], agent=counting, mode="combined")
        pool = propose_candidates(case["payload"], case["policy"], baseline["findings"], max_candidates=16, max_quote_chars=256)
        precheck = preflight(case["payload"], case["policy"], pool)
        before = len(observer.calls)
        typing = typer.classify(case["payload"], case["policy"], pool)
        if network["blocked_external_connections"]:
            raise ValueError("external_connection_attempt_aborts_experiment")
        material = {"case_id": case["case_id"], "split": case["split"], "baseline": baseline,
                    "encoder_accounting": counting.accounting(baseline), "pool": pool,
                    "preflight": precheck, "typing": typing, "generation_indices": list(range(before, len(observer.calls)))}
        materials.append(material)
        detections = {"ner_rules": baseline,
            "typed_seeded_only": compose_typed_detection(case["payload"], case["policy"], baseline, pool, typing, promote_untyped=False),
            "typed_all_candidates": compose_typed_detection(case["payload"], case["policy"], baseline, pool, typing)}
        for arm in ARMS:
            rows.append({"case_id": case["case_id"], "split": case["split"], "language": case["language"],
                         "template_family": case["template_family"], "arm": arm, "detection": detections[arm]})
        save(output / "materials.json", materials)
        save(output / "unscored_rows.json", rows)
        if (index + 1) % 10 == 0:
            print(json.dumps({"materials_complete": index + 1, "total": len(corpus), "local_posts": len(observer.calls)}), flush=True)
    observer.closed = True
    bound_files = ("plan.json", "identities.json", "materials.json", "model_calls.json", "encoding_invocations.json", "unscored_rows.json")
    closure = {"model_phase_closed": True, "closed_at": utc(), "generation_posts": len(observer.calls),
               "material_count": len(materials), "unscored_rows_sha256": sha(output / "unscored_rows.json"),
               "artifact_sha256": {name: sha(output / name) for name in bound_files}}
    save(output / "model_phase_closed.json", closure)
    save(output / "score_phase_started.json", {"started_at": utc(), "model_phase_closed_sha256": sha(output / "model_phase_closed.json")})
    by_id = {r["case_id"]: r for r in corpus}
    labels = {}
    for split in SPLITS:
        path = output / split / "evaluation.json"
        if any(sha(output / split / name) != corpus_hashes[split + "/" + name] for name in ("runtime.json", "evaluation.json")):
            raise ValueError("gold_changed_during_model_phase")
        gold = json.loads(path.read_text(encoding="utf-8"))
        if set(gold) != {r["case_id"] for r in corpus if r["split"] == split}:
            raise ValueError("gold_identity_mismatch")
        labels.update(gold)
    for row in rows:
        row["score"] = score_detection(row["detection"], labels[row["case_id"]], by_id[row["case_id"]]["payload"])
    summary = {}
    for split in SPLITS:
        summary[split] = {}
        for arm in ARMS:
            selected = [r for r in rows if r["split"] == split and r["arm"] == arm]
            summary[split][arm] = {"materials": len(selected), "accepted": sum_counts([r["score"]["accepted"] for r in selected]),
                "ok": sum(r["detection"]["status"] == "ok" for r in selected),
                "exact_materials": sum(r["score"]["accepted_complete_exact"] for r in selected),
                "errors": dict(Counter(e for r in selected for e in r["detection"]["errors"]))}
    encoding_counts = [m["encoder_accounting"]["inference_counts"]["local_encoder"] for m in materials]
    report = {"version": VERSION, "summary": summary, "material_count": len(materials), "row_count": len(rows),
              "actual_generations": len(observer.calls), "encoder_invocations_observed": len(encoding_invocations),
              "encoder_calls_reported": sum(encoding_counts), "encoder_invocations_scope": "LocalNerRuntime.infer entry; not GPU kernel tracing",
              "preflight_executable": sum(m["preflight"].get("executable") is True for m in materials),
              "typing_statuses": dict(Counter(m["typing"]["status"] for m in materials)),
              "complete_encoder_accounting": all(m["encoder_accounting"]["complete"] for m in materials),
              "implementation_unchanged": all(sha(ROOT / rel) == expected for rel, expected in source_hashes.items()),
              "network": network, "cloud_calls": 0, "new_api_cost_cny": 0,
              "scope": "Original 80 development + 40 exposed regression materials; no independent acceptance, no task-utility/novelty claim."}
    save(output / "rows.json", rows)
    save(output / "report.json", report)
    save(output / "network_audit.json", network)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=ROOT / "examples/privacy_semantics_v1/detection")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-root", type=Path, default=ROOT / ".runtime/github_ner")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    result = run(args.data_root, args.output, execute=args.execute, model_root=args.model_root)
    print(json.dumps(result, ensure_ascii=False))
