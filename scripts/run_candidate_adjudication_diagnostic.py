"""Local development-only candidate-role comparison using saved NER proposals.

This does not claim a new blind acceptance or an end-to-end privacy result.
Runtime selection is deterministic by language/protected category, never gold.
Gold is parsed after all model calls. Existing files must remain unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.privacy import _digest
from scripts.run_semantic_detection_benchmark import install_network_guard, score_detection

VERSION = "candidate_position_diagnostic_v1"
ARMS = ("without_position", "with_position")


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def select(runtime):
    selected, quota = [], {}
    for item in runtime:
        categories = tuple(item["policy"]["protected_categories"])
        key = (item["language"], categories)
        maximum = 1 if categories else 2
        if quota.get(key, 0) < maximum:
            selected.append(item)
            quota[key] = quota.get(key, 0)+1
    return selected


def run(source, output, config, *, adjudicator=None, progress=None):
    from memory_migration_study.candidate_adjudicator import LocalCandidateAdjudicator

    source, output = Path(source), Path(output)
    paths = {name: source/name for name in ("runtime.json", "evaluation.json", "rows.json")}
    before = {name: sha(path) for name, path in paths.items()}
    runtime = json.loads(paths["runtime.json"].read_text(encoding="utf-8"))
    previous = json.loads(paths["rows.json"].read_text(encoding="utf-8"))
    lookup = {(row["case_id"], row["arm"]): row for row in previous}
    if len(lookup) != len(previous):
        raise ValueError("duplicate_saved_condition")
    chosen = select(runtime)
    pools = {item["case_id"]: propose_candidates(item["payload"], item["policy"],
             lookup[(item["case_id"], "gliner_combined")]["detection"]["findings"]) for item in chosen}
    output.mkdir(parents=True, exist_ok=False)
    files = [Path(__file__), Path("memory_migration_study/candidate_adjudicator.py"),
             Path("memory_migration_study/candidate_proposals.py"), Path("memory_migration_study/local_detector.py"),
             Path("memory_migration_study/privacy.py")]
    frozen = {str(path): sha(path) for path in files}
    implementation = output/"implementation"
    implementation.mkdir()
    for path in files:
        shutil.copy2(path, implementation/path.name)
    save(output/"plan.json", {"version": VERSION, "arms": ARMS, "source_sha256": before,
         "runtime_selection": "First per language/protected-category scope plus first two empty-scope items per language; runtime order only, no score selection.",
         "selected_case_ids": [item["case_id"] for item in chosen], "implementation_sha256": frozen,
         "config": config, "max_answer_calls": 0, "max_new_encoder_calls": 0,
         "max_local_generations": 4*len(chosen), "scope": "Exposed development only. Saved GLiNER+rules candidate proposals are replayed; no new encoder is run. Exact-span role classification is not final propagated masking or full-project acceptance."})
    save(output/"runtime.json", chosen)
    save(output/"proposal_pools.json", pools)
    agent = adjudicator or LocalCandidateAdjudicator(config)
    LocalSensitivityAgent(config).health()
    if hasattr(agent, "cache_identity"):
        save(output/"runtime_identity.json", agent.cache_identity())
    rows = []
    for item in chosen:
        order = list(ARMS)
        random.Random(VERSION+item["case_id"]).shuffle(order)
        for arm in order:
            result = agent(payload=item["payload"], policy=item["policy"], pool=pools[item["case_id"]],
                           position_context=arm == "with_position")
            rows.append({"case_id": item["case_id"], "language": item["language"], "arm": arm,
                         "candidate_pool_sha256": pools[item["case_id"]]["pool_sha256"], "adjudication": result})
            save(output/"rows.json", rows)
            if progress:
                progress({"completed": len(rows), "expected": 2*len(chosen), "arm": arm,
                          "case_id": item["case_id"], "status": result["status"], "calls": result.get("local_calls")})
    if before != {name: sha(path) for name, path in paths.items()} or frozen != {str(path): sha(path) for path in files}:
        raise ValueError("inputs_or_implementation_changed")
    # Classification is now complete. Gold is first parsed here for scoring.
    gold = json.loads(paths["evaluation.json"].read_text(encoding="utf-8"))
    source_lookup = {item["case_id"]: item for item in chosen}
    for row in rows:
        decision = row["adjudication"]
        scoring_view = {"status": "ok" if decision["status"] == "adjudicated_only" else "needs_review",
                        "findings": decision.get("findings", [])}
        row["score"] = score_detection(scoring_view, gold[row["case_id"]], source_lookup[row["case_id"]]["payload"])
    summary = {}
    for arm in ARMS:
        selected = [row for row in rows if row["arm"] == arm]
        counts = {key: sum(row["score"]["accepted"][key] for row in selected) for key in ("tp", "fp", "fn")}
        summary[arm] = {**counts, "precision": counts["tp"]/(counts["tp"]+counts["fp"]) if counts["tp"]+counts["fp"] else None,
                        "recall": counts["tp"]/(counts["tp"]+counts["fn"]) if counts["tp"]+counts["fn"] else None,
                        "materials": len(selected), "needs_review": sum(row["adjudication"]["status"] != "adjudicated_only" for row in selected),
                        "local_generations": sum(row["adjudication"].get("local_calls", 0) for row in selected)}
    report = {"version": VERSION, "scope": "Development mechanism diagnosis only; not full pipeline or blind acceptance.",
              "arms": summary, "model_calls": sum(group["local_generations"] for group in summary.values()),
              "new_encoder_calls": 0, "cloud_calls": 0, "api_cost_cny": 0, "source_unchanged": True,
              "implementation_unchanged": True, "runtime_selected_before_gold": True}
    save(output/"rows.json", rows)
    save(output/"report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("results/semantic_detection_v1/development"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/local_privacy_detector.json"))
    args = parser.parse_args()
    network = {"allowed_loopback_connections": 0, "blocked_external_connections": 0}
    install_network_guard(network)
    report = run(args.source, args.output, json.loads(args.config.read_text(encoding="utf-8")),
                 progress=lambda item: print(json.dumps(item, ensure_ascii=False), flush=True))
    save(args.output/"network_audit.json", network)
    print(json.dumps(report, ensure_ascii=False), flush=True)
