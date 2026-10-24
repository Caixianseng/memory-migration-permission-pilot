"""Recompute frozen NER experiment scores and accounting without model calls."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.ner_benchmark import ARMS, aggregate
from memory_migration_study.privacy import _digest
from memory_migration_study.reuse_benchmark import save, score_cached_task


def verify(root):
    root = Path(root)
    read = lambda name: json.loads((root / name).read_text(encoding="utf-8"))
    plan, runtime, evaluation = read("plan.json"), read("runtime.json"), read("evaluation.json")
    report, rows = read("report.json"), read("rows.json")
    stories = {story["story_id"]: story for story in runtime}
    expected = Counter((s["story_id"], t["task_id"], a) for s in runtime for t in s["tasks"] for a in ARMS)
    actual = Counter((r["story_id"], r["task_id"], r["arm"]) for r in rows)
    checks = []
    def check(name, passed):
        checks.append({"check": name, "passed": bool(passed)})

    check("complete_unique_condition_matrix", actual == expected and plan["arms"] == list(ARMS))
    check("input_hashes", _digest(runtime) == plan["runtime_sha256"] and _digest(evaluation) == plan["evaluation_sha256"])
    check("report_rows_match", report["rows"] == rows)
    check("answer_scores", all(score_cached_task(r, evaluation[r["story_id"]]) == r["score"] for r in rows))
    check("all_condition_aggregates", aggregate(rows) == report["arms"])
    check("detector_accounting", all(r["detector_calls"] == sum(o["local_calls"] for o in
          (r.get("detection") or {}).get("agent_observations", [])) for r in rows))
    check("call_totals", report["qwen_detector_generations"] == sum(r["detector_calls"] for r in rows if r["arm"] == "qwen")
          and report["encoder_invocations"] == sum(r["detector_calls"] for r in rows if r["arm"] != "qwen")
          and report["answer_generations"] == sum(r["answer_calls"] for r in rows))
    common = []
    for story in runtime:
        for task in story["tasks"]:
            selected = [r for r in rows if r["story_id"] == story["story_id"] and r["task_id"] == task["task_id"]]
            if task["actor_id"] == "owner" and len(selected) == len(ARMS) and all(r["prepare_status"] == "ok" for r in selected):
                common.extend(selected)
    check("paired_denominators", len(common) // len(ARMS) == report["matched_ready_tasks"]
          and len({r["story_id"] for r in common}) == report["matched_ready_stories"]
          and {a: sum(r["score"]["correct"] for r in common if r["arm"] == a) for a in ARMS} == report["matched_ready_correct"])
    archive = root / "implementation"
    check("executed_source_archive", all((archive / name).is_file() and hashlib.sha256((archive / name).read_bytes()).hexdigest() == sha
          for name, sha in plan["implementation_sha256"].items()))
    source = Path(__file__).resolve().parents[1] / "memory_migration_study"
    check("current_source_matches_experiment", {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob("*.py")}
          == plan["implementation_sha256"] and report["implementation_unchanged"])

    # No restoration map was persisted. This is a narrower literal-value scan,
    # not a reconstruction of the original character-level masking alignment.
    literal_scan = {}
    for arm in ARMS:
        ready = [r for r in rows if r["arm"] == arm and r["score"]["legal"] and r["prepare_status"] == "ok"]
        memory, query = [], []
        for row in ready:
            sid = row["story_id"]
            original = stories[sid]["source"]["text"]
            values = [original[s["start"]:s["end"]].casefold() for s in evaluation[sid]["sensitive_spans"]]
            if any(value in m["text"].casefold() for value in values for m in row["payload"]["memories"]):
                memory.append((sid, row["task_id"]))
            if any(value in row["payload"]["query"].casefold() for value in values):
                query.append((sid, row["task_id"]))
        literal_scan[arm] = {"ready_legal_tasks": len(ready), "memory_literal_exposures": len(memory),
                             "query_literal_exposures": len(query),
                             "memory_exposure_stories": sorted({sid for sid, _ in memory}),
                             "query_exposure_stories": sorted({sid for sid, _ in query})}
    network = read("network_audit.json")
    return {"status": "passed" if all(c["passed"] for c in checks) else "failed", "checks": checks,
            "rows_verified": len(rows), "registered_name_literal_scan": literal_scan, "network_audit": network,
            "verification_model_calls": 0, "verification_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "scope": "Score, denominator, accounting, archived/current source and input checks. Literal scan only tests registered full names. Character-level masking counts remain original in-process instrumentation; restoration maps were not saved. Passing consistency checks is not passing a privacy or task-quality acceptance threshold."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.run)
    save(args.output, result)
    print(json.dumps({"status": result["status"], "checks": len(result["checks"]), "rows_verified": result["rows_verified"],
                      "literal_scan": result["registered_name_literal_scan"], "verification_model_calls": 0}))
    raise SystemExit(0 if result["status"] == "passed" else 1)
