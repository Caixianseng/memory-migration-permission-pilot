"""Recheck stored comparison evidence without another model generation."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.evidence import evaluate
from memory_migration_study.plan_verifier import verify_plan
from memory_migration_study.reuse_benchmark import role_cases, score_cached_task, summarize_cache, save


def verify(root):
    root = Path(root)
    roles = json.loads((root / "roles/report.json").read_text(encoding="utf-8"))
    cases = {case["case_id"]: (case, options) for case, options in role_cases()}
    checks = []
    for row in roles["rows"]:
        case, options = cases[row["case_id"]]
        constraints = {k: options[k] for k in ("implicit_readers", "allowed_reader_sets") if k in options}
        current = verify_plan(case, row["plan"], **constraints)
        checks.append({"check": "independent_model", "case": row["case_id"], "method": row["method"],
                       "passed": current == row["model"]})
        if row["direct"] is not None:
            evidence = json.loads((root / "roles/evidence" / f"{row['case_id']}__{row['method']}.json").read_text(encoding="utf-8"))
            checks.append({"check": "raw_http_recompute", "case": row["case_id"], "method": row["method"],
                           "passed": evaluate(evidence) == row["direct"]})
    cache = json.loads((root / "cache/report.json").read_text(encoding="utf-8"))
    evaluation = json.loads((root / "cache/evaluation.json").read_text(encoding="utf-8"))
    checks.append({"check": "answer_scores", "passed": all(
        score_cached_task(row, evaluation[row["story_id"]]) == row["score"] for row in cache["rows"])})
    checks.append({"check": "cache_aggregate", "passed": summarize_cache(cache["rows"], cache["setups"]) == cache["arms"]})
    checks.append({"check": "actual_call_total", "passed": cache["actual_local_calls"] == (
        sum(s["detection"]["local_calls"] for s in cache["setups"]) +
        sum(sum(o["local_calls"] for o in (r.get("detection") or {}).get("agent_observations", []))
            + r["answer_calls"] for r in cache["rows"]))})
    plan = json.loads((root / "cache/plan.json").read_text(encoding="utf-8"))
    archive = root / "cache/implementation"
    checks.append({"check": "executed_source_archive", "passed": all(
        (archive / name).is_file() and hashlib.sha256((archive / name).read_bytes()).hexdigest() == expected
        for name, expected in plan["implementation_sha256"].items())})
    return {"status": "passed" if all(c["passed"] for c in checks) else "failed", "checks": checks,
            "verification_implementation_sha256": {name: hashlib.sha256((Path(__file__).resolve().parents[1] / "memory_migration_study" / name).read_bytes()).hexdigest()
                                                  for name in ("plan_verifier.py", "reuse_benchmark.py", "evidence.py")},
            "model_generations": 0,
            "scope": "Recomputes finite configuration, HTTP visibility, answer scores and counts. Original masking alignment instrumentation is preserved, not reconstructed from a persisted restoration map."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.run)
    save(args.output, result)
    print(json.dumps({"status": result["status"], "checks": len(result["checks"]), "model_generations": 0}))
    raise SystemExit(0 if result["status"] == "passed" else 1)
