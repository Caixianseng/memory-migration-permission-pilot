"""Offline synthetic objective/contract probe, not a new algorithm benchmark."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_migration_study.task_budget_reference import solve_reference, evaluate_plan
from memory_migration_study.policy import make_plan
from memory_migration_study.plan_verifier import verify_plan


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def legacy_full_cover(problem):
    """Observe the original contract unchanged; do not relabel it same-K optimization."""
    case = {"case_id": problem["case_id"],
            "actors": [{"actor_id": a, "user_id": "synthetic-user-" + a,
                        "agent_id": "synthetic-agent-" + a} for a in problem["actors"]],
            "actor_mapping": {a: "synthetic-target-" + a for a in problem["actors"]},
            "records": [{"source_id": r["source_id"], "text": "Synthetic fact " + r["source_id"],
                         "source_readers": r["readers"], "recipient_readers": r["readers"],
                         "target_readers": r["readers"], "export_allowed": r["export_allowed"],
                         "copy_allowed": r["max_target_copies"] > 1} for r in problem["records"]]}
    constraints = {k: problem["target"][k] for k in ("implicit_readers", "allowed_reader_sets")}
    plan = make_plan(case, "role_cover", "synthetic-budget-probe", planner_options=constraints)
    old_check = verify_plan(case, plan, **constraints)
    new_plan = {"case_id": problem["case_id"], "groups": [
        {"readers": c["readers"], "source_ids": sorted(o["source_id"] for o in plan["objects"]
         if o["container_id"] == c["container_id"])} for c in plan["containers"]]}
    return {"method": "unchanged_legacy_complete_cover", "plan": new_plan,
            "legacy_verification": old_check, "legacy_excluded": plan["excluded"],
            "new_contract_evaluation": evaluate_plan(problem, new_plan),
            "same_budget_optimizer": False,
            "contract_note": "Old noncopyable semantics preserve full audience; old copy=True is not an integer cap. "
                             "Do not interpret differences as new-algorithm gains."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if not output.is_relative_to(ROOT / "results"):
        parser.error("output must be a fresh directory under project results")
    output.mkdir(parents=True, exist_ok=False)
    fixture_path = ROOT / "examples/task_budget_feasibility_v1.json"
    frozen_paths = [fixture_path, Path(__file__).resolve(), ROOT / "memory_migration_study/task_budget_reference.py",
                    ROOT / "memory_migration_study/role_cover.py", ROOT / "memory_migration_study/policy.py",
                    ROOT / "memory_migration_study/plan_verifier.py"]
    frozen = {str(p.relative_to(ROOT)).replace("\\", "/"): digest(p) for p in frozen_paths}
    fixture_bytes = fixture_path.read_bytes()
    (output / "frozen_fixtures.json").write_bytes(fixture_bytes)
    (output / "source_manifest.json").write_text(json.dumps(frozen, indent=2) + "\n", encoding="utf-8")
    cases = json.loads(fixture_bytes)["cases"]
    results = []
    started = time.perf_counter()
    with patch("socket.create_connection", side_effect=RuntimeError("offline_probe_network_forbidden")) as connect, \
         patch("socket.socket.connect", side_effect=RuntimeError("offline_probe_network_forbidden")) as sock, \
         patch("urllib.request.urlopen", side_effect=RuntimeError("offline_probe_network_forbidden")) as url:
        for problem in cases:
            comparisons = {objective: solve_reference(problem, objective=objective)
                           for objective in ("edges", "task_weighted_edges", "tasks")}
            legacy = legacy_full_cover(problem)
            results.append({"case_id": problem["case_id"], "constraint_origin": "synthetic",
                            "comparisons": comparisons, "legacy": legacy})
        network_attempts = connect.call_count + sock.call_count + url.call_count
    unchanged = all(digest(p) == frozen[str(p.relative_to(ROOT)).replace("\\", "/")] for p in frozen_paths)
    solved = [s for r in results for s in r["comparisons"].values()]
    summary = {"schema": "task_budget_feasibility_probe_v1", "fixture_cases": len(cases),
               "reference_solves": len(solved), "legacy_full_cover_observations": len(results),
               "all_reference_plans_valid": all(s["evaluation"]["valid"] for s in solved),
               "all_reference_optima_proven": all(s["status"] == "optimal_in_declared_finite_model" for s in solved),
               "source_unchanged": unchanged, "source_manifest": frozen,
               "elapsed_seconds": round(time.perf_counter() - started, 6),
               "network_attempts": network_attempts, "model_calls": 0, "native_product_requests": 0,
               "native_product_group_cap_verified": False, "new_algorithm_evaluated": False,
               "independent_real_world_tasks": 0, "goal_resumed": False,
               "scope": "Configuration-only synthetic mechanism checks; no content, retrieval, identity or native enforcement proof.",
               "weighted_baseline": "Sum each task weight once per edge in its independently eligible sufficient sets; "
                                    "no K feasibility or scoring labels used to filter paths.",
               "results": results}
    (output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k not in {"results", "source_manifest"}},
                     indent=2, ensure_ascii=False))
    if not unchanged or network_attempts or not summary["all_reference_plans_valid"]:
        raise SystemExit("probe_integrity_or_configuration_failure")


if __name__ == "__main__":
    main()
