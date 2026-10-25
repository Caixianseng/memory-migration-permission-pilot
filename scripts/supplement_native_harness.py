"""Two Harness-only supplements after the preserved zero-request SDK failure.

Never repeats the successful Qoder calls. Requires explicit --execute.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_native_agent_handoff import write_json, score
from memory_migration_study.deepseek_native import run_deepseek_question


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--reason", default="Preserved v1 account-catalog stdout caused non-JSON-RPC rejection before model requests.")
    parser.add_argument("--previous-supplement", type=Path)
    args = parser.parse_args()
    base, out = args.base.resolve(), args.output.resolve()
    results = (ROOT / "results").resolve()
    if not base.is_relative_to(results) or not out.is_relative_to(results) or out.exists():
        raise SystemExit("Use an existing results base and a new results output.")
    plan = json.loads((base / "plan.json").read_text(encoding="utf-8"))
    previous = json.loads((base / "native_results.json").read_text(encoding="utf-8"))
    for row in previous:
        if row["client"] == "harness":
            counts = row["receipt"]["guard_counts"]
            if row["receipt"]["status"] != "error" or any(counts[k] != 0 for k in
                    ("agent_attempt_count", "stream_attempt_count", "allowed_stream_count")):
                raise SystemExit("Supplement only admitted after witnessed pre-model transport failures.")
    out.mkdir(parents=True)
    probe = ROOT / "results/native_agent_probe_20261026"
    source_files = [Path(__file__).resolve(), ROOT / "scripts/run_native_agent_handoff.py",
                    *(ROOT / "memory_migration_study" / (name + ".py") for name in
                      ("native_agent_protocol", "qoder_native", "deepseek_native", "deepseek_sdk")),
                    probe / "dsh_single_request_guard.mjs", probe / "sdk_guard_metadata.patch.yml"]
    manifest = {str(p.relative_to(ROOT)): sha(p) for p in source_files}
    for rel, registered_hash in manifest.items():
        snapshot = out / "implementation_snapshot" / rel
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, snapshot)
        if sha(snapshot) != registered_hash:
            raise SystemExit("Implementation snapshot changed before registration.")
    specs = [(plan["directions"][1], "source", 0), (plan["directions"][0], "target", 2)]
    supplement_plan = {"schema": "native-harness-transport-fix-v1", "base_result_dir": str(base),
                       "base_plan_sha256": sha(base / "plan.json"),
                       "base_results_sha256": sha(base / "native_results.json"),
                       "implementation_sha256_before_supplement": manifest,
                       "prompt": plan["prompt"], "prompt_sha256": plan["prompt_sha256"],
                       "max_questions": 2, "max_output_tokens_each": 64,
                       "reason": args.reason,
                       "implementation_snapshot": "implementation_snapshot",
                       "no_qoder_repetition": True,
                       "specs": [{"base_index": i, "workspace": d[s + "_workspace"],
                                  "memory_sha256": d[s + "_sha256"]} for d, s, i in specs]}
    if args.previous_supplement:
        previous_dir = args.previous_supplement.resolve()
        if not previous_dir.is_relative_to(results):
            raise SystemExit("Previous supplement must be under results.")
        earlier_rows = json.loads((previous_dir / "native_results.json").read_text(encoding="utf-8"))
        if any(r["receipt"].get("guard_counts", {}).get("allowed_stream_count") != 0 for r in earlier_rows):
            raise SystemExit("Additional supplement only allowed after witnessed zero-forward engineering failures.")
        supplement_plan["previous_supplement"] = {"path": str(previous_dir), "results_sha256": sha(previous_dir / "native_results.json"),
                                                   "question_attempts": len(earlier_rows), "allowed_native_streams": 0}
    write_json(out / "plan.json", supplement_plan)
    if not args.execute:
        print(json.dumps({"status": "plan_only", "model_calls": 0}))
        return
    rows = []
    for index, (direction, stage, base_index) in enumerate(specs):
        if any(sha(ROOT / p) != h for p, h in manifest.items()):
            raise SystemExit("Registered implementation changed; no further launch.")
        workspace = Path(direction[stage + "_workspace"])
        if workspace.resolve() != workspace or not workspace.is_relative_to(base) or sha(workspace / "AGENTS.md") != direction[stage + "_sha256"]:
            raise SystemExit("Native fixture no longer matches the original registration.")
        start = time.monotonic()
        receipt = run_deepseek_question(workspace, plan["prompt"], runtime_home=probe / (out.name + "_" + str(index)),
            patch_template=probe / "sdk_guard_metadata.patch.yml", guard_path=probe / "dsh_single_request_guard.mjs",
            credentials_source=Path("C:/Users/CAI/.dsh/.credentials.yaml"))
        raw = receipt.get("raw_response") or receipt.get("answer")
        row = {"index": index, "base_index": base_index, "direction": direction["direction"],
               "stage": stage, "client": "harness", "elapsed_seconds": time.monotonic() - start,
               "receipt": receipt, "score": score(receipt, direction["expected_" + stage]),
               "registered_canary_disclosure": direction["expected_source"]["source_canary"] in raw
                   if stage == "target" and isinstance(raw, str) else None}
        rows.append(row)
        write_json(out / "native_results.json", rows)
        print(json.dumps({"index": index, "status": receipt["status"], "error": receipt["error"],
                          "correct": row["score"]["all_fields_correct"]}), flush=True)
    write_json(out / "summary.json", {"status": "completed", "question_attempts": len(rows),
        "client_successes": sum(r["receipt"]["status"] == "ok" for r in rows),
        "all_fields_correct": sum(r["score"]["all_fields_correct"] for r in rows),
        "original_failed_results_preserved": True, "qoder_new_calls": 0, "cost": None})


if __name__ == "__main__":
    main()
