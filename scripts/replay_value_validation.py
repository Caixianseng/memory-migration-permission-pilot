"""Annotate saved real detector results without inference or score changes."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.value_validation import annotate_detection, VALIDATION_VERSION

ANNOTATION_KEYS = {"validation_annotations", "value_validation_version", "value_validation_scope"}


def run(directories):
    checks, counts, sources = [], Counter(), []
    for directory in map(Path, directories):
        runtime_path, rows_path = directory/"runtime.json", directory/"rows.json"
        raw_runtime, raw_rows = runtime_path.read_bytes(), rows_path.read_bytes()
        materials = {x["case_id"]: x for x in json.loads(raw_runtime)}
        rows = json.loads(raw_rows)
        for row in rows:
            payload = materials[row["case_id"]]["payload"]
            before = json.dumps(row["detection"], ensure_ascii=False, sort_keys=True)
            annotated = annotate_detection(payload, row["detection"])
            stripped = {k:v for k,v in annotated.items() if k not in ANNOTATION_KEYS}
            unchanged = stripped == row["detection"] and before == json.dumps(row["detection"], ensure_ascii=False, sort_keys=True)
            fixed_states = all(a.get(k) in {"valid", "invalid", "not_applicable", "unchecked"}
                               for a in annotated["validation_annotations"] for k in ("format", "checksum", "calendar"))
            no_values = all(set(a) == {"source_id", "start", "end", "category", "status", "validation_error", "format", "checksum", "calendar"}
                            for a in annotated["validation_annotations"])
            checks.append({"split": directory.name, "case_id": row["case_id"], "arm": row["arm"],
                           "original_decisions_preserved": unchanged, "fixed_annotations_without_raw_values": fixed_states and no_values})
            for a in annotated["validation_annotations"]:
                for key in ("format", "checksum", "calendar"):
                    counts[(a["category"], key, a[key])] += 1
        same_bytes = raw_runtime == runtime_path.read_bytes() and raw_rows == rows_path.read_bytes()
        sources.append({"run": directory.name, "rows": len(rows), "original_files_unchanged": same_bytes,
                        "runtime_sha256": hashlib.sha256(raw_runtime).hexdigest(), "rows_sha256": hashlib.sha256(raw_rows).hexdigest()})
    passed = bool(checks) and all(x["original_decisions_preserved"] and x["fixed_annotations_without_raw_values"] for x in checks) and all(s["original_files_unchanged"] for s in sources)
    return {"status": "passed" if passed else "failed", "validation_version": VALIDATION_VERSION,
            "detections_replayed": len(checks), "checks": checks, "sources": sources,
            "annotation_counts": [{"category": c,"check": k,"state": s,"count": n} for (c,k,s),n in sorted(counts.items())],
            "additional_model_calls": 0, "new_api_cost_cny": 0,
            "scope": "Pure advisory annotations on actual saved detections. Original decisions and source files preserved. This does not rerun neural models, improve scores or validate real identities/mailboxes/phone ownership."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("output_must_be_new")
    result = run(args.run_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "detections_replayed": result["detections_replayed"], "model_calls": 0}))
    raise SystemExit(0 if result["status"] == "passed" else 1)
