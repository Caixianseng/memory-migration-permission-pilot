"""Zero-model oracle coverage of optional field and amount candidate additions.

All old candidates remain. This measures availability, not actual detection or
privacy. Exposed source material is development/regression only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.amount_candidates import complete_amount_findings
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.structured_candidates import propose_field_findings


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(source):
    source = Path(source)
    files = {name: source/name for name in ("runtime.json", "rows.json", "evaluation.json")}
    before = {name: sha(path) for name, path in files.items()}
    runtime = json.loads(files["runtime.json"].read_text(encoding="utf-8"))
    old = json.loads(files["rows.json"].read_text(encoding="utf-8"))
    index = {(row["case_id"], row["arm"]): row for row in old}
    if len(index) != len(old):
        raise ValueError("duplicate_saved_condition")
    pools, diagnostics = {}, []
    for case in runtime:
        findings = index[(case["case_id"], "gliner_combined")]["detection"]["findings"]
        fields = propose_field_findings(case["payload"], case["policy"])
        amounts = complete_amount_findings(case["payload"], case["policy"], findings)
        if fields["status"] != "candidates_only" or amounts["status"] != "candidates_only":
            pool = None
        else:
            pool = propose_candidates(case["payload"], case["policy"], [*findings, *fields["findings"], *amounts["findings"]])
        pools[case["case_id"]] = pool
        diagnostics.append({"case_id": case["case_id"], "field_status": fields["status"], "field_error": fields["error"],
                            "amount_status": amounts["status"], "amount_error": amounts["error"],
                            "field_candidate_count": len(fields["findings"]), "amount_additions": len(amounts["findings"]),
                            "field_key_count": len(fields["field_key_spans"]),
                            "pool_status": pool["status"] if pool else "needs_review", "pool_sha256": pool["pool_sha256"] if pool else None,
                            "pool_count": len(pool["candidates"]) if pool else 0})
    # Runtime-only proposal generation is finished before parsing labels.
    gold = json.loads(files["evaluation.json"].read_text(encoding="utf-8"))
    total = covered = 0
    missing = []
    for case in runtime:
        cid = case["case_id"]
        pool = pools[cid]
        available = set()
        if pool and pool["status"] == "candidates_only":
            available = {(item["source_id"], item["start"], item["end"], category)
                         for item in pool["candidates"] for category in item["allowed_categories"]}
        expected = {(item["source_id"], item["start"], item["end"], item["category"]) for item in gold[cid]["findings"]}
        total += len(expected)
        covered += len(expected & available)
        missing.extend({"case_id": cid, "source_id": sid, "start": start, "end": end, "category": category}
                       for sid, start, end, category in sorted(expected-available))
    if before != {name: sha(path) for name, path in files.items()}:
        raise ValueError("original_results_changed")
    components = [Path(__file__), *[Path("memory_migration_study")/name for name in
                  ("candidate_proposals.py", "structured_candidates.py", "amount_candidates.py")]]
    return {"kind": "structured_candidate_oracle_ceiling_only", "split": source.name,
            "materials": len(runtime), "gold_spans": total, "complete_gold_spans_in_pool": covered,
            "oracle_recall_ceiling": covered/total if total else None,
            "proposed_candidates": sum(item["pool_count"] for item in diagnostics),
            "needs_review": sum(item["pool_status"] != "candidates_only" for item in diagnostics),
            "field_additions": sum(item["field_candidate_count"] for item in diagnostics),
            "amount_additions": sum(item["amount_additions"] for item in diagnostics),
            "diagnostics": diagnostics, "missing_reference_spans": missing,
            "source_sha256": before, "component_sha256": {str(path): sha(path) for path in components},
            "original_results_unchanged": True, "additional_model_calls": 0, "additional_api_cost_cny": 0,
            "scope": "Original candidates are retained including known structural conflicts. Availability is an oracle ceiling, not achieved precision/recall, boundary reconciliation, a full masking result, or new independent acceptance."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("output_must_be_new")
    report = analyze(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("materials", "gold_spans", "complete_gold_spans_in_pool", "oracle_recall_ceiling", "proposed_candidates", "needs_review", "field_additions", "amount_additions", "additional_model_calls")}, ensure_ascii=False))
