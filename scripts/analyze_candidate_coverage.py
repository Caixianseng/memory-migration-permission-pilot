"""Post-hoc candidate coverage ceiling, never a deployable prediction score.

Proposals come from saved detector outputs and optional generic paired values.
Gold is used afterwards to
measure which complete spans any downstream subset classifier could recover.
No model calls, sensitivity decisions or original-result mutations occur.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

POOLS = {
    "rules": ("rules",),
    "qwen": ("qwen_agent",),
    "gliner_and_rules": ("gliner_combined",),
    "preserve_all_three_detector_spans": ("rules", "qwen_agent", "gliner_combined"),
    "current_final_union": ("union_combined",),
}


def key(f):
    return (f["source_id"], f["start"], f["end"], f["category"])


def _quoted_pools(runtime, index):
    """Freeze runtime-only pools before the evaluator loads any gold labels."""
    from memory_migration_study.candidate_proposals import propose_candidates

    arms_by_pool = {
        "quoted_values_only": (),
        "gliner_and_rules_plus_quoted_values": ("gliner_combined",),
        "all_three_raw_detectors_plus_quoted_values": POOLS["preserve_all_three_detector_spans"],
    }
    pools = {name: {} for name in arms_by_pool}
    for name, arms in arms_by_pool.items():
        for case in runtime:
            findings = [finding for arm in arms for finding in index[(case["case_id"], arm)]["detection"]["findings"]]
            pools[name][case["case_id"]] = propose_candidates(case["payload"], case["policy"], findings)
    return pools


def analyze(root, *, with_quoted_proposals=False):
    root = Path(root)
    paths = [root/name for name in ("runtime.json", "evaluation.json", "rows.json")]
    original = {p.name: p.read_bytes() for p in paths}
    runtime = json.loads(original["runtime.json"])
    rows = json.loads(original["rows.json"])
    sources = {s["case_id"]: {"__query__":s["payload"]["query"], **{m["source_id"]:m["text"] for m in s["payload"]["memories"]}} for s in runtime}
    index = {(r["case_id"],r["arm"]):r for r in rows}
    if len(index) != len(rows):
        raise ValueError("duplicate_condition")
    quoted_pools = _quoted_pools(runtime, index) if with_quoted_proposals else {}
    evaluation = json.loads(original["evaluation.json"])
    summaries, missing = {}, {}
    for pool, arms in POOLS.items():
        proposed = covered = accepted_covered = total_gold = 0
        per_category = Counter()
        missed = []
        for case in runtime:
            cid = case["case_id"]
            candidates, accepted = set(), set()
            for arm in arms:
                row = index[(cid,arm)]
                spans = set(map(key,row["detection"]["findings"]))
                for sid,a,b,category in spans:
                    if type(a) is not int or type(b) is not int or sid not in sources[cid] or not 0 <= a < b <= len(sources[cid][sid]):
                        raise ValueError("unverified_candidate_offset")
                candidates |= spans
                if row["detection"]["status"] == "ok":
                    accepted |= spans
            reference = set(map(key,evaluation[cid]["findings"]))
            proposed += len(candidates)
            total_gold += len(reference)
            covered += len(reference & candidates)
            accepted_covered += len(reference & accepted)
            for span in reference:
                per_category[(span[-1],"gold")] += 1
                per_category[(span[-1],"covered")] += span in candidates
            for sid,a,b,category in sorted(reference-candidates):
                missed.append({"case_id":cid,"source_id":sid,"start":a,"end":b,"category":category})
        summaries[pool] = {"materials":len(runtime), "proposed_spans":proposed,"gold_spans":total_gold,
                           "complete_gold_spans_in_pool":covered,
                           "subset_classifier_recall_ceiling": covered/total_gold if total_gold else None,
                           "accepted_sources_only_ceiling":accepted_covered/total_gold if total_gold else None,
                           "per_category":{c:{"gold":per_category[(c,"gold")],"covered":per_category[(c,"covered")]} for c,_ in sorted(per_category) if _=="gold"}}
        missing[pool] = missed
    proposal_receipts = {}
    for name, pools in quoted_pools.items():
        covered = total_gold = proposed = 0
        statuses, errors, per_category = Counter(), Counter(), Counter()
        missed, receipts = [], {}
        for case in runtime:
            cid = case["case_id"]
            pool = pools[cid]
            statuses[pool["status"]] += 1
            if pool["error"]:
                errors[pool["error"]] += 1
            candidates = set()
            for item in pool["candidates"]:
                # This is an oracle ceiling: a future classifier may choose any
                # policy-protected category, not merely the old proposed label.
                candidates.update((item["source_id"], item["start"], item["end"], category)
                                  for category in item["allowed_categories"])
            reference = set(map(key, evaluation[cid]["findings"]))
            total_gold += len(reference)
            covered += len(reference & candidates)
            proposed += len(pool["candidates"])
            for span in reference:
                per_category[(span[-1], "gold")] += 1
                per_category[(span[-1], "covered")] += span in candidates
            for sid, start, end, category in sorted(reference-candidates):
                missed.append({"case_id": cid, "source_id": sid, "start": start, "end": end, "category": category})
            receipts[cid] = {"pool_sha256": pool["pool_sha256"], "status": pool["status"],
                             "complete": pool["complete"], "candidate_count": len(pool["candidates"])}
        summaries[name] = {"materials": len(runtime), "proposed_candidates": proposed, "gold_spans": total_gold,
                           "complete_gold_spans_in_pool": covered,
                           "subset_classifier_recall_ceiling": covered/total_gold if total_gold else None,
                           "statuses": dict(statuses), "errors": dict(errors),
                           "per_category": {category: {"gold": per_category[(category, "gold")],
                                                        "covered": per_category[(category, "covered")]}
                                            for category, kind in sorted(per_category) if kind == "gold"}}
        missing[name] = missed
        proposal_receipts[name] = receipts
    if any(p.read_bytes() != original[p.name] for p in paths):
        raise ValueError("original_results_changed")
    result = {"kind":"posthoc_candidate_recall_ceiling_only","split":root.name,"pools":summaries,"uncovered_reference_spans":missing,
            "source_sha256":{name:hashlib.sha256(raw).hexdigest() for name,raw in original.items()},
            "additional_model_calls":0,"original_results_unchanged":True,
            "scope":"Exposed old sets are development/regression only. This uses gold only for diagnosis, not inference. A subset classifier cannot exceed this span-pool ceiling; a high ceiling does not mean a real classifier attains it. No achieved precision/recall or new heldout acceptance is claimed."}
    if with_quoted_proposals:
        result.update(proposal_receipts=proposal_receipts, proposal_gold_access=False,
                      proposal_component_sha256=hashlib.sha256((Path(__file__).resolve().parents[1]/"memory_migration_study/candidate_proposals.py").read_bytes()).hexdigest(),
                      oracle_category_scope="Quoted-pool ceilings allow reclassification to any currently protected category; no actual sensitivity or precision decision is scored.")
    return result


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--with-quoted-proposals", action="store_true")
    args=parser.parse_args()
    if args.output.exists():
        raise ValueError("output_must_be_new")
    result=analyze(args.run, with_quoted_proposals=args.with_quoted_proposals)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({"split":result["split"],"coverage_only":{k:v["subset_classifier_recall_ceiling"] for k,v in result["pools"].items()},"model_calls":0}))
