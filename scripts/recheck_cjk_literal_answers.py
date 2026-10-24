"""Replay only saved literal-answer recovery failures; no model inference."""
import argparse
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.privacy import QUERY_SOURCE, detect_sensitive, prepare_private_payload, restore_answer


def recheck(root):
    root = Path(root)
    read = lambda name: json.loads((root/name).read_text(encoding="utf-8"))
    stories = {s["story_id"]: s for s in read("runtime.json")}
    gold = read("evaluation.json")
    checked = []
    for row in read("rows.json"):
        if (row["arm"] != "gliner_cjk" or row["actor_id"] != "owner"
                or row.get("restoration_error") != "literal_has_no_memory_evidence"):
            continue
        story = stories[row["story_id"]]
        query = next(t["query"] for t in story["tasks"] if t["task_id"] == row["task_id"])
        payload = {"query": query, "memories": [{"source_id": "record", "text": story["source"]["text"]}]}
        def observed(*, text, source_id, policy, rule_findings):
            findings = []
            for f in row["detection"]["findings"]:
                is_query = f["source_id"] == QUERY_SOURCE
                if is_query != (source_id == QUERY_SOURCE):
                    continue
                findings.append({"quote": text[f["start"]:f["end"]], "start": f["start"],
                                 "end": f["end"], "category": f["category"]})
            return {"status": "ok", "findings": findings, "local_calls": 0, "elapsed_seconds": 0}
        detection = detect_sensitive(payload, story["policy"], mode="agent", agent=observed)
        request = secrets.token_hex(16)
        authorizer = lambda sid, actor, version: sid == "record" and actor == "owner" and version == story["policy"]["version"]
        prepared = prepare_private_payload(payload, detection, actor_id="owner", request_id=request,
                                           policy_version=story["policy"]["version"], authorizer=authorizer)
        result = restore_answer(row["model_answer"], prepared.get("mapping"), actor_id="owner", request_id=request,
                                policy_version=story["policy"]["version"], authorizer=authorizer,
                                sensitivity_policy=story["policy"])
        expected = gold[row["story_id"]]["answers"][row["task_id"]]
        checked.append({"story_id": row["story_id"], "task_id": row["task_id"],
                        "previous_error": row["restoration_error"], "current_status": result["status"],
                        "current_error": result.get("error"), "saved_answer_correct": row["model_answer"] == expected,
                        "restored_correct": result.get("answer") == expected})
        prepared["mapping"] = None
    return {"scope": "Saved literal answers and verified original findings, fresh local mapping and controlled original-owner authorization; not a rerun of the model or native backend. Historical report unchanged.",
            "model_calls": 0, "checked": checked, "all_restored": bool(checked) and all(r["restored_correct"] for r in checked)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = recheck(args.run)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"checked": len(result["checked"]), "all_restored": result["all_restored"], "model_calls": 0}))
    raise SystemExit(0 if result["all_restored"] else 1)
