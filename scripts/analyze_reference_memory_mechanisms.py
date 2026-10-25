"""Read-only, zero-model selection/serialization/cost audit of a saved run.

Selection comparison uses runtime source positions, never evaluation labels.
Existing row scores are described, not recomputed or changed. This is exposed
development analysis, not an independent acceptance or a causal nonce test.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.analyze_boundary_transfer_mechanisms import digest, normalized_payload, normalized_request


VERSION = "reference_memory_mechanism_analysis_v1"


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records_projection(records):
    # Ephemeral IDs, MACs and label timestamps are not memory content.
    return [{"text": r["text"], "source": r["source"], "source_start": r["source_start"],
             "source_end": r["source_end"],
             "readers": r["access"]["readers"], "allowed_agent_ids": r["access"]["allowed_agent_ids"]}
            for r in records]


def run(source, output):
    source, output = Path(source), Path(output)
    names = ("plan.json", "runtime.json", "evaluation.json", "rows.json", "builds.json", "pools.json",
             "record_store.json", "report.json", "request_transport.jsonl", "transport_audit.json", "network_audit.json")
    before = {name: sha(source / name) for name in names}
    # Evaluation bytes are hashed for provenance but never parsed by this audit.
    runtime, rows, builds, stores, pools, report = (read(source / name) for name in
        ("runtime.json", "rows.json", "builds.json", "record_store.json", "pools.json", "report.json"))
    events = [json.loads(line) for line in (source / "request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    requests = {e["index"]: e for e in events if e["phase"] == "request"}
    responses = {e["index"]: e for e in events if e["phase"] == "response"}
    assert len(requests) == len(responses) and set(requests) == set(responses)
    assert len(requests) == report["generation_calls_observed"]
    assert len(rows) == 200 and len(builds) == 40 and len(runtime) == 8
    row_by_key = {(r["story_id"], r["task_id"], r["arm"]): r for r in rows}
    assert len(row_by_key) == len(rows)
    build_by_key = {(b["story_id"], b["builder"]): b for b in builds}
    store_by_key = {(s["story_id"], s["builder"]): s["records"] for s in stores}
    pool_by_story = {p["story_id"]: p["pool"] for p in pools}
    costs = defaultdict(lambda: {"calls": 0, "prompt_tokens": 0, "output_tokens": 0,
                                 "request_json_utf8_bytes": 0, "response_content_utf8_bytes": 0})
    per_selector, answer_requests = [], {}
    for index, req in requests.items():
        res, body = responses[index], req["request"]
        assert digest(body) == req["request_sha256"] == res["request_sha256"]
        assert digest(res["response"]) == res["response_sha256"]
        assert res["actual_usage_within_budget"] is True
        assert all(req.get(k) == res.get(k) for k in ("stage", "arm", "story_id", "task_id"))
        wire = json.dumps(body, ensure_ascii=False).encode("utf-8")
        assert len(wire) == req["wire_json_utf8_bytes"]
        assert hashlib.sha256(wire).hexdigest() == req["wire_json_utf8_sha256"]
        response = res["response"]
        metric = costs[(req["stage"], req["arm"])]
        values = {"calls": 1, "prompt_tokens": response["prompt_eval_count"],
            "output_tokens": response["eval_count"], "request_json_utf8_bytes": len(wire),
            "response_content_utf8_bytes": len(response["message"]["content"].encode("utf-8"))}
        for key, value in values.items():
            assert type(value) is int and value >= 0
            metric[key] += value
        if req["stage"] == "answer":
            key = (req["story_id"], req["task_id"], req["arm"])
            assert key not in answer_requests
            answer_requests[key] = body
            row = row_by_key[key]
            assert json.loads(body["messages"][1]["content"]) == row["outbound"]
            assert digest(row["outbound"]) == row["actual_payload_sha256"]
            assert response["message"]["content"].strip() == row["model_answer"]
        elif req["arm"] in {"reference_id", "reference_quote"}:
            per_selector.append({"story_id": req["story_id"], "arm": req["arm"],
                                 "transport_index": index, **values})
    assert sum(v["calls"] for (stage, _), v in costs.items() if stage == "build") == report["builder_generations"]
    assert sum(v["calls"] for (stage, _), v in costs.items() if stage == "answer") == report["answer_generations"]

    selection = []
    for story in runtime:
        sid, text = story["story_id"], story["source"]["text"]
        ident, quote, all_build = (build_by_key[(sid, arm)] for arm in
                                  ("reference_id", "reference_quote", "retain_all"))
        chosen, retained = set(ident["selected_fids"]), set(all_build["selected_fids"])
        assert all(text[f["source_start"]:f["source_end"]] == f["text"]
                   for build in (ident, quote, all_build) for f in build["facts"])
        candidates = {c["fid"]: c for c in pool_by_story[sid]["candidates"]}
        dropped = [{"fid": fid, "start": candidates[fid]["start"], "end": candidates[fid]["end"],
                    "source_text": text[candidates[fid]["start"]:candidates[fid]["end"]]}
                   for fid in sorted(retained - chosen)]
        selection.append({"story_id": sid, "id_fids": ident["selected_fids"], "quote_fids": quote["selected_fids"],
            "same_selection": ident["selected_fids"] == quote["selected_fids"],
            "same_facts_and_labels": ident["facts"] == quote["facts"],
            "same_record_content_source_and_acl": records_projection(store_by_key[(sid, "reference_id")]) ==
                records_projection(store_by_key[(sid, "reference_quote")]),
            "retain_all_fids": all_build["selected_fids"], "dropped_source_candidates": dropped})
    pairs = []
    for story in runtime:
        for task in story["tasks"]:
            sid, tid = story["story_id"], task["task_id"]
            a, b = (row_by_key[(sid, tid, arm)] for arm in ("reference_id", "reference_quote"))
            both = a.get("outbound") is not None and b.get("outbound") is not None
            pair = {"story_id": sid, "task_id": tid, "actor_id": task["actor_id"], "both_outbound": both,
                "normalized_outbound_equal": None, "normalized_full_request_equal": None,
                "masking_scores_equal": a["masking"] == b["masking"],
                "primary_id_correct": a["score"]["correct"], "primary_quote_correct": b["score"]["correct"],
                "secondary_id_correct": a["score"].get("secondary_serialization_correct"),
                "secondary_quote_correct": b["score"].get("secondary_serialization_correct")}
            if both:
                pa, pb = normalized_payload(a["outbound"]), normalized_payload(b["outbound"])
                pair.update(normalized_outbound_equal=pa == pb,
                    normalized_full_request_equal=normalized_request(answer_requests[(sid, tid, "reference_id")]) ==
                        normalized_request(answer_requests[(sid, tid, "reference_quote")]),
                    normalized_payload_sha256=digest(pa),
                    id_answer=a["model_answer"], quote_answer=b["model_answer"],
                    id_final_answer=a["final_answer"], quote_final_answer=b["final_answer"],
                    id_serialization=a.get("secondary_serialization"), quote_serialization=b.get("secondary_serialization"))
            pairs.append(pair)
    selectors = {arm: costs[("build", arm)] for arm in ("reference_id", "reference_quote")}
    reduction = {key: {"id": selectors["reference_id"][key], "quote": selectors["reference_quote"][key],
                  "id_absolute_saving": selectors["reference_quote"][key] - selectors["reference_id"][key],
                  "id_relative_saving": 1 - selectors["reference_id"][key] / selectors["reference_quote"][key]
                      if selectors["reference_quote"][key] else None}
                 for key in selectors["reference_id"]}
    assert before == {name: sha(source / name) for name in names}
    result = {"version": VERSION, "input_sha256": before, "analysis_script_sha256": sha(Path(__file__)),
        "normalizer_source_sha256": sha(ROOT / "scripts/analyze_boundary_transfer_mechanisms.py"),
        "evaluation_labels_parsed": False, "source_files_unchanged": True,
        "matched_story_selections": len(selection), "same_selected_fids": sum(s["same_selection"] for s in selection),
        "same_facts_and_labels": sum(s["same_facts_and_labels"] for s in selection),
        "same_records_content_source_and_acl": sum(s["same_record_content_source_and_acl"] for s in selection),
        "registered_task_pairs": len(pairs), "active_model_pairs": sum(p["both_outbound"] for p in pairs),
        "normalized_outbound_equal": sum(p["normalized_outbound_equal"] is True for p in pairs),
        "normalized_full_request_equal": sum(p["normalized_full_request_equal"] is True for p in pairs),
        "same_masking_scores": sum(p["masking_scores_equal"] for p in pairs),
        "primary_score_differences": [p for p in pairs if p["primary_id_correct"] != p["primary_quote_correct"]],
        "secondary_score_differences": [p for p in pairs if p["secondary_id_correct"] != p["secondary_quote_correct"]],
        "shared_secondary_failures": [p for p in pairs if p["actor_id"] == "owner" and
            not p["secondary_id_correct"] and not p["secondary_quote_correct"]],
        "selector_cost_comparison": reduction,
        "ledger_totals_by_stage_arm": [{"stage": stage, "arm": arm, **v} for (stage, arm), v in sorted(costs.items())],
        "physical_saved_requests": len(requests), "new_model_calls": 0,
        "limits": ["Request JSON bytes exclude HTTP headers; response bytes count assistant content only.",
            "Reported prompt/eval tokens are the saved local runtime usage, not an API bill or tokenizer reconstruction.",
            "Identical nonce-normalized inputs establish no selection/content advantage here; this is not a fixed-nonce causal replay.",
            "Secondary serialization is an unchanged-output diagnostic and does not replace frozen primary scores.",
            "Sources and row outcomes are exposed development evidence, not independent acceptance, safety completeness or algorithm novelty."]}
    output.mkdir(parents=True, exist_ok=False)
    for name, value in (("analysis.json", result), ("selection_comparison.json", selection),
                        ("answer_pairs.json", pairs), ("selector_ledger.json", per_selector)):
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.run, args.output)
    print(json.dumps({k: result[k] for k in ("same_selected_fids", "active_model_pairs", "normalized_outbound_equal",
        "normalized_full_request_equal", "selector_cost_comparison", "source_files_unchanged")}, ensure_ascii=False))
