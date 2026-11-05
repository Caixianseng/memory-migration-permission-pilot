"""Four fixed stronger legal BM25 controls; offline only, no model/network calls.

Selection receives only the public question, current authorized source records,
and body-free hierarchy metadata. Each split's selections and actual safe local
deliveries are sealed before evaluation annotations are opened. Complete source
bodies are retained; neither hard byte caps nor feature-window truncation apply.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from .context_adapter import prepare_sources, deliver
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, save
from experiments.revocation_grouping_v1.retrieval_baseline import score_sources, K1, B


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ARMS = {
    "sentence_bm25_top4": {"unit": "current_authorized_full_sentence_source", "k": 4},
    "sentence_bm25_top8": {"unit": "current_authorized_full_sentence_source", "k": 8},
    "authorized_parent_bm25_top3": {"unit": "parent_join_current_authorized_children", "k": 3},
    "authorized_parent_bm25_top4": {"unit": "parent_join_current_authorized_children", "k": 4},
}
DEV_SELECTION_RULE = "eligible_complete_annotated_support_views_desc_then_total_context_bytes_asc_then_arm_name_asc"
CODE_PATHS = [Path(__file__).resolve(), HERE / "context_adapter.py",
              REPO / "experiments/revocation_grouping_v1/lifecycle_host.py",
              REPO / "experiments/revocation_grouping_v1/retrieval_baseline.py",
              REPO / "experiments/permission_context_v1/authorized_expansion.py"]


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def code_hashes():
    return {str(path.relative_to(REPO)): file_hash(path) for path in CODE_PATHS}


def select_control(question, current_sources, hierarchy, arm):
    """Return full original IDs and score audit without access to any labels."""
    if arm not in ARMS or not isinstance(question, str) or not question.strip():
        raise ValueError("fixed_arm_and_public_question_required")
    records = {}
    for source in current_sources:
        sid = source["source_id"]
        if (sid in records or not isinstance(source.get("text"), str)
                or source.get("allow", True) is not True or source.get("allowed", True) is not True):
            raise ValueError("unique_current_authorized_full_sources_required")
        records[sid] = source
    definition = ARMS[arm]
    if definition["unit"] == "current_authorized_full_sentence_source":
        ranked = score_sources(list(records.values()), [question])
        selected = [row["source_id"] for row in ranked[:definition["k"]]]
        audit = {"ranked_units": ranked, "selected_unit_ids": selected}
    else:
        groups = {}
        for sid, source in records.items():
            metadata = hierarchy[sid]
            parent = metadata["parent_id"]
            groups.setdefault(parent, []).append(source)
        parent_records = []
        for parent, children in sorted(groups.items()):
            children.sort(key=lambda source: (hierarchy[source["source_id"]]["position"], source["source_id"]))
            # Repeated titles are retained, matching the already registered
            # parent_bm25 control's concatenation of whole title+sentence units.
            parent_records.append({"source_id": parent,
                                   "text": "\n\n".join(source["text"] for source in children)})
        ranked = score_sources(parent_records, [question])
        selected_parents = [row["source_id"] for row in ranked[:definition["k"]]]
        selected = [source["source_id"] for parent in selected_parents for source in groups[parent]]
        parent_by_id = {record["source_id"]: record for record in parent_records}
        audit = {"ranked_units": [{**row,
                    "current_child_ids": [source["source_id"] for source in groups[row["source_id"]]],
                    "ranking_body_sha256": sha(parent_by_id[row["source_id"]]["text"]),
                    "ranking_body_bytes": len(parent_by_id[row["source_id"]]["text"].encode("utf-8"))}
                  for row in ranked], "selected_unit_ids": selected_parents}
    if len(set(selected)) != len(selected) or set(selected) - records.keys():
        raise AssertionError("selection_not_unique_current_full_source_ids")
    return selected, {"definition": definition, "k1": K1, "b": B,
                      "ranker_call_count": 0, "byte_cap": None,
                      "tie_break": "source_id_ascending", **audit}


def run_split(split, cases, schedules, evaluation_path, output, frozen):
    output.mkdir(parents=True, exist_ok=False)
    save(output / "contract.json", {"split": split, "case_ids": [case["case_id"] for case in cases],
        "arms": ARMS, "k1": K1, "b": B, "code": frozen, "model_calls": 0,
        "byte_budget": "all_current_authorized_source_bytes_no_hard_cap",
        "raw_feature_window_limit": None, "selector_evaluation_labels": False,
        "parent_policy": "rank_only_join_of_current_authorized_children_then_return_all_their_current_full_sources",
        "evaluation": "annotation coverage only; support annotations are not exhaustive or an answerability oracle"})
    rows = []
    started = time.perf_counter()
    for case_index, case in enumerate(cases):
        for arm in ARMS:
            host = LifecycleHost(case["sources"], output / "hosts" / case["case_id"] / arm)
            for event in schedules[case["case_id"]]:
                if code_hashes() != frozen:
                    raise ValueError("frozen_code_changed_during_run")
                host.set_permissions(event["allowed"])
                began = time.perf_counter()
                current = host.allowed_sources()
                current_ids = {source["source_id"] for source in current}
                if current_ids != set(event["allowed"]):
                    raise AssertionError("host_current_view_not_exact_permission_view")
                epoch = host.revision
                selected, trace = select_control(case["question"], current, case["hierarchy"], arm)
                ranking_done = time.perf_counter()
                prepared = prepare_sources(host, selected, current_sources=current,
                    strategy="child_only", expected_epoch=epoch, max_source_bytes=None)
                if set(prepared.source_ids) != set(selected) or set(prepared.source_ids) - current_ids:
                    raise AssertionError("adapter_changed_or_forbidden_selection")
                live = {source["source_id"]: source for source in current}
                for span in prepared.span_witnesses:
                    if (span.start != 0 or span.end != len(live[span.source_id]["text"])
                            or span.excerpt != live[span.source_id]["text"]
                            or span.source_sha256 != sha(live[span.source_id]["text"])):
                        raise AssertionError("selected_original_was_truncated_or_changed")
                messages = [{"role": "system", "content": "Use only the supplied memory."},
                    {"role": "user", "content": json.dumps({"memory": prepared.context,
                        "questions": [{"question_id": case["case_id"], "question": case["question"]}]})}]
                calls = []
                def local_commit():
                    calls.append(1)
                    return {"output": "{}", "receipt": {"instrument_only": True, "physical_request_count": 0}}
                deliver(prepared, host, messages, local_commit)
                if len(calls) != 1:
                    raise AssertionError("safe_gate_did_not_commit_exactly_once")
                trace.update(ranking_and_authorized_view_ms=(ranking_done - began) * 1000,
                             total_prepare_and_local_gate_ms=(time.perf_counter() - began) * 1000)
                row = {"case_id": case["case_id"], "cluster_id": case["cluster_id"],
                    "split": split, "arm": arm, "time": event["time"], "question": case["question"],
                    "allowed": list(event["allowed"]), "selected": list(prepared.source_ids),
                    "selected_sources": [{"source_id": sid, "text": live[sid]["text"],
                        "text_sha256": sha(live[sid]["text"]), "version": live[sid]["version"],
                        "permission_version": live[sid]["permission_version"]} for sid in prepared.source_ids],
                    "context": prepared.context, "context_sha256": prepared.context_sha256,
                    "source_bytes": prepared.source_bytes, "context_bytes": len(prepared.context.encode("utf-8")),
                    "current_total_source_bytes": sum(len(source["text"].encode("utf-8")) for source in current),
                    "no_hard_byte_cap": True, "full_selected_sources_retained": True,
                    "source_witnesses": [asdict(witness) for witness in prepared.witnesses],
                    "prepared_epoch": prepared.prepared_epoch, "forbidden_source_ids": [],
                    "trace": trace, "model_calls": 0, "commit_gate_passed": True}
                save(output / "selection_rows" / f"{len(rows):05d}.json", row)
                rows.append(row)
        print(json.dumps({"split": split, "completed_cases": case_index + 1,
                          "cases": len(cases), "sealed_selection_rows": len(rows)}), flush=True)
    # Ranking and local dispatch for the entire split are already completed.
    # Only now open labels, which are never passed into select_control().
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    for index, row in enumerate(rows):
        required = set(evaluation[row["case_id"]]["support_ids"])
        visible, allowed = set(row["selected"]), set(row["allowed"])
        row.update(all_annotated_support_currently_allowed=required <= allowed,
                   complete_annotated_support_retrieved=required <= visible,
                   original_annotated_support_recall=len(required & visible) / len(required) if required else None,
                   current_annotated_support_recall=len(required & allowed & visible) / len(required & allowed)
                        if required & allowed else None,
                   human_new_permission_semantic_gold=None)
        save(output / "rows" / f"{index:05d}.json", row)
    aggregate = {}
    for arm in ARMS:
        subset = [row for row in rows if row["arm"] == arm]
        eligible = [row for row in subset if row["all_annotated_support_currently_allowed"]]
        aggregate[arm] = {"observations": len(subset), "eligible_annotated_support_views": len(eligible),
            "complete_support_views": sum(row["complete_annotated_support_retrieved"] for row in eligible),
            "context_bytes": sum(row["context_bytes"] for row in subset),
            "source_bytes": sum(row["source_bytes"] for row in subset),
            "mean_selected_source_count": sum(len(row["selected"]) for row in subset) / len(subset),
            "prepare_and_gate_ms": sum(row["trace"]["total_prepare_and_local_gate_ms"] for row in subset),
            "forbidden_payloads": sum(bool(row["forbidden_source_ids"]) for row in subset),
            "model_calls": 0}
    ranking = sorted(ARMS, key=lambda arm: (-aggregate[arm]["complete_support_views"],
                                           aggregate[arm]["context_bytes"], arm))
    summary = {"status": "completed", "split": split, "cases": len(cases), "views_per_case": 3,
        "rows": len(rows), "aggregate": aggregate, "elapsed_seconds": time.perf_counter() - started,
        "ranking_rule": DEV_SELECTION_RULE, "fixed_rule_ranked_arms": ranking,
        "model_calls": 0, "unsafe_payloads_sent": 0,
        "independent_units": "original Hotpot question; permission views are repeated observations",
        "measurement": "current-authorization and nonexhaustive annotated-support coverage; not semantic QA accuracy"}
    save(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    data = HERE / "data_hotpot"
    cases = [json.loads(line) for line in (data / "cases.public.jsonl").read_text(encoding="utf-8").splitlines()]
    schedules = json.loads((data / "schedules.json").read_text(encoding="utf-8"))
    frozen = code_hashes()
    input_hashes = {name: file_hash(data / name) for name in
                    ("cases.public.jsonl", "schedules.json", "evaluation_only.json")}
    save(output / "contract.json", {"schema": "strong-simple-bm25-controls-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(), "arms": ARMS, "code": frozen,
        "input_hashes": input_hashes, "split_order": ["development", "reserved"],
        "dev_selection_rule": DEV_SELECTION_RULE, "followup_max_arms": 2,
        "model_calls": 0, "network_calls": 0, "byte_cap": None,
        "labels_read_only_after_all_split_selections": True})
    # Snapshot only this new runner; the imported frozen files are hash-bound.
    (output / "strong_controls_snapshot.py").write_bytes(Path(__file__).read_bytes())
    summaries = {}
    for split, expected_cases in (("development", 8), ("reserved", 16)):
        selected_cases = [case for case in cases if case["split"] == split]
        if len(selected_cases) != expected_cases:
            raise ValueError("fixed_split_case_count_changed")
        summary = run_split(split, selected_cases, schedules, data / "evaluation_only.json", output / split, frozen)
        summaries[split] = summary
        if split == "development":
            # Written before any reserved selection or reserved evaluation.
            save(output / "dev_based_followup_lock.json", {"selection_split": "development",
                "selection_rule": DEV_SELECTION_RULE, "selected_arms": summary["fixed_rule_ranked_arms"][:2],
                "fixed_arm_definitions": ARMS, "reserved_results_used": False,
                "first_four_development_case_ids": [case["case_id"] for case in selected_cases[:4]],
                "purpose": "At most two new simple controls for the parent's first-four real-model followup; no calls here"})
    if input_hashes != {name: file_hash(data / name) for name in input_hashes} or frozen != code_hashes():
        raise ValueError("input_or_frozen_code_changed")
    save(output / "summary.json", {"status": "completed", "schema": "strong-simple-bm25-controls-v1",
        "model_calls": 0, "network_calls": 0, "total_cases": 24, "total_rows": 288,
        "split_summaries": summaries, "followup_lock": "dev_based_followup_lock.json"})


if __name__ == "__main__":
    main()
