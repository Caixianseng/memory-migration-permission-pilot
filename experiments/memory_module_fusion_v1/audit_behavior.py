"""Read-only behavioral audit of ALL archived fusion rows; no inference/API.

Only public source/question records and behavior fields are used. This script
does not open evaluation_only.json or read support/answer labels from rows. Its
local tokenizer check independently re-encodes ranking windows without model
inference, truncation or padding. It never changes thresholds or frozen code.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PINNED_REVISION = "858a1ac046a05663a35367eac852d7f76feeefdd"


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fraction(numerator, denominator):
    return numerator / denominator if denominator else None


def load_public_tokenizer():
    asset = HERE / "reranker_assets"
    manifest = json.loads((asset / "manifest.json").read_bytes())
    if manifest["model_revision"] != PINNED_REVISION:
        raise ValueError("unexpected_reranker_revision_for_tokenizer_audit")
    relative = next(name for name in manifest["file_sha256"]
                    if name.endswith("/tokenizer.json") and not name.startswith("__MACOSX/"))
    path = asset / relative
    if sha_bytes(path.read_bytes()) != manifest["file_sha256"][relative]:
        raise ValueError("tokenizer_manifest_integrity_failure")
    sys.path.insert(0, str(HERE / "reranker_vendor"))
    from tokenizers import Tokenizer
    tokenizer = Tokenizer.from_file(str(path))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    return tokenizer, {"revision": PINNED_REVISION, "tokenizer_file_sha256": sha_bytes(path.read_bytes()),
                       "model_inference_calls": 0, "local_tokenization_only": True}


def run(run_directory, public_cases=None, output=None):
    directory = Path(run_directory).resolve()
    public_cases = Path(public_cases or HERE / "data_hotpot" / "cases.public.jsonl").resolve()
    output = Path(output or directory / "behavior_audit_v1.json").resolve()
    if output.exists():
        raise ValueError("fresh_audit_output_required")
    contract = json.loads((directory / "contract.json").read_bytes())
    if sha_bytes(public_cases.read_bytes()) != contract["data"]["cases.public.jsonl"]:
        raise ValueError("public_case_manifest_hash_mismatch")
    all_cases = [json.loads(line) for line in public_cases.read_text(encoding="utf-8").splitlines()]
    cases = {case["case_id"]: case for case in all_cases if case["case_id"] in contract["case_ids"]}
    source_maps = {cid: {source["source_id"]: source for source in case["sources"]} for cid, case in cases.items()}
    tokenizer, tokenizer_metadata = load_public_tokenizer()
    token_cache, pair_cache = {}, {}
    rows, row_files = [], {}
    # Deliberately project out evaluation fields before any analysis.
    for path in sorted((directory / "rows").glob("*.json")):
        record = json.loads(path.read_bytes())
        row = {key: record[key] for key in ("case_id", "arm", "time", "allowed", "selected", "context",
                                           "context_sha256", "source_bytes", "context_bytes", "trace",
                                           "commit_gate_passed")}
        key = (row["case_id"], row["arm"], row["time"])
        if key in row_files:
            raise ValueError("duplicate_behavior_row_key")
        rows.append(row)
        row_files[key] = {"filename": path.name, "sha256": sha_bytes(path.read_bytes())}
    arms, expected_cases = tuple(contract["arms"]), set(contract["case_ids"])
    if set(cases) != expected_cases or len(rows) != len(arms) * len(cases) * 3:
        raise ValueError("incomplete_frozen_three_state_behavior_matrix")
    indexed = {(row["case_id"], row["arm"], row["time"]): row for row in rows}
    failures = []
    counts = defaultdict(Counter)
    episodes = {}
    same_episode_conflicts = []
    window_counts = Counter()
    maximum_pair_tokens = 0
    for row in rows:
        cid, arm, timepoint = row["case_id"], row["arm"], row["time"]
        key = (cid, arm, timepoint)
        sources, allowed = source_maps[cid], set(row["allowed"])
        trace, selected = row["trace"], row["selected"]
        def fail(reason, **details):
            failures.append({"case_id": cid, "arm": arm, "time": timepoint,
                             "file": row_files[key]["filename"], "reason": reason, **details})
        if not set(selected) <= allowed or not set(selected) <= sources.keys():
            fail("selected_id_not_currently_authorized_or_registered")
        if len(selected) != len(set(selected)):
            fail("duplicate_selected_source_id")
        if not row["commit_gate_passed"]:
            fail("archived_commit_gate_failed")
        if sha_bytes(row["context"].encode("utf-8")) != row["context_sha256"]:
            fail("context_digest_mismatch")
        if len(row["context"].encode("utf-8")) != row["context_bytes"]:
            fail("context_byte_count_mismatch")
        if sum(len(sources[sid]["text"].encode("utf-8")) for sid in selected) != row["source_bytes"]:
            fail("whole_source_byte_count_mismatch")
        if any(sources[sid]["text"] not in row["context"] for sid in selected):
            fail("selected_whole_original_source_missing_from_payload")
        if arm == "raw" and set(selected) != allowed:
            fail("raw_baseline_does_not_include_all_lawful_sources")
        if trace["prepared"]["context"] != row["context"]:
            fail("prepared_and_archived_context_disagree")
        counts[arm]["rows"] += 1
        counts[arm]["source_bytes"] += row["source_bytes"]
        counts[arm]["context_bytes"] += row["context_bytes"]
        counts[arm]["source_id_count"] += len(selected)
        counts[arm]["cache_reuse_rows"] += int(trace.get("cache_reuse") is not None)
        retrieval = trace.get("retrieval") or {}
        gates = retrieval.get("gate_decisions") or []
        if gates:
            counts[arm]["fresh_gate_episodes"] += 1
            final = gates[-1]
            terminal = ("accepted_k" + str(final["requested_k"]) if final["decision"] == "accept_quality_signal"
                        else "fixed_k" + str(final["requested_k"]) if final["decision"] == "fixed_budget"
                        else final["decision"])
            counts[arm]["terminal_" + terminal] += 1
            for gate in gates:
                if "requested_k" in gate:
                    counts[arm]["attempt_k" + str(gate["requested_k"])] += 1
                if gate.get("quality_or_support_guarantee") is not False:
                    fail("gate_incorrectly_claims_support_or_authorization_proof")
            # H/P ablations often repeat exactly the same ranking decision.
            # Expose both physical audit counts and unique case-state episodes.
            method = retrieval.get("threshold_config", {}).get("method", "unknown")
            episode_key = (cid, timepoint, method)
            behavior = canonical(gates)
            if episode_key in episodes and episodes[episode_key]["gates_json"] != behavior:
                same_episode_conflicts.append({"case_id": cid, "time": timepoint, "method": method})
            episodes.setdefault(episode_key, {"terminal": terminal, "gates_json": behavior})
        counts[arm]["logical_ranker_calls"] += retrieval.get("ranker_call_count", 0)
        counts[arm]["incomplete_cpu_accounting_rows"] += int(retrieval.get("ranker_cpu_accounting_complete") is False)
        for phase in retrieval.get("trace", []):
            if phase.get("phase") != "ranking":
                continue
            if phase.get("ranker_error"):
                counts[arm]["ranker_errors"] += 1
            audit = phase.get("ranker_audit")
            if not audit:
                continue
            window_counts["actual_ranker_audit_episodes"] += 1
            if audit.get("model_revision") != PINNED_REVISION:
                fail("ranker_revision_mismatch")
            pool = audit["feature_pool_source_ids"]
            if not set(pool) <= allowed or set(audit["source_scores"]) != set(pool):
                fail("ranking_feature_pool_not_authorized_or_score_ids_mismatch")
            per_source = defaultdict(list)
            for window in audit["windows"]:
                window_counts["windows_checked"] += 1
                sid, a, b = window["source_id"], window["start"], window["end"]
                if sid not in pool or sid not in allowed or not 0 <= a < b <= len(sources[sid]["text"]):
                    fail("ranking_window_not_valid_authorized_source_span", source_id=sid)
                    continue
                text = sources[sid]["text"]
                if sha_bytes(text[a:b].encode("utf-8")) != window["text_sha256"]:
                    fail("window_span_hash_mismatch", source_id=sid)
                if window["truncated"] is not False or not 0 < window["pair_tokens"] <= 512:
                    fail("ranking_window_truncated_or_over_512", source_id=sid)
                maximum_pair_tokens = max(maximum_pair_tokens, window["pair_tokens"])
                pair_key = (cid, sid, a, b)
                if pair_key not in pair_cache:
                    pair_cache[pair_key] = len(tokenizer.encode(cases[cid]["question"], text[a:b]).ids)
                if pair_cache[pair_key] != window["pair_tokens"]:
                    fail("independent_pair_token_count_mismatch", source_id=sid)
                source_key = (cid, sid)
                if source_key not in token_cache:
                    token_cache[source_key] = [(start, end) for start, end in tokenizer.encode(text, add_special_tokens=False).offsets if end > start]
                offsets = token_cache[source_key]
                start, end, total = window["source_token_start"], window["source_token_end"], window["source_total_tokens"]
                if (total != len(offsets) or not 0 <= start < end <= total
                        or (a, b) != (offsets[start][0], offsets[end - 1][1])):
                    fail("independent_source_token_offsets_mismatch", source_id=sid)
                per_source[sid].append(window)
            for sid in pool:
                window_counts["full_source_token_coverages_checked"] += 1
                sequence = sorted(per_source[sid], key=lambda item: item["source_token_start"])
                cursor, total = 0, None
                for window in sequence:
                    if window["source_token_start"] != cursor:
                        fail("source_feature_token_gap_or_overlap", source_id=sid)
                    cursor, total = window["source_token_end"], window["source_total_tokens"]
                if total is None or cursor != total:
                    fail("source_feature_token_sequence_incomplete", source_id=sid)
                if sequence and abs(max(window["score"] for window in sequence) - audit["source_scores"][sid]) > 1e-9:
                    fail("source_score_not_max_of_verified_feature_windows", source_id=sid)
    unique_gates = defaultdict(Counter)
    for (_, _, method), episode in episodes.items():
        unique_gates[method]["episodes"] += 1
        unique_gates[method][episode["terminal"]] += 1
    proof_pairs = {}
    for hierarchy in (0, 1):
        for rerank in (0, 1):
            off, on = f"h{hierarchy}p0r{rerank}", f"h{hierarchy}p1r{rerank}"
            totals, differences = Counter(), []
            for cid in expected_cases:
                times = sorted(row["time"] for row in rows if row["case_id"] == cid and row["arm"] == off)
                for timepoint in times:
                    a, b = indexed[(cid, off, timepoint)], indexed[(cid, on, timepoint)]
                    totals["paired_views"] += 1
                    for name, same in (("identical_ordered_source_ids", a["selected"] == b["selected"]),
                                       ("identical_source_id_sets", set(a["selected"]) == set(b["selected"])),
                                       ("identical_context_bytes", a["context"] == b["context"]),
                                       ("identical_source_bytes", a["source_bytes"] == b["source_bytes"])):
                        totals[name] += int(same)
                    if a["context"] != b["context"] or a["selected"] != b["selected"]:
                        differences.append({"case_id": cid, "time": timepoint})
            proof_pairs[off + "__" + on] = {**dict(totals),
                "ordered_id_equivalence_fraction": fraction(totals["identical_ordered_source_ids"], totals["paired_views"]),
                "context_equivalence_fraction": fraction(totals["identical_context_bytes"], totals["paired_views"]),
                "differences": differences}
    tradeoffs = {}
    comparisons = ("h0p0r0", "fixed_rerank", "adaptive_bm25", "neighbor", "parent_bm25", "raw", "h1p0r1", "assurance_bridge", "hierarchy_bridge")
    for full in ("h1p1r1", "fusion_bridge"):
        tradeoffs[full] = {}
        for baseline in comparisons:
            ratios, bigger, equal = [], 0, 0
            for cid in expected_cases:
                for timepoint in sorted(row["time"] for row in rows if row["case_id"] == cid and row["arm"] == full):
                    a, b = indexed[(cid, full, timepoint)], indexed[(cid, baseline, timepoint)]
                    if b["source_bytes"]:
                        ratios.append(a["source_bytes"] / b["source_bytes"])
                    bigger += a["source_bytes"] > b["source_bytes"]
                    equal += a["source_bytes"] == b["source_bytes"]
            tradeoffs[full][baseline] = {"total_source_byte_ratio": fraction(counts[full]["source_bytes"], counts[baseline]["source_bytes"]),
                "paired_median_source_byte_ratio": statistics.median(ratios) if ratios else None,
                "paired_views_with_more_bytes": bigger, "paired_views_with_same_bytes": equal,
                "paired_views": len(expected_cases) * 3,
                "quality_tokens_and_supplier_fees_not_inferred_from_bytes": True}
    duplicates = {}
    for cid, sources in source_maps.items():
        by_body = Counter(source["text"] for source in sources.values())
        duplicates[cid] = {"sources": len(sources), "identical_whole_source_text_groups": sum(value > 1 for value in by_body.values())}
    code_match = {name: {"frozen_sha256": digest,
                          "current_sha256": sha_bytes((HERE / name).read_bytes()),
                          "matches": sha_bytes((HERE / name).read_bytes()) == digest}
                  for name, digest in contract["code"].items()}
    result = {"status": "completed", "run_directory": str(directory), "rows_checked": len(rows),
              "case_clusters": len(cases), "arms": list(arms), "states_per_case_arm": 3,
              "read_evaluation_file": False, "support_answer_labels_used": False,
              "model_inference_calls": 0, "generation_api_calls": 0,
              "tokenizer_independent_audit": tokenizer_metadata,
              "archived_row_files_sha256": row_files_as_json(row_files),
              "frozen_code_read_only_verification": code_match,
              "by_arm_behavior": {arm: dict(value) for arm, value in counts.items()},
              "unique_case_state_gate_episodes": {method: dict(value) for method, value in unique_gates.items()},
              "duplicate_gate_episode_behavior_conflicts": same_episode_conflicts,
              "window_integrity": {**dict(window_counts), "maximum_actual_pair_tokens": maximum_pair_tokens,
                                   "unique_pair_tokenizations": len(pair_cache), "unique_sources_tokenized": len(token_cache)},
              "proof_factor_pairs": proof_pairs, "source_byte_tradeoffs": tradeoffs,
              "public_identical_source_opportunities": duplicates,
              "integrity_failures": failures, "all_integrity_checks_passed": not failures,
              "gate_score_is_not_support_or_authorization_proof": True,
              "observations_are_case_state_repeats_not_independent_samples": True,
              "new_thresholds_or_model_tuning": False}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
    print(json.dumps({"status": "completed", "rows": len(rows), "failures": len(failures),
                      "unique_gate_episodes": result["unique_case_state_gate_episodes"],
                      "window_integrity": result["window_integrity"], "output": str(output)}, ensure_ascii=False))
    return result


def row_files_as_json(rows):
    return [{"case_id": cid, "arm": arm, "time": timepoint, **value}
            for (cid, arm, timepoint), value in sorted(rows.items())]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=REPO / "results/memory_module_fusion_v1/hotpot-reserved-20261105-v2")
    parser.add_argument("--public-cases", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    run(args.run, args.public_cases, args.output)
