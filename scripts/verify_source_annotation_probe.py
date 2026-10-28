"""Read-only stdlib audit of the single frozen source-annotation development run.

Does not import the producer, contact a model, deserialize a restoration map,
or change the frozen experiment. Writes only a new requested audit directory.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PLAN_SHA = "e93abc7b87e5127214c8a993dafdda678a5d0b29707e19e10ce3d9a6035a933e"
ARMS = ("receiver_only", "source_label_transfer", "receiver_union")
PROFILE = "strict_customer_relation"
TOKEN = re.compile(r"\[PVT_[A-F0-9]{24}_[A-Z]+_\d+\]")


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text_sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_sha(value):
    return text_sha(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def spans(values, text, *, reference=False):
    require(isinstance(values, list), "span_list")
    result = set()
    for value in values:
        a, b = value.get("start"), value.get("end")
        require(type(a) is int and type(b) is int and 0 <= a < b <= len(text), "span_range")
        require(value.get("category") == "CUSTOMER", "span_category")
        require(value.get("text" if reference else "quote", text[a:b]) == text[a:b], "span_text")
        result.add((a, b, "CUSTOMER"))
    return result


def semantic_unknown(response):
    return (isinstance(response, dict) and response.get("status") == "needs_review"
            and "semantic_uncertainty" in response.get("errors", []))


def source_occurrences(decoded, text):
    require(isinstance(decoded, dict) and set(decoded) == {"status", "findings"}, "raw_schema")
    require(decoded["status"] in {"ok", "needs_review"} and isinstance(decoded["findings"], list), "raw_status")
    result = set()
    for item in decoded["findings"]:
        require(set(item) == {"quote", "occurrence", "category"}, "raw_finding_schema")
        quote, occurrence = item["quote"], item["occurrence"]
        require(isinstance(quote, str) and quote and type(occurrence) is int and occurrence >= 1, "raw_occurrence")
        require(item["category"] == "CUSTOMER", "raw_category")
        # This run must use literal spans; a future wrapper-repair run requires
        # a separately specified audit rather than silently normalizing text.
        starts = [m.start() for m in re.finditer("(?=" + re.escape(quote) + ")", text)]
        require(len(starts) >= occurrence, "raw_quote_absent")
        a = starts[occurrence - 1]
        result.add((a, a + len(quote), "CUSTOMER"))
    return result


def footprint(text, preparation):
    intervals = preparation["actual_mask_intervals"]
    if preparation["status"] != "ok":
        require(preparation["payload"] is None and intervals == [], "blocked_payload")
        return set()
    masked = preparation["payload"]["memories"][0]["text"]
    tokens = list(TOKEN.finditer(masked))
    require(len(tokens) == len(intervals), "footprint_token_count")
    old_cursor = new_cursor = 0
    token_values, covered = {}, set()
    for match, interval in zip(tokens, intervals):
        require(isinstance(interval, list) and len(interval) == 2, "footprint_pair")
        a, b = interval
        require(type(a) is int and type(b) is int and old_cursor <= a < b <= len(text), "footprint_range")
        require(text[old_cursor:a] == masked[new_cursor:match.start()], "footprint_literal_gap")
        value = text[a:b].casefold()
        require(token_values.setdefault(match.group(), value) == value, "footprint_token_value")
        covered.update(range(a, b))
        old_cursor, new_cursor = b, match.end()
    require(text[old_cursor:] == masked[new_cursor:], "footprint_literal_suffix")
    return covered


def record_binding(record, text, index, plan):
    rid, access, label = record["record_id"], record["access"], record["label"]
    digest = text_sha(text)
    require(record["text"] == text and record["source_id"] == rid, "record_text_or_identity")
    require(record["source"] == {"text": text, "source_id": f"source_{index:02d}", "sha256": digest}, "record_source")
    for value in (record, access, label):
        require(value["source_start"] == 0 and value["source_end"] == len(text), "record_exact_range")
    require(access["record_id"] == label["record_id"] == rid, "record_bound_identity")
    require(access["content_sha256"] == label["content_sha256"] == digest, "record_content_hash")
    require(access["source_sha256"] == label["source_sha256"] == digest, "record_source_hash")
    require(access["owner_id"] == "probe_user" and access["origin_agent_id"] == "probe_source", "trusted_owner")
    require(access["principal_scope"]["principals"] == plan["principals"], "trusted_principal")
    require(label["access_sha256"] == canonical_sha(access), "label_access_binding")
    require(all(re.fullmatch(r"[a-f0-9]{64}", record[k]) for k in ("access_signature", "label_signature")), "signature_shape")


def verify(root):
    plan, closed, report = (read(root / name) for name in ("plan.json", "prediction_phase_closed.json", "report.json"))
    require(sha(root / "plan.json") == PLAN_SHA == closed["plan_sha256"] == report["plan_sha256"], "plan_hash")
    hashes = {"plan.json": PLAN_SHA}
    for name, digest in plan["sources"].items():
        require(sha(root / "implementation" / name) == digest, "frozen_source_hash:" + name)
    for name, digest in plan["inputs"].items():
        require(sha(root / "historical" / name) == digest, "historical_hash:" + name)
    for name, key in (("predictions.json", "predictions_sha256"), ("source_annotations.json", "source_annotations_sha256")):
        hashes[name] = sha(root / name)
        require(hashes[name] == closed[key], "closed_hash:" + name)
    hashes["prediction_phase_closed.json"] = sha(root / "prediction_phase_closed.json")
    require(hashes["prediction_phase_closed.json"] == report["closure_sha256"], "report_closure_hash")
    names = sorted(closed["capture_sha256"])
    require(names == sorted(p.name for p in root.glob("transport_*.json")), "capture_inventory")
    for name in names:
        require(sha(root / name) == closed["capture_sha256"][name], "capture_hash:" + name)
    require(closed["reference_parsed"] is False and closed["rows"] == 72, "closure_contract")
    final = read(root / "execution_final.json")
    require(final["status"] == "complete" and final["reference_parsed"] is True and final["rows"] == 72, "execution_completion")
    frozen_driver = root / "implementation/scripts/run_source_annotation_probe.py"
    module = ast.parse(frozen_driver.read_text(encoding="utf-8"))
    execute = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "execute")
    calls = {name: [n.lineno for n in ast.walk(execute) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == name]
             for name in ("close_prediction_phase", "load_closed_reference", "score_rows")}
    require(all(len(v) == 1 for v in calls.values()) and calls["close_prediction_phase"][0]
            < calls["load_closed_reference"][0] < calls["score_rows"][0], "reference_phase_order")
    rows, annotations, receivers = (read(root / name) for name in ("predictions.json", "source_annotations.json", "receiver_responses.json"))
    require(sha(root / "receiver_responses.json") == plan["receiver_responses_sha256"], "receiver_hash")
    texts = read(root / "historical/runtime.json")["texts"]
    require(len(texts) == len(annotations) == len(receivers) == 24 and len(rows) == 72, "material_count")
    by = {(r["cell"]["text_index"], r["cell"]["arm"]): r for r in rows}
    require(set(by) == {(i, arm) for i in range(24) for arm in ARMS} and len(by) == 72, "grid")
    require(all(r["cell"]["profile"] == PROFILE for r in rows), "profile")
    historical = read(root / "historical/predictions.json")
    old_receivers = {r["cell"]["text_index"]: r["response"] for r in historical if r["cell"]["arm"] == "conditional"}
    require(len(old_receivers) == 24 and all(receivers[i] == old_receivers[i] for i in range(24)), "historical_receiver_reuse")
    events = [read(root / name) for name in names]
    require(Counter(e["method"] for e in events) == {"GET": 48, "POST": 28}, "physical_calls")
    require(closed["network"] == report["network"] == final["network"] == {"loopback_connects": 76, "blocked_connects": 0}, "network_receipts")
    require(closed["source_generation_posts"] == report["source_generation_posts"] == final["source_generation_posts"] == 28, "post_receipts")
    cursor, source_errors, raw_checked, format_failures = 0, Counter(), 0, []
    for i, annotation in enumerate(annotations):
        require(read(root / f"source_{i:02d}.json") == annotation, "source_shard")
        count = closed["per_text_posts"][str(i)]
        require(type(count) is int and 1 <= count <= 2, "per_text_budget")
        group = events[cursor:cursor + count + 2]
        cursor += count + 2
        require([e["path"] for e in group[:2]] == ["/api/version", "/api/tags"], "health_capture_order")
        for event in group[2:]:
            require(event["method"] == "POST" and event["path"] == "/api/chat" and event["error_type"] is None, "post_capture")
            body = event["body"]
            require(body["model"] == plan["model"] and body["options"] == plan["options"], "request_identity")
            user = next(m for m in body["messages"] if m["role"] == "user")
            require(json.loads(user["content"])["text"] == texts[i], "request_source_text")
        response = annotation["source_response"]
        require(annotation["local_calls"] == response["local_calls"] == count and annotation["local_calls_complete"] is True, "source_call_accounting")
        envelope = json.loads(group[-1]["raw_response"])
        require(envelope["model"] == plan["model"] and envelope["done"] is True and envelope["done_reason"] == "stop", "raw_envelope")
        errors = response["errors"]
        if errors == ["format_or_span_invalid"]:
            require(count == 2 and annotation["status"] == "needs_review", "format_failure_contract")
            try:
                source_occurrences(json.loads(envelope["message"]["content"]), texts[i])
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                format_failures.append(i)
            else:
                raise ValueError("claimed_format_failure_was_valid")
        else:
            decoded = json.loads(envelope["message"]["content"])
            require(response["quote_wrapper_repairs"] == 0, "wrapper_repair_needs_separate_audit")
            require(decoded["status"] == response["status"] and source_occurrences(decoded, texts[i])
                    == spans(response["findings"], texts[i]), "raw_response_to_source_spans")
            raw_checked += 1
        if annotation["status"] == "ok":
            require(errors == [] and len(annotation["records"]) == 1, "source_success")
            record_binding(annotation["records"][0], texts[i], i, plan)
            require(spans(annotation["records"][0]["label"]["findings"], texts[i])
                    == spans(response["findings"], texts[i]), "source_label_projection")
        else:
            require(annotation["records"] == [] and errors in (["semantic_uncertainty"], ["format_or_span_invalid"]), "source_failure_not_clean")
            source_errors.update(errors)
    require(cursor == 76 and source_errors == {"semantic_uncertainty": 6, "format_or_span_invalid": 3}, "source_failure_inventory")
    controls, ready_count, semantic_evidence, covered = Counter(), 0, {}, {}
    for (i, arm), row in by.items():
        require(read(root / f"row_{i:02d}_{arm}.json") == row, "row_shard")
        preparation, source = row["preparation"], annotations[i]
        require(row["status"] == preparation["status"] and row["new_target_posts"] == preparation["new_target_posts"] == 0, "row_status_cost")
        if arm in ("receiver_only", "source_label_transfer") or source["status"] != "ok":
            require(row["response"] == receivers[i], "same_receiver_response")
        if arm == "receiver_union" and source["status"] == "ok":
            require(spans(row["response"]["findings"], texts[i]) ==
                    spans(source["source_response"]["findings"], texts[i]) | spans(receivers[i]["findings"], texts[i]), "same_union_observations")
        expected = spans(receivers[i]["findings"], texts[i])
        if arm != "receiver_only" and source["status"] == "ok":
            expected |= spans(source["source_response"]["findings"], texts[i])
        require(spans(row["exact_protective_findings"], texts[i]) == expected, "exact_union")
        evidence = {"receiver": semantic_unknown(receivers[i]),
                    "source": arm != "receiver_only" and semantic_unknown(source["source_response"])}
        require(row["semantic_review_evidence"] == evidence, "semantic_evidence")
        semantic_evidence[(i, arm)] = any(evidence.values())
        covered[(i, arm)] = footprint(texts[i], preparation)
        if preparation["status"] == "ok":
            ready_count += 1
            record_binding(row["record"], texts[i], i, plan)
            if arm == "source_label_transfer":
                require(row["record"] == source["records"][0], "transferred_record")
            else:
                require(row["record"]["label"]["findings"] == [], "baseline_empty_label")
            negative = preparation["acl_negative_controls"]
            require(len(negative) == 2 and {(v["actor_id"], v["agent_id"]) for v in negative}
                    == {("probe_wrong_user", "probe_target"), ("probe_user", "probe_wrong_agent")}, "acl_controls_identity")
            require(all(v["status"] == "rejected" and v["error"] == "principal_not_authorized"
                        and v["payload_is_none"] is True for v in negative), "acl_controls_rejected")
            controls[arm] += 2
            require(all(c["access_valid"] is True and c["label_valid"] is True for c in preparation["checks"]), "runtime_binding_checks")
        else:
            require(preparation["acl_negative_controls"] == [], "blocked_negative_controls")
    require(ready_count == 40 and controls == {"receiver_only": 36, "source_label_transfer": 22, "receiver_union": 22}, "80_acl_controls")
    for i in range(24):
        left, right = (by[(i, arm)] for arm in ARMS[1:])
        require((left["status"], left["preparation"]["error"], left["exact_protective_findings"], left["preparation"]["actual_mask_intervals"])
                == (right["status"], right["preparation"]["error"], right["exact_protective_findings"], right["preparation"]["actual_mask_intervals"]), "paired_equivalence")
    # First gold parse occurs only after all predictions, raw captures and
    # source/receiver composition checks above have completed.
    reference = read(root / "historical/evaluation.opaque.json")
    refs = {r["text_index"]: r for r in reference["cases"]}
    require(set(refs) == set(range(24)), "reference_inventory")
    groups, scores, fp_breakdown = {}, {}, []
    for (i, arm), row in by.items():
        text, case = texts[i], refs[i]
        require(case["text_sha256"] == text_sha(text), "reference_source_binding")
        truth, fact = case["expected"][PROFILE], case["allowed_fact"]
        require(text[fact["start"]:fact["end"]] == fact["text"], "allowed_fact_binding")
        gold, predicted = spans(truth["spans"], text, reference=True), spans(row["exact_protective_findings"], text)
        known, ready, mask = truth["decision"] != "needs_review", row["status"] == "ok", covered[(i, arm)]
        protected = {p for a, b, _ in gold for p in range(a, b)}
        unprotected = len(mask - protected) if known and ready else 0
        full = partial = absent = 0
        for a, b, _ in gold:
            hits = len(mask.intersection(range(a, b)))
            full += int(ready and hits == b-a)
            partial += int(ready and 0 < hits < b-a)
            absent += int(ready and hits == 0)
        semantic = not ready and semantic_evidence[(i, arm)]
        value = {"total": 1, "known": int(known), "unknown": int(not known), "prepared": int(ready),
            "known_prepared": int(known and ready), "blocked": int(not ready),
            "known_exact": int(known and ready and predicted == gold), "unknown_blocked": int(not known and not ready),
            "semantic_unknown_review": int(not known and semantic),
            "unknown_blocked_without_semantic_uncertainty": int(not known and not ready and not semantic),
            "unknown_prepared": int(not known and ready), "raw_predicted_protective_tp": len(predicted & gold) if known else 0,
            "raw_predicted_protective_fp": len(predicted - gold) if known else 0,
            "raw_predicted_protective_fn": len(gold - predicted) if known else 0, "reference_spans": len(gold),
            "fully_masked_spans": full, "partially_masked_spans": partial, "unmasked_spans": absent,
            "prepared_incomplete_spans": partial + absent, "actual_masked_unprotected_chars": unprotected,
            "known_prepared_with_unprotected_masking": int(unprotected > 0),
            "blocked_reference_spans": len(gold) if not ready else 0,
            "allowed_fact_retained": int(ready and not mask.intersection(range(fact["start"], fact["end"]))), "allowed_fact_total": 1}
        scores[(i, arm)] = value
        group = groups.setdefault(arm, {**dict.fromkeys(value, 0), "statuses": Counter(), "block_reasons": Counter()})
        for key, number in value.items(): group[key] += number
        group["statuses"][row["status"]] += 1
        group["block_reasons"].update(row["block_reasons"])
        if arm == "receiver_only" and known and predicted - gold:
            fp_breakdown.append({"text_index": i, "status": row["status"], "false_positives": [
                {"start": a, "end": b, "quote": text[a:b]} for a, b, _ in sorted(predicted - gold)]})
    for arm, group in groups.items():
        tp, fp, fn = (group["raw_predicted_protective_" + k] for k in ("tp", "fp", "fn"))
        group["raw_predicted_protective_precision"] = tp / (tp + fp) if tp + fp else None
        group["raw_predicted_protective_recall"] = tp / (tp + fn) if tp + fn else None
        require(group == report["by_arm"][arm], "independent_summary_mismatch:" + arm)
    for row in read(root / "scored_rows.json"):
        require(row["score"] == scores[(row["cell"]["text_index"], row["cell"]["arm"])], "independent_row_score")
    ready_fp = sum(len(r["false_positives"]) for r in fp_breakdown if r["status"] == "ok")
    blocked_fp = sum(len(r["false_positives"]) for r in fp_breakdown if r["status"] != "ok")
    require((ready_fp, blocked_fp) == (2, 3), "fp_scope_partition")
    require(groups["receiver_only"]["known_prepared"] == 18 and groups["source_label_transfer"]["known_prepared"] == 11, "readiness_regression")
    require(spans(annotations[22]["source_response"]["findings"], texts[22]) == {(40, 54, "CUSTOMER")}
            and spans(refs[22]["expected"][PROFILE]["spans"], texts[22], reference=True) == {(24, 26, "CUSTOMER")}, "case22_locations")
    require(all(not covered[(22, arm)].intersection(range(24, 26)) for arm in ARMS), "case22_still_unmasked")
    gate = (groups[ARMS[1]]["known_prepared"] >= groups[ARMS[0]]["known_prepared"]
            and groups[ARMS[1]]["semantic_unknown_review"] == groups[ARMS[1]]["unknown"]
            and groups[ARMS[1]]["prepared_incomplete_spans"] == 0)
    require(gate is False and report["development_gate_passed"] is gate, "failed_development_gate")
    hashes["report.json"], hashes["scored_rows.json"] = sha(root / "report.json"), sha(root / "scored_rows.json")
    return {"status": "passed", "audit_version": "source_annotation_independent_stdlib_v1",
        "frozen_plan_sha256": PLAN_SHA, "artifact_sha256": hashes,
        "frozen_source_files_checked": len(plan["sources"]), "historical_files_checked": len(plan["inputs"]),
        "capture_files_checked": 76, "physical_post_count": 28, "health_get_count": 48,
        "raw_source_decodes_checked": raw_checked, "format_failure_indices": format_failures,
        "source_failure_counts": dict(source_errors),
        "source_failure_indices": [i for i, a in enumerate(annotations) if a["status"] != "ok"],
        "grid_cells_checked": 72, "ready_footprints_checked": ready_count,
        "acl_negative_controls": dict(controls), "acl_negative_controls_total": sum(controls.values()),
        "paired_equivalent_cases": 24, "independent_scores_match": True, "by_arm": groups,
        "receiver_fp_scope": {"all_known_raw": 5, "ready_only": ready_fp, "blocked_known_raw": blocked_fp,
            "details": fp_breakdown, "interpretation": "The three blocked raw false positives were absent from the earlier ready-only count; observations were not improved."},
        "case22": {"source_span": [40, 54], "source_quote": texts[22][40:54], "reference_span": [24, 26],
            "reference_quote": texts[22][24:26], "actual_footprints": {a: by[(22, a)]["preparation"]["actual_mask_intervals"] for a in ARMS},
            "all_arms_still_miss_reference_span": True},
        "development_gate_passed": gate, "audit_model_calls": 0, "audit_network_calls": 0,
        "limits": ["Independent standard-library recomputation; producer scoring functions were not imported.",
            "Raw captures, positions, record hashes and recorded runtime signature checks were audited. The ephemeral HMAC key was not persisted, so signatures cannot be independently reverified offline.",
            "Closure hashes and frozen control flow support the recorded phase order; these are local records, not independently timestamped attestation."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=ROOT / "results/source_annotation_20261028_run_01")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run, output = args.run.resolve(), args.output.resolve()
    require(run == ROOT / "results/source_annotation_20261028_run_01", "fixed_run_required")
    require(output == ROOT / "results/source_annotation_independent_audit_20261028" and not output.exists(), "new_audit_output_required")
    result = verify(run)
    result["verifier_sha256"] = sha(Path(__file__))
    output.mkdir()
    with (output / "audit.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "audit_sha256": sha(output / "audit.json"),
        "verifier_sha256": result["verifier_sha256"], "post_count": 28, "controls": 80,
        "source_failure_counts": result["source_failure_counts"], "fp_scope": result["receiver_fp_scope"],
        "case22": result["case22"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
