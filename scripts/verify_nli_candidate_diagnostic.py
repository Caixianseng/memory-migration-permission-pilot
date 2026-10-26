"""Offline independent NLI artifact audit; standard library, no producer imports."""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATS = set("EMAIL PHONE ID PERSON ADDRESS CUSTOMER PROJECT AMOUNT DATE".split())
SEMANTIC = ("PERSON", "ADDRESS", "CUSTOMER", "PROJECT")
ARMS = ("standard_boundary", "nli_existing", "nli_full_pool")


def read(p):
    return json.loads(Path(p).read_bytes())


def sha(p):
    h = hashlib.sha256()
    with Path(p).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def hashed(x):
    return hashlib.sha256(json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def sources(payload):
    assert set(payload) == {"query", "memories"}
    return {"__query__": payload["query"], **{m["source_id"]: m["text"] for m in payload["memories"]}}


def normalized(p):
    return {"version": p["version"], "protected_categories": list(dict.fromkeys(p["protected_categories"])),
            "policy_id": p.get("policy_id", p["version"]), "max_text_chars": p.get("max_text_chars", 6000),
            "instructions": p.get("instructions", ""), "entity_registry": [
                {"category": c, "value": v} for c, v in sorted({(r["category"], r["value"]) for r in p.get("entity_registry", [])})]}


def key(r):
    return tuple(r[k] for k in ("source_id", "start", "end", "category"))


def finding_keys(rows, payload, strict=False):
    ss = sources(payload); found = set(); invalid = duplicate = 0
    for r in rows:
        if (not isinstance(r, dict) or r.get("source_id") not in ss or type(r.get("start")) is not int
                or type(r.get("end")) is not int or not 0 <= r["start"] < r["end"] <= len(ss[r["source_id"]])
                or r.get("category") not in CATS):
            invalid += 1; continue
        k = key(r); duplicate += k in found; found.add(k)
    if strict and (invalid or duplicate):
        raise ValueError("invalid_gold")
    return found, invalid, duplicate


def metrics(pred, truth):
    tp, fp, fn = len(pred & truth), len(pred - truth), len(truth - pred)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def total_metrics(items):
    t = {k: sum(x[k] for x in items) for k in ("tp", "fp", "fn")}
    tp, fp, fn = (t[k] for k in ("tp", "fp", "fn"))
    return {**t, "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def decide(prior, statuses, allowed):
    positive = [c for c in allowed if statuses["category:" + c] == "E"]
    if len(positive) > 1:
        return "needs_review", None, "multiple_category_entailments"
    if positive:
        if statuses["role:value"] == "C":
            return "needs_review", None, "category_value_contradiction"
        if prior is not None and prior != positive[0]:
            return "needs_review", None, "typed_category_changed"
        return "protect", positive[0], "unique_policy_category_entailment"
    if all(statuses["category:" + c] == "C" for c in allowed) or (
            statuses["role:value"] == "C" and any(statuses["role:" + k] == "E" for k in ("field_label", "generic_role"))):
        return "nonvalue", None, "negative_type_or_nonvalue_evidence"
    return "needs_review", None, "insufficient_or_unresolved_evidence"


def audit(run):
    checks = []
    def ck(name, ok):
        checks.append({"name": name, "passed": bool(ok)})
    plan = read(run / "plan.json"); closed = read(run / "model_phase_closed.json")
    # This check must succeed before any evaluation JSON is parsed below.
    if not (closed["closed"] is True and closed["plan_sha256"] == sha(run / "plan.json")
            and closed["prediction_sha256"] == sha(run / "inference/worker_predictions.json")):
        raise ValueError("prediction_closure_not_valid")
    ck("closure_verified_before_gold_parse", True)
    for name, h in plan["implementation_sha256"].items():
        ck("current_and_snapshot_" + name, sha(ROOT / name) == h and sha(run / "frozen_source" / name) == h)
    for name, h in plan["input_sha256"].items():
        ck("input_hash_" + name, sha(run / name) == h)
    contract = plan["contract"]
    ck("fixed_contract_bytes_and_semantics", read(ROOT / "docs/proposals/nli_candidate_contract_v1_20261026.json") == contract
       and sha(ROOT / "docs/proposals/nli_candidate_contract_v1_20261026.json") == "7eae94ddf1e0995e36fa3d6f0303673ad2551496a6c4c51e0bb99d9560a9a29b"
       and contract["score_contract"]["tau"] == .8)
    reference = plan["runtime_reference"]; qualified = ROOT / "results/mdeberta_nli_runtime_20261026_v3"
    ck("qualified_runtime_binding", reference["plan_sha256"] == sha(qualified / "plan.json")
       and reference["report_sha256"] == sha(qualified / "report.json") and reference["runtime_plan"] == read(qualified / "plan.json")
       and read(qualified / "report.json")["runtime_qualified"] is True)
    qp = reference["runtime_plan"]
    for name, h in qp["implementation_sha256"].items():
        ck("qualified_current_source_" + name, sha(ROOT / name) == h)
    for a in qp["assets"]:
        f = ROOT / qp["asset_root"] / a["name"]
        ck("qualified_asset_" + a["name"], f.stat().st_size == a["size"] and sha(f) == a["sha256"])
    for name, d in qp["runtime_distributions"].items():
        ck("qualified_distribution_" + name, sha(ROOT / d["metadata_file"]) == d["sha256"])
    driver = (ROOT / "scripts/run_nli_candidate_diagnostic.py").read_text(encoding="utf-8")
    tree = ast.parse(driver); worker = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "worker")
    ck("worker_never_names_gold", not any(isinstance(n, ast.Constant) and isinstance(n.value, str) and "evaluation.json" in n.value for n in ast.walk(worker)))
    ck("producer_closes_before_host_score", driver.index('save(output / "model_phase_closed.json"') < driver.index('summary = score_closed(output, plan, predictions)')
       and driver.index('"predictions_not_closed"') < driver.index('gold.update(json.loads(path.read_bytes()))'))
    helper = (ROOT / "scripts/run_candidate_decision_diagnostic.py").read_text(encoding="utf-8")
    ck("historical_reference_gold_copied_not_parsed", '(output / split / name).write_bytes(raw)  # Gold stays bytes.' in helper
       and 'materials = json.loads(raw_materials)  # Predictions only; no scoring labels.' in helper)
    inputs = read(run / "runtime_inputs.json"); materials = read(run / "materials_input.json")
    ck("120_closed_runtime_input_schema", len(inputs) == len(materials) == 120 and len({x["case_id"] for x in inputs}) == 120
       and all(set(x) == {"case_id", "payload", "policy", "pool"} for x in inputs))
    by_case = {x["case_id"]: x for x in materials}
    phase_records = {}; exact_counts = {}
    for phase in ("tokenization", "inference"):
        directory = run / phase; job = read(directory / "worker_job.json"); pred = read(directory / "worker_predictions.json")
        pr = read(directory / "process_receipt.json"); phase_plan = read(directory / "plan.json")
        ck(phase + "_job_closed_and_bound", set(job) == {"schema", "phase", "output", "inputs", "approved_policies", "contract", "agent_config", "implementation_sha256", "runtime_reference", "max_forwards"}
           and job["inputs"] == inputs and job["contract"] == contract and job["implementation_sha256"] == plan["implementation_sha256"]
           and job["runtime_reference"] == reference and job["approved_policies"] == plan["approved_policies"]
           and job["agent_config"] == plan["agent_config"] == {"allow_forward": True, "max_candidates": 16}
           and job["phase"] == phase and job["max_forwards"] == (0 if phase == "tokenization" else 390)
           and pred["job_sha256"] == sha(directory / "worker_job.json") == phase_plan["job_sha256"])
        ck(phase + "_terminal_and_counts", pr["returncode"] == 0 and pred["status"] == "completed" and len(pred["records"]) == 120
           and pred["generation_calls"] == pred["cloud_calls"] == 0 and pr["raw_console_saved"] is False)
        guard = pred["guard"]; ck(phase + "_guard_no_denials", guard["blocked_attempts"] == guard["network_denials"] == guard["application_network_requests"] == 0 and guard["scope_denials"] == [])
        ck(phase + "_zip_probe_scope", all(Path(x["path"]).resolve() == Path(qp["python_identity"]["stdlib_zip"]).resolve()
           and x["read_only"] is True and not any(c in x["mode"] for c in "wax+") for x in guard["stdlib_zip_read_only_probes"]))
        exact_counts[phase] = pred["runtime_counts"]; phase_records[phase] = pred["records"]
        ck(phase + "_schedule", [x["case_id"] for x in pred["records"]] == [x["case_id"] for x in inputs])
    ck("token_phase_zero_model_and_forwards", all(v == 0 for v in exact_counts["tokenization"].values())
       and read(run / "tokenization/worker_predictions.json")["loading_evidence"] is None
       and sha(run / "tokenization/worker_predictions.json") == plan["tokenization_sha256"])
    ck("one_model_390_call_two_hooks", exact_counts["inference"] == closed["runtime_counts"] == {
        "blocked_forward_entries": 0, "classifier_attempts": 390, "classifier_forward_calls": 390,
        "encoder_attempts": 390, "encoder_forward_calls": 390, "model_load_attempts": 1, "model_loads": 1}
       and plan["max_classifier_forwards"] == plan["max_encoder_forwards"] == 390)
    ck("same_strict_qualified_weight_loading", read(run / "inference/worker_predictions.json")["loading_evidence"]
       == read(qualified / "report.json")["qualification_v2"]["weight_loading"])
    qguard = (ROOT / "scripts/qualify_mdeberta_nli_runtime.py").read_text(encoding="utf-8")
    ck("gold_outside_explicit_guard_paths", 'job_path.resolve()' in qguard and 'self.read_roots=[Path(sys.prefix).resolve()' in qguard
       and 'self.write_root=(output/"child_home").resolve()' in qguard and 'guard.read_files.update((ROOT / name).resolve() for name in job["implementation_sha256"])' in driver
       and not any("evaluation.json" in n or "materials_input.json" in n for n in plan["implementation_sha256"]))
    hypothesis_calls = 0; decisions_by_case = {}; stages = {}; preflights = {}
    for item, before, after in zip(inputs, phase_records["tokenization"], phase_records["inference"]):
        cid = item["case_id"]; case = by_case[cid]; ss = sources(item["payload"]); policy = normalized(item["policy"]); pool = item["pool"]
        pf = after["preflight"]; stage = after["stage"]; stages[cid] = stage; preflights[cid] = pf
        ck(cid + "_same_tokenized_requests", before["preflight"]["requests"] == pf["requests"] and pf["status"] == "ready" and pf["executable"] is True
           and pf["errors"] == [] and pf["truncation"] is False and pool == case["pool"] and item["payload"] == case["payload"] and item["policy"] == case["policy"])
        ck(cid + "_material_bindings", pf["payload_sha256"] == hashed(item["payload"]) and pf["policy_sha256"] == hashed(policy)
           and pf["full_policy_sha256"] == hashed(item["policy"]) and pf["contract_sha256"] == hashed(contract)
           and pf["pool_sha256"] == pool["pool_sha256"] and pf["source_sha256"] == {k: hashlib.sha256(v.encode()).hexdigest() for k, v in ss.items()})
        allowed = [c for c in SEMANTIC if c in policy["protected_categories"]]
        assertions = [("role:" + k, contract["hypotheses"]["roles"][k]) for k in ("value", "field_label", "generic_role")]
        assertions += [("category:" + k, contract["hypotheses"]["categories"][k]) for k in allowed]
        expected = []; evidence = {}; cand_map = {}
        for c in pool["candidates"]:
            sid = c["source_id"]; text = ss[sid]; ck(cid + "_candidate_" + c["cid"], text[c["start"]:c["end"]] == c["quote"] and c["source_sha256"] == hashlib.sha256(text.encode()).hexdigest())
            premise = contract["input"]["premise_template"].format(prefix=text[:c["start"]], quote=c["quote"], suffix=text[c["end"]:])
            cand_map[c["cid"]] = c; evidence[c["cid"]] = {"source_id": sid, "start": 0, "end": len(text), "source_sha256": hashlib.sha256(text.encode()).hexdigest()}
            expected += [{"rid": c["cid"] + ":" + k, "cid": c["cid"], "hypothesis_id": k, "premise": premise, "hypothesis": h} for k, h in assertions]
        ck(cid + "_complete_assertion_inventory", pf["allowed_semantic_categories"] == allowed and pf["candidate_count"] == len(cand_map)
           and pf["evidence"] == evidence and len(pf["requests"]) == pf["request_count"] == len(expected)
           and stage["processing_complete"] is True and len(stage["raw_results"]) == len(expected))
        ck(cid + "_full_source_collision_and_budget", not any(t in text for text in ss.values() for t in
           [contract["input"]["target_start"], contract["input"]["target_end"], *pf["reserved_tokens"]])
           and pf["max_pair_tokens"] == max((q["input_token_count"] for q in pf["requests"]), default=0)
           and pf["input_tokens"] == sum(q["input_token_count"] for q in pf["requests"]))
        states = {c: {} for c in cand_map}; probabilities = {c: {} for c in cand_map}
        for req, exp, rr in zip(pf["requests"], expected, stage["raw_results"]):
            ins = req["inputs"]; n = len(ins["input_ids"]); raw = rr["raw_result"]; logits = raw["logits"]
            valid = set(req) == set(exp) | {"inputs", "input_sha256", "input_token_count", "request_sha256"} and all(req[k] == v for k, v in exp.items())
            valid &= req["request_sha256"] == hashed({k: v for k, v in req.items() if k != "request_sha256"}) == rr["request_sha256"]
            valid &= req["input_sha256"] == hashed(ins) and req["input_token_count"] == n and 0 < n <= 512 and set(ins) <= {"input_ids", "attention_mask", "token_type_ids"}
            valid &= {"input_ids", "attention_mask"} <= set(ins) and all(isinstance(v, list) and len(v) == n and all(type(x) is int and x >= 0 for x in v) for v in ins.values())
            valid &= rr["rid"] == req["rid"] and rr["error"] is None and all(rr[k] == 1 for k in ("classifier_forward_delta", "encoder_forward_delta", "classifier_attempt_delta", "encoder_attempt_delta")) and rr["blocked_forward_delta"] == 0
            valid &= set(raw) == {"logits", "shape", "device", "dtype", "label2id"} and raw["shape"] == [1, 3] and raw["device"] == "cpu" and raw["dtype"] == "float32" and raw["label2id"] == {"entailment": 0, "neutral": 1, "contradiction": 2}
            valid &= len(logits) == 3 and all(type(x) in (int, float) and math.isfinite(x) for x in logits)
            ck(cid + "_request_" + req["rid"], valid); hypothesis_calls += 1
            ex = [math.exp(v - max(logits)) for v in logits]; ps = dict(zip(("entailment", "neutral", "contradiction"), (v / sum(ex) for v in ex)))
            states[req["cid"]][req["hypothesis_id"]] = "E" if ps["entailment"] >= .8 else "C" if ps["contradiction"] >= .8 else "U"
            probabilities[req["cid"]][req["hypothesis_id"]] = ps
        calculated = []; promoted = []
        for c in pool["candidates"]:
            name = c["cid"]; decision, category, reason = decide(c["proposed_category"], states[name], allowed)
            d = {"cid": name, "decision": decision, "category": category, "reason": reason, "relations": states[name], "probabilities": probabilities[name]}; calculated.append(d)
            if decision == "protect": promoted.append({"cid": name, **{k: c[k] for k in ("source_id", "start", "end", "quote")}, "category": category, "evidence": evidence[name]})
        review = any(c["decision"] == "needs_review" for c in calculated)
        ck(cid + "_independent_classification", stage["decisions"] == stage["verdicts"] == calculated and stage["findings"] == promoted
           and stage["evaluated_candidates"] == len(cand_map) and stage["status"] == ("needs_review" if review else "typing_only")
           and stage["preflight_sha256"] == hashed(pf) and stage["root_forward_calls"] == stage["encoder_forward_calls"] == stage["local_calls"] == len(expected)
           and stage["inference_attempts"] == len(expected) and stage["generation_calls"] == stage["cloud_calls"] == 0)
        decisions_by_case[cid] = {x["cid"]: x for x in calculated}
    ck("390_physical_requests_not_780", hypothesis_calls == 390)
    # Gold is opened only after the closure verification above; worker inputs were already checked.
    gold = {}
    for split in ("development", "heldout"):
        for name in ("runtime.json", "evaluation.json"):
            ck("corpus_bytes_" + split + "/" + name, sha(run / split / name) == plan["corpus_reference"]["corpus_sha256"][split + "/" + name])
        gold.update(read(run / split / "evaluation.json"))
    rows = read(run / "rows.json"); report = read(run / "report.json")
    ck("360_rows_full_cross_product", len(rows) == 360 and len({(r["case_id"], r["arm"]) for r in rows}) == 360
       and {(r["case_id"], r["arm"]) for r in rows} == {(c, a) for c in by_case for a in ARMS})
    row_map = {}; accepted_map = {}; truth_map = {}; summary = {}; errors = {}; promotions = {}
    for row in rows:
        cid = row["case_id"]; arm = row["arm"]; case = by_case[cid]; det = row["detection"]; truth = finding_keys(gold[cid]["findings"], case["payload"], True)[0]
        pred, invalid, duplicate = finding_keys(det.get("findings", []), case["payload"]); accepted = pred if det["status"] == "ok" and invalid == 0 else set()
        row_map[cid, arm] = row; accepted_map[cid, arm] = accepted; truth_map[cid] = truth
        score = {"accepted": metrics(accepted, truth), "validated_candidate": metrics(pred, truth), "invalid_candidate_count": invalid,
                 "duplicate_candidate_count": duplicate, "accepted_complete_exact": det["status"] == "ok" and invalid == 0 and accepted == truth,
                 "gold_spans": len(truth), "accepted_spans": len(accepted), "validated_candidate_spans": len(pred),
                 "by_category": {c: {"accepted": metrics({v for v in accepted if v[3] == c}, {v for v in truth if v[3] == c}),
                                     "validated_candidate": metrics({v for v in pred if v[3] == c}, {v for v in truth if v[3] == c})} for c in sorted(CATS)}}
        ck(cid + "_score_" + arm, score == row["score"] and row["split"] == case["split"] and row["language"] == case["language"])
        if arm == ARMS[0]:
            ck(cid + "_unchanged_boundary_baseline", det == case["baseline"]); continue
        original = {key(x) for x in case["baseline"]["findings"]}; immutable = {key(x) for x in case["baseline"]["findings"] if x["category"] not in SEMANTIC or "registry" in x.get("method", "").split("+")}
        selected = [c for c in case["pool"]["candidates"] if (c["source_id"], c["start"], c["end"], c["proposed_category"]) not in immutable
                    and (arm == ARMS[2] or (c["source_id"], c["start"], c["end"], c["proposed_category"]) in original)]
        selected_reviews = [c["cid"] for c in selected if decisions_by_case[cid][c["cid"]]["decision"] == "needs_review"]
        aud = det["nli_candidate"]
        ck(cid + "_shared_stage_and_immutable_" + arm, aud["selected_reviews"] == selected_reviews and immutable <= pred
           and aud["authorization_changed"] is aud["default_changed"] is False and det["local_counts"]["shared_prediction_cache"] is True
           and det["local_counts"]["new_encoder_forwards"] == stages[cid]["encoder_forward_calls"]
           and (det["status"] == "needs_review" and det["errors"] == ["nli_selected_semantic_needs_review"] if selected_reviews else det["status"] == "ok")
           and (aud.get("stage_sha256") == hashed(stages[cid]) if det["status"] == "ok" else True))
    for split in ("development", "heldout"):
        summary[split] = {}; errors[split] = {}; promotions[split] = {}
        cs = [c for c, m in by_case.items() if m["split"] == split]
        ck(split + "_complete_material_denominator", len(cs) == (80 if split == "development" else 40))
        for arm in ARMS:
            selected = [row_map[c, arm] for c in cs]; aggregate = total_metrics([r["score"]["accepted"] for r in selected]); original = report["summary"][split][arm]
            ck(split + "_aggregate_" + arm, {k: v for k, v in aggregate.items() if k != "f1"} == original["accepted"]
               and len(selected) == original["materials"] and sum(r["detection"]["status"] == "ok" for r in selected) == original["ok"]
               and sum(r["score"]["accepted_complete_exact"] for r in selected) == original["complete_exact"])
            summary[split][arm] = {**aggregate, "materials": len(cs), "ready": original["ok"], "needs_review": len(cs) - original["ok"], "complete_exact": original["complete_exact"]}
            if arm == ARMS[0]: continue
            counter = Counter()
            for cid in cs:
                base_tp = accepted_map[cid, ARMS[0]] & truth_map[cid]; current_tp = accepted_map[cid, arm] & truth_map[cid]
                lost = base_tp - current_tp; status = row_map[cid, arm]["detection"]["status"]
                counter["lost_baseline_tp_on_needs_review_materials" if status == "needs_review" else "lost_baseline_tp_on_status_ok_materials"] += len(lost)
                counter["new_tp_relative_to_baseline"] += len(current_tp - base_tp)
                if status == "needs_review":
                    counter["gold_spans_on_review_materials"] += len(truth_map[cid])
            errors[split][arm] = dict(counter)
        raw_promote = Counter(); delivered = Counter(); incremental = Counter()
        for cid in cs:
            for c in by_case[cid]["pool"]["candidates"]:
                d = decisions_by_case[cid][c["cid"]]
                if c["proposed_category"] is None and d["decision"] == "protect":
                    k = (c["source_id"], c["start"], c["end"], d["category"]); correct = k in truth_map[cid]
                    raw_promote["tp" if correct else "fp"] += 1
                    if row_map[cid, ARMS[2]]["detection"]["status"] == "ok" and k in accepted_map[cid, ARMS[2]]:
                        delivered["tp" if correct else "fp"] += 1
            added = accepted_map[cid, ARMS[2]] - accepted_map[cid, ARMS[1]]
            incremental["tp"] += len(added & truth_map[cid]); incremental["fp"] += len(added - truth_map[cid])
        promotions[split] = {"raw_untyped_protect_candidates": dict(raw_promote), "accepted_exact_untyped_promotion_spans": dict(delivered), "full_minus_existing_accepted_added_spans": dict(incremental)}
    ck("report_cost_and_scope", report["runtime_counts"] == exact_counts["inference"] and report["materials"] == 120 and report["rows"] == 360
       and report["independent_acceptance"] is report["default_changed"] is False and report["new_generations"] == report["cloud_calls"] == report["new_api_cost_cny"] == 0
       and report["implementation_unchanged"] is True)
    return {"schema": "independent_nli_candidate_audit_v1", "status": "passed" if all(x["passed"] for x in checks) else "failed",
            "checks_passed": sum(x["passed"] for x in checks), "checks_total": len(checks), "failed_checks": [x["name"] for x in checks if not x["passed"]],
            "checks": checks, "summary": summary, "tp_loss_decomposition": errors, "untyped_promotion_analysis": promotions,
            "artifact_sha256": {n: sha(run / n) for n in ("plan.json", "model_phase_closed.json", "inference/worker_predictions.json", "tokenization/worker_predictions.json", "rows.json", "report.json")},
            "audit_model_calls": 0, "audit_native_calls": 0,
            "limits": ["Read-only artifact and frozen-source verification; no producer/scorer module imported and no tokenizer/model rerun.",
                       "Saved tokenization and inference input receipts match; this is not an independent tokenizer execution or hardware call trace.",
                       "Classifier and encoder hooks observe the same 390 calls, not 780 independent model calls.",
                       "Gold isolation is supported by closed job fields, frozen code paths, guard receipts and hash closure, not an independent external seal or OS sandbox.",
                       "Original standard boundary baseline and reported detections were scored independently; composition closure was not re-executed using production code.",
                       "All 120 materials are exposed development/regression; no independent acceptance, legal-answer effect, native migration improvement or novelty is established."]}


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("--run", type=Path, required=True); p.add_argument("--output", type=Path, required=True); a = p.parse_args()
    if a.output.exists(): raise ValueError("new_output_required")
    result = audit(a.run.resolve())
    with a.output.open("xb") as f:
        f.write((json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())
    print(json.dumps({"status": result["status"], "passed": result["checks_passed"], "total": result["checks_total"], "failed": result["failed_checks"], "output_sha256": sha(a.output)}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
