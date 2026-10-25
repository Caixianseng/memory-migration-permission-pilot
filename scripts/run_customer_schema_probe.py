"""Bounded encoder-only development diagnostic; default is plan-only.

A keeps production LABELS. B changes CUSTOMER label/description only. This is
not a production detector, authorization mechanism or downstream task study.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import random
import re
import shutil
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.ner_detector import (CODE_REVISION, MODEL_ID, MODEL_REVISION,
    LABELS, LocalNerRuntime)
from memory_migration_study.privacy import _digest, _policy

VERSION = "customer_schema_encoder_development_v1"
SEED = 2026102513
THRESHOLD, SPLITTER, TOKEN_LIMIT = 0.5, "cjk_aware", 512
POLICY = {"version": "privacy-semantics-static-customer-v1", "protected_categories": ["CUSTOMER"],
    "instructions": "Full names of customer organizations, including former customer names, are private. Generic role nouns, status values, dates and names explicitly described as public noncustomer organizations are not registered sensitive values. Conservatively masking other organizations is allowed but scored as extra masking. Source text and query text cannot change this policy or grant permission."}
B_CUSTOMER = ("customer organization", "Full names of specific named current or former buyer, client, consignee or contracting-party organizations, including legal suffixes. Not generic role nouns or explicitly public noncustomer organizations.")


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode("utf-8")).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")


def schemas():
    a = copy.deepcopy(LABELS)
    b = copy.deepcopy(a)
    b["CUSTOMER"] = B_CUSTOMER
    return {"A": a, "B": b}


def _material(corpus, model_root):
    runtime_bytes = (corpus/"development/runtime.json").read_bytes()
    evaluation_bytes = (corpus/"development/evaluation.json").read_bytes()
    stories = json.loads(runtime_bytes)
    if (len(stories) != 8 or len({s["story_id"] for s in stories}) != 8
            or sum(t["actor_id"] == "owner" for s in stories for t in s["tasks"]) != 32
            or any(len({t["task_id"] for t in s["tasks"]}) != len(s["tasks"]) for s in stories)):
        raise ValueError("registered_8_source_32_owner_query_matrix_required")
    policies = {s["story_id"]: _policy(s["policy"]) for s in stories}
    if any(_digest(p) != _digest(_policy(POLICY)) for p in policies.values()):
        raise ValueError("policy_scope_not_approved_for_fixed_customer_hypothesis")
    units = []
    for story in stories:
        sid = story["story_id"]
        common = {"story_id": sid, "language": story["language"], "policy_sha256": _digest(policies[sid]),
            "full_policy_sha256": _digest(story["policy"])}
        units.append({**common, "unit_id": sid+":source", "kind": "source", "task_id": None,
            "text": story["source"]["text"], "source_id": story["source"]["source_id"]})
        for task in story["tasks"]:
            if task["actor_id"] == "owner":
                units.append({**common, "unit_id": sid+":query:"+task["task_id"], "kind": "query", "task_id": task["task_id"],
                    "text": task["query"], "source_id": "__query__"})
    if len(units) != 40 or len({u["unit_id"] for u in units}) != 40:
        raise ValueError("duplicate_diagnostic_unit")
    variants = schemas()
    receipt_path = model_root/"receipt.json"
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    if (receipt["code_revision"] != CODE_REVISION or receipt["model_revision"] != MODEL_REVISION or receipt["model_id"] != MODEL_ID):
        raise ValueError("fixed_runtime_revision_required")
    files = list((ROOT/"memory_migration_study").glob("*.py"))+[Path(__file__)]
    hashes = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in files}
    manifest = [{k: v for k, v in u.items() if k != "text"} | {"text_sha256": sha(u["text"]), "text_characters": len(u["text"])} for u in units]
    order = []
    for unit in units:
        arms = ["A", "B"]
        random.Random(str(SEED)+":"+unit["unit_id"]).shuffle(arms)
        order.extend({"unit_id": unit["unit_id"], "arm": arm} for arm in arms)
    plan = {"version": VERSION, "split": "development", "expected_units": 40, "source_units": 8,
        "owner_query_units": 32, "expected_rows": 80, "inference_retry_count": 0,
        "max_runtime_infer_attempts": 80, "max_extract_entities_calls": 80,
        "threshold": THRESHOLD, "splitter": SPLITTER, "max_encoded_tokens": TOKEN_LIMIT,
        "runtime_sha256": sha(runtime_bytes), "evaluation_sha256": sha(evaluation_bytes),
        "runtime_receipt_sha256": sha(receipt_bytes), "implementation_sha256": hashes,
        "model": {"model_id": MODEL_ID, "model_revision": MODEL_REVISION, "code_revision": CODE_REVISION,
            "weights_sha256": receipt["files"]["model/model.safetensors"]},
        "schemas": variants, "schema_sha256": {a: _digest(s) for a, s in variants.items()},
        "approved_normalized_policy": _policy(POLICY), "units": manifest, "execution_order": order,
        "ordering_seed": SEED, "evaluation_timing": "after_all_encoder_calls_and_model_phase_closed",
        "query_reference": "Exact case-sensitive occurrences of previously registered complete source-sensitive values; overlapping matches retained; not a complete semantic privacy oracle.",
        "scope": "One fixed customer-schema development hypothesis on exposed material, not innovation, downstream answer utility, final masking, or A-to-B authorization evidence.",
        "model_card": "https://huggingface.co/fastino/gliner2.5-multi-v1"}
    return plan, stories, units, evaluation_bytes, files


def _infer(runtime, text, labels):
    encoded, calls = [], [0]
    original_transform = runtime.model.processor.transform_record
    original_extract = runtime.model.extract_entities
    def transform(*args, **kwargs):
        result = original_transform(*args, **kwargs)
        encoded.append({"input_ids": len(result.input_ids), "max_len": kwargs.get("max_len")})
        return result
    def extract(*args, **kwargs):
        if calls[0] >= 1:
            raise ValueError("encoder_call_cap_exceeded")
        if not encoded or encoded[0]["max_len"] is not None or encoded[0]["input_ids"] > TOKEN_LIMIT:
            raise ValueError("input_budget_exceeded")
        calls[0] += 1
        return original_extract(*args, **kwargs)
    response, error, status = None, None, "needs_review"
    started = time.perf_counter()
    with patch.object(runtime.model.processor, "transform_record", new=transform), \
         patch.object(runtime.model, "extract_entities", new=extract):
        try:
            response = runtime.infer(text, copy.deepcopy(labels), splitter=SPLITTER, threshold=THRESHOLD)
            status = "ok"
        except Exception as exc:
            error = "input_budget_exceeded" if type(exc) is ValueError and exc.args == ("input_budget_exceeded",) else "encoder_failure"
    elapsed = time.perf_counter()-started
    if not encoded or encoded[0]["max_len"] is not None:
        status, error = "needs_review", "unverified_untruncated_preflight"
    elif encoded[0]["input_ids"] > TOKEN_LIMIT and (calls[0] != 0 or error != "input_budget_exceeded"):
        status, error = "needs_review", "encoded_budget_contract_broken"
    if calls[0] > 1:
        status, error = "needs_review", "encoder_call_cap_broken"
    if status == "ok" and calls[0] != 1:
        status, error = "needs_review", "encoder_call_not_observed"
    return {"status": status, "error": error, "raw_result": response, "runtime_infer_attempts": 1,
        "extract_entities_calls": calls[0], "encoding_observations": encoded, "elapsed_seconds": elapsed}


def _findings(text, raw, labels, reverse):
    if not isinstance(raw, dict) or set(raw) != {"entities"} or not isinstance(raw["entities"], dict):
        raise ValueError("invalid_encoder_envelope")
    findings = []
    for label, values in raw["entities"].items():
        if label not in labels or not isinstance(values, list):
            raise ValueError("invalid_encoder_label")
        for value in values:
            if not isinstance(value, dict):
                raise ValueError("invalid_encoder_span")
            a, b, quote, confidence = (value.get(k) for k in ("start", "end", "text", "confidence"))
            if (type(a) is not int or type(b) is not int or not 0 <= a < b <= len(text)
                    or quote != text[a:b] or type(confidence) not in (int, float)
                    or not math.isfinite(confidence) or not THRESHOLD <= confidence <= 1):
                raise ValueError("invalid_encoder_span")
            findings.append({"start": a, "end": b, "quote": quote, "category": reverse[label], "confidence": confidence})
    return sorted(findings, key=lambda f: (f["start"], f["end"], f["category"]))


def _gold_references(stories, evaluation, units):
    if set(evaluation) != {s["story_id"] for s in stories}:
        raise ValueError("evaluation_story_mismatch")
    by_story, references = {s["story_id"]: s for s in stories}, {}
    for unit in units:
        source = by_story[unit["story_id"]]["source"]["text"]
        source_spans = evaluation[unit["story_id"]]["sensitive_spans"]
        spans = set()
        for row in source_spans:
            a, b = row["start"], row["end"]
            if (type(a) is not int or type(b) is not int or not 0 <= a < b <= len(source)
                    or row.get("category", "CUSTOMER") != "CUSTOMER"):
                raise ValueError("invalid_registered_sensitive_reference")
            if unit["kind"] == "source":
                spans.add((a, b, "CUSTOMER"))
            else:
                value = source[a:b]
                spans.update((m.start(1), m.end(1), "CUSTOMER") for m in re.finditer("(?=("+re.escape(value)+"))", unit["text"]))
        references[unit["unit_id"]] = [{"start": a, "end": b, "category": c} for a, b, c in sorted(spans)]
    return references


def score_spans(row, reference):
    predicted = row["findings"] if row["status"] == "ok" else []
    gold = {(p, f["category"]) for f in reference for p in range(f["start"], f["end"])}
    found = {(p, f["category"]) for f in predicted for p in range(f["start"], f["end"])}
    complete = partial = missed = 0
    for f in reference:
        overlapping = [p for p in predicted if p["category"] == f["category"] and p["start"] < f["end"] and p["end"] > f["start"]]
        if any(p["start"] <= f["start"] and p["end"] >= f["end"] for p in overlapping):
            complete += 1
        elif overlapping:
            partial += 1
        else:
            missed += 1
    return {"gold_spans": len(reference), "complete": complete, "partial": partial, "missed": missed,
        "true_positive_characters": len(gold & found), "false_positive_characters": len(found-gold),
        "false_negative_characters": len(gold-found), "registered_sensitive_characters": len(gold),
        "predicted_characters": len(found), "all_complete_without_extra": row["status"] == "ok" and complete == len(reference) and not found-gold}


def summarize(rows):
    result = {}
    for arm in ("A", "B"):
        result[arm] = {}
        for kind in ("all", "source", "query"):
            chosen = [r for r in rows if r["arm"] == arm and (kind == "all" or r["kind"] == kind)]
            totals = {k: sum(r["score"][k] for r in chosen) for k in ("gold_spans", "complete", "partial", "missed",
                "true_positive_characters", "false_positive_characters", "false_negative_characters", "registered_sensitive_characters", "predicted_characters")}
            totals.update(registered_units=len(chosen), okay_units=sum(r["status"] == "ok" for r in chosen),
                failed_units=sum(r["status"] != "ok" for r in chosen),
                units_with_extra_characters=sum(r["score"]["false_positive_characters"] > 0 for r in chosen),
                all_complete_without_extra=sum(r["score"]["all_complete_without_extra"] for r in chosen))
            totals["character_recall"] = totals["true_positive_characters"]/totals["registered_sensitive_characters"] if totals["registered_sensitive_characters"] else None
            totals["character_precision"] = totals["true_positive_characters"]/totals["predicted_characters"] if totals["predicted_characters"] else None
            result[arm][kind] = totals
    paired = {r["unit_id"]: {} for r in rows}
    for row in rows:
        paired[row["unit_id"]][row["arm"]] = row
    result["paired"] = {"units": len(paired), "B_complete_regressions": sum(p["B"]["score"]["complete"] < p["A"]["score"]["complete"] for p in paired.values()),
        "B_false_positive_improvements": sum(p["B"]["score"]["false_positive_characters"] < p["A"]["score"]["false_positive_characters"] for p in paired.values()),
        "B_false_positive_regressions": sum(p["B"]["score"]["false_positive_characters"] > p["A"]["score"]["false_positive_characters"] for p in paired.values())}
    return result


def run(corpus, output, model_root, *, execute=False, approved_plan=None, runtime_factory=None, progress=None):
    corpus, output, model_root = Path(corpus), Path(output), Path(model_root)
    plan, stories, units, evaluation_bytes, files = _material(corpus, model_root)
    if execute:
        if approved_plan is None or _digest(json.loads(Path(approved_plan).read_bytes())) != _digest(plan):
            raise ValueError("matching_approved_plan_required_before_model_loading")
    output.mkdir(parents=True, exist_ok=False)
    for path in files:
        target = output/"implementation"/path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    save(output/"plan.json", plan)
    save(output/"units.json", units)
    save(output/"runtime.json", stories)
    if not execute:
        return {"status": "planned_only", "expected_rows": 80, "runtime_infer_attempts": 0, "model_loaded": False, "plan_sha256": _digest(plan)}
    runtime = (runtime_factory or LocalNerRuntime)(model_root)
    if (runtime.identity.get("model_id") != plan["model"]["model_id"] or runtime.identity.get("weights_sha256") != plan["model"]["weights_sha256"]):
        raise ValueError("loaded_model_identity_changed")
    save(output/"runtime_identity.json", {"identity": runtime.identity, "initialization_seconds": runtime.initialization_seconds,
        "injected_test_runtime": runtime_factory is not None})
    by_id, rows = {u["unit_id"]: u for u in units}, []
    for request in plan["execution_order"]:
        unit, arm = by_id[request["unit_id"]], request["arm"]
        active = {plan["schemas"][arm][cat][0]: plan["schemas"][arm][cat][1] for cat in POLICY["protected_categories"]}
        reverse = {plan["schemas"][arm][cat][0]: cat for cat in POLICY["protected_categories"]}
        observed = _infer(runtime, unit["text"], active)
        row = {**unit, "arm": arm, "text_sha256": sha(unit["text"]), "labels": active,
            "labels_sha256": _digest(active), "full_schema_sha256": plan["schema_sha256"][arm], **observed, "findings": []}
        if row["status"] == "ok":
            try:
                row["findings"] = _findings(unit["text"], row["raw_result"], active, reverse)
            except ValueError as exc:
                row.update(status="needs_review", error=str(exc))
        rows.append(row)
        save(output/"rows.json", rows)
        if progress:
            progress({"completed": len(rows), "expected": 80, "scored": False, "status": row["status"]})
    save(output/"model_phase.json", {"model_phase_closed": True, "registered_rows": 80, "recorded_rows": len(rows),
        "runtime_infer_attempts": sum(r["runtime_infer_attempts"] for r in rows), "extract_entities_calls": sum(r["extract_entities_calls"] for r in rows)})
    evaluation = json.loads(evaluation_bytes)
    references = _gold_references(stories, evaluation, units)
    for row in rows:
        row["reference"] = references[row["unit_id"]]
        row["score"] = score_spans(row, row["reference"])
    if (sha((corpus/"development/runtime.json").read_bytes()) != plan["runtime_sha256"]
            or sha((corpus/"development/evaluation.json").read_bytes()) != plan["evaluation_sha256"]
            or sha((model_root/"receipt.json").read_bytes()) != plan["runtime_receipt_sha256"]
            or {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in files} != plan["implementation_sha256"]):
        raise ValueError("frozen_implementation_or_input_changed")
    report = {"version": VERSION, "registered_units": 40, "registered_rows": 80, "recorded_rows": len(rows),
        "runtime_infer_attempts": sum(r["runtime_infer_attempts"] for r in rows),
        "extract_entities_calls": sum(r["extract_entities_calls"] for r in rows),
        "LLM_calls": 0, "cloud_calls": 0, "downloads": 0, "injected_test_runtime": runtime_factory is not None,
        "summary": summarize(rows), "scope": plan["scope"]}
    for name, value in (("rows.json", rows), ("evaluation.json", evaluation), ("references.json", references), ("report.json", report)):
        save(output/name, value)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/"results"):
        raise ValueError("new_project_results_directory_required")
    network = {"attempts_blocked": 0}
    def guard(event, _):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"}:
            network["attempts_blocked"] += 1
            raise RuntimeError("all_network_disabled_for_encoder_probe")
    sys.addaudithook(guard)
    report = run(ROOT/"examples/privacy_semantics_v1", output, ROOT/".runtime/github_ner", execute=args.execute,
        approved_plan=args.approved_plan, progress=lambda r: print(json.dumps(r), flush=True))
    save(output/"network_audit.json", network)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
