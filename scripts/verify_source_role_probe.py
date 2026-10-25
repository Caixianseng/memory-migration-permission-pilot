"""Small independent, zero-inference audit of the 16-slot source-role probe."""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_reference_memory_study import digest, sha, require, equal, _literal_assignment

ARMS = ("structure", "baseline_ner_projection")
VERSION = "source_role_span_prevalidation_v1"
REFERENCE_SHA = "8693b5cd8e682de5eee08783ca623dc57b5329cb19d531d7e8be97a41c2926a2"


def full_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for piece in iter(lambda: stream.read(4*1024*1024), b""):
            h.update(piece)
    return h.hexdigest()


def valid_span(value, text):
    require(isinstance(value, dict), "raw_span_type")
    a, b, quote, confidence = (value.get(k) for k in ("start", "end", "text", "confidence"))
    require(type(a) is int and type(b) is int and 0 <= a < b <= len(text) and text[a:b] == quote
            and isinstance(quote, str) and quote.strip() and type(confidence) in (int, float)
            and math.isfinite(confidence) and .5 <= confidence <= 1, "raw_span_not_exact")
    return a, b, quote, confidence


def role_pattern(values):
    return "(?:"+"|".join((r"(?<![A-Za-z])"+re.escape(v)+r"(?![A-Za-z])") if v.isascii() else re.escape(v)
                           for v in sorted(values, key=len, reverse=True))+ ")"


def baseline(text, source_id, raw, aliases, label):
    require(isinstance(raw, dict) and set(raw) == {"entities"} and isinstance(raw["entities"], dict)
            and not(set(raw["entities"])-{label}), "ner_raw_envelope")
    candidates, found = [], {}
    anchors = [(m.start(), m.end(), role) for role, names in aliases.items() if role != "status"
               for m in re.finditer(role_pattern(names), text, re.I)]
    for values in raw["entities"].values():
        require(isinstance(values, list), "ner_raw_list")
        for value in values:
            a, b, quote, confidence = valid_span(value, text)
            candidates.append({"start": a, "end": b, "quote": quote, "category": "CUSTOMER", "confidence": confidence})
            choices = [(y, x, role) for x, y, role in anchors if 0 <= a-y <= 32 and re.fullmatch(r"[\s,:：，=＝|｜]*(?:(?:is|was|是|为)\s*)?", text[y:a], re.I)]
            if not choices:
                continue
            nearest = max(y for y, _, _ in choices)
            close = [(x, role) for y, x, role in choices if y == nearest]
            if len({role for _, role in close}) == 1:
                x, role = close[0]
                found[(role, a, b)] = {"role": role, "source_id": source_id, "start": a, "end": b, "quote": quote,
                    "confidence": confidence, "method": "ner_nearest_explicit_role", "anchor_start": x, "anchor_end": nearest, "anchor_quote": text[x:nearest]}
    status = role_pattern(aliases["status"])+r"\s*(?::|：|=|＝|\bis\b|\bwas\b|登记为|是|为)\s*(?P<value>[^。；;\r\n.!?！？]+)"
    for m in re.finditer(status, text, re.I):
        left, right = m.span("value")
        a = left+len(text[left:right])-len(text[left:right].lstrip())
        b = right-(len(text[left:right])-len(text[left:right].rstrip()))
        if a < b:
            found[("status", a, b)] = {"role": "status", "source_id": source_id, "start": a, "end": b, "quote": text[a:b], "confidence": None,
                "method": "explicit_status_field", "anchor_start": m.start(), "anchor_end": left, "anchor_quote": text[m.start():left]}
    return sorted(candidates, key=lambda f: (f["start"], f["end"], f["category"])), sorted(found.values(), key=lambda f: (f["start"], f["end"], f["role"]))


def native(text, source_id, raw, roles):
    if not isinstance(raw, dict) or set(raw) != {"business_roles"} or not isinstance(raw["business_roles"], list) or len(raw["business_roles"]) > 32:
        return [], "native_role_envelope_invalid"
    found = {}
    for i, record in enumerate(raw["business_roles"]):
        require(isinstance(record, dict) and set(record) == set(roles), "native_role_fields")
        for role, values in record.items():
            require(isinstance(values, list), "native_role_list")
            for value in values:
                require(set(value) == {"text", "start", "end", "confidence"}, "native_raw_extra_fields")
                a, b, quote, confidence = valid_span(value, text)
                key = role, a, b
                if key in found:
                    found[key]["record_indices"].append(i)
                else:
                    found[key] = {"role": role, "source_id": source_id, "start": a, "end": b, "quote": quote, "confidence": confidence,
                                  "record_indices": [i], "method": "native_anchorless_structure"}
    require(len(found) <= 128, "native_candidate_budget")
    return sorted(found.values(), key=lambda f: (f["start"], f["end"], f["role"])), None


def verify(directory, *, root=ROOT, approved_plan=None):
    run, root = Path(directory).resolve(), Path(root).resolve()
    names = ("plan", "sources", "rows", "reference", "report", "model_phase", "runtime_identity", "network_audit")
    values = {n: json.loads((run/(n+".json")).read_bytes()) for n in names}
    plan, sources, rows, reference, report = (values[n] for n in ("plan", "sources", "rows", "reference", "report"))
    require(plan["version"] == VERSION and plan["role_contract_version"] == "explicit_source_business_roles_v1" and plan["mode"] == "anchorless"
            and plan["dtype"] == "list" and plan["threshold"] == .5 and plan["splitter"] == "cjk_aware" and plan["max_encoded_tokens"] == 512
            and plan["expected_sources"] == 8 and plan["expected_rows"] == 16 and plan["retry_count"] == plan["generative_model_calls"] == 0
            and plan["network_allowed"] is False and plan["ordering_seed"] == 2026102521, "registered_protocol")
    equal(plan["registered_extraction_api_budget"], {"structure": 8, "baseline_ner": 8, "total": 16}, "registered_api_budget")
    approved = Path(approved_plan or root/"results/source_role_probe_plan_20261025_v1/plan.json")
    equal(json.loads(approved.read_bytes()), plan, "approved_plan_changed")
    require(values["model_phase"]["model_phase_closed"] is True and report["status"] == "completed", "not_terminal")
    paths, identical = {}, True
    for name, expected in plan["implementation_sha256"].items():
        rel = Path(name.replace("\\", "/"))
        require(not rel.is_absolute() and ".." not in rel.parts and rel.suffix == ".py", "unsafe_archive")
        saved, current = run/"implementation"/rel, root/rel
        equal(full_sha(saved), expected, "archive_hash")
        paths[rel.as_posix()] = saved
        identical = identical and current.is_file() and full_sha(current) == expected
    require(set(paths) == {p.relative_to(run/"implementation").as_posix() for p in (run/"implementation").rglob("*.py")}, "archive_inventory")
    require({"scripts/probe_source_roles.py", "scripts/run_customer_schema_probe.py", "memory_migration_study/ner_detector.py"} <= set(paths), "missing_archived_dependency")
    identical = identical and {"memory_migration_study/"+p.name for p in (root/"memory_migration_study").glob("*.py")} == {n for n in paths if n.startswith("memory_migration_study/")}
    driver = paths["scripts/probe_source_roles.py"]
    equal(_literal_assignment(driver, "VERSION"), VERSION, "archived_version")
    roles, aliases = (_literal_assignment(driver, n) for n in ("ROLES", "ALIASES"))
    equal(plan["roles"], roles, "fixed_roles")
    equal(plan["baseline"]["explicit_role_anchors"], aliases, "fixed_baseline_anchors")
    labels = _literal_assignment(paths["memory_migration_study/ner_detector.py"], "LABELS")["CUSTOMER"]
    equal(plan["baseline"]["ner_labels"], {labels[0]: labels[1]}, "baseline_ner_labels")
    tree = ast.parse(driver.read_text(encoding="utf-8-sig"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    loop = [n for n in fn.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "source"]
    closure = [n for n in fn.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id == "save"
               and n.value.args and isinstance(n.value.args[0], ast.BinOp) and isinstance(n.value.args[0].right, ast.Constant) and n.value.args[0].right.value == "model_phase.json"]
    parses = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "loads" and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "reference_bytes"]
    require(len(loop) == len(closure) == len(parses) == 1 and loop[0].end_lineno < closure[0].lineno < parses[0].lineno, "reference_before_closed")
    structure = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "structure_call")
    extract = [n for n in ast.walk(structure) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "extract"]
    require(len(extract) == 1, "single_structure_extract")
    options = {k.arg: .5 if isinstance(k.value, ast.Name) and k.value.id == "THRESHOLD" else ast.literal_eval(k.value) for k in extract[0].keywords}
    equal(options, {"threshold": .5, "format_results": True, "include_confidence": True, "include_spans": True, "max_len": None}, "actual_structure_extract_options")
    sourcebytes = (root/"examples/privacy_semantics_v1/development/runtime.json").read_bytes()
    equal(sha(sourcebytes), plan["runtime_sha256"], "runtime_hash")
    actualsources = [{"story_id": s["story_id"], "language": s["language"], **s["source"]} for s in json.loads(sourcebytes)]
    equal(sources, actualsources, "original_sources")
    require(len(sources) == len({s["story_id"] for s in sources}) == 8 and Counter(s["language"] for s in sources) == {"en": 4, "zh": 4}, "source_matrix")
    by_id = {s["story_id"]: s for s in sources}
    equal(plan["sources"], [{k: s[k] for k in ("story_id", "source_id", "language")} | {"source_sha256": sha(s["text"])} for s in sources], "source_manifest")
    refpath = root/"examples/privacy_semantics_v1/development/source_roles_reference_v1.json"
    require(full_sha(refpath) == plan["reference_sha256"] == REFERENCE_SHA, "reference_hash")
    equal(json.loads(refpath.read_bytes()), reference, "saved_reference_changed")
    equal((reference["version"], reference["role_contract_version"]), ("source_roles_reference_v1", "explicit_source_business_roles_v1"), "reference_contract")
    truth = {}
    require(len(reference["stories"]) == 8 and {s["story_id"] for s in reference["stories"]} == set(by_id), "reference_matrix")
    for item in reference["stories"]:
        source, target = by_id[item["story_id"]], set()
        equal((item["source_id"], item["source_sha256"]), (source["source_id"], sha(source["text"])), "reference_source")
        for f in item["annotations"]:
            require(f["role"] in roles and f["source_id"] == source["source_id"], "reference_role")
            for prefix in ("", "support_"):
                a, b = f[prefix+"start"], f[prefix+"end"]
                require(type(a) is int and type(b) is int and 0 <= a < b <= len(source["text"]) and source["text"][a:b] == f[prefix+"quote"], "reference_exact_span")
            key = (f["role"], f["start"], f["end"])
            require(key not in target and f["support_start"] <= f["start"] < f["end"] <= f["support_end"], "reference_duplicate_or_support")
            target.add(key)
        truth[item["story_id"]] = target
    modelroot = root/".runtime/github_ner"
    receiptbytes, configbytes = (modelroot/"receipt.json").read_bytes(), (modelroot/"model/config.json").read_bytes()
    require(sha(receiptbytes) == plan["runtime_receipt_sha256"] and sha(configbytes) == plan["model_config_sha256"], "runtime_receipt_or_config_hash")
    receipt, identity = json.loads(receiptbytes), values["runtime_identity"]
    require(identity["injected_test_runtime"] is False, "injected_runtime")
    equal({k: identity["identity"][k] for k in plan["model"]}, plan["model"], "model_identity")
    require(identity["identity"]["weights_sha256"] == plan["weights_sha256"] == receipt["files"]["model/model.safetensors"]
            and identity["identity"]["files_sha256"] == digest(receipt["files"]), "runtime_model_digest")
    equal(full_sha(modelroot/"model/model.safetensors"), plan["weights_sha256"], "actual_weights_hash")
    require(len(rows) == 16 and {(r["story_id"], r["arm"]) for r in rows} == {(s, a) for s in by_id for a in ARMS}, "probe_matrix")
    output, errors = {}, Counter()
    compiled = {"json_structures": [{"business_roles": {r: "" for r in roles}}], "classifications": [], "entities": {}, "relations": [],
                "json_descriptions": {"business_roles": roles}, "entity_descriptions": {}, "relation_descriptions": {}, "record_metadata": {"business_roles": {"mode": "anchorless"}}}
    for row in rows:
        source, arm = by_id[row["story_id"]], row["arm"]
        equal((row["source_id"], row["language"], row["source_sha256"]), (source["source_id"], source["language"], sha(source["text"])), "row_source")
        require(type(row["extract_api_calls"]) is int and 0 <= row["extract_api_calls"] <= 1, "row_api_count")
        encoding = row["encoding_observations"]
        require(encoding and all(type(e["input_ids"]) is int and e["input_ids"] >= 0 and e["max_len"] is None for e in encoding), "unverified_encoding")
        if any(e["input_ids"] > 512 for e in encoding):
            require(row["extract_api_calls"] == 0 and row["status"] == "needs_review" and row["error"] == "input_budget_exceeded", "overflow_extraction")
        if arm == "structure":
            equal(row["compiled_schema"], compiled, "actual_structure_schema")
            equal(row["compiled_schema_sha256"], digest(compiled), "actual_structure_schema_hash")
            require(all(e["schema_sha256"] == digest(compiled) for e in encoding), "encoded_schema_hash")
            expected, error = native(source["text"], source["source_id"], row["raw_result"], roles)
            equal((row["status"], row["error"]), ("ok", None) if error is None else ("needs_review", error), "native_host_status")
            if error:
                errors[error] += 1
        else:
            equal((row["runtime_infer_attempts"], row["extract_entities_calls"]), (1, row["extract_api_calls"]), "baseline_api_count")
            candidates, expected = baseline(source["text"], source["source_id"], row["raw_result"], aliases, labels[0])
            require(row["status"] == "ok" and row["error"] is None, "baseline_failed")
            equal(row["ner_candidate_findings"], candidates, "raw_ner_conversion")
        equal(row["findings"], expected, "raw_to_final_findings")
        predictions = {(f["role"], f["start"], f["end"]) for f in expected} if row["status"] == "ok" else set()
        actual, target = predictions, truth[row["story_id"]]
        score = {"tp": len(actual&target), "fp": len(actual-target), "fn": len(target-actual), "per_role": {role: {"tp": sum(x[0] == role for x in actual&target), "fp": sum(x[0] == role for x in actual-target), "fn": sum(x[0] == role for x in target-actual)} for role in roles}}
        equal(row["score"], score, "independent_set_score")
    for arm in ARMS:
        selected = [r for r in rows if r["arm"] == arm]
        cell = {"units": len(selected), "valid_span_outputs": sum(r["status"] == "ok" for r in selected), "needs_review": sum(r["status"] != "ok" for r in selected),
                "extract_api_calls": sum(r["extract_api_calls"] for r in selected), **{k: sum(r["score"][k] for r in selected) for k in ("tp", "fp", "fn")},
                "per_role": {role: {k: sum(r["score"]["per_role"][role][k] for r in selected) for k in ("tp", "fp", "fn")} for role in roles}}
        cell.update(precision=cell["tp"]/(cell["tp"]+cell["fp"]) if cell["tp"]+cell["fp"] else None, recall=cell["tp"]/(cell["tp"]+cell["fn"]) if cell["tp"]+cell["fn"] else None)
        output[arm] = cell
    equal(report["arms"], output, "independent_aggregate")
    count = sum(r["extract_api_calls"] for r in rows)
    require(count <= 16 and all(c["extract_api_calls"] <= 8 for c in output.values()), "physical_api_cap")
    equal(values["model_phase"], {"model_phase_closed": True, "completed_slots": 16, "structure_api_calls": output["structure"]["extract_api_calls"], "ner_api_calls": output["baseline_ner_projection"]["extract_api_calls"]}, "model_phase_counts")
    for k, expected in {"version": VERSION, "expected_rows": 16, "recorded_rows": 16, "source_stories": 8, "reference_items": sum(map(len, truth.values())), "reference_parsed_after_model_phase": True,
                        "generative_model_calls": 0, "cloud_calls": 0, "new_api_cost_cny": 0, "implementation_unchanged": True, "total_extraction_api_calls": count}.items():
        equal(report[k], expected, "report_"+k)
    equal(values["network_audit"], {"attempts_blocked": 0}, "network_audit")
    return {"version": "independent_source_role_probe_v1", "status": "passed", "registered_rows": 16, "reference_items": sum(map(len, truth.values())),
        "arms": output, "native_failure_codes": dict(errors), "actual_extraction_api_calls": count, "maximum_encoded_tokens_observed": max(e["input_ids"] for r in rows for e in r["encoding_observations"]),
        "current_snapshot_identical": bool(identical), "actual_weights_sha256_verified": True, "verification_model_calls": 0, "actual_neural_forward_count": None,
        "evidence_sha256": {n+".json": full_sha(run/(n+".json")) for n in names}, "verifier_sha256": full_sha(Path(__file__)),
        "limits": ["Evidence consistency only, not effect acceptance or proof that public hashes authenticate execution.", "AI-precompiled/root-Agent-reviewed exposed-source role reference; not independent human or blind annotation.",
                   "Extraction API invocations are counted; actual neural forward calls were not instrumented. Empty raw output may arise from API/schema adaptation and is not proof of model inability.",
                   "Native empty output is preserved as needs_review with the full missed-reference denominator.", "Source role sets are not downstream answers, privacy detection acceptance, relation graphs, authority or an innovation claim."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), "new_receipt_required")
    result = verify(args.run, approved_plan=args.approved_plan)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
    print(json.dumps({k: result[k] for k in ("status", "registered_rows", "arms", "native_failure_codes", "actual_extraction_api_calls")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
