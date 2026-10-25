"""Plan-first source-only role span probe; 8 structure + 8 NER API cap.

Business roles never confer access or revise privacy classifications. No query,
original answer evaluation, authority, or registry value is model input.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
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
from memory_migration_study.ner_detector import CjkAwareSplitter, LocalNerRuntime, LABELS, MODEL_ID, MODEL_REVISION, CODE_REVISION
from memory_migration_study.privacy import _digest
from scripts.run_customer_schema_probe import _infer, _findings

VERSION = "source_role_span_prevalidation_v2"
ROLE_CONTRACT = "explicit_source_business_roles_v1"
SEED, TOKEN_LIMIT, THRESHOLD = 2026102521, 512, .5
ROLES = {
    "customer": "Named customer or client organization.",
    "buyer": "Named buyer or purchaser organization.",
    "consignee": "Named consignee organization.",
    "account_holder": "Named account-holder organization.",
    "audit_observer": "Named audit observer organization.",
    "carrier": "Named transport carrier organization.",
    "status": "Exact stated business or processing status.",
}
ALIASES = {
    "customer": ("customer", "client", "签约客户", "客户"),
    "buyer": ("buyer", "purchaser", "买方", "购买方"),
    "consignee": ("consignee organization", "consignee", "收货组织", "收货方", "收货人"),
    "account_holder": ("account holder", "账户持有人", "账号持有人"),
    "audit_observer": ("audit observer", "审计观察机构", "审计观察方"),
    "carrier": ("carrier", "承运机构", "承运商", "承运方"),
    "status": ("service stage", "transport condition", "certification outcome", "acceptance result",
               "business status", "service status", "服务环节", "运输环节", "认证结论", "验收结论", "业务状态", "服务状态"),
}
NER_LABELS = {LABELS["CUSTOMER"][0]: LABELS["CUSTOMER"][1]}


def sha(raw):
    return hashlib.sha256(raw if isinstance(raw, bytes) else raw.encode()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")


def _alias_pattern(values):
    parts = []
    for s in sorted(values, key=len, reverse=True):
        parts.append((r"(?<![A-Za-z])"+re.escape(s)+r"(?![A-Za-z])") if s.isascii() else re.escape(s))
    return "(?:"+"|".join(parts)+")"


def baseline_projection(text, source_id, ner_findings):
    """Exact NER spans plus nearest explicit prefix; no company/value dictionary."""
    anchors = [(m.start(), m.end(), role) for role, values in ALIASES.items() if role != "status"
        for m in re.finditer(_alias_pattern(values), text, re.I)]
    findings = []
    for f in ner_findings:
        eligible = [(a, b, role) for a, b, role in anchors if b <= f["start"] and f["start"]-b <= 32
            and re.fullmatch(r"[\s,:：，=＝|｜]*(?:(?:is|was|是|为)\s*)?", text[b:f["start"]], re.I)]
        if not eligible:
            continue
        best = max(b for _, b, _ in eligible)
        roles = {r for _, b, r in eligible if b == best}
        if len(roles) != 1:
            continue
        a, b, role = next(x for x in eligible if x[1] == best)
        findings.append({"role": role, "source_id": source_id, "start": f["start"], "end": f["end"],
            "quote": text[f["start"]:f["end"]], "confidence": f["confidence"],
            "method": "ner_nearest_explicit_role", "anchor_start": a, "anchor_end": b, "anchor_quote": text[a:b]})
    pattern = _alias_pattern(ALIASES["status"])+r"\s*(?::|：|=|＝|\bis\b|\bwas\b|登记为|是|为)\s*(?P<value>[^。；;\r\n.!?！？]+)"
    for m in re.finditer(pattern, text, re.I):
        a, b = m.span("value")
        while a < b and text[a].isspace():
            a += 1
        while b > a and text[b-1].isspace():
            b -= 1
        if a < b:
            findings.append({"role": "status", "source_id": source_id, "start": a, "end": b, "quote": text[a:b],
                "confidence": None, "method": "explicit_status_field", "anchor_start": m.start(), "anchor_end": m.start("value"),
                "anchor_quote": text[m.start():m.start("value")]})
    unique = {(f["role"], f["start"], f["end"]): f for f in findings}
    return sorted(unique.values(), key=lambda f: (f["start"], f["end"], f["role"]))


def native_findings(text, source_id, raw):
    """Accept actual native half-open offsets; never locate a missing first quote."""
    if raw == {} or raw == {"business_roles": []}:
        raise ValueError("native_empty_no_records")
    if not isinstance(raw, dict) or set(raw) != {"business_roles"} or not isinstance(raw["business_roles"], list) or len(raw["business_roles"]) > 32:
        raise ValueError("native_role_envelope_invalid")
    found = {}
    for index, record in enumerate(raw["business_roles"]):
        if not isinstance(record, dict) or set(record) != set(ROLES) | {"confidence"}:
            raise ValueError("native_role_record_fields_invalid")
        confidence = record["confidence"]
        if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("native_role_record_confidence_invalid")
        for role, values in record.items():
            if role == "confidence":
                continue
            if not isinstance(values, list):
                raise ValueError("native_role_value_list_required")
            for value in values:
                if not isinstance(value, dict) or set(value) != {"text", "start", "end", "confidence"}:
                    raise ValueError("native_role_exact_span_fields_required")
                a, b, quote, confidence = (value[k] for k in ("start", "end", "text", "confidence"))
                if (type(a) is not int or type(b) is not int or not 0 <= a < b <= len(text)
                        or not isinstance(quote, str) or text[a:b] != quote or not quote.strip()
                        or type(confidence) not in (int, float) or not math.isfinite(confidence) or not THRESHOLD <= confidence <= 1):
                    raise ValueError("native_role_span_not_exact")
                key = role, a, b
                if key in found:
                    found[key]["record_indices"].append(index)
                else:
                    found[key] = {"role": role, "source_id": source_id, "start": a, "end": b, "quote": quote,
                        "confidence": confidence, "record_indices": [index], "method": "native_anchorless_structure"}
    if len(found) > 128:
        raise ValueError("native_role_candidate_budget_exceeded")
    return sorted(found.values(), key=lambda f: (f["start"], f["end"], f["role"]))


def _shape(value):
    shape = getattr(value, "shape", None)
    return [int(x) for x in shape] if shape is not None else None


@contextmanager
def inference_observer(runtime, text):
    """Observe actual frozen native decode/encode/encoder calls, without results mutation."""
    model = runtime.model
    observed = {"decoder_batch_calls": 0, "encode_tokens_calls": 0, "encoder_forward_calls": 0,
        "native_batch_observations": [], "encoder_observations": [],
        "observer_available": {name: callable(getattr(model, name, None)) for name in ("_extract_from_batch", "encode_tokens")}}
    encoder = getattr(model, "encoder", None)
    observed["observer_available"]["encoder_forward"] = callable(getattr(encoder, "forward", None))
    if not all(observed["observer_available"].values()):
        raise ValueError("native_inference_observer_unavailable")
    original_decode, original_encode, original_forward = model._extract_from_batch, model.encode_tokens, encoder.forward
    def decode(*args, **kwargs):
        observed["decoder_batch_calls"] += 1
        batch = args[0] if args else kwargs["batch"]
        metadata = args[2] if len(args) > 2 else kwargs["metadata_list"]
        texts = getattr(batch, "original_texts", [])
        expected = text if text.endswith((".", "!", "?")) else text+"."
        mapping = [{"native_text_sha256": sha(t), "original_prefix_exact": t.startswith(text),
            "added_suffix": t[len(text):] if t.startswith(text) else None,
            "matches_pinned_normalization": t == expected} for t in texts]
        if len(mapping) != 1 or not all(m["matches_pinned_normalization"] for m in mapping):
            raise ValueError("native_source_normalization_not_prefix")
        specs = []
        for sample in getattr(batch, "record_specs", ()):
            specs.append([{"task_index": int(i), "task_name": spec.task_name, "mode": spec.mode,
                "anchor_query_id": spec.anchor_query_id, "fields": [{"name": f.name, "query_id": int(f.query_id),
                    "cardinality": getattr(f.cardinality, "value", str(f.cardinality)), "exclusive": bool(f.exclusive)} for f in spec.fields]}
                for i, spec in sample.items()])
        observed["native_batch_observations"].append({"input_ids_shape": _shape(getattr(batch, "input_ids", None)),
            "text_mapping": mapping, "record_specs": specs,
            "metadata": [{"field_metadata": deepcopy(m.get("field_metadata", {})), "field_orders": deepcopy(m.get("field_orders", {})),
                "field_metadata_count": len(m.get("field_metadata", {}))} for m in metadata]})
        return original_decode(*args, **kwargs)
    def encode(*args, **kwargs):
        observed["encode_tokens_calls"] += 1
        hidden = args[1] if len(args) > 1 else kwargs.get("hidden_states")
        if hidden is not None:
            raise ValueError("unregistered_precomputed_encoder_states")
        return original_encode(*args, **kwargs)
    def forward(*args, **kwargs):
        observed["encoder_forward_calls"] += 1
        ids = kwargs.get("input_ids", args[0] if args else None)
        shape = _shape(ids)
        observed["encoder_observations"].append({"input_ids_shape": shape, "input_ids_parameter_present": ids is not None})
        if shape is None or len(shape) != 2 or shape[0] != 1 or not 0 < shape[1] <= TOKEN_LIMIT:
            raise ValueError("actual_encoder_input_budget_invalid")
        return original_forward(*args, **kwargs)
    with patch.object(model, "_extract_from_batch", new=decode), patch.object(model, "encode_tokens", new=encode), patch.object(encoder, "forward", new=forward):
        yield observed


def structure_call(runtime, text, source_id):
    started, calls, encoded, raw, compiled, native_schema = time.perf_counter(), 0, [], None, None, None
    schema_metadata, inference = None, {}
    status, error, findings = "needs_review", None, []
    try:
        with runtime.lock:
            runtime.model.processor.word_splitter = CjkAwareSplitter()
            native_schema = runtime.model.create_schema()
            builder = native_schema.structure("business_roles", mode="anchorless")
            for role, description in ROLES.items():
                builder.field(role, dtype="list", description=description)
            compiled = native_schema.build()
            schema_metadata = {"field_metadata": deepcopy(native_schema._field_metadata), "field_orders": deepcopy(native_schema._field_orders)}
            original = runtime.model.processor.transform_record
            def transform(*args, **kwargs):
                maximum = kwargs.get("max_len", args[2] if len(args) > 2 else None)
                actual_text, actual_schema = args[:2]
                actual_schema = actual_schema.build() if callable(getattr(actual_schema, "build", None)) else actual_schema
                if maximum is not None or actual_text != text or _digest(actual_schema) != _digest(compiled):
                    raise ValueError("structure_preflight_input_changed")
                transformed = original(*args, **kwargs)
                encoded.append({"input_ids": len(transformed.input_ids), "max_len": maximum, "schema_sha256": _digest(actual_schema)})
                if len(transformed.input_ids) > TOKEN_LIMIT:
                    raise ValueError("input_budget_exceeded")
                return transformed
            with inference_observer(runtime, text) as inference, patch.object(runtime.model.processor, "transform_record", new=transform):
                # Measure the complete native schema before entering extraction.
                runtime.model.processor.transform_record(text, deepcopy(compiled), max_len=None)
                calls = 1
                raw = runtime.model.extract(text, native_schema, threshold=THRESHOLD, format_results=True,
                    include_confidence=True, include_spans=True, max_len=None)
            if any(inference[k] != 1 for k in ("decoder_batch_calls", "encode_tokens_calls", "encoder_forward_calls")):
                raise ValueError("native_structure_inference_not_observed")
            findings = native_findings(text, source_id, raw)
            status = "ok"
    except Exception as exc:
        allowed = {"input_budget_exceeded", "structure_preflight_input_changed", "native_role_envelope_invalid",
            "native_role_record_fields_invalid", "native_role_value_list_required", "native_role_exact_span_fields_required",
            "native_role_span_not_exact", "native_role_candidate_budget_exceeded", "native_role_record_confidence_invalid",
            "native_empty_no_records",
            "native_inference_observer_unavailable", "native_structure_inference_not_observed", "native_source_normalization_not_prefix",
            "unregistered_precomputed_encoder_states", "actual_encoder_input_budget_invalid"}
        error = exc.args[0] if type(exc) is ValueError and exc.args and exc.args[0] in allowed else "native_structure_api_or_execution_failed"
    return {"status": status, "error": error, "findings": findings, "raw_result": raw,
        "compiled_schema": compiled, "compiled_schema_sha256": _digest(compiled) if compiled is not None else None,
        "native_schema_metadata": schema_metadata, "schema_object_preserved": native_schema is not None,
        "inference_observations": inference, "extract_api_calls": calls, "encoding_observations": encoded, "elapsed_seconds": time.perf_counter()-started}


def _material(corpus, model_root, reference):
    raw = (corpus/"development/runtime.json").read_bytes()
    runtime = json.loads(raw)
    sources = [{"story_id": s["story_id"], "language": s["language"], **deepcopy(s["source"])} for s in runtime]
    if len(sources) != 8 or len({s["story_id"] for s in sources}) != 8 or Counter(s["language"] for s in sources) != {"en": 4, "zh": 4}:
        raise ValueError("registered_eight_exposed_sources_required")
    receipt_bytes, config_bytes = (model_root/"receipt.json").read_bytes(), (model_root/"model/config.json").read_bytes()
    receipt, config = json.loads(receipt_bytes), json.loads(config_bytes)
    if any(receipt.get(k) != v for k, v in {"model_id": MODEL_ID, "model_revision": MODEL_REVISION, "code_revision": CODE_REVISION}.items()):
        raise ValueError("fixed_encoder_revision_required")
    files = list((ROOT/"memory_migration_study").glob("*.py"))+[Path(__file__), ROOT/"scripts/run_customer_schema_probe.py"]
    plan = {"version": VERSION, "role_contract_version": ROLE_CONTRACT, "mode": "anchorless", "roles": ROLES,
        "dtype": "list", "threshold": THRESHOLD, "splitter": "cjk_aware", "max_encoded_tokens": TOKEN_LIMIT,
        "expected_sources": 8, "expected_rows": 16, "registered_extraction_api_budget": {"structure": 8, "baseline_ner": 8, "total": 16},
        "api_count_unit": "invoked public model.extract / extract_entities APIs after complete untruncated encoding checks, not unique GPU batches",
        "retry_count": 0, "generative_model_calls": 0, "network_allowed": False, "ordering_seed": SEED,
        "runtime_sha256": sha(raw), "reference_sha256": sha(reference.read_bytes()) if reference else None,
        "reference_evaluation_timing": "parse only after every structure and baseline slot ends and model_phase_closed",
        "runtime_receipt_sha256": sha(receipt_bytes), "model_config_sha256": sha(config_bytes),
        "model": {k: receipt[k] for k in ("model_id", "model_revision", "code_revision")},
        "weights_sha256": receipt["files"]["model/model.safetensors"],
        "configured_heads_not_training_or_quality_evidence": {k: config.get("boundary_head", {}).get(k) for k in ("enable_records", "enable_relations")},
        "implementation_sha256": {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in files},
        "sources": [{"story_id": s["story_id"], "source_id": s["source_id"], "language": s["language"], "source_sha256": sha(s["text"])} for s in sources],
        "baseline": {"ner_labels": NER_LABELS, "explicit_role_anchors": ALIASES, "maximum_prefix_gap": 32,
            "source_value_or_gold_dictionary": False, "status_projection": "fixed generic status key/copula to sentence or line boundary"},
        "business_role_not_privacy_category": True, "customer_contract": "only explicit customer/client; buyer, consignee and account holder do not imply customer",
        "span_contract": "native exact coordinates required; repeated surfaces retain distinct offsets; no first-match recovery; same role/occurrence duplicates retain record provenance",
        "native_record_shape": "business_roles records contain exactly seven list fields plus finite numeric record confidence; every value has text/start/end/confidence",
        "inference_observer": "actual _extract_from_batch, encode_tokens and encoder.forward counted separately from API calls; native batch metadata/record specs and known suffix-period normalization retained",
        "input_contract": "original source text and fixed schema only; no task query, reference, registry values, ACL or authority input",
        "scope": "Eight exposed development sources. Role-value sets only, no relation graph, permission change, privacy acceptance, downstream utility or novelty claim.",
        "api_choice": {"public_api": "retain actual model.create_schema() object; structure(mode='anchorless').field(dtype='list',description=...); model.extract(source, original Schema object); build() dict only preflight/hash",
            "reason": "fixed extract_json convenience API selects natural mode and first customer field as anchor; this independent-role probe explicitly avoids that before execution",
            "v1_adapter_limit": "v1 passed build() dictionary and lost runtime field_metadata/orders; this is real metadata loss, but not established as the sole cause of v1 empty results. V1 archives stay unchanged.",
            "source": "https://github.com/fastino-ai/GLiNER2/blob/ca4f68235b50fe4c3ecf3876851d748fe4b15c6c/gliner2/inference/runtime.py#L2090"}}
    return plan, sources, files


def _reference(value, sources):
    if value.get("version") != "source_roles_reference_v1" or value.get("role_contract_version") != ROLE_CONTRACT:
        raise ValueError("reference_contract_mismatch")
    rows = value.get("stories")
    if not isinstance(rows, list) or len(rows) != 8 or {r["story_id"] for r in rows} != {s["story_id"] for s in sources}:
        raise ValueError("reference_source_matrix_mismatch")
    result, by_id = {}, {s["story_id"]: s for s in sources}
    for row in rows:
        s, annotations = by_id[row["story_id"]], row.get("annotations")
        if row.get("source_id") != s["source_id"] or row.get("source_sha256") != sha(s["text"]) or not isinstance(annotations, list):
            raise ValueError("reference_source_binding_invalid")
        seen = set()
        for a in annotations:
            if a.get("role") not in ROLES or a.get("source_id") != s["source_id"]:
                raise ValueError("reference_role_invalid")
            for start, end, quote in (("start", "end", "quote"), ("support_start", "support_end", "support_quote")):
                x, y = a.get(start), a.get(end)
                if type(x) is not int or type(y) is not int or not 0 <= x < y <= len(s["text"]) or s["text"][x:y] != a.get(quote):
                    raise ValueError("reference_span_not_exact")
            if not a["support_start"] <= a["start"] < a["end"] <= a["support_end"] or (a["role"], a["start"], a["end"]) in seen:
                raise ValueError("reference_scope_or_duplicate_invalid")
            seen.add((a["role"], a["start"], a["end"]))
        result[s["story_id"]] = annotations
    return result


def score(row, reference):
    predicted = {(f["role"], f["start"], f["end"]) for f in row["findings"]} if row["status"] == "ok" else set()
    truth = {(f["role"], f["start"], f["end"]) for f in reference}
    return {"tp": len(predicted & truth), "fp": len(predicted-truth), "fn": len(truth-predicted),
        "per_role": {role: {"tp": len({x for x in predicted & truth if x[0] == role}), "fp": len({x for x in predicted-truth if x[0] == role}),
            "fn": len({x for x in truth-predicted if x[0] == role})} for role in ROLES}}


def run(corpus, output, model_root, *, execute=False, approved_plan=None, reference=None, runtime_factory=None, progress=None):
    corpus, output, model_root = map(Path, (corpus, output, model_root))
    reference = Path(reference) if reference else None
    plan, sources, files = _material(corpus, model_root, reference)
    if execute and (not approved_plan or not reference or _digest(json.loads(Path(approved_plan).read_bytes())) != _digest(plan)):
        raise ValueError("exact_preapproved_plan_and_frozen_reference_required")
    output.mkdir(parents=True, exist_ok=False)
    save(output/"plan.json", plan)
    save(output/"sources.json", sources)
    if not execute:
        result = {"status": "planned_only", "structure_api_calls": 0, "ner_api_calls": 0, "generative_model_calls": 0, "reference_parsed": False}
        save(output/"report.json", result)
        return result
    reference_bytes = reference.read_bytes()  # Hash-bound bytes, deliberately not parsed yet.
    for file in files:
        target = output/"implementation"/file.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, target)
    runtime = (runtime_factory or LocalNerRuntime)(model_root)
    save(output/"runtime_identity.json", {"identity": runtime.identity, "initialization_seconds": runtime.initialization_seconds,
        "injected_test_runtime": runtime_factory is not None})
    rows = []
    for source in sources:
        arms = ["structure", "baseline_ner_projection"]
        random.Random(str(SEED)+source["story_id"]).shuffle(arms)
        for arm in arms:
            if arm == "structure":
                observed = structure_call(runtime, source["text"], source["source_id"])
            else:
                inference = {}
                try:
                    with inference_observer(runtime, source["text"]) as inference:
                        observed = _infer(runtime, source["text"], NER_LABELS)
                except ValueError:
                    observed = {"status": "needs_review", "error": "baseline_inference_observer_unavailable", "raw_result": None,
                        "runtime_infer_attempts": 0, "extract_entities_calls": 0, "encoding_observations": [], "elapsed_seconds": 0}
                observed["inference_observations"] = inference
                findings = []
                if observed["status"] == "ok":
                    try:
                        candidates = _findings(source["text"], observed["raw_result"], NER_LABELS, {next(iter(NER_LABELS)): "CUSTOMER"})
                        findings = baseline_projection(source["text"], source["source_id"], candidates)
                        observed["ner_candidate_findings"] = candidates
                    except ValueError:
                        observed.update(status="needs_review", error="baseline_ner_span_invalid")
                observed.update(findings=findings, extract_api_calls=observed["extract_entities_calls"])
            row = {"story_id": source["story_id"], "source_id": source["source_id"], "language": source["language"],
                "source_sha256": sha(source["text"]), "arm": arm, **observed}
            rows.append(row)
            save(output/"rows.json", rows)
            if progress:
                progress({"completed": len(rows), "expected": 16, "source": source["story_id"], "arm": arm, "scored": False})
    save(output/"model_phase.json", {"model_phase_closed": True, "completed_slots": len(rows),
        "structure_api_calls": sum(r["extract_api_calls"] for r in rows if r["arm"] == "structure"),
        "ner_api_calls": sum(r["extract_api_calls"] for r in rows if r["arm"] != "structure")})
    if len(rows) != 16 or sha(reference.read_bytes()) != plan["reference_sha256"] or sha(reference_bytes) != plan["reference_sha256"]:
        raise ValueError("source_probe_matrix_or_reference_changed")
    reference_value = json.loads(reference_bytes)
    references = _reference(reference_value, sources)
    for row in rows:
        row["score"] = score(row, references[row["story_id"]])
    hashes = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in files}
    if hashes != plan["implementation_sha256"] or sha((corpus/"development/runtime.json").read_bytes()) != plan["runtime_sha256"]:
        raise ValueError("probe_implementation_or_source_changed")
    save(output/"rows.json", rows)
    save(output/"reference.json", reference_value)
    report = {"version": VERSION, "status": "completed", "expected_rows": 16, "recorded_rows": len(rows), "source_stories": 8,
        "reference_items": sum(len(v) for v in references.values()), "reference_parsed_after_model_phase": True,
        "generative_model_calls": 0, "cloud_calls": 0, "new_api_cost_cny": 0, "implementation_unchanged": True,
        "arms": {}, "scope": plan["scope"]}
    for arm in ("structure", "baseline_ner_projection"):
        selected = [r for r in rows if r["arm"] == arm]
        cell = {"units": len(selected), "valid_span_outputs": sum(r["status"] == "ok" for r in selected),
            "needs_review": sum(r["status"] != "ok" for r in selected), "extract_api_calls": sum(r["extract_api_calls"] for r in selected),
            **{k: sum(r.get("inference_observations", {}).get(k, 0) for r in selected) for k in ("decoder_batch_calls", "encode_tokens_calls", "encoder_forward_calls")},
            **{k: sum(r["score"][k] for r in selected) for k in ("tp", "fp", "fn")},
            "per_role": {role: {k: sum(r["score"]["per_role"][role][k] for r in selected) for k in ("tp", "fp", "fn")} for role in ROLES}}
        cell.update(precision=cell["tp"]/(cell["tp"]+cell["fp"]) if cell["tp"]+cell["fp"] else None,
            recall=cell["tp"]/(cell["tp"]+cell["fn"]) if cell["tp"]+cell["fn"] else None)
        report["arms"][arm] = cell
    report["total_extraction_api_calls"] = sum(c["extract_api_calls"] for c in report["arms"].values())
    report["actual_encoder_forward_calls"] = sum(c["encoder_forward_calls"] for c in report["arms"].values())
    if (report["total_extraction_api_calls"] > 16 or report["actual_encoder_forward_calls"] > 16
            or any(c["extract_api_calls"] > 8 or c["encoder_forward_calls"] > 8 for c in report["arms"].values())):
        raise ValueError("registered_api_budget_exceeded")
    save(output/"report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    parser.add_argument("--reference", type=Path, default=ROOT/"examples/privacy_semantics_v1/development/source_roles_reference_v1.json")
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/"results"):
        raise ValueError("new_project_results_directory_required")
    network = {"attempts_blocked": 0}
    def guard(name, values):
        if name in {"socket.connect", "socket.getaddrinfo", "socket.sendto"}:
            network["attempts_blocked"] += 1
            raise RuntimeError("source_role_probe_network_disabled")
    sys.addaudithook(guard)
    try:
        result = run(ROOT/"examples/privacy_semantics_v1", args.output, ROOT/".runtime/github_ner", execute=args.run,
            approved_plan=args.approved_plan, reference=args.reference, progress=lambda v: print(json.dumps(v), flush=True))
        print(json.dumps(result, ensure_ascii=False))
    finally:
        if args.output.is_dir():
            save(args.output/"network_audit.json", network)


if __name__ == "__main__":
    main()
