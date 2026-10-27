"""Optional pinned GLiNER entity-attribute baseline; no model import at import time.

Native attributes are scored on retained extracted spans, not on a supplied
candidate pool. Two policy replays share one extract; entry counters are nested
observations and must not be summed as independent neural/model invocations.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import threading

from .relation_occurrence import BUSINESS_SCOPE, CLASS_LABELS, GLINER_GUIDE
from .sensitivity_contract import category_contract_identity

VERSION = "native_span_attributes_v1"
MAX_TOKENS = 512
MAX_CANDIDATES = 2
NER_THRESHOLD = .5
ATTRIBUTE_THRESHOLD = .5
ATTRIBUTE_NAME = "customer_relation"
COUNTERS = ("extract_invocations", "encoder_forward_entries", "attribute_attach_entries",
            "explicit_span_score_entries")


def _require(ok, code):
    if not ok:
        raise ValueError("native_span_" + code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _text_hash(text):
    _require(isinstance(text, str) and bool(text.strip()) and len(text) <= 6000, "invalid_text")
    return hashlib.sha256(text.encode()).hexdigest()


def compiled_spec():
    contracts = category_contract_identity()
    description = (contracts["any_specific_organization"]["definitions"]["CUSTOMER"]
                   + " Trusted business scope: " + BUSINESS_SCOPE + " " + GLINER_GUIDE)
    return {"version": VERSION, "scope": BUSINESS_SCOPE, "contracts": contracts,
            "entity_description": description, "attribute_labels": deepcopy(CLASS_LABELS),
            "attribute_name": ATTRIBUTE_NAME, "qualify_labels": True, "multi_label": False,
            "applies_to": ["organization"], "ner_threshold": NER_THRESHOLD,
            "host_attribute_threshold": ATTRIBUTE_THRESHOLD,
            "max_tokens": MAX_TOKENS, "max_candidates": MAX_CANDIDATES,
            "input_layout": "unchanged_full_source_text_with_scope_and_guide_in_entity_schema",
            "decision_contract": {
                "strict_customer_relation": "fixed_five_class_relation_truth_table; low_attribute_confidence_needs_review",
                "any_specific_organization": "protect_all_validated_native_NER_organization_spans; attributes_do_not_gate",
            }}


def _score(value, *, minimum=0):
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= 1


def decode_entities(text, raw):
    """Validate exact character locations and native attribute fields without gold."""
    _text_hash(text)
    _require(isinstance(raw, dict) and set(raw) == {"entities"}
             and isinstance(raw["entities"], dict) and set(raw["entities"]) <= {"organization"},
             "invalid_native_output")
    items = raw["entities"].get("organization", [])
    _require(isinstance(items, list), "invalid_native_entities")
    reverse = {value: key for key, value in CLASS_LABELS.items()}
    result, seen = [], set()
    for item in items:
        _require(isinstance(item, dict)
                 and set(item) == {"text", "start", "end", "confidence", ATTRIBUTE_NAME}, "invalid_entity_fields")
        start, end, quote = item["start"], item["end"], item["text"]
        _require(type(start) is int and type(end) is int and 0 <= start < end <= len(text)
                 and isinstance(quote, str) and text[start:end] == quote
                 and _score(item["confidence"], minimum=NER_THRESHOLD), "invalid_entity_span_or_score")
        _require((start, end) not in seen, "duplicate_entity_span")
        seen.add((start, end))
        attr = item[ATTRIBUTE_NAME]
        _require(isinstance(attr, dict) and set(attr) == {"label", "confidence"}
                 and isinstance(attr["label"], str) and attr["label"] in reverse
                 and _score(attr["confidence"]), "invalid_native_attribute")
        result.append({"start": start, "end": end, "text": quote,
                       "entity_confidence": item["confidence"], "attribute_class": reverse[attr["label"]],
                       "attribute_label": attr["label"], "attribute_confidence": attr["confidence"]})
    return sorted(result, key=lambda item: (item["start"], item["end"]))


@contextmanager
def _observe_entry(obj, name, on_entry):
    """Restore class/instance lookup exactly even when the native method raises."""
    original = getattr(obj, name)
    _require(callable(original), "missing_native_entry")
    owned = name in vars(obj)
    def observed(*args, **kwargs):
        on_entry()
        return original(*args, **kwargs)
    setattr(obj, name, observed)
    try:
        yield
    finally:
        if owned:
            setattr(obj, name, original)
        else:
            delattr(obj, name)


class NativeSpanAttributeRuntime:
    """Serial wrapper around an already loaded, pinned LocalNerRuntime."""
    def __init__(self, ner_runtime, *, max_extracts=12, on_capture=None):
        _require(type(max_extracts) is int and 0 <= max_extracts <= 12, "invalid_extract_cap")
        _require(on_capture is None or callable(on_capture), "invalid_capture_callback")
        self.ner, self.maximum_extracts, self.on_capture = ner_runtime, max_extracts, on_capture
        self.counts = {name: 0 for name in COUNTERS}
        self.events, self._serial = [], threading.RLock()
        self._runtime_identity = deepcopy(ner_runtime.identity)
        _require(isinstance(self._runtime_identity, dict) and bool(self._runtime_identity), "runtime_identity_required")
        _digest(self._runtime_identity)
        self._adapter_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    @property
    def identity(self):
        _require(self.ner.identity == self._runtime_identity, "runtime_identity_changed")
        _require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == self._adapter_sha,
                 "adapter_source_changed")
        return {"version": VERSION, "runtime": deepcopy(self._runtime_identity),
                "extract_cap": self.maximum_extracts, "adapter_sha256": self._adapter_sha,
                "spec_sha256": _digest(compiled_spec())}

    def snapshot_counts(self):
        return deepcopy(self.counts)

    def _build_schema(self):
        from gliner2.inference.schema import AttributeGroup
        spec = compiled_spec()
        return self.ner.model.create_schema().entities({"organization": spec["entity_description"]}).entity_attributes({
            ATTRIBUTE_NAME: AttributeGroup(labels=list(spec["attribute_labels"].values()), multi_label=False,
                threshold=ATTRIBUTE_THRESHOLD, applies_to=["organization"], qualify_labels=True)})

    def _configure_splitter(self):
        from .ner_detector import CjkAwareSplitter
        processor = self.ner.model.processor
        if not isinstance(processor.word_splitter, CjkAwareSplitter):
            processor.word_splitter = CjkAwareSplitter(processor.word_splitter)

    def _preflight_locked(self, text):
        _text_hash(text)
        self.identity
        self._configure_splitter()
        schema = self._build_schema()
        transformed = self.ner.model.processor.transform_record(text, schema, max_len=None)
        count = len(transformed.input_ids)
        _require(type(count) is int and count > 0, "invalid_token_count")
        return schema, {"token_count": count, "fits": count <= MAX_TOKENS,
                        "max_len": None, "schema": deepcopy(schema.build()),
                        "text_sha256": _text_hash(text), "spec_sha256": _digest(compiled_spec()),
                        "counter_snapshot": self.snapshot_counts()}

    def preflight(self, text):
        with self._serial, self.ner.lock:
            return self._preflight_locked(text)[1]

    def infer(self, text):
        with self._serial, self.ner.lock:
            schema, receipt = self._preflight_locked(text)
            before = self.snapshot_counts()
            evidence = {"version": VERSION, "text_sha256": _text_hash(text), "scope": BUSINESS_SCOPE,
                        "spec_sha256": _digest(compiled_spec()), "runtime_identity": self.identity,
                        "preflight": receipt, "raw_result": None, "entities": [],
                        "status": "needs_review", "error_kind": None, "errors": [], "processing_complete": False}
            event = {"text": text, "preflight": deepcopy(receipt), "before": before}
            try:
                if not receipt["fits"]:
                    evidence.update(error_kind="coverage", errors=["input_budget_exceeded"])
                else:
                    _require(self.counts["extract_invocations"] < self.maximum_extracts, "extract_cap_exhausted")
                    model = self.ner.model
                    def increment(name):
                        self.counts[name] += 1
                    options = {"threshold": NER_THRESHOLD, "format_results": True,
                               "include_confidence": True, "include_spans": True, "max_len": None}
                    event["options"] = deepcopy(options)
                    with _observe_entry(model.encoder, "forward", lambda: increment("encoder_forward_entries")), \
                         _observe_entry(model, "_attach_entity_attributes", lambda: increment("attribute_attach_entries")), \
                         _observe_entry(model.boundary_head, "score_explicit_spans", lambda: increment("explicit_span_score_entries")):
                        self.counts["extract_invocations"] += 1
                        raw = model.extract(text, schema, **options)
                    evidence["raw_result"] = deepcopy(raw)
                    event["decoded_output"] = deepcopy(raw)
                    evidence["entities"] = decode_entities(text, raw)
                    self.identity
                    if len(evidence["entities"]) > MAX_CANDIDATES:
                        evidence.update(error_kind="coverage", errors=["candidate_budget_exceeded"])
                    else:
                        evidence.update(status="ok", processing_complete=True)
                evidence["counts"] = {key: self.counts[key] - before[key] for key in COUNTERS}
                evidence["evidence_sha256"] = _digest(evidence)
                return evidence
            except Exception as exc:
                event["error_type"] = type(exc).__name__
                event["error_code"] = str(exc) if isinstance(exc, ValueError) else "native_inference_failed"
                raise
            finally:
                event["after"] = self.snapshot_counts()
                self.events.append(deepcopy(event))
                if self.on_capture is not None:
                    self.on_capture(deepcopy(event))


def decide(text, policy, evidence):
    """Bound pure replay; no inference and no creation of access authority."""
    result = {"status": "needs_review", "findings": [], "errors": [], "local_calls": 0,
              "elapsed_seconds": 0.0, "candidate_decisions": [], "relation_errors": [],
              "evidence_sha256": None, "prompt_version": VERSION}
    try:
        from .privacy import _policy
        normalized = _policy(policy)
        contract = normalized.get("category_contract")
        contracts = category_contract_identity()
        _require(normalized["protected_categories"] == ["CUSTOMER"] and isinstance(contract, dict)
                 and contract == contracts.get(contract.get("ontology_id"))
                 and normalized["instructions"] == BUSINESS_SCOPE
                 and len(text) <= normalized["max_text_chars"], "unsupported_policy")
        _require(isinstance(evidence, dict) and evidence.get("version") == VERSION
                 and evidence.get("text_sha256") == _text_hash(text)
                 and evidence.get("scope") == BUSINESS_SCOPE
                 and evidence.get("spec_sha256") == _digest(compiled_spec())
                 and evidence.get("evidence_sha256") == _digest({k: v for k, v in evidence.items() if k != "evidence_sha256"}),
                 "evidence_binding_changed")
        result["evidence_sha256"] = evidence["evidence_sha256"]
        if evidence["error_kind"] == "coverage":
            result.update(errors=["input_budget_exceeded"], relation_errors=deepcopy(evidence["errors"]))
            return result
        _require(evidence.get("status") == "ok" and evidence.get("processing_complete") is True
                 and evidence.get("error_kind") is None and evidence.get("errors") == []
                 and evidence.get("entities") == decode_entities(text, evidence.get("raw_result"))
                 and len(evidence["entities"]) <= MAX_CANDIDATES, "incomplete_native_evidence")
        review = False
        for candidate in evidence["entities"]:
            label, score = candidate["attribute_class"], candidate["attribute_confidence"]
            if contract["ontology_id"] == "any_specific_organization":
                decision = "sensitive"
            elif score < ATTRIBUTE_THRESHOLD:
                decision = "needs_review"
            elif label == "not_specific_name":
                decision = "not_sensitive"
            elif label in {"current_customer", "former_customer"}:
                decision = "sensitive"
            elif label == "explicit_noncustomer":
                decision = "not_sensitive"
            else:
                decision = "needs_review"
            result["candidate_decisions"].append({**deepcopy(candidate), "decision": decision})
            if decision == "sensitive":
                result["findings"].append({"quote": candidate["text"], "category": "CUSTOMER",
                                           "start": candidate["start"], "end": candidate["end"]})
            review |= decision == "needs_review"
        result.update(status="needs_review" if review else "ok", errors=["semantic_uncertainty"] if review else [])
    except Exception as exc:
        result.update(status="needs_review", findings=[], errors=["invalid_input_or_policy"],
                      relation_errors=[str(exc) if isinstance(exc, ValueError) else "invalid_native_replay"])
    return result


def observation_status(response, evidence):
    if response.get("errors") == ["invalid_input_or_policy"]:
        return "engineering_error"
    if evidence.get("error_kind") == "coverage":
        return "coverage_review"
    if response.get("status") == "ok" and response.get("errors") == []:
        return "ok"
    if response.get("status") == "needs_review" and response.get("errors") == ["semantic_uncertainty"]:
        return "needs_review"
    return "engineering_error"
