"""Optional offline GLiNER2 entity detector for explicitly approved type policies.

Entity extraction cannot interpret arbitrary business sensitivity instructions.
The trusted caller must approve complete policies for this narrower backend;
unrecognized policies fail closed. Authorization remains in memory_labels.
"""
from __future__ import annotations
import hashlib
from importlib import metadata
import json
import math
import os
from pathlib import Path
import re
import sys
import threading
import time

from .privacy import _digest, _policy

CODE_REVISION = "ca4f68235b50fe4c3ecf3876851d748fe4b15c6c"
MODEL_REVISION = "cf5593a5d45e3bbf204b9df621b13b1c0cf25ee3"
MODEL_ID = "fastino/gliner2.5-multi-v1"
SCHEMA_VERSION = "typed_local_ner_v1"
LABELS = {
    "CUSTOMER": ("organization", "Full names of organizations, companies or cooperatives, including customer names and legal suffixes. Generic role words such as customer or client are not names."),
    "PROJECT": ("project name", "Full project names and project code identifiers. Not the generic word project."),
    "PERSON": ("person", "Full names of people."),
    "ADDRESS": ("address", "Full postal or street addresses including building and unit."),
    "EMAIL": ("email", "Complete email addresses."),
    "PHONE": ("phone number", "Complete telephone numbers including country or area code."),
    "ID": ("identity document number", "Government identity document or passport numbers."),
    "AMOUNT": ("money amount", "Monetary amounts including currency and unit."),
    "DATE": ("date", "Complete calendar dates mentioned in business text."),
}

_CJK_PARTS = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U0002fa1f]|[^\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U0002fa1f]+")


class CjkAwareSplitter:
    """Refine only CJK runs; preserve upstream Latin/email/punctuation boundaries.

    This wrapper uses the original string for offsets, never indexes into a
    case-folded token (Unicode case conversion can change its length).
    """
    def __init__(self, base=None):
        if base is None:
            from gliner2.processing.word_splitter import WhitespaceTokenSplitter
            base = WhitespaceTokenSplitter()
        self.base = base

    def __call__(self, text, lower=True):
        for _, start, end in self.base(text, lower=False):
            for match in _CJK_PARTS.finditer(text[start:end]):
                token = match.group()
                yield token.lower() if lower else token, start + match.start(), start + match.end()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class LocalNerRuntime:
    """One CPU model, serial extraction, immutable downloaded identities."""
    def __init__(self, root, *, threads=4):
        started = time.monotonic()
        root = Path(root).resolve()
        receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
        if (receipt.get("code_revision") != CODE_REVISION or receipt.get("model_revision") != MODEL_REVISION
                or receipt.get("model_id") != MODEL_ID):
            raise ValueError("ner_runtime_revision_mismatch")
        required = {"model/model.safetensors", "model/config.json", "model/tokenizer.json", "model/tokenizer_config.json",
                    "model/encoder_config/config.json", "vendor/gliner2/__init__.py"}
        if not required <= set(receipt.get("files", {})):
            raise ValueError("ner_runtime_inventory_incomplete")
        for name, expected in receipt["files"].items():
            path = (root / name).resolve()
            if not path.is_relative_to(root) or not path.is_file() or file_sha(path) != expected:
                raise ValueError("ner_runtime_file_changed")
        vendor = root / "vendor"
        existing = sys.modules.get("gliner2")
        if existing is not None and not Path(existing.__file__).resolve().is_relative_to(vendor):
            raise ValueError("different_gliner_package_already_loaded")
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
        os.environ["DO_NOT_TRACK"] = "1"
        sys.path.insert(0, str(vendor))
        import torch
        from gliner2 import AutoExtractor
        if type(threads) is not int or not 1 <= threads <= 8:
            raise ValueError("invalid_ner_thread_count")
        torch.set_num_threads(threads)
        self.model = AutoExtractor.from_pretrained(str(root / "model"), local_files_only=True,
                                                   map_location="cpu", attention_backend="standard")
        self.model.eval()
        self.lock = threading.Lock()
        self.identity = {"code_revision": CODE_REVISION, "model_revision": MODEL_REVISION, "model_id": MODEL_ID,
                         "files_sha256": _digest(receipt["files"]), "weights_sha256": receipt["files"]["model/model.safetensors"],
                         "device": "cpu", "threads": threads,
                         "dependencies": {name: metadata.version(name) for name in ("torch", "transformers", "safetensors", "tokenizers")}}
        self.initialization_seconds = round(time.monotonic() - started, 6)

    def infer(self, text, labels, *, splitter, threshold):
        from gliner2.processing.word_splitter import resolve_word_splitter
        with self.lock:
            # Shared weight model; splitter is set under the same serial lock
            # used for preprocessing and inference, so configurations cannot mix.
            self.model.processor.word_splitter = CjkAwareSplitter() if splitter == "cjk_aware" else resolve_word_splitter(splitter)
            schema = self.model.create_schema().entities(labels)
            transformed = self.model.processor.transform_record(text, schema, max_len=None)
            # Use the actual schema+text encoding, with no silent truncation.
            if len(transformed.input_ids) > 512:
                raise ValueError("input_budget_exceeded")
            return self.model.extract_entities(text, labels, threshold=threshold,
                                               include_confidence=True, include_spans=True)


class GlinerEntityAgent:
    max_local_calls = 1

    def __init__(self, runtime, *, approved_policies, splitter="cjk_aware", threshold=0.5):
        if splitter not in {"char", "whitespace", "cjk_aware"}:
            raise ValueError("invalid_ner_splitter")
        if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 < threshold < 1:
            raise ValueError("invalid_ner_threshold")
        if not isinstance(approved_policies, list) or not approved_policies:
            raise ValueError("explicit_entity_policy_approval_required")
        self.approved = frozenset(_digest(_policy(p)) for p in approved_policies)
        self.runtime, self.splitter, self.threshold = runtime, splitter, threshold

    def cache_identity(self):
        return {"runtime": self.runtime.identity, "splitter": self.splitter, "threshold": self.threshold,
                "policy_contracts": sorted(self.approved), "labels": LABELS, "schema_version": SCHEMA_VERSION,
                "adapter_sha256": file_sha(__file__)}

    def __call__(self, *, text, source_id, policy, rule_findings):
        started, calls = time.monotonic(), 0
        def finish(status, findings, code=None):
            return {"status": status, "findings": findings, "errors": [code] if code else [],
                    "local_calls": calls, "elapsed_seconds": round(time.monotonic() - started, 6),
                    "model": MODEL_ID, "digest": self.runtime.identity.get("weights_sha256", MODEL_REVISION),
                    "prompt_version": SCHEMA_VERSION, "inference_kind": "local_encoder",
                    "diagnostics": []}
        try:
            normalized = _policy(policy)
            if (not isinstance(text, str) or not isinstance(source_id, str) or not source_id or rule_findings != []
                    or len(text) > normalized["max_text_chars"] or _digest(normalized) not in self.approved):
                return finish("needs_review", [], "invalid_input_or_policy")
            if not text.strip() or not normalized["protected_categories"]:
                return finish("ok", [])
            labels = {LABELS[cat][0]: LABELS[cat][1] for cat in normalized["protected_categories"]}
            reverse = {LABELS[cat][0]: cat for cat in normalized["protected_categories"]}
            # One encoder forward is counted separately from LLM generations by
            # the caller's experiment manifest; never calls a cloud service.
            calls = 1
            result = self.runtime.infer(text, labels, splitter=self.splitter, threshold=self.threshold)
            if not isinstance(result, dict) or set(result) != {"entities"} or not isinstance(result["entities"], dict):
                return finish("needs_review", [], "format_or_span_invalid")
            findings = []
            for label, items in result["entities"].items():
                if label not in reverse or not isinstance(items, list):
                    return finish("needs_review", [], "format_or_span_invalid")
                for entity in items:
                    if not isinstance(entity, dict):
                        return finish("needs_review", [], "format_or_span_invalid")
                    a, b, quote, score = (entity.get(k) for k in ("start", "end", "text", "confidence"))
                    if (type(a) is not int or type(b) is not int or not 0 <= a < b <= len(text)
                            or not isinstance(quote, str) or text[a:b] != quote
                            or type(score) not in (int, float) or not math.isfinite(score)
                            or not self.threshold <= score <= 1):
                        return finish("needs_review", [], "format_or_span_invalid")
                    findings.append({"start": a, "end": b, "quote": quote, "category": reverse[label]})
            return finish("ok", findings)
        except Exception as exc:
            if type(exc) is ValueError and exc.args == ("input_budget_exceeded",):
                calls = 0
                return finish("needs_review", [], "input_budget_exceeded")
            return finish("needs_review", [], "local_failure")
