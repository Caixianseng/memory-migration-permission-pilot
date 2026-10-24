"""Optional source-preserving evidence chunks, not semantic memory extraction.

The host segments original paragraphs/sentences and validates local sensitivity
candidates through the existing detector contract. It neither ranks facts nor
summarizes, deduplicates, rewrites, or grants access. A coverage certificate
describes candidate retained text even when detection requires review; it does
not certify privacy or imply that rejected chunks entered a memory store.
"""
from __future__ import annotations

import hashlib
import re
import time

from .privacy import QUERY_SOURCE, _digest, _policy, detect_sensitive

BUILDER_VERSION = "source_coverage_chunking_v1"
_SENTENCE_END = re.compile(r'''[。！？!?；;]+[”’"'」』）)]*|\.+[”’"'」』）)]*(?=\s|$)''')


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _certificate(text, spans):
    """Compute an exact source difference, including omitted whitespace runs."""
    cursor, omitted, retained = 0, [], []
    for start, end in spans:
        if cursor < start:
            omitted.append({"start": cursor, "end": start,
                            "whitespace_only": not text[cursor:start].strip()})
        retained.append({"start": start, "end": end, "sha256": _sha(text[start:end])})
        cursor = end
    if cursor < len(text):
        omitted.append({"start": cursor, "end": len(text),
                        "whitespace_only": not text[cursor:].strip()})
    kept_chars = sum(end-start for start, end in spans)
    kept_nonspace = sum(not c.isspace() for start, end in spans for c in text[start:end])
    source_nonspace = sum(not c.isspace() for c in text)
    return {"version": BUILDER_VERSION, "scope": "candidate_source_coverage_not_privacy_or_store_acceptance",
            "source_sha256": _sha(text), "source_characters": len(text),
            "source_non_whitespace_characters": source_nonspace, "spans": retained,
            "retained_characters": kept_chars, "retained_non_whitespace_characters": kept_nonspace,
            "omitted_characters": len(text)-kept_chars,
            "omitted_non_whitespace_characters": source_nonspace-kept_nonspace,
            "omitted_spans": omitted, "all_non_whitespace_covered": kept_nonspace == source_nonspace,
            "all_characters_covered": kept_chars == len(text)}


def verify_coverage_certificate(text, certificate):
    """Independently recompute hashes/counts from a caller's original source.

    A matching hash is an integrity check, not authentication. The trusted
    caller must supply the authoritative source, not an evaluated output.
    """
    try:
        if not isinstance(text, str) or not isinstance(certificate, dict):
            return False
        spans, previous = [], 0
        for item in certificate["spans"]:
            if not isinstance(item, dict) or set(item) != {"start", "end", "sha256"}:
                return False
            start, end = item["start"], item["end"]
            if (type(start) is not int or type(end) is not int or not previous <= start < end <= len(text)
                    or not text[start:end].strip()):
                return False
            spans.append((start, end))
            previous = end
        return certificate == _certificate(text, spans)
    except (KeyError, TypeError, ValueError):
        return False


def _chunk_spans(text, maximum):
    """Prefer complete nonblank paragraphs; pack sentences in long paragraphs.

    Newline-only and whitespace-only paragraphs are omitted explicitly in the
    coverage difference. Unbreakable overlong sentences fail rather than slice
    an entity arbitrarily. Whitespace inside a retained paragraph is unchanged.
    """
    chunks = []
    for match in re.finditer(r"[^\r\n]+", text):
        start, end = match.span()
        if not match.group().strip():
            continue
        if end-start <= maximum:
            chunks.append((start, end))
            continue
        stops = [start+m.end() for m in _SENTENCE_END.finditer(text[start:end])]
        if not stops or stops[-1] != end:
            stops.append(end)
        unit_start, chunk_start, chunk_end = start, None, None
        for unit_end in stops:
            if not text[unit_start:unit_end].strip():
                unit_start = unit_end
                continue
            if unit_end-unit_start > maximum:
                raise ValueError("unbreakable_sentence_exceeds_chunk_limit")
            if chunk_start is None:
                chunk_start, chunk_end = unit_start, unit_end
            elif unit_end-chunk_start <= maximum:
                chunk_end = unit_end
            else:
                chunks.append((chunk_start, chunk_end))
                chunk_start, chunk_end = unit_start, unit_end
            unit_start = unit_end
        if chunk_start is not None:
            chunks.append((chunk_start, chunk_end))
    return chunks


class CoverageMemoryBuilder:
    """Standard lossless evidence-chunking comparator with local field labels.

    The injected detector uses LocalSensitivityAgent/GlinerEntityAgent's
    ``text/source_id/policy/rule_findings`` contract. Existing ``detect_sensitive``
    validates its candidates and unions rules. Any incomplete call accounting or
    needs-review chunk makes the whole build needs-review. Facts remain visible
    as candidates, with per-fact status, for honest coverage/error accounting.
    """
    def __init__(self, detector=None, *, max_chunk_chars=1000, max_chunks=16,
                 max_source_chars=6000, max_total_chars=6000):
        limits = {"max_chunk_chars": max_chunk_chars, "max_chunks": max_chunks,
                  "max_source_chars": max_source_chars, "max_total_chars": max_total_chars}
        if any(type(v) is not int or v <= 0 for v in limits.values()):
            raise ValueError("coverage_limits_must_be_positive_integers")
        if (max_chunk_chars > 6000 or max_source_chars > 6000 or max_total_chars > 6000
                or max_chunks > 256):
            raise ValueError("coverage_limits_exceed_supported_bounds")
        self.detector, self.limits = detector, limits
        # Classify known trusted host implementations, never model-supplied
        # response metadata. Third-party injected detectors stay unspecified.
        from .local_detector import LocalSensitivityAgent
        from .ner_detector import GlinerEntityAgent
        self.inference_kind = ("local_encoder" if isinstance(detector, GlinerEntityAgent) else
                               "local_generation" if isinstance(detector, LocalSensitivityAgent) else
                               "rules_only" if detector is None else "injected_local_detector")

    def __call__(self, *, text, source_id, policy):
        started = time.monotonic()
        facts, diagnostics, calls, elapsed, complete = [], [], 0, 0.0, True
        metadata = {"builder_version": BUILDER_VERSION,
                    "construction_kind": "programmatic_source_chunks_not_semantic_facts",
                    "construction_inference_kind": "programmatic", "inference_kind": self.inference_kind,
                    "builder_local_calls": 0, "configuration_sha256": _digest(self.limits)}

        def finish(status, errors, spans):
            source = text if isinstance(text, str) else ""
            return {"status": status, "facts": facts, "errors": errors, "diagnostics": diagnostics,
                    "local_calls": calls, "detector_local_calls": calls, "local_calls_complete": complete,
                    "agent_elapsed_seconds": round(elapsed, 6), "elapsed_seconds": round(time.monotonic()-started, 6),
                    "quote_wrapper_repairs": 0, "coverage": _certificate(source, spans),
                    "accepted_for_store": status == "ok", **metadata}

        if (not isinstance(text, str) or not text.strip() or not isinstance(source_id, str)
                or not source_id or len(source_id) > 256 or source_id == QUERY_SOURCE):
            return finish("needs_review", ["invalid_input"], [])
        try:
            normalized = _policy(policy)
        except (ValueError, TypeError):
            return finish("needs_review", ["invalid_input_or_policy"], [])
        metadata.update(source_text_sha256=_sha(text), policy_sha256=_digest(normalized))
        if len(text) > self.limits["max_source_chars"]:
            return finish("needs_review", ["source_character_budget_exceeded"], [])
        try:
            spans = _chunk_spans(text, min(self.limits["max_chunk_chars"], normalized["max_text_chars"]))
        except ValueError:
            return finish("needs_review", ["unbreakable_sentence_exceeds_chunk_limit"], [])
        # Validate the whole layout before calling a model or returning a prefix.
        if len(spans) > self.limits["max_chunks"]:
            return finish("needs_review", ["chunk_count_budget_exceeded"], [])
        if sum(end-start for start, end in spans) > self.limits["max_total_chars"]:
            return finish("needs_review", ["retained_character_budget_exceeded"], [])
        errors = set()
        for index, (start, end) in enumerate(spans):
            chunk_id = "coverage_"+_sha(source_id)[:24]+"_"+str(index+1)
            result = detect_sensitive({"query": "", "memories": [{"source_id": chunk_id, "text": text[start:end]}]},
                                      normalized, mode="combined", agent=self.detector)
            calls += result["local_calls"]
            elapsed += result["agent_elapsed_seconds"]
            complete = complete and result["local_calls_complete"]
            okay = result["status"] == "ok" and result["local_calls_complete"]
            if not okay:
                errors.add("sensitivity_detection_requires_review")
            diagnostics.append({"chunk_index": index, "source_start": start, "source_end": end,
                                "status": "ok" if okay else "needs_review", "errors": list(result["errors"]),
                                "local_calls": result["local_calls"], "local_calls_complete": result["local_calls_complete"]})
            # No model-provided fields, authority claims or source IDs propagate.
            findings = [{key: f[key] for key in ("start", "end", "category")}
                        for f in result["findings"] if f["source_id"] == chunk_id] if okay else []
            facts.append({"text": text[start:end], "source_start": start, "source_end": end,
                          "findings": findings, "status": "ok" if okay else "needs_review"})
        return finish("needs_review" if errors else "ok", sorted(errors), spans)
