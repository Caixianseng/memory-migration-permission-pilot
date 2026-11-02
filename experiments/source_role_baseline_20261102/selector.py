"""Whole-message baselines, not a Knowledge Triage reproduction.

Only trusted host inputs belong here. The caller must authorize the supplied
sources BEFORE selection and reauthorize ALL host-registered actual input
dependencies before delivery. Selected source IDs are descriptive metadata;
they cannot attenuate the current host's actual-input AND dependency rule.
Source text and speaker labels are data, never permission grants. The required
boundary verifier must establish original message boundaries and speaker from
host evidence; a model's source/role claims do not qualify.

No I/O, model, question, reference answer, score or summarization interface.
Offsets are Python Unicode code-point offsets into the exact source text.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import hashlib
import json
from typing import Callable, Sequence


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SourceBlob:
    source_id: str
    text: str
    text_sha256: str


@dataclass(frozen=True)
class MessageEvidence:
    source_id: str
    message_id: str
    speaker: str
    start: int
    end: int


@dataclass(frozen=True)
class AuthorizedScope:
    """Previously verified host decision; this class does not authenticate it."""

    subject: str
    receiver: str
    policy_version: str
    source_ids: frozenset[str]


@dataclass(frozen=True)
class LengthMetric:
    """Only exact UTF-8 bytes are qualified by this isolated implementation."""

    metric_id: str = "utf8-bytes-v1"
    unit: str = "utf8_bytes"

    def measure(self, payload: str) -> int:
        return len(payload.encode("utf-8"))


def render_payload(items: Sequence[dict]) -> str:
    return json.dumps({"schema": "whole-message-memory-v1", "memory": list(items)},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def select(
    sources: Sequence[SourceBlob],
    messages: Sequence[MessageEvidence],
    *,
    scope: AuthorizedScope,
    budget: int,
    strategy: str,
    boundary_verifier: Callable[[SourceBlob, MessageEvidence], bool] | None,
    metric: LengthMetric = LengthMetric(),
) -> dict:
    """Select complete verified messages under the full serialized-byte cap.

    Strategies share one candidate pool. Source-first is chronological within
    each supplied source; source-role-round-robin alternates source/speaker
    buckets. A too-large unit is omitted, never clipped. The scope and boundary
    verifier are trusted host assertions, not an independent authorization
    oracle. Caller must keep their evidence outside the model-controlled data.
    """
    if (not isinstance(scope, AuthorizedScope)
            or not all(_nonempty(x) for x in
                       (scope.subject, scope.receiver, scope.policy_version))
            or not isinstance(scope.source_ids, frozenset)
            or not all(_nonempty(x) for x in scope.source_ids)):
        raise ValueError("trusted_host_scope_required")
    if type(budget) is not int or budget < 0:
        raise ValueError("nonnegative_integer_budget_required")
    if strategy not in {"source_first", "source_role_round_robin"}:
        raise ValueError("unknown_strategy")
    if type(metric) is not LengthMetric or metric.unit != "utf8_bytes" or metric.metric_id != "utf8-bytes-v1":
        raise ValueError("only_exact_utf8_byte_metric_qualified")
    source_map: dict[str, SourceBlob] = {}
    for source in sources:
        if not isinstance(source, SourceBlob) or not _nonempty(source.source_id):
            raise ValueError("invalid_source")
        if source.source_id not in scope.source_ids:
            raise ValueError("input_source_not_pre_authorized")
        if source.source_id in source_map:
            raise ValueError("duplicate_source_id")
        if not _nonempty(source.text) or sha256(source.text) != source.text_sha256:
            raise ValueError("source_hash_mismatch")
        source_map[source.source_id] = source

    review: list[dict] = []
    seen: set[tuple[str, str]] = set()
    ranges: dict[str, list[tuple[int, int]]] = {}
    verified: list[dict] = []
    source_rank = {sid: i for i, sid in enumerate(source_map)}
    for msg in messages:
        if not isinstance(msg, MessageEvidence):
            raise ValueError("structured_message_evidence_required")
        if msg.source_id not in source_map:
            raise ValueError("message_source_not_in_authorized_input")
        key = (msg.source_id, msg.message_id)
        if key in seen or not all(_nonempty(x) for x in (msg.message_id, msg.speaker)):
            raise ValueError("invalid_or_duplicate_message_identity")
        seen.add(key)
        src = source_map[msg.source_id]
        if (type(msg.start) is not int or type(msg.end) is not int
                or not 0 <= msg.start < msg.end <= len(src.text)):
            raise ValueError("invalid_message_offsets")
        prior = ranges.setdefault(msg.source_id, [])
        if any(msg.start < end and start < msg.end for start, end in prior):
            raise ValueError("overlapping_message_boundaries")
        prior.append((msg.start, msg.end))
        ok = boundary_verifier is not None and boundary_verifier(src, msg) is True
        if not ok:
            review.append({"source_id": msg.source_id, "message_id": msg.message_id,
                           "reason": "unverified_original_boundary_or_speaker"})
            continue
        quote = src.text[msg.start:msg.end]
        verified.append({"source_id": msg.source_id, "message_id": msg.message_id,
                         "speaker": msg.speaker, "start": msg.start, "end": msg.end,
                         "source_sha256": src.text_sha256,
                         "quote_sha256": sha256(quote), "text": quote})

    represented_sources = {sid for sid, _ in seen}
    for sid in source_map:
        if sid not in represented_sources:
            review.append({"source_id": sid, "message_id": None,
                           "reason": "missing_original_message_evidence"})

    base = {"schema": "source-role-baseline-result-v1", "strategy": strategy,
            "metric": metric.metric_id, "budget_unit": metric.unit, "budget": budget,
            "token_budget_qualified": False, "authorization_performed": False,
            "required_pre_delivery_reauthorization": True,
            "scope": {"subject": scope.subject, "receiver": scope.receiver,
                      "policy_version": scope.policy_version},
            "input_source_ids": list(source_map), "boundary_review": review}
    if review:
        return {**base, "status": "needs_review", "payload": None,
                "selected": [], "selected_source_ids": [], "omitted": [],
                "measured_payload_length": None}
    verified.sort(key=lambda x: (source_rank[x["source_id"]], x["start"]))
    candidate_blob = render_payload(verified)
    base.update(candidate_pool_sha256=sha256(candidate_blob), candidate_count=len(verified))
    if strategy == "source_role_round_robin":
        buckets: OrderedDict[tuple[str, str], deque] = OrderedDict()
        for item in verified:
            buckets.setdefault((item["source_id"], item["speaker"]), deque()).append(item)
        ordered = []
        while any(buckets.values()):
            for bucket in buckets.values():
                if bucket:
                    ordered.append(bucket.popleft())
    else:
        ordered = verified
    if metric.measure(render_payload([])) > budget:
        return {**base, "status": "overflow", "payload": None, "selected": [],
                "selected_source_ids": [], "measured_payload_length": None,
                "omitted": [{"source_id": x["source_id"], "message_id": x["message_id"],
                             "reason": "envelope_exceeds_budget"} for x in ordered]}
    selected, omitted = [], []
    for item in ordered:
        if metric.measure(render_payload(selected + [item])) <= budget:
            selected.append(item)
        else:
            reason = ("unit_exceeds_budget" if metric.measure(render_payload([item])) > budget
                      else "remaining_budget")
            omitted.append({"source_id": item["source_id"], "message_id": item["message_id"],
                            "reason": reason})
    payload = render_payload(selected)
    status = "ok" if not omitted else "partial" if selected else "overflow"
    return {**base, "status": status, "payload": payload, "selected": selected,
            "selected_source_ids": list(dict.fromkeys(x["source_id"] for x in selected)),
            "omitted": omitted, "measured_payload_length": metric.measure(payload)}
