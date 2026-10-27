"""Zero-model audit of frozen relation-probe preparations.

Only the caller reads/freezes files and evaluation data. The temporary wrapper
observes the existing preparation path; maps never leave its stack. Equality
allows only the random nonce in validated tokens/source identifiers to differ.
This is equivalent replay evidence, not authentication of a caller-supplied row.
"""
from copy import deepcopy
import re
import threading
from unittest.mock import patch

from memory_migration_study import privacy, privacy_egress
from memory_migration_study.privacy_payload_eval import masking_intervals
from scripts import relation_probe_scoring as original
from scripts.run_boundary_preparation_audit import score_mask

VERSION = "relation_redaction_trace_audit_v1"
SOURCE_ID = "probe"
_SERIAL = threading.RLock()
_TOKEN = re.compile(r"\[PVT_([A-F0-9]{24})_(PERSON|ADDRESS|CUSTOMER|PROJECT|EMAIL|PHONE|ID|AMOUNT|DATE|MIXED)_([1-9][0-9]*)\]")
_SOURCE = re.compile(r"m_([A-F0-9]{24})_1")
_CANONICAL_NONCE = "0" * 24


def _require(condition, reason):
    if not condition:
        raise ValueError("relation_redaction_" + reason)


def _normalized_payload(payload):
    """Preserve every literal, category/index and list position except nonce."""
    _require(isinstance(payload, dict) and set(payload) == {"query", "memories"}
             and payload["query"] == "" and isinstance(payload["memories"], list)
             and len(payload["memories"]) == 1, "invalid_payload")
    memory = payload["memories"][0]
    _require(isinstance(memory, dict) and set(memory) == {"source_id", "text"}
             and isinstance(memory["source_id"], str) and isinstance(memory["text"], str), "invalid_memory")
    match = _SOURCE.fullmatch(memory["source_id"])
    _require(match is not None, "invalid_opaque_source")
    nonce = match[1]
    text = memory["text"]
    matches = list(_TOKEN.finditer(text))
    _require(all(token[1] == nonce for token in matches), "mixed_or_wrong_nonce")
    _require("[PVT_" not in _TOKEN.sub("", text).upper(), "malformed_token")
    normalized = _TOKEN.sub(lambda token: "[PVT_" + _CANONICAL_NONCE + "_" + token[2] + "_" + token[3] + "]", text)
    return {"query": "", "memories": [{"source_id": "m_" + _CANONICAL_NONCE + "_1", "text": normalized}]}


def _canonical_preparation(preparation):
    """Only payload nonce and its dependent hash are random in this contract."""
    copied = deepcopy(preparation)
    if copied["status"] == "ok":
        copied["payload"] = _normalized_payload(copied["payload"])
        _require(copied["metadata"]["payload_sha256"] == original._hash(preparation["payload"]),
                 "invalid_payload_hash")
        copied["metadata"]["payload_sha256"] = original._hash(copied["payload"])
    return copied


def audit_observation(text, policy, row):
    """Observe actual masking of an exact bound replay, with no gold or I/O.

    Malformed/changed frozen material raises ValueError. A faithfully reproduced
    blocked row remains ``blocked`` with no payload/footprint; it is never scored
    as clean detection. The original row is not modified.
    """
    _require(isinstance(text, str) and bool(text) and len(text) <= 6000, "invalid_text")
    _require(isinstance(row, dict) and {"cell", "status", "response", "preparation"} <= set(row), "invalid_row")
    _require(isinstance(row["cell"], dict) and row["cell"].get("profile") in original.PROFILES, "invalid_profile")
    frozen = deepcopy(row)
    normalized = privacy._policy(policy)
    _require(normalized.get("category_contract", {}).get("ontology_id") == frozen["cell"]["profile"],
             "policy_profile_mismatch")
    original._validate_status(frozen, text)
    original._validate_preparation(frozen, text)
    sealed = frozen["preparation"]
    _require(sealed["binding"].get("source_id") == SOURCE_ID
             and sealed["binding"]["policy_sha256"] == original._hash(normalized), "source_or_policy_binding_mismatch")
    source = original._source_payload(text, SOURCE_ID)
    observed = []

    with _SERIAL:
        prepare = privacy.prepare_private_payload

        def observe(payload, detection, **kwargs):
            _require(payload == source and kwargs.get("sensitivity_policy") == normalized,
                     "replay_input_changed")
            result = prepare(payload, detection, **kwargs)
            actor = kwargs.get("actor_id")
            _require(actor in {original.ACTOR, original.WRONG_ACTOR}, "unexpected_actor")
            receipt = {"actor": actor, "prepare_status": result["status"], "prepare_error": result["error"],
                       "payload_is_none": result["payload"] is None, "mask_footprint": {},
                       "egress": None, "trace_status": "not_ready"}
            if actor == original.ACTOR:
                receipt["egress"] = privacy_egress.validate_outbound(payload, result, detection, normalized)
                if result["status"] == "ok":
                    _require(isinstance(result.get("mapping"), privacy.RestorationMap), "missing_ephemeral_mapping")
                    pairs = [(privacy.QUERY_SOURCE, payload["query"], result["payload"]["query"])]
                    pairs.extend((left["source_id"], left["text"], right["text"])
                                 for left, right in zip(payload["memories"], result["payload"]["memories"], strict=True))
                    receipt["mask_footprint"] = {sid: [list(span) for span in masking_intervals(raw, masked, result["mapping"]._entries)]
                                                 for sid, raw, masked in pairs}
                    receipt["trace_status"] = "aligned"
            observed.append(receipt)
            # The existing caller still needs the ordinary return contract.
            # No mapping or plaintext entry is retained by this observer.
            return result

        with patch.object(privacy, "prepare_private_payload", side_effect=observe):
            replayed = original.prepare_observation(text, normalized, frozen["response"], source_id=SOURCE_ID)
    replay_row = {**frozen, "preparation": replayed}
    original._validate_preparation(replay_row, text)
    _require(_canonical_preparation(sealed) == _canonical_preparation(replayed), "replay_not_equivalent")
    main = [item for item in observed if item["actor"] == original.ACTOR]
    denied = [item for item in observed if item["actor"] == original.WRONG_ACTOR]
    _require(len(main) == 1 and len(denied) == int(replayed["status"] == "ok"), "unexpected_prepare_call_count")
    if denied:
        _require(denied[0]["prepare_status"] == "needs_review"
                 and denied[0]["prepare_error"] == "memory_authorization_failed"
                 and denied[0]["payload_is_none"], "negative_control_changed")
    primary = main[0]
    trace = {"version": VERSION, "status": "aligned" if replayed["status"] == "ok" else "blocked",
             "text_sha256": original._text_hash(text), "policy_sha256": original._hash(normalized),
             "profile": frozen["cell"]["profile"], "source_id": SOURCE_ID,
             "observation_status": frozen["status"], "response_sha256": original._hash(frozen["response"]),
             "frozen_preparation_sha256": original._hash(sealed),
             "canonical_preparation_sha256": original._hash(_canonical_preparation(sealed)),
             "prepare_status": primary["prepare_status"], "prepare_error": primary["prepare_error"],
             "mask_alignment_status": primary["trace_status"], "mask_footprint": primary["mask_footprint"],
             "egress": primary["egress"], "acl_negative_control": deepcopy(replayed["acl_negative_control"]),
             "prepare_calls": len(observed), "new_model_calls": 0, "mapping_persisted": False,
             "comparison": "entire_preparation_equal_after_validated_nonce_and_dependent_payload_hash_normalization"}
    trace["trace_sha256"] = original._hash(trace)
    return trace


def score_observation(text, trace, expected):
    """Score a closed trace using existing character coverage, never substring.

    ``expected`` uses the old relation reference cell: decision, spans and
    must_mask_values. It is deliberately a separate call from preparation.
    """
    _require(isinstance(trace, dict) and trace.get("version") == VERSION
             and trace.get("text_sha256") == original._text_hash(text)
             and trace.get("trace_sha256") == original._hash({k: v for k, v in trace.items() if k != "trace_sha256"}),
             "invalid_trace_binding")
    _require(isinstance(expected, dict) and expected.get("decision") in {"sensitive", "not_sensitive", "needs_review"},
             "invalid_reference")
    spans = original._spans(expected.get("spans"), text, reference=True)
    _require(bool(spans) == (expected["decision"] == "sensitive"), "invalid_reference_decision")
    footprint = trace.get("mask_footprint")
    _require(isinstance(footprint, dict), "invalid_trace_footprint")
    if trace["prepare_status"] == "ok":
        _require(trace["status"] == "aligned" and trace["mask_alignment_status"] == "aligned"
                 and set(footprint) == {privacy.QUERY_SOURCE, SOURCE_ID}
                 and footprint[privacy.QUERY_SOURCE] == [], "invalid_ready_trace")
        prior = -1
        for pair in footprint[SOURCE_ID]:
            _require(isinstance(pair, list) and len(pair) == 2 and all(type(x) is int for x in pair)
                     and 0 <= pair[0] < pair[1] <= len(text) and pair[0] >= prior, "invalid_trace_interval")
            prior = pair[1]
    else:
        _require(trace["status"] == "blocked" and trace["prepare_status"] == "needs_review"
                 and footprint == {} and trace["mask_alignment_status"] == "not_ready", "invalid_blocked_trace")
    ready = trace["prepare_status"] == "ok" and trace["egress"]["status"] == "ok"
    base = {"reference_known": expected["decision"] != "needs_review", "ready": ready,
            "trace_status": trace["status"], "trace_sha256": trace["trace_sha256"], "new_model_calls": 0}
    if expected["decision"] == "needs_review":
        return {**base, "gold_spans": None, "fully_masked_spans": None, "partially_masked_spans": None,
                "unmasked_spans": None, "unmasked_or_not_ready_spans": None,
                "masked_unprotected_characters": None, "all_reference_spans_masked_and_ready": None}
    converted = {"findings": [{"source_id": SOURCE_ID, "start": start, "end": end, "category": category}
                              for start, end, category in sorted(spans)]}
    row = {"prepare_status": trace["prepare_status"], "egress": trace["egress"],
           "mask_alignment_status": "ok" if trace["mask_alignment_status"] == "aligned" else "not_ready",
           "mask_footprint": footprint}
    measured = score_mask(row, converted)
    return {**base, **measured, "unmasked_spans": measured["unmasked_or_not_ready_spans"] if ready else None,
            "fully_masked_spans": measured["fully_masked_spans"] if ready else None,
            "partially_masked_spans": measured["partially_masked_spans"] if ready else None}
