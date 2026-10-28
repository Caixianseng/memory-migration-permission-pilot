"""Opt-in deterministic request serialization over frozen v1 semantics.

Object key insertion order is not model input in this version. Lists, exact
source strings, candidate IDs/positions, policy meaning and labels are retained.
This is the project's restricted JSON contract, not RFC 8785/JCS. No transport,
model, file I/O, grant or semantic correction is provided here.
"""
from copy import deepcopy
import json

from . import candidate_context_batch as legacy

VERSION = "candidate_context_batch_v2"
SERIALIZATION_VERSION = "sorted_json_objects_preserved_lists_utf8_v1"
MODES = legacy.MODES
CandidateContextError = legacy.CandidateContextError


def compiled_spec():
    previous = legacy.compiled_spec()
    result = deepcopy(previous)
    result.update(
        version=VERSION,
        legacy_semantic_spec_sha256=legacy._digest(previous),
        serialization={
            "version": SERIALIZATION_VERSION,
            "object_keys": "recursive Python JSON sort_keys order",
            "lists": "preserve original order; no sorting or deduplication",
            "strings": "exact codepoints; no Unicode, whitespace or symbol normalization",
            "encoding": "UTF-8, ensure_ascii=False, compact separators, allow_nan=False",
            "scope": "model user JSON content and canonical request digest",
            "not_jcs": True,
        },
    )
    return result


def build_request(text, pool, *, mode="plain"):
    """Validate the untouched pool and build an explicitly v2 request.

    The historical v1 builder remains authoritative for candidate qualification,
    positional marking and conservative byte preflight. Only the embedded JSON
    object's serialization changes. Reordering object keys preserves byte length
    for this restricted payload; this invariant is checked instead of assumed.
    """
    request = legacy.build_request(text, pool, mode=mode)
    content = request["messages"][1]["content"]
    canonical_content = json.dumps(json.loads(content), ensure_ascii=False,
                                   sort_keys=True, separators=(",", ":"), allow_nan=False)
    legacy._require(len(canonical_content.encode("utf-8")) == len(content.encode("utf-8")),
                    "serialization_byte_bound_changed")
    request["messages"][1]["content"] = canonical_content
    request["version"] = VERSION
    request["serialization_version"] = SERIALIZATION_VERSION
    request["spec_sha256"] = legacy._digest(compiled_spec())
    request.pop("request_sha256")
    request["request_sha256"] = legacy._digest(request)
    return request


def decode_response(text, pool, raw, *, request, mode="plain"):
    """Use unchanged v1 label/position decisions, binding them to a v2 request.

    Unknowns and engineering errors retain v1's blocking behavior. This function
    requires the retained request and rejects historical v1 or modified requests.
    It cannot attest that a caller really sent these bytes to a model; external
    capture/provenance checks remain the trusted experiment host's responsibility.
    """
    expected = build_request(text, pool, mode=mode)
    legacy._require(type(request) is dict and request.get("version") == VERSION,
                    "request_version_mismatch")
    try:
        actual_digest = legacy._digest({key: value for key, value in request.items()
                                       if key != "request_sha256"})
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise CandidateContextError("request_contract_mismatch") from None
    # Python object equality treats True==1 and 4096==4096.0. Their JSON bytes
    # differ, so equality alone is insufficient to validate a retained request.
    legacy._require(request == expected and actual_digest == expected["request_sha256"],
                    "request_contract_mismatch")
    result = legacy.decode_response(text, pool, raw, mode=mode)
    result.update(request_sha256=expected["request_sha256"],
                  request_version=VERSION, serialization_version=SERIALIZATION_VERSION)
    return result
