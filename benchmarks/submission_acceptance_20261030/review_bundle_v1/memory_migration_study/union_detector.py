"""Standard conservative union of independently executed local detectors.

Members see fresh copies of the same input, never the other member's output.
Successful raw spans are validated independently by the existing host contract;
this adapter neither expands them nor unifies named-entity identities. Any
failed/uncertain member makes the complete result require review.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from .privacy import _digest, _policy, detect_sensitive


UNION_VERSION = "independent_local_detector_union_v1"
INFERENCE_KINDS = ("local_encoder", "local_generation", "unknown")
_AUTHORITY_KEYS = frozenset({"authority", "authorization", "authorized", "permissions", "readers",
                              "owner_id", "actor_id", "agent_id", "grants", "role", "allow"})


def _trusted_cap(detector):
    value = getattr(detector, "max_local_calls", 2)
    if type(value) is not int or not 1 <= value <= 4:
        raise ValueError("invalid_union_member_call_limit")
    return value


class IndependentUnionDetector:
    def __init__(self, first, second, *, member_kinds=("local_encoder", "local_generation")):
        if not callable(first) or not callable(second):
            raise ValueError("two_callable_union_members_required")
        if (not isinstance(member_kinds, (list, tuple)) or len(member_kinds) != 2
                or any(not isinstance(kind, str) or kind not in INFERENCE_KINDS for kind in member_kinds)):
            raise ValueError("invalid_union_member_kinds")
        self._members = (first, second)
        self._kinds = tuple(member_kinds)
        self._caps = tuple(_trusted_cap(detector) for detector in self._members)
        if sum(self._caps) > 4:
            raise ValueError("union_call_limit_exceeded")

    @property
    def max_local_calls(self):
        return sum(self._caps)

    def cache_identity(self):
        """Missing trusted member identity disables cache reuse via caller policy."""
        members = []
        for index, (detector, kind, cap) in enumerate(zip(self._members, self._kinds, self._caps)):
            if _trusted_cap(detector) != cap:
                raise ValueError("union_member_contract_changed")
            try:
                identity = detector.cache_identity()
                if not isinstance(identity, dict) or not identity:
                    raise ValueError("missing_identity")
                json.dumps(identity, allow_nan=False)
            except (AttributeError, TypeError, ValueError):
                raise ValueError("union_member_identity_required") from None
            members.append({"index": index, "inference_kind": kind, "max_local_calls": cap,
                            "detector": deepcopy(identity)})
        return {"version": UNION_VERSION, "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "members": members, "max_local_calls": self.max_local_calls}

    def __call__(self, *, text, source_id, policy, rule_findings):
        started = time.monotonic()
        observations, counts, known_total, complete = [], {kind: 0 for kind in INFERENCE_KINDS}, 0, True

        def finish(status, findings=(), error=None):
            try:
                identity_digest = _digest(self.cache_identity())
            except (AttributeError, TypeError, ValueError):
                identity_digest = "unavailable"
            return {"status": status, "findings": list(findings), "errors": [error] if error else [],
                    "local_calls": known_total if complete else None, "local_calls_complete": complete,
                    "known_local_calls": known_total, "elapsed_seconds": round(time.monotonic()-started, 6),
                    "model": "independent-local-union", "digest": identity_digest, "prompt_version": UNION_VERSION,
                    "inference_kind": "mixed_local", "inference_counts": counts,
                    "member_observations": observations, "diagnostics": []}

        try:
            normalized = _policy(policy)
            if (not isinstance(text, str) or not isinstance(source_id, str) or not source_id
                    or not isinstance(rule_findings, list)
                    or tuple(_trusted_cap(d) for d in self._members) != self._caps):
                return finish("needs_review", error="invalid_input_or_policy")
            # Use a fixed validation identity rather than the external source ID.
            # The original source ID is passed unchanged only to each detector.
            validation_payload = {"query": "", "memories": [{"source_id": "union_host_check", "text": text}]}
            preflight = detect_sensitive(validation_payload, normalized, mode="rules")
            if preflight["status"] != "ok":
                return finish("needs_review", error="invalid_input_or_policy")
            if not text.strip() or not normalized["protected_categories"]:
                return finish("ok")
        except (AttributeError, TypeError, ValueError):
            return finish("needs_review", error="invalid_input_or_policy")

        merged, any_failed = {}, False
        for index, (detector, kind, cap) in enumerate(zip(self._members, self._kinds, self._caps)):
            before = time.monotonic()
            response, member_calls, errors = None, None, []
            try:
                response = detector(text=text, source_id=source_id, policy=deepcopy(normalized),
                                    rule_findings=deepcopy(rule_findings))
            except Exception:
                errors.append("local_agent_error")
            if isinstance(response, dict):
                calls = response.get("local_calls")
                if type(calls) is int and 0 <= calls <= cap and response.get("local_calls_complete", True) is True:
                    member_calls = calls
                    known_total += calls
                    counts[kind] += calls
                else:
                    errors.append("invalid_member_call_count")
                # Authority fields must not be accepted as a second contract.
                if _AUTHORITY_KEYS.intersection(response):
                    errors.append("member_authority_fields_rejected")
                if isinstance(response.get("findings"), list) and any(
                        isinstance(finding, dict) and _AUTHORITY_KEYS.intersection(finding)
                        for finding in response["findings"]):
                    errors.append("member_authority_fields_rejected")
            else:
                errors.append("local_agent_needs_review")
            if member_calls is None:
                complete = False

            if not errors:
                def observed_response(**_):
                    return response
                # The limit is fixed by the trusted member callable, not supplied
                # by a model response. Validation does not invoke a model again.
                observed_response.max_local_calls = cap
                checked = detect_sensitive(validation_payload, normalized, mode="agent", agent=observed_response)
                if checked["status"] != "ok" or not checked["local_calls_complete"]:
                    errors.extend(checked["errors"] or ["local_agent_needs_review"])
                else:
                    for finding in response["findings"]:
                        # Validation already proved exact locations. Preserve raw
                        # spans rather than its expanded/maximalized output.
                        a = finding["start"] if "start" in finding else text.index(finding["quote"])
                        b = finding["end"] if "end" in finding else a + len(finding["quote"])
                        key = (a, b, finding["category"])
                        merged[key] = {"start": a, "end": b, "quote": text[a:b], "category": finding["category"]}
            failed = bool(errors)
            any_failed |= failed
            observations.append({"index": index, "inference_kind": kind, "status": "needs_review" if failed else "ok",
                                 "local_calls": member_calls, "local_calls_complete": member_calls is not None,
                                 "elapsed_seconds": round(time.monotonic()-before, 6), "errors": sorted(set(errors))})

        if any_failed:
            return finish("needs_review", error="local_failure")
        return finish("ok", [merged[key] for key in sorted(merged)])
