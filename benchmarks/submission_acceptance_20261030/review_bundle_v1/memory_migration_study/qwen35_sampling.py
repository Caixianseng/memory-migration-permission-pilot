"""Explicit presence-penalty control around the unchanged Qwen3.5 adapter.

The inherited call/repair flow is retained. Only the outgoing POST options gain
one explicit parameter; this module does not assess permissions or accuracy.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

from .qwen35_occurrence import Qwen35OccurrenceAgent, build_request as legacy_request

VERSION = "qwen35_explicit_presence_sampling_v1"
ARMS = {"presence_15": 1.5, "presence_zero": 0.0}


def penalty_for(arm):
    if type(arm) is not str or arm not in ARMS:
        raise ValueError("unsupported_sampling_arm")
    return ARMS[arm]


def explicit_request(body, arm):
    """Copy a legacy POST request, adding exactly one previously absent option."""
    penalty = penalty_for(arm)
    if type(body) is not dict or type(body.get("options")) is not dict:
        raise ValueError("invalid_sampling_request")
    if "presence_penalty" in body["options"]:
        raise ValueError("legacy_presence_already_explicit")
    request = deepcopy(body)
    request["options"]["presence_penalty"] = penalty
    return request


def build_request(text, source_id, policy, rule_findings, *, arm, repair=False):
    """Pure frozen initial/repair request; no model, network or file mutation."""
    return explicit_request(legacy_request(text, source_id, policy, rule_findings,
                                          repair=repair), arm)


class SamplingQwen35Agent(Qwen35OccurrenceAgent):
    """Reuse the old adapter, composing one transformation at its transport edge."""

    def __init__(self, *, arm, expected_digest, transport=None, **kwargs):
        self.sampling_arm = arm
        self.presence_penalty = penalty_for(arm)
        if transport is not None and not callable(transport):
            raise ValueError("invalid_local_transport")
        upstream = transport if transport is not None else self._transport

        def sampling_transport(method, path, body=None):
            if (method, path) == ("POST", "/api/chat"):
                body = explicit_request(body, self.sampling_arm)
            return upstream(method, path, body)

        super().__init__(expected_digest=expected_digest, transport=sampling_transport, **kwargs)

    def cache_identity(self):
        identity = super().cache_identity()
        identity["legacy_implementation_sha256"] = identity["implementation_sha256"]
        identity.update(sampling_version=VERSION, sampling_arm=self.sampling_arm,
            implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            presence_penalty=self.presence_penalty,
            sampling_change="transport POST options.presence_penalty only")
        identity["options"]["presence_penalty"] = self.presence_penalty
        return identity

    def __call__(self, **kwargs):
        result = super().__call__(**kwargs)
        return {**result, "sampling_identity": self.cache_identity(),
                "sampling_arm": self.sampling_arm,
                "sampling_presence_penalty": self.presence_penalty}
